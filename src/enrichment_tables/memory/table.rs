#![allow(unsafe_op_in_unsafe_fn)] // TODO review ShallowCopy usage code and fix properly.

use std::{
    collections::HashSet,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use async_trait::async_trait;
use bytes::Bytes;
use evmap::{
    shallow_copy::CopyValue,
    {self},
};
use evmap_derive::ShallowCopy;
use futures::{StreamExt, stream::BoxStream};
use thread_local::ThreadLocal;
use tokio::{
    sync::broadcast::{Receiver, Sender},
    time::interval,
};
use tokio_stream::wrappers::IntervalStream;
use vector_lib::{
    ByteSizeOf, EstimatedJsonEncodedSizeOf,
    config::LogNamespace,
    enrichment::{Case, Condition, Error, IndexHandle, InternalError, Table},
    event::{Event, EventStatus, Finalizable},
    internal_event::{
        ByteSize, BytesSent, CountByteSize, EventsSent, InternalEventHandle, Output, Protocol,
    },
    shutdown::ShutdownSignal,
    sink::StreamSink,
};
use vrl::value::{KeyString, ObjectMap, Value};

use super::{
    persist::{self, LINE_OVERHEAD, PersistJob, PersistRow, Persistence, TableStatus},
    source::MemorySource,
};
use crate::{
    SourceSender,
    enrichment_tables::memory::{
        MemoryConfig, OnFull,
        internal_events::{
            MemoryEnrichmentTableEvicted, MemoryEnrichmentTableFlushed,
            MemoryEnrichmentTableInsertFailed, MemoryEnrichmentTableInserted,
            MemoryEnrichmentTableRead, MemoryEnrichmentTableReadFailed,
            MemoryEnrichmentTableTtlExpired,
        },
    },
};

/// Single memory entry containing the value and TTL
#[derive(Clone, Eq, PartialEq, Hash, ShallowCopy)]
pub struct MemoryEntry {
    value: String,
    update_time: CopyValue<Instant>,
    ttl: u64,
}

impl ByteSizeOf for MemoryEntry {
    fn allocated_bytes(&self) -> usize {
        self.value.size_of()
    }
}

impl MemoryEntry {
    pub(super) fn as_object_map(&self, now: Instant, key: &str) -> Result<ObjectMap, Error> {
        let ttl = self
            .ttl
            .saturating_sub(now.duration_since(*self.update_time).as_secs());
        Ok(ObjectMap::from([
            (
                KeyString::from("key"),
                Value::Bytes(Bytes::copy_from_slice(key.as_bytes())),
            ),
            (
                KeyString::from("value"),
                // Unreachable in normal operation: `value` was serialized by `handle_value`.
                serde_json::from_str::<Value>(&self.value).map_err(|source| Error::Internal {
                    source: InternalError::FailedToDecode {
                        details: source.to_string(),
                    },
                })?,
            ),
            (
                KeyString::from("ttl"),
                Value::Integer(ttl.try_into().unwrap_or(i64::MAX)),
            ),
        ]))
    }

    fn expired(&self, now: Instant) -> bool {
        now.duration_since(*self.update_time).as_secs() > self.ttl
    }

    fn persist_row(&self, key: &str, now: Instant, now_unix: u64) -> Option<PersistRow> {
        if self.expired(now) {
            return None;
        }
        let remaining = self
            .ttl
            .saturating_sub(now.duration_since(*self.update_time).as_secs());
        Some(PersistRow {
            key: key.to_owned(),
            value: self.value.clone(),
            exp_unix: now_unix.saturating_add(remaining),
        })
    }
}

#[derive(Default)]
struct MemoryMetadata {
    byte_size: u64,
    evictions_total: u64,
    /// Keys written since the last persistence tick; only tracked when persisting.
    dirty: HashSet<String>,
}

/// [`MemoryEntry`] combined with its key
#[derive(Clone)]
pub(super) struct MemoryEntryPair {
    /// Key of this entry
    pub(super) key: String,
    /// The value of this entry
    pub(super) entry: MemoryEntry,
}

// Used to ensure that these 2 are locked together
pub(super) struct MemoryWriter {
    pub(super) write_handle: evmap::WriteHandle<String, MemoryEntry>,
    metadata: MemoryMetadata,
}

/// A struct that implements [vector_lib::enrichment::Table] to handle loading enrichment data from a memory structure.
pub struct Memory {
    read_handle_factory: evmap::ReadHandleFactory<String, MemoryEntry>,
    read_handle: ThreadLocal<evmap::ReadHandle<String, MemoryEntry>>,
    pub(super) write_handle: Arc<Mutex<MemoryWriter>>,
    pub(super) config: MemoryConfig,
    #[allow(dead_code)]
    expired_items_receiver: Receiver<Vec<MemoryEntryPair>>,
    expired_items_sender: Sender<Vec<MemoryEntryPair>>,
    persistence: Option<Arc<Mutex<Persistence>>>,
}

impl Memory {
    /// Creates a new [Memory] based on the provided config, loading `persist_path` when set.
    pub fn new(config: MemoryConfig) -> Self {
        let (read_handle, write_handle) = evmap::new();
        // Buffer could only be used if source is stuck exporting available items, but in that case,
        // publishing will not happen either, because the lock would be held, so this buffer is not
        // that important
        let (expired_tx, expired_rx) = tokio::sync::broadcast::channel(5);
        // On a reload that does not preserve state, the outgoing table keeps writing this
        // file until its sink stops, up to one tick. Accepted: every line stays valid, and a
        // stale value can win on the next load once, which a cache tolerates.
        let (persistence, loaded) = match &config.persist_path {
            Some(path) => {
                let (persistence, rows) = Persistence::open(path);
                (Some(Arc::new(Mutex::new(persistence))), rows)
            }
            None => (None, Vec::new()),
        };
        let memory = Self {
            config,
            read_handle_factory: read_handle.factory(),
            read_handle: ThreadLocal::new(),
            write_handle: Arc::new(Mutex::new(MemoryWriter {
                write_handle,
                metadata: MemoryMetadata::default(),
            })),
            expired_items_sender: expired_tx,
            expired_items_receiver: expired_rx,
            persistence,
        };
        if !loaded.is_empty() {
            memory.restore(loaded);
        }
        memory
    }

    /// Inserts rows read from the persistence log, then evicts the oldest if the result
    /// is over `max_byte_size`.
    fn restore(&self, rows: Vec<persist::LoadedRow>) {
        let mut writer = self.write_handle.lock().expect("mutex poisoned");
        let now = Instant::now();
        let ttl = self.config.ttl;
        for row in rows {
            // Clamped, so a wall clock stepped back since the write cannot outlive the TTL.
            let remaining = row.remaining_secs.min(ttl);
            // Back-dated so the remaining lifetime is right, which restores rows in expiry
            // order. Early in boot `checked_sub` can fail and flatten that order; accepted.
            let (update_time, ttl) = now
                .checked_sub(Duration::from_secs(ttl - remaining))
                .map_or((now, remaining), |t| (t, ttl));
            writer.write_handle.update(
                row.key,
                MemoryEntry {
                    value: row.value,
                    update_time: update_time.into(),
                    ttl,
                },
            );
        }
        writer.write_handle.refresh();
        writer.metadata.byte_size = self.live_byte_size();
        if let Some(max_byte_size) = self.config.max_byte_size
            && writer.metadata.byte_size > max_byte_size
        {
            self.make_room(&mut writer, None, 0, max_byte_size);
        }
    }

    fn live_byte_size(&self) -> u64 {
        self.get_read_handle().read().map_or(0, |reader| {
            reader
                .iter()
                .map(|(k, v)| (k.size_of() + v.get_one().size_of()) as u64)
                .sum()
        })
    }

    /// Creates a new [Memory] based on the provided config and previous state.
    pub fn from_previous_state(
        config: MemoryConfig,
        prev_state: Box<dyn std::any::Any + Send + Sync>,
    ) -> Self {
        if let Ok(prev_memory) = prev_state.downcast::<Memory>() {
            Self {
                persistence: Self::resume_persistence(&config, &prev_memory.write_handle),
                config,
                read_handle_factory: prev_memory.read_handle_factory,
                read_handle: prev_memory.read_handle,
                write_handle: prev_memory.write_handle,
                expired_items_sender: prev_memory.expired_items_sender,
                expired_items_receiver: prev_memory.expired_items_receiver,
            }
        } else {
            Self::new(config)
        }
    }

    /// The carried-over table is the source of truth, so its first tick rewrites the log.
    fn resume_persistence(
        config: &MemoryConfig,
        write_handle: &Mutex<MemoryWriter>,
    ) -> Option<Arc<Mutex<Persistence>>> {
        let persistence = config
            .persist_path
            .as_deref()
            .map(|path| Arc::new(Mutex::new(Persistence::resume(path))));
        if persistence.is_none() {
            let mut writer = write_handle.lock().expect("mutex poisoned");
            writer.metadata.dirty.clear();
        }
        persistence
    }

    pub(super) fn get_read_handle(&self) -> &evmap::ReadHandle<String, MemoryEntry> {
        self.read_handle
            .get_or(|| self.read_handle_factory.handle())
    }

    pub(super) fn subscribe_to_expired_items(&self) -> Receiver<Vec<MemoryEntryPair>> {
        self.expired_items_sender.subscribe()
    }

    fn handle_value(&self, value: ObjectMap) {
        let mut writer = self.write_handle.lock().expect("mutex poisoned");
        let now = Instant::now();

        for (k, value) in value.into_iter() {
            let new_entry_key = String::from(k);
            let Ok(v) = serde_json::to_string(&value) else {
                emit!(MemoryEnrichmentTableInsertFailed {
                    key: &new_entry_key,
                    include_key_metric_tag: self.config.internal_metrics.include_key_tag
                });
                continue;
            };
            let new_entry = MemoryEntry {
                value: v,
                update_time: now.into(),
                ttl: self
                    .config
                    .ttl_field
                    .path
                    .as_ref()
                    .and_then(|p| value.get(p))
                    .and_then(|v| v.as_integer())
                    .map(|v| v as u64)
                    .unwrap_or(self.config.ttl),
            };
            let new_entry_size = new_entry_key.size_of() + new_entry.size_of();
            if let Some(max_byte_size) = self.config.max_byte_size
                && writer
                    .metadata
                    .byte_size
                    .saturating_add(new_entry_size as u64)
                    > max_byte_size
            {
                let fits = match self.config.on_full {
                    OnFull::Reject => false,
                    OnFull::EvictOldest => self.make_room(
                        &mut writer,
                        Some(&new_entry_key),
                        new_entry_size as u64,
                        max_byte_size,
                    ),
                };
                if !fits {
                    emit!(MemoryEnrichmentTableInsertFailed {
                        key: &new_entry_key,
                        include_key_metric_tag: self.config.internal_metrics.include_key_tag
                    });
                    continue;
                }
            }
            writer.metadata.byte_size = writer
                .metadata
                .byte_size
                .saturating_add(new_entry_size as u64);
            emit!(MemoryEnrichmentTableInserted {
                key: &new_entry_key,
                include_key_metric_tag: self.config.internal_metrics.include_key_tag
            });
            if self.persistence.is_some() {
                writer.metadata.dirty.insert(new_entry_key.clone());
            }
            writer.write_handle.update(new_entry_key, new_entry);
        }

        if self.config.flush_interval.is_none() {
            self.flush(writer);
        }
    }

    /// Makes room for `new_size` bytes under `key` by removing the least recently written
    /// entries: about 5% of the table, more if the new entry needs it. Evicted entries are
    /// not exported as expired. Returns false, evicting nothing, when the entry cannot fit
    /// even in an otherwise empty table.
    ///
    /// Rejecting at the cap kept stale keys and refused new ones, so a full deduplicating
    /// table stopped deduplicating.
    /// PROVENANCE: OBSERVED fleet data 2026-10-01 (a 4 MiB table rejecting new keys).
    fn make_room(
        &self,
        writer: &mut MutexGuard<'_, MemoryWriter>,
        key: Option<&str>,
        new_size: u64,
        max_byte_size: u64,
    ) -> bool {
        // Publish pending writes so the sizes below are exact.
        writer.write_handle.refresh();
        let mut live = 0u64;
        let mut replaced = 0u64;
        let mut candidates = Vec::new();
        if let Some(reader) = self.get_read_handle().read() {
            candidates.reserve(reader.len());
            for (k, v) in reader.iter() {
                let size = (k.size_of() + v.get_one().size_of()) as u64;
                live += size;
                match v.get_one() {
                    Some(_) if Some(k.as_str()) == key => replaced = size,
                    Some(entry) => candidates.push((*entry.update_time, k.clone(), size)),
                    None => {}
                }
            }
        }
        let needed = (live - replaced + new_size).saturating_sub(max_byte_size);
        let (count, freed) = if needed == 0 {
            (0, 0)
        } else if let Some(selected) = select_oldest(&mut candidates, needed) {
            selected
        } else {
            writer.metadata.byte_size = live;
            return false;
        };
        if count > 0 {
            for (_, k, _) in candidates.drain(..count) {
                writer.write_handle.empty(k);
            }
            writer.write_handle.refresh();
            writer.metadata.evictions_total += count as u64;
            emit!(MemoryEnrichmentTableEvicted { count });
        }
        // The caller adds `new_size`, which replaces `replaced`.
        writer.metadata.byte_size = live - replaced - freed;
        true
    }

    fn scan_and_mark_for_deletion(&self, writer: &mut MutexGuard<'_, MemoryWriter>) -> bool {
        let now = Instant::now();

        let mut needs_flush = false;
        // Since evmap holds 2 separate maps for the data, we are free to directly remove
        // elements via the writer, while we are iterating the reader
        // Refresh will happen only after we manually invoke it after iteration
        if let Some(reader) = self.get_read_handle().read() {
            for (k, v) in reader.iter() {
                if let Some(entry) = v.get_one()
                    && entry.expired(now)
                {
                    // Byte size is not reduced at this point, because the actual deletion
                    // will only happen at refresh time
                    writer.write_handle.empty(k.clone());
                    emit!(MemoryEnrichmentTableTtlExpired {
                        key: k,
                        include_key_metric_tag: self.config.internal_metrics.include_key_tag
                    });
                    needs_flush = true;
                }
            }
        };

        needs_flush
    }

    fn scan(&self, mut writer: MutexGuard<'_, MemoryWriter>) {
        let needs_flush = self.scan_and_mark_for_deletion(&mut writer);
        if needs_flush {
            self.flush(writer);
        }
    }

    fn flush(&self, mut writer: MutexGuard<'_, MemoryWriter>) {
        // First publish items to be removed, if needed
        if self
            .config
            .source_config
            .as_ref()
            .map(|c| c.export_expired_items)
            .unwrap_or_default()
        {
            let pending_removal = writer
                .write_handle
                .pending()
                .iter()
                // We only use empty operation to remove keys
                .filter_map(|o| match o {
                    evmap::Operation::Empty(k) => Some(k),
                    _ => None,
                })
                .filter_map(|key| {
                    writer.write_handle.get_one(key).map(|v| MemoryEntryPair {
                        key: key.to_string(),
                        entry: v.clone(),
                    })
                })
                .collect::<Vec<_>>();
            if let Err(error) = self.expired_items_sender.send(pending_removal) {
                error!(
                    message = "Error exporting expired items from memory enrichment table.",
                    error = %error,
                );
            }
        }

        writer.write_handle.refresh();
        if let Some(reader) = self.get_read_handle().read() {
            let mut byte_size = 0;
            for (k, v) in reader.iter() {
                byte_size += k.size_of() + v.get_one().size_of();
            }
            writer.metadata.byte_size = byte_size as u64;
            emit!(MemoryEnrichmentTableFlushed {
                new_objects_count: reader.len(),
                new_byte_size: byte_size
            });
        }
    }

    /// Collects this tick's persistence write: the rows written since the last tick, or
    /// every live row when the log is due for compaction.
    fn persist_job(&self) -> Option<(Arc<Mutex<Persistence>>, PersistJob)> {
        let persistence = Arc::clone(self.persistence.as_ref()?);
        let mut writer = self.write_handle.lock().expect("mutex poisoned");
        // Publishes pending writes, and a map that was never published reads as None.
        writer.write_handle.refresh();
        let reader = self.get_read_handle().read()?;
        let now = Instant::now();
        let now_unix = persist::unix_now();

        let live_bytes: u64 = reader
            .iter()
            .filter_map(|(k, v)| v.get_one().map(|e| line_estimate(k, &e.value)))
            .sum();
        // Keys evicted or expired since their write are dropped here, so a failing log
        // cannot grow the dirty set past the table.
        let dirty_rows: Vec<PersistRow> = writer
            .metadata
            .dirty
            .drain()
            .filter_map(|k| reader.get_one(&k)?.persist_row(&k, now, now_unix))
            .collect();
        let append_bytes: u64 = dirty_rows
            .iter()
            .map(|r| line_estimate(&r.key, &r.value))
            .sum();

        let compact = persistence
            .lock()
            .expect("mutex poisoned")
            .should_compact(append_bytes, live_bytes);
        let compact_rows = compact.then(|| {
            reader
                .iter()
                .filter_map(|(k, v)| v.get_one()?.persist_row(k, now, now_unix))
                .collect()
        });
        let status = TableStatus {
            entries: reader.len(),
            bytes: writer.metadata.byte_size,
            max_bytes: self.config.max_byte_size,
            evictions_total: writer.metadata.evictions_total,
        };
        Some((
            persistence,
            PersistJob {
                rows: dirty_rows,
                compact_rows,
                status,
            },
        ))
    }

    fn requeue_dirty(&self, keys: Vec<String>) {
        if !keys.is_empty() {
            let mut writer = self.write_handle.lock().expect("mutex poisoned");
            writer.metadata.dirty.extend(keys);
        }
    }

    /// One persistence tick, with the file I/O off the async runtime.
    async fn persist_tick(&self) {
        let Some((persistence, job)) = self.persist_job() else {
            return;
        };
        let requeue = tokio::task::spawn_blocking(move || {
            persistence.lock().expect("mutex poisoned").write(job)
        })
        .await
        .unwrap_or_default();
        self.requeue_dirty(requeue);
    }

    pub(crate) fn as_source(
        &self,
        shutdown: ShutdownSignal,
        out: SourceSender,
        log_namespace: LogNamespace,
    ) -> MemorySource {
        MemorySource {
            memory: self.clone(),
            shutdown,
            out,
            log_namespace,
        }
    }
}

impl Clone for Memory {
    fn clone(&self) -> Self {
        Self {
            read_handle_factory: self.read_handle_factory.clone(),
            read_handle: ThreadLocal::new(),
            write_handle: Arc::clone(&self.write_handle),
            config: self.config.clone(),
            expired_items_sender: self.expired_items_sender.clone(),
            expired_items_receiver: self.expired_items_sender.subscribe(),
            persistence: self.persistence.clone(),
        }
    }
}

const fn line_estimate(key: &str, value: &str) -> u64 {
    (key.len() + value.len()) as u64 + LINE_OVERHEAD
}

/// Moves the oldest entries to the front of `candidates` and returns how many to evict
/// and the bytes that frees: 5% of them (at least one), extended in age order until
/// `needed` bytes are covered. None when all of them together are not enough.
fn select_oldest(candidates: &mut [(Instant, String, u64)], needed: u64) -> Option<(usize, u64)> {
    let n = candidates.len();
    if n == 0 {
        return None;
    }
    let mut count = (n / 20).max(1);
    candidates.select_nth_unstable_by_key(count - 1, |c| c.0);
    let mut freed: u64 = candidates[..count].iter().map(|c| c.2).sum();
    if freed < needed {
        candidates[count..].sort_unstable_by_key(|c| c.0);
        while freed < needed && count < n {
            freed += candidates[count].2;
            count += 1;
        }
    }
    (freed >= needed).then_some((count, freed))
}

impl Table for Memory {
    fn find_table_row<'a>(
        &self,
        case: Case,
        condition: &'a [Condition<'a>],
        select: Option<&'a [String]>,
        wildcard: Option<&Value>,
        index: Option<IndexHandle>,
    ) -> Result<ObjectMap, Error> {
        let mut rows = self.find_table_rows(case, condition, select, wildcard, index)?;

        match rows.pop() {
            Some(row) if rows.is_empty() => Ok(row),
            Some(_) => Err(Error::MoreThanOneRowFound),
            None => Err(Error::NoRowsFound),
        }
    }

    fn find_table_rows<'a>(
        &self,
        _case: Case,
        condition: &'a [Condition<'a>],
        _select: Option<&'a [String]>,
        _wildcard: Option<&Value>,
        _index: Option<IndexHandle>,
    ) -> Result<Vec<ObjectMap>, Error> {
        match condition.first() {
            Some(_) if condition.len() > 1 => Err(Error::OnlyOneConditionAllowed),
            Some(Condition::Equals { value, .. }) => {
                let key = value.to_string_lossy();
                match self.get_read_handle().get_one(key.as_ref()) {
                    Some(row) => {
                        emit!(MemoryEnrichmentTableRead {
                            key: &key,
                            include_key_metric_tag: self.config.internal_metrics.include_key_tag
                        });
                        row.as_object_map(Instant::now(), &key).map(|r| vec![r])
                    }
                    None => {
                        emit!(MemoryEnrichmentTableReadFailed {
                            key: &key,
                            include_key_metric_tag: self.config.internal_metrics.include_key_tag
                        });
                        Ok(Default::default())
                    }
                }
            }
            Some(_) => Err(Error::OnlyEqualityConditionAllowed),
            None => Err(Error::MissingCondition { kind: "Key" }),
        }
    }

    fn add_index(&mut self, _case: Case, fields: &[&str]) -> Result<IndexHandle, Error> {
        match fields.len() {
            0 => Err(Error::MissingRequiredField { field: "Key" }),
            1 => Ok(IndexHandle(0)),
            _ => Err(Error::OnlyOneFieldAllowed),
        }
    }

    /// Returns a list of the field names that are in each index
    fn index_fields(&self) -> Vec<(Case, Vec<String>)> {
        Vec::new()
    }

    /// Doesn't need reload, data is written directly
    fn needs_reload(&self) -> bool {
        false
    }

    fn extract_state(&self) -> Option<Box<dyn std::any::Any + Send + Sync>> {
        let writer = self.write_handle.lock().expect("mutex poisoned");
        self.flush(writer);
        Some(Box::new(self.clone()))
    }
}

impl std::fmt::Debug for Memory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Memory {} row(s)", self.get_read_handle().len())
    }
}

#[async_trait]
impl StreamSink<Event> for Memory {
    async fn run(mut self: Box<Self>, mut input: BoxStream<'_, Event>) -> Result<(), ()> {
        let events_sent = register!(EventsSent::from(Output(None)));
        let bytes_sent = register!(BytesSent::from(Protocol("memory_enrichment_table".into(),)));
        // No interval at all when unset: a `Duration::MAX` period panics on overflow once
        // its first tick is polled more than 5 ms late, which a slow first scan or
        // persistence write causes.
        let mut flush_interval = self
            .config
            .flush_interval
            .map(|secs| IntervalStream::new(interval(Duration::from_secs(secs))));
        let mut scan_interval = IntervalStream::new(interval(Duration::from_secs(
            self.config.scan_interval.into(),
        )));

        loop {
            tokio::select! {
                event = input.next() => {
                    let mut event = if let Some(event) = event {
                        event
                    } else {
                        break;
                    };
                    let event_byte_size = event.estimated_json_encoded_size_of();

                    let finalizers = event.take_finalizers();

                    // Panic: This sink only accepts Logs, so this should never panic
                    let log = event.into_log();

                    if let (Value::Object(map), _) = log.into_parts() {
                        self.handle_value(map)
                    };

                    finalizers.update_status(EventStatus::Delivered);
                    events_sent.emit(CountByteSize(1, event_byte_size));
                    bytes_sent.emit(ByteSize(event_byte_size.get()));
                }

                Some(_) = async {
                    match flush_interval.as_mut() {
                        Some(flush_interval) => flush_interval.next().await,
                        None => std::future::pending().await,
                    }
                } => {
                    let writer = self.write_handle.lock().expect("mutex poisoned");
                    self.flush(writer);
                }

                Some(_) = scan_interval.next() => {
                    let writer = self.write_handle.lock().expect("mutex poisoned");
                    self.scan(writer);
                    // The first tick fires at startup, so an oversized log is compacted then.
                    self.persist_tick().await;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{num::NonZeroU64, slice::from_ref, time::Duration};

    use futures::{StreamExt, future::ready};
    use futures_util::stream;
    use tokio::time;

    use vector_lib::{
        event::{EventContainer, MetricValue},
        lookup::lookup_v2::OptionalValuePath,
        metrics::Controller,
        sink::VectorSink,
    };

    use super::*;
    use crate::{
        config::EnrichmentTableConfig,
        enrichment_tables::memory::{
            config::MemorySourceConfig, internal_events::InternalMetricsConfig,
        },
        event::{Event, LogEvent},
        test_util::components::{
            SINK_TAGS, SOURCE_TAGS, run_and_assert_sink_compliance,
            run_and_assert_source_compliance,
        },
    };

    fn build_memory_config(modfn: impl Fn(&mut MemoryConfig)) -> MemoryConfig {
        let mut config = MemoryConfig::default();
        modfn(&mut config);
        config
    }

    #[test]
    fn finds_row() {
        let memory = Memory::new(Default::default());
        memory.handle_value(ObjectMap::from([("test_key".into(), Value::from(5))]));

        let condition = Condition::Equals {
            field: "key",
            value: Value::from("test_key"),
        };

        assert_eq!(
            Ok(ObjectMap::from([
                ("key".into(), Value::from("test_key")),
                ("ttl".into(), Value::from(memory.config.ttl)),
                ("value".into(), Value::from(5)),
            ])),
            memory.find_table_row(Case::Sensitive, &[condition], None, None, None)
        );
    }

    #[tokio::test]
    async fn extract_state_preserves_data() {
        let memory = Memory::new(Default::default());
        memory.handle_value(ObjectMap::from([("test_key".into(), Value::from(5))]));

        let condition = Condition::Equals {
            field: "key",
            value: Value::from("test_key"),
        };

        let expected = ObjectMap::from([
            ("key".into(), Value::from("test_key")),
            ("ttl".into(), Value::from(memory.config.ttl)),
            ("value".into(), Value::from(5)),
        ]);
        assert_eq!(
            Ok(expected.clone()),
            memory.find_table_row(
                Case::Sensitive,
                std::slice::from_ref(&condition),
                None,
                None,
                None
            )
        );

        // Now build a new table using old state
        let new_memory = MemoryConfig::default()
            .build(&Default::default(), memory.extract_state())
            .await
            .unwrap();
        assert_eq!(
            Ok(expected),
            new_memory.find_table_row(Case::Sensitive, &[condition], None, None, None)
        );
    }

    #[test]
    fn calculates_ttl() {
        let ttl = 100;
        let secs_to_subtract = 10;
        let memory = Memory::new(build_memory_config(|c| c.ttl = ttl));
        {
            let mut handle = memory.write_handle.lock().unwrap();
            handle.write_handle.update(
                "test_key".to_string(),
                MemoryEntry {
                    value: "5".to_string(),
                    update_time: (Instant::now() - Duration::from_secs(secs_to_subtract)).into(),
                    ttl,
                },
            );
            handle.write_handle.refresh();
        }

        let condition = Condition::Equals {
            field: "key",
            value: Value::from("test_key"),
        };

        assert_eq!(
            Ok(ObjectMap::from([
                ("key".into(), Value::from("test_key")),
                ("ttl".into(), Value::from(ttl - secs_to_subtract)),
                ("value".into(), Value::from(5)),
            ])),
            memory.find_table_row(Case::Sensitive, &[condition], None, None, None)
        );
    }

    #[test]
    fn calculates_ttl_override() {
        let global_ttl = 100;
        let ttl_override = 10;
        let memory = Memory::new(build_memory_config(|c| {
            c.ttl = global_ttl;
            c.ttl_field = OptionalValuePath::new("ttl");
        }));
        memory.handle_value(ObjectMap::from([
            (
                "ttl_override".into(),
                Value::from(ObjectMap::from([
                    ("val".into(), Value::from(5)),
                    ("ttl".into(), Value::from(ttl_override)),
                ])),
            ),
            (
                "default_ttl".into(),
                Value::from(ObjectMap::from([("val".into(), Value::from(5))])),
            ),
        ]));

        let default_condition = Condition::Equals {
            field: "key",
            value: Value::from("default_ttl"),
        };
        let override_condition = Condition::Equals {
            field: "key",
            value: Value::from("ttl_override"),
        };

        assert_eq!(
            Ok(ObjectMap::from([
                ("key".into(), Value::from("default_ttl")),
                ("ttl".into(), Value::from(global_ttl)),
                (
                    "value".into(),
                    Value::from(ObjectMap::from([("val".into(), Value::from(5))]))
                ),
            ])),
            memory.find_table_row(Case::Sensitive, &[default_condition], None, None, None)
        );
        assert_eq!(
            Ok(ObjectMap::from([
                ("key".into(), Value::from("ttl_override")),
                ("ttl".into(), Value::from(ttl_override)),
                (
                    "value".into(),
                    Value::from(ObjectMap::from([
                        ("val".into(), Value::from(5)),
                        ("ttl".into(), Value::from(ttl_override))
                    ]))
                ),
            ])),
            memory.find_table_row(Case::Sensitive, &[override_condition], None, None, None)
        );
    }

    #[test]
    fn removes_expired_records_on_scan_interval() {
        let ttl = 100;
        let memory = Memory::new(build_memory_config(|c| {
            c.ttl = ttl;
        }));
        {
            let mut handle = memory.write_handle.lock().unwrap();
            handle.write_handle.update(
                "test_key".to_string(),
                MemoryEntry {
                    value: "5".to_string(),
                    update_time: (Instant::now() - Duration::from_secs(ttl + 10)).into(),
                    ttl,
                },
            );
            handle.write_handle.refresh();
        }

        // Finds the value before scan
        let condition = Condition::Equals {
            field: "key",
            value: Value::from("test_key"),
        };
        assert_eq!(
            Ok(ObjectMap::from([
                ("key".into(), Value::from("test_key")),
                ("ttl".into(), Value::from(0)),
                ("value".into(), Value::from(5)),
            ])),
            memory.find_table_row(Case::Sensitive, from_ref(&condition), None, None, None)
        );

        // Force scan
        let writer = memory.write_handle.lock().unwrap();
        memory.scan(writer);

        // The value is not present anymore
        assert!(
            memory
                .find_table_rows(Case::Sensitive, &[condition], None, None, None)
                .unwrap()
                .pop()
                .is_none()
        );
    }

    #[test]
    fn does_not_show_values_before_flush_interval() {
        let ttl = 100;
        let memory = Memory::new(build_memory_config(|c| {
            c.ttl = ttl;
            c.flush_interval = Some(10);
        }));
        memory.handle_value(ObjectMap::from([("test_key".into(), Value::from(5))]));

        let condition = Condition::Equals {
            field: "key",
            value: Value::from("test_key"),
        };

        assert!(
            memory
                .find_table_rows(Case::Sensitive, &[condition], None, None, None)
                .unwrap()
                .pop()
                .is_none()
        );
    }

    #[test]
    fn updates_ttl_on_value_replacement() {
        let ttl = 100;
        let memory = Memory::new(build_memory_config(|c| c.ttl = ttl));
        {
            let mut handle = memory.write_handle.lock().unwrap();
            handle.write_handle.update(
                "test_key".to_string(),
                MemoryEntry {
                    value: "5".to_string(),
                    update_time: (Instant::now() - Duration::from_secs(ttl / 2)).into(),
                    ttl,
                },
            );
            handle.write_handle.refresh();
        }
        let condition = Condition::Equals {
            field: "key",
            value: Value::from("test_key"),
        };

        assert_eq!(
            Ok(ObjectMap::from([
                ("key".into(), Value::from("test_key")),
                ("ttl".into(), Value::from(ttl / 2)),
                ("value".into(), Value::from(5)),
            ])),
            memory.find_table_row(Case::Sensitive, from_ref(&condition), None, None, None)
        );

        memory.handle_value(ObjectMap::from([("test_key".into(), Value::from(5))]));

        assert_eq!(
            Ok(ObjectMap::from([
                ("key".into(), Value::from("test_key")),
                ("ttl".into(), Value::from(ttl)),
                ("value".into(), Value::from(5)),
            ])),
            memory.find_table_row(Case::Sensitive, &[condition], None, None, None)
        );
    }

    #[test]
    fn ignores_all_values_over_byte_size_limit() {
        let memory = Memory::new(build_memory_config(|c| {
            c.max_byte_size = Some(1);
        }));
        memory.handle_value(ObjectMap::from([("test_key".into(), Value::from(5))]));

        let condition = Condition::Equals {
            field: "key",
            value: Value::from("test_key"),
        };

        assert!(
            memory
                .find_table_rows(Case::Sensitive, &[condition], None, None, None)
                .unwrap()
                .pop()
                .is_none()
        );
    }

    #[test]
    fn ignores_values_when_byte_size_limit_is_reached() {
        let ttl = 100;
        let memory = Memory::new(build_memory_config(|c| {
            c.ttl = ttl;
            c.max_byte_size = Some(150);
        }));
        memory.handle_value(ObjectMap::from([("test_key".into(), Value::from(5))]));
        memory.handle_value(ObjectMap::from([("rejected_key".into(), Value::from(5))]));

        assert_eq!(
            Ok(ObjectMap::from([
                ("key".into(), Value::from("test_key")),
                ("ttl".into(), Value::from(ttl)),
                ("value".into(), Value::from(5)),
            ])),
            memory.find_table_row(
                Case::Sensitive,
                &[Condition::Equals {
                    field: "key",
                    value: Value::from("test_key")
                }],
                None,
                None,
                None
            )
        );

        assert!(
            memory
                .find_table_rows(
                    Case::Sensitive,
                    &[Condition::Equals {
                        field: "key",
                        value: Value::from("rejected_key")
                    }],
                    None,
                    None,
                    None
                )
                .unwrap()
                .pop()
                .is_none()
        );
    }

    #[test]
    fn missing_key() {
        let memory = Memory::new(Default::default());

        let condition = Condition::Equals {
            field: "key",
            value: Value::from("test_key"),
        };

        assert!(
            memory
                .find_table_rows(Case::Sensitive, &[condition], None, None, None)
                .unwrap()
                .pop()
                .is_none()
        );
    }

    #[tokio::test]
    async fn sink_spec_compliance() {
        let event = Event::Log(LogEvent::from(ObjectMap::from([(
            "test_key".into(),
            Value::from(5),
        )])));

        let memory = Memory::new(Default::default());

        run_and_assert_sink_compliance(
            VectorSink::from_event_streamsink(memory),
            stream::once(ready(event)),
            &SINK_TAGS,
        )
        .await;
    }

    #[tokio::test]
    async fn flush_metrics_without_interval() {
        let event = Event::Log(LogEvent::from(ObjectMap::from([(
            "test_key".into(),
            Value::from(5),
        )])));

        let memory = Memory::new(Default::default());

        run_and_assert_sink_compliance(
            VectorSink::from_event_streamsink(memory),
            stream::once(ready(event)),
            &SINK_TAGS,
        )
        .await;

        let metrics = Controller::get().unwrap().capture_metrics();
        let insertions_counter = metrics
            .iter()
            .find(|m| {
                matches!(m.value(), MetricValue::Counter { .. })
                    && m.name() == "memory_enrichment_table_insertions_total"
            })
            .expect("Insertions metric is missing!");
        let MetricValue::Counter {
            value: insertions_count,
        } = insertions_counter.value()
        else {
            unreachable!();
        };
        let flushes_counter = metrics
            .iter()
            .find(|m| {
                matches!(m.value(), MetricValue::Counter { .. })
                    && m.name() == "memory_enrichment_table_flushes_total"
            })
            .expect("Flushes metric is missing!");
        let MetricValue::Counter {
            value: flushes_count,
        } = flushes_counter.value()
        else {
            unreachable!();
        };
        let object_count_gauge = metrics
            .iter()
            .find(|m| {
                matches!(m.value(), MetricValue::Gauge { .. })
                    && m.name() == "memory_enrichment_table_objects_count"
            })
            .expect("Object count metric is missing!");
        let MetricValue::Gauge {
            value: object_count,
        } = object_count_gauge.value()
        else {
            unreachable!();
        };
        let byte_size_gauge = metrics
            .iter()
            .find(|m| {
                matches!(m.value(), MetricValue::Gauge { .. })
                    && m.name() == "memory_enrichment_table_byte_size"
            })
            .expect("Byte size metric is missing!");
        assert_eq!(*insertions_count, 1.0);
        assert_eq!(*flushes_count, 1.0);
        assert_eq!(*object_count, 1.0);
        assert!(!byte_size_gauge.is_empty());
    }

    #[tokio::test]
    async fn flush_metrics_with_interval() {
        let event = Event::Log(LogEvent::from(ObjectMap::from([(
            "test_key".into(),
            Value::from(5),
        )])));

        let memory = Memory::new(build_memory_config(|c| {
            c.flush_interval = Some(1);
        }));

        run_and_assert_sink_compliance(
            VectorSink::from_event_streamsink(memory),
            stream::iter(vec![event.clone(), event]).flat_map(|e| {
                stream::once(async move {
                    tokio::time::sleep(Duration::from_millis(600)).await;
                    e
                })
            }),
            &SINK_TAGS,
        )
        .await;

        let metrics = Controller::get().unwrap().capture_metrics();
        let insertions_counter = metrics
            .iter()
            .find(|m| {
                matches!(m.value(), MetricValue::Counter { .. })
                    && m.name() == "memory_enrichment_table_insertions_total"
            })
            .expect("Insertions metric is missing!");
        let MetricValue::Counter {
            value: insertions_count,
        } = insertions_counter.value()
        else {
            unreachable!();
        };
        let flushes_counter = metrics
            .iter()
            .find(|m| {
                matches!(m.value(), MetricValue::Counter { .. })
                    && m.name() == "memory_enrichment_table_flushes_total"
            })
            .expect("Flushes metric is missing!");
        let MetricValue::Counter {
            value: flushes_count,
        } = flushes_counter.value()
        else {
            unreachable!();
        };
        let object_count_gauge = metrics
            .iter()
            .find(|m| {
                matches!(m.value(), MetricValue::Gauge { .. })
                    && m.name() == "memory_enrichment_table_objects_count"
            })
            .expect("Object count metric is missing!");
        let MetricValue::Gauge {
            value: object_count,
        } = object_count_gauge.value()
        else {
            unreachable!();
        };
        let byte_size_gauge = metrics
            .iter()
            .find(|m| {
                matches!(m.value(), MetricValue::Gauge { .. })
                    && m.name() == "memory_enrichment_table_byte_size"
            })
            .expect("Byte size metric is missing!");

        assert_eq!(*insertions_count, 2.0);
        // One is done right away and the next one after the interval
        assert_eq!(*flushes_count, 2.0);
        assert_eq!(*object_count, 1.0);
        assert!(!byte_size_gauge.is_empty());
    }

    #[tokio::test]
    async fn flush_metrics_with_key() {
        let event = Event::Log(LogEvent::from(ObjectMap::from([(
            "test_key".into(),
            Value::from(5),
        )])));

        let memory = Memory::new(build_memory_config(|c| {
            c.internal_metrics = InternalMetricsConfig {
                include_key_tag: true,
            };
        }));

        run_and_assert_sink_compliance(
            VectorSink::from_event_streamsink(memory),
            stream::once(ready(event)),
            &SINK_TAGS,
        )
        .await;

        let metrics = Controller::get().unwrap().capture_metrics();
        let insertions_counter = metrics
            .iter()
            .find(|m| {
                matches!(m.value(), MetricValue::Counter { .. })
                    && m.name() == "memory_enrichment_table_insertions_total"
            })
            .expect("Insertions metric is missing!");

        assert!(insertions_counter.tag_matches("key", "test_key"));
    }

    #[tokio::test]
    async fn flush_metrics_without_key() {
        let event = Event::Log(LogEvent::from(ObjectMap::from([(
            "test_key".into(),
            Value::from(5),
        )])));

        let memory = Memory::new(Default::default());

        run_and_assert_sink_compliance(
            VectorSink::from_event_streamsink(memory),
            stream::once(ready(event)),
            &SINK_TAGS,
        )
        .await;

        let metrics = Controller::get().unwrap().capture_metrics();
        let insertions_counter = metrics
            .iter()
            .find(|m| {
                matches!(m.value(), MetricValue::Counter { .. })
                    && m.name() == "memory_enrichment_table_insertions_total"
            })
            .expect("Insertions metric is missing!");

        assert!(insertions_counter.tag_value("key").is_none());
    }

    #[tokio::test]
    async fn source_spec_compliance() {
        let mut memory_config = MemoryConfig::default();
        memory_config.source_config = Some(MemorySourceConfig {
            export_interval: Some(NonZeroU64::try_from(1).unwrap()),
            export_batch_size: None,
            remove_after_export: false,
            export_expired_items: false,
            source_key: "test".to_string(),
        });
        let memory = memory_config.get_or_build_memory(None).await;
        memory.handle_value(ObjectMap::from([("test_key".into(), Value::from(5))]));

        let mut events: Vec<Event> = run_and_assert_source_compliance(
            memory_config,
            time::Duration::from_secs(5),
            &SOURCE_TAGS,
        )
        .await;

        assert!(!events.is_empty());
        let event = events.remove(0);
        let log = event.as_log();

        assert!(!log.value().is_empty());
    }

    fn find(memory: &Memory, key: &str) -> Option<ObjectMap> {
        memory
            .find_table_rows(
                Case::Sensitive,
                &[Condition::Equals {
                    field: "key",
                    value: Value::from(key),
                }],
                None,
                None,
                None,
            )
            .unwrap()
            .pop()
    }

    fn ttl_of(memory: &Memory, key: &str) -> i64 {
        find(memory, key).unwrap()["ttl"].as_integer().unwrap()
    }

    /// Writes `count` entries aged `count - i` seconds, so `key_00` is the oldest, and
    /// returns the table's byte size.
    fn fill_aged(memory: &Memory, count: usize, value: &str) -> u64 {
        let mut writer = memory.write_handle.lock().unwrap();
        let now = Instant::now();
        for i in 0..count {
            writer.write_handle.update(
                format!("key_{i:02}"),
                MemoryEntry {
                    value: value.to_string(),
                    update_time: (now - Duration::from_secs((count - i) as u64)).into(),
                    ttl: 1000,
                },
            );
        }
        writer.write_handle.refresh();
        let size = memory.live_byte_size();
        writer.metadata.byte_size = size;
        size
    }

    fn evictions_total(memory: &Memory) -> u64 {
        memory.write_handle.lock().unwrap().metadata.evictions_total
    }

    #[test]
    fn evict_oldest_removes_oldest_five_percent_to_fit() {
        let probe = Memory::new(Default::default());
        let full = fill_aged(&probe, 40, "5");
        let memory = Memory::new(build_memory_config(|c| {
            c.on_full = OnFull::EvictOldest;
            c.max_byte_size = Some(full);
        }));
        fill_aged(&memory, 40, "5");

        memory.handle_value(ObjectMap::from([("key_new".into(), Value::from(5))]));

        assert!(find(&memory, "key_00").is_none());
        assert!(find(&memory, "key_01").is_none());
        for i in 2..40 {
            assert!(
                find(&memory, &format!("key_{i:02}")).is_some(),
                "key_{i:02}"
            );
        }
        assert!(find(&memory, "key_new").is_some());
        assert_eq!(evictions_total(&memory), 2);
    }

    #[test]
    fn evict_oldest_removes_enough_for_a_large_entry() {
        let probe = Memory::new(Default::default());
        let full = fill_aged(&probe, 40, "5");
        let memory = Memory::new(build_memory_config(|c| {
            c.on_full = OnFull::EvictOldest;
            c.max_byte_size = Some(full);
        }));
        fill_aged(&memory, 40, "5");

        let large = "x".repeat(400);
        memory.handle_value(ObjectMap::from([("key_new".into(), Value::from(large))]));

        assert!(find(&memory, "key_new").is_some());
        let evicted = evictions_total(&memory) as usize;
        assert!(evicted > 2, "evicted {evicted}");
        for i in 0..40 {
            let present = find(&memory, &format!("key_{i:02}")).is_some();
            assert_eq!(present, i >= evicted, "key_{i:02}");
        }
        assert!(memory.write_handle.lock().unwrap().metadata.byte_size <= full);
    }

    #[test]
    fn evict_oldest_rejects_an_entry_larger_than_the_table() {
        let memory = Memory::new(build_memory_config(|c| {
            c.on_full = OnFull::EvictOldest;
            c.max_byte_size = Some(150);
        }));
        memory.handle_value(ObjectMap::from([("small".into(), Value::from(5))]));
        let large = "x".repeat(400);
        memory.handle_value(ObjectMap::from([("large".into(), Value::from(large))]));

        assert!(find(&memory, "small").is_some());
        assert!(find(&memory, "large").is_none());
        assert_eq!(evictions_total(&memory), 0);
    }

    #[test]
    fn reject_keeps_old_entries_at_the_cap() {
        let probe = Memory::new(Default::default());
        let full = fill_aged(&probe, 40, "5");
        let memory = Memory::new(build_memory_config(|c| {
            c.on_full = OnFull::Reject;
            c.max_byte_size = Some(full);
        }));
        fill_aged(&memory, 40, "5");

        memory.handle_value(ObjectMap::from([("key_new".into(), Value::from(5))]));

        assert!(find(&memory, "key_new").is_none());
        assert!(find(&memory, "key_00").is_some());
        assert_eq!(evictions_total(&memory), 0);
    }

    fn persist_config(path: &std::path::Path) -> MemoryConfig {
        build_memory_config(|c| {
            c.ttl = 100;
            c.persist_path = Some(path.to_path_buf());
        })
    }

    /// One tick's persistence write, run inline.
    fn persist_now(memory: &Memory) {
        let (persistence, job) = memory.persist_job().unwrap();
        let requeue = persistence.lock().unwrap().write(job);
        memory.requeue_dirty(requeue);
    }

    fn failed_ticks(memory: &Memory) -> u64 {
        memory
            .persistence
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .failed_ticks()
    }

    fn log_lines(path: &std::path::Path) -> usize {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .filter(|l| !l.is_empty())
            .count()
    }

    fn read_status(path: &std::path::Path) -> persist::StatusFile {
        serde_json::from_slice(&std::fs::read(persist::status_path(path)).unwrap()).unwrap()
    }

    #[test]
    fn persistence_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("table.ndjson");
        let config = persist_config(&path);

        let memory = Memory::new(config.clone());
        memory.handle_value(ObjectMap::from([
            ("fresh".into(), Value::from(5)),
            (
                "object".into(),
                Value::from(ObjectMap::from([("a".into(), Value::from("b"))])),
            ),
        ]));
        {
            let mut writer = memory.write_handle.lock().unwrap();
            writer.write_handle.update(
                "aged".to_string(),
                MemoryEntry {
                    value: "7".to_string(),
                    update_time: (Instant::now() - Duration::from_secs(30)).into(),
                    ttl: 100,
                },
            );
            writer.metadata.dirty.insert("aged".to_string());
        }
        persist_now(&memory);
        drop(memory);

        let expired = format!(
            "{{\"k\":\"expired\",\"v\":1,\"exp\":{}}}\n",
            persist::unix_now() - 10
        );
        let mut log = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        std::io::Write::write_all(&mut log, expired.as_bytes()).unwrap();
        drop(log);

        let memory = Memory::new(config);
        assert_eq!(find(&memory, "fresh").unwrap()["value"], Value::from(5));
        assert_eq!(
            find(&memory, "object").unwrap()["value"],
            Value::from(ObjectMap::from([("a".into(), Value::from("b"))]))
        );
        assert_eq!(find(&memory, "aged").unwrap()["value"], Value::from(7));
        assert!(find(&memory, "expired").is_none());
        assert!((99..=100).contains(&ttl_of(&memory, "fresh")));
        assert!((69..=70).contains(&ttl_of(&memory, "aged")));
        assert_eq!(
            memory.write_handle.lock().unwrap().metadata.byte_size,
            memory.live_byte_size()
        );
    }

    #[test]
    fn load_clamps_a_far_future_expiry_to_the_ttl() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("table.ndjson");
        let exp = persist::unix_now() + 1_000_000_000;
        std::fs::write(&path, format!("{{\"k\":\"a\",\"v\":1,\"exp\":{exp}}}\n")).unwrap();

        let memory = Memory::new(persist_config(&path));

        assert_eq!(ttl_of(&memory, "a"), 100);
    }

    #[test]
    fn load_with_the_clock_at_the_epoch_clamps_to_the_ttl() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("table.ndjson");
        let exp = persist::unix_now() + 50;
        std::fs::write(&path, format!("{{\"k\":\"a\",\"v\":1,\"exp\":{exp}}}\n")).unwrap();

        let (_, rows) = Persistence::open_at(&path, 0);
        let memory = Memory::new(build_memory_config(|c| c.ttl = 100));
        memory.restore(rows);

        assert_eq!(ttl_of(&memory, "a"), 100);
    }

    #[test]
    fn load_evicts_oldest_when_over_the_cap() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("table.ndjson");
        let now = persist::unix_now();
        let lines: String = (0..40)
            .map(|i| {
                format!(
                    "{{\"k\":\"key_{i:02}\",\"v\":5,\"exp\":{}}}\n",
                    now + 50 + i
                )
            })
            .collect();
        std::fs::write(&path, lines).unwrap();

        let probe = Memory::new(Default::default());
        let full = fill_aged(&probe, 40, "5");
        let memory = Memory::new(build_memory_config(|c| {
            c.ttl = 100;
            c.persist_path = Some(path.clone());
            c.max_byte_size = Some(full - 1);
        }));

        assert!(find(&memory, "key_00").is_none());
        assert!(find(&memory, "key_02").is_some());
        assert!(memory.write_handle.lock().unwrap().metadata.byte_size < full);
    }

    #[test]
    fn compacts_an_oversized_log_at_startup() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("table.ndjson");
        let exp = persist::unix_now() + 50;
        let lines: String = (0..10)
            .map(|i| format!("{{\"k\":\"a\",\"v\":{i},\"exp\":{exp}}}\n"))
            .collect();
        std::fs::write(&path, lines).unwrap();

        let memory = Memory::new(persist_config(&path));
        assert_eq!(find(&memory, "a").unwrap()["value"], Value::from(9));
        persist_now(&memory);

        assert_eq!(log_lines(&path), 1);
        let memory = Memory::new(persist_config(&path));
        assert_eq!(find(&memory, "a").unwrap()["value"], Value::from(9));
    }

    #[test]
    fn leaves_a_compact_log_alone_at_startup() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("table.ndjson");
        let exp = persist::unix_now() + 50;
        let lines: String = ["a", "b", "c"]
            .iter()
            .map(|k| format!("{{\"k\":\"{k}\",\"v\":1,\"exp\":{exp}}}\n"))
            .collect();
        std::fs::write(&path, &lines).unwrap();

        let memory = Memory::new(persist_config(&path));
        persist_now(&memory);

        assert_eq!(std::fs::read_to_string(&path).unwrap(), lines);
    }

    #[test]
    fn compacts_at_a_tick_past_twice_the_live_size() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("table.ndjson");
        let memory = Memory::new(persist_config(&path));

        let mut lines = Vec::new();
        for _ in 0..3 {
            memory.handle_value(ObjectMap::from([("a".into(), Value::from(5))]));
            persist_now(&memory);
            lines.push(log_lines(&path));
        }

        // Each tick appends one line for the one live row until the log would pass
        // twice the live size; that tick rewrites it instead.
        assert_eq!(lines, vec![1, 2, 1]);
    }

    #[test]
    fn skips_corrupt_lines_on_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("table.ndjson");
        let exp = persist::unix_now() + 50;
        std::fs::write(
            &path,
            format!(
                "{{\"k\":\"a\",\"v\":1,\"exp\":{exp}}}\nnot json\n{{\"k\":\"b\",\"v\":2,\"exp\":{exp}}}\n{{\"k\":\"torn\""
            ),
        )
        .unwrap();

        let memory = Memory::new(persist_config(&path));
        assert!(find(&memory, "a").is_some());
        assert!(find(&memory, "b").is_some());
        assert!(find(&memory, "torn").is_none());

        // The next append starts on a fresh line, so the torn tail does not swallow it.
        memory.handle_value(ObjectMap::from([("c".into(), Value::from(3))]));
        persist_now(&memory);
        let memory = Memory::new(persist_config(&path));
        assert_eq!(find(&memory, "c").unwrap()["value"], Value::from(3));
        assert!(find(&memory, "a").is_some());
    }

    #[test]
    fn a_log_with_no_readable_line_is_not_compacted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("table.ndjson");
        std::fs::write(&path, "not json\nstill not json\n").unwrap();

        let memory = Memory::new(persist_config(&path));
        persist_now(&memory);

        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "not json\nstill not json\n"
        );
    }

    #[test]
    fn failed_append_keeps_the_log_and_retries_its_rows() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("table.ndjson");
        let memory = Memory::new(persist_config(&path));
        memory.handle_value(ObjectMap::from([("a".into(), Value::from(1))]));
        persist_now(&memory);
        let before = std::fs::read(&path).unwrap();

        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_readonly(true);
        std::fs::set_permissions(&path, perms.clone()).unwrap();
        memory.handle_value(ObjectMap::from([("b".into(), Value::from(2))]));
        persist_now(&memory);
        persist_now(&memory);

        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert_eq!(failed_ticks(&memory), 2);
        let status = read_status(&path);
        assert!(status.persist_failing);
        assert_eq!(status.failed_ticks, 2);

        #[allow(clippy::permissions_set_readonly_false)]
        perms.set_readonly(false);
        std::fs::set_permissions(&path, perms).unwrap();
        persist_now(&memory);

        assert_eq!(failed_ticks(&memory), 0);
        assert!(!read_status(&path).persist_failing);
        let memory = Memory::new(persist_config(&path));
        assert_eq!(find(&memory, "b").unwrap()["value"], Value::from(2));
    }

    #[test]
    fn failing_writes_keep_the_dirty_set_within_the_table() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing").join("table.ndjson");
        let probe = Memory::new(Default::default());
        let full = fill_aged(&probe, 40, "5");
        let memory = Memory::new(build_memory_config(|c| {
            c.persist_path = Some(path.clone());
            c.on_full = OnFull::EvictOldest;
            c.max_byte_size = Some(full);
        }));

        for i in 0..400 {
            memory.handle_value(ObjectMap::from([(
                format!("w_{i:03}").into(),
                Value::from(5),
            )]));
            if i % 10 == 9 {
                persist_now(&memory);
                let live = memory.get_read_handle().len();
                let dirty = memory.write_handle.lock().unwrap().metadata.dirty.len();
                assert!(dirty <= live, "dirty {dirty} > live {live}");
            }
        }
        assert_eq!(failed_ticks(&memory), 40);
    }

    #[test]
    fn missing_directory_fails_without_panicking() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing").join("table.ndjson");
        let memory = Memory::new(persist_config(&path));
        memory.handle_value(ObjectMap::from([("a".into(), Value::from(1))]));
        persist_now(&memory);
        persist_now(&memory);

        assert_eq!(failed_ticks(&memory), 2);
        assert!(!path.exists());
        assert!(find(&memory, "a").is_some());
    }

    #[test]
    fn failed_compaction_keeps_the_old_log() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("table.ndjson");
        let exp = persist::unix_now() + 50;
        let lines: String = (0..10)
            .map(|i| format!("{{\"k\":\"a\",\"v\":{i},\"exp\":{exp}}}\n"))
            .collect();
        std::fs::write(&path, &lines).unwrap();
        // A directory where the temporary file goes makes the rewrite fail.
        std::fs::create_dir(dir.path().join("table.ndjson.tmp")).unwrap();

        let memory = Memory::new(persist_config(&path));
        persist_now(&memory);

        assert_eq!(std::fs::read_to_string(&path).unwrap(), lines);
        assert_eq!(failed_ticks(&memory), 1);
    }

    #[test]
    fn failed_compaction_still_appends_the_tick_rows() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("table.ndjson");
        let exp = persist::unix_now() + 50;
        let lines: String = (0..10)
            .map(|i| format!("{{\"k\":\"a\",\"v\":{i},\"exp\":{exp}}}\n"))
            .collect();
        std::fs::write(&path, &lines).unwrap();
        std::fs::create_dir(dir.path().join("table.ndjson.tmp")).unwrap();

        let memory = Memory::new(persist_config(&path));
        memory.handle_value(ObjectMap::from([("b".into(), Value::from(2))]));
        persist_now(&memory);

        let log = std::fs::read_to_string(&path).unwrap();
        assert!(log.starts_with(&lines));
        assert_eq!(log_lines(&path), 11);
        assert!(read_status(&path).persist_failing);
        // The appended row is not queued again.
        assert!(
            memory
                .write_handle
                .lock()
                .unwrap()
                .metadata
                .dirty
                .is_empty()
        );
        let memory = Memory::new(persist_config(&path));
        assert_eq!(find(&memory, "b").unwrap()["value"], Value::from(2));
        assert_eq!(find(&memory, "a").unwrap()["value"], Value::from(9));
    }

    #[tokio::test]
    async fn sink_persists_on_the_scan_tick() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("table.ndjson");
        let config = build_memory_config(|c| {
            c.persist_path = Some(path.clone());
            c.scan_interval = NonZeroU64::new(1).unwrap();
        });
        let event = Event::Log(LogEvent::from(ObjectMap::from([(
            "test_key".into(),
            Value::from(5),
        )])));
        // Keep the sink running past one scan tick after the event.
        let wait =
            stream::once(time::sleep(Duration::from_millis(1500))).filter_map(|()| ready(None));

        VectorSink::from_event_streamsink(Memory::new(config.clone()))
            .run(stream::once(ready(event)).chain(wait).map(Into::into))
            .await
            .unwrap();

        let memory = Memory::new(config);
        assert_eq!(find(&memory, "test_key").unwrap()["value"], Value::from(5));
        assert!(persist::status_path(&path).exists());
    }

    #[test]
    fn writes_the_status_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("table.ndjson");
        let memory = Memory::new(build_memory_config(|c| {
            c.persist_path = Some(path.clone());
            c.max_byte_size = Some(1 << 20);
        }));
        memory.handle_value(ObjectMap::from([
            ("a".into(), Value::from(1)),
            ("b".into(), Value::from(2)),
        ]));
        let before = persist::unix_now();
        persist_now(&memory);

        let status = read_status(&path);
        let last = status.last_snapshot_unix.unwrap();
        assert!(last >= before && last <= persist::unix_now());
        assert_eq!(
            status,
            persist::StatusFile {
                entries: 2,
                bytes: memory.live_byte_size(),
                max_bytes: Some(1 << 20),
                evictions_total: 0,
                persist_failing: false,
                failed_ticks: 0,
                last_snapshot_unix: Some(last),
            }
        );
        let raw: serde_json::Value =
            serde_json::from_slice(&std::fs::read(persist::status_path(&path)).unwrap()).unwrap();
        let mut keys: Vec<_> = raw.as_object().unwrap().keys().cloned().collect();
        keys.sort();
        assert_eq!(
            keys,
            [
                "bytes",
                "entries",
                "evictions_total",
                "failed_ticks",
                "last_snapshot_unix",
                "max_bytes",
                "persist_failing"
            ]
        );
    }
}
