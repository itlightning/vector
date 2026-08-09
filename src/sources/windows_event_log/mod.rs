use async_trait::async_trait;
use vector_lib::config::LogNamespace;
use vrl::value::{Kind, kind::Collection};

use vector_config::component::SourceDescription;

use crate::config::{DataType, SourceConfig, SourceContext, SourceOutput};

// Cross-platform: config types (pure serde structs, no Windows dependencies)
mod config;
pub use self::config::*;

cfg_if::cfg_if! {
    if #[cfg(windows)] {
        mod bookmark;
        mod checkpoint;
        pub mod error;
        /// Publisher display-name tables, pure Rust and free of Win32, so the
        /// fill-vs-lookup invariant (tables come only from enumeration) is
        /// testable without a live publisher manifest. See the module docs.
        mod format_cache;
        mod metadata;
        mod parser;
        mod recovery;
        mod render;
        mod rendering_info;
        /// Process-global bounded caches for publisher metadata, name tables
        /// and SIDs, with the lock discipline that keeps them safe to share.
        mod shared_cache;
        mod sid_resolver;
        mod status;
        mod subscription;
        /// Invariants of the pure decision layer over randomly generated
        /// `(call site, code, returned count)` triples. Needs no Windows.
        #[cfg(test)]
        mod property_tests;
        /// Exclusive access to the process-global fault-injection seams. Any
        /// test that installs a seam or creates a subscription must hold a
        /// `SeamSession`; the requirement is enforced, not documented.
        #[cfg(test)]
        mod test_seams;
        mod win32_errors;
        mod xml_parser;

        use std::path::PathBuf;
        use std::sync::Arc;

        use chrono::Utc;
        use futures::{FutureExt, StreamExt};
        use vector_lib::EstimatedJsonEncodedSizeOf;
        use vector_lib::finalizer::OrderedFinalizer;
        use vector_lib::internal_event::{
            ByteSize, BytesReceived, CountByteSize, InternalEventHandle, Protocol,
        };
        use windows::Win32::Foundation::{DUPLICATE_SAME_ACCESS, DuplicateHandle, HANDLE};
        use windows::Win32::System::Threading::GetCurrentProcess;

        use crate::{
            SourceSender,
            event::{BatchNotifier, BatchStatus, BatchStatusReceiver},
            internal_events::{
                EventsReceived, StreamClosedError, WindowsEventLogParseError, WindowsEventLogQueryError,
            },
            shutdown::ShutdownSignal,
        };

        use self::{
            checkpoint::Checkpointer,
            error::WindowsEventLogError,
            parser::EventLogParser,
            subscription::{EventLogSubscription, WaitResult},
            xml_parser::WindowsEvent,
        };
    }
}

#[cfg(all(test, windows))]
mod tests;

// Integration tests are feature-gated to avoid requiring Windows Event Log service.
// To run integration tests on Windows: cargo test --features sources-windows_event_log-integration-tests
#[cfg(all(test, windows, feature = "sources-windows_event_log-integration-tests"))]
mod integration_tests;

cfg_if::cfg_if! {
if #[cfg(windows)] {

/// Entry for the acknowledgment finalizer containing checkpoint information.
/// Each entry represents a batch of events that need to be acknowledged before
/// the checkpoint can be safely updated. Contains all channel bookmarks from
/// the batch since a single batch may span multiple channels.
#[derive(Debug, Clone)]
struct FinalizerEntry {
    /// Checkpoint positions for every channel represented in the batch.
    positions: Vec<checkpoint::ChannelPosition>,
}

/// Shared checkpointer type for use with the finalizer
type SharedCheckpointer = Arc<Checkpointer>;

/// Stream of acknowledged batches produced by the finalizer.
///
/// Owned by the source loop, never by a detached task: the checkpoint write is
/// the last step of processing a batch, so whatever polls this stream has to be
/// something shutdown waits for.
type AckStream = futures::stream::BoxStream<'static, (BatchStatus, FinalizerEntry)>;

/// Finalizer for handling acknowledgments.
/// Supports both synchronous (immediate checkpoint) and asynchronous (deferred checkpoint) modes.
enum Finalizer {
    /// Synchronous mode: checkpoints are updated immediately after reading events.
    /// Used when acknowledgements are disabled.
    Sync(SharedCheckpointer),
    /// Asynchronous mode: checkpoints are updated only after downstream sinks acknowledge receipt.
    /// Used when acknowledgements are enabled.
    Async(OrderedFinalizer<FinalizerEntry>),
}

impl Finalizer {
    /// Create a new finalizer based on acknowledgement configuration, plus the
    /// stream of acknowledged batches the caller must drive.
    ///
    /// The finalizer is built with no shutdown signal on purpose. Handing it a
    /// shutdown signal ends the ack stream the instant shutdown fires, so acks
    /// still in flight at that moment are discarded and their checkpoints are
    /// never written. The events were delivered, the recorded position stayed
    /// behind them, and the next start re-reads from that stale position and
    /// ships the same events again. With no signal the stream ends only after
    /// the finalizer is dropped AND every pending ack has been yielded, which
    /// is what makes a real drain possible on the way out.
    fn new(acknowledgements: bool, checkpointer: SharedCheckpointer) -> (Self, AckStream) {
        if acknowledgements {
            let (finalizer, ack_stream) = OrderedFinalizer::<FinalizerEntry>::new(None);
            (Self::Async(finalizer), ack_stream)
        } else {
            // Sync mode checkpoints inline, so there is nothing to acknowledge.
            // An empty (not pending) stream keeps the drain a no-op instead of
            // a hang.
            (
                Self::Sync(checkpointer),
                futures::stream::empty::<(BatchStatus, FinalizerEntry)>().boxed(),
            )
        }
    }

    /// Finalize a batch of events.
    /// In sync mode, immediately updates the checkpoint.
    /// In async mode, registers the entry for deferred checkpoint update.
    async fn finalize(&self, entry: FinalizerEntry, receiver: Option<BatchStatusReceiver>) {
        match (self, receiver) {
            (Self::Sync(checkpointer), None) => {
                if let Err(e) = checkpointer.set_batch(entry.positions.clone()).await {
                    warn!(
                        message = "Failed to update checkpoint.",
                        error = %e
                    );
                }
            }
            (Self::Async(finalizer), Some(receiver)) => {
                finalizer.add(entry, receiver);
            }
            (Self::Sync(_), Some(_)) => {
                warn!(message = "Received acknowledgement receiver in sync mode, ignoring.");
            }
            (Self::Async(_), None) => {
                warn!(
                    message = "No acknowledgement receiver in async mode, checkpoint may be lost."
                );
            }
        }
    }
}

/// Comma-separated channel names in a batch, for log text.
fn channel_list(positions: &[checkpoint::ChannelPosition]) -> String {
    positions
        .iter()
        .map(|position| position.channel.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Write the checkpoint for one acknowledged batch.
async fn apply_ack(checkpointer: &Checkpointer, status: BatchStatus, entry: FinalizerEntry) {
    let channels = channel_list(&entry.positions);
    if status != BatchStatus::Delivered {
        debug!(
            message = format!("Events not delivered, checkpoint not updated (channels={channels})."),
            channels = %channels,
            status = ?status
        );
        return;
    }

    if let Err(e) = checkpointer.set_batch(entry.positions).await {
        warn!(
            message = format!(
                "Failed to update checkpoint after acknowledgement (channels={channels}). These events will be read again on restart."
            ),
            channels = %channels,
            error = %e
        );
    } else {
        debug!(
            message = format!("Checkpoint updated after acknowledgement (channels={channels})."),
            channels = %channels
        );
    }
}

/// Apply every acknowledgement that is already available, without waiting.
///
/// The pull loop blocks on Windows wait handles, so acks can only be picked up
/// between iterations. Nothing is lost by not waiting here: an ack that is not
/// ready yet stays queued in the stream and is applied on a later pass, or in
/// the shutdown drain.
async fn apply_ready_acks(ack_stream: &mut AckStream, checkpointer: &Checkpointer) {
    while let Some(Some((status, entry))) = ack_stream.next().now_or_never() {
        apply_ack(checkpointer, status, entry).await;
    }
}

/// Drop the finalizer and apply every acknowledgement still outstanding.
///
/// This is the shutdown path, and it is the whole point of building the
/// finalizer without a shutdown signal. Dropping the finalizer closes the entry
/// side, so the stream yields the acks already pending and then ends. Returning
/// early instead would leave delivered events uncheckpointed, which is exactly
/// how a restart produces duplicates.
async fn drain_acks(finalizer: Finalizer, ack_stream: &mut AckStream, checkpointer: &Checkpointer) {
    drop(finalizer);
    let mut drained = 0usize;
    while let Some((status, entry)) = ack_stream.next().await {
        drained += 1;
        apply_ack(checkpointer, status, entry).await;
    }
    debug!(
        message = "Acknowledgement stream drained.",
        acknowledgements = drained
    );
}

/// Parse, emit metrics for, send, and finalize a non-empty batch of pulled Windows events.
///
/// Both the `EventsAvailable` path and the speculative-timeout path share this
/// logic. Returns `true` if the downstream pipeline closed and the caller
/// should break out of the main event loop.
///
/// `events` is DRAINED rather than consumed: the container belongs to the
/// subscription, which recycles it for the next pull (see
/// `EventLogSubscription::recycle_event_buffer`). Taking it by `&mut` is also
/// what lets the caller keep an immutable borrow of the subscription across
/// this call.
#[allow(clippy::too_many_arguments)]
async fn process_event_batch(
    events: &mut Vec<WindowsEvent>,
    parser: &EventLogParser,
    log_namespace: LogNamespace,
    acknowledgements: bool,
    subscription: &EventLogSubscription,
    out: &mut SourceSender,
    finalizer: &Finalizer,
    events_received: &impl InternalEventHandle<Data = CountByteSize>,
    bytes_received: &impl InternalEventHandle<Data = ByteSize>,
) -> bool {
    // Rate limiting between batches (async-compatible).
    if let Some(limiter) = subscription.rate_limiter() {
        limiter.until_ready().await;
    }

    let (batch, receiver) = BatchNotifier::maybe_new_with_receiver(acknowledgements);
    let mut log_events = Vec::new();
    let mut total_byte_size = 0usize;
    let mut channels_in_batch = std::collections::HashSet::new();

    for event in events.drain(..) {
        let channel = event.channel.clone();
        channels_in_batch.insert(channel.clone());
        let event_id = event.event_id;
        match parser.parse_event(event) {
            Ok(mut log_event) => {
                log_namespace.insert_standard_vector_source_metadata(
                    &mut log_event,
                    WindowsEventLogConfig::NAME,
                    Utc::now(),
                );

                let byte_size = log_event.estimated_json_encoded_size_of();
                total_byte_size += byte_size.get();
                if let Some(ref batch) = batch {
                    log_event = log_event.with_batch_notifier(batch);
                }
                log_events.push(log_event);
            }
            Err(e) => {
                emit!(WindowsEventLogParseError {
                    error: e.to_string(),
                    channel,
                    event_id: Some(event_id),
                });
            }
        }
    }

    if !log_events.is_empty() {
        let count = log_events.len();
        events_received.emit(CountByteSize(count, total_byte_size.into()));
        bytes_received.emit(ByteSize(total_byte_size));

        // BACK PRESSURE: block until the pipeline accepts the batch.
        // We don't call EvtNext again until this completes.
        if let Err(_error) = out.send_batch(log_events).await {
            emit!(StreamClosedError { count });
            return true; // signal: break the main loop
        }

        // Register checkpoint entry with the finalizer.
        let positions: Vec<checkpoint::ChannelPosition> = channels_in_batch
            .into_iter()
            .filter_map(|channel| subscription.channel_position(&channel))
            .collect();

        if !positions.is_empty() {
            let entry = FinalizerEntry { positions };
            finalizer.finalize(entry, receiver).await;
        }
    }

    false // pipeline still open
}

/// Transfer ownership of `subscription` into a `spawn_blocking` task, run `f`
/// on it, then return both the subscription and the result.
///
/// All blocking Windows APIs (`WaitForMultipleObjects`, `EvtNext`, `EvtRender`)
/// must run in `spawn_blocking` to avoid stalling the async runtime. The
/// ownership-transfer pattern ensures only one thread holds the subscription
/// at a time, preventing data races without requiring locks.
async fn with_subscription_blocking<F, R>(
    subscription: EventLogSubscription,
    f: F,
) -> Result<(EventLogSubscription, R), WindowsEventLogError>
where
    F: FnOnce(EventLogSubscription) -> (EventLogSubscription, R) + Send + 'static,
    R: Send + 'static,
{
    tokio::task::spawn_blocking(move || f(subscription))
        .await
        .map_err(|e| WindowsEventLogError::ConfigError {
            message: format!("Blocking subscription task panicked: {e}"),
        })
}

/// Windows Event Log source implementation
pub struct WindowsEventLogSource {
    config: WindowsEventLogConfig,
    data_dir: PathBuf,
    acknowledgements: bool,
    log_namespace: LogNamespace,
}

impl WindowsEventLogSource {
    pub fn new(
        config: WindowsEventLogConfig,
        data_dir: PathBuf,
        acknowledgements: bool,
        log_namespace: LogNamespace,
    ) -> crate::Result<Self> {
        config.validate()?;

        Ok(Self {
            config,
            data_dir,
            acknowledgements,
            log_namespace,
        })
    }

    /// Where this source writes its channel status.
    ///
    /// `data_dir` is already resolved to this source's own subdirectory, so the
    /// default sits beside the checkpoint file and needs no component id of its
    /// own. An explicit `status_path` overrides it outright.
    fn status_file_path(&self) -> PathBuf {
        status::StatusWriter::resolve_path(self.config.status_path.as_ref(), &self.data_dir)
    }

    async fn run_internal(
        &mut self,
        mut out: SourceSender,
        shutdown: ShutdownSignal,
    ) -> Result<(), WindowsEventLogError> {
        let checkpointer = Arc::new(Checkpointer::new(&self.data_dir).await?);

        let (finalizer, mut ack_stream) =
            Finalizer::new(self.acknowledgements, Arc::clone(&checkpointer));

        let mut subscription = EventLogSubscription::new(
            &self.config,
            Arc::clone(&checkpointer),
            self.acknowledgements,
        )
        .await?;
        let parser = EventLogParser::new(&self.config, self.log_namespace);

        let events_received = register!(EventsReceived);
        let bytes_received = register!(BytesReceived::from(Protocol::from("windows_event_log")));

        let timeout_ms = self.config.event_timeout_ms as u32;
        let batch_size = self.config.batch_size as usize;
        let acknowledgements = self.acknowledgements;

        info!(
            message = "Starting Windows Event Log source (pull mode).",
            acknowledgements = acknowledgements,
        );

        // Spawn async shutdown watcher that signals the Windows shutdown event
        // when the Vector shutdown signal fires. This wakes WaitForMultipleObjects
        // while subscription is moved into spawn_blocking.
        //
        // We duplicate the handle so the watcher owns an independent kernel reference.
        // This prevents use-after-close if the subscription panics and drops before
        // the watcher fires — the duplicate remains valid until explicitly closed.
        let (watcher_handle_raw, watcher_owns_handle): (isize, bool) = {
            unsafe {
                let src = HANDLE(subscription.shutdown_event_raw());
                let process = GetCurrentProcess();
                let mut dup = HANDLE::default();
                if DuplicateHandle(
                    process,
                    src,
                    process,
                    &mut dup,
                    0,
                    false,
                    DUPLICATE_SAME_ACCESS,
                )
                .is_ok()
                {
                    (dup.0 as isize, true)
                } else {
                    // Fallback: use the original handle without ownership.
                    // The watcher will signal but NOT close — EventLogSubscription::drop
                    // owns the handle and will close it.
                    warn!(
                        message = "Failed to duplicate shutdown event handle, falling back to shared handle."
                    );
                    (src.0 as isize, false)
                }
            }
        };
        let shutdown_watcher = shutdown.clone();
        crate::spawn_in_current_span(async move {
            shutdown_watcher.await;
            unsafe {
                let handle =
                    windows::Win32::Foundation::HANDLE(watcher_handle_raw as *mut std::ffi::c_void);
                _ = windows::Win32::System::Threading::SetEvent(handle);
                if watcher_owns_handle {
                    _ = windows::Win32::Foundation::CloseHandle(handle);
                }
            }
        });

        // Per-channel status file. Written by default into this source's own
        // data directory, next to the checkpoint file, because that is where
        // the reader looks for it.
        let status_path = self.status_file_path();
        info!(
            message = "Writing Windows Event Log channel status.",
            path = %status_path.display(),
            interval_secs = self.config.status_interval_secs,
        );
        let mut status_writer = status::StatusWriter::new(
            status_path,
            self.config.status_interval_secs,
            std::time::Instant::now(),
        );

        // Track when we last flushed checkpoints
        let mut last_checkpoint = std::time::Instant::now();
        let checkpoint_interval =
            std::time::Duration::from_secs(self.config.checkpoint_interval_secs);

        // Exponential backoff on consecutive recoverable errors
        let mut error_backoff = std::time::Duration::from_millis(100);
        const MAX_ERROR_BACKOFF: std::time::Duration = std::time::Duration::from_secs(5);

        // Health heartbeat: log every ~30s regardless of checkpoint interval
        let mut timeout_count: u32 = 0;
        let health_interval_timeouts = (30_000 / self.config.event_timeout_ms).max(1) as u32;

        loop {
            // Checkpoint whatever downstream has already acknowledged. The
            // stream is only polled here, so this has to run every pass.
            //
            // Runs before the status write on purpose: it is cheap and
            // non-blocking, while the status write hands the subscription to a
            // blocking thread. Checkpointing first keeps the position the
            // status file reports from lagging the position we have already
            // durably recorded.
            apply_ready_acks(&mut ack_stream, &checkpointer).await;

            // The status file runs on its own cadence and refreshes channel
            // metadata itself. It deliberately does not reuse what the pull
            // loop maintains: that refresh is skipped for channels that
            // returned no events, and a quiet channel is exactly the case a
            // reader has to tell apart from a wedged one. Both the metadata
            // queries and the file write are blocking, so they ride the same
            // blocking thread as the subscription.
            if status_writer.is_due(std::time::Instant::now()) {
                let mut writer = status_writer;
                let (returned_sub, returned_writer) =
                    with_subscription_blocking(subscription, move |sub| {
                        let snapshot = sub.status_snapshot();
                        writer.write(&snapshot, std::time::Instant::now());
                        (sub, writer)
                    })
                    .await?;
                subscription = returned_sub;
                status_writer = returned_writer;
            }

            // Move subscription into blocking thread for WaitForMultipleObjects.
            // Ownership transfer ensures no data races between the blocking thread
            // and async code. The shutdown watcher uses a raw HANDLE value (just an
            // integer) to signal shutdown without needing access to the subscription.
            let (returned_sub, wait_result) =
                with_subscription_blocking(subscription, move |sub| {
                    let result = sub.wait_for_events_blocking(timeout_ms);
                    (sub, result)
                })
                .await?;
            subscription = returned_sub;

            match wait_result {
                WaitResult::EventsAvailable => {
                    // Pull events via spawn_blocking (EvtNext/EvtRender are blocking APIs)
                    let (returned_sub, events_result) =
                        with_subscription_blocking(subscription, move |mut sub| {
                            let result = sub.pull_events(batch_size);
                            (sub, result)
                        })
                        .await?;
                    subscription = returned_sub;

                    match events_result {
                        Ok(mut events) => {
                            error_backoff = std::time::Duration::from_millis(100);
                            let pipeline_closed = if events.is_empty() {
                                false
                            } else {
                                debug!(
                                    message = "Pulled Windows Event Log events.",
                                    event_count = events.len()
                                );
                                process_event_batch(
                                    &mut events,
                                    &parser,
                                    self.log_namespace,
                                    acknowledgements,
                                    &subscription,
                                    &mut out,
                                    &finalizer,
                                    &events_received,
                                    &bytes_received,
                                )
                                .await
                            };
                            // Every path that took the buffer returns it, empty
                            // batches included: on a quiet host that IS the path.
                            subscription.recycle_event_buffer(events);
                            if pipeline_closed {
                                break;
                            }
                        }
                        Err(e) => {
                            // Per-channel failures never reach here: they are
                            // classified, logged with the real channel name,
                            // and recovered inside the subscription. What is
                            // left is source-level, so it is attributed to the
                            // source rather than to a fictitious channel named
                            // "all".
                            emit!(WindowsEventLogQueryError {
                                channel: config::SOURCE_LEVEL_CHANNEL.to_string(),
                                query: None,
                                error: e.to_string(),
                            });
                            if !e.is_recoverable() {
                                error!(
                                    message = "Non-recoverable pull error, shutting down.",
                                    error = %e
                                );
                                break;
                            }
                            // Exponential backoff on consecutive recoverable errors
                            warn!(
                                message = "Recoverable pull error, backing off.",
                                backoff_ms = error_backoff.as_millis() as u64,
                                error = %e
                            );
                            tokio::time::sleep(error_backoff).await;
                            error_backoff = (error_backoff * 2).min(MAX_ERROR_BACKOFF);
                        }
                    }
                }

                WaitResult::Timeout => {
                    // Periodic checkpoint flush (sync mode only)
                    if !acknowledgements && last_checkpoint.elapsed() >= checkpoint_interval {
                        if let Err(e) = subscription.flush_bookmarks().await {
                            warn!(
                                message = "Failed to flush bookmarks during periodic checkpoint.",
                                error = %e
                            );
                        }
                        last_checkpoint = std::time::Instant::now();
                    }

                    // Health heartbeat on a separate ~30s cadence
                    timeout_count += 1;
                    if timeout_count >= health_interval_timeouts {
                        timeout_count = 0;
                        let (total, active) = subscription.channel_health_summary();
                        if active < total {
                            // DEBUG, not WARN. A channel that is down already
                            // emitted its onset ERROR once and will emit its
                            // recovery WARN once; this 30s pulse would turn one
                            // episode into a warn-band line every half minute.
                            // Exactly two warn-band lines per episode, no more.
                            debug!(
                                message = "Some channel subscriptions are inactive.",
                                total_channels = total,
                                active_channels = active,
                            );
                        } else {
                            debug!(
                                message = "All channel subscriptions healthy.",
                                total_channels = total,
                            );
                        }
                    }

                    // Speculative pull: self-heal against any lost-wakeup scenario,
                    // regardless of root cause. If the OS signal was lost through any
                    // mechanism (not just the pre-drain race fixed in #25194), this
                    // ensures the source recovers within one timeout period.
                    // Use the speculative pull variant so idle timeout cycles don't
                    // refresh per-channel record-count gauges via EvtOpenLog /
                    // EvtGetLogInfo on every configured channel.
                    let (returned_sub, speculative_result) =
                        with_subscription_blocking(subscription, move |mut sub| {
                            let result = sub.pull_events_speculative(batch_size);
                            (sub, result)
                        })
                        .await?;
                    subscription = returned_sub;

                    match speculative_result {
                        Ok(mut events) => {
                            // Healthy cycle: reset backoff so the next transient
                            // error starts fresh.
                            error_backoff = std::time::Duration::from_millis(100);
                            let pipeline_closed = if events.is_empty() {
                                false
                            } else {
                                // DEBUG, not WARN. The speculative pull is a
                                // self-heal that works: it recovering events is the
                                // mechanism functioning, not a fault. It also fires
                                // routinely on the batch right after a rebuild,
                                // which put a third and fourth warn-band line on a
                                // single unregister episode in the lab.
                                debug!(
                                    message = "Speculative timeout pull recovered events; possible lost wakeup detected.",
                                    event_count = events.len(),
                                );
                                process_event_batch(
                                    &mut events,
                                    &parser,
                                    self.log_namespace,
                                    acknowledgements,
                                    &subscription,
                                    &mut out,
                                    &finalizer,
                                    &events_received,
                                    &bytes_received,
                                )
                                .await
                            };
                            subscription.recycle_event_buffer(events);
                            if pipeline_closed {
                                break;
                            }
                        }
                        Err(e) => {
                            // Per-channel failures never reach here: they are
                            // classified, logged with the real channel name,
                            // and recovered inside the subscription. What is
                            // left is source-level, so it is attributed to the
                            // source rather than to a fictitious channel named
                            // "all".
                            emit!(WindowsEventLogQueryError {
                                channel: config::SOURCE_LEVEL_CHANNEL.to_string(),
                                query: None,
                                error: e.to_string(),
                            });
                            if !e.is_recoverable() {
                                error!(
                                    message = "Non-recoverable speculative pull error, shutting down.",
                                    error = %e
                                );
                                break;
                            }
                            // Exponential backoff mirrors the EventsAvailable error path.
                            warn!(
                                message = "Recoverable speculative pull error, backing off.",
                                backoff_ms = error_backoff.as_millis() as u64,
                                error = %e
                            );
                            tokio::time::sleep(error_backoff).await;
                            error_backoff = (error_backoff * 2).min(MAX_ERROR_BACKOFF);
                        }
                    }
                }

                WaitResult::Shutdown => {
                    info!(message = "Windows Event Log wait received shutdown signal.");
                    if !acknowledgements {
                        info!(message = "Flushing bookmarks before shutdown.");
                        if let Err(e) = subscription.flush_bookmarks().await {
                            warn!(message = "Failed to flush bookmarks on shutdown.", error = %e);
                        }
                    }
                    break;
                }
            }
        }

        // Every exit from the loop goes through the drain, not just the
        // shutdown one: a batch that was delivered but not yet acknowledged is
        // uncheckpointed no matter why the loop ended.
        drain_acks(finalizer, &mut ack_stream, &checkpointer).await;

        Ok(())
    }
}

} // if #[cfg(windows)]
} // cfg_if!

#[async_trait]
#[typetag::serde(name = "windows_event_log")]
impl SourceConfig for WindowsEventLogConfig {
    async fn build(&self, _cx: SourceContext) -> crate::Result<super::Source> {
        #[cfg(not(windows))]
        {
            Err("The windows_event_log source is only supported on Windows.".into())
        }

        #[cfg(windows)]
        {
            let data_dir = _cx
                .globals
                .resolve_and_make_data_subdir(self.data_dir.as_ref(), _cx.key.id())?;

            let acknowledgements = _cx.do_acknowledgements(self.acknowledgements);

            let log_namespace = _cx.log_namespace(self.log_namespace);
            let source = WindowsEventLogSource::new(
                self.clone(),
                data_dir,
                acknowledgements,
                log_namespace,
            )?;
            Ok(Box::pin(async move {
                let mut source = source;
                if let Err(error) = source.run_internal(_cx.out, _cx.shutdown).await {
                    error!(message = "Windows Event Log source failed.", %error);
                }
                Ok(())
            }))
        }
    }

    fn outputs(&self, global_log_namespace: LogNamespace) -> Vec<SourceOutput> {
        let log_namespace = self
            .log_namespace
            .map(|b| {
                if b {
                    LogNamespace::Vector
                } else {
                    LogNamespace::Legacy
                }
            })
            .unwrap_or(global_log_namespace);

        let schema_definition = match log_namespace {
            LogNamespace::Vector => vector_lib::schema::Definition::new_with_default_metadata(
                Kind::object(std::collections::BTreeMap::from([
                    ("timestamp".into(), Kind::timestamp().or_undefined()),
                    ("message".into(), Kind::bytes().or_undefined()),
                    ("level".into(), Kind::bytes().or_undefined()),
                    ("source".into(), Kind::bytes().or_undefined()),
                    ("event_id".into(), Kind::integer().or_undefined()),
                    ("provider_name".into(), Kind::bytes().or_undefined()),
                    ("computer".into(), Kind::bytes().or_undefined()),
                    ("user_id".into(), Kind::bytes().or_undefined()),
                    ("user_name".into(), Kind::bytes().or_undefined()),
                    ("record_id".into(), Kind::integer().or_undefined()),
                    ("activity_id".into(), Kind::bytes().or_undefined()),
                    ("related_activity_id".into(), Kind::bytes().or_undefined()),
                    ("process_id".into(), Kind::integer().or_undefined()),
                    ("thread_id".into(), Kind::integer().or_undefined()),
                    ("channel".into(), Kind::bytes().or_undefined()),
                    ("opcode".into(), Kind::integer().or_undefined()),
                    ("task".into(), Kind::integer().or_undefined()),
                    ("keywords".into(), Kind::bytes().or_undefined()),
                    ("level_value".into(), Kind::integer().or_undefined()),
                    ("provider_guid".into(), Kind::bytes().or_undefined()),
                    ("version".into(), Kind::integer().or_undefined()),
                    ("qualifiers".into(), Kind::integer().or_undefined()),
                    (
                        "string_inserts".into(),
                        Kind::array(Collection::empty().with_unknown(Kind::bytes())).or_undefined(),
                    ),
                    (
                        "event_data".into(),
                        Kind::object(std::collections::BTreeMap::new()).or_undefined(),
                    ),
                    (
                        "user_data".into(),
                        Kind::object(std::collections::BTreeMap::new()).or_undefined(),
                    ),
                    ("message_source".into(), Kind::bytes().or_undefined()),
                    ("task_name".into(), Kind::bytes().or_undefined()),
                    ("opcode_name".into(), Kind::bytes().or_undefined()),
                    (
                        "keyword_names".into(),
                        Kind::array(Collection::empty().with_unknown(Kind::bytes())).or_undefined(),
                    ),
                ])),
                [LogNamespace::Vector],
            )
            .with_standard_vector_source_metadata(),
            LogNamespace::Legacy => {
                vector_lib::schema::Definition::any().with_standard_vector_source_metadata()
            }
        };

        vec![SourceOutput::new_maybe_logs(
            DataType::Log,
            schema_definition,
        )]
    }

    fn resources(&self) -> Vec<crate::config::Resource> {
        self.channels
            .iter()
            .map(|channel| crate::config::Resource::DiskBuffer(channel.clone()))
            .collect()
    }

    fn can_acknowledge(&self) -> bool {
        true
    }
}

inventory::submit! {
    SourceDescription::new::<WindowsEventLogConfig>(
        "windows_event_log",
        "Collect logs from Windows Event Log channels",
        "A Windows-specific source that subscribes to Windows Event Log channels and streams events in real-time using the Windows Event Log API.",
        "https://vector.dev/docs/reference/configuration/sources/windows_event_log/"
    )
}
