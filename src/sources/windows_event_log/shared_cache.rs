//! Process-global, bounded metadata caches shared by every event-log source.
//!
//! ## Why these are not per source
//!
//! Everything cached here is keyed on a HOST-global identity: a publisher name,
//! a publisher name plus locale, a SID. None of it is source-specific, so a
//! process running six sources over two hundred channels held six independent
//! copies of the same enumerated name tables. A rich provider's table is
//! hundreds of display strings, so that duplication is the cost being removed.
//!
//! It is a MEMORY win and not a handle one. A lab breakdown of a themed-feed
//! host counted one Section and sixteen File handles against six hundred and
//! twenty-two Events, so cached publisher metadata holds no DLL mappings in this
//! process; the handle count is the inherent cost of one subscription per
//! channel and is not what this module is for.
//!
//! ## Bounded, all three
//!
//! Every cache here has a capacity. An unbounded map keyed on "every publisher
//! this host has ever emitted an event from" reads as a slow leak over a long
//! soak, which is indistinguishable from the real thing at the point somebody
//! is looking at a graph.
//!
//! ## Lock discipline
//!
//! Two lock levels, and the order between them is the whole safety argument:
//!
//! 1. **The map lock** (an `RwLock` per cache) is held ONLY to look an entry up
//!    or insert one. It is never held across a wevtapi call, and never held
//!    while another lock is taken. Callers clone the entry's `Arc` out and drop
//!    the guard before doing any work with it.
//! 2. **The entry lock** (a `Mutex` on the publisher entry) is held across the
//!    wevtapi calls that use that publisher's handle, because a metadata handle
//!    is not documented as safe for concurrent use.
//!
//! **No caller ever holds two entry locks at once.** Only the publisher cache
//! has an entry lock at all. The format and SID caches need none, because no
//! wevtapi call happens under their map locks: the caller asks the format cache
//! what to do, RELEASES, enumerates under the publisher entry lock, then comes
//! back to store the result.
//!
//! Why that cannot deadlock, stated precisely, because the nesting is real and
//! runs the way round a reader might not expect: a caller resolving an event
//! DOES hold the publisher entry lock while it briefly takes the format map
//! lock. The safety argument is not an ordering between the two, it is that a
//! map lock is never HELD while any entry lock is acquired. Every function below
//! takes its map lock, finishes, and returns; none of them calls out while
//! holding one. So no thread can ever wait on an entry lock while holding a map
//! lock, the wait-for graph has no cycle, and there is no retry loop anywhere
//! here to livelock instead.
//!
//! ## Eviction and handle lifetime
//!
//! Evicting a publisher entry drops the map's `Arc`. The handle closes when the
//! LAST `Arc` goes, so a thread that took an entry out and is mid-call keeps its
//! handle valid; eviction can never close a handle out from under a formatter.
//! That is a correctness property, not a memory one.

use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, RwLock};

use lru::LruCache;
use windows::Win32::System::EventLog::{EVT_HANDLE, EvtOpenPublisherMetadata};
use windows::core::HSTRING;

use super::format_cache::{FormatCache, NameField, Prepare, PublisherNames, SYSTEM_DEFAULT_LOCALE};
use super::subscription::PublisherHandle;

/// Live publisher metadata handles, process-wide.
///
/// The hot publisher set on a real host is far below this, and a miss costs one
/// `EvtOpenPublisherMetadata`. Bounded because the key space is every publisher
/// the host has ever emitted from, not because these handles dominate anything:
/// the lab breakdown puts them at a rounding error of the process total.
const PUBLISHER_CACHE_CAPACITY: usize = 128;

/// Enumerated display-name tables, process-wide.
///
/// A rich provider's table is hundreds of strings, and this is the cache that
/// used to have no bound at all.
const FORMAT_CACHE_CAPACITY: usize = 512;

/// Resolved SID-to-account names, process-wide.
///
/// Small values and a high hit rate, so this one can afford to be wide.
const SID_CACHE_CAPACITY: usize = 4096;

/// One publisher's metadata handle, plus the lock that serializes wevtapi calls
/// against it.
///
/// `None` means no open has been attempted yet. A failed open is stored as
/// `Some(PublisherHandle(0))` so a provider with no manifest is not re-opened on
/// every event, and is retried only when the caller asks.
pub(super) struct PublisherEntry {
    handle: Mutex<Option<PublisherHandle>>,
}

impl PublisherEntry {
    const fn new() -> Self {
        Self {
            handle: Mutex::new(None),
        }
    }

    /// Take this publisher's lock for a stretch of wevtapi calls.
    ///
    /// The guard is the caller's proof it may use the handle. Hold it across
    /// every call that names this publisher and drop it before touching any
    /// other entry.
    pub(super) fn lock(&self) -> PublisherGuard<'_> {
        PublisherGuard {
            handle: self.handle.lock().unwrap_or_else(|e| e.into_inner()),
        }
    }
}

/// Exclusive use of one publisher's metadata handle.
pub(super) struct PublisherGuard<'a> {
    handle: MutexGuard<'a, Option<PublisherHandle>>,
}

impl PublisherGuard<'_> {
    /// The raw metadata handle, opening it on first use.
    ///
    /// `0` means the publisher has no readable metadata. `retry_failed` re-opens
    /// after a previous failure, which is what the enumeration path asks for and
    /// the per-field fallback path does not.
    pub(super) fn raw(&mut self, provider_name: &str, retry_failed: bool) -> isize {
        if let Some(existing) = self.handle.as_ref()
            && (existing.0 != 0 || !retry_failed)
        {
            return existing.0;
        }

        let provider_hstring = HSTRING::from(provider_name);
        // Locale 0 is the thread/system default, matching prior behavior and the
        // locked product choice: forwarded events keep origin `<Locale>` in XML
        // and we ignore it.
        let raw = unsafe {
            EvtOpenPublisherMetadata(None, &provider_hstring, None, SYSTEM_DEFAULT_LOCALE, 0)
                .map(|h| h.0)
                .unwrap_or(0)
        };
        *self.handle = Some(PublisherHandle(raw));
        raw
    }

    /// The handle as already opened, without attempting one.
    pub(super) fn opened(&self) -> EVT_HANDLE {
        EVT_HANDLE(self.handle.as_ref().map_or(0, |h| h.0))
    }
}

fn publisher_cache() -> &'static RwLock<LruCache<String, Arc<PublisherEntry>>> {
    static CACHE: OnceLock<RwLock<LruCache<String, Arc<PublisherEntry>>>> = OnceLock::new();
    CACHE.get_or_init(|| {
        RwLock::new(LruCache::new(
            NonZeroUsize::new(PUBLISHER_CACHE_CAPACITY).expect("capacity is not zero"),
        ))
    })
}

/// The shared entry for `provider_name`, inserting an unopened one if needed.
///
/// The map lock is released before this returns, so the caller does its wevtapi
/// work under the entry lock alone.
pub(super) fn publisher_entry(provider_name: &str) -> Arc<PublisherEntry> {
    let mut map = publisher_cache().write().unwrap_or_else(|e| e.into_inner());
    if let Some(existing) = map.get(provider_name) {
        return Arc::clone(existing);
    }
    let entry = Arc::new(PublisherEntry::new());
    map.put(provider_name.to_string(), Arc::clone(&entry));
    entry
}

/// The one enumerated-name table in the process.
///
/// Kept as a whole [`FormatCache`] rather than as per-publisher entries because
/// no wevtapi call happens under this lock: the caller asks `prepare` what to do,
/// releases, enumerates under the PUBLISHER entry lock, and comes back to store.
/// Every method below is a short map-only critical section, which is exactly the
/// discipline the shared caches were ruled to keep.
fn format_cache() -> &'static RwLock<FormatCache> {
    static CACHE: OnceLock<RwLock<FormatCache>> = OnceLock::new();
    CACHE.get_or_init(|| RwLock::new(FormatCache::with_capacity(FORMAT_CACHE_CAPACITY)))
}

/// What the caller must do before looking this publisher's names up.
pub(super) fn format_prepare(
    publisher: &str,
    locale: u32,
    now: std::time::Instant,
    refresh: std::time::Duration,
) -> Prepare {
    format_cache()
        .write()
        .unwrap_or_else(|e| e.into_inner())
        .prepare(publisher, locale, now, refresh)
}

/// Store a freshly enumerated table.
pub(super) fn format_store_table(
    publisher: &str,
    locale: u32,
    now: std::time::Instant,
    names: PublisherNames,
) {
    format_cache()
        .write()
        .unwrap_or_else(|e| e.into_inner())
        .store_table(publisher, locale, now, names);
}

/// Record that this publisher has no readable metadata.
pub(super) fn format_store_unopenable(publisher: &str, locale: u32, now: std::time::Instant) {
    format_cache()
        .write()
        .unwrap_or_else(|e| e.into_inner())
        .store_unopenable(publisher, locale, now);
}

/// One scalar display name, owned: a borrow could not outlive the map guard.
pub(super) fn format_scalar(
    publisher: &str,
    locale: u32,
    field: NameField,
    value: u64,
) -> Option<String> {
    format_cache()
        .write()
        .unwrap_or_else(|e| e.into_inner())
        .get_scalar(publisher, locale, field, value)
}

/// The keyword names for a mask.
pub(super) fn format_keywords(publisher: &str, locale: u32, mask: u64) -> Option<Vec<String>> {
    format_cache()
        .write()
        .unwrap_or_else(|e| e.into_inner())
        .get_keywords(publisher, locale, mask)
}

fn sid_cache() -> &'static RwLock<LruCache<String, Option<String>>> {
    static CACHE: OnceLock<RwLock<LruCache<String, Option<String>>>> = OnceLock::new();
    CACHE.get_or_init(|| {
        RwLock::new(LruCache::new(
            NonZeroUsize::new(SID_CACHE_CAPACITY).expect("capacity is not zero"),
        ))
    })
}

/// The cached account name for `sid`, if this SID has been looked up before.
///
/// The outer `Option` is "have we asked"; the inner one is the answer, so a SID
/// that does not resolve is remembered as unresolvable rather than re-queried on
/// every event carrying it.
pub(super) fn sid_lookup(sid: &str) -> Option<Option<String>> {
    let mut map = sid_cache().write().unwrap_or_else(|e| e.into_inner());
    map.get(sid).cloned()
}

/// Remember the outcome of resolving `sid`.
pub(super) fn sid_store(sid: &str, name: Option<String>) {
    let mut map = sid_cache().write().unwrap_or_else(|e| e.into_inner());
    map.put(sid.to_string(), name);
}

/// Test-only: how many publisher entries are resident.
#[cfg(test)]
pub(super) fn publisher_len() -> usize {
    publisher_cache()
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .len()
}

/// Test-only: how many format entries are resident.
#[cfg(test)]
pub(super) fn format_len() -> usize {
    format_cache()
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .len()
}

/// Test-only: drop every cached entry, so one test's residents cannot decide
/// another's hit or miss. Callers must hold the seam session.
#[cfg(test)]
pub(super) fn clear_all() {
    publisher_cache()
        .write()
        .unwrap_or_else(|e| e.into_inner())
        .clear();
    *format_cache().write().unwrap_or_else(|e| e.into_inner()) =
        FormatCache::with_capacity(FORMAT_CACHE_CAPACITY);
    sid_cache()
        .write()
        .unwrap_or_else(|e| e.into_inner())
        .clear();
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::*;
    use crate::sources::windows_event_log::format_cache::PublisherNames;
    use crate::sources::windows_event_log::test_seams::SeamSession;

    fn names_with_task(id: u16, name: &str) -> PublisherNames {
        let mut names = PublisherNames::default();
        names.tasks.insert(id, name.to_string());
        names
    }

    /// Two sources asking about one publisher share ONE table.
    ///
    /// This is the memory property the shared caches exist for: the tables are
    /// keyed on host-global identity, so six sources used to hold six copies of
    /// the same hundreds of display strings. Written as two independent lookups
    /// because that is what two sources are: nothing is passed between them.
    #[test]
    fn one_publisher_table_serves_every_source() {
        let _seams = SeamSession::acquire();
        clear_all();
        let now = Instant::now();
        let refresh = Duration::from_secs(86_400);

        // The "first source" enumerates.
        assert_eq!(
            format_prepare("Contoso-Provider", SYSTEM_DEFAULT_LOCALE, now, refresh),
            Prepare::NeedEnumerate,
            "an unseen publisher must be enumerated once"
        );
        format_store_table(
            "Contoso-Provider",
            SYSTEM_DEFAULT_LOCALE,
            now,
            names_with_task(7, "Logon"),
        );

        // The "second source" finds it resident and enumerates nothing.
        assert_eq!(
            format_prepare("Contoso-Provider", SYSTEM_DEFAULT_LOCALE, now, refresh),
            Prepare::Ready,
            "a second source must reuse the table rather than build its own"
        );
        assert_eq!(
            format_scalar(
                "Contoso-Provider",
                SYSTEM_DEFAULT_LOCALE,
                NameField::Task,
                7
            )
            .as_deref(),
            Some("Logon")
        );
        assert_eq!(format_len(), 1, "one publisher, one resident table");
    }

    /// The format cache is BOUNDED, which is the half that keeps a long soak
    /// from reading like a leak: the key space is every publisher the host has
    /// ever emitted from.
    #[test]
    fn the_format_cache_evicts_rather_than_growing_without_end() {
        let _seams = SeamSession::acquire();
        clear_all();
        let now = Instant::now();

        for i in 0..(FORMAT_CACHE_CAPACITY + 64) {
            format_store_table(
                &format!("Publisher-{i}"),
                SYSTEM_DEFAULT_LOCALE,
                now,
                names_with_task(1, "Task"),
            );
        }
        assert_eq!(
            format_len(),
            FORMAT_CACHE_CAPACITY,
            "the cache must stop at its capacity, not track every publisher seen"
        );
    }

    /// A SID resolves once and is remembered, including when it does not
    /// resolve: an unresolvable SID re-queried on every event carrying it is the
    /// cost this cache exists to avoid.
    #[test]
    fn a_sid_answer_is_remembered_either_way() {
        let _seams = SeamSession::acquire();
        clear_all();

        assert!(sid_lookup("S-1-5-21-fake").is_none(), "not asked yet");
        sid_store("S-1-5-21-fake", None);
        assert_eq!(
            sid_lookup("S-1-5-21-fake"),
            Some(None),
            "an unresolvable SID is remembered as unresolvable, not forgotten"
        );

        sid_store("S-1-5-18", Some("NT AUTHORITY".to_string()));
        assert_eq!(
            sid_lookup("S-1-5-18"),
            Some(Some("NT AUTHORITY".to_string()))
        );
    }

    /// Two threads formatting against ONE publisher serialize and both finish.
    ///
    /// The entry lock is what makes concurrent sources safe against a metadata
    /// handle that is not documented as thread-safe, and the lock order (map
    /// before entry, never two entries) is what makes it deadlock-free. The
    /// timeout is the assertion: a lock-order defect here would hang rather than
    /// fail, and a hung test that is not bounded takes the suite with it.
    #[test]
    fn concurrent_formatters_on_one_publisher_serialize_and_finish() {
        let _seams = SeamSession::acquire();
        clear_all();

        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let mut handles = Vec::new();
        for _ in 0..2 {
            let done_tx = done_tx.clone();
            handles.push(std::thread::spawn(move || {
                for _ in 0..50 {
                    // The real sequence: take the shared entry (map lock, then
                    // released), then its own lock for the wevtapi call. The
                    // provider does not exist, so the open fails fast and is
                    // remembered; the locking is what is under test.
                    let entry = publisher_entry("Nonexistent-Test-Provider");
                    let mut publisher = entry.lock();
                    _ = publisher.raw("Nonexistent-Test-Provider", false);
                }
                _ = done_tx.send(());
            }));
        }
        drop(done_tx);

        for _ in 0..2 {
            done_rx
                .recv_timeout(Duration::from_secs(30))
                .expect("a formatter did not finish: the entry lock deadlocked");
        }
        for handle in handles {
            handle.join().expect("formatter thread panicked");
        }
    }

    /// An entry evicted while a caller holds it stays valid for that caller.
    ///
    /// The handle closes when the LAST `Arc` drops, so eviction can never close
    /// a handle out from under a formatter mid-call. A correctness property, and
    /// the reason the entries are `Arc` rather than owned by the map.
    #[test]
    fn eviction_cannot_close_a_handle_a_caller_still_holds() {
        let _seams = SeamSession::acquire();
        clear_all();

        let held = publisher_entry("Held-Provider");
        for i in 0..(PUBLISHER_CACHE_CAPACITY + 8) {
            _ = publisher_entry(&format!("Filler-{i}"));
        }
        assert_eq!(
            publisher_len(),
            PUBLISHER_CACHE_CAPACITY,
            "the publisher cache is bounded too"
        );

        // Evicted from the map, still usable through the Arc the caller took.
        let mut publisher = held.lock();
        _ = publisher.raw("Held-Provider", false);
    }
}
