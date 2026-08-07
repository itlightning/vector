use std::{
    collections::HashMap,
    num::{NonZeroU32, NonZeroUsize},
    sync::Arc,
};

use lru::LruCache;

use governor::{
    Quota, RateLimiter,
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
};
use metrics::{Counter, Gauge, counter, gauge};
use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::System::EventLog::{
    EVT_HANDLE, EvtClose, EvtNext, EvtOpenChannelConfig, EvtSubscribe,
    EvtSubscribeStartAfterBookmark, EvtSubscribeStartAtOldestRecord, EvtSubscribeStrict,
    EvtSubscribeToFutureEvents,
};
use windows::Win32::System::Threading::{
    CreateEventW, ResetEvent, SetEvent, WaitForMultipleObjects,
};
use windows::core::HSTRING;

use super::{
    bookmark::BookmarkManager,
    checkpoint::{ChannelPosition, Checkpointer},
    config::WindowsEventLogConfig,
    error::*,
    metadata,
    recovery::{
        Backoff, BatchAdaptation, EpisodeState, FailureEdge, GapDetection, GapVerdict, ResumeState,
        Rung, evaluate_gap, jitter_seed,
    },
    sid_resolver::SidResolver,
    win32_errors::{
        DrainOutcome, QueryOrigin, SkipReason, SubscribeOutcome, classify_evt_next,
        classify_subscribe, describe, win32_code,
    },
    xml_parser,
};

use crate::internal_events::WindowsEventLogBookmarkError;

/// Test-only hook called inside the `pull_events` drain loop after each
/// `EvtNext` invocation. Used by the lost-wakeup regression test
/// (see `test_pull_events_preserves_setevent_during_drain`) to race a
/// `SetEvent` against the drain without relying on thread-timing.
/// No-op and zero-cost in non-test builds.
///
/// Only one test should install a hook at a time; tests that install a hook
/// must use `#[serial_test::serial]` or equivalent serialization to prevent
/// concurrent tests from triggering each other's hook.
#[cfg(test)]
static DRAIN_STEP_HOOK: std::sync::Mutex<Option<std::sync::Arc<dyn Fn(HANDLE) + Send + Sync>>> =
    std::sync::Mutex::new(None);

/// Maximum number of entries in the EvtFormatMessage result cache.
pub const FORMAT_CACHE_CAPACITY: usize = 10_000;
/// Maximum number of cached publisher metadata handles.
const PUBLISHER_CACHE_CAPACITY: usize = 256;

/// RAII wrapper for EvtOpenPublisherMetadata handles.
/// Calls EvtClose on drop to prevent handle leaks when evicted from LRU cache.
pub struct PublisherHandle(pub isize);

impl Drop for PublisherHandle {
    fn drop(&mut self) {
        if self.0 != 0 {
            unsafe {
                let _ = EvtClose(EVT_HANDLE(self.0));
            }
        }
    }
}

/// Test-only handle accounting.
///
/// The discard-and-rebuild recovery model's main risk is leaking EVT handles:
/// every rebuild discards handles that `EvtNext` may have populated even while
/// failing. Counting opens and closes lets a test assert the balance returns to
/// baseline after N forced rebuilds, which needs no special build and targets
/// exactly that risk.
///
/// The counters live on the channel rather than in a global, so a test asserting
/// on them cannot be perturbed by any other test opening subscriptions in
/// parallel. They are `#[cfg(test)]` and never compile into shipped binaries.
/// Close an event handle returned by `EvtNext`, accounting for it.
///
/// `EvtNext` can return an error with handles already populated. Every path
/// that abandons a batch must run these handles through here or we leak.
#[inline]
fn close_event_handle(handle: EVT_HANDLE) {
    // A null handle is what the fault-injection seam produces for a scripted
    // count; it is accounted for above but must not reach the API.
    if handle.0 != 0 {
        unsafe {
            let _ = EvtClose(handle);
        }
    }
}

/// Test-only script that replaces the `EvtNext` result.
///
/// Plays a fixed sequence of `(win32_code, returned_count)` pairs, including
/// the error-with-nonzero-count case that the real API produces and that the
/// old drain loop silently dropped events on. Precedent: `DRAIN_STEP_HOOK`.
/// Only one test may install a script at a time; installers must serialize.
#[cfg(test)]
pub(super) static EVT_NEXT_SCRIPT: std::sync::Mutex<
    Option<std::collections::VecDeque<(u32, u32)>>,
> = std::sync::Mutex::new(None);

/// Test-only script that replaces the `EvtSubscribe` result with a win32 code.
///
/// A failed rebuild is otherwise unreachable from a test on a healthy host, and
/// the interesting case is precisely a failure that arrives while the current
/// subscription is still serving events (D22).
#[cfg(test)]
pub(super) static EVT_SUBSCRIBE_SCRIPT: std::sync::Mutex<Option<std::collections::VecDeque<u32>>> =
    std::sync::Mutex::new(None);

/// Test-only: force `render_event_xml` to fail, so the unprocessable-event path
/// (D19) can be exercised without a real malformed event.
#[cfg(test)]
pub(super) static FAIL_ALL_RENDERS: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Why a rebuild is happening, which decides what a failure is allowed to cost.
///
/// The distinction is the whole of D22: rebuilding a channel that is already
/// dead has nothing to preserve, but a proactive rebuild (periodic refresh,
/// batch reduction) runs against a HEALTHY subscription, and tearing that down
/// because its replacement failed to open is a self-inflicted outage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RebuildKind {
    /// There is no working subscription to lose.
    FromDead,
    /// The current subscription is serving events and must survive a failure.
    Proactive,
}

/// Builds subscriptions for one channel.
///
/// Holding the subscription behind a factory rather than a raw handle is the
/// central structural choice here, and it is Winlogbeat's: every recovery path
/// necessarily goes through `build`, so no call site can invent its own partial
/// recovery, and error classification is demoted from load-bearing to an
/// optimization. A missed error code then costs one extra rebuild instead of a
/// permanent wedge.
struct SubscriptionFactory {
    channel: String,
    /// The query as configured: either the operator's `event_query` or one we
    /// generated from `only_event_ids`.
    base_query: String,
    /// Whether `base_query` came from the operator. `ERROR_EVT_INVALID_QUERY`
    /// (15001) means "permanent config error" for an operator query and
    /// "advance one ladder rung" for one of ours, so origin must travel with
    /// the query.
    base_origin: QueryOrigin,
    read_existing_events: bool,
}

impl SubscriptionFactory {
    /// The query to subscribe with at this ladder rung, and its origin.
    ///
    /// A generated time predicate can only be composed onto a wildcard base;
    /// intersecting it with an arbitrary operator XPath is not reliably
    /// expressible. When we cannot compose, the subscription over-delivers and
    /// the exact in-process `(TimeCreated, RecordId)` boundary trims it, which
    /// is the same mechanism the millisecond flooring already relies on.
    fn query_for(&self, resume: &ResumeState) -> (String, QueryOrigin) {
        let Some(floor) = resume.time_floor() else {
            return (self.base_query.clone(), self.base_origin);
        };
        if !matches!(resume.rung, Rung::TimeAdvance(_)) || self.base_query != "*" {
            return (self.base_query.clone(), self.base_origin);
        }
        let predicate = format!(
            "*[System[TimeCreated[@SystemTime>='{}']]]",
            floor.format("%Y-%m-%dT%H:%M:%S%.3fZ")
        );
        (predicate, QueryOrigin::Generated)
    }

    /// Create a subscription handle. Never closes anything: the caller swaps
    /// the new handle in and only then closes the old one, so a failed
    /// `EvtSubscribe` cannot strand a channel with nothing (Fluent Bit's
    /// ordering).
    fn build(
        &self,
        signal_event: HANDLE,
        bookmark: &BookmarkManager,
        bookmark_positioned: bool,
        resume: &ResumeState,
    ) -> Result<(EVT_HANDLE, QueryOrigin), (windows::core::Error, QueryOrigin)> {
        let (query, origin) = self.query_for(resume);
        let channel_hstring = HSTRING::from(self.channel.as_str());
        let query_hstring = HSTRING::from(query.as_str());

        // A freshly created bookmark has a valid, non-null handle but marks no
        // position. Subscribing StartAfterBookmark|Strict against it fails with
        // ERROR_NOT_FOUND, so the handle being non-null is not the question:
        // whether it has ever been positioned is.
        let bookmark_handle = bookmark.as_handle();
        let use_bookmark = bookmark_positioned
            && resume.rung != Rung::FutureOnly
            && !matches!(resume.rung, Rung::TimeAdvance(_))
            && bookmark_handle.0 != 0;

        // EvtSubscribeStrict is load-bearing and must never be dropped:
        // without it Windows silently repositions on a dead bookmark, the
        // time-fallback rung never fires, and silent data loss presents as a
        // perfectly healthy subscription.
        let flags = if use_bookmark {
            EvtSubscribeStartAfterBookmark.0 | EvtSubscribeStrict.0
        } else if resume.rung == Rung::FutureOnly {
            EvtSubscribeToFutureEvents.0
        } else if resume.last_event_time.is_some() || self.read_existing_events {
            EvtSubscribeStartAtOldestRecord.0
        } else {
            EvtSubscribeToFutureEvents.0
        };

        let result = unsafe {
            EvtSubscribe(
                None,
                signal_event,
                &channel_hstring,
                &query_hstring,
                if use_bookmark {
                    bookmark_handle
                } else {
                    EVT_HANDLE(0)
                },
                None, // NULL context = pull mode
                None, // NULL callback = pull mode
                flags,
            )
        };

        // Test-only fault injection: replaces the API result with a scripted
        // win32 code. A successfully opened handle is closed here so the
        // injection cannot leak it.
        #[cfg(test)]
        let result = {
            let scripted = EVT_SUBSCRIBE_SCRIPT
                .lock()
                .unwrap()
                .as_mut()
                .and_then(std::collections::VecDeque::pop_front);
            match scripted {
                Some(code) => {
                    if let Ok(handle) = result {
                        unsafe {
                            let _ = EvtClose(handle);
                        }
                    }
                    Err(windows::core::Error::from_hresult(windows::core::HRESULT(
                        code as i32,
                    )))
                }
                None => result,
            }
        };

        match result {
            Ok(handle) => Ok((handle, origin)),
            Err(e) => Err((e, origin)),
        }
    }
}

/// Per-channel subscription state for pull model.
struct ChannelSubscription {
    channel: String,
    /// `None` while the channel is down between a teardown and a successful
    /// rebuild. Never a stale handle: there is no state in which a discarded
    /// handle is still reachable.
    subscription_handle: Option<EVT_HANDLE>,
    factory: SubscriptionFactory,
    /// Origin of the query the live subscription was built with, which is what
    /// splits 15001 by meaning.
    active_query_origin: QueryOrigin,
    signal_event: HANDLE,
    bookmark: BookmarkManager,
    /// Whether `bookmark` marks a real position. A freshly created bookmark is
    /// a valid handle that marks nothing, and subscribing strictly against it
    /// fails with ERROR_NOT_FOUND.
    bookmark_positioned: bool,
    resume: ResumeState,
    backoff: Backoff,
    batch: BatchAdaptation,
    episode: EpisodeState,
    /// Earliest instant at which a rebuild may be attempted.
    retry_at: Option<std::time::Instant>,
    /// Skipped for this subscription generation. The periodic refresh is what
    /// retries it, so an ACL flap heals within a day with no special case.
    skipped_this_generation: Option<SkipReason>,
    /// When the next periodic refresh is due.
    next_refresh: std::time::Instant,
    /// `TimeCreated` of the most recent event, for the triage fields on the
    /// onset and recovery edges.
    last_event_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Previous record id, for gap detection.
    last_record_id_seen: Option<u64>,
    /// The active query filters events, so record ids skip by construction and
    /// gap detection cannot mean anything on this channel.
    query_filters: bool,
    /// Test-only handle accounting, per channel so parallel tests cannot
    /// perturb each other. `opens - closes` must return to its baseline after
    /// any number of rebuilds.
    #[cfg(test)]
    subscription_opens: i64,
    #[cfg(test)]
    subscription_closes: i64,
    #[cfg(test)]
    event_handle_closes: i64,
    /// Pre-registered counter for events read on this channel.
    events_read_counter: Counter,
    /// Pre-registered counter for render errors on this channel.
    render_errors_counter: Counter,
    /// Gauge indicating whether this channel subscription is active (1.0) or failed (0.0).
    subscription_active_gauge: Gauge,
    /// Gauge tracking the timestamp (unix seconds) of the last event received on this channel.
    last_event_timestamp_gauge: Gauge,
    /// Gauge tracking total record count in the channel log.
    /// SOC teams use `rate(events_read_total)` vs this gauge to detect ingestion lag.
    channel_records_gauge: Gauge,
    /// Set once any event on this channel arrived carrying `<RenderingInfo>`,
    /// i.e. was delivered as forwarded rendered text. Sticky for the process
    /// lifetime of the channel because record-id trust is a property of the
    /// channel's population, not of the individual event that revealed it.
    rendered_delivery_seen: bool,
}

// SAFETY: Windows kernel handles are thread-safe, and this type is only ever
// moved between threads by ownership transfer (see `with_subscription_blocking`
// in mod.rs), never shared. The `Sync` impl is therefore broader than the
// ownership-transfer pattern actually needs: it is harmless while nothing holds
// a shared reference, but a future change must not quietly come to depend on
// it. Winlogbeat's shutdown access-violation class (closing EVT handles from a
// thread other than the one rendering) is structurally impossible here for the
// same reason: exactly one thread holds the subscription at a time, and
// shutdown signals a separate Windows event object rather than closing handles
// across threads.
unsafe impl Send for ChannelSubscription {}
unsafe impl Sync for ChannelSubscription {}

impl ChannelSubscription {
    /// Whether this channel is currently readable.
    const fn is_live(&self) -> bool {
        self.subscription_handle.is_some() && self.skipped_this_generation.is_none()
    }

    /// Close the current subscription handle, if any, accounting for it.
    ///
    /// No self-cancel flag rides this close: the subscription is moved into the
    /// blocking task by ownership transfer, so there is never a drain in flight
    /// on another thread for this close to be misread by. See the
    /// `ERROR_CANCELLED` arm in `win32_errors`.
    fn close_current(&mut self) {
        if let Some(handle) = self.subscription_handle.take() {
            #[cfg(test)]
            {
                self.subscription_closes += 1;
            }
            unsafe {
                let _ = EvtClose(handle);
            }
        }
    }

    /// Build a new subscription and swap it in.
    ///
    /// Build-new-then-swap, never close-then-build: a failed `EvtSubscribe`
    /// after a close-first leaves the channel stranded with nothing, which is a
    /// self-inflicted outage. On success the old handle is closed only after
    /// the new one exists.
    ///
    /// `kind` decides what a FAILURE is allowed to cost. Build-new-then-swap is
    /// not only about the order of two calls: a proactive rebuild runs against a
    /// live subscription, so a failed replacement must leave that subscription
    /// serving events and be retried later. Closing it would be exactly the
    /// strand D22 exists to prevent.
    fn rebuild(&mut self, cause: &str, kind: RebuildKind) -> bool {
        self.retry_at = None;

        match self.factory.build(
            self.signal_event,
            &self.bookmark,
            self.bookmark_positioned,
            &self.resume,
        ) {
            Ok((handle, origin)) => {
                self.close_current();
                #[cfg(test)]
                {
                    self.subscription_opens += 1;
                }
                self.subscription_handle = Some(handle);
                self.active_query_origin = origin;
                self.skipped_this_generation = None;
                self.backoff.reset();
                self.subscription_active_gauge.set(1.0);
                counter!(
                    "windows_event_log_subscriptions_total",
                    "channel" => self.channel.clone()
                )
                .increment(1);

                // Recovery WARN, once per episode, carrying the rung we came
                // back on and how far behind the channel is in data terms.
                if self.episode.observe_recovery() {
                    let resumed_from = self.resume.rung.resumed_from().as_str();
                    let last_event_at = self.last_event_at_rfc3339();
                    // Bypasses the internal log rate limiter: its bucket key is
                    // callsite plus component_id and does NOT include the
                    // channel, so on a multi-channel source the second
                    // channel's edges would be swallowed.
                    warn!(
                        message = format!(
                            "Windows Event Log channel recovered (channel={}, resumed_from={}, last_event_at={}).",
                            self.channel, resumed_from, last_event_at
                        ),
                        error_type = "channel_recovered",
                        channel = %self.channel,
                        resumed_from = resumed_from,
                        last_event_at = %last_event_at,
                        cause = cause,
                        internal_log_rate_limit = false,
                    );
                } else {
                    debug!(
                        message = "Windows Event Log subscription created.",
                        channel = %self.channel,
                        cause = cause,
                        rung = self.resume.rung.as_str(),
                    );
                }
                true
            }
            Err((error, origin)) => {
                let code = win32_code(&error);

                // D22. A proactive rebuild's replacement failed, but the current
                // subscription is healthy and still serving events. Keep it,
                // say so at DEBUG (this is not an episode: nothing is down), and
                // come back to it on a backoff-spaced schedule.
                if kind == RebuildKind::Proactive && self.subscription_handle.is_some() {
                    let retry_in = self.backoff.next_delay();
                    self.next_refresh = std::time::Instant::now() + retry_in;
                    debug!(
                        message = "Proactive Windows Event Log rebuild failed; keeping the live subscription.",
                        channel = %self.channel,
                        cause = cause,
                        win32_error = code,
                        win32_error_name = describe(code).unwrap_or("unknown"),
                        retry_in_ms = retry_in.as_millis() as u64,
                    );
                    return false;
                }

                self.close_current();
                self.subscription_active_gauge.set(0.0);

                match classify_subscribe(code, origin) {
                    SubscribeOutcome::SkipChannel(reason) => {
                        self.skip_channel(reason, code, &error);
                    }
                    SubscribeOutcome::BookmarkDead => {
                        // Not a poison event: the stored position no longer
                        // resolves, so there is no offending record to skip and
                        // nothing to isolate. Go to the time rung directly, or
                        // to future-only when there is no stored time at all.
                        let rung = self.resume.bookmark_dead();
                        self.bookmark_positioned = false;
                        self.log_rung_advance(rung, code, "bookmark_dead");
                        self.schedule_retry(code, &error, cause);
                    }
                    SubscribeOutcome::GeneratedQueryInvalid => {
                        // Our own ladder predicate is invalid. Advance exactly
                        // one rung (D21) and never retry the same predicate.
                        let rung = self.resume.advance_rung();
                        self.log_rung_advance(rung, code, "generated_query_invalid");
                        if rung == Rung::IsolateOne {
                            self.batch.isolate();
                        }
                        self.schedule_retry(code, &error, cause);
                    }
                    SubscribeOutcome::Retry => self.schedule_retry(code, &error, cause),
                }
                false
            }
        }
    }

    /// Announce a resume-ladder move. Every rung is deliberate data loss and
    /// must be visible; the terminal rung discards the whole backlog and is
    /// therefore an ERROR (D16).
    fn log_rung_advance(&self, rung: Rung, code: u32, reason: &str) {
        if rung == Rung::FutureOnly {
            error!(
                message = format!(
                    "Windows Event Log channel fell back to future-events-only; \
                     backlog for this channel is not recoverable (channel={}).",
                    self.channel
                ),
                error_type = "resume_future_only",
                channel = %self.channel,
                reason = reason,
                win32_error = code,
                internal_log_rate_limit = false,
            );
        } else {
            warn!(
                message = "Advancing Windows Event Log resume ladder.",
                channel = %self.channel,
                rung = rung.as_str(),
                reason = reason,
                win32_error = code,
                win32_error_name = describe(code).unwrap_or("unknown"),
                internal_log_rate_limit = false,
            );
        }
    }

    /// Skip this channel for this subscription generation.
    ///
    /// The 24h periodic refresh is what retries it, so a transient ACL flap
    /// heals within a day out of a mechanism already in the plan, and a
    /// permanently unreadable channel costs one warning per day rather than one
    /// per minute.
    fn skip_channel(&mut self, reason: SkipReason, code: u32, error: &windows::core::Error) {
        self.close_current();
        self.skipped_this_generation = Some(reason);
        self.subscription_active_gauge.set(0.0);
        error!(
            message = format!(
                "Windows Event Log channel skipped for this subscription generation \
                 (channel={}, reason={:?}, last_event_at={}).",
                self.channel,
                reason,
                self.last_event_at_rfc3339()
            ),
            error_type = "channel_skipped",
            channel = %self.channel,
            reason = ?reason,
            win32_error = code,
            win32_error_name = describe(code).unwrap_or("unknown"),
            hresult = error.code().0,
            internal_log_rate_limit = false,
        );
    }

    /// Log the failure edge and arm the backoff timer.
    fn schedule_retry(&mut self, code: u32, error: &windows::core::Error, cause: &str) {
        let delay = self.backoff.next_delay();
        self.retry_at = Some(std::time::Instant::now() + delay);

        let name = describe(code).unwrap_or("unknown");
        let last_event_at = self.last_event_at_rfc3339();
        match self.episode.observe_failure(std::time::Instant::now()) {
            FailureEdge::Onset => {
                error!(
                    message = format!(
                        "Windows Event Log channel query failed (channel={}, win32_error={}, \
                         last_event_at={}).",
                        self.channel, code, last_event_at
                    ),
                    error_type = "query_failed",
                    channel = %self.channel,
                    win32_error = code,
                    win32_error_name = name,
                    hresult = error.code().0,
                    last_event_at = %last_event_at,
                    cause = cause,
                    retry_in_ms = delay.as_millis() as u64,
                    internal_log_rate_limit = false,
                );
            }
            FailureEdge::OngoingReminder => {
                debug!(
                    message = "Windows Event Log channel still unavailable.",
                    error_type = "channel_unavailable_ongoing",
                    channel = %self.channel,
                    win32_error = code,
                    win32_error_name = name,
                    last_event_at = %last_event_at,
                    attempt = self.backoff.attempt(),
                    internal_log_rate_limit = false,
                );
            }
            FailureEdge::Repeat => {
                debug!(
                    message = "Windows Event Log channel rebuild failed, retrying.",
                    channel = %self.channel,
                    win32_error = code,
                    win32_error_name = name,
                    retry_in_ms = delay.as_millis() as u64,
                );
            }
        }
    }

    /// RFC3339 `last_event_at`, or a literal marker when the channel has never
    /// produced an event for us. Absolute, so consumers derive the age.
    ///
    /// Quiet channels make a large value normal, so this is triage context and
    /// must never be a severity input.
    fn last_event_at_rfc3339(&self) -> String {
        self.last_event_at
            .map_or_else(|| "never".to_string(), |t| t.to_rfc3339())
    }

    /// The checkpoint position for this channel: the opaque bookmark plus the
    /// additive `(TimeCreated, EventRecordID)` fallback the resume ladder needs
    /// when the bookmark turns out to be dead.
    fn position(&self) -> Option<ChannelPosition> {
        let bookmark_xml = match BookmarkManager::serialize_handle(self.bookmark.as_handle()) {
            Ok(xml) if xml_parser::is_valid_bookmark_xml(&xml) => xml,
            Ok(_) => return None,
            Err(e) => {
                emit!(WindowsEventLogBookmarkError {
                    channel: self.channel.clone(),
                    error: e.to_string(),
                });
                return None;
            }
        };
        Some(ChannelPosition {
            channel: self.channel.clone(),
            bookmark_xml,
            // Full FILETIME (100ns) resolution: RFC3339 with nanoseconds.
            last_event_time: self
                .resume
                .last_event_time
                .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)),
            last_record_id: self.resume.last_record_id,
        })
    }

    /// Close a handle returned by `EvtNext`, accounting for it.
    fn discard_event_handle(&mut self, handle: EVT_HANDLE) {
        #[cfg(test)]
        {
            self.event_handle_closes += 1;
        }
        close_event_handle(handle);
    }

    /// Gap-detection applicability for this channel.
    const fn gap_detection(&self) -> GapDetection {
        GapDetection {
            query_filters: self.query_filters,
            rendered_delivery: self.rendered_delivery_seen,
        }
    }
}

/// Result of waiting for events across all channels.
pub enum WaitResult {
    /// At least one channel has events available.
    EventsAvailable,
    /// Timeout expired without any events.
    Timeout,
    /// Shutdown was signaled.
    Shutdown,
}

/// Pull-model Windows Event Log subscription using EvtSubscribe + signal event + EvtNext.
///
/// Instead of a callback (push model), we use:
/// 1. `CreateEventW` to create a manual-reset signal per channel
/// 2. `EvtSubscribe` with NULL callback (pull mode) and signal event
/// 3. `WaitForMultipleObjects` to wait for any channel signal or shutdown
/// 4. `EvtNext` to pull events in batches when signaled
///
/// This eliminates event drops under back pressure because we don't call
/// `EvtNext` again until the pipeline has consumed the current batch.
pub struct EventLogSubscription {
    config: Arc<WindowsEventLogConfig>,
    channels: Vec<ChannelSubscription>,
    checkpointer: Arc<Checkpointer>,
    rate_limiter: Option<RateLimiter<NotKeyed, InMemoryState, DefaultClock>>,
    shutdown_event: HANDLE,
    render_buffer: Vec<u8>,
    /// Cached EvtOpenPublisherMetadata handles keyed by provider name.
    /// Bounded LRU; evicted handles are closed via `PublisherHandle::drop`.
    publisher_cache: LruCache<String, PublisherHandle>,
    /// Cached EvtFormatMessage results. Outer key is provider name (looked up
    /// via `&str` — zero allocation on the hot path), inner LRU is bounded per provider.
    format_cache: HashMap<String, LruCache<(u32, u64), Option<String>>>,
    /// Pre-registered counter for metadata cache hits.
    cache_hits_counter: Counter,
    /// Pre-registered counter for metadata cache misses.
    cache_misses_counter: Counter,
    /// SID-to-username resolver with LRU cache.
    sid_resolver: SidResolver,
    /// Reusable UTF-16 decode buffer to avoid per-event allocations.
    decode_buffer: Vec<u16>,
    /// How often each channel subscription is rebuilt from its bookmark.
    refresh_interval: std::time::Duration,
    /// Round-robin index for fair channel scheduling. Rotates the starting
    /// channel each pull_events call to prevent a single busy channel
    /// (e.g., Security on a domain controller) from starving others.
    round_robin_index: usize,
}

// SAFETY: Windows HANDLE and EVT_HANDLE are kernel objects safe to use across
// threads. In windows 0.58, HANDLE wraps *mut c_void which is !Send/!Sync,
// but the underlying kernel handles are thread-safe. All mutation requires
// &mut self; &self methods are read-only or delegate to Sync types (RateLimiter).
unsafe impl Send for EventLogSubscription {}
unsafe impl Sync for EventLogSubscription {}

impl EventLogSubscription {
    /// Create a new pull-model subscription for all configured channels.
    ///
    /// Each channel gets its own signal event and EvtSubscribe handle.
    /// A shutdown event is created for clean termination of blocking waits.
    pub async fn new(
        config: &WindowsEventLogConfig,
        checkpointer: Arc<Checkpointer>,
        _acknowledgements: bool,
    ) -> Result<Self, WindowsEventLogError> {
        // Create rate limiter if configured
        let rate_limiter = if config.events_per_second > 0 {
            NonZeroU32::new(config.events_per_second).map(|rate| {
                info!(
                    message = "Enabling rate limiting for Windows Event Log source.",
                    events_per_second = config.events_per_second
                );
                RateLimiter::direct(Quota::per_second(rate))
            })
        } else {
            None
        };

        let config = Arc::new(config.clone());

        // Validate channels exist and are accessible
        Self::validate_channels(&config)?;

        // Store as isize while held across await points (HANDLE wraps *mut c_void which is !Send)
        let shutdown_event_raw: isize = unsafe {
            let h = CreateEventW(None, true, false, None).map_err(|e| {
                WindowsEventLogError::ConfigError {
                    message: format!("Failed to create shutdown event: {e}"),
                }
            })?;
            h.0 as isize
        };

        let mut channel_subscriptions = Vec::with_capacity(config.channels.len());

        let refresh_interval = config.subscription_refresh_interval();
        let base_query = build_xpath_query(&config)?;
        let base_origin = if config.event_query.is_some() {
            QueryOrigin::Operator
        } else {
            QueryOrigin::Generated
        };
        // A filtering query skips record ids by construction, so gap detection
        // has nothing to say on it.
        let query_filters = base_query != "*";

        for channel in &config.channels {
            // Initialize bookmark and resume position from the checkpoint.
            let checkpoint = checkpointer.get(channel).await;
            let mut resume = ResumeState::new(true);
            let mut bookmark_positioned = false;
            let bookmark = match checkpoint.as_ref() {
                Some(checkpoint) => match BookmarkManager::from_xml(&checkpoint.bookmark_xml) {
                    Ok(bm) => {
                        info!(
                            message = "Resuming from checkpoint bookmark.",
                            channel = %channel
                        );
                        bookmark_positioned = true;
                        bm
                    }
                    Err(e) => {
                        warn!(
                            message = "Corrupted bookmark XML in checkpoint, creating fresh bookmark. Potential re-delivery of events.",
                            channel = %channel,
                            error = %e
                        );
                        BookmarkManager::new()?
                    }
                },
                None => {
                    info!(
                        message = "No checkpoint found, creating fresh bookmark.",
                        channel = %channel
                    );
                    BookmarkManager::new()?
                }
            };

            // The additive position fields, when present, give the ladder a
            // place to fall back to if the bookmark turns out to be dead.
            if let Some(checkpoint) = checkpoint.as_ref()
                && let (Some(time), Some(record_id)) = (
                    checkpoint
                        .last_event_time
                        .as_deref()
                        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                        .map(|dt| dt.with_timezone(&chrono::Utc)),
                    checkpoint.last_record_id,
                )
            {
                resume.observe_event(time, record_id);
            }
            let resume_seed_time = resume.last_event_time;

            // Create manual-reset signal event, initially signaled.
            // Initially signaled ensures the first iteration drains any buffered events.
            // Manual reset prevents missing signals between WaitForMultipleObjects return
            // and EvtNext draining.
            let signal_event = unsafe {
                CreateEventW(None, true, true, None).map_err(|e| {
                    WindowsEventLogError::ConfigError {
                        message: format!(
                            "Failed to create signal event for channel '{channel}': {e}"
                        ),
                    }
                })?
            };

            let factory = SubscriptionFactory {
                channel: channel.clone(),
                base_query: base_query.clone(),
                base_origin,
                read_existing_events: config.read_existing_events,
            };

            debug!(
                message = "Creating pull-mode subscription.",
                channel = %channel,
                query = %base_query,
                read_existing = config.read_existing_events,
            );

            let subscription_active_gauge = gauge!(
                "windows_event_log_subscription_active",
                "channel" => channel.clone()
            );

            let mut channel_sub = ChannelSubscription {
                channel: channel.clone(),
                subscription_handle: None,
                factory,
                active_query_origin: base_origin,
                signal_event,
                bookmark,
                bookmark_positioned,
                resume,
                backoff: Backoff::new(jitter_seed(channel)),
                batch: BatchAdaptation::new(config.batch_size as usize),
                episode: EpisodeState::default(),
                retry_at: None,
                skipped_this_generation: None,
                next_refresh: std::time::Instant::now() + refresh_interval,
                // Seeded from the checkpoint, not left unknown until the first
                // event arrives. An onset ERROR raised right after a restart
                // would otherwise report `last_event_at=never` on a channel
                // that has been collecting for weeks, which is the opposite of
                // the triage fact D29 exists to carry.
                last_event_at: resume_seed_time,
                last_record_id_seen: None,
                query_filters,
                #[cfg(test)]
                subscription_opens: 0,
                #[cfg(test)]
                subscription_closes: 0,
                #[cfg(test)]
                event_handle_closes: 0,
                events_read_counter: counter!(
                    "windows_event_log_events_read_total",
                    "channel" => channel.clone()
                ),
                render_errors_counter: counter!(
                    "windows_event_log_render_errors_total",
                    "channel" => channel.clone()
                ),
                subscription_active_gauge,
                last_event_timestamp_gauge: gauge!(
                    "windows_event_log_last_event_timestamp_seconds",
                    "channel" => channel.clone()
                ),
                channel_records_gauge: gauge!(
                    "windows_event_log_channel_records_total",
                    "channel" => channel.clone()
                ),
                rendered_delivery_seen: false,
            };

            // A channel that cannot be built right now is NOT a startup
            // failure. Vector never gives up on its own: it keeps rebuilding
            // with backoff and the agent decides when to stop asking. The
            // original wedge was the opposite polarity.
            channel_sub.rebuild("startup", RebuildKind::FromDead);
            channel_subscriptions.push(channel_sub);
        }

        // Verify we have at least one channel to work with. Channels that are
        // merely unavailable right now are kept and retried; only a
        // configuration that names no usable channel at all is an error.
        if channel_subscriptions.is_empty() {
            unsafe {
                let _ = CloseHandle(HANDLE(shutdown_event_raw as *mut std::ffi::c_void));
            }
            return Err(WindowsEventLogError::ConfigError {
                message: "No channels could be subscribed to. All channels may be inaccessible or direct/analytic channels.".into(),
            });
        }

        info!(
            message = "Successfully subscribed to channels (pull mode).",
            channel_count = channel_subscriptions.len()
        );

        let shutdown_event = HANDLE(shutdown_event_raw as *mut std::ffi::c_void);
        Ok(Self {
            config,
            channels: channel_subscriptions,
            checkpointer,
            rate_limiter,
            shutdown_event,
            render_buffer: vec![0u8; 16384],
            publisher_cache: LruCache::new(NonZeroUsize::new(PUBLISHER_CACHE_CAPACITY).unwrap()),
            format_cache: HashMap::new(),
            cache_hits_counter: counter!("windows_event_log_cache_hits_total"),
            cache_misses_counter: counter!("windows_event_log_cache_misses_total"),
            sid_resolver: SidResolver::new(),
            decode_buffer: vec![0u16; 8192],
            refresh_interval,
            round_robin_index: 0,
        })
    }

    /// Wait for events to become available on any channel, or for shutdown.
    ///
    /// Uses `WaitForMultipleObjects` via `spawn_blocking` to avoid blocking the
    /// Tokio runtime. The wait array puts shutdown first so a stop request wins
    /// over any channel that is already signaled.
    pub fn wait_for_events_blocking(&self, timeout_ms: u32) -> WaitResult {
        // Build wait handle array: [shutdown_event, channel0_signal, channel1_signal, ...]
        let mut handles = Vec::with_capacity(self.channels.len() + 1);
        handles.push(self.shutdown_event);
        handles.extend(self.channels.iter().map(|c| c.signal_event));

        let result = unsafe { WaitForMultipleObjects(&handles, false, timeout_ms) };

        match result {
            r if r == WAIT_TIMEOUT => WaitResult::Timeout,
            r if r == WAIT_OBJECT_0 => WaitResult::Shutdown,
            r if r.0 <= WAIT_OBJECT_0.0 + self.channels.len() as u32 => WaitResult::EventsAvailable,
            _ => {
                // WAIT_FAILED or unexpected - treat as timeout to avoid tight loop
                warn!(
                    message = "WaitForMultipleObjects returned unexpected result.",
                    result = result.0
                );
                WaitResult::Timeout
            }
        }
    }

    /// Pull events from all signaled channels with fair scheduling.
    ///
    /// Each channel gets a per-channel budget of `max_events / num_channels`
    /// to prevent a single busy channel (e.g., Security) from starving others.
    /// The starting channel rotates each call via round-robin. Channels that
    /// don't use their budget simply leave slots unused — the next pull_events
    /// call reclaims them naturally since the signal stays set.
    ///
    /// # At-least-once delivery semantics
    ///
    /// If a bookmark update fails mid-batch, events processed *before* the
    /// failure are still returned and sent downstream, but the bookmark position
    /// does not advance. On restart, those events will be re-read from the
    /// channel, resulting in duplicates. This is an intentional trade-off:
    /// at-least-once delivery is preferable to data loss.
    pub fn pull_events(
        &mut self,
        max_events: usize,
    ) -> Result<Vec<xml_parser::WindowsEvent>, WindowsEventLogError> {
        self.pull_events_inner(max_events, true)
    }

    /// Pull events for timeout-based speculative recovery.
    ///
    /// This keeps the same event-drain behavior as `pull_events`, but avoids
    /// refreshing per-channel record-count gauges for channels that were empty.
    /// Timeout pulls can run repeatedly while the host is idle, so skipping
    /// those metadata queries prevents steady `EvtOpenLog`/`EvtGetLogInfo`
    /// churn without changing event recovery behavior.
    pub fn pull_events_speculative(
        &mut self,
        max_events: usize,
    ) -> Result<Vec<xml_parser::WindowsEvent>, WindowsEventLogError> {
        self.pull_events_inner(max_events, false)
    }

    fn pull_events_inner(
        &mut self,
        max_events: usize,
        update_records_for_empty_channels: bool,
    ) -> Result<Vec<xml_parser::WindowsEvent>, WindowsEventLogError> {
        let mut all_events = Vec::with_capacity(max_events.min(1000));
        let num_channels = self.channels.len().max(1);
        let per_channel_budget = (max_events / num_channels).max(1);
        let start = self.round_robin_index % num_channels;
        self.round_robin_index = self.round_robin_index.wrapping_add(1);

        for i in 0..num_channels {
            let channel_idx = (start + i) % num_channels;
            let now = std::time::Instant::now();
            let channel_sub = &mut self.channels[channel_idx];
            let channel_limit = per_channel_budget.min(max_events.saturating_sub(all_events.len()));

            if channel_limit == 0 {
                break;
            }

            // Reset the signal BEFORE anything else on this channel, including
            // the liveness gate below. A down channel `continue`s past the
            // drain, so if the signal were left set the outer wait would return
            // immediately and spin at full speed until the backoff expires.
            //
            // Resetting first is also the fix for the lost-wakeup race
            // (vectordotdev/vector#25194): the service signals this manual-reset
            // event on each new matching event, and SetEvent on an already-set
            // event is a no-op, so a post-drain reset would clobber any signal
            // raised during the drain and hang the subscription until the next
            // event arrives.
            unsafe {
                let _ = ResetEvent(channel_sub.signal_event);
            }

            // Periodic refresh. Rebuilding from the bookmark is clean by
            // construction (no gap, no duplicates), so the cost is near zero
            // and it bounds unknown-unknown degradation on subscriptions that
            // would otherwise live for weeks. It is also what retries a channel
            // skipped earlier for access denied.
            if now >= channel_sub.next_refresh {
                channel_sub.next_refresh = now + self.refresh_interval;
                let kind = if channel_sub.subscription_handle.is_some() {
                    RebuildKind::Proactive
                } else {
                    RebuildKind::FromDead
                };
                channel_sub.skipped_this_generation = None;
                channel_sub.rebuild("periodic_refresh", kind);
            }

            // A channel that is down waits out its backoff. Backoff carries
            // per-channel jitter, so an EventLog service restart does not have
            // every channel rebuild in lockstep against a service that is
            // already recovering.
            if !channel_sub.is_live() {
                if channel_sub.skipped_this_generation.is_some() {
                    continue;
                }
                match channel_sub.retry_at {
                    Some(at) if now < at => continue,
                    _ => {
                        if !channel_sub.rebuild("retry", RebuildKind::FromDead) {
                            continue;
                        }
                    }
                }
            }

            let mut channel_drained = false;
            let mut bookmark_failed = false;
            let mut channel_count = 0usize;

            // If we exit the drain loop early (channel budget exhausted or
            // bookmark update failed mid-batch), we re-SetEvent at the end
            // of this iteration so the next pull_events call revisits this
            // channel without waiting for a fresh OS signal.
            'drain: loop {
                if channel_count >= channel_limit {
                    break;
                }

                // Batch size is per channel and adaptive: one oversized event
                // must not permanently cap a channel's throughput.
                let batch_size = (channel_limit - channel_count).min(channel_sub.batch.current());
                let mut event_handles: Vec<isize> = vec![0isize; batch_size.max(1)];
                let mut returned: u32 = 0;

                let Some(handle) = channel_sub.subscription_handle else {
                    break;
                };

                let result = unsafe { EvtNext(handle, &mut event_handles, 0, 0, &mut returned) };

                // Test-only fault injection: replaces the API result with a
                // scripted (code, count) pair, including the
                // error-with-nonzero-count case the real API produces.
                #[cfg(test)]
                let result = {
                    let scripted = EVT_NEXT_SCRIPT
                        .lock()
                        .unwrap()
                        .as_mut()
                        .and_then(std::collections::VecDeque::pop_front);
                    match scripted {
                        Some((0, count)) => {
                            returned = count.min(event_handles.len() as u32);
                            Ok(())
                        }
                        Some((code, count)) => {
                            returned = count.min(event_handles.len() as u32);
                            Err(windows::core::Error::from_hresult(windows::core::HRESULT(
                                code as i32,
                            )))
                        }
                        None => result,
                    }
                };

                // Test-only hook: lets the lost-wakeup regression test race
                // a SetEvent against the drain without thread-timing. No-op
                // and zero-cost in non-test builds.
                #[cfg(test)]
                {
                    let hook = DRAIN_STEP_HOOK.lock().unwrap().clone();
                    if let Some(h) = hook {
                        h(channel_sub.signal_event);
                    }
                }

                if let Err(err) = result {
                    let code = win32_code(&err);
                    let outcome =
                        classify_evt_next(code, returned, channel_sub.active_query_origin);

                    // EvtNext can return an error with handles already
                    // populated. Whatever we do next, those handles are ours
                    // to close: leaving them is a leak, and retrying the same
                    // handle after such an error loses events, because on 1734
                    // the API cursor advances even when the call fails
                    // (Winlogbeat #3076).
                    if !matches!(outcome, DrainOutcome::Drained) {
                        for &raw in &event_handles[..returned as usize] {
                            channel_sub.discard_event_handle(EVT_HANDLE(raw));
                        }
                    }

                    match outcome {
                        DrainOutcome::Drained => {
                            channel_drained = true;
                            break;
                        }
                        DrainOutcome::SkipChannel(reason) => {
                            channel_sub.skip_channel(reason, code, &err);
                            channel_drained = true;
                            break;
                        }
                        DrainOutcome::ReduceBatch => {
                            let reduced = channel_sub.batch.halve();
                            warn!(
                                message = "Reducing Windows Event Log batch size after an oversized read.",
                                channel = %channel_sub.channel,
                                batch_size = reduced,
                                win32_error = code,
                                win32_error_name = describe(code).unwrap_or("unknown"),
                                internal_log_rate_limit = false,
                            );
                            // The current subscription is healthy: the batch was
                            // simply too large for the API to marshal. A failed
                            // replacement must not cost us the live one.
                            channel_sub.rebuild("batch_reduction", RebuildKind::Proactive);
                            channel_drained = true;
                            break;
                        }
                        DrainOutcome::Rebuild => {
                            // Discard, tear down, resubscribe from the last
                            // persisted checkpoint. Unknown codes land here on
                            // purpose: a missed code then costs one rebuild
                            // instead of a permanent wedge.
                            if channel_sub.resume.note_rebuild() {
                                // A deterministic failure at a fixed position
                                // would otherwise rebuild forever. Escape it in
                                // order of precision: isolate to one record,
                                // skip that record, and only then start
                                // discarding time windows.
                                let rung = channel_sub.resume.advance_rung();
                                if rung == Rung::IsolateOne {
                                    channel_sub.batch.isolate();
                                }
                                warn!(
                                    message = format!(
                                        "Windows Event Log resume position appears poisoned; \
                                         escaping by {} (channel={}).",
                                        rung.as_str(),
                                        channel_sub.channel
                                    ),
                                    error_type = "poison_escape",
                                    channel = %channel_sub.channel,
                                    rung = rung.as_str(),
                                    skipping_next_record = channel_sub.resume.skip_next_record,
                                    win32_error = code,
                                    internal_log_rate_limit = false,
                                );
                            }
                            channel_sub.close_current();
                            channel_sub.schedule_retry(code, &err, "evt_next");
                            channel_sub.subscription_active_gauge.set(0.0);
                            channel_drained = true;
                            break;
                        }
                    }
                }

                if returned == 0 {
                    channel_drained = true;
                    break;
                }

                channel_sub.events_read_counter.increment(returned as u64);
                channel_sub
                    .last_event_timestamp_gauge
                    .set(chrono::Utc::now().timestamp() as f64);

                let batch_handles = &event_handles[..returned as usize];
                for (idx, &raw_handle) in batch_handles.iter().enumerate() {
                    let event_handle = EVT_HANDLE(raw_handle);

                    match super::render::render_event_xml(
                        &mut self.render_buffer,
                        &mut self.decode_buffer,
                        event_handle,
                    ) {
                        Ok(xml) => {
                            // Single-pass: parse all System fields in one traversal
                            let system_fields = xml_parser::parse_system_section(&xml);

                            // Early pre-filter: discard non-matching event IDs before
                            // the expensive resolve_event_metadata / format_event_message
                            // calls. This guarantees improved performance even when
                            // XPath-level filtering is not applied (e.g. large ID lists).
                            if let Some(ref only_ids) = self.config.only_event_ids
                                && !only_ids.contains(&system_fields.event_id)
                            {
                                counter!("windows_event_log_events_filtered_total", "reason" => "event_id_prefilter")
                                    .increment(1);
                                channel_sub.discard_event_handle(event_handle);
                                continue;
                            }
                            if self
                                .config
                                .ignore_event_ids
                                .contains(&system_fields.event_id)
                            {
                                counter!("windows_event_log_events_filtered_total", "reason" => "event_id_prefilter")
                                    .increment(1);
                                channel_sub.discard_event_handle(event_handle);
                                continue;
                            }

                            let channel_name = if system_fields.channel.is_empty() {
                                channel_sub.channel.clone()
                            } else {
                                system_fields.channel.clone()
                            };
                            // Single decision point for the <RenderingInfo>
                            // crash guard: forwarded rendered-text events are
                            // parsed out of the XML and never reach
                            // EvtFormatMessage, which faults the process
                            // against an unreachable publisher rather than
                            // returning an error.
                            let display = metadata::resolve_event_display(
                                &mut self.publisher_cache,
                                &mut self.format_cache,
                                &self.cache_hits_counter,
                                &self.cache_misses_counter,
                                event_handle,
                                &xml,
                                &system_fields,
                                self.config.render_message,
                            );

                            if display.rendered_delivery && !channel_sub.rendered_delivery_seen {
                                // Same per-event signal that drives the crash
                                // guard also marks this channel's record IDs
                                // as untrustworthy: forwarded IDs come from
                                // many originating machines interleaved, so
                                // every batch would otherwise look like a gap.
                                channel_sub.rendered_delivery_seen = true;
                                channel_sub.resume.mark_record_identity_unusable();
                            }

                            if let Ok(Some(mut event)) = xml_parser::build_event(
                                xml,
                                &channel_name,
                                &self.config,
                                display.rendered_message,
                                system_fields,
                            ) {
                                event.task_name = display.task_name;
                                event.opcode_name = display.opcode_name;
                                event.keyword_names = display.keyword_names;

                                // Exact in-process boundary. The generated
                                // XPath predicate floors to the millisecond and
                                // therefore over-delivers; trimming here at
                                // full (TimeCreated, RecordId) resolution is
                                // what makes precision contribute zero
                                // duplicates on every resume path. It is also
                                // where a deliberately skipped poison record is
                                // dropped.
                                // `past_boundary` separates the two reasons a
                                // record is not emitted: an over-delivered
                                // duplicate (the XPath floors to the
                                // millisecond) versus the deliberate one-shot
                                // poison skip. Only the latter has to be made
                                // durable.
                                let past_boundary = channel_sub
                                    .resume
                                    .should_emit(event.time_created, event.record_id);
                                if !channel_sub
                                    .resume
                                    .admit(event.time_created, event.record_id)
                                {
                                    if past_boundary {
                                        // The poison skip. Advance the bookmark
                                        // and the boundary past it so a restart
                                        // does not resume onto the same record
                                        // and repeat the whole escape.
                                        if channel_sub.bookmark.update(event_handle).is_ok() {
                                            channel_sub.bookmark_positioned = true;
                                        }
                                        channel_sub
                                            .resume
                                            .observe_event(event.time_created, event.record_id);
                                        // The rung WARN already reported this
                                        // skip; leaving the gap detector behind
                                        // would report it a second time as an
                                        // unexplained gap.
                                        channel_sub.last_record_id_seen = Some(event.record_id);
                                    }
                                    counter!(
                                        "windows_event_log_events_filtered_total",
                                        "reason" => "resume_boundary"
                                    )
                                    .increment(1);
                                    channel_sub.discard_event_handle(event_handle);
                                    continue;
                                }

                                // Record-id gap detection: the only signal we
                                // have for retention-overwrite data loss, and
                                // customer-actionable (raise the channel's max
                                // size).
                                match evaluate_gap(
                                    channel_sub.last_record_id_seen,
                                    event.record_id,
                                    channel_sub.gap_detection(),
                                    channel_sub.resume.rung.is_deliberate_skip(),
                                ) {
                                    GapVerdict::Gap { missing } => {
                                        warn!(
                                            message = "Windows Event Log record ID gap detected; events were overwritten before they could be read.",
                                            error_type = "record_id_gap",
                                            channel = %channel_sub.channel,
                                            missing_records = missing,
                                            previous_record_id =
                                                channel_sub.last_record_id_seen,
                                            record_id = event.record_id,
                                            internal_log_rate_limit = false,
                                        );
                                    }
                                    GapVerdict::DeliberateSkip { missing } => {
                                        // Same gap, different story: the rung
                                        // WARN already reported this as
                                        // intentional. Quantify it without a
                                        // second, unexplained-sounding alarm.
                                        warn!(
                                            message = "Windows Event Log resume skip discarded records, as reported.",
                                            error_type = "record_id_gap_expected",
                                            channel = %channel_sub.channel,
                                            skipped_records = missing,
                                            rung = channel_sub.resume.rung.as_str(),
                                            internal_log_rate_limit = false,
                                        );
                                    }
                                    GapVerdict::Continuous | GapVerdict::Suppressed => {}
                                }
                                channel_sub.last_record_id_seen = Some(event.record_id);
                                channel_sub
                                    .resume
                                    .observe_event(event.time_created, event.record_id);
                                channel_sub.last_event_at = Some(event.time_created);

                                // Resolve SID to human-readable account name
                                if let Some(ref sid) = event.user_id {
                                    if let Some(account_name) = self.sid_resolver.resolve(sid) {
                                        event.user_name = Some(account_name);
                                    }
                                }

                                let bookmark_update = channel_sub.bookmark.update(event_handle);
                                if bookmark_update.is_ok() {
                                    channel_sub.bookmark_positioned = true;
                                }
                                if let Err(e) = bookmark_update {
                                    emit!(WindowsEventLogBookmarkError {
                                        channel: channel_sub.channel.clone(),
                                        error: e.to_string(),
                                    });
                                    bookmark_failed = true;
                                    // Events already in all_events will still be delivered
                                    // (at-least-once semantics — see doc comment on pull_events).
                                    // Close current handle normally
                                    channel_sub.discard_event_handle(event_handle);
                                    // Close remaining unprocessed handles to prevent leak
                                    for &h in &batch_handles[idx + 1..] {
                                        channel_sub.discard_event_handle(EVT_HANDLE(h));
                                    }
                                    break 'drain;
                                }
                                all_events.push(event);
                                channel_count += 1;
                            }
                        }
                        Err(e) => {
                            // A batch that READ successfully but contains one
                            // unprocessable event never tears down the
                            // subscription. One bad event costs one event. This
                            // path is entirely separate from an EvtNext
                            // failure, and conflating the two is what would
                            // turn a single malformed event into a channel
                            // outage.
                            channel_sub.render_errors_counter.increment(1);

                            // Advance the bookmark PAST the skipped event. The
                            // bookmark is updated from the event handle, which
                            // needs no successful render, so this works on
                            // exactly the event we could not process. Without
                            // it a restart resumes onto the same event, fails
                            // again, and skips it again forever: the event is
                            // never delivered and never passed, which is not
                            // "one bad event costs one event", it is a channel
                            // that can never make progress past it.
                            let advanced = channel_sub.bookmark.update(event_handle).is_ok();
                            if advanced {
                                channel_sub.bookmark_positioned = true;
                            }
                            warn!(
                                message = "Failed to render event XML; skipping this event and continuing the batch.",
                                channel = %channel_sub.channel,
                                batch_index = idx,
                                bookmark_advanced = advanced,
                                error = %e
                            );
                        }
                    }

                    channel_sub.discard_event_handle(event_handle);
                }

                // The batch read cleanly. Reset the ladder and give the batch
                // size a path back up, so a transient cause never leaves a
                // channel permanently coarse or slow.
                let was_escaping = channel_sub.resume.rung != Rung::Bookmark;
                channel_sub.resume.observe_clean_read();
                if was_escaping {
                    channel_sub.batch.restore();
                } else {
                    channel_sub.batch.observe_clean_batch();
                }
                channel_sub.backoff.reset();
            }

            if channel_drained && !bookmark_failed {
                // Update channel record count gauge for lag detection.
                if update_records_for_empty_channels || channel_count > 0 {
                    super::render::update_channel_records(
                        &channel_sub.channel,
                        &channel_sub.channel_records_gauge,
                    );
                }
            } else {
                // Drain exited early (budget exhausted or bookmark_failed
                // mid-batch). Re-arm the signal so the next pull_events
                // revisits this channel immediately without waiting for a
                // fresh OS notification. Pairs with the pre-drain ResetEvent
                // above.
                unsafe {
                    let _ = SetEvent(channel_sub.signal_event);
                }
            }
        }

        Ok(all_events)
    }

    /// Returns the raw shutdown event handle value for use in the async shutdown watcher.
    ///
    /// The returned pointer is the underlying value of the Windows HANDLE. It can be
    /// safely copied and used from another thread to call `SetEvent` because Windows
    /// kernel objects are reference-counted and remain valid as long as at least one
    /// handle is open (which this subscription maintains until Drop).
    pub const fn shutdown_event_raw(&self) -> *mut std::ffi::c_void {
        self.shutdown_event.0
    }

    /// Test-only accessor for the first channel's signal event handle. Used
    /// by the lost-wakeup regression test to scope its drain-loop hook to
    /// exactly this subscription, so it does not fire on concurrent
    /// `pull_events` calls from other tests in the same process.
    #[cfg(test)]
    pub(super) fn first_channel_signal_raw(&self) -> isize {
        self.channels[0].signal_event.0 as isize
    }

    /// Test-only: rebuild every channel immediately, ignoring backoff.
    ///
    /// Lets the handle-accounting test force N rebuilds without waiting out the
    /// real backoff schedule.
    #[cfg(test)]
    pub(super) fn force_rebuild_all(&mut self) {
        for channel in &mut self.channels {
            channel.rebuild("test_forced", RebuildKind::FromDead);
        }
    }

    /// Test-only: run a PROACTIVE rebuild on every channel, the way the periodic
    /// refresh and batch reduction do, i.e. against a subscription that is
    /// currently healthy.
    #[cfg(test)]
    pub(super) fn force_proactive_rebuild_all(&mut self) {
        for channel in &mut self.channels {
            channel.rebuild("test_proactive", RebuildKind::Proactive);
        }
    }

    /// Test-only: whether the first channel currently has a live subscription.
    #[cfg(test)]
    pub(super) fn first_channel_is_live(&self) -> bool {
        self.channels[0].is_live()
    }

    /// Test-only: open subscription handles outstanding on the first channel.
    #[cfg(test)]
    pub(super) fn first_channel_handle_balance(&self) -> i64 {
        self.channels[0].subscription_opens - self.channels[0].subscription_closes
    }

    /// Test-only: how many `EvtNext` handles the first channel has discarded.
    #[cfg(test)]
    pub(super) fn first_channel_event_handle_closes(&self) -> i64 {
        self.channels[0].event_handle_closes
    }

    /// Returns a reference to the rate limiter, if configured.
    pub const fn rate_limiter(
        &self,
    ) -> Option<&RateLimiter<NotKeyed, InMemoryState, DefaultClock>> {
        self.rate_limiter.as_ref()
    }

    /// Returns (total_channels, active_channels) for health reporting.
    pub fn channel_health_summary(&self) -> (usize, usize) {
        let total = self.channels.len();
        // A channel is considered active if its subscription handle is non-null
        let active = self.channels.iter().filter(|c| c.is_live()).count();
        (total, active)
    }

    /// Flush all bookmarks to checkpoint storage.
    ///
    /// Call this before shutdown to ensure no events are lost.
    pub async fn flush_bookmarks(&mut self) -> Result<(), WindowsEventLogError> {
        debug!(message = "Flushing bookmarks to checkpoint storage.");

        let positions: Vec<ChannelPosition> = self
            .channels
            .iter()
            .filter_map(|sub| sub.position())
            .collect();

        if !positions.is_empty() {
            self.checkpointer.set_batch(positions).await?;
            counter!("windows_event_log_checkpoint_writes_total").increment(1);
        }

        debug!(message = "Bookmark flush complete.");
        Ok(())
    }

    /// Get the current checkpoint position for a specific channel.
    ///
    /// Used for acknowledgment-based checkpointing where the position needs to
    /// be captured when events are read, not when they are acknowledged.
    pub fn channel_position(&self, channel: &str) -> Option<ChannelPosition> {
        self.channels
            .iter()
            .find(|sub| sub.channel == channel)
            .and_then(ChannelSubscription::position)
    }

    fn validate_channels(config: &WindowsEventLogConfig) -> Result<(), WindowsEventLogError> {
        for channel in &config.channels {
            let channel_hstring = HSTRING::from(channel.as_str());
            let channel_handle = unsafe { EvtOpenChannelConfig(None, &channel_hstring, 0) };

            match channel_handle {
                Ok(handle) => {
                    if let Err(e) = unsafe { EvtClose(handle) } {
                        warn!(message = "Failed to close channel config handle.", error = %e);
                    }
                }
                Err(e) => {
                    let code = win32_code(&e);
                    // A channel that is absent or unreadable right now is never
                    // a startup failure: the subscription loop keeps retrying
                    // it with backoff and the agent is what decides to stop
                    // asking. The original nine-hour wedge was a channel that
                    // provably existed and came back.
                    warn!(
                        message = "Channel not readable at startup; the subscription loop will keep retrying it.",
                        channel = %channel,
                        win32_error = code,
                        win32_error_name = describe(code).unwrap_or("unknown"),
                    );
                }
            }
        }

        Ok(())
    }
}

/// Maximum XPath query length supported by Windows Event Log API.
/// Queries exceeding this limit fall back to `"*"` (all events).
const XPATH_MAX_LENGTH: usize = 4096;

/// Build an XPath query from config, incorporating `only_event_ids` when no
/// explicit `event_query` is set.
///
/// When `only_event_ids` is configured and no custom `event_query` is provided,
/// generates a query like `*[System[EventID=4624 or EventID=4625]]` so that
/// the Windows API filters events at the source, avoiding the cost of pulling,
/// rendering, and discarding non-matching events.
///
/// If the generated query exceeds [`XPATH_MAX_LENGTH`] (4096 chars), falls back
/// to `"*"` and lets the downstream filter in `build_event()` handle it.
pub(super) fn build_xpath_query(
    config: &WindowsEventLogConfig,
) -> Result<String, WindowsEventLogError> {
    // Explicit event_query always takes precedence.
    if let Some(ref custom_query) = config.event_query {
        return Ok(custom_query.clone());
    }

    // Generate XPath from only_event_ids if present and non-empty.
    if let Some(ref ids) = config.only_event_ids
        && !ids.is_empty()
    {
        let query = if ids.len() == 1 {
            format!("*[System[EventID={}]]", ids[0])
        } else {
            let predicates: Vec<String> = ids.iter().map(|id| format!("EventID={id}")).collect();
            format!("*[System[{}]]", predicates.join(" or "))
        };

        if query.len() <= XPATH_MAX_LENGTH {
            return Ok(query);
        }
        // Query too long — fall back to wildcard and rely on
        // the in-process filter in build_event().
        warn!(
            message = "Generated XPath query exceeds maximum length, falling back to wildcard.",
            query_len = query.len(),
            max_len = XPATH_MAX_LENGTH,
            num_event_ids = ids.len(),
        );
    }

    Ok("*".to_string())
}

impl Drop for EventLogSubscription {
    fn drop(&mut self) {
        // Close subscription handles and signal events. Handles are closed on
        // the thread that owns the subscription, which is the same thread that
        // rendered from them: ownership transfer, not sharing.
        for sub in &mut self.channels {
            sub.close_current();
            unsafe {
                let _ = CloseHandle(sub.signal_event);
            }
        }
        // Publisher metadata handles are closed automatically by PublisherHandle::drop
        // when the LRU cache is dropped.

        // Close shutdown event
        unsafe {
            let _ = CloseHandle(self.shutdown_event);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    async fn create_test_checkpointer() -> (Arc<Checkpointer>, tempfile::TempDir) {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let checkpointer = Arc::new(Checkpointer::new(temp_dir.path()).await.unwrap());
        (checkpointer, temp_dir)
    }

    #[test]
    fn test_rate_limiter_configuration() {
        let mut config = WindowsEventLogConfig::default();
        assert_eq!(config.events_per_second, 0);

        config.events_per_second = 1000;
        assert_eq!(config.events_per_second, 1000);
    }

    #[tokio::test]
    async fn test_rate_limiter_disabled_by_default() {
        let config = WindowsEventLogConfig::default();
        assert_eq!(
            config.events_per_second, 0,
            "Rate limiting should be disabled by default"
        );
    }

    /// Test pull subscription creation and basic operation
    #[tokio::test]
    async fn test_pull_subscription_creation() {
        let mut config = WindowsEventLogConfig::default();
        config.channels = vec!["Application".to_string()];
        config.event_timeout_ms = 1000;

        let (checkpointer, _temp_dir) = create_test_checkpointer().await;

        let subscription = EventLogSubscription::new(&config, checkpointer, false).await;
        assert!(
            subscription.is_ok(),
            "Pull subscription creation should succeed: {:?}",
            subscription.err()
        );

        let sub = subscription.unwrap();
        assert_eq!(
            sub.channels.len(),
            1,
            "Should have one channel subscription"
        );
    }

    /// Test that wait_for_events_blocking returns timeout or events available
    #[tokio::test]
    async fn test_wait_for_events_timeout() {
        let mut config = WindowsEventLogConfig::default();
        config.channels = vec!["Application".to_string()];
        config.read_existing_events = false;
        config.event_timeout_ms = 100;

        let (checkpointer, _temp_dir) = create_test_checkpointer().await;

        let subscription = EventLogSubscription::new(&config, checkpointer, false)
            .await
            .expect("Subscription creation should succeed");

        // Use ownership transfer pattern for spawn_blocking
        let (subscription, result) = tokio::task::spawn_blocking(move || {
            let r = subscription.wait_for_events_blocking(100);
            (subscription, r)
        })
        .await
        .unwrap();

        // The first call may return EventsAvailable since signals are initially signaled.
        // That's expected behavior per the pull model design.
        match result {
            WaitResult::EventsAvailable | WaitResult::Timeout => {}
            WaitResult::Shutdown => panic!("Should not get shutdown"),
        }

        // Keep subscription alive until end of test
        drop(subscription);
    }

    /// Test that signal_shutdown wakes a waiting thread
    #[tokio::test]
    async fn test_shutdown_signal_wakes_wait() {
        let mut config = WindowsEventLogConfig::default();
        config.channels = vec!["Application".to_string()];
        config.event_timeout_ms = 500;

        let (checkpointer, _temp_dir) = create_test_checkpointer().await;

        let subscription = EventLogSubscription::new(&config, checkpointer, false)
            .await
            .expect("Subscription creation should succeed");

        // First drain the initially-signaled state using ownership transfer
        let (subscription, _) = tokio::task::spawn_blocking(move || {
            let r = subscription.wait_for_events_blocking(50);
            (subscription, r)
        })
        .await
        .unwrap();

        let shutdown_event_raw = subscription.shutdown_event_raw() as isize;

        let wait_handle = tokio::task::spawn_blocking(move || {
            let r = subscription.wait_for_events_blocking(30000);
            (subscription, r)
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        unsafe {
            let handle = HANDLE(shutdown_event_raw as *mut std::ffi::c_void);
            let _ = SetEvent(handle);
        }

        let (subscription, result) = wait_handle.await.unwrap();
        match result {
            WaitResult::Shutdown => {} // Expected
            WaitResult::EventsAvailable => {
                // Acceptable - there may have been real events
            }
            WaitResult::Timeout => {
                panic!("Should not timeout - shutdown should have woken the wait");
            }
        }

        drop(subscription);
    }

    /// Test that shutdown wins when both shutdown and channel handles are signaled.
    #[tokio::test]
    async fn test_shutdown_signal_takes_priority_over_channel_signal() {
        let mut config = WindowsEventLogConfig::default();
        config.channels = vec!["Application".to_string()];
        config.event_timeout_ms = 500;

        let (checkpointer, _temp_dir) = create_test_checkpointer().await;

        let subscription = EventLogSubscription::new(&config, checkpointer, false)
            .await
            .expect("Subscription creation should succeed");

        unsafe {
            let handle = HANDLE(subscription.shutdown_event_raw());
            let _ = SetEvent(handle);
        }

        let result = subscription.wait_for_events_blocking(0);
        assert!(
            matches!(result, WaitResult::Shutdown),
            "shutdown should take priority over already-signaled channels"
        );
    }

    /// Test pull_events with read_existing_events=true
    #[tokio::test]
    async fn test_pull_events_returns_events() {
        let mut config = WindowsEventLogConfig::default();
        config.channels = vec!["Application".to_string()];
        config.read_existing_events = true;
        config.event_timeout_ms = 2000;

        let (checkpointer, _temp_dir) = create_test_checkpointer().await;

        let subscription = EventLogSubscription::new(&config, checkpointer, false)
            .await
            .expect("Subscription creation should succeed");

        // Wait and pull using ownership transfer pattern
        let (mut subscription, wait_result) = tokio::task::spawn_blocking(move || {
            let r = subscription.wait_for_events_blocking(2000);
            (subscription, r)
        })
        .await
        .unwrap();

        match wait_result {
            WaitResult::EventsAvailable => {
                let events = subscription.pull_events(100).unwrap();
                assert!(
                    !events.is_empty(),
                    "With read_existing_events=true, should get historical events"
                );
            }
            WaitResult::Timeout => {
                // Might happen on a system with empty Application log
            }
            WaitResult::Shutdown => panic!("Unexpected shutdown"),
        }
    }

    /// Test multiple concurrent pull subscriptions
    #[tokio::test]
    async fn test_multiple_concurrent_subscriptions() {
        let mut config1 = WindowsEventLogConfig::default();
        config1.channels = vec!["Application".to_string()];
        config1.event_timeout_ms = 1000;

        let mut config2 = WindowsEventLogConfig::default();
        config2.channels = vec!["System".to_string()];
        config2.event_timeout_ms = 1000;

        let (checkpointer1, _temp_dir1) = create_test_checkpointer().await;
        let (checkpointer2, _temp_dir2) = create_test_checkpointer().await;

        let sub1 = EventLogSubscription::new(&config1, checkpointer1, false)
            .await
            .expect("Subscription 1 (Application) should succeed");
        let sub2 = EventLogSubscription::new(&config2, checkpointer2, false)
            .await
            .expect("Subscription 2 (System) should succeed");

        // Both should be independently functional
        assert_eq!(sub1.channels.len(), 1);
        assert_eq!(sub2.channels.len(), 1);
        assert_eq!(sub1.channels[0].channel, "Application");
        assert_eq!(sub2.channels[0].channel, "System");
    }

    /// Test read_existing_events=false only receives future events
    #[tokio::test]
    async fn test_read_existing_events_false_only_receives_future_events() {
        use chrono::Utc;

        let mut config = WindowsEventLogConfig::default();
        config.channels = vec!["Application".to_string()];
        config.read_existing_events = false;
        config.event_timeout_ms = 500;

        let (checkpointer, _temp_dir) = create_test_checkpointer().await;
        let subscription_start_time = Utc::now();

        let mut subscription = EventLogSubscription::new(&config, checkpointer, false)
            .await
            .expect("Subscription creation should succeed");

        // Brief wait then pull
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

        let events = subscription.pull_events(100).unwrap_or_default();

        let tolerance = chrono::Duration::seconds(5);
        let earliest_allowed = subscription_start_time - tolerance;

        for event in &events {
            assert!(
                event.time_created >= earliest_allowed,
                "Event timestamp {} is before subscription start time {} (minus tolerance). \
                 read_existing_events=false may not be respected. Event ID: {}, Record ID: {}",
                event.time_created,
                subscription_start_time,
                event.event_id,
                event.record_id
            );
        }
    }

    /// Test that subscription gracefully handles an invalid/corrupted bookmark
    /// from a checkpoint, falling back to a fresh bookmark without crashing.
    #[tokio::test]
    async fn test_checkpoint_with_invalid_bookmark_falls_back_gracefully() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let checkpointer = Arc::new(Checkpointer::new(temp_dir.path()).await.unwrap());

        let fake_bookmark = r#"<BookmarkList><Bookmark Channel='Application' RecordId='999999999' IsCurrent='true'/></BookmarkList>"#;

        checkpointer
            .set("Application".to_string(), fake_bookmark.to_string())
            .await
            .expect("Should be able to set checkpoint");

        let mut config = WindowsEventLogConfig::default();
        config.channels = vec!["Application".to_string()];
        config.read_existing_events = true;
        config.event_timeout_ms = 500;

        // The subscription should succeed even with a corrupted/invalid bookmark,
        // gracefully falling back to a fresh bookmark.
        let mut subscription = EventLogSubscription::new(&config, checkpointer, false)
            .await
            .expect("Subscription should succeed even with invalid bookmark checkpoint");

        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

        // Just verify we can pull events without panicking.
        // The bookmark format above is not a real Windows bookmark, so the
        // subscription will fall back to reading from scratch. We only assert
        // that the subscription is functional.
        let _events = subscription.pull_events(100).unwrap_or_default();
    }

    /// Proves that `pull_events` works independently of signal state — the
    /// invariant the speculative timeout pull in mod.rs relies on.
    ///
    /// Steps:
    /// 1. Subscribe to the Application log with `read_existing_events = true`.
    /// 2. Manually clear the channel signal via `ResetEvent`, simulating a lost wakeup.
    /// 3. Assert `wait_for_events_blocking` times out (signal cleared, no OS wake-up).
    /// 4. Assert `pull_events` still returns events — `EvtNext` fetches from the queue
    ///    regardless of signal state, so the speculative pull in mod.rs self-heals.
    #[tokio::test]
    #[serial]
    async fn test_pull_events_works_with_cleared_signal() {
        // Seed the Application log with a record so the "events remain
        // available despite cleared signal" assertion below does not depend
        // on whatever backlog the runner happens to have. Freshly provisioned
        // CI images can have an empty Application log, which would otherwise
        // make `pull_events` legitimately return empty and produce a spurious
        // failure unrelated to the invariant under test.
        let seed_output = std::process::Command::new("eventcreate")
            .args([
                "/T",
                "INFORMATION",
                "/ID",
                "100",
                "/L",
                "APPLICATION",
                "/SO",
                "VectorTestSpeculativePullSeed",
                "/D",
                "seed event for #25194 speculative-pull regression test",
            ])
            .output()
            .expect("failed to spawn eventcreate — required for deterministic seeding");
        assert!(
            seed_output.status.success(),
            "eventcreate failed to seed Application log (exit={:?}): stdout={:?} stderr={:?}. \
             This test requires a seeded event to be deterministic; a locked-down runner \
             without the privilege to write to Application cannot run this test reliably.",
            seed_output.status.code(),
            String::from_utf8_lossy(&seed_output.stdout),
            String::from_utf8_lossy(&seed_output.stderr),
        );
        // Give the service a moment to persist the record before we subscribe.
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        let mut config = WindowsEventLogConfig::default();
        config.channels = vec!["Application".to_string()];
        config.read_existing_events = true;
        config.event_timeout_ms = 500;

        let (checkpointer, _temp_dir) = create_test_checkpointer().await;

        let mut subscription = EventLogSubscription::new(&config, checkpointer, false)
            .await
            .expect("Subscription creation should succeed");

        // Manually clear the signal to simulate a lost wakeup. The seeded
        // event above guarantees at least one record is queued in EvtNext
        // regardless of the runner's pre-existing log state.
        let signal_raw = subscription.first_channel_signal_raw();
        unsafe {
            let _ = ResetEvent(HANDLE(signal_raw as *mut std::ffi::c_void));
        }

        // Signal is cleared: an immediate (0ms) poll must report Timeout.
        // A 0ms wait reads only the current signal state with no grace
        // window, so unrelated Windows system events arriving between the
        // `ResetEvent` above and the poll cannot re-signal the handle and
        // cause a spurious failure.
        let wait_result = subscription.wait_for_events_blocking(0);

        assert!(
            matches!(wait_result, WaitResult::Timeout),
            "expected Timeout after manual ResetEvent; signal was not cleared"
        );

        // Despite the cleared signal, pull_events must still return events.
        // This is the invariant the speculative timeout pull in mod.rs depends on.
        let events = subscription.pull_events(100).unwrap_or_default();
        assert!(
            !events.is_empty(),
            "pull_events must return events independently of signal state; \
             this is the invariant the speculative timeout pull in mod.rs depends on"
        );
    }

    /// Regression test for vectordotdev/vector#25194.
    ///
    /// The Windows Event Log service signals the pull-mode wait handle via
    /// `SetEvent` each time a new matching event is recorded. Because the
    /// handle is manual-reset, `SetEvent` on an already-signaled handle is
    /// a no-op. If `pull_events` resets the signal *after* draining events
    /// via `EvtNext`, any signal that fires between the last `EvtNext` and
    /// the `ResetEvent` call is silently lost — the subscription then
    /// permanently hangs until a subsequent event arrives.
    ///
    /// The fix is to reset the signal *before* the drain loop, so signals
    /// raised during the drain are preserved and the next wait returns
    /// immediately.
    ///
    /// This test pins that invariant by driving the real `pull_events`
    /// against a real `EvtSubscribe` handle. It installs a
    /// `DRAIN_STEP_HOOK` that runs inside the drain loop after each
    /// `EvtNext` and fires `SetEvent` on the subscription's signal
    /// handle — simulating the OS signaling a new event arrival during
    /// the drain window. After `pull_events` returns, the signal must
    /// still be set — observed via a 0ms `wait_for_events_blocking`
    /// so the check measures only the reset/preserve behavior of
    /// `pull_events` and is not contaminated by unrelated Windows
    /// system events arriving during a nonzero wait. Under the old
    /// post-drain `ResetEvent` order, the hook's `SetEvent` would be
    /// clobbered by the reset and the immediate poll would return
    /// `Timeout` — which is exactly what #25194 reports.
    #[tokio::test]
    #[serial]
    async fn test_pull_events_preserves_setevent_during_drain() {
        use std::sync::Arc as StdArc;

        let mut config = WindowsEventLogConfig::default();
        config.channels = vec!["Application".to_string()];
        config.read_existing_events = true;
        config.event_timeout_ms = 1000;

        let (checkpointer, _temp_dir) = create_test_checkpointer().await;

        let mut subscription = EventLogSubscription::new(&config, checkpointer, false)
            .await
            .expect("Subscription creation should succeed");

        // Capture THIS subscription's signal handle so the hook can scope
        // itself to this test. DRAIN_STEP_HOOK is a process-global, and
        // cargo runs tests in parallel by default; without handle-keying,
        // a concurrent test's pull_events could trigger our one-shot
        // hook first, flip `fired`, and SetEvent on the wrong handle.
        let target_signal_raw = subscription.first_channel_signal_raw();

        // Install the drain-loop hook: every EvtNext call inside
        // pull_events fires SetEvent on the subscription's signal
        // handle. This simulates the OS signaling a fresh event
        // mid-drain, which is exactly the race window #25194 exposes.
        // The hook only needs to fire once to prove the invariant; we
        // use an AtomicBool to keep it deterministic. The hook is keyed
        // to `target_signal_raw` so concurrent pull_events calls from
        // other tests no-op here.
        let fired = StdArc::new(std::sync::atomic::AtomicBool::new(false));
        {
            let fired = StdArc::clone(&fired);
            let hook: StdArc<dyn Fn(HANDLE) + Send + Sync> = StdArc::new(move |signal: HANDLE| {
                if signal.0 as isize != target_signal_raw {
                    return;
                }
                if !fired.swap(true, std::sync::atomic::Ordering::SeqCst) {
                    unsafe {
                        let _ = SetEvent(signal);
                    }
                }
            });
            *DRAIN_STEP_HOOK.lock().unwrap() = Some(hook);
        }

        // Drop-guard: clear the hook even if the test panics, so it
        // doesn't contaminate other tests in the same process.
        struct HookGuard;
        impl Drop for HookGuard {
            fn drop(&mut self) {
                *DRAIN_STEP_HOOK.lock().unwrap() = None;
            }
        }
        let _guard = HookGuard;

        // Drive pull_events with a very large budget so the drain
        // exits via ERROR_NO_MORE_ITEMS (channel_drained = true),
        // which is the path that ran the post-drain ResetEvent in the
        // old buggy code. Exiting via budget exhaustion would skip
        // that reset and cause this test to false-pass against the
        // pre-fix code.
        let _ = subscription.pull_events(usize::MAX).unwrap_or_default();

        assert!(
            fired.load(std::sync::atomic::Ordering::SeqCst),
            "drain-loop hook never ran — pull_events must call EvtNext \
             at least once even on an empty channel"
        );

        // Observe the signal state IMMEDIATELY with a 0ms wait. We want
        // to know whether pull_events's reset clobbered the hook's
        // SetEvent — NOT whether new real events arrive during some
        // wait window. A nonzero timeout against the live Application
        // channel lets arbitrary Windows system events re-signal us
        // and false-pass against the pre-fix code. 0ms = WaitForMultiple-
        // Objects returns the current state with no grace period, so
        // only the reset/preserve behavior of pull_events is measured.
        let result = subscription.wait_for_events_blocking(0);

        match result {
            WaitResult::EventsAvailable => {}
            WaitResult::Timeout => panic!(
                "signal set during the drain window was lost — this is the \
                 lost-wakeup race from vectordotdev/vector#25194. \
                 pull_events must call ResetEvent BEFORE draining, not after."
            ),
            WaitResult::Shutdown => panic!("unexpected shutdown"),
        }
    }

    /// Installs a scripted `EvtNext` result sequence for the duration of a test.
    ///
    /// Entries are `(win32_code, returned_count)`; a code of 0 means success.
    /// The error-with-nonzero-count entries are the important ones: `EvtNext`
    /// really does return errors with handles already populated, and the drain
    /// loop must account for and close those handles rather than dropping them.
    struct ScriptGuard;

    impl ScriptGuard {
        fn install(script: &[(u32, u32)]) -> Self {
            *EVT_NEXT_SCRIPT.lock().unwrap() = Some(script.iter().copied().collect());
            Self
        }
    }

    impl Drop for ScriptGuard {
        fn drop(&mut self) {
            *EVT_NEXT_SCRIPT.lock().unwrap() = None;
        }
    }

    async fn application_subscription() -> (EventLogSubscription, tempfile::TempDir) {
        let (checkpointer, temp_dir) = create_test_checkpointer().await;
        let subscription = application_subscription_with(checkpointer).await;
        (subscription, temp_dir)
    }

    /// Same, but against a caller-supplied checkpointer, so a test can simulate
    /// a restart by building a second subscription over the same checkpoint.
    async fn application_subscription_with(
        checkpointer: Arc<Checkpointer>,
    ) -> EventLogSubscription {
        let mut config = WindowsEventLogConfig::default();
        config.channels = vec!["Application".to_string()];
        config.read_existing_events = true;
        config.event_timeout_ms = 500;
        EventLogSubscription::new(&config, checkpointer, false)
            .await
            .expect("subscription creation should succeed")
    }

    /// Installs a scripted `EvtSubscribe` failure sequence for a test.
    struct SubscribeScriptGuard;

    impl SubscribeScriptGuard {
        fn install(codes: &[u32]) -> Self {
            *EVT_SUBSCRIBE_SCRIPT.lock().unwrap() = Some(codes.iter().copied().collect());
            Self
        }
    }

    impl Drop for SubscribeScriptGuard {
        fn drop(&mut self) {
            *EVT_SUBSCRIBE_SCRIPT.lock().unwrap() = None;
        }
    }

    /// Forces every render to fail, exercising the unprocessable-event path.
    struct RenderFailGuard;

    impl RenderFailGuard {
        fn install() -> Self {
            FAIL_ALL_RENDERS.store(true, std::sync::atomic::Ordering::SeqCst);
            Self
        }
    }

    impl Drop for RenderFailGuard {
        fn drop(&mut self) {
            FAIL_ALL_RENDERS.store(false, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// Counts warn-band (WARN and ERROR) tracing events on this thread.
    ///
    /// The episode contract is a statement about what an operator sees, so it
    /// has to be asserted on emitted log records, not on the flags the code
    /// keeps.
    #[derive(Clone, Default)]
    struct WarnBandCounter {
        warns: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for WarnBandCounter {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let level = *event.metadata().level();
            if level <= tracing::Level::WARN {
                self.warns
                    .lock()
                    .unwrap()
                    .push(format!("{level} {}", event.metadata().target()));
            }
        }
    }

    /// A failed PROACTIVE rebuild must leave the live subscription serving
    /// events (D22).
    ///
    /// The periodic refresh (D9) and batch reduction (D11) both rebuild while
    /// the current subscription is HEALTHY. Closing it because its replacement
    /// failed to open is a self-inflicted outage, and it is the exact failure
    /// mode build-new-then-swap exists to prevent.
    #[tokio::test]
    #[serial]
    async fn a_failed_proactive_rebuild_keeps_the_live_subscription() {
        let (mut subscription, _temp_dir) = application_subscription().await;
        assert!(subscription.first_channel_is_live());
        let baseline = subscription.first_channel_handle_balance();

        {
            // RPC_S_SERVER_UNAVAILABLE: transient, and the kind of failure a
            // refresh really does hit on a service that is restarting.
            let _guard = SubscribeScriptGuard::install(&[1722]);
            subscription.force_proactive_rebuild_all();
        }

        assert!(
            subscription.first_channel_is_live(),
            "a failed proactive rebuild must not close the working subscription"
        );
        assert_eq!(
            subscription.first_channel_handle_balance(),
            baseline,
            "the live handle must still be the one we started with"
        );

        let events = subscription
            .pull_events(usize::MAX)
            .expect("the surviving subscription must still read");
        assert!(
            !events.is_empty(),
            "the previous subscription must still be serving events after the \
             failed rebuild"
        );
    }

    /// A rebuild from a DEAD subscription has nothing to preserve, so a failure
    /// there legitimately leaves the channel down and retrying.
    #[tokio::test]
    #[serial]
    async fn a_failed_rebuild_from_dead_leaves_the_channel_down() {
        let (mut subscription, _temp_dir) = application_subscription().await;

        {
            let _guard = ScriptGuard::install(&[(15007, 0)]);
            let _ = subscription.pull_events(100).expect("must not error out");
        }
        assert!(!subscription.first_channel_is_live());

        {
            let _guard = SubscribeScriptGuard::install(&[15007]);
            subscription.force_rebuild_all();
        }
        assert!(
            !subscription.first_channel_is_live(),
            "nothing was live to preserve; the channel stays down and retries"
        );
    }

    /// D19: an event we cannot process costs exactly that event, ONCE.
    ///
    /// Skipping it without advancing the bookmark past it means a restart reads
    /// it again and skips it again, forever: the channel can never make progress
    /// past the bad event, which is a permanent stall dressed up as a skip.
    #[tokio::test]
    #[serial]
    async fn a_skipped_unrenderable_event_is_not_redelivered_after_a_restart() {
        let _ = std::process::Command::new("eventcreate")
            .args([
                "/T",
                "INFORMATION",
                "/ID",
                "102",
                "/L",
                "APPLICATION",
                "/SO",
                "VectorTestRenderSkip",
                "/D",
                "seed event for the render-skip bookmark advance assertion",
            ])
            .output();
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        // Baseline: what is in the backlog right now, read normally.
        let (mut baseline_sub, _baseline_dir) = application_subscription().await;
        let backlog: std::collections::HashSet<u64> = baseline_sub
            .pull_events(usize::MAX)
            .unwrap_or_default()
            .iter()
            .map(|e| e.record_id)
            .collect();
        assert!(
            !backlog.is_empty(),
            "the Application backlog must be readable, otherwise this proves nothing"
        );
        drop(baseline_sub);

        // Same backlog, but every event is unprocessable.
        let (checkpointer, _temp_dir) = create_test_checkpointer().await;
        let mut skipping = application_subscription_with(Arc::clone(&checkpointer)).await;
        {
            let _guard = RenderFailGuard::install();
            let delivered = skipping.pull_events(usize::MAX).unwrap_or_default();
            assert!(
                delivered.is_empty(),
                "unprocessable events are not delivered"
            );
            assert!(
                skipping.first_channel_is_live(),
                "one bad event must never tear down the subscription"
            );
        }
        skipping
            .flush_bookmarks()
            .await
            .expect("bookmarks must flush");
        drop(skipping);

        // Restart over the same checkpoint.
        let mut restarted = application_subscription_with(checkpointer).await;
        let after_restart: Vec<u64> = restarted
            .pull_events(usize::MAX)
            .unwrap_or_default()
            .iter()
            .map(|e| e.record_id)
            .collect();

        for record_id in &after_restart {
            assert!(
                !backlog.contains(record_id),
                "record {record_id} was skipped as unrenderable and then read \
                 again after a restart; the bookmark never advanced past it"
            );
        }
    }

    /// The episode contract, in the vocabulary an operator sees: one unavailable
    /// episode produces exactly one warn-band onset and exactly one warn-band
    /// recovery. Everything in between is DEBUG.
    ///
    /// The original incident shipped 12,650 error rows for one condition, and
    /// the lab's single unregister episode still logged four warn-band lines
    /// against a design that calls for two.
    #[tokio::test]
    #[serial]
    async fn one_episode_produces_exactly_one_onset_and_one_recovery() {
        use tracing_subscriber::layer::SubscriberExt;

        let (mut subscription, _temp_dir) = application_subscription().await;

        let counter = WarnBandCounter::default();
        let collector = tracing_subscriber::registry().with(counter.clone());

        tracing::subscriber::with_default(collector, || {
            // Onset: the channel goes away underneath us.
            {
                let _guard = ScriptGuard::install(&[(15007, 0)]);
                let _ = subscription.pull_events(100).expect("must not error out");
            }
            assert!(!subscription.first_channel_is_live());

            // The down window: repeated failed rebuilds. Every one of these is
            // the same condition already reported, so none of them may reach the
            // warn band.
            {
                let _guard = SubscribeScriptGuard::install(&[15007; 6]);
                for _ in 0..6 {
                    subscription.force_rebuild_all();
                    assert!(!subscription.first_channel_is_live());
                }
            }

            // Recovery.
            subscription.force_rebuild_all();
            assert!(subscription.first_channel_is_live());
        });

        let lines = counter.warns.lock().unwrap().clone();
        assert_eq!(
            lines.len(),
            2,
            "one episode must produce exactly one onset and one recovery, got: {lines:#?}"
        );
        assert!(
            lines[0].starts_with("ERROR"),
            "the onset is an ERROR, got: {lines:#?}"
        );
        assert!(
            lines[1].starts_with("WARN"),
            "the recovery is a WARN, got: {lines:#?}"
        );
    }

    /// Handle accounting across forced rebuilds.
    ///
    /// The discard-and-rebuild recovery model's main risk is leaking EVT
    /// handles, so the count of open subscription handles must return to its
    /// baseline after any number of rebuilds.
    #[tokio::test]
    #[serial]
    async fn handle_count_returns_to_baseline_after_forced_rebuilds() {
        let (mut subscription, _temp_dir) = application_subscription().await;

        let baseline = subscription.first_channel_handle_balance();
        assert_eq!(baseline, 1, "startup must leave exactly one open handle");

        for _ in 0..8 {
            subscription.force_rebuild_all();
            assert!(
                subscription.first_channel_is_live(),
                "a rebuild against a live Application channel must succeed"
            );
            assert_eq!(
                subscription.first_channel_handle_balance(),
                baseline,
                "every rebuild must close exactly the handle it replaced"
            );
        }
    }

    /// `EvtNext` can return an error with handles already populated. Those
    /// handles are ours to close: leaving them is a leak, and retrying the same
    /// handle after such an error loses events, because on 1734 the API cursor
    /// advances even when the call fails.
    #[tokio::test]
    #[serial]
    async fn evt_next_error_with_populated_handles_discards_them() {
        let (mut subscription, _temp_dir) = application_subscription().await;

        let _guard = ScriptGuard::install(&[(15011, 4)]);

        let events = subscription
            .pull_events(100)
            .expect("a per-channel fault must never surface as a source error");
        assert!(events.is_empty());

        assert_eq!(
            subscription.first_channel_event_handle_closes(),
            4,
            "all four handles returned alongside the error must be discarded"
        );
        assert!(
            !subscription.first_channel_is_live(),
            "a retryable EvtNext error must tear the subscription down rather \
             than retrying the same handle"
        );
    }

    /// 4317 with a zero count is benign and fires roughly 46 times per three
    /// minutes on a healthy channel. Deleting its benign handler regressed a
    /// healthy channel to 18 shipping ERROR events per three minutes, so it
    /// must not tear anything down.
    #[tokio::test]
    #[serial]
    async fn benign_invalid_operation_does_not_tear_down() {
        let (mut subscription, _temp_dir) = application_subscription().await;

        let _guard = ScriptGuard::install(&[(4317, 0)]);

        let _ = subscription
            .pull_events(100)
            .expect("a benign drain terminator is not an error");
        assert!(
            subscription.first_channel_is_live(),
            "4317 with a zero returned count must leave the subscription alone"
        );
        assert_eq!(subscription.first_channel_event_handle_closes(), 0);
    }

    /// An unknown code rebuilds rather than retrying the same handle, and the
    /// channel comes back on its own.
    #[tokio::test]
    #[serial]
    async fn unknown_codes_rebuild_and_recover() {
        let (mut subscription, _temp_dir) = application_subscription().await;

        {
            let _guard = ScriptGuard::install(&[(60123, 0)]);
            let _ = subscription.pull_events(100).expect("must not error out");
            assert!(
                !subscription.first_channel_is_live(),
                "an unknown code must rebuild rather than retry the same handle"
            );
        }

        subscription.force_rebuild_all();
        assert!(
            subscription.first_channel_is_live(),
            "the channel must come back on its own"
        );
    }

    /// Exactly-once delivery across a rebuild.
    ///
    /// Rebuilding resumes from the checkpoint, which over-delivers by design
    /// (the generated XPath floors to the millisecond). The exact in-process
    /// `(TimeCreated, RecordId)` boundary is what makes that contribute zero
    /// duplicates, so no record id may appear in two consecutive reads.
    #[tokio::test]
    #[serial]
    async fn rebuild_does_not_redeliver_events() {
        // Best-effort seed. Writing to Application needs privilege the test
        // runner may not have, and this assertion does not depend on the seed:
        // it reads whatever backlog the channel already holds and only requires
        // that the SECOND read repeats nothing from the first.
        let _ = std::process::Command::new("eventcreate")
            .args([
                "/T",
                "INFORMATION",
                "/ID",
                "101",
                "/L",
                "APPLICATION",
                "/SO",
                "VectorTestRebuildDedupe",
                "/D",
                "seed event for the rebuild exactly-once assertion",
            ])
            .output();
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        let (mut subscription, _temp_dir) = application_subscription().await;

        let first: Vec<u64> = subscription
            .pull_events(usize::MAX)
            .unwrap_or_default()
            .iter()
            .map(|e| e.record_id)
            .collect();
        assert!(
            !first.is_empty(),
            "the Application backlog must be readable, otherwise this proves nothing"
        );

        subscription.force_rebuild_all();

        let second: Vec<u64> = subscription
            .pull_events(usize::MAX)
            .unwrap_or_default()
            .iter()
            .map(|e| e.record_id)
            .collect();

        for record_id in &second {
            assert!(
                !first.contains(record_id),
                "record {record_id} was delivered twice across a rebuild"
            );
        }
    }
}
