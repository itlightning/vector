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

/// Test-only: publisher metadata handles that reached `EvtClose`.
///
/// Counted INSIDE the guard and after the API call, so neither deleting the
/// drop body nor inverting the null test can increment it. A drop that ran is
/// not the property; a handle that was released is.
#[cfg(test)]
pub(super) static PUBLISHER_HANDLE_CLOSES: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Test-only: subscription handles that reached `EvtClose`, counted after the
/// API call in `close_current`. Observable after the owner has been dropped,
/// which the per-channel counters are not.
#[cfg(test)]
pub(super) static SUBSCRIPTION_HANDLE_CLOSES: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Test-only: channel signal events released by `EventLogSubscription::drop`.
#[cfg(test)]
pub(super) static SUBSCRIPTION_TEARDOWN_CLOSES: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

impl Drop for PublisherHandle {
    fn drop(&mut self) {
        if self.0 != 0 {
            unsafe {
                let _ = EvtClose(EVT_HANDLE(self.0));
            }
            #[cfg(test)]
            PUBLISHER_HANDLE_CLOSES.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
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
///
/// Returns whether `EvtClose` was actually called. The caller's accounting
/// keys on that return value rather than on its own call count, so a handle
/// that never reaches the API is never counted as closed: an accounting seam
/// that counts calls INTO the seam cannot see a guard here that stops closing
/// real handles, which is the leak this accounting exists to catch.
#[inline]
fn close_event_handle(handle: EVT_HANDLE) -> bool {
    // A null handle is what the fault-injection seam produces for a scripted
    // count; it is a retired slot but must not reach the API.
    if handle.0 != 0 {
        unsafe {
            let _ = EvtClose(handle);
        }
        return true;
    }
    false
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

/// Test-only: force `BookmarkManager::update` to fail, so the mid-batch
/// bookmark-failure path can be exercised. That path's contract is that it
/// closes the current handle AND every remaining handle in the batch exactly
/// once, which is only assertable if the failure can be produced on demand.
#[cfg(test)]
pub(super) static FAIL_ALL_BOOKMARK_UPDATES: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Test-only record of the batch size requested from each `EvtNext` call, as
/// `(channel, requested)`.
///
/// The batch ladder (D11) is only meaningful as what we ASK the API for next, so
/// this is the observable the adaptation tests assert on. Asserting the internal
/// counter instead is exactly the failure mode section 10.4 of the plan
/// describes. It doubles as the round-robin observable: the channel order across
/// calls is visible here and nowhere else.
#[cfg(test)]
pub(super) static EVT_NEXT_REQUESTS: std::sync::Mutex<Option<Vec<(String, usize)>>> =
    std::sync::Mutex::new(None);

/// Test-only running total of the event count `EvtNext` handed back.
///
/// This is the drain loop's only independent oracle for "how many records did
/// the API give us". Every other count in a test is produced by the same
/// admission gate under test, so comparing two of those cannot detect a gate
/// that drops uniformly: both sides degrade together.
#[cfg(test)]
pub(super) static EVT_NEXT_RETURNED_TOTAL: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Test-only record of the flags passed to each `EvtSubscribe` call.
///
/// `EvtSubscribeStrict` is D20 and load-bearing: without it Windows silently
/// repositions on a dead bookmark and silent data loss presents as a healthy
/// subscription. Nothing else in the system can observe that a flag was dropped,
/// so the exact argument is recorded and asserted. The length also counts
/// subscribe ATTEMPTS, which is how the refresh and backoff schedules are
/// asserted without reading a timer field.
#[cfg(test)]
pub(super) static EVT_SUBSCRIBE_FLAG_LOG: std::sync::Mutex<Option<Vec<u32>>> =
    std::sync::Mutex::new(None);

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

        // Test-only: record the exact flag word. A mutation that drops
        // EvtSubscribeStrict changes nothing else that any other assertion can
        // see, which is precisely why it needs its own observable.
        #[cfg(test)]
        if let Some(log) = EVT_SUBSCRIBE_FLAG_LOG.lock().unwrap().as_mut() {
            log.push(flags);
        }

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
    /// `EvtNext` handles that actually reached `EvtClose`.
    #[cfg(test)]
    event_handle_closes: i64,
    /// Batch slots routed through the discard path, closed at the API or not.
    /// The fault-injection seam hands the drain null slots, so this is what a
    /// scripted test asserts and it can never stand in for the counter above.
    #[cfg(test)]
    event_handle_slots_retired: i64,
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
            // Counted after the API call, so teardown can be asserted from
            // outside the dropped value.
            #[cfg(test)]
            SUBSCRIPTION_HANDLE_CLOSES.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
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
    ///
    /// Two counters, deliberately: `event_handle_slots_retired` says the drain
    /// routed every slot of the batch through here, and `event_handle_closes`
    /// says the API call actually happened. Only the second can see a leak.
    fn discard_event_handle(&mut self, handle: EVT_HANDLE) {
        let _closed = close_event_handle(handle);
        #[cfg(test)]
        {
            self.event_handle_slots_retired += 1;
            if _closed {
                self.event_handle_closes += 1;
            }
        }
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
                #[cfg(test)]
                event_handle_slots_retired: 0,
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

                // Test-only: the batch size we are ASKING for is the observable
                // the adaptation ladder is asserted on.
                #[cfg(test)]
                if let Some(log) = EVT_NEXT_REQUESTS.lock().unwrap().as_mut() {
                    log.push((channel_sub.channel.clone(), event_handles.len()));
                }

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
                        Some((code, count)) => {
                            // The real call already ran and may have populated
                            // handles. Close them and hand the drain loop a
                            // synthetic buffer: injection must never leak a
                            // handle, and it must never silently swallow a real
                            // batch either. The bookmark has not advanced, so a
                            // rebuild re-reads exactly these events, which is
                            // what makes the exactly-once assertion across an
                            // injected fault mean something.
                            for &raw in &event_handles[..returned as usize] {
                                let _ = close_event_handle(EVT_HANDLE(raw));
                            }
                            event_handles.fill(0);
                            returned = count.min(event_handles.len() as u32);
                            if code == 0 {
                                Ok(())
                            } else {
                                Err(windows::core::Error::from_hresult(windows::core::HRESULT(
                                    code as i32,
                                )))
                            }
                        }
                        None => result,
                    }
                };

                // Test-only: the independent oracle for how many records the
                // API actually produced, counted before any of the drain's own
                // filtering decisions can touch it.
                #[cfg(test)]
                EVT_NEXT_RETURNED_TOTAL
                    .fetch_add(u64::from(returned), std::sync::atomic::Ordering::SeqCst);

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

                                // Exact in-process boundary. The generated XPath
                                // predicate floors to the millisecond and
                                // therefore over-delivers; trimming here at full
                                // (TimeCreated, RecordId) resolution is what
                                // makes precision contribute zero duplicates on
                                // every resume path. It is also where a
                                // deliberately skipped poison record is dropped,
                                // and `past_boundary` is what separates the two:
                                // an over-delivered duplicate needs nothing,
                                // while the one-shot poison skip has to be made
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

    /// Test-only: how many `EvtNext` handles the first channel actually closed
    /// at the API. Driven by the return of `close_event_handle`, so a guard
    /// that stops closing real handles drives this to zero.
    #[cfg(test)]
    pub(super) fn first_channel_event_handle_closes(&self) -> i64 {
        self.channels[0].event_handle_closes
    }

    /// Test-only: batch slots the first channel routed through the discard
    /// path. Counts the null slots the fault-injection seam produces, which is
    /// what a scripted fault can assert and is NOT evidence of a close.
    #[cfg(test)]
    pub(super) fn first_channel_event_handle_slots_retired(&self) -> i64 {
        self.channels[0].event_handle_slots_retired
    }

    /// Test-only: the names of the channels that are currently readable, in
    /// declaration order.
    ///
    /// Round-robin fairness is a statement about which channels get drained in
    /// what order, and a channel that could not be opened on this host is
    /// legitimately absent from that order.
    #[cfg(test)]
    pub(super) fn live_channel_names(&self) -> Vec<String> {
        self.channels
            .iter()
            .filter(|c| c.is_live())
            .map(|c| c.channel.clone())
            .collect()
    }

    /// Test-only: would a record-id gap on the first channel still be REPORTED?
    ///
    /// This is a decision, not a field: forwarded rendered-text delivery marks a
    /// channel's record ids as untrustworthy and self-disables gap detection
    /// (D23), and the only way that decision shows up anywhere is in the verdict
    /// `evaluate_gap` returns.
    #[cfg(test)]
    pub(super) fn first_channel_reports_record_id_gaps(&self) -> bool {
        matches!(
            evaluate_gap(Some(1), 5, self.channels[0].gap_detection(), false),
            GapVerdict::Gap { .. }
        )
    }

    /// Test-only: could the resume ladder still select the single-record skip
    /// on the first channel?
    ///
    /// Advances a CLONE of the resume state, so asking the question does not
    /// move the real ladder. This is a decision, not a field: revoking record
    /// identity has to change what the ladder can choose, or it changes
    /// nothing that matters.
    #[cfg(test)]
    pub(super) fn first_channel_ladder_can_skip_one_record(&self) -> bool {
        let mut probe = self.channels[0].resume.clone();
        probe.advance_rung();
        probe.advance_rung() == Rung::SkipRecord
    }

    /// Test-only: the `last_event_at` field value the first channel would put
    /// on an onset ERROR or a recovery WARN.
    #[cfg(test)]
    pub(super) fn first_channel_last_event_at(&self) -> String {
        self.channels[0].last_event_at_rfc3339()
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
            #[cfg(test)]
            SUBSCRIPTION_TEARDOWN_CLOSES.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
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
    use super::super::recovery::TimeRung;
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
            subscription.first_channel_event_handle_slots_retired(),
            4,
            "all four slots returned alongside the error must be discarded. \
             The injected batch is synthetic, so this asserts the drain retired \
             every slot, not that the API was called"
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
        assert_eq!(subscription.first_channel_event_handle_slots_retired(), 0);
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

    // ---------------------------------------------------------------------
    // Behavioral coverage for the drain loop's own decisions.
    //
    // A mutation run over this file showed the loop was driven shallowly: error
    // ROUTING was asserted, the loop's internal decisions were not. Everything
    // below asserts an observable outcome (what batch size is requested next,
    // which channel is drained next, what flag word reaches the API, what is
    // delivered), never a field the implementation happens to set. That
    // distinction is section 10.4 of the plan and it is why these tests are
    // phrased the way they are.
    // ---------------------------------------------------------------------

    /// Records the batch size asked of each `EvtNext` call.
    struct RequestLog;

    impl RequestLog {
        fn install() -> Self {
            *EVT_NEXT_REQUESTS.lock().unwrap() = Some(Vec::new());
            EVT_NEXT_RETURNED_TOTAL.store(0, std::sync::atomic::Ordering::SeqCst);
            Self
        }

        /// Requested sizes, in call order.
        fn sizes(&self) -> Vec<usize> {
            EVT_NEXT_REQUESTS
                .lock()
                .unwrap()
                .as_ref()
                .map(|log| log.iter().map(|(_, size)| *size).collect())
                .unwrap_or_default()
        }

        /// Channels drained, in call order.
        fn channels(&self) -> Vec<String> {
            EVT_NEXT_REQUESTS
                .lock()
                .unwrap()
                .as_ref()
                .map(|log| log.iter().map(|(channel, _)| channel.clone()).collect())
                .unwrap_or_default()
        }

        fn clear(&self) {
            if let Some(log) = EVT_NEXT_REQUESTS.lock().unwrap().as_mut() {
                log.clear();
            }
        }

        /// How many records `EvtNext` handed the drain loop since installation.
        fn returned_total(&self) -> u64 {
            EVT_NEXT_RETURNED_TOTAL.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl Drop for RequestLog {
        fn drop(&mut self) {
            *EVT_NEXT_REQUESTS.lock().unwrap() = None;
        }
    }

    /// Records the flag word passed to each `EvtSubscribe` call. Its length is
    /// also the number of subscribe ATTEMPTS, successful or not.
    struct FlagLog;

    impl FlagLog {
        fn install() -> Self {
            *EVT_SUBSCRIBE_FLAG_LOG.lock().unwrap() = Some(Vec::new());
            Self
        }

        fn flags(&self) -> Vec<u32> {
            EVT_SUBSCRIBE_FLAG_LOG
                .lock()
                .unwrap()
                .as_ref()
                .cloned()
                .unwrap_or_default()
        }

        fn attempts(&self) -> usize {
            self.flags().len()
        }
    }

    impl Drop for FlagLog {
        fn drop(&mut self) {
            *EVT_SUBSCRIBE_FLAG_LOG.lock().unwrap() = None;
        }
    }

    /// Forces every bookmark update to fail, exercising the mid-batch
    /// bookmark-failure path.
    struct BookmarkFailGuard;

    impl BookmarkFailGuard {
        fn install() -> Self {
            FAIL_ALL_BOOKMARK_UPDATES.store(true, std::sync::atomic::Ordering::SeqCst);
            Self
        }
    }

    impl Drop for BookmarkFailGuard {
        fn drop(&mut self) {
            FAIL_ALL_BOOKMARK_UPDATES.store(false, std::sync::atomic::Ordering::SeqCst);
        }
    }

    async fn subscription_from(config: &WindowsEventLogConfig) -> EventLogSubscription {
        let (checkpointer, _temp_dir) = create_test_checkpointer().await;
        // The checkpoint directory only has to outlive creation for these
        // tests: none of them restart over the same checkpoint.
        std::mem::forget(_temp_dir);
        EventLogSubscription::new(config, checkpointer, false)
            .await
            .expect("subscription creation should succeed")
    }

    fn application_config() -> WindowsEventLogConfig {
        let mut config = WindowsEventLogConfig::default();
        config.channels = vec!["Application".to_string()];
        config.read_existing_events = true;
        config.event_timeout_ms = 500;
        config
    }

    /// Read a channel until it stops producing, returning every record id in
    /// delivery order.
    fn drain_all(subscription: &mut EventLogSubscription) -> Vec<u64> {
        let mut seen = Vec::new();
        for _ in 0..64 {
            let batch = subscription.pull_events(usize::MAX).unwrap_or_default();
            if batch.is_empty() {
                break;
            }
            seen.extend(batch.iter().map(|e| e.record_id));
        }
        seen
    }

    // ---------------------------------------------------------------------
    // D20: the subscribe flag word.
    // ---------------------------------------------------------------------

    /// `EvtSubscribeStrict` is the mechanism that makes a dead bookmark fail
    /// LOUDLY instead of silently repositioning, and it is what caught the
    /// startup bug where every channel was down. Dropping it changes nothing
    /// any other assertion can see: the subscription still opens, still reads,
    /// and silently loses data only on a host whose bookmark has died. So the
    /// exact flag word is asserted here.
    #[tokio::test]
    #[serial]
    async fn bookmark_resume_passes_start_after_bookmark_and_strict() {
        let mut subscription = subscription_from(&application_config()).await;

        // Position the bookmark: a fresh bookmark marks no position, and
        // subscribing strictly against one that marks nothing is the startup
        // bug, not the resume path.
        let delivered = drain_all(&mut subscription);
        assert!(
            !delivered.is_empty(),
            "the Application backlog must be readable, otherwise the bookmark \
             never gets positioned and this proves nothing"
        );

        let flag_log = FlagLog::install();
        subscription.force_rebuild_all();

        assert_eq!(
            flag_log.flags(),
            vec![EvtSubscribeStartAfterBookmark.0 | EvtSubscribeStrict.0],
            "a bookmark resume must subscribe with StartAfterBookmark AND Strict"
        );
        assert_ne!(
            flag_log.flags()[0] & EvtSubscribeStrict.0,
            0,
            "EvtSubscribeStrict must be set: without it Windows silently \
             repositions on a dead bookmark and data loss presents as a healthy \
             subscription (D20)"
        );
    }

    /// The other two resume modes carry exactly their own flag and nothing else.
    #[tokio::test]
    #[serial]
    async fn oldest_and_future_only_resume_modes_pass_their_exact_flag() {
        {
            let flag_log = FlagLog::install();
            let _subscription = subscription_from(&application_config()).await;
            assert_eq!(
                flag_log.flags(),
                vec![EvtSubscribeStartAtOldestRecord.0],
                "read_existing_events with no usable bookmark reads from the \
                 oldest record"
            );
        }

        let mut config = application_config();
        config.read_existing_events = false;
        let flag_log = FlagLog::install();
        let _subscription = subscription_from(&config).await;
        assert_eq!(
            flag_log.flags(),
            vec![EvtSubscribeToFutureEvents.0],
            "without read_existing_events and with no stored position, only \
             future events are collected"
        );
    }

    // ---------------------------------------------------------------------
    // D22: what a failed rebuild is allowed to cost, per rebuild kind.
    // ---------------------------------------------------------------------

    /// The two operands of the D22 guard mean different things and must be
    /// pinned independently. This is the FromDead-with-a-live-handle case: the
    /// periodic refresh is not in play, so there is nothing to preserve and the
    /// failed rebuild legitimately leaves the channel down.
    #[tokio::test]
    #[serial]
    async fn a_failed_rebuild_from_dead_closes_a_live_subscription() {
        let mut subscription = subscription_from(&application_config()).await;
        assert!(subscription.first_channel_is_live());

        {
            let _guard = SubscribeScriptGuard::install(&[15007]);
            subscription.force_rebuild_all();
        }

        assert!(
            !subscription.first_channel_is_live(),
            "a FromDead rebuild is not covered by the proactive keep-the-live-one \
             guard: holding a handle is not by itself a reason to keep it"
        );
    }

    /// And the proactive-with-no-live-handle case: there is no live subscription
    /// to preserve, so the failure must be classified and acted on rather than
    /// deferred as a harmless refresh miss.
    #[tokio::test]
    #[serial]
    async fn a_failed_proactive_rebuild_with_no_live_handle_still_classifies() {
        use tracing_subscriber::layer::SubscriberExt;

        let mut subscription = subscription_from(&application_config()).await;
        {
            let _guard = ScriptGuard::install(&[(15007, 0)]);
            let _ = subscription.pull_events(100).expect("must not error out");
        }
        assert!(!subscription.first_channel_is_live());

        let counter = WarnBandCounter::default();
        let collector = tracing_subscriber::registry().with(counter.clone());
        tracing::subscriber::with_default(collector, || {
            // ERROR_EVT_INVALID_CHANNEL_PATH: a permanent skip, which is logged
            // unconditionally rather than being episode-gated.
            let _guard = SubscribeScriptGuard::install(&[15000]);
            subscription.force_proactive_rebuild_all();
        });

        let lines = counter.warns.lock().unwrap().clone();
        assert_eq!(
            lines.len(),
            1,
            "with no live subscription to protect, a proactive failure must be \
             classified and reported, not deferred as a refresh miss: {lines:#?}"
        );
        assert!(lines[0].starts_with("ERROR"), "got: {lines:#?}");
    }

    /// A deferred proactive rebuild comes back LATER, not immediately. Pushing
    /// the retry into the past would turn every failed refresh into a rebuild
    /// storm against a service that is already unwell.
    #[tokio::test]
    #[serial]
    async fn a_failed_proactive_rebuild_defers_the_next_refresh() {
        let mut subscription = subscription_from(&application_config()).await;
        let flag_log = FlagLog::install();

        {
            // Seven consecutive failures walk the backoff to its 60s cap, so the
            // deferral this asserts is measured in tens of seconds rather than
            // in a window a loaded test host can close on its own.
            let _guard = SubscribeScriptGuard::install(&[1722; 7]);
            for _ in 0..7 {
                subscription.force_proactive_rebuild_all();
            }
        }
        assert_eq!(flag_log.attempts(), 7, "the failed attempts themselves");
        assert!(subscription.first_channel_is_live());

        let _ = subscription.pull_events(1);
        assert_eq!(
            flag_log.attempts(),
            7,
            "the deferred refresh is a capped backoff away, not immediate; \
             scheduling it into the past turns every failed refresh into a \
             rebuild storm against a service that is already unwell"
        );
    }

    /// D21: our OWN generated predicate coming back invalid advances one rung,
    /// and the isolate rung's whole purpose is that the next read asks for one
    /// record so a failure is attributable to exactly one record.
    #[tokio::test]
    #[serial]
    async fn an_invalid_generated_query_at_subscribe_isolates_the_batch() {
        let mut subscription = subscription_from(&application_config()).await;

        {
            let _guard = SubscribeScriptGuard::install(&[15001]);
            subscription.force_rebuild_all();
        }
        subscription.force_rebuild_all();
        assert!(subscription.first_channel_is_live());

        let request_log = RequestLog::install();
        let _guard = ScriptGuard::install(&[(259, 0)]);
        let _ = subscription.pull_events(usize::MAX);

        assert_eq!(
            request_log.sizes(),
            vec![1],
            "the isolate rung must ask the API for exactly one record"
        );
    }

    // ---------------------------------------------------------------------
    // Per-channel budget and round-robin fairness.
    // ---------------------------------------------------------------------

    /// The event budget is SPLIT across channels, not handed to each of them.
    /// A channel count that does not divide the budget evenly is the case that
    /// distinguishes a division from anything else.
    #[tokio::test]
    #[serial]
    async fn the_per_channel_budget_divides_the_max_across_channels() {
        let mut config = application_config();
        config.channels = vec![
            "Application".to_string(),
            "System".to_string(),
            "Setup".to_string(),
        ];
        let mut subscription = subscription_from(&config).await;

        let request_log = RequestLog::install();
        let _guard = ScriptGuard::install(&[(259, 0); 3]);
        let _ = subscription.pull_events(7);

        assert_eq!(
            request_log.sizes().first().copied(),
            Some(2),
            "7 events across 3 channels is 2 per channel, not 7 and not 21"
        );
    }

    /// The starting channel rotates every call, so a busy channel cannot starve
    /// its siblings. Four consecutive calls over two channels must visit them in
    /// alternating order.
    #[tokio::test]
    #[serial]
    async fn channels_are_drained_in_rotating_order() {
        let mut config = application_config();
        config.channels = vec!["Application".to_string(), "System".to_string()];
        let mut subscription = subscription_from(&config).await;

        let live = subscription.live_channel_names();
        assert_eq!(
            live.len(),
            2,
            "both channels must be readable for this to prove anything, got {live:?}"
        );

        let request_log = RequestLog::install();
        let _guard = ScriptGuard::install(&[(259, 0); 8]);
        for _ in 0..4 {
            let _ = subscription.pull_events(usize::MAX);
        }

        let expected: Vec<String> = vec![
            live[0].clone(),
            live[1].clone(),
            live[1].clone(),
            live[0].clone(),
            live[0].clone(),
            live[1].clone(),
            live[1].clone(),
            live[0].clone(),
        ];
        assert_eq!(
            request_log.channels(),
            expected,
            "each call must start at the next channel and then wrap"
        );
    }

    // ---------------------------------------------------------------------
    // Periodic refresh and backoff scheduling.
    // ---------------------------------------------------------------------

    /// D9: the refresh fires when it is DUE and then schedules the next one into
    /// the future. Firing early wastes rebuilds; rescheduling into the past
    /// rebuilds on every single pull.
    #[tokio::test]
    #[serial]
    async fn the_periodic_refresh_fires_when_due_and_then_reschedules_forward() {
        let mut config = application_config();
        config.read_existing_events = false;
        config.subscription_refresh_secs = 1;
        let mut subscription = subscription_from(&config).await;

        let flag_log = FlagLog::install();

        let _ = subscription.pull_events(1);
        assert_eq!(
            flag_log.attempts(),
            0,
            "the refresh is not due yet and must not fire"
        );

        tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
        let _ = subscription.pull_events(1);
        assert_eq!(flag_log.attempts(), 1, "the refresh is due and must fire");

        let _ = subscription.pull_events(1);
        assert_eq!(
            flag_log.attempts(),
            1,
            "the next refresh is a full interval away; rescheduling into the past \
             would rebuild on every pull"
        );
    }

    /// A down channel waits out its backoff, then recovers AND drains within the
    /// same pull. Three decisions ride on this: only a down channel is rebuilt,
    /// the backoff deadline is respected, and a successful rebuild falls through
    /// to the drain rather than costing the caller a whole cycle.
    #[tokio::test]
    #[serial]
    async fn a_down_channel_waits_out_its_backoff_then_recovers_and_drains() {
        let mut subscription = subscription_from(&application_config()).await;

        {
            let _guard = ScriptGuard::install(&[(15007, 0)]);
            let _ = subscription.pull_events(usize::MAX);
        }
        assert!(!subscription.first_channel_is_live());

        let flag_log = FlagLog::install();
        let _ = subscription.pull_events(usize::MAX);
        assert_eq!(
            flag_log.attempts(),
            0,
            "the backoff deadline has not passed; retrying now is the stampede \
             the jittered backoff exists to prevent"
        );

        tokio::time::sleep(std::time::Duration::from_millis(1300)).await;
        let events = subscription
            .pull_events(usize::MAX)
            .expect("recovery must not surface as a source error");

        assert_eq!(flag_log.attempts(), 1, "the channel must retry once it may");
        assert!(subscription.first_channel_is_live());
        assert!(
            !events.is_empty(),
            "a recovered channel must be drained in the SAME pull; skipping the \
             drain costs a whole cycle of latency for nothing"
        );
    }

    // ---------------------------------------------------------------------
    // The in-loop filters.
    // ---------------------------------------------------------------------

    /// The event-id prefilter KEEPS the configured ids. Inverting it delivers
    /// nothing at all, which no delivery-count assertion elsewhere notices
    /// because those tests do not configure `only_event_ids`.
    #[tokio::test]
    #[serial]
    async fn the_only_event_ids_prefilter_keeps_the_configured_ids() {
        let mut baseline = subscription_from(&application_config()).await;
        let ids: Vec<u32> = baseline
            .pull_events(usize::MAX)
            .unwrap_or_default()
            .iter()
            .map(|e| e.event_id)
            .collect();
        assert!(
            !ids.is_empty(),
            "the Application backlog must be readable, otherwise this proves nothing"
        );
        let wanted = ids[0];
        drop(baseline);

        let mut config = application_config();
        config.only_event_ids = Some(vec![wanted]);
        let mut subscription = subscription_from(&config).await;

        let delivered = drain_all(&mut subscription);
        assert!(
            !delivered.is_empty(),
            "events matching the configured id must be delivered, not filtered out"
        );
    }

    /// D23 self-disables record-id gap detection for channels delivered as
    /// forwarded rendered text. Reading LOCAL events must not trip that: doing so
    /// would silently switch off the only signal we have for retention-overwrite
    /// data loss, on every channel, forever.
    #[tokio::test]
    #[serial]
    async fn reading_local_events_leaves_record_id_gap_detection_active() {
        let mut subscription = subscription_from(&application_config()).await;

        let delivered = drain_all(&mut subscription);
        assert!(
            !delivered.is_empty(),
            "events must actually be rendered for the forwarded-delivery decision \
             to be reached at all"
        );

        assert!(
            subscription.first_channel_reports_record_id_gaps(),
            "local events carry no <RenderingInfo>, so record ids stay trustworthy \
             and a gap must still be reported"
        );
    }

    /// The admission gate emits new events and drops only what it has already
    /// seen. Inverting it delivers nothing while looking, from the outside, like
    /// a quiet channel.
    ///
    /// Asserted against the count `EvtNext` handed back, which is the only
    /// oracle in reach that does not itself pass through the gate. "Delivered
    /// something" is the weak assertion this whole exercise exists to
    /// eliminate, and so is a comparison against a second drain: both sides run
    /// the same gate, so a gate that drops uniformly degrades both and the
    /// comparison stays green.
    #[tokio::test]
    #[serial]
    async fn the_admission_gate_emits_every_record_evtnext_returns() {
        let mut subscription = subscription_from(&application_config()).await;
        let request_log = RequestLog::install();

        let delivered = drain_all(&mut subscription);

        assert!(
            request_log.returned_total() >= 5,
            "the Application backlog must hold several records for a partial \
             delivery to be distinguishable from a complete one, got {}",
            request_log.returned_total()
        );

        let mut seen = std::collections::HashSet::new();
        for record_id in &delivered {
            assert!(
                seen.insert(*record_id),
                "record {record_id} was delivered twice within one drain"
            );
        }
        // Not an equality: the exact in-process boundary legitimately trims
        // records that arrive out of `(TimeCreated, RecordId)` order, which on
        // a real Application log is a small tail (measured at roughly 3% on the
        // development host). The claim being pinned is that the gate passes the
        // BULK of what the API returns. An inverted gate delivers only that
        // out-of-order tail, which is why a non-empty check cannot see it and a
        // proportion can.
        let returned = request_log.returned_total();
        assert!(
            delivered.len() as u64 * 2 > returned,
            "the admission gate emitted {} of the {returned} records the API \
             returned; trimming the out-of-order tail is expected, dropping the \
             bulk of a backlog is an inverted gate",
            delivered.len()
        );
    }

    /// A bookmark failure mid-batch abandons the rest of the batch, and every
    /// handle in it is ours to close exactly once. Closing one twice is a
    /// use-after-close against the API; missing one is the leak the whole
    /// handle-accounting seam exists to catch.
    #[tokio::test]
    #[serial]
    async fn a_mid_batch_bookmark_failure_closes_each_handle_exactly_once() {
        let mut baseline = subscription_from(&application_config()).await;
        let backlog = baseline.pull_events(2).unwrap_or_default().len();
        assert_eq!(
            backlog, 2,
            "this assertion needs a batch of exactly two events to distinguish \
             the current handle from the remainder"
        );
        drop(baseline);

        let mut subscription = subscription_from(&application_config()).await;
        let _guard = BookmarkFailGuard::install();
        let delivered = subscription.pull_events(2).unwrap_or_default();

        assert!(
            delivered.is_empty(),
            "an event whose position cannot be recorded is not delivered"
        );
        assert_eq!(
            subscription.first_channel_event_handle_closes(),
            2,
            "the failing handle and the one remaining handle, each closed once \
             AT THE API. These are real handles from a real EvtNext, so this \
             counts EvtClose calls, not trips through the accounting seam"
        );
    }

    /// The channel signal is re-armed only when the drain exited EARLY. Re-arming
    /// after a clean drain spins the wait loop at full speed; not re-arming after
    /// an early exit strands the remaining backlog until the next OS
    /// notification, which on a quiet channel may be hours.
    #[tokio::test]
    #[serial]
    async fn the_signal_is_rearmed_only_when_the_drain_exited_early() {
        let mut subscription = subscription_from(&application_config()).await;

        let delivered = subscription.pull_events(1).unwrap_or_default();
        assert_eq!(
            delivered.len(),
            1,
            "a budget of one must exit the drain early with backlog remaining"
        );
        assert!(
            matches!(
                subscription.wait_for_events_blocking(0),
                WaitResult::EventsAvailable
            ),
            "an early exit must re-arm the signal so the next pull revisits this \
             channel without waiting for a fresh OS notification"
        );

        // A clean drain leaves the signal alone. Retried, because a real event
        // arriving on Application would legitimately re-signal it.
        let mut quiesced = false;
        for _ in 0..5 {
            {
                let _guard = ScriptGuard::install(&[(259, 0)]);
                let _ = subscription.pull_events(usize::MAX);
            }
            if matches!(
                subscription.wait_for_events_blocking(0),
                WaitResult::Timeout
            ) {
                quiesced = true;
                break;
            }
        }
        assert!(
            quiesced,
            "a fully drained channel must not re-arm its own signal; doing so \
             spins the wait loop at full speed"
        );
    }

    /// The speculative pull exists to stop `EvtOpenLog`/`EvtGetLogInfo` churn on
    /// an idle host, so whether that query is ISSUED is the contract. A gauge
    /// write is not observable; the call is.
    #[tokio::test]
    #[serial]
    async fn record_count_queries_are_skipped_on_idle_speculative_pulls() {
        use super::super::render::CHANNEL_RECORDS_UPDATES;
        use std::sync::atomic::Ordering::SeqCst;

        let mut subscription = subscription_from(&application_config()).await;

        {
            let _guard = ScriptGuard::install(&[(259, 0)]);
            CHANNEL_RECORDS_UPDATES.store(0, SeqCst);
            let _ = subscription.pull_events_speculative(10);
        }
        assert_eq!(
            CHANNEL_RECORDS_UPDATES.load(SeqCst),
            0,
            "a speculative pull that read nothing must not query the log's record \
             count; that query is the churn this path exists to avoid"
        );

        {
            let _guard = ScriptGuard::install(&[(259, 0)]);
            CHANNEL_RECORDS_UPDATES.store(0, SeqCst);
            let _ = subscription.pull_events(10);
        }
        assert_eq!(
            CHANNEL_RECORDS_UPDATES.load(SeqCst),
            1,
            "a normal pull refreshes the record count even on an empty channel; \
             that gauge is how ingestion lag is detected"
        );
    }

    /// D17, at the layer that actually runs it: the deliberate one-shot skip.
    ///
    /// `admit` has good unit tests and they are load-bearing for nothing on
    /// their own, because the drain loop is `admit`'s only caller. Driven from
    /// here, the ladder walks to the skip rung and the assertion is what an
    /// operator would see: the poison record is not delivered, the record after
    /// it is, and a restart does not resume onto the record we deliberately
    /// dropped and repeat the whole escape.
    #[tokio::test]
    #[serial]
    async fn the_deliberate_skip_drops_one_record_and_survives_a_restart() {
        let mut baseline_sub = subscription_from(&application_config()).await;
        let backlog = drain_all(&mut baseline_sub);
        assert!(
            backlog.len() >= 6,
            "this walks a ladder over a partially read backlog and needs at \
             least six records, got {}",
            backlog.len()
        );
        drop(baseline_sub);

        let (checkpointer, _temp_dir) = create_test_checkpointer().await;
        let mut config = application_config();
        config.channels = vec!["Application".to_string()];
        let mut subscription = EventLogSubscription::new(&config, Arc::clone(&checkpointer), false)
            .await
            .expect("subscription creation should succeed");

        let read = subscription.pull_events(3).unwrap_or_default();
        assert_eq!(read.len(), 3, "the resume boundary must land mid-backlog");
        let poisoned = backlog[3];
        let next_good = backlog[4];

        // Two stuck detections: Bookmark -> IsolateOne -> SkipRecord. A moving
        // position is normal recovery, so only a position that does not move
        // across three consecutive rebuilds counts.
        for _ in 0..6 {
            {
                let _guard = ScriptGuard::install(&[(15011, 0)]);
                let _ = subscription.pull_events(usize::MAX);
            }
            subscription.force_rebuild_all();
        }
        assert!(subscription.first_channel_is_live());

        let delivered = drain_all(&mut subscription);
        assert!(
            !delivered.contains(&poisoned),
            "record {poisoned} sat immediately past the resume boundary on the \
             skip rung and had to be dropped; the escape did nothing"
        );
        assert!(
            delivered.contains(&next_good),
            "the skip costs exactly ONE record: {next_good} must still arrive"
        );

        subscription
            .flush_bookmarks()
            .await
            .expect("bookmarks must flush");
        drop(subscription);

        let mut restarted = EventLogSubscription::new(&config, checkpointer, false)
            .await
            .expect("subscription creation should succeed");
        let after_restart = drain_all(&mut restarted);
        assert!(
            !after_restart.contains(&poisoned),
            "record {poisoned} came back after a restart: the skip never became \
             durable, so every restart re-walks the entire escape ladder"
        );
    }

    /// D24: the periodic refresh is the ONLY thing that ever un-skips a channel.
    /// A skipped channel is deliberately not retried on the pull path, so if the
    /// refresh does not clear the skip, a transient ACL flap or a momentary bad
    /// channel path becomes a permanent outage for the life of the process.
    #[tokio::test]
    #[serial]
    async fn the_periodic_refresh_is_what_un_skips_a_skipped_channel() {
        let mut config = application_config();
        config.subscription_refresh_secs = 1;
        let mut subscription = subscription_from(&config).await;

        {
            // ERROR_EVT_INVALID_CHANNEL_PATH: skip for this generation.
            let _guard = ScriptGuard::install(&[(15000, 0)]);
            let _ = subscription.pull_events(usize::MAX);
        }
        assert!(
            !subscription.first_channel_is_live(),
            "a skip must take the channel out of service"
        );

        let _ = subscription.pull_events(usize::MAX);
        assert!(
            !subscription.first_channel_is_live(),
            "the pull path must not retry a skipped channel; that is the retry \
             loop and the log noise D24 removes"
        );

        tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
        let _ = subscription.pull_events(usize::MAX);
        assert!(
            subscription.first_channel_is_live(),
            "the refresh must clear the skip and rebuild, so an ACL flap heals \
             within one interval instead of never"
        );
    }

    // ---------------------------------------------------------------------
    // D11: the halve-and-recover cycle on RPC_S_INVALID_BOUND (1734).
    //
    // 1734 is a real platform condition we have never been able to trigger on
    // our hardware (plan 10.2 leg 5, 10.5), so until now our response to it was
    // verified by nothing but a classifier routing test. These drive the whole
    // cycle through the EvtNext seam and assert it in terms of what we ask the
    // API for next and what comes back.
    // ---------------------------------------------------------------------

    /// On 1734 the batch halves and the subscription reopens FROM THE BOOKMARK.
    /// Reopening from anywhere else would either replay the channel or discard
    /// its backlog on what is only a marshalling-size problem.
    #[tokio::test]
    #[serial]
    async fn an_oversized_read_halves_the_batch_and_reopens_from_the_bookmark() {
        let mut subscription = subscription_from(&application_config()).await;
        assert!(
            !drain_all(&mut subscription).is_empty(),
            "the backlog must be readable so the bookmark is positioned"
        );
        let baseline_handles = subscription.first_channel_handle_balance();

        let request_log = RequestLog::install();
        let flag_log = FlagLog::install();

        {
            let _guard = ScriptGuard::install(&[(1734, 0)]);
            let _ = subscription
                .pull_events(usize::MAX)
                .expect("an oversized read is not a source error");
        }

        assert_eq!(
            request_log.sizes(),
            vec![100],
            "the failing read asked for the configured batch size"
        );
        assert_eq!(
            flag_log.flags(),
            vec![EvtSubscribeStartAfterBookmark.0 | EvtSubscribeStrict.0],
            "the reopen must resume from the bookmark, strictly"
        );
        assert!(
            subscription.first_channel_is_live(),
            "an oversized read is a size problem, not a dead channel"
        );
        assert_eq!(
            subscription.first_channel_handle_balance(),
            baseline_handles,
            "the reopen must close exactly the handle it replaced"
        );

        request_log.clear();
        let _ = subscription.pull_events(usize::MAX);
        assert_eq!(
            request_log.sizes().first().copied(),
            Some(50),
            "the next read must ask for half as much"
        );
    }

    /// Repeated 1734 keeps halving, and stops at one. A batch of zero is not a
    /// request the API can serve, so the floor is the whole reason the ladder
    /// terminates instead of wedging the channel.
    #[tokio::test]
    #[serial]
    async fn repeated_oversized_reads_halve_the_batch_to_a_floor_of_one() {
        let mut subscription = subscription_from(&application_config()).await;
        let request_log = RequestLog::install();

        for _ in 0..8 {
            let _guard = ScriptGuard::install(&[(1734, 0)]);
            let _ = subscription.pull_events(usize::MAX);
        }

        assert_eq!(
            request_log.sizes(),
            vec![100, 50, 25, 12, 6, 3, 1, 1],
            "the batch halves on every oversized read and floors at one"
        );
    }

    /// Recovery after a PLAIN reduction is gradual. The reduction was caused by
    /// the data on the channel, so stepping straight back to the configured size
    /// on the first clean batch would just walk into the same oversized event
    /// again.
    #[tokio::test]
    #[serial]
    async fn recovery_after_a_plain_batch_reduction_is_gradual() {
        let mut subscription = subscription_from(&application_config()).await;

        {
            let _guard = ScriptGuard::install(&[(1734, 0)]);
            let _ = subscription.pull_events(usize::MAX);
        }

        let request_log = RequestLog::install();

        // Nine clean batches: one short of the recovery threshold.
        {
            let _renders = RenderFailGuard::install();
            let mut script = vec![(0u32, 1u32); 9];
            script.push((259, 0));
            let _guard = ScriptGuard::install(&script);
            let _ = subscription.pull_events(usize::MAX);
        }
        assert_eq!(
            request_log.sizes(),
            vec![50; 10],
            "nine clean batches is not enough; the size must not step up early"
        );

        // The tenth crosses it.
        request_log.clear();
        {
            let _renders = RenderFailGuard::install();
            let _guard = ScriptGuard::install(&[(0, 1), (259, 0)]);
            let _ = subscription.pull_events(usize::MAX);
        }
        assert_eq!(
            request_log.sizes(),
            vec![50, 100],
            "the tenth consecutive clean batch steps the size back up"
        );
    }

    /// Recovery after a POISON-ESCAPE rung is immediate. That reduction was not
    /// caused by size at all: the batch was forced to one purely to attribute a
    /// failure to a single record, so once a batch reads clean there is nothing
    /// left to be careful about. This is how 4.2 and 4.3.1 are reconciled, and
    /// the two paths must not be collapsed into one.
    #[tokio::test]
    #[serial]
    async fn recovery_after_a_poison_escape_rung_is_immediate() {
        let mut subscription = subscription_from(&application_config()).await;
        assert!(
            !drain_all(&mut subscription).is_empty(),
            "a resume position must exist before it can be found stuck"
        );

        // Three rebuilds that resume at the same position: a moving position is
        // normal recovery, a stuck one is a poisoned position.
        for _ in 0..3 {
            {
                let _guard = ScriptGuard::install(&[(15011, 0)]);
                let _ = subscription.pull_events(usize::MAX);
            }
            subscription.force_rebuild_all();
        }
        assert!(subscription.first_channel_is_live());

        let request_log = RequestLog::install();
        let _renders = RenderFailGuard::install();
        let _guard = ScriptGuard::install(&[(0, 1), (259, 0)]);
        let _ = subscription.pull_events(usize::MAX);

        assert_eq!(
            request_log.sizes(),
            vec![1, 100],
            "the isolate rung asks for one record, and the first clean batch \
             restores the configured size immediately rather than gradually"
        );
    }

    /// Nothing is lost and nothing is duplicated across the whole cycle.
    ///
    /// This is the invariant D8 trades partial-batch emit away for: on 1734 the
    /// API cursor advances even when the call fails, so the returned handles are
    /// discarded and the position is taken from the bookmark instead. If that
    /// were wrong, the events in flight at each fault would silently vanish.
    #[tokio::test]
    #[serial]
    async fn no_events_are_lost_or_duplicated_across_the_halve_and_recover_cycle() {
        let mut baseline = subscription_from(&application_config()).await;
        let before: Vec<u64> = drain_all(&mut baseline);
        assert!(
            !before.is_empty(),
            "the Application backlog must be readable, otherwise this proves nothing"
        );
        drop(baseline);

        let mut subscription = subscription_from(&application_config()).await;
        let mut delivered: Vec<u64> = Vec::new();
        for _ in 0..4 {
            {
                let _guard = ScriptGuard::install(&[(1734, 0)]);
                let _ = subscription.pull_events(usize::MAX);
            }
            delivered.extend(drain_all(&mut subscription));
        }

        let mut seen = std::collections::HashSet::new();
        for record_id in &delivered {
            assert!(
                seen.insert(*record_id),
                "record {record_id} was delivered twice across the batch-adaptation \
                 cycle"
            );
        }
        for record_id in &before {
            assert!(
                seen.contains(record_id),
                "record {record_id} was readable before the cycle and was never \
                 delivered: the events in flight at an oversized read were \
                 discarded without the position falling back to the bookmark"
            );
        }
    }

    // ---------------------------------------------------------------------
    // Handle lifetime, asserted at the API rather than at the seam.
    // ---------------------------------------------------------------------

    /// Every handle `EvtNext` hands back must reach `EvtClose`.
    ///
    /// The oracle is deliberately not the accounting seam. A seam that counts
    /// calls INTO itself cannot see a null guard below it that stops closing
    /// real handles, and that mutation leaks one handle per event while the
    /// old balance test stayed green. `event_handle_closes` is now driven by
    /// whether `close_event_handle` actually called the API, and it is
    /// compared against the record count recorded BEFORE any drain decision.
    #[tokio::test]
    #[serial]
    async fn every_event_handle_evtnext_returns_is_closed_at_the_api() {
        let mut subscription = subscription_from(&application_config()).await;
        let request_log = RequestLog::install();

        // Rebuilds interleaved with real drains: both the drain and the
        // discard-on-rebuild path retire handles, and a leak in either is a
        // leak.
        let mut delivered = 0usize;
        for _ in 0..3 {
            delivered += drain_all(&mut subscription).len();
            subscription.force_rebuild_all();
            assert!(
                subscription.first_channel_is_live(),
                "a rebuild against a live Application channel must succeed"
            );
        }

        let returned = request_log.returned_total();
        assert!(
            returned >= 5 && delivered > 0,
            "the Application backlog must produce several records, otherwise a \
             leak of every handle is indistinguishable from a quiet channel; \
             returned {returned}, delivered {delivered}"
        );
        assert_eq!(
            subscription.first_channel_event_handle_closes() as u64,
            returned,
            "every one of the {returned} handles the API returned must reach \
             EvtClose exactly once"
        );
    }

    /// The RAII wrapper on publisher metadata handles releases the handle, and
    /// releases nothing when it holds none.
    ///
    /// Asserted on the close count kept inside the guard and after the API
    /// call, so neither an empty drop body nor an inverted null test can
    /// satisfy it. "Drop ran" is not the property.
    #[test]
    fn a_dropped_publisher_handle_is_released_at_the_api() {
        use std::sync::atomic::Ordering::SeqCst;
        use windows::Win32::System::EventLog::EvtOpenPublisherMetadata;

        let provider = HSTRING::from("Microsoft-Windows-Kernel-General");
        let handle = unsafe { EvtOpenPublisherMetadata(None, &provider, None, 0, 0) }
            .expect("the kernel publisher manifest is present on every Windows host");

        let before = PUBLISHER_HANDLE_CLOSES.load(SeqCst);
        {
            let _wrapped = PublisherHandle(handle.0);
            assert_eq!(
                PUBLISHER_HANDLE_CLOSES.load(SeqCst),
                before,
                "nothing may be released while the wrapper is still alive"
            );
        }
        assert_eq!(
            PUBLISHER_HANDLE_CLOSES.load(SeqCst) - before,
            1,
            "dropping the wrapper must close the publisher metadata handle; \
             every LRU eviction leaks one otherwise"
        );

        {
            let _null = PublisherHandle(0);
        }
        assert_eq!(
            PUBLISHER_HANDLE_CLOSES.load(SeqCst) - before,
            1,
            "a wrapper holding no handle must not reach the API"
        );
    }

    /// Teardown releases the subscription handle and the channel signal event.
    ///
    /// Counted from inside the real close paths, so the count is still
    /// readable after the owner is gone. Deleting the drop body leaks one
    /// subscription and one event object per channel for the process lifetime.
    #[tokio::test]
    #[serial]
    async fn dropping_the_subscription_releases_every_handle_it_holds() {
        use std::sync::atomic::Ordering::SeqCst;

        let subscription = subscription_from(&application_config()).await;
        assert!(
            subscription.first_channel_is_live(),
            "there must be a live handle for teardown to have anything to release"
        );

        let handles_before = SUBSCRIPTION_HANDLE_CLOSES.load(SeqCst);
        let events_before = SUBSCRIPTION_TEARDOWN_CLOSES.load(SeqCst);
        drop(subscription);

        assert_eq!(
            SUBSCRIPTION_HANDLE_CLOSES.load(SeqCst) - handles_before,
            1,
            "teardown must close the live subscription handle"
        );
        assert_eq!(
            SUBSCRIPTION_TEARDOWN_CLOSES.load(SeqCst) - events_before,
            1,
            "teardown must close the channel signal event"
        );
    }

    // ---------------------------------------------------------------------
    // Checkpoint identity and validity.
    // ---------------------------------------------------------------------

    /// Ack-mode checkpointing looks a position up by channel name. Returning a
    /// sibling's position writes channel A's progress under channel B, which is
    /// silent; returning none never advances the checkpoint at all, which
    /// re-delivers everything after a restart.
    #[tokio::test]
    #[serial]
    async fn a_checkpoint_position_belongs_to_the_channel_it_was_asked_for() {
        let mut config = application_config();
        config.channels = vec!["Application".to_string(), "System".to_string()];
        let mut subscription = subscription_from(&config).await;

        let live = subscription.live_channel_names();
        assert_eq!(
            live.len(),
            2,
            "two channels are required: with one, a cross-channel read is \
             indistinguishable from a correct one, got {live:?}"
        );

        let delivered = drain_all(&mut subscription);
        assert!(
            !delivered.is_empty(),
            "both bookmarks must be positioned, otherwise no position exists to \
             be looked up"
        );

        let first = subscription
            .channel_position(&live[0])
            .unwrap_or_else(|| panic!("{} must have a position after a drain", live[0]));
        let second = subscription
            .channel_position(&live[1])
            .unwrap_or_else(|| panic!("{} must have a position after a drain", live[1]));

        assert_eq!(
            first.channel, live[0],
            "the position returned for {} must be its own, not a sibling's",
            live[0]
        );
        assert_eq!(
            second.channel, live[1],
            "the position returned for {} must be its own, not a sibling's",
            live[1]
        );
        assert_ne!(
            first.bookmark_xml, second.bookmark_xml,
            "two channels drained to different points must not share a bookmark"
        );
        assert!(
            subscription
                .channel_position("Channel-That-Is-Not-Configured")
                .is_none(),
            "a channel that is not subscribed has no position"
        );
    }

    /// A bookmark that marks no position must never reach the checkpoint.
    ///
    /// Persisting one gives the next start a bookmark it has to fall back
    /// from, which is the dead-bookmark path the whole resume ladder exists to
    /// survive: a checkpoint write that creates the failure it protects against.
    #[tokio::test]
    #[serial]
    async fn a_bookmark_marking_no_position_is_never_checkpointed() {
        let mut subscription = subscription_from(&application_config()).await;

        assert!(
            subscription.channel_position("Application").is_none(),
            "a freshly created bookmark marks nothing and its XML carries no \
             RecordId, so there is no position to persist"
        );

        let delivered = drain_all(&mut subscription);
        assert!(
            !delivered.is_empty(),
            "the Application backlog must be readable, otherwise the negative \
             assertion above is vacuous"
        );
        let position = subscription
            .channel_position("Application")
            .expect("a positioned bookmark IS checkpointable");
        assert!(
            position.bookmark_xml.contains("RecordId"),
            "the persisted XML must carry the position, got: {}",
            position.bookmark_xml
        );
    }

    // ---------------------------------------------------------------------
    // Generated query composition (D21).
    // ---------------------------------------------------------------------

    /// The generated time predicate is composed onto a wildcard base and
    /// nowhere else.
    ///
    /// Three separate guards decide this and each fails differently: a time
    /// rung subscribing with the bare base loses the fallback entirely, a
    /// bookmark rung subscribing with a predicate it never asked for narrows a
    /// healthy resume, and composing over an operator's XPath silently
    /// replaces the operator's filter with ours.
    #[test]
    fn a_time_predicate_is_composed_onto_a_wildcard_base_and_nothing_else() {
        use chrono::TimeZone;

        fn factory(base: &str) -> SubscriptionFactory {
            SubscriptionFactory {
                channel: "Application".to_string(),
                base_query: base.to_string(),
                base_origin: QueryOrigin::Operator,
                read_existing_events: true,
            }
        }

        const OPERATOR_QUERY: &str = "*[System[EventID=4624]]";
        let when = chrono::Utc.with_ymd_and_hms(2026, 8, 7, 12, 0, 0).unwrap();

        let mut resume = ResumeState::new(true);
        resume.observe_event(when, 42);

        // Bookmark rung. A time floor exists, and it must not be used: the
        // bookmark is the position.
        assert_eq!(
            factory("*").query_for(&resume),
            ("*".to_string(), QueryOrigin::Operator),
            "a bookmark resume subscribes with the configured query"
        );

        // Time rung over a wildcard base: the predicate IS the resume position.
        resume.rung = Rung::TimeAdvance(TimeRung::BoundaryTick);
        assert_eq!(
            factory("*").query_for(&resume),
            (
                "*[System[TimeCreated[@SystemTime>='2026-08-07T12:00:00.000Z']]]".to_string(),
                QueryOrigin::Generated
            ),
            "a time rung over a wildcard base subscribes with the generated \
             predicate, tagged as ours so 15001 advances the ladder instead of \
             failing the channel"
        );

        // Time rung over an operator query: not composable, so the operator's
        // query stands and the exact in-process boundary does the trimming.
        assert_eq!(
            factory(OPERATOR_QUERY).query_for(&resume),
            (OPERATOR_QUERY.to_string(), QueryOrigin::Operator),
            "an operator XPath is never intersected with a generated predicate"
        );
    }

    // ---------------------------------------------------------------------
    // Log severity and triage fields.
    // ---------------------------------------------------------------------

    /// Captures `(level, error_type)` for every warn-band record.
    #[derive(Clone, Default)]
    struct ErrorTypeCapture {
        seen: std::sync::Arc<std::sync::Mutex<Vec<(String, String)>>>,
    }

    struct ErrorTypeVisitor(Option<String>);

    impl tracing::field::Visit for ErrorTypeVisitor {
        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            if field.name() == "error_type" {
                self.0 = Some(value.to_string());
            }
        }

        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            if field.name() == "error_type" {
                self.0 = Some(format!("{value:?}"));
            }
        }
    }

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for ErrorTypeCapture {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let level = *event.metadata().level();
            if level > tracing::Level::WARN {
                return;
            }
            let mut visitor = ErrorTypeVisitor(None);
            event.record(&mut visitor);
            self.seen
                .lock()
                .unwrap()
                .push((level.to_string(), visitor.0.unwrap_or_default()));
        }
    }

    /// D16: the terminal rung discards the channel's whole backlog and is an
    /// ERROR. Every other rung discards a bounded window and is a WARN.
    ///
    /// The severity IS the decision here, so both directions are asserted: a
    /// polarity flip makes ordinary ladder movement page an operator and makes
    /// unrecoverable backlog loss a warning.
    #[tokio::test]
    #[serial]
    async fn the_terminal_resume_rung_is_an_error_and_the_others_are_warnings() {
        use tracing_subscriber::layer::SubscriberExt;

        fn capture<F: FnOnce()>(f: F) -> Vec<(String, String)> {
            let capture = ErrorTypeCapture::default();
            let collector = tracing_subscriber::registry().with(capture.clone());
            tracing::subscriber::with_default(collector, f);
            let seen = capture.seen.lock().unwrap().clone();
            seen
        }

        // No event has ever been observed, so a dead bookmark has no stored
        // time to fall back to and the ladder goes straight to the terminal
        // rung.
        let mut fresh = subscription_from(&application_config()).await;
        let terminal = capture(|| {
            let _guard = SubscribeScriptGuard::install(&[15011]);
            fresh.force_rebuild_all();
        });
        assert!(
            terminal
                .iter()
                .any(|(level, kind)| level == "ERROR" && kind == "resume_future_only"),
            "falling back to future-events-only discards the backlog \
             irrecoverably and must be an ERROR, got: {terminal:#?}"
        );

        // With a stored position the same failure takes a time rung, which
        // discards a bounded window and is ordinary ladder movement.
        let mut positioned = subscription_from(&application_config()).await;
        assert!(
            !drain_all(&mut positioned).is_empty(),
            "a stored position is required for the time rung to be reachable"
        );
        let time_rung = capture(|| {
            let _guard = SubscribeScriptGuard::install(&[15011]);
            positioned.force_rebuild_all();
        });
        assert!(
            time_rung.iter().any(|(level, _)| level == "WARN"),
            "a time-window rung must be announced, got: {time_rung:#?}"
        );
        assert!(
            !time_rung
                .iter()
                .any(|(_, kind)| kind == "resume_future_only"),
            "a bounded time-window fallback is not backlog loss and must not \
             claim to be, got: {time_rung:#?}"
        );
    }

    /// `last_event_at` is the triage fact on the onset ERROR and the recovery
    /// WARN (D29), and the agent's give-up WARN (D30) reads it. It is absolute
    /// so consumers derive the age, and "never" is a distinct, meaningful value.
    #[tokio::test]
    #[serial]
    async fn last_event_at_reads_never_until_an_event_arrives_and_a_timestamp_after() {
        let mut subscription = subscription_from(&application_config()).await;

        assert_eq!(
            subscription.first_channel_last_event_at(),
            "never",
            "a channel that has produced nothing for us must say so plainly, \
             not report a zero or empty timestamp"
        );

        let delivered = drain_all(&mut subscription);
        assert!(!delivered.is_empty(), "events must actually arrive");

        let reported = subscription.first_channel_last_event_at();
        let parsed = chrono::DateTime::parse_from_rfc3339(&reported)
            .unwrap_or_else(|e| panic!("last_event_at must be RFC3339, got {reported:?}: {e}"));
        assert!(
            parsed.timestamp() > 0,
            "an absolute timestamp is what lets a consumer derive the age, got \
             {reported:?}"
        );
    }

    /// The 30s health heartbeat is an operator's only "are my channels up"
    /// signal, and both halves carry meaning: the total is the configured
    /// channel count and the active count is how many are readable right now.
    #[tokio::test]
    #[serial]
    async fn the_health_summary_counts_configured_and_live_channels() {
        let mut config = application_config();
        config.channels = vec!["Application".to_string(), "System".to_string()];
        let mut subscription = subscription_from(&config).await;

        assert_eq!(
            subscription.channel_health_summary(),
            (2, 2),
            "two configured channels, both readable on a healthy host"
        );

        {
            // One channel goes down; the other is untouched.
            let _guard = ScriptGuard::install(&[(15007, 0)]);
            let _ = subscription.pull_events(100).expect("must not error out");
        }

        assert_eq!(
            subscription.channel_health_summary(),
            (2, 1),
            "the total is the configuration and does not move; the active count \
             is the live channels and must drop by exactly the one that failed"
        );
    }

    // ---------------------------------------------------------------------
    // D23: rendered-text delivery revokes record-id trust.
    // ---------------------------------------------------------------------

    /// Rewrites the XML of every rendered event.
    struct XmlRewriteGuard;

    impl XmlRewriteGuard {
        fn install(f: std::sync::Arc<dyn Fn(String) -> String + Send + Sync>) -> Self {
            *super::super::render::RENDER_XML_REWRITE.lock().unwrap() = Some(f);
            Self
        }
    }

    impl Drop for XmlRewriteGuard {
        fn drop(&mut self) {
            *super::super::render::RENDER_XML_REWRITE.lock().unwrap() = None;
        }
    }

    /// An event delivered as rendered text revokes record-id trust for its
    /// channel, permanently.
    ///
    /// A genuine one needs a WEC forwarding pair, but the decision is derived
    /// by PARSING the event XML, so an event whose XML carries
    /// `<RenderingInfo>` is an input to the real derivation rather than a
    /// stubbed verdict. Both consequences are asserted on behavior: gap
    /// detection stops reporting, and the ladder can no longer select the
    /// single-record skip, which on interleaved forwarded ids would discard an
    /// arbitrary machine's event.
    #[tokio::test]
    #[serial]
    async fn an_event_delivered_as_rendered_text_revokes_record_id_trust() {
        // Control: the same backlog, unmodified. Both properties must hold
        // afterwards, or the treatment below proves nothing.
        let mut control = subscription_from(&application_config()).await;
        let baseline = drain_all(&mut control);
        assert!(
            baseline.len() >= 2,
            "the Application backlog must hold at least two records: one to \
             carry <RenderingInfo> and one plain one after it, got {}",
            baseline.len()
        );
        assert!(
            control.first_channel_reports_record_id_gaps(),
            "local events leave record ids trustworthy"
        );
        assert!(
            control.first_channel_ladder_can_skip_one_record(),
            "local events leave the single-record skip available"
        );
        drop(control);

        // Treatment: the FIRST event of the same backlog arrives carrying
        // <RenderingInfo>, every later one is untouched. That is the
        // production shape, and it makes the stickiness assertion real: one
        // forwarded event is proof about the CHANNEL, not about that event.
        let mut subscription = subscription_from(&application_config()).await;
        let delivered = {
            let rewritten = std::sync::atomic::AtomicBool::new(false);
            let _guard = XmlRewriteGuard::install(std::sync::Arc::new(move |xml: String| {
                if rewritten.swap(true, std::sync::atomic::Ordering::SeqCst) {
                    return xml;
                }
                xml.replace(
                    "</Event>",
                    "<RenderingInfo Culture='en-US'><Message>forwarded</Message>\
                     </RenderingInfo></Event>",
                )
            }));
            drain_all(&mut subscription)
        };
        assert!(
            delivered.len() >= 2,
            "the forwarded-delivery decision is derived per rendered event, so \
             the marked event and at least one plain event after it must both \
             be delivered, got {}",
            delivered.len()
        );

        assert!(
            !subscription.first_channel_reports_record_id_gaps(),
            "forwarded record ids interleave many originating machines, so every \
             batch looks like a gap and detection must self-suppress. It must \
             also stay suppressed across the plain events that followed"
        );
        assert!(
            !subscription.first_channel_ladder_can_skip_one_record(),
            "a single-record skip is not expressible against interleaved \
             forwarded record ids and the ladder must go straight to the time \
             rungs"
        );
    }
}
