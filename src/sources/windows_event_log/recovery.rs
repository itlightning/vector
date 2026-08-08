//! Per-channel recovery state: backoff, resume ladder, batch adaptation,
//! poison-event escape, and the observability episode edges.
//!
//! Everything here is pure data and arithmetic with no Win32 dependency, so it
//! is unit-testable without an event log. `subscription.rs` owns the handles
//! and calls into this module for every decision that is not a syscall.

use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};

/// Backoff floor. Fast enough that a service blip costs one second.
const BACKOFF_BASE: Duration = Duration::from_secs(1);
/// Backoff ceiling. Vector never gives up on its own; the agent stops asking by
/// dropping the binding, so the ceiling only has to stop the retry rate from
/// being a load source.
const BACKOFF_CAP: Duration = Duration::from_secs(60);
/// Fraction of the computed delay that jitter can subtract.
const JITTER_FRACTION: f64 = 0.25;

/// Consecutive clean batches required before the adapted batch size steps back
/// up toward the configured value.
const CLEAN_BATCHES_TO_RECOVER: u32 = 10;

/// Consecutive rebuilds that resume at the same position before we conclude the
/// position itself is poisoned. Two is enough to distinguish "transient" from
/// "deterministic at this record" and cheap enough not to matter if wrong.
const STUCK_REBUILDS_BEFORE_ESCAPE: u32 = 3;

/// Interval for the still-unavailable reminder. DEBUG, not WARN: prolonged
/// absence usually means the software was uninstalled, and exactly one
/// warn-band event per episode is emitted, by the agent, at give-up.
pub(super) const UNAVAILABLE_REMINDER_INTERVAL: Duration = Duration::from_secs(3600);

/// Exponential backoff with per-channel jitter.
///
/// Jitter is not decoration. An EventLog service restart invalidates every
/// channel at once; without jitter they rebuild in lockstep and stampede a
/// service that is already recovering.
#[derive(Debug, Clone)]
pub(super) struct Backoff {
    attempt: u32,
    /// Per-channel, so two channels never draw the same sequence.
    jitter_state: u64,
}

impl Backoff {
    /// `seed` should be derived from the channel name so the jitter sequence is
    /// stable per channel and different between channels.
    pub(super) const fn new(seed: u64) -> Self {
        Self {
            attempt: 0,
            // Avoid the all-zero state, which is a fixed point of xorshift.
            jitter_state: seed | 1,
        }
    }

    /// Number of failed attempts since the last [`Self::reset`].
    pub(super) const fn attempt(&self) -> u32 {
        self.attempt
    }

    /// Advance and return the next delay: 1s doubling to a 60s cap, minus up to
    /// 25% jitter.
    pub(super) fn next_delay(&mut self) -> Duration {
        let shift = self.attempt.min(6);
        let raw = BACKOFF_BASE.saturating_mul(1u32 << shift).min(BACKOFF_CAP);
        self.attempt = self.attempt.saturating_add(1);

        // xorshift64*: no dependency, deterministic per channel, and good
        // enough to decorrelate rebuild storms.
        self.jitter_state ^= self.jitter_state << 13;
        self.jitter_state ^= self.jitter_state >> 7;
        self.jitter_state ^= self.jitter_state << 17;
        let unit = (self.jitter_state >> 11) as f64 / (1u64 << 53) as f64;

        let reduction = raw.mul_f64(JITTER_FRACTION * unit);
        raw.saturating_sub(reduction)
    }

    pub(super) const fn reset(&mut self) {
        self.attempt = 0;
    }
}

/// Where a channel resumed from, for the recovery WARN.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ResumedFrom {
    Bookmark,
    TimeFallback,
    FutureOnly,
}

impl ResumedFrom {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Bookmark => "bookmark",
            Self::TimeFallback => "time_fallback",
            Self::FutureOnly => "future_only",
        }
    }
}

/// One rung of the resume ladder.
///
/// The ordering is deliberate and is the whole point of D17: precision first,
/// convenience last. A single one-second time rung on a busy channel can
/// discard thousands of good events to escape one bad record; a single-record
/// skip cannot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Rung {
    /// Strict bookmark resume. The normal state.
    Bookmark,
    /// Batch size forced to 1 so the next failure is attributable to exactly
    /// one record rather than to a window.
    IsolateOne,
    /// Skip the isolated record id. This loses exactly one event, which is the
    /// correct cost of one poison event.
    SkipRecord,
    /// Time-window rungs, used only when record identity is unusable: record
    /// ids reset when a channel is recreated or cleared and are meaningless on
    /// forwarded channels.
    TimeAdvance(TimeRung),
    /// Terminal rung. Discards the backlog, so it emits ERROR when it fires.
    FutureOnly,
}

/// Time-window rungs in ascending order of data loss.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TimeRung {
    /// Advance past the boundary tick only.
    BoundaryTick,
    OneSecond,
    TenSeconds,
    OneMinute,
    FiveMinutes,
    ThirtyMinutes,
}

impl TimeRung {
    pub(super) const fn advance_by(self) -> Duration {
        match self {
            // One 100ns FILETIME tick, expressed in nanoseconds.
            Self::BoundaryTick => Duration::from_nanos(100),
            Self::OneSecond => Duration::from_secs(1),
            Self::TenSeconds => Duration::from_secs(10),
            Self::OneMinute => Duration::from_secs(60),
            Self::FiveMinutes => Duration::from_secs(300),
            Self::ThirtyMinutes => Duration::from_secs(1800),
        }
    }

    const fn next(self) -> Option<Self> {
        match self {
            Self::BoundaryTick => Some(Self::OneSecond),
            Self::OneSecond => Some(Self::TenSeconds),
            Self::TenSeconds => Some(Self::OneMinute),
            Self::OneMinute => Some(Self::FiveMinutes),
            Self::FiveMinutes => Some(Self::ThirtyMinutes),
            Self::ThirtyMinutes => None,
        }
    }

    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::BoundaryTick => "boundary_tick",
            Self::OneSecond => "+1s",
            Self::TenSeconds => "+10s",
            Self::OneMinute => "+60s",
            Self::FiveMinutes => "+5m",
            Self::ThirtyMinutes => "+30m",
        }
    }
}

impl Rung {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Bookmark => "bookmark",
            Self::IsolateOne => "isolate_one",
            Self::SkipRecord => "skip_record",
            Self::TimeAdvance(t) => t.as_str(),
            Self::FutureOnly => "future_only",
        }
    }

    pub(super) const fn resumed_from(self) -> ResumedFrom {
        match self {
            Self::Bookmark | Self::IsolateOne | Self::SkipRecord => ResumedFrom::Bookmark,
            Self::TimeAdvance(_) => ResumedFrom::TimeFallback,
            Self::FutureOnly => ResumedFrom::FutureOnly,
        }
    }

    /// True once we are deliberately discarding events, which is what
    /// suppresses the "unexpected gap" framing on record-id gap detection: the
    /// gap is intentional and the rung WARN already reported it.
    pub(super) const fn is_deliberate_skip(self) -> bool {
        !matches!(self, Self::Bookmark | Self::IsolateOne)
    }
}

/// The resume position and ladder state for one channel.
#[derive(Debug, Clone)]
pub(super) struct ResumeState {
    pub(super) rung: Rung,
    /// Full-precision `TimeCreated` of the last good event. Stored at 100ns
    /// FILETIME resolution so the in-process boundary can be exact.
    pub(super) last_event_time: Option<DateTime<Utc>>,
    /// `EventRecordID` of the last good event, paired with the time above to
    /// make position identity exact.
    pub(super) last_record_id: Option<u64>,
    /// One-shot: drop the first record delivered after this resume.
    ///
    /// The poison record's id is unknowable by construction. `EvtNext` failed,
    /// so no handle came back and nothing identified it; the only thing we know
    /// is that it is the record sitting immediately past the resume boundary.
    /// Keying the skip on `last_record_id` would be a no-op, because the
    /// boundary below already drops everything at or before the last good
    /// event.
    pub(super) skip_next_record: bool,
    /// Position identity at the last rebuild, used to detect a stuck position.
    stuck_position: Option<(DateTime<Utc>, u64)>,
    stuck_count: u32,
    /// True once record identity has proven unusable, which is the only reason
    /// to escalate to time windows.
    record_identity_usable: bool,
}

impl ResumeState {
    pub(super) const fn new(record_identity_usable: bool) -> Self {
        Self {
            rung: Rung::Bookmark,
            last_event_time: None,
            last_record_id: None,
            skip_next_record: false,
            stuck_position: None,
            stuck_count: 0,
            record_identity_usable,
        }
    }

    /// Record a successfully processed event.
    pub(super) const fn observe_event(&mut self, time: DateTime<Utc>, record_id: u64) {
        self.last_event_time = Some(time);
        self.last_record_id = Some(record_id);
    }

    /// A batch read cleanly. Reset the ladder and the stuck detector so a
    /// transient cause never leaves a channel permanently coarse or slow.
    pub(super) const fn observe_clean_read(&mut self) {
        self.rung = Rung::Bookmark;
        self.skip_next_record = false;
        self.stuck_position = None;
        self.stuck_count = 0;
    }

    /// Mark record identity as untrustworthy for this channel. Forwarded events
    /// interleave record ids from many originating machines, so a record-id
    /// skip is not expressible there.
    pub(super) const fn mark_record_identity_unusable(&mut self) {
        self.record_identity_usable = false;
    }

    /// Called once per rebuild. Returns true when the resume position has not
    /// moved for [`STUCK_REBUILDS_BEFORE_ESCAPE`] consecutive rebuilds, which
    /// is what distinguishes a positional failure from a transient one. A
    /// moving position is normal recovery and must not trigger this.
    pub(super) fn note_rebuild(&mut self) -> bool {
        let position = match (self.last_event_time, self.last_record_id) {
            (Some(t), Some(r)) => Some((t, r)),
            _ => None,
        };
        if position.is_some() && position == self.stuck_position {
            self.stuck_count = self.stuck_count.saturating_add(1);
        } else {
            self.stuck_position = position;
            self.stuck_count = 1;
        }
        self.stuck_count >= STUCK_REBUILDS_BEFORE_ESCAPE
    }

    /// Advance exactly one rung. Called once per stuck detection, never once
    /// per rebuild, so a flapping channel cannot walk the ladder in seconds.
    pub(super) fn advance_rung(&mut self) -> Rung {
        self.stuck_count = 0;
        self.rung = match self.rung {
            Rung::Bookmark => Rung::IsolateOne,
            Rung::IsolateOne => {
                if self.record_identity_usable && self.last_record_id.is_some() {
                    Rung::SkipRecord
                } else {
                    Rung::TimeAdvance(TimeRung::BoundaryTick)
                }
            }
            Rung::SkipRecord => Rung::TimeAdvance(TimeRung::BoundaryTick),
            Rung::TimeAdvance(t) => match t.next() {
                Some(next) => Rung::TimeAdvance(next),
                None => Rung::FutureOnly,
            },
            Rung::FutureOnly => Rung::FutureOnly,
        };

        // Total, not conditional: the flag must always describe the rung the
        // ladder is actually on. Arming means the record immediately past the
        // boundary, which is the first record the next resume delivers.
        // Disarming matters when the ladder moves past the skip rung without a
        // record ever arriving to consume it: the poison sat at the `EvtNext`
        // level, nothing was delivered, and the time rung is now the skip
        // mechanism. A stale one-shot there would eat a good event on top of
        // the window we already meant to discard.
        self.skip_next_record = self.rung == Rung::SkipRecord;

        self.rung
    }

    /// The stored position no longer resolves.
    ///
    /// This is NOT a poison event and must not walk the poison ladder: there is
    /// no offending record, so a single-record skip is meaningless and isolating
    /// the batch to one record accomplishes nothing. The correct response is the
    /// time rung, or future-events-only when there is no stored time to fall
    /// back to (D16: that rung is deliberate loss of the whole backlog and its
    /// caller emits ERROR).
    pub(super) const fn bookmark_dead(&mut self) -> Rung {
        self.stuck_count = 0;
        self.skip_next_record = false;
        self.rung = if self.last_event_time.is_some() {
            match self.rung {
                // Already escalating by time: take the next window rather than
                // restarting at the bottom.
                Rung::TimeAdvance(t) => match t.next() {
                    Some(next) => Rung::TimeAdvance(next),
                    None => Rung::FutureOnly,
                },
                Rung::FutureOnly => Rung::FutureOnly,
                _ => Rung::TimeAdvance(TimeRung::BoundaryTick),
            }
        } else {
            Rung::FutureOnly
        };
        self.rung
    }

    /// The lower bound for the generated XPath predicate, floored to the
    /// millisecond.
    ///
    /// Flooring makes the query **over-deliver**, never under-deliver, and the
    /// exact in-process boundary below trims the excess. That is what lets
    /// precision contribute zero duplicates on every path: the XPath is coarse
    /// on purpose and the fine cut happens where we have full resolution.
    pub(super) fn time_floor(&self) -> Option<DateTime<Utc>> {
        let base = self.last_event_time?;
        let advance = match self.rung {
            Rung::TimeAdvance(t) => t.advance_by(),
            _ => Duration::ZERO,
        };
        let advanced = base + chrono::Duration::from_std(advance).ok()?;
        // Floor to the millisecond.
        let nanos = advanced.timestamp_subsec_nanos();
        Some(advanced - chrono::Duration::nanoseconds(i64::from(nanos % 1_000_000)))
    }

    /// Consume the one-shot poison skip, if it is armed.
    ///
    /// This is the ONLY reason this type can withhold an event, and it is
    /// deliberately blind to the event: it takes no time and no record id,
    /// because nothing about an event may decide whether the event is sent
    /// (section 4.0 rules 8 and 31). It returns true exactly once per arming, for the first record
    /// delivered after the resume, which is the poison record we could not name.
    ///
    /// There is no time boundary here and there must never be one again. The
    /// version that compared `(TimeCreated, RecordId)` against the last sent
    /// event discarded real events in production: `EvtNext` delivers in RECORD
    /// order, the provider writes the time, and the two are not ordered
    /// together (35 inversions in 2820 events, worst step 984 ms). The gate
    /// suppressed at most one millisecond of duplicates on a rare fallback path
    /// and paid with silent, unrecoverable loss on the common one (D31).
    pub(super) const fn take_poison_skip(&mut self) -> bool {
        if self.skip_next_record {
            self.skip_next_record = false;
            return true;
        }
        false
    }
}

/// Adaptive batch size.
///
/// One oversized event must not permanently cap a channel's throughput, so the
/// reduction is temporary and recovers on its own.
#[derive(Debug, Clone)]
pub(super) struct BatchAdaptation {
    configured: usize,
    current: usize,
    clean_batches: u32,
}

impl BatchAdaptation {
    pub(super) const fn new(configured: usize) -> Self {
        Self {
            configured,
            current: configured,
            clean_batches: 0,
        }
    }

    pub(super) const fn current(&self) -> usize {
        self.current
    }

    /// Halve on `RPC_S_INVALID_BOUND` (1734), to a floor of 1. Returns the new
    /// size.
    pub(super) const fn halve(&mut self) -> usize {
        self.clean_batches = 0;
        self.current = if self.current > 1 {
            self.current / 2
        } else {
            1
        };
        self.current
    }

    /// Force to 1 for the isolate rung, so a failure is attributable to exactly
    /// one record.
    pub(super) const fn isolate(&mut self) {
        self.clean_batches = 0;
        self.current = 1;
    }

    /// A batch read cleanly. After enough of them, step back up.
    pub(super) fn observe_clean_batch(&mut self) {
        if self.current >= self.configured {
            self.clean_batches = 0;
            return;
        }
        self.clean_batches += 1;
        if self.clean_batches >= CLEAN_BATCHES_TO_RECOVER {
            self.clean_batches = 0;
            self.current = (self.current * 2).min(self.configured);
        }
    }

    pub(super) const fn restore(&mut self) {
        self.current = self.configured;
        self.clean_batches = 0;
    }
}

/// Observability edges for one channel, per episode.
///
/// The contract is: onset ERROR once, repeats DEBUG, hourly reminder DEBUG,
/// recovery WARN once. Anything noisier turns a channel outage into thousands
/// of shipped error rows, which is what the original incident did.
#[derive(Debug, Clone, Default)]
pub(super) struct EpisodeState {
    onset_logged: bool,
    last_reminder: Option<Instant>,
}

/// What the caller should log for this failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FailureEdge {
    /// First failure of an episode: ERROR, once.
    Onset,
    /// The hourly still-unavailable reminder: DEBUG.
    OngoingReminder,
    /// A repeat inside an episode: DEBUG.
    Repeat,
}

impl EpisodeState {
    /// Classify this failure. `now` is injected so tests do not sleep.
    pub(super) fn observe_failure(&mut self, now: Instant) -> FailureEdge {
        if !self.onset_logged {
            self.onset_logged = true;
            self.last_reminder = Some(now);
            return FailureEdge::Onset;
        }
        match self.last_reminder {
            Some(last) if now.duration_since(last) >= UNAVAILABLE_REMINDER_INTERVAL => {
                self.last_reminder = Some(now);
                FailureEdge::OngoingReminder
            }
            _ => FailureEdge::Repeat,
        }
    }

    /// Returns true exactly once per episode, when the channel comes back.
    pub(super) const fn observe_recovery(&mut self) -> bool {
        let was_failing = self.onset_logged;
        self.onset_logged = false;
        self.last_reminder = None;
        was_failing
    }
}

/// Record-id gap detection.
///
/// The only signal we have for retention-overwrite data loss, and it is
/// customer-actionable (raise the channel's max size). It is only meaningful on
/// a local channel with an unfiltered query and no deliberate skip in play,
/// hence the three suppressions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum GapVerdict {
    /// Contiguous, or first event: nothing to say.
    Continuous,
    /// A genuine unexplained gap of `missing` record ids.
    Gap { missing: u64 },
    /// A gap we caused ourselves; the rung WARN already reported it, so this
    /// must not read as a second unrelated alarm.
    DeliberateSkip { missing: u64 },
    /// Detection does not apply on this channel at all.
    Suppressed,
}

/// Reasons gap detection is off for a channel.
#[derive(Debug, Clone, Copy)]
pub(super) struct GapDetection {
    /// Operator-supplied filtering queries skip record ids by construction.
    pub(super) query_filters: bool,
    /// Forwarded channels interleave record ids from many originating machines
    /// and are not monotonic at all. Driven by the same per-event
    /// `<RenderingInfo>` signal as the render crash guard.
    pub(super) rendered_delivery: bool,
}

/// Evaluate one event's record id against the previous one.
pub(super) const fn evaluate_gap(
    previous: Option<u64>,
    current: u64,
    detection: GapDetection,
    deliberate_skip_in_play: bool,
) -> GapVerdict {
    if detection.query_filters || detection.rendered_delivery {
        return GapVerdict::Suppressed;
    }
    let Some(previous) = previous else {
        return GapVerdict::Continuous;
    };
    if current <= previous + 1 {
        return GapVerdict::Continuous;
    }
    let missing = current - previous - 1;
    if deliberate_skip_in_play {
        GapVerdict::DeliberateSkip { missing }
    } else {
        GapVerdict::Gap { missing }
    }
}

/// Stable per-channel jitter seed.
pub(super) fn jitter_seed(channel: &str) -> u64 {
    // FNV-1a. Small, dependency-free, and stable across runs so a channel's
    // backoff sequence is reproducible in a bug report.
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in channel.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100_0000_01b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(secs: i64, nanos: u32) -> DateTime<Utc> {
        DateTime::from_timestamp(secs, nanos).unwrap()
    }

    #[test]
    fn backoff_doubles_to_the_cap_and_never_exceeds_it() {
        let mut backoff = Backoff::new(jitter_seed("System"));
        let mut previous = Duration::ZERO;
        for _ in 0..12 {
            let delay = backoff.next_delay();
            assert!(delay <= BACKOFF_CAP, "delay {delay:?} exceeded the cap");
            // Jitter only ever subtracts, so the floor is 75% of the raw value.
            assert!(delay >= BACKOFF_BASE.mul_f64(0.75) || previous == Duration::ZERO);
            previous = delay;
        }
    }

    #[test]
    fn jitter_decorrelates_channels() {
        let mut a = Backoff::new(jitter_seed("System"));
        let mut b = Backoff::new(jitter_seed("Application"));
        // An EventLog restart invalidates every channel at once; identical
        // delays are exactly the stampede this exists to prevent.
        let a_delays: Vec<_> = (0..5).map(|_| a.next_delay()).collect();
        let b_delays: Vec<_> = (0..5).map(|_| b.next_delay()).collect();
        assert_ne!(a_delays, b_delays);
    }

    #[test]
    fn backoff_resets_after_recovery() {
        let mut backoff = Backoff::new(jitter_seed("System"));
        for _ in 0..6 {
            let _ = backoff.next_delay();
        }
        assert!(backoff.attempt() > 0);
        backoff.reset();
        assert_eq!(backoff.attempt(), 0);
        assert!(backoff.next_delay() <= BACKOFF_BASE);
    }

    #[test]
    fn a_moving_position_is_not_stuck() {
        let mut resume = ResumeState::new(true);
        for i in 0..10u64 {
            resume.observe_event(ts(1_700_000_000 + i as i64, 0), i);
            assert!(!resume.note_rebuild(), "moving position must not trigger");
        }
    }

    #[test]
    fn a_fixed_position_trips_the_stuck_detector() {
        let mut resume = ResumeState::new(true);
        resume.observe_event(ts(1_700_000_000, 0), 42);
        assert!(!resume.note_rebuild());
        assert!(!resume.note_rebuild());
        assert!(resume.note_rebuild());
    }

    /// Precision before convenience: isolate, then skip exactly one record, and
    /// only then start discarding time windows.
    #[test]
    fn ladder_isolates_and_skips_before_touching_time() {
        let mut resume = ResumeState::new(true);
        resume.observe_event(ts(1_700_000_000, 0), 42);

        assert_eq!(resume.advance_rung(), Rung::IsolateOne);
        assert_eq!(resume.advance_rung(), Rung::SkipRecord);
        assert_eq!(
            resume.advance_rung(),
            Rung::TimeAdvance(TimeRung::BoundaryTick)
        );
        assert_eq!(
            resume.advance_rung(),
            Rung::TimeAdvance(TimeRung::OneSecond)
        );
    }

    /// On a channel where record ids are meaningless, the single-record skip is
    /// not expressible, so the ladder falls through to time windows.
    #[test]
    fn unusable_record_identity_falls_through_to_time_rungs() {
        let mut resume = ResumeState::new(false);
        resume.observe_event(ts(1_700_000_000, 0), 42);
        assert_eq!(resume.advance_rung(), Rung::IsolateOne);
        assert_eq!(
            resume.advance_rung(),
            Rung::TimeAdvance(TimeRung::BoundaryTick)
        );
        // No single-record skip was armed, so the next record delivered is
        // still sent: the time rung is what does the discarding here.
        assert!(!resume.take_poison_skip());
    }

    #[test]
    fn ladder_terminates_at_future_only_and_stays_there() {
        let mut resume = ResumeState::new(false);
        resume.observe_event(ts(1_700_000_000, 0), 42);
        for _ in 0..20 {
            resume.advance_rung();
        }
        assert_eq!(resume.rung, Rung::FutureOnly);
        assert_eq!(resume.advance_rung(), Rung::FutureOnly);
    }

    #[test]
    fn a_clean_read_resets_the_ladder() {
        let mut resume = ResumeState::new(true);
        resume.observe_event(ts(1_700_000_000, 0), 42);
        resume.advance_rung();
        resume.advance_rung();
        resume.observe_clean_read();
        assert_eq!(resume.rung, Rung::Bookmark);
        // A clean read disarms the pending skip: the next record delivered is
        // a normal event again, not something to discard.
        assert!(!resume.take_poison_skip());
    }

    /// The XPath floors to the millisecond so it over-delivers; the exact
    /// in-process boundary trims the excess. Together they contribute zero
    /// duplicates.
    #[test]
    fn time_floor_floors_to_the_millisecond() {
        let mut resume = ResumeState::new(true);
        resume.observe_event(ts(1_700_000_000, 123_456_700), 1);
        let floor = resume.time_floor().unwrap();
        assert_eq!(floor.timestamp_subsec_nanos(), 123_000_000);
    }

    /// Rules 28 to 31: the stored time and the stored record number are inputs
    /// to the fallback query and to gap reporting, and they decide nothing
    /// about delivery.
    ///
    /// This replaces an assertion that the stored pair TRIMMED events at an
    /// exact `(TimeCreated, RecordId)` boundary. That trim was the production
    /// defect: it discarded 7 of 38 real records on the captured field shape.
    /// The stored values themselves are kept, so the test is now that they are
    /// held and are inert.
    #[test]
    fn the_stored_position_is_recorded_and_never_withholds_an_event() {
        let mut resume = ResumeState::new(true);
        let last = ts(1_700_000_000, 123_456_700);
        resume.observe_event(last, 10);

        assert_eq!(resume.last_event_time, Some(last));
        assert_eq!(resume.last_record_id, Some(10));

        // An event inside the same millisecond, an event at the stored
        // position, and an event a full second behind it. None of them is
        // withheld, because nothing but the poison one-shot can withhold.
        assert!(!resume.take_poison_skip());
        resume.observe_event(ts(1_700_000_000, 123_000_000), 9);
        assert!(!resume.take_poison_skip());
        resume.observe_event(ts(1_699_999_999, 0), 11);
        assert!(!resume.take_poison_skip());

        // And the stored values track the last event SENT, not the maximum
        // time seen: rules 19 and 29 build the floor time from the last event the
        // source sent, so a lower time there over-delivers, which is the safe
        // direction.
        assert_eq!(resume.last_event_time, Some(ts(1_699_999_999, 0)));
        assert_eq!(resume.last_record_id, Some(11));
    }

    /// The behavior D17 buys: at the skip rung the poison event is dropped and
    /// the very next good event is delivered, so escaping one bad record costs
    /// one record and never a time window.
    ///
    /// The poison record's id is unknowable: `EvtNext` failed, so no handle came
    /// back. What is knowable is its position, immediately past the boundary.
    #[test]
    fn poison_escape_drops_the_poison_event_and_delivers_the_next_one() {
        let mut resume = ResumeState::new(true);
        // Last good event: record 42.
        resume.observe_event(ts(1_700_000_000, 0), 42);

        assert_eq!(resume.advance_rung(), Rung::IsolateOne);
        assert_eq!(resume.advance_rung(), Rung::SkipRecord);

        // Record 43 is the poison: the first record the resume delivers.
        assert!(
            resume.take_poison_skip(),
            "the poison event must not be delivered"
        );
        // And the escape costs exactly that one record.
        assert!(
            !resume.take_poison_skip(),
            "the next good event must be delivered"
        );
    }

    /// The skip is a one-shot, not a mode. A second escape has to be a second
    /// stuck detection, otherwise a channel would bleed events silently.
    #[test]
    fn the_poison_skip_is_consumed_once() {
        let mut resume = ResumeState::new(true);
        resume.observe_event(ts(1_700_000_000, 0), 42);
        resume.advance_rung();
        resume.advance_rung();

        assert!(resume.take_poison_skip());
        for id in 44..50u64 {
            assert!(
                !resume.take_poison_skip(),
                "record {id} must be delivered; the skip is one-shot"
            );
        }
    }

    /// The one-shot is armed by landing on the skip rung, so it must be
    /// disarmed by leaving it.
    ///
    /// This is the `EvtNext`-level poison: the failure is upstream of record
    /// delivery, so no record ever arrives to consume the arm. The ladder keeps
    /// escalating and reaches the time rung with the skip still pending. If the
    /// arm survived, the first good record past the new time floor would be
    /// silently dropped, one event lost on top of the window the time rung
    /// already discards, in the one path where the time advance IS the skip.
    #[test]
    fn advancing_past_the_skip_rung_disarms_the_one_shot() {
        let mut resume = ResumeState::new(true);
        resume.observe_event(ts(1_700_000_000, 0), 42);

        assert_eq!(resume.advance_rung(), Rung::IsolateOne);
        assert_eq!(resume.advance_rung(), Rung::SkipRecord);
        assert!(resume.skip_next_record, "the skip rung arms the one-shot");

        // Nothing is delivered: the poison is at the `EvtNext` level, so the
        // arm is never consumed and the channel goes stuck again.
        assert_eq!(
            resume.advance_rung(),
            Rung::TimeAdvance(TimeRung::BoundaryTick)
        );
        assert!(
            !resume.skip_next_record,
            "leaving the skip rung must disarm the unconsumed one-shot"
        );

        // The time floor advanced and records flow again. The first one past
        // the new floor is a good event and must be sent.
        assert!(
            !resume.take_poison_skip(),
            "the first record past the new time floor must be sent"
        );
        assert!(!resume.take_poison_skip());
    }

    /// A dead bookmark is not a poison event. There is no offending record, so a
    /// single-record skip is meaningless and isolating the batch accomplishes
    /// nothing: the correct response is the time rung.
    #[test]
    fn dead_bookmark_resumes_by_time_and_consumes_no_skip() {
        let mut resume = ResumeState::new(true);
        resume.observe_event(ts(1_700_000_000, 0), 42);

        let rung = resume.bookmark_dead();
        assert_eq!(rung, Rung::TimeAdvance(TimeRung::BoundaryTick));
        assert_eq!(rung.resumed_from(), ResumedFrom::TimeFallback);
        assert!(
            !resume.take_poison_skip(),
            "a dead bookmark must not silently eat a record on top of the resume"
        );
    }

    /// Nothing to fall back to: the stranded-bookmark rung. Deliberate loss of
    /// the whole backlog, which is why its caller emits ERROR (D16).
    #[test]
    fn dead_bookmark_without_a_stored_time_goes_future_only() {
        let mut resume = ResumeState::new(true);
        assert_eq!(resume.bookmark_dead(), Rung::FutureOnly);
        assert_eq!(resume.rung.resumed_from(), ResumedFrom::FutureOnly);
    }

    /// Repeated bookmark death escalates the window rather than sticking at the
    /// boundary tick forever.
    #[test]
    fn repeated_bookmark_death_widens_the_time_window() {
        let mut resume = ResumeState::new(true);
        resume.observe_event(ts(1_700_000_000, 0), 42);
        assert_eq!(
            resume.bookmark_dead(),
            Rung::TimeAdvance(TimeRung::BoundaryTick)
        );
        assert_eq!(
            resume.bookmark_dead(),
            Rung::TimeAdvance(TimeRung::OneSecond)
        );
        for _ in 0..10 {
            resume.bookmark_dead();
        }
        assert_eq!(resume.rung, Rung::FutureOnly);
    }

    #[test]
    fn batch_halves_to_a_floor_of_one_and_recovers() {
        let mut batch = BatchAdaptation::new(100);
        assert_eq!(batch.halve(), 50);
        assert_eq!(batch.halve(), 25);
        for _ in 0..5 {
            batch.halve();
        }
        assert_eq!(batch.current(), 1);

        for _ in 0..CLEAN_BATCHES_TO_RECOVER {
            batch.observe_clean_batch();
        }
        assert_eq!(batch.current(), 2);
    }

    #[test]
    fn batch_recovery_stops_at_the_configured_size() {
        let mut batch = BatchAdaptation::new(4);
        batch.isolate();
        assert_eq!(batch.current(), 1);
        for _ in 0..(CLEAN_BATCHES_TO_RECOVER * 10) {
            batch.observe_clean_batch();
        }
        assert_eq!(batch.current(), 4);
    }

    #[test]
    fn episode_edges_are_onset_once_then_quiet() {
        let mut episode = EpisodeState::default();
        let start = Instant::now();
        assert_eq!(episode.observe_failure(start), FailureEdge::Onset);
        for i in 1..50 {
            assert_eq!(
                episode.observe_failure(start + Duration::from_secs(i)),
                FailureEdge::Repeat
            );
        }
        assert_eq!(
            episode.observe_failure(start + UNAVAILABLE_REMINDER_INTERVAL),
            FailureEdge::OngoingReminder
        );
        assert!(episode.observe_recovery());
        // Recovery is once per episode, not once per healthy batch.
        assert!(!episode.observe_recovery());
    }

    #[test]
    fn gap_detection_reports_missing_count() {
        let detection = GapDetection {
            query_filters: false,
            rendered_delivery: false,
        };
        assert_eq!(
            evaluate_gap(Some(10), 11, detection, false),
            GapVerdict::Continuous
        );
        assert_eq!(
            evaluate_gap(Some(10), 20, detection, false),
            GapVerdict::Gap { missing: 9 }
        );
    }

    /// The three suppressions. A gap we caused, a filtering query, and a
    /// forwarded channel must never raise an unexplained-gap alarm.
    #[test]
    fn gap_detection_has_three_suppressions() {
        let plain = GapDetection {
            query_filters: false,
            rendered_delivery: false,
        };
        assert_eq!(
            evaluate_gap(Some(10), 20, plain, true),
            GapVerdict::DeliberateSkip { missing: 9 }
        );
        assert_eq!(
            evaluate_gap(
                Some(10),
                20,
                GapDetection {
                    query_filters: true,
                    rendered_delivery: false
                },
                false
            ),
            GapVerdict::Suppressed
        );
        assert_eq!(
            evaluate_gap(
                Some(10),
                20,
                GapDetection {
                    query_filters: false,
                    rendered_delivery: true
                },
                false
            ),
            GapVerdict::Suppressed
        );
    }

    #[test]
    fn deliberate_skip_flag_tracks_the_ladder() {
        assert!(!Rung::Bookmark.is_deliberate_skip());
        assert!(!Rung::IsolateOne.is_deliberate_skip());
        assert!(Rung::SkipRecord.is_deliberate_skip());
        assert!(Rung::TimeAdvance(TimeRung::OneSecond).is_deliberate_skip());
        assert!(Rung::FutureOnly.is_deliberate_skip());
    }

    /// A time rung resumes AFTER the last good event, never before it.
    ///
    /// The only existing `time_floor` test sits on the `Bookmark` rung, where
    /// the advance is `Duration::ZERO` and the direction of the arithmetic is
    /// unobservable. Flipping the sign on a busy channel is not a small error:
    /// it re-delivers everything back to the start of the window, on the exact
    /// rung that only ever fires because the bookmark already failed.
    #[test]
    fn a_time_rung_moves_the_floor_forward_not_backward() {
        let base = ts(1_700_000_000, 0);

        for (rung, expected_advance) in [
            (TimeRung::BoundaryTick, Duration::from_nanos(100)),
            (TimeRung::OneSecond, Duration::from_secs(1)),
            (TimeRung::TenSeconds, Duration::from_secs(10)),
            (TimeRung::OneMinute, Duration::from_secs(60)),
            (TimeRung::FiveMinutes, Duration::from_secs(300)),
            (TimeRung::ThirtyMinutes, Duration::from_secs(1800)),
        ] {
            let mut resume = ResumeState::new(true);
            resume.observe_event(base, 1);
            resume.rung = Rung::TimeAdvance(rung);

            let floor = resume.time_floor().unwrap();
            assert!(
                floor >= base,
                "{rung:?} resumed BEFORE the last good event ({floor} < {base}); \
                 that is mass re-delivery, not an escape"
            );
            // Floored to the millisecond, so the boundary tick lands exactly on
            // the base and every other rung lands its full window ahead.
            let expected = base + chrono::Duration::from_std(expected_advance).unwrap()
                - chrono::Duration::nanoseconds(i64::from(
                    expected_advance.subsec_nanos() % 1_000_000,
                ));
            assert_eq!(floor, expected, "wrong window width for {rung:?}");
        }
    }

    /// D23: marking record identity unusable must actually change the ladder's
    /// choice. The existing coverage constructs the unusable state directly via
    /// `ResumeState::new(false)`, so the setter itself could do nothing and the
    /// whole forwarded-channel mechanism would silently be a no-op.
    #[test]
    fn marking_record_identity_unusable_takes_the_skip_rung_off_the_table() {
        let mut resume = ResumeState::new(true);
        resume.observe_event(ts(1_700_000_000, 0), 7);
        resume.mark_record_identity_unusable();

        assert_eq!(resume.advance_rung(), Rung::IsolateOne);
        assert_eq!(
            resume.advance_rung(),
            Rung::TimeAdvance(TimeRung::BoundaryTick),
            "forwarded record ids interleave from many machines, so a \
             single-record skip is not expressible and the ladder must go \
             straight to time windows"
        );
        assert!(
            !resume.skip_next_record,
            "no record skip may be armed on a channel whose record ids mean nothing"
        );
    }

    /// `restore` is the OTHER recovery path, and it is the one the poison escape
    /// uses. Without it a channel that escaped a poison record stays at a batch
    /// size of one forever, which is a permanent throughput cap applied for a
    /// problem that is already over.
    #[test]
    fn restore_returns_to_the_configured_size_in_one_step() {
        let mut batch = BatchAdaptation::new(100);
        batch.isolate();
        assert_eq!(batch.current(), 1);

        batch.restore();
        assert_eq!(
            batch.current(),
            100,
            "an escape's batch reduction is not a size problem, so a clean read \
             ends it outright rather than gradually"
        );
    }

    /// The `resumed_from` and `rung` log fields are the structured values the
    /// source pack keys on (4.5). A wrong or empty one costs attribution on
    /// exactly the messages an operator reads during an outage.
    #[test]
    fn log_field_labels_are_the_exact_strings_the_pack_keys_on() {
        assert_eq!(ResumedFrom::Bookmark.as_str(), "bookmark");
        assert_eq!(ResumedFrom::TimeFallback.as_str(), "time_fallback");
        assert_eq!(ResumedFrom::FutureOnly.as_str(), "future_only");

        assert_eq!(TimeRung::BoundaryTick.as_str(), "boundary_tick");
        assert_eq!(TimeRung::OneSecond.as_str(), "+1s");
        assert_eq!(TimeRung::TenSeconds.as_str(), "+10s");
        assert_eq!(TimeRung::OneMinute.as_str(), "+60s");
        assert_eq!(TimeRung::FiveMinutes.as_str(), "+5m");
        assert_eq!(TimeRung::ThirtyMinutes.as_str(), "+30m");

        assert_eq!(Rung::Bookmark.as_str(), "bookmark");
        assert_eq!(Rung::IsolateOne.as_str(), "isolate_one");
        assert_eq!(Rung::SkipRecord.as_str(), "skip_record");
        assert_eq!(Rung::FutureOnly.as_str(), "future_only");
        assert_eq!(Rung::TimeAdvance(TimeRung::OneMinute).as_str(), "+60s");
    }

    /// D27's jitter has to keep varying. A PRNG that degenerates to a fixed
    /// point still produces a legal-looking delay, so the channel-decorrelation
    /// test above passes while every channel is once again perfectly in step
    /// with itself.
    #[test]
    fn jitter_keeps_varying_at_a_fixed_attempt() {
        let mut backoff = Backoff::new(jitter_seed("Application"));
        let mut delays = Vec::new();
        for _ in 0..8 {
            delays.push(backoff.next_delay());
            backoff.reset();
        }

        assert!(
            delays.windows(2).any(|pair| pair[0] != pair[1]),
            "every delay at attempt 0 was identical ({delays:?}); the jitter \
             state has collapsed to a fixed point"
        );
    }

    /// Jitter only ever SUBTRACTS, and never more than a quarter. A jitter term
    /// that can exceed the delay turns the backoff into no backoff at all,
    /// which is the retry storm the whole mechanism exists to prevent.
    #[test]
    fn jitter_never_takes_more_than_a_quarter_of_the_delay() {
        for channel in ["Application", "System", "Setup", "Security"] {
            let mut backoff = Backoff::new(jitter_seed(channel));
            for attempt in 0..10u32 {
                let raw = BACKOFF_BASE
                    .saturating_mul(1u32 << attempt.min(6))
                    .min(BACKOFF_CAP);
                let delay = backoff.next_delay();
                assert!(
                    delay >= raw.mul_f64(0.75),
                    "{channel} attempt {attempt}: delay {delay:?} fell below 75% \
                     of {raw:?}; jitter must reduce by at most a quarter"
                );
                assert!(
                    delay <= raw,
                    "{channel} attempt {attempt}: jitter added time"
                );
            }
        }
    }
}
