//! Per-channel status file: the facts another process needs to decide whether
//! this collector is keeping up with each channel.
//!
//! The source rewrites one JSON object every interval describing what it knows
//! per channel: whether a subscription exists, where it is positioned, how far
//! the channel has run ahead of that position, and which resume-ladder steps
//! punched a hole in the data.
//!
//! Nothing here is a health verdict. The reader knows things this process
//! cannot: what an operator configured, what happened across restarts and
//! reinstalls, and what every other source on the host is doing. A verdict
//! computed here would be a second and worse copy of the one made there, split
//! across two binaries that ship on different schedules.
//!
//! The file is written by default, next to the checkpoint file in the source's
//! own data directory, because that is where the reader looks for it.
//! `status_path` moves it somewhere else and is the rare case.

use std::{
    collections::{BTreeMap, VecDeque},
    fs,
    io::Write,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use vector_lib::internal_event::error_type;

use super::recovery::{Rung, TimeRung};

/// Wire version of the file. Present so a future shape change is detectable
/// rather than silently misparsed by a reader built against this one.
pub(super) const STATUS_SCHEMA_VERSION: u32 = 1;

/// Name of the file inside the source's data directory.
///
/// The reader finds it by scanning the data directory, exactly as it already
/// finds the checkpoint file, so this name is part of the interface and cannot
/// be changed on its own.
pub(super) const STATUS_FILE_NAME: &str = "windows_event_log_status.json";

/// Gaps retained per channel, oldest evicted first.
///
/// A channel that flaps walks the ladder repeatedly, so the list has to be
/// bounded or a single sick channel grows the file without limit. One full walk
/// of the ladder produces at most seven gap entries (the record skip, five
/// widening time windows, and the terminal rung), so sixteen holds the current
/// episode plus the one before it, which is as far back as a reader diagnosing
/// a live problem looks. At roughly 150 bytes of JSON per entry that caps the
/// gap text at about 2 KiB per channel.
pub(super) const MAX_RETAINED_GAPS: usize = 16;

/// Format used for every timestamp in the file.
fn rfc3339(time: DateTime<Utc>) -> String {
    time.to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// One hole in a channel's data, recorded when the resume ladder created it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct GapRecord {
    /// Time of the last event delivered before the hole. `null` when the
    /// channel had delivered nothing at all.
    pub(super) from: Option<String>,
    /// Time the source resumed at, which is the upper bound of the hole.
    /// `null` when the hole is bounded by a record rather than by a time.
    pub(super) to: Option<String>,
    /// When the source created the hole.
    pub(super) at: String,
    /// The ladder step responsible, using the same slugs as the `rung` field.
    pub(super) cause: String,
    /// True only when the count of lost records is known exactly.
    pub(super) exact: bool,
    /// Records lost, when that number is knowable. A time-bounded hole cannot
    /// count what it never read, so it reports `null` rather than a guess.
    ///
    /// Named to match the field on the log event that reports the same skip.
    /// A consumer correlates the two, so one skip must not have two spellings.
    pub(super) missing_records: Option<u64>,
}

/// Everything the file says about one channel. All facts, no judgments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct ChannelStatus {
    /// A live subscription handle exists for this channel.
    pub(super) subscribed: bool,
    /// Slug of the reason this channel is skipped for the current subscription
    /// generation, or `null` when it is not skipped.
    pub(super) skipped_reason: Option<String>,
    /// Current resume-ladder step.
    pub(super) rung: String,
    /// `TimeCreated` of the most recent event delivered from this channel.
    pub(super) last_event_at: Option<String>,
    /// When this channel last returned zero events to a read, meaning the
    /// subscription was at the head of the channel at that moment. `null` until
    /// it has happened since the process started.
    ///
    /// Exact, unlike [`Self::newest_record_id`], and it is the fact a reader
    /// should decide on: a read that comes back empty IS caught up, with no
    /// arithmetic and no approximation. It has to be stamped here because the
    /// source reads far more often than anything polling this file, so a busy
    /// channel can reach the head many times between two samples and be caught
    /// mid-batch by both of them.
    pub(super) last_drained_at: Option<String>,
    /// `EventRecordID` of the most recent event delivered from this channel.
    pub(super) last_record_id: Option<u64>,
    /// Estimated newest record id present in the channel. Reported for a human
    /// reading the file; it decides nothing, because it undershoots on a
    /// channel whose record ids have holes and so is biased toward calling a
    /// behind channel caught up. See [`newest_record_estimate`] for what makes
    /// it an estimate and when it is withheld entirely.
    pub(super) newest_record_id: Option<u64>,
    /// Whether the collector's base query selects a subset of events.
    ///
    /// Reported so a reader can withhold a lag figure it cannot compute:
    /// [`Self::newest_record_id`] counts every record in the channel while
    /// [`Self::last_record_id`] only advances on records the filter let
    /// through. Health is untouched: a filtered subscription that reads
    /// nothing is at the head of what it asked for.
    ///
    /// Additive: a reader that predates the field treats an absent key as
    /// `false`, which is what an unfiltered collector meant.
    #[serde(default)]
    pub(super) query_filters: bool,
    /// Whether the stored bookmark marks a real position.
    pub(super) bookmark_positioned: bool,
    /// Consecutive failed rebuild attempts for this channel.
    pub(super) retry_attempt: u32,
    /// Times a name was absent from the publisher table and the per-event
    /// fallback ran. Internal diagnostics; not a health input.
    ///
    /// Additive: absent means zero, which is what a collector that never
    /// counted misses meant.
    #[serde(default)]
    pub(super) name_table_misses: u64,
    /// Holes this source knows it created, newest last.
    pub(super) gaps: Vec<GapRecord>,
}

/// The whole file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct StatusSnapshot {
    pub(super) schema: u32,
    /// When this file was written. A reader treats an old value as "no
    /// information", so it must be the write time and not the collection time.
    pub(super) as_of: String,
    pub(super) channels: BTreeMap<String, ChannelStatus>,
}

impl StatusSnapshot {
    pub(super) fn new(as_of: DateTime<Utc>) -> Self {
        Self {
            schema: STATUS_SCHEMA_VERSION,
            as_of: rfc3339(as_of),
            channels: BTreeMap::new(),
        }
    }
}

/// Record counts read straight from the channel, not from anything the source
/// has been keeping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ChannelRecordStats {
    pub(super) count: u64,
    pub(super) oldest: u64,
}

/// Estimate the newest record id in a channel from its oldest record id and its
/// record count.
///
/// The estimate is approximate by construction: record ids are monotonic per
/// channel but are not guaranteed contiguous, so a channel that lost records to
/// anything other than retention reports a newest id above this value.
///
/// It is withheld rather than corrected in two cases. An empty channel has no
/// newest record. And an estimate that lands below a record this source has
/// already delivered is not credible, so it is dropped: clamping it up to the
/// delivered id would report the channel as caught up, which is the single
/// wrong answer a reader cannot recover from. Absent is honest; zero lag is not.
pub(super) const fn newest_record_estimate(
    stats: Option<ChannelRecordStats>,
    last_record_id: Option<u64>,
) -> Option<u64> {
    let Some(stats) = stats else {
        return None;
    };
    if stats.count == 0 {
        return None;
    }
    let newest = match stats.oldest.checked_add(stats.count) {
        Some(sum) => sum - 1,
        None => return None,
    };
    if let Some(delivered) = last_record_id
        && newest < delivered
    {
        return None;
    }
    Some(newest)
}

/// Whether landing on this ladder step loses data, and whether the loss is
/// countable.
///
/// The first time step is the one exception among the escalations: it re-reads
/// the last event's own millisecond, so it can deliver a duplicate but can
/// never skip a record. It must never produce a gap entry, because a reported
/// hole that does not exist is as misleading as an unreported one.
const fn gap_shape(rung: Rung) -> Option<(bool, Option<u64>)> {
    match rung {
        // No loss: the bookmark resume is exact and isolating the batch only
        // changes how many records are read at a time.
        Rung::Bookmark | Rung::IsolateOne => None,
        Rung::TimeAdvance(TimeRung::BoundaryTick) => None,
        // Exactly one record, by definition of the step.
        Rung::SkipRecord => Some((true, Some(1))),
        // Bounded by two times. Nothing counted the records inside the window,
        // and nothing can: they were never read.
        Rung::TimeAdvance(_) | Rung::FutureOnly => Some((false, None)),
    }
}

/// Build the gap record for a ladder step, or `None` when the step loses
/// nothing.
///
/// `from` is the last event delivered before the step and `resume_at` is where
/// the source will start reading again, which together bound the hole. A record
/// skip passes `None` for `resume_at`: its hole is bounded by a record rather
/// than by a time, and the exact count says all there is to say.
pub(super) fn gap_for_rung(
    rung: Rung,
    from: Option<DateTime<Utc>>,
    resume_at: Option<DateTime<Utc>>,
    at: DateTime<Utc>,
) -> Option<GapRecord> {
    let (exact, missing_records) = gap_shape(rung)?;
    Some(GapRecord {
        from: from.map(rfc3339),
        to: resume_at.map(rfc3339),
        at: rfc3339(at),
        cause: rung.as_str().to_string(),
        exact,
        missing_records,
    })
}

/// Append a gap to a channel's bounded history.
pub(super) fn push_gap(gaps: &mut VecDeque<GapRecord>, gap: GapRecord) {
    while gaps.len() >= MAX_RETAINED_GAPS {
        gaps.pop_front();
    }
    gaps.push_back(gap);
}

/// Write the snapshot to a temporary file in the target directory and rename it
/// over the target.
///
/// The reader polls this file on its own cadence and has no way to lock it, so
/// a partially written file would be read as a real one and produce a wrong
/// verdict. A rename within one directory is atomic for the reader: it observes
/// either the previous file or the complete new one.
pub(super) fn write_atomic(path: &Path, snapshot: &StatusSnapshot) -> std::io::Result<()> {
    let directory = path.parent().unwrap_or_else(|| Path::new("."));
    if !directory.as_os_str().is_empty() {
        fs::create_dir_all(directory)?;
    }

    let file_name = path
        .file_name()
        .map_or_else(|| "status.json".to_string(), |n| n.to_string_lossy().into());
    // The process id keeps two collectors that were pointed at one path (an
    // upgrade running both binaries for a moment, say) from truncating each
    // other's half-written temp file.
    let temp = directory.join(format!("{file_name}.{}.tmp", std::process::id()));

    let encoded = serde_json::to_vec(snapshot).map_err(std::io::Error::other)?;
    {
        let mut file = fs::File::create(&temp)?;
        file.write_all(&encoded)?;
        file.sync_all()?;
    }

    match fs::rename(&temp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            // Leaving the temp behind would accumulate one file per failed
            // interval.
            _ = fs::remove_file(&temp);
            Err(e)
        }
    }
}

/// Cadence and failure state for the status file.
#[derive(Debug)]
pub(super) struct StatusWriter {
    path: PathBuf,
    interval: Duration,
    next_due: Instant,
    /// Whether the last write failed, so a directory that stays unwritable
    /// costs one warning rather than one per interval.
    failing: bool,
}

impl StatusWriter {
    pub(super) fn new(path: PathBuf, interval_secs: u64, now: Instant) -> Self {
        Self {
            path,
            interval: Duration::from_secs(interval_secs.max(1)),
            // Due immediately: a reader that starts with the collector should
            // not wait a full interval to learn anything.
            next_due: now,
            failing: false,
        }
    }

    /// Where the file goes: the configured override, or the source's own data
    /// directory, which is where the reader looks.
    pub(super) fn resolve_path(configured: Option<&PathBuf>, data_dir: &Path) -> PathBuf {
        configured.map_or_else(|| data_dir.join(STATUS_FILE_NAME), Clone::clone)
    }

    pub(super) fn is_due(&self, now: Instant) -> bool {
        now >= self.next_due
    }

    /// Persist a snapshot and arm the next interval.
    ///
    /// The interval is armed whatever the outcome, so a failing write cannot
    /// turn into a hot loop.
    pub(super) fn write(&mut self, snapshot: &StatusSnapshot, now: Instant) {
        self.next_due = now + self.interval;

        match write_atomic(&self.path, snapshot) {
            Ok(()) => {
                if self.failing {
                    self.failing = false;
                    debug!(
                        message = "Windows Event Log status file is writable again.",
                        path = %self.path.display(),
                    );
                }
            }
            Err(e) => {
                // Warned once on the way into the failure and then held at
                // DEBUG: this runs on every host on a steady timer, and an
                // unwritable directory does not become news again each interval.
                if self.failing {
                    debug!(
                        message = "Windows Event Log status file write failed again.",
                        path = %self.path.display(),
                        error = %e,
                    );
                } else {
                    self.failing = true;
                    warn!(
                        message = format!(
                            "Failed to write the Windows Event Log status file (path={}). \
                             Per-source liveness reporting is unavailable until it succeeds.",
                            self.path.display()
                        ),
                        // Our slug goes in `error_code`; `error_type` is
                        // Vector's fixed taxonomy, and what failed here is a
                        // write.
                        error_code = "status_write_failed",
                        error_type = error_type::WRITER_FAILED,
                        path = %self.path.display(),
                        error = %e,
                        internal_log_rate_limit = false,
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(secs, 0).unwrap()
    }

    fn stats(count: u64, oldest: u64) -> Option<ChannelRecordStats> {
        Some(ChannelRecordStats { count, oldest })
    }

    /// The estimate itself: a channel holding `count` records starting at
    /// `oldest` has its newest record at `oldest + count - 1`.
    #[test]
    fn newest_record_is_oldest_plus_count_minus_one() {
        assert_eq!(newest_record_estimate(stats(100, 1), None), Some(100));
        assert_eq!(newest_record_estimate(stats(50, 951), None), Some(1_000));
        // A channel holding exactly one record: newest is that record.
        assert_eq!(newest_record_estimate(stats(1, 42), None), Some(42));
    }

    /// The one wrong answer that matters. An estimate below a record already
    /// delivered would compute as zero or negative lag, and a reader treats
    /// zero lag as "caught up". Absent is the honest answer.
    #[test]
    fn an_estimate_behind_the_delivered_record_is_withheld_not_clamped() {
        // The channel was cleared and refilled, so its ids restarted low while
        // this source still holds a high delivered id.
        assert_eq!(newest_record_estimate(stats(10, 1), Some(9_000)), None);
        // Exactly equal is caught up, and that is a real answer.
        assert_eq!(newest_record_estimate(stats(10, 1), Some(10)), Some(10));
    }

    #[test]
    fn an_empty_or_unavailable_channel_has_no_newest_record() {
        assert_eq!(newest_record_estimate(stats(0, 1), Some(5)), None);
        assert_eq!(newest_record_estimate(None, Some(5)), None);
        // Arithmetic that would wrap is unavailable, never a wrapped number.
        assert_eq!(newest_record_estimate(stats(u64::MAX, 5), None), None);
    }

    /// The lossless steps must produce nothing. A reported hole that does not
    /// exist sends a reader chasing data loss that never happened.
    #[test]
    fn the_lossless_rungs_record_no_gap() {
        let from = Some(ts(1_700_000_000));
        let at = ts(1_700_000_010);
        for rung in [
            Rung::Bookmark,
            Rung::IsolateOne,
            Rung::TimeAdvance(TimeRung::BoundaryTick),
        ] {
            assert_eq!(
                gap_for_rung(rung, from, Some(at), at),
                None,
                "{rung:?} loses nothing and must not record a gap"
            );
        }
    }

    /// The boundary tick specifically. It steps the floor by zero and re-reads
    /// the last event's own millisecond, so it can duplicate and can never
    /// skip. Stated on its own because it is the step most easily mistaken for
    /// a lossy one: it is an escalation, and every other escalation loses data.
    #[test]
    fn the_boundary_tick_never_produces_a_gap() {
        let at = ts(1_700_000_010);
        assert_eq!(
            gap_for_rung(
                Rung::TimeAdvance(TimeRung::BoundaryTick),
                Some(ts(1_700_000_000)),
                // Even resuming at a floor later than the last event, which is
                // what a bug in the floor arithmetic would look like, the step
                // itself is defined as lossless and reports nothing.
                Some(ts(1_700_000_005)),
                at
            ),
            None
        );
    }

    /// A record skip loses exactly one record and knows it. The count is the
    /// entire value of the entry, so it must be exact and must be one.
    #[test]
    fn a_record_skip_is_an_exact_single_record_gap() {
        let from = ts(1_700_000_000);
        let at = ts(1_700_000_010);
        let gap = gap_for_rung(Rung::SkipRecord, Some(from), None, at).unwrap();

        assert_eq!(gap.cause, "skip_record");
        assert!(gap.exact);
        assert_eq!(gap.missing_records, Some(1));
        assert_eq!(gap.from.as_deref(), Some("2023-11-14T22:13:20.000Z"));
        // Bounded by a record, not by a time.
        assert_eq!(gap.to, None);
    }

    /// The time steps and the terminal step bound the hole by two times and
    /// cannot count it. Claiming an exact count there would be a fabrication.
    #[test]
    fn the_time_rungs_and_future_only_are_inexact_and_uncounted() {
        let from = ts(1_700_000_000);
        let resume = ts(1_700_000_030);
        let at = ts(1_700_000_010);

        for (rung, cause) in [
            (Rung::TimeAdvance(TimeRung::OneSecond), "+1s"),
            (Rung::TimeAdvance(TimeRung::TenSeconds), "+10s"),
            (Rung::TimeAdvance(TimeRung::OneMinute), "+60s"),
            (Rung::TimeAdvance(TimeRung::FiveMinutes), "+5m"),
            (Rung::TimeAdvance(TimeRung::ThirtyMinutes), "+30m"),
            (Rung::FutureOnly, "future_only"),
        ] {
            let gap = gap_for_rung(rung, Some(from), Some(resume), at).unwrap();
            assert_eq!(gap.cause, cause);
            assert!(!gap.exact, "{cause} cannot know what it never read");
            assert_eq!(gap.missing_records, None, "{cause} must not invent a count");
            assert_eq!(gap.from.as_deref(), Some("2023-11-14T22:13:20.000Z"));
            assert_eq!(gap.to.as_deref(), Some("2023-11-14T22:13:50.000Z"));
        }
    }

    /// A channel with no delivered event still records the hole; it simply has
    /// no lower bound to give.
    #[test]
    fn a_gap_with_no_prior_event_reports_a_null_lower_bound() {
        let at = ts(1_700_000_010);
        let gap = gap_for_rung(Rung::FutureOnly, None, Some(at), at).unwrap();
        assert_eq!(gap.from, None);
        assert_eq!(gap.to.as_deref(), Some("2023-11-14T22:13:30.000Z"));
    }

    /// A flapping channel walks the ladder over and over. Without a bound the
    /// list grows for as long as the process runs.
    #[test]
    fn the_gap_list_is_bounded_and_evicts_the_oldest() {
        let mut gaps = VecDeque::new();
        for i in 0..(MAX_RETAINED_GAPS * 4) {
            let gap = gap_for_rung(
                Rung::SkipRecord,
                Some(ts(1_700_000_000 + i as i64)),
                None,
                ts(1_700_000_000 + i as i64),
            )
            .unwrap();
            push_gap(&mut gaps, gap);
        }

        assert_eq!(gaps.len(), MAX_RETAINED_GAPS);
        // The newest survived and the oldest did not.
        let newest = ts(1_700_000_000 + (MAX_RETAINED_GAPS * 4 - 1) as i64);
        assert_eq!(gaps.back().unwrap().at, rfc3339(newest));
        let oldest_kept = ts(1_700_000_000 + (MAX_RETAINED_GAPS * 3) as i64);
        assert_eq!(gaps.front().unwrap().at, rfc3339(oldest_kept));
    }

    fn sample_snapshot() -> StatusSnapshot {
        let mut snapshot = StatusSnapshot::new(ts(1_700_000_100));
        snapshot.channels.insert(
            "Microsoft-Windows-Windows Defender/Operational".to_string(),
            ChannelStatus {
                subscribed: true,
                skipped_reason: None,
                rung: "bookmark".to_string(),
                last_event_at: Some(rfc3339(ts(1_700_000_000))),
                last_drained_at: Some(rfc3339(ts(1_700_000_090))),
                last_record_id: Some(123_456),
                newest_record_id: Some(123_460),
                query_filters: false,
                bookmark_positioned: true,
                retry_attempt: 0,
                name_table_misses: 0,
                gaps: vec![
                    gap_for_rung(
                        Rung::SkipRecord,
                        Some(ts(1_699_999_000)),
                        None,
                        ts(1_699_999_001),
                    )
                    .unwrap(),
                ],
            },
        );
        snapshot.channels.insert(
            "Security".to_string(),
            ChannelStatus {
                subscribed: false,
                skipped_reason: Some("access_denied".to_string()),
                rung: "bookmark".to_string(),
                last_event_at: None,
                last_drained_at: None,
                last_record_id: None,
                newest_record_id: None,
                query_filters: true,
                bookmark_positioned: false,
                retry_attempt: 3,
                name_table_misses: 7,
                gaps: Vec::new(),
            },
        );
        snapshot
    }

    /// The file is a contract with another process, so it has to survive the
    /// round trip through JSON unchanged, and the field names have to be the
    /// ones the reader was built against.
    #[test]
    fn the_snapshot_round_trips_through_json() {
        let snapshot = sample_snapshot();
        let encoded = serde_json::to_string(&snapshot).unwrap();
        let decoded: StatusSnapshot = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, snapshot);

        let value: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        assert_eq!(value["schema"], 1);
        assert_eq!(value["as_of"], "2023-11-14T22:15:00.000Z");

        let defender = &value["channels"]["Microsoft-Windows-Windows Defender/Operational"];
        assert_eq!(defender["subscribed"], true);
        assert_eq!(defender["last_record_id"], 123_456);
        assert_eq!(defender["newest_record_id"], 123_460);
        assert_eq!(defender["bookmark_positioned"], true);
        assert_eq!(defender["last_drained_at"], "2023-11-14T22:14:50.000Z");
        assert_eq!(defender["retry_attempt"], 0);
        assert_eq!(defender["query_filters"], false);
        assert_eq!(defender["name_table_misses"], 0);
        assert_eq!(defender["gaps"][0]["cause"], "skip_record");
        assert_eq!(defender["gaps"][0]["exact"], true);
        assert_eq!(defender["gaps"][0]["missing_records"], 1);

        // Absent facts are explicit nulls, never missing keys: a reader that
        // cannot tell "no value" from "field removed" cannot detect a schema
        // it does not understand.
        let security = &value["channels"]["Security"];
        assert!(security["last_event_at"].is_null());
        assert!(security["last_drained_at"].is_null());
        assert!(security["newest_record_id"].is_null());
        assert_eq!(security["skipped_reason"], "access_denied");
        assert_eq!(security["query_filters"], true);
        assert_eq!(security["name_table_misses"], 7);
    }

    /// Additive fields must not invalidate a file a previous writer produced.
    ///
    /// `schema` stays 1: a bump would make every not-yet-upgraded reader drop
    /// the whole channel map to unknown. Absent keys default, they do not
    /// fail the parse.
    #[test]
    fn an_older_file_omitting_additive_fields_still_parses() {
        let body = r#"{
            "schema": 1,
            "as_of": "2023-11-14T22:15:00.000Z",
            "channels": {
                "Security": {
                    "subscribed": true,
                    "skipped_reason": null,
                    "rung": "bookmark",
                    "last_event_at": null,
                    "last_drained_at": "2023-11-14T22:14:50.000Z",
                    "last_record_id": 10,
                    "newest_record_id": 20,
                    "bookmark_positioned": true,
                    "retry_attempt": 0,
                    "gaps": []
                }
            }
        }"#;
        let decoded: StatusSnapshot =
            serde_json::from_str(body).expect("an absent additive field is not a schema change");
        let security = &decoded.channels["Security"];
        assert!(
            !security.query_filters,
            "unreported means unfiltered, which is what that writer meant"
        );
        assert_eq!(
            security.name_table_misses, 0,
            "unreported misses are zero, not a parse failure"
        );
        assert_eq!(security.last_record_id, Some(10));
    }

    /// The reader polls without locking, so it must never observe a partial
    /// file. Asserted on the mechanism: the target is replaced by a rename and
    /// no temporary file is left behind for the reader to trip over.
    #[test]
    fn the_write_replaces_the_target_and_leaves_no_temporary_behind() {
        let dir = tempfile::tempdir().unwrap();
        // A subdirectory that does not exist yet, because the agent points the
        // path wherever it likes and the source has to create it.
        let path = dir.path().join("state").join("wel-status.json");

        write_atomic(&path, &StatusSnapshot::new(ts(1_700_000_000))).unwrap();
        let first: StatusSnapshot =
            serde_json::from_slice(&fs::read(&path).unwrap()).expect("first write must parse");
        assert_eq!(first.as_of, "2023-11-14T22:13:20.000Z");

        // Overwrite: the rename has to replace an existing target rather than
        // fail, which is the failure mode this would have on a naive rename.
        write_atomic(&path, &sample_snapshot()).unwrap();
        let second: StatusSnapshot =
            serde_json::from_slice(&fs::read(&path).unwrap()).expect("second write must parse");
        assert_eq!(second, sample_snapshot());

        let leftovers: Vec<_> = fs::read_dir(path.parent().unwrap())
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".tmp"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "temporary files must not survive a successful write: {leftovers:?}"
        );
    }

    /// With nothing configured the file lands in the source's own data
    /// directory under the fixed name, which is where the reader scans for it.
    /// That is the path production uses; an override is the rare case.
    #[test]
    fn an_unconfigured_path_resolves_into_the_data_directory() {
        let data_dir = Path::new("C:\\ProgramData\\vector\\wel");
        assert_eq!(
            StatusWriter::resolve_path(None, data_dir),
            data_dir.join("windows_event_log_status.json")
        );

        let configured = PathBuf::from("D:\\elsewhere\\status.json");
        assert_eq!(
            StatusWriter::resolve_path(Some(&configured), data_dir),
            configured,
            "an explicit path wins outright and is not joined onto anything"
        );
    }

    #[test]
    fn the_writer_fires_immediately_and_then_on_its_interval() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wel-status.json");
        let start = Instant::now();
        let mut writer = StatusWriter::new(path.clone(), 30, start);

        assert!(
            writer.is_due(start),
            "a reader starting with the collector must not wait an interval for \
             its first fact"
        );
        writer.write(&StatusSnapshot::new(ts(1_700_000_000)), start);

        assert!(!writer.is_due(start + Duration::from_secs(29)));
        assert!(writer.is_due(start + Duration::from_secs(30)));
        assert!(path.exists());
    }

    /// A write that fails must still arm the next interval, otherwise an
    /// unwritable directory turns the timer into a hot loop.
    #[test]
    fn a_failed_write_still_arms_the_next_interval() {
        let dir = tempfile::tempdir().unwrap();
        // A directory where the file should be: create succeeds nowhere along
        // this path, so the write fails without needing permissions games.
        let path = dir.path().join("occupied");
        fs::create_dir(&path).unwrap();

        let start = Instant::now();
        let mut writer = StatusWriter::new(path, 30, start);
        writer.write(&StatusSnapshot::new(ts(1_700_000_000)), start);

        assert!(!writer.is_due(start + Duration::from_secs(29)));
        assert!(writer.is_due(start + Duration::from_secs(30)));
    }
}
