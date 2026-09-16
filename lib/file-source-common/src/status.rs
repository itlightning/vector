//! A periodic, self-describing status file for the `file` source.
//!
//! The checkpoint file answers "where did the reader get to", keyed by content
//! fingerprint, and it exists for the reader's own resume. It is a poor basis for a
//! SECOND consumer asking "is this source collecting, and is it behind": that consumer
//! has to re-derive the fingerprint the reader would compute, which means replicating
//! the source's configured fingerprint parameters exactly, and a mismatch there is
//! silent (a fingerprint that matches no entry is indistinguishable from a file read to
//! byte zero).
//!
//! This module writes what such a consumer actually needs, as facts, on a fixed
//! interval: what the source discovered, what it did with each file, where it is in
//! each one, and how big each one was AT THE MOMENT OF THE SNAPSHOT. No health verdict
//! is expressed here; the reader of this file owns that judgment.
//!
//! ## Two properties are load-bearing
//!
//! **The size is measured when the status is written, never carried over from the last
//! read.** A size cached from the last read reports `position == size` for a file that
//! grew but was not read, which makes a wedged reader look caught up. That is the exact
//! failure this file exists to expose, so the snapshot re-stats every watched path.
//!
//! **The write happens inside the file server's own loop.** Freshness of this file is
//! evidence THAT THE LOOP RAN. A writer on an independent task would keep stamping a
//! fresh `as_of` while the read loop was hung, which manufactures the false-healthy
//! signal the whole file is meant to remove. So a wedged read stalls this file, `as_of`
//! ages out, and a consumer that notices should report "I cannot judge", not "caught
//! up" and not a lag figure.
//!
//! ## Timestamps
//!
//! `as_of` is wall-clock (RFC3339, UTC) because it is compared against a consumer's own
//! clock. Per-file read recency is `last_read_secs_ago`, RELATIVE to `as_of`, because it
//! is derived from a monotonic `Instant` and converting it to wall clock would invent
//! precision across a suspend or a clock step.

use std::{
    io,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::warn;

use super::{FilePosition, fingerprinter::FileFingerprint};

/// The name the file source gives its status file under the source's data directory.
pub const STATUS_FILE_NAME: &str = "file_source_status.json";

/// Temporary name used to make the write atomic, alongside the stable file.
const TMP_FILE_NAME: &str = "file_source_status.new.json";

/// Upper bound on the status interval, mirroring the checkpoint interval's bound.
pub const MAX_STATUS_INTERVAL_SECS: u64 = 3600;

/// Default cadence of the status write.
pub const DEFAULT_STATUS_INTERVAL_SECS: u64 = 30;

/// What the source is doing with one discovered file.
///
/// Deliberately a closed set of OBSERVATIONS, not judgments. "Behind" and "stuck" are
/// verdicts a consumer reaches by comparing `position` to `size` over time, and belong
/// to whoever owns the health model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileState {
    /// Watched, and the read position is behind the size measured at snapshot time.
    Reading,
    /// Watched, and the read position has reached the size measured at snapshot time.
    CaughtUp,
    /// Discovered, but with no complete first line yet, so it cannot be fingerprinted
    /// and is not yet watched. The ordinary state of a log between creation and its
    /// first newline.
    TooSmallToFingerprint,
    /// Discovered, but the source could not read it (permissions, or it vanished between
    /// the glob and the open). The error itself is reported through the source's normal
    /// internal events; this file only records that it happened.
    Unreadable,
}

/// One discovered file, as of the snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileStatus {
    /// The path the source last saw this file at. A rotation that renames the file is
    /// followed by fingerprint, so this can be one scan stale; `fingerprint` is the
    /// stable identity.
    pub path: String,

    /// The content fingerprint, when the file has one. Same shape the checkpoint file
    /// uses, so a consumer can join the two without re-deriving anything.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<FileFingerprint>,

    /// Bytes read so far. Omitted for a file that is not being watched.
    ///
    /// This is bytes READ, not bytes shipped: multiline aggregation and the sink's
    /// buffer sit downstream of this number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub position: Option<FilePosition>,

    /// The file's size, measured at snapshot time. Omitted when the stat failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,

    /// How long before `as_of` this file was last read successfully. Omitted for a file
    /// that has never been read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_read_secs_ago: Option<u64>,

    /// What the source is doing with it.
    pub state: FileState,
}

/// One snapshot of a `file` source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileSourceStatus {
    /// Format version. A consumer that does not recognize it must treat the file as
    /// unusable rather than guess.
    pub version: String,

    /// When this snapshot was taken (RFC3339, UTC).
    pub as_of: String,

    /// The include patterns this source resolved, verbatim from its configuration.
    /// Present so a consumer never has to re-glob to know what was asked for.
    pub include_patterns: Vec<String>,

    /// The source's own scan cooldown. A file created after the last scan cannot appear
    /// here for up to this long.
    ///
    /// Reported because it is a true fact about this source that only this source knows,
    /// and the snapshot is facts-only. NO CONSUMER SIZES ANYTHING FROM IT today, and this
    /// doc used to claim one did; a grace attached to it is a decision for whoever
    /// attaches it, not a promise made here.
    pub glob_minimum_cooldown_secs: u64,

    /// The cadence this file is rewritten on. A consumer sizes its staleness grace from
    /// this, for the same reason.
    pub status_interval_secs: u64,

    /// Files the source discovered on its last scan.
    pub files_discovered: usize,

    /// How many of those it could not read.
    pub files_unreadable: usize,

    /// Every discovered file, watched or not.
    pub files: Vec<FileStatus>,
}

impl FileSourceStatus {
    /// The version every writer here stamps.
    pub const VERSION: &'static str = "1";

    /// An empty snapshot: the source ran, and found nothing.
    ///
    /// A positive fact, and a different one from "the source never ran", which is what
    /// an absent or stale file means.
    #[must_use]
    pub fn new(
        as_of: DateTime<Utc>,
        include_patterns: Vec<String>,
        glob_minimum_cooldown: Duration,
        status_interval: Duration,
    ) -> Self {
        Self {
            version: Self::VERSION.to_string(),
            as_of: as_of.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            include_patterns,
            glob_minimum_cooldown_secs: glob_minimum_cooldown.as_secs(),
            status_interval_secs: status_interval.as_secs(),
            files_discovered: 0,
            files_unreadable: 0,
            files: Vec::new(),
        }
    }

    /// Add one file to the snapshot, maintaining the counts.
    pub fn push(&mut self, file: FileStatus) {
        self.files_discovered += 1;
        if file.state == FileState::Unreadable {
            self.files_unreadable += 1;
        }
        self.files.push(file);
    }
}

/// Owns the status file's path, cadence, and due time.
///
/// Held by the file server's loop and polled with [`StatusWriter::is_due`], so the write
/// only happens on a pass the loop actually reached.
pub struct StatusWriter {
    path: PathBuf,
    tmp_path: PathBuf,
    interval: Duration,
    next_due: Instant,
    /// A write failure logs once rather than once per interval: a status file that
    /// cannot be written is usually a directory-permissions problem that will not fix
    /// itself, and repeating it every interval buries the rest of the log.
    warned: bool,
}

impl StatusWriter {
    /// A writer under `data_dir`, or at `path` when one was configured.
    ///
    /// The first write is due immediately: a consumer starting alongside the source
    /// should not wait a full interval to learn anything.
    #[must_use]
    pub fn new(path: PathBuf, interval: Duration, now: Instant) -> Self {
        let tmp_path = path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(TMP_FILE_NAME);
        Self {
            path,
            tmp_path,
            interval: interval.max(Duration::from_secs(1)),
            next_due: now,
            warned: false,
        }
    }

    /// The default location for a source whose data directory is `data_dir`.
    #[must_use]
    pub fn default_path(data_dir: &Path) -> PathBuf {
        data_dir.join(STATUS_FILE_NAME)
    }

    /// Whether a write is due, without arming the next one.
    #[must_use]
    pub fn is_due(&self, now: Instant) -> bool {
        now >= self.next_due
    }

    /// Write the snapshot whole, then arm the next interval.
    ///
    /// The next interval is armed whether or not the write succeeded: a failing write
    /// must not turn into a hot loop, and the resulting stale file is itself the signal.
    pub async fn write(&mut self, status: &FileSourceStatus, now: Instant) {
        self.next_due = now + self.interval;

        if let Err(error) = self.write_inner(status).await {
            if !self.warned {
                self.warned = true;
                warn!(
                    message = "Failed writing file source status file.",
                    path = ?self.path,
                    %error,
                );
            }
        } else {
            self.warned = false;
        }
    }

    /// Serialize to the temporary file, then rename over the stable one, so a reader
    /// never observes a partial file.
    ///
    /// No `fsync`. The rename is what gives torn-read safety: `std::fs::rename` is one
    /// replace-existing rename operation on every platform we ship (`FileRenameInfoEx`,
    /// falling back to `MoveFileExW` with `MOVEFILE_REPLACE_EXISTING`, on Windows;
    /// `rename(2)` elsewhere), so a concurrent reader opens either the whole previous
    /// snapshot or the whole new one, whether or not the bytes have reached the platter.
    /// The Windows caveat is failure, not tearing: a reader holding the stable path open
    /// without `FILE_SHARE_DELETE` makes the rename fail, which is the pre-existing
    /// warn-once-and-retry path.
    /// Flushing would buy crash durability alone, for a snapshot that is rewritten every
    /// interval and whose torn remains read as unparseable, which every consumer already
    /// treats as "no facts from this file". The checkpoint file DOES flush and keeps
    /// doing so: losing it costs re-read or skipped data, not one interval of reporting.
    async fn write_inner(&self, status: &FileSourceStatus) -> Result<(), io::Error> {
        let tmp_path = self.tmp_path.clone();
        let bytes = serde_json::to_vec(status)?;

        tokio::task::spawn_blocking(move || -> Result<(), io::Error> {
            use std::io::Write as _;
            let mut f = std::io::BufWriter::new(std::fs::File::create(tmp_path)?);
            f.write_all(&bytes)?;
            f.into_inner()?;
            Ok(())
        })
        .await
        .map_err(io::Error::other)??;

        tokio::fs::rename(&self.tmp_path, &self.path).await
    }
}

/// Seconds between `earlier` and `now`, saturating.
///
/// Both are monotonic, so this cannot go backwards; the saturation is for a caller that
/// hands them over in the wrong order rather than for a clock step.
#[must_use]
pub fn secs_ago(now: Instant, earlier: Instant) -> u64 {
    now.saturating_duration_since(earlier).as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> FileSourceStatus {
        let as_of = DateTime::parse_from_rfc3339("2026-08-12T10:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let mut status = FileSourceStatus::new(
            as_of,
            vec![r"C:\Windows\Logs\CBS\CBS.log".to_string()],
            Duration::from_secs(60),
            Duration::from_secs(30),
        );
        status.push(FileStatus {
            path: r"C:\Windows\Logs\CBS\CBS.log".to_string(),
            fingerprint: Some(FileFingerprint::FirstLinesChecksum(42)),
            position: Some(100),
            size: Some(100),
            last_read_secs_ago: Some(3),
            state: FileState::CaughtUp,
        });
        status
    }

    /// The field spellings are the whole contract with the consumer, which parses this
    /// file and cannot see a rename here. Written as a literal on purpose.
    #[test]
    fn the_wire_shape_is_the_contract() {
        let json = serde_json::to_string(&sample()).unwrap();
        assert_eq!(
            json,
            r#"{"version":"1","as_of":"2026-08-12T10:00:00.000Z","include_patterns":["C:\\Windows\\Logs\\CBS\\CBS.log"],"glob_minimum_cooldown_secs":60,"status_interval_secs":30,"files_discovered":1,"files_unreadable":0,"files":[{"path":"C:\\Windows\\Logs\\CBS\\CBS.log","fingerprint":{"first_lines_checksum":42},"position":100,"size":100,"last_read_secs_ago":3,"state":"caught_up"}]}"#
        );
    }

    #[test]
    fn it_round_trips() {
        let status = sample();
        let json = serde_json::to_string(&status).unwrap();
        let parsed: FileSourceStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, status);
    }

    /// An empty snapshot is a POSITIVE fact ("the source looked and found nothing"), so
    /// it must serialize as an empty list rather than be indistinguishable from a file
    /// that was never written.
    #[test]
    fn an_empty_snapshot_still_reports_its_patterns() {
        let as_of = Utc::now();
        let status = FileSourceStatus::new(
            as_of,
            vec!["/var/log/*.log".to_string()],
            Duration::from_secs(60),
            Duration::from_secs(30),
        );
        assert_eq!(status.files_discovered, 0);
        assert!(status.files.is_empty());
        assert_eq!(status.include_patterns, vec!["/var/log/*.log".to_string()]);
    }

    #[test]
    fn unreadable_files_are_counted() {
        let mut status = FileSourceStatus::new(Utc::now(), vec![], Duration::ZERO, Duration::ZERO);
        status.push(FileStatus {
            path: "/var/log/denied.log".to_string(),
            fingerprint: None,
            position: None,
            size: None,
            last_read_secs_ago: None,
            state: FileState::Unreadable,
        });
        status.push(FileStatus {
            path: "/var/log/fine.log".to_string(),
            fingerprint: None,
            position: Some(0),
            size: Some(0),
            last_read_secs_ago: None,
            state: FileState::CaughtUp,
        });
        assert_eq!(status.files_discovered, 2);
        assert_eq!(status.files_unreadable, 1);
    }

    /// The first write is due immediately, and arming pushes it out by exactly the
    /// interval.
    #[tokio::test]
    async fn the_first_write_is_due_immediately_then_spaced() {
        let dir = tempfile::tempdir().unwrap();
        let now = Instant::now();
        let mut writer = StatusWriter::new(
            StatusWriter::default_path(dir.path()),
            Duration::from_secs(30),
            now,
        );
        assert!(writer.is_due(now));

        writer.write(&sample(), now).await;
        assert!(!writer.is_due(now));
        assert!(!writer.is_due(now + Duration::from_secs(29)));
        assert!(writer.is_due(now + Duration::from_secs(30)));
    }

    /// The write is whole-file and atomic: what lands on disk parses, and the temporary
    /// file does not survive alongside it.
    #[tokio::test]
    async fn a_written_status_parses_back() {
        let dir = tempfile::tempdir().unwrap();
        let path = StatusWriter::default_path(dir.path());
        let now = Instant::now();
        let mut writer = StatusWriter::new(path.clone(), Duration::from_secs(30), now);

        writer.write(&sample(), now).await;

        let bytes = std::fs::read(&path).unwrap();
        let parsed: FileSourceStatus = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed, sample());
        assert!(!dir.path().join(TMP_FILE_NAME).exists());
    }

    /// A write into a directory that does not exist fails without panicking, arms the
    /// next interval anyway (so a broken path cannot become a hot loop), and leaves no
    /// file behind for a consumer to misread.
    #[tokio::test]
    async fn a_failed_write_still_arms_the_next_interval() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("no-such-dir").join(STATUS_FILE_NAME);
        let now = Instant::now();
        let mut writer = StatusWriter::new(path.clone(), Duration::from_secs(30), now);

        writer.write(&sample(), now).await;

        assert!(!path.exists());
        assert!(!writer.is_due(now + Duration::from_secs(29)));
        assert!(writer.is_due(now + Duration::from_secs(30)));
    }

    /// An interval of zero would spin the loop; the writer floors it.
    #[test]
    fn a_zero_interval_is_floored() {
        let now = Instant::now();
        let writer = StatusWriter::new(PathBuf::from("status.json"), Duration::ZERO, now);
        assert_eq!(writer.interval, Duration::from_secs(1));
    }
}
