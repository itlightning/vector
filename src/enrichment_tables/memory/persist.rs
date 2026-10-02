//! Disk persistence for the memory enrichment table.
//!
//! The log is append-only NDJSON, one `{"k": key, "v": value, "exp": unix_secs}` line per
//! written row; on load the last line per key wins and expired rows are dropped. Nothing
//! here ever truncates or deletes the log on an error: a failed append adds at most a torn
//! line (skipped on load) and a failed compaction leaves the previous log in place.

use std::{
    collections::HashMap,
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

/// Log bytes a row costs beyond its key and value: the line's JSON punctuation, a
/// ten-digit expiry and the newline. Only feeds the compaction threshold estimate.
pub(super) const LINE_OVERHEAD: u64 = 31;

/// A row restored from the log, with its remaining lifetime.
pub(super) struct LoadedRow {
    pub(super) key: String,
    pub(super) value: String,
    pub(super) remaining_secs: u64,
}

/// A row to write, with its absolute wall-clock expiry.
pub(super) struct PersistRow {
    pub(super) key: String,
    pub(super) value: String,
    pub(super) exp_unix: u64,
}

/// Table figures reported in the status file.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct TableStatus {
    pub(super) entries: usize,
    pub(super) bytes: u64,
    pub(super) max_bytes: Option<u64>,
    pub(super) evictions_total: u64,
}

/// One tick's write.
pub(super) struct PersistJob {
    /// Rows written since the last tick that are still in the table. Their keys go back
    /// to the table when the write fails, so the next tick retries them.
    pub(super) rows: Vec<PersistRow>,
    /// Every live row, when the log is due for a rewrite.
    pub(super) compact_rows: Option<Vec<PersistRow>>,
    pub(super) status: TableStatus,
}

#[derive(Deserialize)]
struct LogLine {
    k: String,
    v: Box<RawValue>,
    exp: u64,
}

/// Contents of `<persist_path>.status.json`.
#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub(super) struct StatusFile {
    pub(super) entries: usize,
    pub(super) bytes: u64,
    pub(super) max_bytes: Option<u64>,
    pub(super) evictions_total: u64,
    pub(super) persist_failing: bool,
    /// Consecutive ticks whose write failed; 0 while healthy.
    pub(super) failed_ticks: u64,
    /// Wall-clock time of the last tick whose write succeeded.
    pub(super) last_snapshot_unix: Option<u64>,
}

pub(super) struct Persistence {
    path: PathBuf,
    tmp_path: PathBuf,
    status_path: PathBuf,
    status_tmp_path: PathBuf,
    log_bytes: u64,
    /// Rewrite the whole log on the next tick, whatever its size.
    compact_pending: bool,
    /// The log could not be read, so its content is unknown and must not be replaced.
    compaction_blocked: bool,
    /// The log may end in a torn line; the next append starts with a newline.
    needs_newline: bool,
    failed_ticks: u64,
    status_warned: bool,
    last_snapshot_unix: Option<u64>,
}

pub(super) fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = OsString::from(path.as_os_str());
    name.push(suffix);
    PathBuf::from(name)
}

pub(super) fn status_path(path: &Path) -> PathBuf {
    with_suffix(path, ".status.json")
}

impl Persistence {
    fn new(path: &Path) -> Self {
        let status_path = status_path(path);
        Self {
            path: path.to_path_buf(),
            tmp_path: with_suffix(path, ".tmp"),
            status_tmp_path: with_suffix(&status_path, ".tmp"),
            status_path,
            log_bytes: 0,
            compact_pending: false,
            compaction_blocked: false,
            needs_newline: false,
            failed_ticks: 0,
            status_warned: false,
            last_snapshot_unix: None,
        }
    }

    /// Reads the log at `path` and returns the live rows it holds.
    pub(super) fn open(path: &Path) -> (Self, Vec<LoadedRow>) {
        Self::open_at(path, unix_now())
    }

    /// [`Self::open`] with `now` as the wall-clock time in unix seconds.
    pub(super) fn open_at(path: &Path, now: u64) -> (Self, Vec<LoadedRow>) {
        let mut this = Self::new(path);
        let content = match fs::read(path) {
            Ok(content) => content,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return (this, Vec::new()),
            Err(error) => {
                warn!(
                    message = "Failed reading memory enrichment table persistence log; starting empty.",
                    path = ?path,
                    %error,
                );
                this.compaction_blocked = true;
                this.log_bytes = fs::metadata(path).map_or(0, |m| m.len());
                return (this, Vec::new());
            }
        };
        this.log_bytes = content.len() as u64;
        this.needs_newline = content.last().is_some_and(|b| *b != b'\n');

        let mut latest: HashMap<String, (Box<RawValue>, u64)> = HashMap::new();
        let mut corrupt = 0usize;
        for line in content.split(|b| *b == b'\n') {
            if line.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            match serde_json::from_slice::<LogLine>(line) {
                Ok(line) => {
                    latest.insert(line.k, (line.v, line.exp));
                }
                Err(_) => corrupt += 1,
            }
        }
        if corrupt > 0 {
            warn!(
                message = "Skipped corrupt lines in memory enrichment table persistence log.",
                path = ?path,
                corrupt_lines = corrupt,
            );
            // A log with no readable line is not ours to rewrite.
            this.compaction_blocked = latest.is_empty();
        }

        let rows = latest
            .into_iter()
            .filter(|(_, (_, exp))| *exp > now)
            .map(|(key, (value, exp))| LoadedRow {
                key,
                value: value.get().to_owned(),
                remaining_secs: exp - now,
            })
            .collect();
        (this, rows)
    }

    /// State for a table carried over from a previous configuration: the log is not
    /// read, and the first tick rewrites it from the table.
    pub(super) fn resume(path: &Path) -> Self {
        let mut this = Self::new(path);
        this.log_bytes = fs::metadata(path).map_or(0, |m| m.len());
        this.compact_pending = true;
        this
    }

    /// Whether this tick should rewrite the log instead of appending `append_bytes`.
    pub(super) const fn should_compact(&self, append_bytes: u64, live_bytes: u64) -> bool {
        !self.compaction_blocked
            && (self.compact_pending
                || self.log_bytes.saturating_add(append_bytes) > live_bytes.saturating_mul(2))
    }

    /// Writes one tick and the status file. Returns the keys to retry on the next tick.
    pub(super) fn write(&mut self, job: PersistJob) -> Vec<String> {
        if job.compact_rows.is_none() && job.rows.is_empty() {
            // Nothing to write proves nothing: a failure stands until a write succeeds.
            if self.failed_ticks == 0 {
                self.last_snapshot_unix = Some(unix_now());
            }
            self.write_status(job.status);
            return Vec::new();
        }
        let mut appended = false;
        let result = match &job.compact_rows {
            Some(all) => self.compact(all).inspect_err(|_| {
                // The old log is still in place, so this tick's rows go on it and the
                // rewrite is retried next tick.
                appended = job.rows.is_empty() || self.append(&job.rows).is_ok();
            }),
            None => self.append(&job.rows),
        };
        let requeue = match result {
            Ok(()) => {
                if self.failed_ticks > 0 {
                    info!(
                        message = "Memory enrichment table persistence resumed.",
                        path = ?self.path,
                        missed_ticks = self.failed_ticks,
                    );
                    self.failed_ticks = 0;
                }
                self.last_snapshot_unix = Some(unix_now());
                Vec::new()
            }
            Err(error) => {
                if self.failed_ticks == 0 {
                    warn!(
                        message = "Failed writing memory enrichment table persistence log.",
                        path = ?self.path,
                        %error,
                    );
                }
                self.failed_ticks += 1;
                if appended {
                    Vec::new()
                } else {
                    job.rows.into_iter().map(|row| row.key).collect()
                }
            }
        };
        self.write_status(job.status);
        requeue
    }

    fn append(&mut self, rows: &[PersistRow]) -> io::Result<()> {
        let mut buf = Vec::new();
        if self.needs_newline {
            buf.push(b'\n');
        }
        for row in rows {
            write_line(&mut buf, row)?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        match file.write_all(&buf) {
            Ok(()) => {
                self.log_bytes += buf.len() as u64;
                self.needs_newline = false;
                Ok(())
            }
            Err(error) => {
                self.needs_newline = true;
                if let Ok(meta) = file.metadata() {
                    self.log_bytes = meta.len();
                }
                Err(error)
            }
        }
    }

    /// Writes every live row to a temporary file and renames it over the log. The
    /// temporary file is synced first: a power loss after the rename must not leave an
    /// empty log in place of the old one.
    fn compact(&mut self, rows: &[PersistRow]) -> io::Result<()> {
        let mut buf = Vec::new();
        for row in rows {
            write_line(&mut buf, row)?;
        }
        let result = (|| {
            let mut file = File::create(&self.tmp_path)?;
            file.write_all(&buf)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&self.tmp_path, &self.path)
        })();
        if let Err(error) = result {
            _ = fs::remove_file(&self.tmp_path);
            return Err(error);
        }
        self.log_bytes = buf.len() as u64;
        self.needs_newline = false;
        self.compact_pending = false;
        Ok(())
    }

    /// Temporary file and rename, so a reader never sees a partial file. Not synced: the
    /// file is rewritten every tick and a torn one reads as unparseable.
    fn write_status(&mut self, table: TableStatus) {
        let status = StatusFile {
            entries: table.entries,
            bytes: table.bytes,
            max_bytes: table.max_bytes,
            evictions_total: table.evictions_total,
            persist_failing: self.failed_ticks > 0,
            failed_ticks: self.failed_ticks,
            last_snapshot_unix: self.last_snapshot_unix,
        };
        let result = serde_json::to_vec(&status)
            .map_err(io::Error::from)
            .and_then(|bytes| {
                fs::write(&self.status_tmp_path, bytes)?;
                fs::rename(&self.status_tmp_path, &self.status_path)
            });
        match result {
            Ok(()) => self.status_warned = false,
            Err(error) => {
                if !self.status_warned {
                    warn!(
                        message = "Failed writing memory enrichment table status file.",
                        path = ?self.status_path,
                        %error,
                    );
                    self.status_warned = true;
                }
            }
        }
    }

    #[cfg(test)]
    pub(super) const fn failed_ticks(&self) -> u64 {
        self.failed_ticks
    }
}

/// `value` is already JSON text, so it is written verbatim.
fn write_line(buf: &mut Vec<u8>, row: &PersistRow) -> io::Result<()> {
    buf.extend_from_slice(b"{\"k\":");
    serde_json::to_writer(&mut *buf, &row.key)?;
    buf.extend_from_slice(b",\"v\":");
    buf.extend_from_slice(row.value.as_bytes());
    writeln!(buf, ",\"exp\":{}}}", row.exp_unix)
}
