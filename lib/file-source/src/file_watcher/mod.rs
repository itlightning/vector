use bytes::{Bytes, BytesMut};
use chrono::{DateTime, Utc};
use std::{
    io::{self, SeekFrom},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use tokio::{
    fs::File,
    io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncSeekExt, BufReader},
    time::Instant,
};
use tracing::{debug, warn};
use vector_common::constants::GZIP_MAGIC;

use file_source_common::{
    AsyncFileInfo, FilePosition, PortableFileExt, ReadFrom,
    buffer::{ReadResult, read_until_with_max_size},
};
use vector_common::compression::gzip_multiple_decoder;

use crate::encoding::{
    DetectViaKind, EncodingDetectOutcome, FileEncodingDetector, FileEncodingMode,
    FileEncodingState,
};

const EOF_READ_BACKOFF_MIN: Duration = Duration::from_millis(1);
const EOF_READ_BACKOFF_MAX: Duration = Duration::from_millis(250);

enum VerifiedPeek {
    Sniff(Vec<u8>),
    InodeMismatch,
}

#[cfg(test)]
mod tests;

/// The `RawLine` struct is a thin wrapper around the bytes that have been read
/// in order to retain the context of where in the file they have been read from.
///
/// The offset field contains the byte offset of the beginning of the line within
/// the file that it was read from.
#[derive(Debug)]
pub struct RawLine {
    pub offset: u64,
    pub bytes: Bytes,
}

#[derive(Debug)]
pub struct RawLineResult {
    pub raw_line: Option<RawLine>,
    pub discarded_for_size_and_truncated: Vec<BytesMut>,
}

/// The `FileWatcher` struct defines the polling based state machine which reads
/// from a file path, transparently updating the underlying file descriptor when
/// the file has been rolled over, as is common for logs.
///
/// The `FileWatcher` is expected to live for the lifetime of the file
/// path. `FileServer` is responsible for clearing away `FileWatchers` which no
/// longer exist.
pub struct FileWatcher {
    pub path: PathBuf,
    findable: bool,
    reader: Box<dyn AsyncBufRead + Send + Unpin>,
    file_position: FilePosition,
    devno: u64,
    inode: u64,
    is_dead: bool,
    reached_eof: bool,
    last_read_attempt: Instant,
    last_read_success: Instant,
    /// When this watcher was created. Unlike `last_read_success`, which is seeded
    /// from the file's mtime, this is a wall-clock "we started watching" mark and
    /// is the floor for any age-based cleanup of files that never shipped a line.
    watch_start: Instant,
    read_retry_delay: Duration,
    last_seen: Instant,
    max_line_bytes: usize,
    line_delimiter: Bytes,
    buf: BytesMut,
    encoding_state: FileEncodingState,
    encoding_detector: Option<Arc<dyn FileEncodingDetector>>,
    fixed_encoding_name: Option<&'static str>,
    /// When Pending, set at watcher creation (and again when the underlying
    /// inode changes); basis for the idle-timeout force-decide.
    pending_since: Option<Instant>,
    gzipped: bool,
}

impl FileWatcher {
    /// Create a new `FileWatcher`
    ///
    /// The input path will be used by `FileWatcher` to prime its state
    /// machine. A `FileWatcher` tracks _only one_ file. This function returns
    /// None if the path does not exist or is not readable by the current process.
    pub async fn new(
        path: PathBuf,
        read_from: ReadFrom,
        ignore_before: Option<DateTime<Utc>>,
        max_line_bytes: usize,
        line_delimiter: Bytes,
        encoding_mode: &FileEncodingMode,
    ) -> Result<FileWatcher, std::io::Error> {
        let f = File::open(&path).await?;
        let file_info = f.file_info().await?;
        let (devno, ino) = (file_info.portable_dev(), file_info.portable_ino());

        #[cfg(unix)]
        let metadata = file_info;
        #[cfg(windows)]
        let metadata = f.metadata().await?;

        let mut reader = BufReader::new(f);

        let too_old = if let (Some(ignore_before), Ok(modified_time)) = (
            ignore_before,
            metadata.modified().map(DateTime::<Utc>::from),
        ) {
            modified_time < ignore_before
        } else {
            false
        };

        let gzipped = is_gzipped(&mut reader).await?;

        // Determine the actual position at which we should start reading
        let (reader, file_position): (Box<dyn AsyncBufRead + Send + Unpin>, FilePosition) =
            match (gzipped, too_old, read_from) {
                (true, true, _) => {
                    debug!(
                        message = "Not reading gzipped file older than `ignore_older`.",
                        ?path,
                    );
                    (Box::new(null_reader()), 0)
                }
                (true, _, ReadFrom::Checkpoint(file_position)) => {
                    debug!(
                        message = "Not re-reading gzipped file with existing stored offset.",
                        ?path,
                        %file_position
                    );
                    (Box::new(null_reader()), file_position)
                }
                // TODO: This may become the default, leading us to stop reading gzipped files that
                // we were reading before. Should we merge this and the next branch to read
                // compressed file from the beginning even when `read_from = "end"` (implicitly via
                // default or explicitly via config)?
                (true, _, ReadFrom::End) => {
                    debug!(
                        message = "Can't read from the end of already-compressed file.",
                        ?path,
                    );
                    (Box::new(null_reader()), 0)
                }
                (true, false, ReadFrom::Beginning) => {
                    (Box::new(BufReader::new(gzip_multiple_decoder(reader))), 0)
                }
                (false, true, _) => {
                    let pos = reader.seek(SeekFrom::End(0)).await.unwrap();
                    (Box::new(reader), pos)
                }
                (false, false, ReadFrom::Checkpoint(file_position)) => {
                    let pos = reader.seek(SeekFrom::Start(file_position)).await.unwrap();
                    (Box::new(reader), pos)
                }
                (false, false, ReadFrom::Beginning) => {
                    let pos = reader.seek(SeekFrom::Start(0)).await.unwrap();
                    (Box::new(reader), pos)
                }
                (false, false, ReadFrom::End) => {
                    let pos = reader.seek(SeekFrom::End(0)).await.unwrap();
                    (Box::new(reader), pos)
                }
            };

        let ts = metadata
            .modified()
            .ok()
            .and_then(|mtime| mtime.elapsed().ok())
            .and_then(|diff| Instant::now().checked_sub(diff))
            .unwrap_or_else(Instant::now);

        let (encoding_state, encoding_detector, fixed_encoding_name, pending_since) =
            match encoding_mode {
                FileEncodingMode::Fixed { encoding_name } => {
                    (FileEncodingState::Inactive, None, *encoding_name, None)
                }
                FileEncodingMode::Auto { detector } => (
                    FileEncodingState::Pending,
                    Some(Arc::clone(detector)),
                    None,
                    Some(Instant::now()),
                ),
            };

        Ok(FileWatcher {
            path,
            findable: true,
            reader,
            file_position,
            devno,
            inode: ino,
            is_dead: false,
            reached_eof: false,
            last_read_attempt: ts,
            last_read_success: ts,
            watch_start: Instant::now(),
            read_retry_delay: EOF_READ_BACKOFF_MIN,
            last_seen: ts,
            max_line_bytes,
            line_delimiter,
            buf: BytesMut::new(),
            encoding_state,
            encoding_detector,
            fixed_encoding_name,
            pending_since,
            gzipped,
        })
    }

    /// Encoding annotation for emitted lines (`None` = already UTF-8 bytes).
    pub fn line_encoding_name(&self) -> Option<&'static str> {
        self.encoding_state
            .encoding_name()
            .or(self.fixed_encoding_name)
    }

    pub fn encoding_state(&self) -> &FileEncodingState {
        &self.encoding_state
    }

    pub async fn update_path(&mut self, path: PathBuf) -> io::Result<()> {
        let file_handle = File::open(&path).await?;

        let file_info = file_handle.file_info().await?;
        if (file_info.portable_dev(), file_info.portable_ino()) != (self.devno, self.inode) {
            let mut reader = BufReader::new(File::open(&path).await?);
            let gzipped = is_gzipped(&mut reader).await?;
            self.gzipped = gzipped;
            let new_reader: Box<dyn AsyncBufRead + Send + Unpin> = if gzipped {
                if self.file_position != 0 {
                    Box::new(null_reader())
                } else {
                    Box::new(BufReader::new(gzip_multiple_decoder(reader)))
                }
            } else {
                reader.seek(io::SeekFrom::Start(self.file_position)).await?;
                Box::new(reader)
            };
            self.reader = new_reader;

            let file_info = file_handle.file_info().await?;
            self.devno = file_info.portable_dev();
            self.inode = file_info.portable_ino();

            // Fresh underlying file content: re-run auto-detection when enabled.
            if self.encoding_detector.is_some() {
                self.encoding_state = FileEncodingState::Pending;
                self.pending_since = Some(Instant::now());
            }
        }
        self.reached_eof = false;
        self.read_retry_delay = EOF_READ_BACKOFF_MIN;
        self.path = path;
        Ok(())
    }

    pub fn set_file_findable(&mut self, f: bool) {
        self.findable = f;
        if f {
            self.last_seen = Instant::now();
        }
    }

    pub fn file_findable(&self) -> bool {
        self.findable
    }

    pub fn set_dead(&mut self) {
        self.is_dead = true;
    }

    pub fn dead(&self) -> bool {
        self.is_dead
    }

    pub fn get_file_position(&self) -> FilePosition {
        self.file_position
    }

    /// Whether the path still refers to the watched device+inode.
    ///
    /// `Ok(false)` means another file (for example a rotation successor) now
    /// occupies the path; destructive path-based operations must be skipped.
    pub async fn path_matches_watched_inode(&self) -> io::Result<bool> {
        let file = File::open(&self.path).await?;
        let file_info = file.file_info().await?;
        Ok((file_info.portable_dev(), file_info.portable_ino()) == (self.devno, self.inode))
    }

    /// Path-open peek with inode verify on the same handle (shared by detect and idle force-decide).
    async fn verified_peek_sniff(&self, max_bytes: usize) -> io::Result<VerifiedPeek> {
        let file = File::open(&self.path).await?;
        let file_info = file.file_info().await?;
        if (file_info.portable_dev(), file_info.portable_ino()) != (self.devno, self.inode) {
            return Ok(VerifiedPeek::InodeMismatch);
        }

        let sniff = if self.gzipped {
            let decoder = gzip_multiple_decoder(BufReader::new(file));
            let mut limited = decoder.take(max_bytes as u64);
            let mut buf = Vec::new();
            limited.read_to_end(&mut buf).await?;
            buf
        } else {
            // read_to_end on a limited reader: a single read() may return short
            // and under-fill the sniff window even when more bytes exist.
            let mut limited = file.take(max_bytes as u64);
            let mut buf = Vec::new();
            limited.read_to_end(&mut buf).await?;
            buf
        };
        Ok(VerifiedPeek::Sniff(sniff))
    }

    async fn skip_bom_on_reader(&mut self, bom_skip_bytes: u16) -> io::Result<()> {
        if bom_skip_bytes == 0 || self.file_position != 0 {
            return Ok(());
        }
        let mut discard = vec![0u8; bom_skip_bytes as usize];
        self.reader.read_exact(&mut discard).await?;
        self.file_position = u64::from(bom_skip_bytes);
        Ok(())
    }

    /// Run auto-detection when Pending. Returns whether framing may proceed.
    pub(super) async fn ensure_encoding_ready<E>(&mut self, emitter: &E) -> io::Result<bool>
    where
        E: file_source_common::FileSourceInternalEvents,
    {
        if !matches!(self.encoding_state, FileEncodingState::Pending) {
            return Ok(!matches!(self.encoding_state, FileEncodingState::Rejected));
        }

        let Some(detector) = self.encoding_detector.clone() else {
            self.encoding_state = FileEncodingState::Inactive;
            return Ok(true);
        };

        let peek = match self.verified_peek_sniff(detector.max_peek_bytes()).await {
            Ok(VerifiedPeek::InodeMismatch) => {
                self.last_read_attempt = Instant::now();
                return Ok(false);
            }
            Ok(VerifiedPeek::Sniff(sniff)) => sniff,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                self.set_dead();
                return Ok(false);
            }
            Err(e) => {
                // Peek failures (permissions, sharing violations) must not become
                // per-pass watch errors: with a fixed charset an unreadable file
                // emits nothing until an actual read fails. Log at debug level and
                // space out retries via the regular attempt throttle.
                self.last_read_attempt = Instant::now();
                debug!(
                    message = "Charset detection peek failed; will retry.",
                    file = %self.path.display(),
                    error = %e,
                );
                return Ok(false);
            }
        };

        let waive_min = self.pending_since.is_some_and(|since| {
            since.elapsed() >= Duration::from_secs(detector.idle_timeout_secs())
        });

        match detector.detect(&peek, waive_min) {
            EncodingDetectOutcome::Pending => {
                // Space out re-peeks the same way regular read attempts are spaced;
                // otherwise a sustained-Pending file is peeked on every server pass.
                self.last_read_attempt = Instant::now();
                Ok(false)
            }
            EncodingDetectOutcome::Decided {
                encoding_name,
                via,
                via_kind,
                line_delimiter,
                bom_skip_bytes,
            } => {
                let event_encoding = encoding_name.unwrap_or("UTF-8");
                emitter.emit_file_encoding_detected(&self.path, event_encoding, via);
                if via_kind == DetectViaKind::Fallback {
                    warn!(
                        message = "File character encoding detection was inconclusive; using fallback charset.",
                        file = %self.path.display(),
                        encoding = event_encoding,
                    );
                }
                self.line_delimiter = line_delimiter;
                self.encoding_state = FileEncodingState::Decided {
                    encoding_name,
                    bom_skip_bytes,
                };
                self.pending_since = None;
                self.skip_bom_on_reader(bom_skip_bytes).await?;
                Ok(true)
            }
            EncodingDetectOutcome::Rejected {
                encoding_name,
                via: _,
                ratio,
            } => {
                emitter.emit_file_encoding_rejected(&self.path, encoding_name, ratio);
                self.encoding_state = FileEncodingState::Rejected;
                self.pending_since = None;
                Ok(false)
            }
        }
    }

    /// Read a single line from the underlying file
    ///
    /// This function will attempt to read a new line from its file, blocking,
    /// up to some maximum but unspecified amount of time. `read_line` will open
    /// a new file handler as needed, transparently to the caller.
    pub(super) async fn read_line(&mut self) -> io::Result<RawLineResult> {
        self.track_read_attempt();

        let reader = &mut self.reader;
        let file_position = &mut self.file_position;
        let initial_position = *file_position;
        match read_until_with_max_size(
            reader.as_mut(),
            file_position,
            self.line_delimiter.as_ref(),
            &mut self.buf,
            self.max_line_bytes,
        )
        .await
        {
            Ok(ReadResult {
                successfully_read: Some(_),
                discarded_for_size_and_truncated,
            }) => {
                self.track_read_success();
                Ok(RawLineResult {
                    raw_line: Some(RawLine {
                        offset: initial_position,
                        bytes: self.buf.split().freeze(),
                    }),
                    discarded_for_size_and_truncated,
                })
            }
            Ok(ReadResult {
                successfully_read: None,
                discarded_for_size_and_truncated,
            }) => {
                if !self.file_findable() {
                    self.set_dead();
                    // File has been deleted, so return what we have in the buffer, even though it
                    // didn't end with a newline. This is not a perfect signal for when we should
                    // give up waiting for a newline, but it's decent.
                    let buf = self.buf.split().freeze();
                    if buf.is_empty() {
                        // EOF
                        self.reached_eof = true;
                        Ok(RawLineResult {
                            raw_line: None,
                            discarded_for_size_and_truncated,
                        })
                    } else {
                        Ok(RawLineResult {
                            raw_line: Some(RawLine {
                                offset: initial_position,
                                bytes: buf,
                            }),
                            discarded_for_size_and_truncated,
                        })
                    }
                } else {
                    self.track_read_eof();
                    Ok(RawLineResult {
                        raw_line: None,
                        discarded_for_size_and_truncated,
                    })
                }
            }
            Err(e) => {
                if let io::ErrorKind::NotFound = e.kind() {
                    self.set_dead();
                }
                Err(e)
            }
        }
    }

    #[inline]
    fn track_read_attempt(&mut self) {
        self.last_read_attempt = Instant::now();
    }

    #[inline]
    fn track_read_success(&mut self) {
        self.reached_eof = false;
        self.read_retry_delay = EOF_READ_BACKOFF_MIN;
        self.last_read_success = Instant::now();
    }

    #[inline]
    fn track_read_eof(&mut self) {
        self.read_retry_delay = if self.reached_eof {
            std::cmp::min(
                self.read_retry_delay.saturating_mul(2),
                EOF_READ_BACKOFF_MAX,
            )
        } else {
            EOF_READ_BACKOFF_MIN
        };
        self.reached_eof = true;
    }

    #[inline]
    pub fn last_read_success(&self) -> Instant {
        self.last_read_success
    }

    #[inline]
    pub fn watch_start(&self) -> Instant {
        self.watch_start
    }

    #[inline]
    pub fn should_read(&self) -> bool {
        if matches!(self.encoding_state, FileEncodingState::Rejected) {
            return false;
        }

        if self.reached_eof && self.last_read_attempt.elapsed() < self.read_retry_delay {
            return false;
        }

        self.last_read_success.elapsed() < Duration::from_secs(10)
            || self.last_read_attempt.elapsed() > Duration::from_secs(10)
    }

    #[inline]
    pub fn last_seen(&self) -> Instant {
        self.last_seen
    }

    #[inline]
    pub fn reached_eof(&self) -> bool {
        self.reached_eof
    }
}

async fn is_gzipped(r: &mut BufReader<File>) -> io::Result<bool> {
    let header_bytes = r.fill_buf().await?;
    // WARN: The paired `BufReader::consume` is not called intentionally. If we
    // do we'll chop a decent part of the potential gzip stream off.
    Ok(header_bytes.starts_with(GZIP_MAGIC))
}

fn null_reader() -> impl AsyncBufRead {
    io::Cursor::new(Vec::new())
}
