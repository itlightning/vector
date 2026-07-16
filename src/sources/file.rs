use std::{convert::TryInto, future, path::PathBuf, time::Duration};

use bytes::Bytes;
use chrono::Utc;
use futures::{FutureExt, Stream, StreamExt, TryFutureExt};
use regex::bytes::Regex;
use serde_with::serde_as;
use snafu::{ResultExt, Snafu};
use tokio::sync::oneshot;
use tracing::{Instrument, Span};
use vector_lib::{
    EstimatedJsonEncodedSizeOf,
    codecs::{BytesDeserializer, BytesDeserializerConfig},
    config::{LegacyKey, LogNamespace},
    configurable::configurable_component,
    file_source::{
        DetectViaKind, EncodingDetectOutcome, FileEncodingDetector, FileEncodingMode,
        file_server::{FileServer, Line, calculate_ignore_before},
        paths_provider::{Glob, MatchOptions},
    },
    file_source_common::{
        Checkpointer, FileFingerprint, FingerprintStrategy, Fingerprinter, ReadFrom, ReadFromConfig,
    },
    finalizer::OrderedFinalizer,
    lookup::{OwnedValuePath, lookup_v2::OptionalValuePath, owned_value_path, path},
};
use vrl::value::Kind;

use super::util::{CharsetMode, EncodingConfig, MultilineConfig};
use crate::{
    SourceSender,
    config::{
        DataType, SourceAcknowledgementsConfig, SourceConfig, SourceContext, SourceOutput,
        log_schema,
    },
    encoding_detect::{
        AutoDetectConfig, DetectOutcome, DetectVia, detect_charset, detect_charset_idle_force,
    },
    encoding_transcode::{Decoder, Encoder},
    event::{BatchNotifier, BatchStatus, LogEvent},
    internal_events::{
        FileBytesReceived, FileEventsReceived, FileInternalMetricsConfig, FileOpen,
        FileSourceInternalEventsEmitter, StreamClosedError,
    },
    line_agg::{self, LineAgg},
    serde::bool_or_struct,
    shutdown::ShutdownSignal,
};

#[derive(Debug, Snafu)]
enum BuildError {
    #[snafu(display(
        "message_start_indicator {:?} is not a valid regex: {}",
        indicator,
        source
    ))]
    InvalidMessageStartIndicator {
        indicator: String,
        source: regex::Error,
    },
}

/// Configuration for the `file` source.
#[serde_as]
#[configurable_component(source("file", "Collect logs from files."))]
#[derive(Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    /// Array of file patterns to include. [Globbing](https://vector.dev/docs/reference/configuration/sources/file/#globbing) is supported.
    #[configurable(metadata(docs::examples = "/var/log/**/*.log"))]
    pub include: Vec<PathBuf>,

    /// Array of file patterns to exclude. [Globbing](https://vector.dev/docs/reference/configuration/sources/file/#globbing) is supported.
    ///
    /// Takes precedence over the `include` option. Note: The `exclude` patterns are applied _after_ the attempt to glob everything
    /// in `include`. This means that all files are first matched by `include` and then filtered by the `exclude`
    /// patterns. This can be impactful if `include` contains directories with contents that are not accessible.
    #[serde(default)]
    #[configurable(metadata(docs::examples = "/var/log/binary-file.log"))]
    pub exclude: Vec<PathBuf>,

    /// Overrides the name of the log field used to add the file path to each event.
    ///
    /// The value is the full path to the file where the event was read message.
    ///
    /// Set to `""` to suppress this key.
    #[serde(default = "default_file_key")]
    #[configurable(metadata(docs::examples = "path"))]
    pub file_key: OptionalValuePath,

    /// Whether or not to start reading from the beginning of a new file.
    #[configurable(
        deprecated = "This option has been deprecated, use `ignore_checkpoints`/`read_from` instead."
    )]
    #[configurable(metadata(docs::hidden))]
    #[serde(default)]
    pub start_at_beginning: Option<bool>,

    /// Whether or not to ignore existing checkpoints when determining where to start reading a file.
    ///
    /// Checkpoints are still written normally.
    #[serde(default)]
    pub ignore_checkpoints: Option<bool>,

    #[serde(default = "default_read_from")]
    #[configurable(derived)]
    pub read_from: ReadFromConfig,

    /// Ignore files with a data modification date older than the specified number of seconds.
    #[serde(alias = "ignore_older", default)]
    #[configurable(metadata(docs::type_unit = "seconds"))]
    #[configurable(metadata(docs::examples = 600))]
    #[configurable(metadata(docs::human_name = "Ignore Older Files"))]
    pub ignore_older_secs: Option<u64>,

    /// The maximum size of a line before it is discarded.
    ///
    /// This protects against malformed lines or tailing incorrect files.
    #[serde(default = "default_max_line_bytes")]
    #[configurable(metadata(docs::type_unit = "bytes"))]
    pub max_line_bytes: usize,

    /// Overrides the name of the log field used to add the current hostname to each event.
    ///
    /// By default, the [global `log_schema.host_key` option][global_host_key] is used.
    ///
    /// Set to `""` to suppress this key.
    ///
    /// [global_host_key]: https://vector.dev/docs/reference/configuration/global-options/#log_schema.host_key
    #[configurable(metadata(docs::examples = "hostname"))]
    pub host_key: Option<OptionalValuePath>,

    /// The directory used to persist file checkpoint positions.
    ///
    /// By default, the [global `data_dir` option][global_data_dir] is used.
    /// Make sure the running user has write permissions to this directory.
    ///
    /// If this directory is specified, then Vector will attempt to create it.
    ///
    /// [global_data_dir]: https://vector.dev/docs/reference/configuration/global-options/#data_dir
    #[serde(default)]
    #[configurable(metadata(docs::examples = "/var/local/lib/vector/"))]
    #[configurable(metadata(docs::human_name = "Data Directory"))]
    pub data_dir: Option<PathBuf>,

    /// Enables adding the file offset to each event and sets the name of the log field used.
    ///
    /// The value is the byte offset of the start of the line within the file.
    ///
    /// Off by default, the offset is only added to the event if this is set.
    #[serde(default)]
    #[configurable(metadata(docs::examples = "offset"))]
    pub offset_key: Option<OptionalValuePath>,

    /// The delay between file discovery calls.
    ///
    /// This controls the interval at which files are searched. A higher value results in greater
    /// chances of some short-lived files being missed between searches, but a lower value increases
    /// the performance impact of file discovery.
    #[serde(
        alias = "glob_minimum_cooldown",
        default = "default_glob_minimum_cooldown_ms"
    )]
    #[serde_as(as = "serde_with::DurationMilliSeconds<u64>")]
    #[configurable(metadata(docs::type_unit = "milliseconds"))]
    #[configurable(metadata(docs::human_name = "Glob Minimum Cooldown"))]
    pub glob_minimum_cooldown_ms: Duration,

    #[configurable(derived)]
    #[serde(alias = "fingerprinting", default)]
    fingerprint: FingerprintConfig,

    /// Ignore missing files when fingerprinting.
    ///
    /// This may be useful when used with source directories containing dangling symlinks.
    #[serde(default)]
    pub ignore_not_found: bool,

    /// String value used to identify the start of a multi-line message.
    #[configurable(deprecated = "This option has been deprecated, use `multiline` instead.")]
    #[configurable(metadata(docs::hidden))]
    #[serde(default)]
    pub message_start_indicator: Option<String>,

    /// How long to wait for more data when aggregating a multi-line message, in milliseconds.
    #[configurable(deprecated = "This option has been deprecated, use `multiline` instead.")]
    #[configurable(metadata(docs::hidden))]
    #[serde(default = "default_multi_line_timeout")]
    pub multi_line_timeout: u64,

    /// Multiline aggregation configuration.
    ///
    /// If not specified, multiline aggregation is disabled.
    #[configurable(derived)]
    #[serde(default)]
    pub multiline: Option<MultilineConfig>,

    /// Max amount of bytes to read from a single file before switching over to the next file.
    /// **Note:** This does not apply when `oldest_first` is `true`.
    ///
    /// This allows distributing the reads more or less evenly across
    /// the files.
    #[serde(default = "default_max_read_bytes")]
    #[configurable(metadata(docs::type_unit = "bytes"))]
    pub max_read_bytes: usize,

    /// Instead of balancing read capacity fairly across all watched files, prioritize draining the oldest files before moving on to read data from more recent files.
    #[serde(default)]
    pub oldest_first: bool,

    /// After reaching EOF, the number of seconds to wait before removing the file, unless new data is written.
    ///
    /// If not specified, files are not removed.
    #[serde(alias = "remove_after", default)]
    #[configurable(metadata(docs::type_unit = "seconds"))]
    #[configurable(metadata(docs::examples = 0))]
    #[configurable(metadata(docs::examples = 5))]
    #[configurable(metadata(docs::examples = 60))]
    #[configurable(metadata(docs::human_name = "Wait Time Before Removing File"))]
    pub remove_after_secs: Option<u64>,

    /// String sequence used to separate one file line from another.
    #[serde(default = "default_line_delimiter")]
    #[configurable(metadata(docs::examples = "\r\n"))]
    pub line_delimiter: String,

    #[configurable(derived)]
    #[serde(default)]
    pub encoding: Option<EncodingConfig>,

    #[configurable(derived)]
    #[serde(default, deserialize_with = "bool_or_struct")]
    acknowledgements: SourceAcknowledgementsConfig,

    /// The namespace to use for logs. This overrides the global setting.
    #[configurable(metadata(docs::hidden))]
    #[serde(default)]
    log_namespace: Option<bool>,

    #[configurable(derived)]
    #[serde(default)]
    internal_metrics: FileInternalMetricsConfig,

    /// How long to keep an open handle to a rotated log file.
    /// The default value represents "no limit"
    #[serde_as(as = "serde_with::DurationSeconds<u64>")]
    #[configurable(metadata(docs::type_unit = "seconds"))]
    #[serde(default = "default_rotate_wait", rename = "rotate_wait_secs")]
    pub rotate_wait: Duration,
}

fn default_max_line_bytes() -> usize {
    bytesize::kib(100u64) as usize
}

fn default_file_key() -> OptionalValuePath {
    OptionalValuePath::from(owned_value_path!("file"))
}

const fn default_read_from() -> ReadFromConfig {
    ReadFromConfig::Beginning
}

const fn default_glob_minimum_cooldown_ms() -> Duration {
    Duration::from_millis(1000)
}

const fn default_multi_line_timeout() -> u64 {
    1000
} // deprecated

const fn default_max_read_bytes() -> usize {
    2048
}

fn default_line_delimiter() -> String {
    "\n".to_string()
}

const fn default_rotate_wait() -> Duration {
    Duration::from_secs(u64::MAX / 2)
}

/// Configuration for how files should be identified.
///
/// This is important for `checkpointing` when file rotation is used.
#[configurable_component]
#[derive(Clone, Debug, PartialEq, Eq)]
#[serde(tag = "strategy", rename_all = "snake_case")]
#[configurable(metadata(
    docs::enum_tag_description = "The strategy used to uniquely identify files.\n\nThis is important for checkpointing when file rotation is used."
))]
pub enum FingerprintConfig {
    /// Read lines from the beginning of the file and compute a checksum over them.
    Checksum {
        /// The number of bytes to skip ahead (or ignore) when reading the data used for generating the checksum.
        /// If the file is compressed, the number of bytes refer to the header in the uncompressed content. Only
        /// gzip is supported at this time.
        ///
        /// This can be helpful if all files share a common header that should be skipped.
        #[serde(default = "default_ignored_header_bytes")]
        #[configurable(metadata(docs::type_unit = "bytes"))]
        ignored_header_bytes: usize,

        /// The number of lines to read for generating the checksum.
        ///
        /// The number of lines are determined from the uncompressed content if the file is compressed. Only
        /// gzip is supported at this time.
        ///
        /// If the file has less than this amount of lines, it won’t be read at all.
        #[serde(default = "default_lines")]
        #[configurable(metadata(docs::type_unit = "lines"))]
        lines: usize,
    },

    /// Use the [device and inode][inode] as the identifier.
    ///
    /// [inode]: https://en.wikipedia.org/wiki/Inode
    #[serde(rename = "device_and_inode")]
    DevInode,
}

impl Default for FingerprintConfig {
    fn default() -> Self {
        Self::Checksum {
            ignored_header_bytes: 0,
            lines: default_lines(),
        }
    }
}

const fn default_ignored_header_bytes() -> usize {
    0
}

const fn default_lines() -> usize {
    1
}

impl From<FingerprintConfig> for FingerprintStrategy {
    fn from(config: FingerprintConfig) -> FingerprintStrategy {
        match config {
            FingerprintConfig::Checksum {
                ignored_header_bytes,
                lines,
            } => FingerprintStrategy::FirstLinesChecksum {
                ignored_header_bytes,
                lines,
            },
            FingerprintConfig::DevInode => FingerprintStrategy::DevInode,
        }
    }
}

#[derive(Debug)]
pub(crate) struct FinalizerEntry {
    pub(crate) file_id: FileFingerprint,
    pub(crate) offset: u64,
}

impl Default for FileConfig {
    fn default() -> Self {
        Self {
            include: vec![PathBuf::from("/var/log/**/*.log")],
            exclude: vec![],
            file_key: default_file_key(),
            start_at_beginning: None,
            ignore_checkpoints: None,
            read_from: default_read_from(),
            ignore_older_secs: None,
            max_line_bytes: default_max_line_bytes(),
            fingerprint: FingerprintConfig::default(),
            ignore_not_found: false,
            host_key: None,
            offset_key: None,
            data_dir: None,
            glob_minimum_cooldown_ms: default_glob_minimum_cooldown_ms(),
            message_start_indicator: None,
            multi_line_timeout: default_multi_line_timeout(), // millis
            multiline: None,
            max_read_bytes: default_max_read_bytes(),
            oldest_first: false,
            remove_after_secs: None,
            line_delimiter: default_line_delimiter(),
            encoding: None,
            acknowledgements: Default::default(),
            log_namespace: None,
            internal_metrics: Default::default(),
            rotate_wait: default_rotate_wait(),
        }
    }
}

impl_generate_config_from_default!(FileConfig);

#[async_trait::async_trait]
#[typetag::serde(name = "file")]
impl SourceConfig for FileConfig {
    async fn build(&self, cx: SourceContext) -> crate::Result<super::Source> {
        // add the source name as a subdir, so that multiple sources can
        // operate within the same given data_dir (e.g. the global one)
        // without the file servers' checkpointers interfering with each
        // other
        let data_dir = cx
            .globals
            // source are only global, name can be used for subdir
            .resolve_and_make_data_subdir(self.data_dir.as_ref(), cx.key.id())?;

        // Clippy rule, because async_trait?
        #[allow(clippy::suspicious_else_formatting)]
        {
            if let Some(ref config) = self.multiline {
                let _: line_agg::Config = config.try_into()?;
            }

            if let Some(ref indicator) = self.message_start_indicator {
                Regex::new(indicator)
                    .with_context(|_| InvalidMessageStartIndicatorSnafu { indicator })?;
            }
        }

        let acknowledgements = cx.do_acknowledgements(self.acknowledgements);

        let log_namespace = cx.log_namespace(self.log_namespace);

        // Single validation pass; `charset: auto` yields the resolved detection
        // tunables consumed below.
        let resolved_auto = match self.encoding.as_ref() {
            Some(encoding) => encoding.validate_and_resolve()?,
            None => None,
        };

        let resolved_encoding = resolve_file_encoding(self, resolved_auto)?;

        Ok(file_source(
            self,
            data_dir,
            cx.shutdown,
            cx.out,
            acknowledgements,
            log_namespace,
            resolved_encoding,
        ))
    }

    fn outputs(&self, global_log_namespace: LogNamespace) -> Vec<SourceOutput> {
        let file_key = self.file_key.clone().path.map(LegacyKey::Overwrite);
        let host_key = self
            .host_key
            .clone()
            .unwrap_or(log_schema().host_key().cloned().into())
            .path
            .map(LegacyKey::Overwrite);

        let offset_key = self
            .offset_key
            .clone()
            .and_then(|k| k.path)
            .map(LegacyKey::Overwrite);

        let schema_definition = BytesDeserializerConfig
            .schema_definition(global_log_namespace.merge(self.log_namespace))
            .with_standard_vector_source_metadata()
            .with_source_metadata(
                Self::NAME,
                host_key,
                &owned_value_path!("host"),
                Kind::bytes().or_undefined(),
                Some("host"),
            )
            .with_source_metadata(
                Self::NAME,
                offset_key,
                &owned_value_path!("offset"),
                Kind::integer(),
                None,
            )
            .with_source_metadata(
                Self::NAME,
                file_key,
                &owned_value_path!("path"),
                Kind::bytes(),
                None,
            );

        vec![SourceOutput::new_maybe_logs(
            DataType::Log,
            schema_definition,
        )]
    }

    fn can_acknowledge(&self) -> bool {
        true
    }
}

/// Resolved line delimiter and encoding mode for `FileServer` (computed once at build).
pub struct ResolvedFileEncoding {
    pub line_delimiter: Bytes,
    pub mode: FileEncodingMode,
}

fn resolve_file_encoding(
    config: &FileConfig,
    resolved_auto: Option<AutoDetectConfig>,
) -> crate::Result<ResolvedFileEncoding> {
    match config.encoding.as_ref() {
        Some(encoding) => match encoding.charset {
            CharsetMode::Auto => {
                // `validate_and_resolve` returns the auto config for `charset: auto`;
                // a missing value here is a caller bug surfaced as a config error
                // rather than a panic.
                let Some(auto) = resolved_auto else {
                    return Err(
                        "charset auto requires resolved auto-detection settings".into(),
                    );
                };
                let detector = std::sync::Arc::new(AutoFileEncodingDetector {
                    auto,
                    line_delimiter: config.line_delimiter.clone(),
                    sanitize_utf8: encoding.sanitize_utf8,
                });
                Ok(ResolvedFileEncoding {
                    line_delimiter: Bytes::from(config.line_delimiter.clone()),
                    mode: FileEncodingMode::Auto { detector },
                })
            }
            CharsetMode::Explicit(explicit) => {
                let delim = Encoder::new(explicit).encode_from_utf8(&config.line_delimiter);
                Ok(ResolvedFileEncoding {
                    line_delimiter: delim,
                    mode: FileEncodingMode::Fixed {
                        encoding_name: Some(explicit.name()),
                    },
                })
            }
        },
        None => Ok(ResolvedFileEncoding {
            line_delimiter: Bytes::from(config.line_delimiter.clone()),
            mode: FileEncodingMode::Fixed {
                encoding_name: None,
            },
        }),
    }
}

pub fn file_source(
    config: &FileConfig,
    data_dir: PathBuf,
    shutdown: ShutdownSignal,
    mut out: SourceSender,
    acknowledgements: bool,
    log_namespace: LogNamespace,
    resolved_encoding: ResolvedFileEncoding,
) -> super::Source {
    // the include option must be specified but also must contain at least one entry.
    if config.include.is_empty() {
        error!(
            message = "`include` configuration option must contain at least one file pattern.",
            internal_log_rate_limit = false
        );
        return Box::pin(future::ready(Err(())));
    }

    let exclude_patterns = config
        .exclude
        .iter()
        .map(|path_buf| path_buf.iter().collect::<std::path::PathBuf>())
        .collect::<Vec<PathBuf>>();
    let ignore_before = calculate_ignore_before(config.ignore_older_secs);
    let glob_minimum_cooldown = config.glob_minimum_cooldown_ms;
    let (ignore_checkpoints, read_from) = reconcile_position_options(
        config.start_at_beginning,
        config.ignore_checkpoints,
        Some(config.read_from),
    );

    let emitter = FileSourceInternalEventsEmitter {
        include_file_metric_tag: config.internal_metrics.include_file_tag,
    };

    let paths_provider = Glob::new(
        &config.include,
        &exclude_patterns,
        MatchOptions::default(),
        emitter.clone(),
    )
    .expect("invalid glob patterns");

    let ResolvedFileEncoding {
        line_delimiter: line_delimiter_as_bytes,
        mode: encoding_mode,
    } = resolved_encoding;

    let checkpointer = Checkpointer::new(&data_dir);
    let strategy = config.fingerprint.clone().into();

    let file_server = FileServer {
        paths_provider,
        max_read_bytes: config.max_read_bytes,
        ignore_checkpoints,
        read_from,
        ignore_before,
        max_line_bytes: config.max_line_bytes,
        line_delimiter: line_delimiter_as_bytes,
        encoding_mode,
        data_dir,
        glob_minimum_cooldown,
        fingerprinter: Fingerprinter::new(strategy, config.max_line_bytes, config.ignore_not_found),
        oldest_first: config.oldest_first,
        remove_after: config.remove_after_secs.map(Duration::from_secs),
        emitter,
        rotate_wait: config.rotate_wait,
    };

    let event_metadata = EventMetadata {
        host_key: config
            .host_key
            .clone()
            .unwrap_or(log_schema().host_key().cloned().into())
            .path,
        hostname: crate::get_hostname().ok(),
        file_key: config.file_key.clone().path,
        offset_key: config.offset_key.clone().and_then(|k| k.path),
    };

    let include = config.include.clone();
    let exclude = config.exclude.clone();
    let multiline_config = config.multiline.clone();
    let message_start_indicator = config.message_start_indicator.clone();
    let multi_line_timeout = config.multi_line_timeout;

    let (finalizer, shutdown_checkpointer) = if acknowledgements {
        // The shutdown sent in to the finalizer is the global
        // shutdown handle used to tell it to stop accepting new batch
        // statuses and just wait for the remaining acks to come in.
        let (finalizer, mut ack_stream) = OrderedFinalizer::<FinalizerEntry>::new(None);

        // We set up a separate shutdown signal to tie together the
        // finalizer and the checkpoint writer task in the file
        // server, to make it continue to write out updated
        // checkpoints until all the acks have come in.
        let (send_shutdown, shutdown2) = oneshot::channel::<()>();
        let checkpoints = checkpointer.view();
        crate::spawn_in_current_span(async move {
            while let Some((status, entry)) = ack_stream.next().await {
                if status == BatchStatus::Delivered {
                    checkpoints.update(entry.file_id, entry.offset);
                }
            }
            send_shutdown.send(())
        });
        (Some(finalizer), shutdown2.map(|_| ()).boxed())
    } else {
        // When not dealing with end-to-end acknowledgements, just
        // clone the global shutdown to stop the checkpoint writer.
        (None, shutdown.clone().map(|_| ()).boxed())
    };

    let checkpoints = checkpointer.view();
    let include_file_metric_tag = config.internal_metrics.include_file_tag;
    Box::pin(async move {
        info!(message = "Starting file server.", include = ?include, exclude = ?exclude);

        // One decoder per detected/fixed charset name (shared across files).
        let mut encoding_decoders: std::collections::HashMap<&'static str, Decoder> =
            std::collections::HashMap::new();

        // sizing here is just a guess
        let (tx, rx) = futures::channel::mpsc::channel::<Vec<Line>>(2);
        let rx = rx
            .map(futures::stream::iter)
            .flatten()
            .map(move |mut line| {
                emit!(FileBytesReceived {
                    byte_size: line.text.len(),
                    file: &line.filename,
                    include_file_metric_tag,
                });
                // Transcode each line from the file's encoding charset to utf8.
                // `line.encoding` is a charset name the file source obtained from
                // `Encoding::name()` (auto-detected or an explicit charset), which is always a
                // valid Encoding Standard label, so `for_label` round-trips it losslessly; the
                // `unwrap_or` is unreachable and only avoids a panic path.
                // (The name crosses the file-source boundary as `&str` to keep that crate free
                // of `encoding_rs`; see `lib/file-source/src/encoding.rs`.)
                if let Some(encoding_name) = line.encoding {
                    let decoder = encoding_decoders.entry(encoding_name).or_insert_with(|| {
                        let encoding = encoding_rs::Encoding::for_label(encoding_name.as_bytes())
                            .unwrap_or(encoding_rs::UTF_8);
                        Decoder::new(encoding)
                    });
                    line.text = decoder.decode_to_utf8_with_file(line.text, Some(&line.filename));
                }
                line
            });

        let messages: Box<dyn Stream<Item = Line> + Send + std::marker::Unpin> =
            if let Some(ref multiline_config) = multiline_config {
                wrap_with_line_agg(
                    rx,
                    multiline_config.try_into().unwrap(), // validated in build
                )
            } else if let Some(msi) = message_start_indicator {
                wrap_with_line_agg(
                    rx,
                    line_agg::Config::for_legacy(
                        Regex::new(&msi).unwrap(), // validated in build
                        multi_line_timeout,
                    ),
                )
            } else {
                Box::new(rx)
            };

        // Once file server ends this will run until it has finished processing remaining
        // logs in the queue.
        let span = Span::current();
        let mut messages = messages.map(move |line| {
            let mut event = create_event(
                line.text,
                line.start_offset,
                &line.filename,
                &event_metadata,
                log_namespace,
                include_file_metric_tag,
            );

            if let Some(finalizer) = &finalizer {
                let (batch, receiver) = BatchNotifier::new_with_receiver();
                event = event.with_batch_notifier(&batch);
                let entry = FinalizerEntry {
                    file_id: line.file_id,
                    offset: line.end_offset,
                };
                // checkpoints.update will be called from ack_stream's thread
                finalizer.add(entry, receiver);
            } else {
                checkpoints.update(line.file_id, line.end_offset);
            }
            event
        });
        tokio::spawn(async move {
            match out
                .send_event_stream(&mut messages)
                .instrument(span.or_current())
                .await
            {
                Ok(()) => {
                    debug!("Finished sending.");
                }
                Err(_) => {
                    let (count, _) = messages.size_hint();
                    emit!(StreamClosedError { count });
                }
            }
        });

        let span = info_span!("file_server");
        tokio::task::spawn_blocking(move || {
            let _enter = span.enter();
            let rt = tokio::runtime::Handle::current();
            let result =
                rt.block_on(file_server.run(tx, shutdown, shutdown_checkpointer, checkpointer));
            emit!(FileOpen { count: 0 });
            // Panic if we encounter any error originating from the file server.
            // We're at the `spawn_blocking` call, the panic will be caught and
            // passed to the `JoinHandle` error, similar to the usual threads.
            result.expect("file server exited with an error");
        })
        .map_err(|error| error!(message="File server unexpectedly stopped.", %error, internal_log_rate_limit = false))
        .await
    })
}

/// Emit deprecation warning if the old option is used, and take it into account when determining
/// defaults. Any of the newer options will override it when set directly.
fn reconcile_position_options(
    start_at_beginning: Option<bool>,
    ignore_checkpoints: Option<bool>,
    read_from: Option<ReadFromConfig>,
) -> (bool, ReadFrom) {
    if start_at_beginning.is_some() {
        warn!(
            message = "Use of deprecated option `start_at_beginning`. Please use `ignore_checkpoints` and `read_from` options instead."
        )
    }

    match start_at_beginning {
        Some(true) => (
            ignore_checkpoints.unwrap_or(true),
            read_from.map(Into::into).unwrap_or(ReadFrom::Beginning),
        ),
        _ => (
            ignore_checkpoints.unwrap_or(false),
            read_from.map(Into::into).unwrap_or_default(),
        ),
    }
}

fn wrap_with_line_agg(
    rx: impl Stream<Item = Line> + Send + std::marker::Unpin + 'static,
    config: line_agg::Config,
) -> Box<dyn Stream<Item = Line> + Send + std::marker::Unpin + 'static> {
    let logic = line_agg::Logic::new(config);
    Box::new(
        LineAgg::new(
            rx.map(|line| {
                (
                    line.filename,
                    line.text,
                    (
                        line.file_id,
                        line.start_offset,
                        line.end_offset,
                        line.encoding,
                    ),
                )
            }),
            logic,
        )
        .map(
            |(filename, text, (file_id, start_offset, initial_end, encoding), lastline_context)| {
                Line {
                    text,
                    filename,
                    file_id,
                    start_offset,
                    end_offset: lastline_context
                        .map_or(initial_end, |(_, _, lastline_end_offset, _)| {
                            lastline_end_offset
                        }),
                    encoding,
                }
            },
        ),
    )
}

/// Bridges file-source auto-detection to Vector's charset detector + delimiter encoder.
struct AutoFileEncodingDetector {
    auto: AutoDetectConfig,
    line_delimiter: String,
    /// When true, UTF-8-decided files are decoded (never zero-copy) so malformed
    /// bytes are replaced with U+FFFD and every emitted line is valid UTF-8.
    sanitize_utf8: bool,
}

impl FileEncodingDetector for AutoFileEncodingDetector {
    fn max_peek_bytes(&self) -> usize {
        self.auto.max_bytes
    }

    fn idle_timeout_secs(&self) -> u64 {
        self.auto.idle_timeout_secs
    }

    fn detect(&self, sniff: &[u8], waive_min: bool) -> EncodingDetectOutcome {
        let outcome = if waive_min {
            detect_charset_idle_force(sniff, &self.auto)
        } else {
            detect_charset(sniff, &self.auto)
        };
        match outcome {
            DetectOutcome::Pending => EncodingDetectOutcome::Pending,
            DetectOutcome::Decided { encoding, via } => {
                let bom_skip_bytes = encoding_rs::Encoding::for_bom(sniff)
                    .filter(|(enc, _)| *enc == encoding_rs::UTF_8)
                    .map(|(_, len)| len as u16)
                    .unwrap_or(0);
                // Zero-copy only when the sniff proved the bytes are UTF-8 (a UTF-8
                // BOM or strict validation). A fallback decision means the window was
                // NOT valid UTF-8 even when the fallback charset is UTF-8, so those
                // files must flow through the decoder to get U+FFFD substitution and
                // the malformed-input warning, matching explicit `charset: utf-8`.
                // `sanitize_utf8` opts proven-UTF-8 files into the same decoder path
                // to guarantee valid UTF-8 output beyond the detection window.
                let zero_copy_utf8 = encoding == encoding_rs::UTF_8
                    && matches!(via, DetectVia::Bom | DetectVia::Utf8Valid)
                    && !self.sanitize_utf8;
                EncodingDetectOutcome::Decided {
                    encoding_name: if zero_copy_utf8 {
                        None
                    } else {
                        Some(encoding.name())
                    },
                    via: via.as_str(),
                    via_kind: detect_via_kind(via),
                    line_delimiter: if zero_copy_utf8 {
                        Bytes::from(self.line_delimiter.clone())
                    } else {
                        Encoder::new(encoding).encode_from_utf8(&self.line_delimiter)
                    },
                    bom_skip_bytes: if zero_copy_utf8 { bom_skip_bytes } else { 0 },
                }
            }
            DetectOutcome::Rejected {
                encoding,
                via,
                ratio,
            } => EncodingDetectOutcome::Rejected {
                encoding_name: encoding.name(),
                via: via.as_str(),
                ratio,
            },
        }
    }
}

/// Maps the detector-internal `DetectVia` to the typed kind that crosses the
/// file-source boundary (the string label in events stays separate).
const fn detect_via_kind(via: DetectVia) -> DetectViaKind {
    match via {
        DetectVia::Bom => DetectViaKind::Bom,
        DetectVia::Utf16Heuristic => DetectViaKind::Utf16Heuristic,
        DetectVia::Utf8Valid => DetectViaKind::Utf8Valid,
        DetectVia::Fallback => DetectViaKind::Fallback,
    }
}

struct EventMetadata {
    host_key: Option<OwnedValuePath>,
    hostname: Option<String>,
    file_key: Option<OwnedValuePath>,
    offset_key: Option<OwnedValuePath>,
}

fn create_event(
    line: Bytes,
    offset: u64,
    file: &str,
    meta: &EventMetadata,
    log_namespace: LogNamespace,
    include_file_metric_tag: bool,
) -> LogEvent {
    let deserializer = BytesDeserializer;
    let mut event = deserializer.parse_single(line, log_namespace);

    log_namespace.insert_vector_metadata(
        &mut event,
        log_schema().source_type_key(),
        path!("source_type"),
        Bytes::from_static(FileConfig::NAME.as_bytes()),
    );
    log_namespace.insert_vector_metadata(
        &mut event,
        log_schema().timestamp_key(),
        path!("ingest_timestamp"),
        Utc::now(),
    );

    let legacy_host_key = meta.host_key.as_ref().map(LegacyKey::Overwrite);
    // `meta.host_key` is already `unwrap_or_else`ed so we can just pass it in.
    if let Some(hostname) = &meta.hostname {
        log_namespace.insert_source_metadata(
            FileConfig::NAME,
            &mut event,
            legacy_host_key,
            path!("host"),
            hostname.clone(),
        );
    }

    let legacy_offset_key = meta.offset_key.as_ref().map(LegacyKey::Overwrite);
    log_namespace.insert_source_metadata(
        FileConfig::NAME,
        &mut event,
        legacy_offset_key,
        path!("offset"),
        offset,
    );

    let legacy_file_key = meta.file_key.as_ref().map(LegacyKey::Overwrite);
    log_namespace.insert_source_metadata(
        FileConfig::NAME,
        &mut event,
        legacy_file_key,
        path!("path"),
        file,
    );

    emit!(FileEventsReceived {
        count: 1,
        file,
        byte_size: event.estimated_json_encoded_size_of(),
        include_file_metric_tag,
    });

    event
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashSet,
        fs::{self, File},
        future::Future,
        io::{BufWriter, Seek, Write},
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use encoding_rs::UTF_16LE;
    use flate2::{Compression, write::GzEncoder};
    use indoc::indoc;
    use similar_asserts::assert_eq;
    use tempfile::tempdir;
    use tokio::time::{Duration, sleep, timeout};
    use vector_lib::schema::Definition;
    use vrl::{value, value::kind::Collection};

    use super::*;
    use crate::{
        config::Config,
        event::{Event, EventStatus, Value},
        shutdown::ShutdownSignal,
        sources::file,
        test_util::{
            components::{FILE_SOURCE_TAGS, assert_source_compliance},
            wait_for_atomic_usize_timeout_ms,
        },
    };

    #[test]
    fn generate_config() {
        crate::test_util::test_generate_config::<FileConfig>();
    }

    fn test_default_file_config(dir: &tempfile::TempDir) -> file::FileConfig {
        // Store checkpoints in a subdirectory so they don't appear in the
        // glob-watched directory (which covers dir.path()/*).
        let data_dir = dir.path().join(".data");
        fs::create_dir_all(&data_dir).unwrap();
        file::FileConfig {
            fingerprint: FingerprintConfig::Checksum {
                ignored_header_bytes: 0,
                lines: 1,
            },
            data_dir: Some(data_dir),
            glob_minimum_cooldown_ms: Duration::from_millis(100),
            internal_metrics: FileInternalMetricsConfig {
                include_file_tag: true,
            },
            ..Default::default()
        }
    }

    async fn sleep_500_millis() {
        sleep(Duration::from_millis(500)).await;
    }

    #[test]
    fn parse_config() {
        let config: FileConfig = serde_yaml::from_str(indoc! {
            r#"
            include:
              - /var/log/**/*.log
            file_key: file
            glob_minimum_cooldown_ms: 1000
            multi_line_timeout: 1000
            max_read_bytes: 2048
            line_delimiter: "\n"
            "#,
        })
        .unwrap();
        assert_eq!(config, FileConfig::default());
        assert_eq!(
            config.fingerprint,
            FingerprintConfig::Checksum {
                ignored_header_bytes: 0,
                lines: 1
            }
        );

        let config: FileConfig = serde_yaml::from_str(indoc! {
            r#"
            include:
              - /var/log/**/*.log
            fingerprint:
              strategy: device_and_inode
            "#,
        })
        .unwrap();
        assert_eq!(config.fingerprint, FingerprintConfig::DevInode);

        let config: FileConfig = serde_yaml::from_str(indoc! {
            r#"
            include:
              - /var/log/**/*.log
            fingerprint:
              strategy: checksum
              bytes: 128
              ignored_header_bytes: 512
            "#,
        })
        .unwrap();
        assert_eq!(
            config.fingerprint,
            FingerprintConfig::Checksum {
                ignored_header_bytes: 512,
                lines: 1
            }
        );

        let config: FileConfig = serde_yaml::from_str(indoc! {
            r#"
            include:
              - /var/log/**/*.log
            encoding:
              charset: utf-16le
            "#,
        })
        .unwrap();
        assert_eq!(config.encoding, Some(EncodingConfig::explicit(UTF_16LE)));

        let config: FileConfig = serde_yaml::from_str(indoc! {
            r#"
            include:
              - /var/log/**/*.log
            read_from: beginning
            "#,
        })
        .unwrap();
        assert_eq!(config.read_from, ReadFromConfig::Beginning);

        let config: FileConfig = serde_yaml::from_str(indoc! {
            r#"
            include:
              - /var/log/**/*.log
            read_from: end
            "#,
        })
        .unwrap();
        assert_eq!(config.read_from, ReadFromConfig::End);
    }

    #[test]
    fn resolve_data_dir() {
        let global_dir = tempdir().unwrap();
        let local_dir = tempdir().unwrap();

        let mut config = Config::default();
        config.global.data_dir = global_dir.keep().into();

        // local path given -- local should win
        let local_data_dir = Some(local_dir.path().to_path_buf());
        let res = config
            .global
            .resolve_and_validate_data_dir(local_data_dir.as_ref())
            .unwrap();
        assert_eq!(res, local_dir.path());

        // no local path given -- global fallback should be in effect
        let res = config.global.resolve_and_validate_data_dir(None).unwrap();
        assert_eq!(res, config.global.data_dir.unwrap());
    }

    #[test]
    fn output_schema_definition_vector_namespace() {
        let definitions = FileConfig::default()
            .outputs(LogNamespace::Vector)
            .remove(0)
            .schema_definition(true);

        assert_eq!(
            definitions,
            Some(
                Definition::new_with_default_metadata(Kind::bytes(), [LogNamespace::Vector])
                    .with_meaning(OwnedTargetPath::event_root(), "message")
                    .with_metadata_field(
                        &owned_value_path!("vector", "source_type"),
                        Kind::bytes(),
                        None
                    )
                    .with_metadata_field(
                        &owned_value_path!("vector", "ingest_timestamp"),
                        Kind::timestamp(),
                        None
                    )
                    .with_metadata_field(
                        &owned_value_path!("file", "host"),
                        Kind::bytes().or_undefined(),
                        Some("host")
                    )
                    .with_metadata_field(
                        &owned_value_path!("file", "offset"),
                        Kind::integer(),
                        None
                    )
                    .with_metadata_field(&owned_value_path!("file", "path"), Kind::bytes(), None)
            )
        )
    }

    #[test]
    fn output_schema_definition_legacy_namespace() {
        let definitions = FileConfig::default()
            .outputs(LogNamespace::Legacy)
            .remove(0)
            .schema_definition(true);

        assert_eq!(
            definitions,
            Some(
                Definition::new_with_default_metadata(
                    Kind::object(Collection::empty()),
                    [LogNamespace::Legacy]
                )
                .with_event_field(
                    &owned_value_path!("message"),
                    Kind::bytes(),
                    Some("message")
                )
                .with_event_field(&owned_value_path!("source_type"), Kind::bytes(), None)
                .with_event_field(&owned_value_path!("timestamp"), Kind::timestamp(), None)
                .with_event_field(
                    &owned_value_path!("host"),
                    Kind::bytes().or_undefined(),
                    Some("host")
                )
                .with_event_field(&owned_value_path!("offset"), Kind::undefined(), None)
                .with_event_field(&owned_value_path!("file"), Kind::bytes(), None)
            )
        )
    }

    #[test]
    fn create_event_legacy_namespace() {
        let line = Bytes::from("hello world");
        let file = "some_file.rs";
        let offset: u64 = 0;

        let meta = EventMetadata {
            host_key: Some(owned_value_path!("host")),
            hostname: Some("Some.Machine".to_string()),
            file_key: Some(owned_value_path!("file")),
            offset_key: Some(owned_value_path!("offset")),
        };
        let log = create_event(line, offset, file, &meta, LogNamespace::Legacy, false);

        assert_eq!(log["file"], "some_file.rs".into());
        assert_eq!(log["host"], "Some.Machine".into());
        assert_eq!(log["offset"], 0.into());
        assert_eq!(*log.get_message().unwrap(), "hello world".into());
        assert_eq!(*log.get_source_type().unwrap(), "file".into());
        assert!(log[log_schema().timestamp_key().unwrap().to_string()].is_timestamp());
    }

    #[test]
    fn create_event_custom_fields_legacy_namespace() {
        let line = Bytes::from("hello world");
        let file = "some_file.rs";
        let offset: u64 = 0;

        let meta = EventMetadata {
            host_key: Some(owned_value_path!("hostname")),
            hostname: Some("Some.Machine".to_string()),
            file_key: Some(owned_value_path!("file_path")),
            offset_key: Some(owned_value_path!("off")),
        };
        let log = create_event(line, offset, file, &meta, LogNamespace::Legacy, false);

        assert_eq!(log["file_path"], "some_file.rs".into());
        assert_eq!(log["hostname"], "Some.Machine".into());
        assert_eq!(log["off"], 0.into());
        assert_eq!(*log.get_message().unwrap(), "hello world".into());
        assert_eq!(*log.get_source_type().unwrap(), "file".into());
        assert!(log[log_schema().timestamp_key().unwrap().to_string()].is_timestamp());
    }

    #[test]
    fn create_event_vector_namespace() {
        let line = Bytes::from("hello world");
        let file = "some_file.rs";
        let offset: u64 = 0;

        let meta = EventMetadata {
            host_key: Some(owned_value_path!("ignored")),
            hostname: Some("Some.Machine".to_string()),
            file_key: Some(owned_value_path!("ignored")),
            offset_key: Some(owned_value_path!("ignored")),
        };
        let log = create_event(line, offset, file, &meta, LogNamespace::Vector, false);

        assert_eq!(log.value(), &value!("hello world"));

        assert_eq!(
            log.metadata()
                .value()
                .get(path!("vector", "source_type"))
                .unwrap(),
            &value!("file")
        );
        assert!(
            log.metadata()
                .value()
                .get(path!("vector", "ingest_timestamp"))
                .unwrap()
                .is_timestamp()
        );

        assert_eq!(
            log.metadata()
                .value()
                .get(path!(FileConfig::NAME, "host"))
                .unwrap(),
            &value!("Some.Machine")
        );
        assert_eq!(
            log.metadata()
                .value()
                .get(path!(FileConfig::NAME, "offset"))
                .unwrap(),
            &value!(0)
        );
        assert_eq!(
            log.metadata()
                .value()
                .get(path!(FileConfig::NAME, "path"))
                .unwrap(),
            &value!("some_file.rs")
        );
    }

    #[tokio::test]
    async fn file_happy_path() {
        let n = 5;

        let dir = tempdir().unwrap();
        let config = file::FileConfig {
            include: vec![dir.path().join("*")],
            ..test_default_file_config(&dir)
        };

        let path1 = dir.path().join("file1");
        let path2 = dir.path().join("file2");

        let received = run_file_source(&config, false, NoAcks, LogNamespace::Legacy, None, async {
            let mut file1 = File::create(&path1).unwrap();
            let mut file2 = File::create(&path2).unwrap();

            for i in 0..n {
                writeln!(&mut file1, "hello {i}").unwrap();
                writeln!(&mut file2, "goodbye {i}").unwrap();
            }

            file1.flush().unwrap();
            file2.flush().unwrap();

            sleep_500_millis().await;
        })
        .await;

        let mut hello_i = 0;
        let mut goodbye_i = 0;

        for event in received {
            let line =
                event.as_log()[log_schema().message_key().unwrap().to_string()].to_string_lossy();
            if line.starts_with("hello") {
                assert_eq!(line, format!("hello {}", hello_i));
                assert_eq!(
                    event.as_log()["file"].to_string_lossy(),
                    path1.to_str().unwrap()
                );
                hello_i += 1;
            } else {
                assert_eq!(line, format!("goodbye {}", goodbye_i));
                assert_eq!(
                    event.as_log()["file"].to_string_lossy(),
                    path2.to_str().unwrap()
                );
                goodbye_i += 1;
            }
        }
        assert_eq!(hello_i, n);
        assert_eq!(goodbye_i, n);
    }

    // https://github.com/vectordotdev/vector/issues/8363
    #[tokio::test]
    async fn file_read_empty_lines() {
        let n = 5;

        let dir = tempdir().unwrap();
        let config = file::FileConfig {
            include: vec![dir.path().join("*")],
            ..test_default_file_config(&dir)
        };

        let path = dir.path().join("file");

        let received = run_file_source(&config, false, NoAcks, LogNamespace::Legacy, None, async {
            let mut file = File::create(&path).unwrap();

            writeln!(&mut file, "line for checkpointing").unwrap();
            for _i in 0..n {
                writeln!(&mut file).unwrap();
            }
            file.flush().unwrap();

            sleep_500_millis().await;
        })
        .await;

        assert_eq!(received.len(), n + 1);
    }

    #[tokio::test]
    async fn file_truncate() {
        let n = 5;

        let dir = tempdir().unwrap();
        let config = file::FileConfig {
            include: vec![dir.path().join("*")],
            ..test_default_file_config(&dir)
        };
        let path = dir.path().join("file");
        let received = run_file_source(&config, false, NoAcks, LogNamespace::Legacy, None, async {
            let mut file = File::create(&path).unwrap();

            for i in 0..n {
                writeln!(&mut file, "pretrunc {i}").unwrap();
            }

            file.flush().unwrap();
            sleep_500_millis().await; // The writes must be observed before truncating

            file.set_len(0).unwrap();
            file.seek(std::io::SeekFrom::Start(0)).unwrap();

            file.sync_all().unwrap();
            sleep_500_millis().await; // The truncate must be observed before writing again

            for i in 0..n {
                writeln!(&mut file, "posttrunc {i}").unwrap();
            }

            file.flush().unwrap();
            sleep_500_millis().await;
        })
        .await;

        let mut i = 0;
        let mut pre_trunc = true;

        for event in received {
            assert_eq!(
                event.as_log()["file"].to_string_lossy(),
                path.to_str().unwrap()
            );

            let line =
                event.as_log()[log_schema().message_key().unwrap().to_string()].to_string_lossy();

            if pre_trunc {
                assert_eq!(line, format!("pretrunc {}", i));
            } else {
                assert_eq!(line, format!("posttrunc {}", i));
            }

            i += 1;
            if i == n {
                i = 0;
                pre_trunc = false;
            }
        }
    }

    #[tokio::test]
    async fn file_rotate() {
        let n = 5;

        let dir = tempdir().unwrap();
        let config = file::FileConfig {
            include: vec![dir.path().join("*")],
            ..test_default_file_config(&dir)
        };

        let path = dir.path().join("file");
        let archive_path = dir.path().join("file");
        let received = run_file_source(&config, false, NoAcks, LogNamespace::Legacy, None, async {
            let mut file = File::create(&path).unwrap();

            for i in 0..n {
                writeln!(&mut file, "prerot {i}").unwrap();
            }

            file.flush().unwrap();
            sleep_500_millis().await; // The writes must be observed before rotating

            fs::rename(&path, archive_path).expect("could not rename");
            file.sync_all().unwrap();

            let mut file = File::create(&path).unwrap();

            file.sync_all().unwrap();
            sleep_500_millis().await; // The rotation must be observed before writing again

            for i in 0..n {
                writeln!(&mut file, "postrot {i}").unwrap();
            }

            file.flush().unwrap();
            sleep_500_millis().await;
        })
        .await;

        let mut i = 0;
        let mut pre_rot = true;

        for event in received {
            assert_eq!(
                event.as_log()["file"].to_string_lossy(),
                path.to_str().unwrap()
            );

            let line =
                event.as_log()[log_schema().message_key().unwrap().to_string()].to_string_lossy();

            if pre_rot {
                assert_eq!(line, format!("prerot {}", i));
            } else {
                assert_eq!(line, format!("postrot {}", i));
            }

            i += 1;
            if i == n {
                i = 0;
                pre_rot = false;
            }
        }
    }

    #[tokio::test]
    async fn file_multiple_paths() {
        let n = 5;

        let dir = tempdir().unwrap();
        let config = file::FileConfig {
            include: vec![dir.path().join("*.txt"), dir.path().join("a.*")],
            exclude: vec![dir.path().join("a.*.txt")],
            ..test_default_file_config(&dir)
        };

        let path1 = dir.path().join("a.txt");
        let path2 = dir.path().join("b.txt");
        let path3 = dir.path().join("a.log");
        let path4 = dir.path().join("a.ignore.txt");
        let received = run_file_source(&config, false, NoAcks, LogNamespace::Legacy, None, async {
            let mut file1 = File::create(&path1).unwrap();
            let mut file2 = File::create(&path2).unwrap();
            let mut file3 = File::create(&path3).unwrap();
            let mut file4 = File::create(&path4).unwrap();

            for i in 0..n {
                writeln!(&mut file1, "1 {i}").unwrap();
                writeln!(&mut file2, "2 {i}").unwrap();
                writeln!(&mut file3, "3 {i}").unwrap();
                writeln!(&mut file4, "4 {i}").unwrap();
            }
            file1.flush().unwrap();
            file2.flush().unwrap();
            file3.flush().unwrap();
            file4.flush().unwrap();

            sleep_500_millis().await;
        })
        .await;

        let mut is = [0; 3];

        for event in received {
            let line =
                event.as_log()[log_schema().message_key().unwrap().to_string()].to_string_lossy();
            let mut split = line.split(' ');
            let file = split.next().unwrap().parse::<usize>().unwrap();
            assert_ne!(file, 4);
            let i = split.next().unwrap().parse::<usize>().unwrap();

            assert_eq!(is[file - 1], i);
            is[file - 1] += 1;
        }

        assert_eq!(is, [n as usize; 3]);
    }

    #[tokio::test]
    async fn file_exclude_paths() {
        let n = 5;

        let dir = tempdir().unwrap();
        let config = file::FileConfig {
            include: vec![dir.path().join("a//b/*.log.*")],
            exclude: vec![dir.path().join("a//b/test.log.*")],
            ..test_default_file_config(&dir)
        };

        let path1 = dir.path().join("a//b/a.log.1");
        let path2 = dir.path().join("a//b/test.log.1");
        let received = run_file_source(&config, false, NoAcks, LogNamespace::Legacy, None, async {
            std::fs::create_dir_all(dir.path().join("a/b")).unwrap();
            let mut file1 = File::create(&path1).unwrap();
            let mut file2 = File::create(&path2).unwrap();

            for i in 0..n {
                writeln!(&mut file1, "1 {i}").unwrap();
                writeln!(&mut file2, "2 {i}").unwrap();
            }

            file1.flush().unwrap();
            file2.flush().unwrap();
            sleep_500_millis().await;
        })
        .await;

        let mut is = [0; 1];

        for event in received {
            let line =
                event.as_log()[log_schema().message_key().unwrap().to_string()].to_string_lossy();
            let mut split = line.split(' ');
            let file = split.next().unwrap().parse::<usize>().unwrap();
            assert_ne!(file, 4);
            let i = split.next().unwrap().parse::<usize>().unwrap();

            assert_eq!(is[file - 1], i);
            is[file - 1] += 1;
        }

        assert_eq!(is, [n as usize; 1]);
    }

    #[tokio::test]
    async fn file_key_acknowledged() {
        file_key(Acks).await
    }

    #[tokio::test]
    async fn file_key_no_acknowledge() {
        file_key(NoAcks).await
    }

    async fn file_key(acks: AckingMode) {
        // Default
        {
            let dir = tempdir().unwrap();
            let config = file::FileConfig {
                include: vec![dir.path().join("*")],
                ..test_default_file_config(&dir)
            };

            let path = dir.path().join("file");
            let received =
                run_file_source(&config, true, acks, LogNamespace::Legacy, None, async {
                    let mut file = File::create(&path).unwrap();

                    writeln!(&mut file, "hello there").unwrap();
                    file.flush().unwrap();

                    sleep_500_millis().await;
                })
                .await;

            assert_eq!(received.len(), 1);
            assert_eq!(
                received[0].as_log()["file"].to_string_lossy(),
                path.to_str().unwrap()
            );
        }

        // Custom
        {
            let dir = tempdir().unwrap();
            let config = file::FileConfig {
                include: vec![dir.path().join("*")],
                file_key: OptionalValuePath::from(owned_value_path!("source")),
                ..test_default_file_config(&dir)
            };

            let path = dir.path().join("file");
            let received =
                run_file_source(&config, true, acks, LogNamespace::Legacy, None, async {
                    let mut file = File::create(&path).unwrap();

                    writeln!(&mut file, "hello there").unwrap();
                    file.flush().unwrap();

                    sleep_500_millis().await;
                })
                .await;

            assert_eq!(received.len(), 1);
            assert_eq!(
                received[0].as_log()["source"].to_string_lossy(),
                path.to_str().unwrap()
            );
        }

        // Hidden
        {
            let dir = tempdir().unwrap();
            let config = file::FileConfig {
                include: vec![dir.path().join("*")],
                ..test_default_file_config(&dir)
            };

            let path = dir.path().join("file");
            let received =
                run_file_source(&config, true, acks, LogNamespace::Legacy, None, async {
                    let mut file = File::create(&path).unwrap();

                    writeln!(&mut file, "hello there").unwrap();

                    file.flush().unwrap();
                    sleep_500_millis().await;
                })
                .await;

            assert_eq!(received.len(), 1);
            assert_eq!(
                received[0].as_log().keys().unwrap().collect::<HashSet<_>>(),
                vec![
                    default_file_key()
                        .path
                        .expect("file key to exist")
                        .to_string()
                        .into(),
                    log_schema().host_key().unwrap().to_string().into(),
                    log_schema().message_key().unwrap().to_string().into(),
                    log_schema().timestamp_key().unwrap().to_string().into(),
                    log_schema().source_type_key().unwrap().to_string().into()
                ]
                .into_iter()
                .collect::<HashSet<_>>()
            );
        }
    }

    #[tokio::test]
    async fn file_start_position_server_restart_acknowledged() {
        file_start_position_server_restart(Acks).await
    }

    #[tokio::test]
    async fn file_start_position_server_restart_no_acknowledge() {
        file_start_position_server_restart(NoAcks).await
    }

    async fn file_start_position_server_restart(acking: AckingMode) {
        let dir = tempdir().unwrap();
        let config = file::FileConfig {
            include: vec![dir.path().join("*")],
            ..test_default_file_config(&dir)
        };

        let path = dir.path().join("file");
        let mut file = File::create(&path).unwrap();
        writeln!(&mut file, "zeroth line").unwrap();
        file.flush().unwrap();

        // First time server runs it picks up existing lines.
        {
            let received =
                run_file_source(&config, true, acking, LogNamespace::Legacy, None, async {
                    sleep_500_millis().await;
                    writeln!(&mut file, "first line").unwrap();
                    file.flush().unwrap();
                    sleep_500_millis().await;
                })
                .await;

            let lines = extract_messages_string(received);
            assert_eq!(lines, vec!["zeroth line", "first line"]);
        }
        // Restart server, read file from checkpoint.
        {
            let received =
                run_file_source(&config, true, acking, LogNamespace::Legacy, None, async {
                    sleep_500_millis().await;
                    writeln!(&mut file, "second line").unwrap();
                    file.flush().unwrap();
                    sleep_500_millis().await;
                })
                .await;

            let lines = extract_messages_string(received);
            assert_eq!(lines, vec!["second line"]);
        }
        // Restart server, read files from beginning.
        {
            let config = file::FileConfig {
                include: vec![dir.path().join("*")],
                ignore_checkpoints: Some(true),
                read_from: ReadFromConfig::Beginning,
                ..test_default_file_config(&dir)
            };
            let received =
                run_file_source(&config, false, acking, LogNamespace::Legacy, None, async {
                    sleep_500_millis().await;
                    writeln!(&mut file, "third line").unwrap();
                    file.flush().unwrap();
                    sleep_500_millis().await;
                })
                .await;

            let lines = extract_messages_string(received);
            assert_eq!(
                lines,
                vec!["zeroth line", "first line", "second line", "third line"]
            );
        }
    }

    #[tokio::test]
    async fn file_start_position_server_restart_unfinalized() {
        let dir = tempdir().unwrap();
        let config = file::FileConfig {
            include: vec![dir.path().join("*")],
            ..test_default_file_config(&dir)
        };

        let path = dir.path().join("file");
        let mut file = File::create(&path).unwrap();
        writeln!(&mut file, "the line").unwrap();
        file.flush().unwrap();

        // First time server runs it picks up existing lines.
        let received = run_file_source(
            &config,
            false,
            Unfinalized,
            LogNamespace::Legacy,
            None,
            sleep(Duration::from_secs(5)),
        )
        .await;
        let lines = extract_messages_string(received);
        assert_eq!(lines, vec!["the line"]);

        // Restart server, it re-reads file since the events were not acknowledged before shutdown
        let received = run_file_source(
            &config,
            false,
            Unfinalized,
            LogNamespace::Legacy,
            None,
            sleep(Duration::from_secs(5)),
        )
        .await;
        let lines = extract_messages_string(received);
        assert_eq!(lines, vec!["the line"]);
    }

    #[tokio::test]
    async fn file_duplicate_processing_after_restart() {
        let dir = tempdir().unwrap();
        let config = file::FileConfig {
            include: vec![dir.path().join("*")],
            ..test_default_file_config(&dir)
        };

        let path = dir.path().join("file");
        let mut file = File::create(&path).unwrap();

        let line_count = 4000;
        for i in 0..line_count {
            writeln!(&mut file, "Here's a line for you: {i}").unwrap();
        }
        file.flush().unwrap();

        // First time server runs it should pick up a bunch of lines
        let received = run_file_source(
            &config,
            true,
            Acks,
            LogNamespace::Legacy,
            None,
            // shutdown signal is sent after this duration
            sleep_500_millis(),
        )
        .await;
        let lines = extract_messages_string(received);

        // ...but not all the lines; if the first run processed the entire file, we may not hit the
        // bug we're testing for, which happens if the finalizer stream exits on shutdown with pending acks
        assert!(lines.len() < line_count);

        // Restart the server, and it should read the rest without duplicating any.
        // Use the event counter to drain rx continuously (removing backpressure so
        // the file server can read all remaining lines without being stalled), then
        // trigger shutdown once all expected events have been received.
        let remaining = line_count - lines.len();
        let event_count = Arc::new(AtomicUsize::new(0));
        let received = run_file_source(
            &config,
            true,
            Acks,
            LogNamespace::Legacy,
            Some(Arc::clone(&event_count)),
            async {
                wait_for_atomic_usize_timeout_ms(
                    Arc::clone(&event_count),
                    |n| n >= remaining,
                    5_000,
                )
                .await;
            },
        )
        .await;
        let lines2 = extract_messages_string(received);

        // Between both runs, we should have the expected number of lines
        assert_eq!(lines.len() + lines2.len(), line_count);
    }

    #[tokio::test]
    async fn file_start_position_server_restart_with_file_rotation_acknowledged() {
        file_start_position_server_restart_with_file_rotation(Acks).await
    }

    #[tokio::test]
    async fn file_start_position_server_restart_with_file_rotation_no_acknowledge() {
        file_start_position_server_restart_with_file_rotation(NoAcks).await
    }

    async fn file_start_position_server_restart_with_file_rotation(acking: AckingMode) {
        let dir = tempdir().unwrap();
        let config = file::FileConfig {
            include: vec![dir.path().join("*")],
            ..test_default_file_config(&dir)
        };

        let path = dir.path().join("file");
        let path_for_old_file = dir.path().join("file.old");
        // Run server first time, collect some lines.
        {
            let received =
                run_file_source(&config, true, acking, LogNamespace::Legacy, None, async {
                    let mut file = File::create(&path).unwrap();
                    writeln!(&mut file, "first line").unwrap();
                    file.flush().unwrap();
                    sleep_500_millis().await;
                })
                .await;

            let lines = extract_messages_string(received);
            assert_eq!(lines, vec!["first line"]);
        }
        // Perform 'file rotation' to archive old lines.
        fs::rename(&path, &path_for_old_file).expect("could not rename");
        // Restart the server and make sure it does not re-read the old file
        // even though it has a new name.
        {
            let received =
                run_file_source(&config, false, acking, LogNamespace::Legacy, None, async {
                    let mut file = File::create(&path).unwrap();
                    writeln!(&mut file, "second line").unwrap();
                    file.flush().unwrap();
                    sleep_500_millis().await;
                })
                .await;

            let lines = extract_messages_string(received);
            assert_eq!(lines, vec!["second line"]);
        }
    }

    #[cfg(unix)] // this test uses unix-specific function `futimes` during test time
    #[tokio::test]
    async fn file_start_position_ignore_old_files() {
        use std::{
            os::unix::io::AsRawFd,
            time::{Duration, SystemTime},
        };

        let dir = tempdir().unwrap();
        let config = file::FileConfig {
            include: vec![dir.path().join("*")],
            ignore_older_secs: Some(5),
            ..test_default_file_config(&dir)
        };

        let before_path = dir.path().join("before");
        let mut before_file = File::create(&before_path).unwrap();
        let after_path = dir.path().join("after");
        let mut after_file = File::create(&after_path).unwrap();

        writeln!(&mut before_file, "first line").unwrap(); // first few bytes make up unique file fingerprint
        writeln!(&mut after_file, "_first line").unwrap(); //   and therefore need to be non-identical

        {
            // Set the modified times
            let before = SystemTime::now() - Duration::from_secs(8);
            let after = SystemTime::now() - Duration::from_secs(2);

            let before_time = libc::timeval {
                tv_sec: before
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as _,
                tv_usec: 0,
            };
            let before_times = [before_time, before_time];

            let after_time = libc::timeval {
                tv_sec: after
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as _,
                tv_usec: 0,
            };
            let after_times = [after_time, after_time];

            unsafe {
                libc::futimes(before_file.as_raw_fd(), before_times.as_ptr());
                libc::futimes(after_file.as_raw_fd(), after_times.as_ptr());
            }
        }

        before_file.sync_all().unwrap();
        after_file.sync_all().unwrap();

        let received = run_file_source(&config, false, NoAcks, LogNamespace::Legacy, None, async {
            sleep_500_millis().await;
            writeln!(&mut before_file, "second line").unwrap();
            writeln!(&mut after_file, "_second line").unwrap();

            before_file.flush().unwrap();
            after_file.flush().unwrap();
            sleep_500_millis().await;
        })
        .await;

        let before_lines = received
            .iter()
            .filter(|event| event.as_log()["file"].to_string_lossy().ends_with("before"))
            .map(|event| {
                event.as_log()[log_schema().message_key().unwrap().to_string()].to_string_lossy()
            })
            .collect::<Vec<_>>();
        let after_lines = received
            .iter()
            .filter(|event| event.as_log()["file"].to_string_lossy().ends_with("after"))
            .map(|event| {
                event.as_log()[log_schema().message_key().unwrap().to_string()].to_string_lossy()
            })
            .collect::<Vec<_>>();
        assert_eq!(before_lines, vec!["second line"]);
        assert_eq!(after_lines, vec!["_first line", "_second line"]);
    }

    #[tokio::test]
    async fn file_max_line_bytes() {
        let dir = tempdir().unwrap();
        let config = file::FileConfig {
            include: vec![dir.path().join("*")],
            max_line_bytes: 10,
            ..test_default_file_config(&dir)
        };

        let path = dir.path().join("file");
        let received = run_file_source(&config, false, NoAcks, LogNamespace::Legacy, None, async {
            let mut file = File::create(&path).unwrap();

            writeln!(&mut file, "short").unwrap();
            writeln!(&mut file, "this is too long").unwrap();
            writeln!(&mut file, "11 eleven11").unwrap();
            let super_long = "This line is super long and will take up more space than BufReader's internal buffer, just to make sure that everything works properly when multiple read calls are involved".repeat(10000);
            writeln!(&mut file, "{super_long}").unwrap();
            writeln!(&mut file, "exactly 10").unwrap();
            writeln!(&mut file, "it can end on a line that's too long").unwrap();

            file.flush().unwrap();
            sleep_500_millis().await;
            sleep_500_millis().await;

            writeln!(&mut file, "and then continue").unwrap();
            writeln!(&mut file, "last short").unwrap();
            file.flush().unwrap();

            sleep_500_millis().await;
            sleep_500_millis().await;
        }).await;

        let received = extract_messages_value(received);

        assert_eq!(
            received,
            vec!["short".into(), "exactly 10".into(), "last short".into()]
        );
    }

    #[tokio::test]
    async fn test_multi_line_aggregation_legacy() {
        let dir = tempdir().unwrap();
        let config = file::FileConfig {
            include: vec![dir.path().join("*")],
            message_start_indicator: Some("INFO".into()),
            multi_line_timeout: 25,
            ..test_default_file_config(&dir)
        };

        let path = dir.path().join("file");
        let event_count = Arc::new(AtomicUsize::new(0));
        let received = run_file_source(
            &config,
            false,
            NoAcks,
            LogNamespace::Legacy,
            Some(Arc::clone(&event_count)),
            async {
                let mut file = File::create(&path).unwrap();

                // Write all lines through the second "INFO hello". Events 1-4
                // are emitted immediately by EndExclude; event 5 ("INFO hello"
                // standalone) requires the 25ms timeout to fire.
                writeln!(&mut file, "leftover foo").unwrap();
                writeln!(&mut file, "INFO hello").unwrap();
                writeln!(&mut file, "INFO goodbye").unwrap();
                writeln!(&mut file, "part of goodbye").unwrap();
                writeln!(&mut file, "INFO hi again").unwrap();
                writeln!(&mut file, "and some more").unwrap();
                writeln!(&mut file, "INFO hello").unwrap();
                file.flush().unwrap();

                // Block until event 5 is observed: the timeout fired and
                // "INFO hello" was emitted before we write "too slow".
                wait_for_atomic_usize_timeout_ms(Arc::clone(&event_count), |n| n >= 5, 500).await;

                writeln!(&mut file, "too slow").unwrap();
                writeln!(&mut file, "INFO doesn't have").unwrap();
                writeln!(&mut file, "to be INFO in").unwrap();
                writeln!(&mut file, "the middle").unwrap();
                file.flush().unwrap();

                // Wait for events 6 ("too slow") and 7 ("INFO doesn't have")
                // before triggering shutdown.
                wait_for_atomic_usize_timeout_ms(Arc::clone(&event_count), |n| n >= 7, 500).await;
            },
        )
        .await;

        let received = extract_messages_value(received);

        assert_eq!(
            received,
            vec![
                "leftover foo".into(),
                "INFO hello".into(),
                "INFO goodbye\npart of goodbye".into(),
                "INFO hi again\nand some more".into(),
                "INFO hello".into(),
                "too slow".into(),
                "INFO doesn't have".into(),
                "to be INFO in\nthe middle".into(),
            ]
        );
    }

    #[tokio::test]
    async fn test_multi_line_aggregation() {
        let dir = tempdir().unwrap();
        let config = file::FileConfig {
            include: vec![dir.path().join("*")],
            multiline: Some(MultilineConfig {
                start_pattern: "INFO".to_owned(),
                condition_pattern: "INFO".to_owned(),
                mode: line_agg::Mode::HaltBefore,
                timeout_ms: Duration::from_millis(25),
            }),
            ..test_default_file_config(&dir)
        };

        let path = dir.path().join("file");
        let event_count = Arc::new(AtomicUsize::new(0));
        let received = run_file_source(
            &config,
            false,
            NoAcks,
            LogNamespace::Legacy,
            Some(Arc::clone(&event_count)),
            async {
                let mut file = File::create(&path).unwrap();

                // Write all lines through the second "INFO hello". Events 1-4
                // are emitted immediately by EndExclude; event 5 ("INFO hello"
                // standalone) requires the 25ms timeout to fire.
                writeln!(&mut file, "leftover foo").unwrap();
                writeln!(&mut file, "INFO hello").unwrap();
                writeln!(&mut file, "INFO goodbye").unwrap();
                writeln!(&mut file, "part of goodbye").unwrap();
                writeln!(&mut file, "INFO hi again").unwrap();
                writeln!(&mut file, "and some more").unwrap();
                writeln!(&mut file, "INFO hello").unwrap();
                file.flush().unwrap();

                // Block until event 5 is observed: the timeout fired and
                // "INFO hello" was emitted before we write "too slow".
                wait_for_atomic_usize_timeout_ms(Arc::clone(&event_count), |n| n >= 5, 500).await;

                writeln!(&mut file, "too slow").unwrap();
                writeln!(&mut file, "INFO doesn't have").unwrap();
                writeln!(&mut file, "to be INFO in").unwrap();
                writeln!(&mut file, "the middle").unwrap();
                file.flush().unwrap();

                // Wait for events 6 ("too slow") and 7 ("INFO doesn't have")
                // before triggering shutdown.
                wait_for_atomic_usize_timeout_ms(Arc::clone(&event_count), |n| n >= 7, 500).await;
            },
        )
        .await;

        let received = extract_messages_value(received);

        assert_eq!(
            received,
            vec![
                "leftover foo".into(),
                "INFO hello".into(),
                "INFO goodbye\npart of goodbye".into(),
                "INFO hi again\nand some more".into(),
                "INFO hello".into(),
                "too slow".into(),
                "INFO doesn't have".into(),
                "to be INFO in\nthe middle".into(),
            ]
        );
    }

    #[tokio::test]
    async fn test_multi_line_checkpointing() {
        let dir = tempdir().unwrap();
        let config = file::FileConfig {
            include: vec![dir.path().join("*")],
            offset_key: Some(OptionalValuePath::from(owned_value_path!("offset"))),
            multiline: Some(MultilineConfig {
                start_pattern: "INFO".to_owned(),
                condition_pattern: "INFO".to_owned(),
                mode: line_agg::Mode::HaltBefore,
                timeout_ms: Duration::from_millis(25), // less than 50 in sleep()
            }),
            ..test_default_file_config(&dir)
        };

        let path = dir.path().join("file");
        let mut file = File::create(&path).unwrap();

        writeln!(&mut file, "INFO hello").unwrap();
        writeln!(&mut file, "part of hello").unwrap();

        file.sync_all().unwrap();

        // Read and aggregate existing lines. wait_shutdown=true ensures the
        // checkpoint is fully written to disk before the second run reads it.
        let received = run_file_source(
            &config,
            true,
            Acks,
            LogNamespace::Legacy,
            None,
            sleep_500_millis(),
        )
        .await;

        assert_eq!(received[0].as_log()["offset"], 0.into());

        let lines = extract_messages_string(received);
        assert_eq!(lines, vec!["INFO hello\npart of hello"]);

        // After restart, we should not see any part of the previously aggregated lines
        let received_after_restart =
            run_file_source(&config, false, Acks, LogNamespace::Legacy, None, async {
                writeln!(&mut file, "INFO goodbye").unwrap();
                file.flush().unwrap();
                sleep_500_millis().await;
            })
            .await;
        assert_eq!(
            received_after_restart[0].as_log()["offset"],
            (lines[0].len() + 1).into()
        );
        let lines = extract_messages_string(received_after_restart);
        assert_eq!(lines, vec!["INFO goodbye"]);
    }

    #[tokio::test]
    async fn test_fair_reads() {
        let dir = tempdir().unwrap();
        let config = file::FileConfig {
            include: vec![dir.path().join("*")],
            max_read_bytes: 1,
            oldest_first: false,
            ..test_default_file_config(&dir)
        };

        let older_path = dir.path().join("z_older_file");
        let mut older = File::create(&older_path).unwrap();

        writeln!(&mut older, "hello i am the old file").unwrap();
        writeln!(&mut older, "i have been around a while").unwrap();
        writeln!(&mut older, "you can read newer files at the same time").unwrap();
        older.sync_all().unwrap();

        let newer_path = dir.path().join("a_newer_file");
        let mut newer = File::create(&newer_path).unwrap();

        writeln!(&mut newer, "and i am the new file").unwrap();
        writeln!(&mut newer, "this should be interleaved with the old one").unwrap();
        writeln!(&mut newer, "which is fine because we want fairness").unwrap();
        newer.sync_all().unwrap();

        let received = run_file_source(
            &config,
            false,
            NoAcks,
            LogNamespace::Legacy,
            None,
            sleep_500_millis(),
        )
        .await;

        let received = extract_messages_value(received);

        let old_first = vec![
            "hello i am the old file".into(),
            "and i am the new file".into(),
            "i have been around a while".into(),
            "this should be interleaved with the old one".into(),
            "you can read newer files at the same time".into(),
            "which is fine because we want fairness".into(),
        ];
        let new_first: Vec<_> = old_first
            .chunks(2)
            .flat_map(|chunk| chunk.iter().rev().cloned().collect::<Vec<_>>())
            .collect();

        if received[0] == old_first[0] {
            assert_eq!(received, old_first);
        } else {
            assert_eq!(received, new_first);
        }
    }

    #[tokio::test]
    async fn test_oldest_first() {
        let dir = tempdir().unwrap();
        let config = file::FileConfig {
            include: vec![dir.path().join("*")],
            max_read_bytes: 1,
            oldest_first: true,
            ..test_default_file_config(&dir)
        };

        let older_path = dir.path().join("z_older_file");
        let mut older = File::create(&older_path).unwrap();
        older.sync_all().unwrap();

        // Sleep to ensure the creation timestamps are different
        sleep_500_millis().await;

        let newer_path = dir.path().join("a_newer_file");
        let mut newer = File::create(&newer_path).unwrap();
        newer.sync_all().unwrap();

        writeln!(&mut older, "hello i am the old file").unwrap();
        writeln!(&mut older, "i have been around a while").unwrap();
        writeln!(&mut older, "you should definitely read all of me first").unwrap();
        older.flush().unwrap();

        writeln!(&mut newer, "i'm new").unwrap();
        writeln!(&mut newer, "hopefully you read all the old stuff first").unwrap();
        writeln!(&mut newer, "because otherwise i'm not going to make sense").unwrap();
        newer.flush().unwrap();

        let received = run_file_source(
            &config,
            false,
            NoAcks,
            LogNamespace::Legacy,
            None,
            sleep_500_millis(),
        )
        .await;

        let received = extract_messages_value(received);

        assert_eq!(
            received,
            vec![
                "hello i am the old file".into(),
                "i have been around a while".into(),
                "you should definitely read all of me first".into(),
                "i'm new".into(),
                "hopefully you read all the old stuff first".into(),
                "because otherwise i'm not going to make sense".into(),
            ]
        );
    }

    #[tokio::test]
    async fn test_split_reads() {
        let dir = tempdir().unwrap();
        let config = file::FileConfig {
            include: vec![dir.path().join("*")],
            max_read_bytes: 1,
            ..test_default_file_config(&dir)
        };

        let path = dir.path().join("file");
        let mut file = File::create(&path).unwrap();

        writeln!(&mut file, "hello i am a normal line").unwrap();
        file.sync_all().unwrap();

        let received = run_file_source(&config, false, NoAcks, LogNamespace::Legacy, None, async {
            sleep_500_millis().await;

            write!(&mut file, "i am not a full line").unwrap();

            file.flush().unwrap();
            // Longer than the EOF timeout
            sleep_500_millis().await;

            writeln!(&mut file, " until now").unwrap();

            file.flush().unwrap();
            sleep_500_millis().await;
        })
        .await;

        let received = extract_messages_value(received);

        assert_eq!(
            received,
            vec![
                "hello i am a normal line".into(),
                "i am not a full line until now".into(),
            ]
        );
    }

    #[tokio::test]
    async fn test_gzipped_file() {
        let dir = tempdir().unwrap();
        let config = file::FileConfig {
            include: vec![PathBuf::from("tests/data/gzipped.log")],
            // TODO: remove this once files are fingerprinted after decompression
            //
            // Currently, this needs to be smaller than the total size of the compressed file
            // because the fingerprinter tries to read until a newline, which it's not going to see
            // in the compressed data, or this number of bytes. If it hits EOF before that, it
            // can't return a fingerprint because the value would change once more data is written.
            max_line_bytes: 100,
            ..test_default_file_config(&dir)
        };

        let received = run_file_source(
            &config,
            false,
            NoAcks,
            LogNamespace::Legacy,
            None,
            sleep_500_millis(),
        )
        .await;

        let received = extract_messages_value(received);

        assert_eq!(
            received,
            vec![
                "this is a simple file".into(),
                "i have been compressed".into(),
                "in order to make me smaller".into(),
                "but you can still read me".into(),
                "hooray".into(),
            ]
        );
    }

    #[tokio::test]
    async fn test_non_utf8_encoded_file() {
        let dir = tempdir().unwrap();
        let config = file::FileConfig {
            include: vec![PathBuf::from("tests/data/utf-16le.log")],
            encoding: Some(EncodingConfig::explicit(UTF_16LE)),
            ..test_default_file_config(&dir)
        };

        let received = run_file_source(
            &config,
            false,
            NoAcks,
            LogNamespace::Legacy,
            None,
            sleep_500_millis(),
        )
        .await;

        let received = extract_messages_value(received);

        assert_eq!(
            received,
            vec![
                "hello i am a file".into(),
                "i can unicode".into(),
                "but i do so in 16 bits".into(),
                "and when i byte".into(),
                "i become little-endian".into(),
            ]
        );
    }

    #[tokio::test]
    async fn test_non_default_line_delimiter() {
        let dir = tempdir().unwrap();
        let config = file::FileConfig {
            include: vec![dir.path().join("*")],
            line_delimiter: "\r\n".to_string(),
            ..test_default_file_config(&dir)
        };

        let path = dir.path().join("file");
        let received = run_file_source(&config, false, NoAcks, LogNamespace::Legacy, None, async {
            let mut file = File::create(&path).unwrap();

            write!(&mut file, "hello i am a line\r\n").unwrap();
            write!(&mut file, "and i am too\r\n").unwrap();
            write!(&mut file, "CRLF is how we end\r\n").unwrap();
            write!(&mut file, "please treat us well\r\n").unwrap();

            file.flush().unwrap();
            sleep_500_millis().await;
        })
        .await;

        let received = extract_messages_value(received);

        assert_eq!(
            received,
            vec![
                "hello i am a line".into(),
                "and i am too".into(),
                "CRLF is how we end".into(),
                "please treat us well".into()
            ]
        );
    }

    // Regression test for https://github.com/vectordotdev/vector/issues/24027
    // Tests that multi-character delimiters (like \r\n) are correctly handled when
    // split across buffer boundaries. Without the fix, events would be merged together.
    #[tokio::test]
    async fn test_multi_char_delimiter_split_across_buffer_boundary() {
        let dir = tempdir().unwrap();
        let config = file::FileConfig {
            include: vec![dir.path().join("*")],
            line_delimiter: "\r\n".to_string(),
            ..test_default_file_config(&dir)
        };

        let path = dir.path().join("file");
        let received = run_file_source(&config, false, NoAcks, LogNamespace::Legacy, None, async {
            let mut file = File::create(&path).unwrap();

            sleep_500_millis().await;

            // Create data where \r\n is split at 8KB buffer boundary
            // This reproduces the exact scenario that caused data corruption:
            // - Event 1 ends with \r at byte 8191
            // - The \n appears at byte 8192 (right at the buffer boundary)
            // - Without the fix, Event 1 and Event 2 would be merged

            let buffer_size = 8192;

            // Event 1: Position \r\n to split at first boundary
            let event1_prefix = "Event 1: ";
            let padding1_len = buffer_size - event1_prefix.len() - 1; // -1 for the \r
            write!(&mut file, "{}", event1_prefix).unwrap();
            file.write_all(&vec![b'X'; padding1_len]).unwrap();
            write!(&mut file, "\r\n").unwrap(); // \r at byte 8191, \n at byte 8192

            // Event 2: Position \r\n to split at second boundary
            let event2_prefix = "Event 2: ";
            let padding2_len = buffer_size - event2_prefix.len() - 1;
            write!(&mut file, "{}", event2_prefix).unwrap();
            file.write_all(&vec![b'Y'; padding2_len]).unwrap();
            write!(&mut file, "\r\n").unwrap(); // \r at byte 16383, \n at byte 16384

            // Event 3: Normal line without boundary split
            write!(&mut file, "Event 3: Final\r\n").unwrap();

            sleep_500_millis().await;
        })
        .await;

        let messages = extract_messages_value(received);

        // The bug would cause Events 1 and 2 to be merged into a single message
        assert_eq!(
            messages.len(),
            3,
            "Should receive exactly 3 separate events (bug would merge them)"
        );

        // Verify each event is correctly separated and starts with expected prefix
        let msg0 = messages[0].to_string_lossy();
        let msg1 = messages[1].to_string_lossy();
        let msg2 = messages[2].to_string_lossy();

        assert!(
            msg0.starts_with("Event 1: "),
            "First event should start with 'Event 1: ', got: {}",
            msg0
        );
        assert!(
            msg1.starts_with("Event 2: "),
            "Second event should start with 'Event 2: ', got: {}",
            msg1
        );
        assert_eq!(msg2, "Event 3: Final");

        // Ensure no event contains embedded CR/LF (sign of incorrect merging)
        for (i, msg) in messages.iter().enumerate() {
            let msg_str = msg.to_string_lossy();
            assert!(
                !msg_str.contains('\r'),
                "Event {} should not contain embedded \\r",
                i
            );
            assert!(
                !msg_str.contains('\n'),
                "Event {} should not contain embedded \\n",
                i
            );
        }
    }

    fn utf16le_bytes(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
    }

    enum TestLogSinkInner {
        Plain(File),
        Gzip(GzEncoder<BufWriter<File>>),
        Finished,
    }

    struct TestLogSink {
        inner: TestLogSinkInner,
    }

    impl Write for TestLogSink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            match &mut self.inner {
                TestLogSinkInner::Plain(file) => file.write(buf),
                TestLogSinkInner::Gzip(encoder) => encoder.write(buf),
                TestLogSinkInner::Finished => Err(std::io::Error::new(
                    std::io::ErrorKind::NotConnected,
                    "gzip stream finished",
                )),
            }
        }

        fn flush(&mut self) -> std::io::Result<()> {
            match &mut self.inner {
                TestLogSinkInner::Plain(file) => file.flush(),
                TestLogSinkInner::Gzip(encoder) => {
                    encoder.flush()?;
                    encoder.get_mut().flush()?;
                    encoder.get_mut().get_mut().sync_all()?;
                    Ok(())
                }
                TestLogSinkInner::Finished => Ok(()),
            }
        }
    }

    impl Drop for TestLogSink {
        fn drop(&mut self) {
            if let TestLogSinkInner::Gzip(encoder) =
                std::mem::replace(&mut self.inner, TestLogSinkInner::Finished)
            {
                let _ = encoder.finish();
            }
        }
    }

    impl TestLogSink {
        fn create(path: &std::path::Path, gzip: bool) -> std::io::Result<Self> {
            if gzip {
                let file = File::create(path)?;
                let encoder = GzEncoder::new(BufWriter::new(file), Compression::default());
                Ok(Self {
                    inner: TestLogSinkInner::Gzip(encoder),
                })
            } else {
                Ok(Self {
                    inner: TestLogSinkInner::Plain(File::create(path)?),
                })
            }
        }
    }

    fn write_complete_gzip_file(path: &std::path::Path, data: &[u8]) {
        let file = File::create(path).unwrap();
        let mut encoder = GzEncoder::new(BufWriter::new(file), Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap();
    }

    /// Append one complete gzip member to `path`, creating the file if needed.
    /// Appending members is the only way a gzip file can grow observably: a
    /// member is not decodable until its trailer is written, and the reader
    /// never picks up bytes added to a file it has already read to EOF, so
    /// each growth step must be a self-contained member that is on disk
    /// before the reader first reaches it.
    fn append_gzip_member(path: &std::path::Path, data: &[u8]) {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap();
        let mut encoder = GzEncoder::new(BufWriter::new(file), Compression::default());
        encoder.write_all(data).unwrap();
        let mut writer = encoder.finish().unwrap();
        writer.flush().unwrap();
    }

    /// Write `data` as the entire file contents (truncating any existing file),
    /// plain or gzip-compressed. For plain files a whole-file rewrite also
    /// models growth: reads go through the file handle's offset, so a
    /// still-Pending watcher drains the rewritten content once it decides. For
    /// gzip a rewrite is only safe while no watcher exists: the watcher
    /// buffers the creation-time compressed bytes when it probes for the gzip
    /// magic, so rewriting a watched gzip file leaves its reader replaying the
    /// old generation. Watched gzip files grow via `append_gzip_member`.
    fn write_whole(path: &std::path::Path, data: &[u8], gzip: bool) {
        if gzip {
            write_complete_gzip_file(path, data);
        } else {
            std::fs::write(path, data).unwrap();
        }
    }

    macro_rules! encoding_auto_plain_and_gzip {
        ($plain:ident, $gzip:ident, $impl_fn:ident) => {
            #[tokio::test]
            async fn $plain() {
                $impl_fn(false).await;
            }

            #[tokio::test]
            async fn $gzip() {
                $impl_fn(true).await;
            }
        };
    }

    async fn encoding_auto_mixed_glob_impl(gzip: bool) {
        let dir = tempdir().unwrap();
        let config = file::FileConfig {
            include: vec![dir.path().join("*")],
            encoding: Some(EncodingConfig {
                auto_detect_min_bytes: Some(32),
                ..EncodingConfig::auto()
            }),
            ..test_default_file_config(&dir)
        };

        let utf8_path = dir.path().join("utf8.log");
        let utf16_path = dir.path().join("utf16.log");
        let counter = Arc::new(AtomicUsize::new(0));
        let received = run_file_source(
            &config,
            false,
            NoAcks,
            LogNamespace::Legacy,
            Some(Arc::clone(&counter)),
            async {
                {
                    let mut utf8 = TestLogSink::create(&utf8_path, gzip).unwrap();
                    // Meet min_bytes with UTF-8 content.
                    let line = format!("{}\n", "u".repeat(64));
                    write!(&mut utf8, "{line}").unwrap();
                    utf8.flush().unwrap();
                }

                {
                    let mut utf16 = TestLogSink::create(&utf16_path, gzip).unwrap();
                    let payload = utf16le_bytes(&format!("{}\n", "v".repeat(64)));
                    utf16.write_all(&payload).unwrap();
                    utf16.flush().unwrap();
                }

                // Both files emit one line; wait for them rather than a fixed sleep.
                wait_for_atomic_usize_timeout_ms(Arc::clone(&counter), |n| n >= 2, 5_000).await;
            },
        )
        .await;

        let received = extract_messages_string(received);
        assert!(
            received.iter().any(|m| m.contains('u')),
            "expected utf-8 file lines, got {received:?}"
        );
        assert!(
            received.iter().any(|m| m.contains('v')),
            "expected utf-16 file lines, got {received:?}"
        );
        assert!(
            received.iter().all(|m| !m.contains('\0')),
            "decoded lines must not contain NUL, got {received:?}"
        );
    }

    encoding_auto_plain_and_gzip!(
        test_encoding_auto_mixed_glob,
        test_encoding_auto_mixed_glob_gzip,
        encoding_auto_mixed_glob_impl
    );

    async fn encoding_auto_rotation_redetect_impl(gzip: bool) {
        let dir = tempdir().unwrap();
        let config = file::FileConfig {
            include: vec![dir.path().join("app.log")],
            encoding: Some(EncodingConfig {
                auto_detect_min_bytes: Some(32),
                ..EncodingConfig::auto()
            }),
            ..test_default_file_config(&dir)
        };

        let path = dir.path().join("app.log");
        let rotated = dir.path().join("app.log.1");
        let received = run_file_source(&config, false, NoAcks, LogNamespace::Legacy, None, async {
            {
                let mut file = TestLogSink::create(&path, gzip).unwrap();
                let first = format!("{}\n", "a".repeat(64));
                write!(&mut file, "{first}").unwrap();
                file.flush().unwrap();
            }
            sleep_500_millis().await;

            // Rotate: move old file aside, create new file with different encoding.
            std::fs::rename(&path, &rotated).unwrap();
            {
                let mut file = TestLogSink::create(&path, gzip).unwrap();
                let payload = utf16le_bytes(&format!("{}\n", "b".repeat(64)));
                file.write_all(&payload).unwrap();
                file.flush().unwrap();
            }
            sleep(Duration::from_millis(800)).await;
        })
        .await;

        let received = extract_messages_string(received);
        assert!(
            received.iter().any(|m| m.contains('a')),
            "missing first-generation utf-8 lines: {received:?}"
        );
        assert!(
            received.iter().any(|m| m.contains('b')),
            "missing rotated utf-16 lines: {received:?}"
        );
    }

    encoding_auto_plain_and_gzip!(
        test_encoding_auto_rotation_redetect,
        test_encoding_auto_rotation_redetect_gzip,
        encoding_auto_rotation_redetect_impl
    );

    // Rename rotation where the rotated name still matches the glob: the Pending
    // watcher first sees an inode mismatch at its old path (stays Pending, never
    // Rejected), then the glob pass remaps it to the rotated path where it
    // decides and drains its content.
    #[tokio::test]
    async fn test_encoding_auto_rotation_in_glob_remaps_and_drains() {
        let dir = tempdir().unwrap();
        let config = file::FileConfig {
            include: vec![dir.path().join("*")],
            encoding: Some(EncodingConfig {
                auto_detect_min_bytes: Some(64),
                ..EncodingConfig::auto()
            }),
            ..test_default_file_config(&dir)
        };

        let path = dir.path().join("app.log");
        let rotated = dir.path().join("app.log.rotated");
        // Staged outside the glob (subdirectories are not matched).
        let staging = dir.path().join(".data").join("gen2.log");
        let decoy = dir.path().join("decoy.log");
        let counter = Arc::new(AtomicUsize::new(0));
        let received = run_file_source(
            &config,
            false,
            NoAcks,
            LogNamespace::Legacy,
            Some(Arc::clone(&counter)),
            async {
                // Sub-min but newline-terminated: fingerprints, stays Pending.
                std::fs::write(&path, b"tiny gen one\n").unwrap();
                {
                    let mut decoy_file = File::create(&decoy).unwrap();
                    writeln!(&mut decoy_file, "{}", "d".repeat(70)).unwrap();
                }
                // Causal checkpoint: decoy emission proves a full server pass ran
                // with generation one still Pending.
                wait_for_atomic_usize_timeout_ms(Arc::clone(&counter), |n| n >= 1, 5_000).await;
                assert_eq!(counter.load(Ordering::SeqCst), 1);

                // Rotate without ever leaving the path absent: hard-link the old
                // inode to the rotated name, then atomically replace the path with
                // generation two. The old watcher can therefore only observe a
                // same-path inode mismatch (never NotFound) until the glob pass
                // remaps it to the rotated name.
                std::fs::hard_link(&path, &rotated).unwrap();
                std::fs::write(&staging, format!("{}\n", "r".repeat(70))).unwrap();
                std::fs::rename(&staging, &path).unwrap();

                // Grow the rotated file past min_bytes with a second complete
                // line; the unchanged first line keeps the fingerprint matching
                // the old watcher.
                let mut tail = std::fs::OpenOptions::new()
                    .append(true)
                    .open(&rotated)
                    .unwrap();
                writeln!(&mut tail, "{}", "k".repeat(70)).unwrap();
                tail.flush().unwrap();

                // decoy + generation two + both rotated lines.
                wait_for_atomic_usize_timeout_ms(Arc::clone(&counter), |n| n >= 4, 5_000).await;
            },
        )
        .await;

        let received = extract_messages_string(received);
        assert!(
            received.iter().any(|m| m == "tiny gen one"),
            "rotated file must drain its pre-rotation line after remap: {received:?}"
        );
        assert!(
            received.iter().any(|m| m.contains('k')),
            "rotated file must drain its post-rotation line: {received:?}"
        );
        assert!(
            received.iter().any(|m| m.contains('r')),
            "generation two must emit through its own watcher: {received:?}"
        );
        assert!(
            received.iter().all(|m| !m.contains('\u{FFFD}')),
            "nothing may be rejected or mangled during rotation: {received:?}"
        );
    }

    async fn encoding_auto_empty_grow_utf16_impl(gzip: bool) {
        let dir = tempdir().unwrap();
        let config = file::FileConfig {
            include: vec![dir.path().join("*")],
            encoding: Some(EncodingConfig {
                auto_detect_min_bytes: Some(32),
                ..EncodingConfig::auto()
            }),
            ..test_default_file_config(&dir)
        };

        let path = dir.path().join("grow.log");
        let counter = Arc::new(AtomicUsize::new(0));
        let received = run_file_source(
            &config,
            false,
            NoAcks,
            LogNamespace::Legacy,
            Some(Arc::clone(&counter)),
            async {
                // Empty file: below min, must stay Pending.
                write_whole(&path, b"", gzip);
                sleep(Duration::from_millis(300)).await;
                assert_eq!(counter.load(Ordering::SeqCst), 0);

                // Grow past min with a complete UTF-16 line.
                let payload = utf16le_bytes(&format!("{}\n", "g".repeat(64)));
                write_whole(&path, &payload, gzip);
                wait_for_atomic_usize_timeout_ms(Arc::clone(&counter), |n| n >= 1, 5_000).await;
            },
        )
        .await;

        let received = extract_messages_string(received);
        assert_eq!(received.len(), 1);
        assert!(received[0].contains('g'));
        assert!(!received[0].contains('\0'));
    }

    encoding_auto_plain_and_gzip!(
        test_encoding_auto_empty_grow_utf16,
        test_encoding_auto_empty_grow_utf16_gzip,
        encoding_auto_empty_grow_utf16_impl
    );

    async fn encoding_auto_binary_rejected_impl(gzip: bool) {
        let dir = tempdir().unwrap();
        let config = file::FileConfig {
            include: vec![dir.path().join("*")],
            encoding: Some(EncodingConfig {
                auto_detect_min_bytes: Some(32),
                ..EncodingConfig::auto()
            }),
            ..test_default_file_config(&dir)
        };

        let bin_path = dir.path().join("bin.dat");
        let good_path = dir.path().join("good.log");
        let received = run_file_source(&config, false, NoAcks, LogNamespace::Legacy, None, async {
            {
                let mut good = TestLogSink::create(&good_path, gzip).unwrap();
                let line = format!("{}\n", "ok".repeat(32));
                write!(&mut good, "{line}").unwrap();
                good.flush().unwrap();
            }

            {
                let mut file = TestLogSink::create(&bin_path, gzip).unwrap();
                let mut bytes = vec![0u8; 256];
                for (i, b) in bytes.iter_mut().enumerate() {
                    *b = (i as u8).wrapping_mul(37).wrapping_add(0x80);
                }
                file.write_all(&bytes).unwrap();
                file.flush().unwrap();
            }
            sleep_500_millis().await;
        })
        .await;

        let received = extract_messages_string(received);
        assert!(
            received.iter().all(|m| m.contains("ok")),
            "only the utf-8 companion file should emit, got {received:?}"
        );
        assert!(
            received.iter().all(|m| !m.contains('\u{FFFD}')),
            "rejected binary must not contribute replacement-filled lines: {received:?}"
        );
    }

    encoding_auto_plain_and_gzip!(
        test_encoding_auto_binary_rejected,
        test_encoding_auto_binary_rejected_gzip,
        encoding_auto_binary_rejected_impl
    );

    async fn encoding_auto_ratio_zero_allows_binary_impl(gzip: bool) {
        let dir = tempdir().unwrap();
        let config = file::FileConfig {
            include: vec![dir.path().join("*")],
            encoding: Some(EncodingConfig {
                auto_detect_min_bytes: Some(32),
                max_replacement_ratio: Some(0.0),
                ..EncodingConfig::auto()
            }),
            ..test_default_file_config(&dir)
        };

        let path = dir.path().join("bin.dat");
        let counter = Arc::new(AtomicUsize::new(0));
        let received = run_file_source(
            &config,
            false,
            NoAcks,
            LogNamespace::Legacy,
            Some(Arc::clone(&counter)),
            async {
                {
                    let mut file = TestLogSink::create(&path, gzip).unwrap();
                    // Invalid UTF-8 that still frames on `\n` under fallback UTF-8.
                    let mut bytes = vec![0x80u8; 64];
                    bytes.push(b'\n');
                    file.write_all(&bytes).unwrap();
                    file.flush().unwrap();
                }
                wait_for_atomic_usize_timeout_ms(Arc::clone(&counter), |n| n >= 1, 5_000).await;
            },
        )
        .await;

        assert!(
            !received.is_empty(),
            "ratio 0 must not reject; got no events"
        );
    }

    encoding_auto_plain_and_gzip!(
        test_encoding_auto_ratio_zero_allows_binary,
        test_encoding_auto_ratio_zero_allows_binary_gzip,
        encoding_auto_ratio_zero_allows_binary_impl
    );

    async fn encoding_auto_bom_stripped_from_event_impl(gzip: bool) {
        let dir = tempdir().unwrap();
        let config = file::FileConfig {
            include: vec![dir.path().join("*")],
            encoding: Some(EncodingConfig {
                auto_detect_min_bytes: Some(128),
                ..EncodingConfig::auto()
            }),
            ..test_default_file_config(&dir)
        };

        let path = dir.path().join("bom.log");
        let received = run_file_source(&config, false, NoAcks, LogNamespace::Legacy, None, async {
            {
                let mut file = TestLogSink::create(&path, gzip).unwrap();
                file.write_all(&[0xef, 0xbb, 0xbf]).unwrap();
                writeln!(&mut file, "hello bom").unwrap();
                file.flush().unwrap();
            }
            sleep_500_millis().await;
        })
        .await;

        let received = extract_messages_string(received);
        assert_eq!(received, vec!["hello bom".to_string()]);
        assert!(!received[0].starts_with('\u{feff}'));
        assert!(!received[0].as_bytes().starts_with(&[0xef, 0xbb, 0xbf]));
    }

    encoding_auto_plain_and_gzip!(
        test_encoding_auto_bom_stripped_from_event,
        test_encoding_auto_bom_stripped_from_event_gzip,
        encoding_auto_bom_stripped_from_event_impl
    );

    async fn encoding_auto_utf16le_bom_impl(gzip: bool) {
        let dir = tempdir().unwrap();
        let config = file::FileConfig {
            include: vec![dir.path().join("*")],
            encoding: Some(EncodingConfig {
                // High min proves the BOM decides regardless of window size.
                auto_detect_min_bytes: Some(1024),
                ..EncodingConfig::auto()
            }),
            ..test_default_file_config(&dir)
        };

        let path = dir.path().join("bom16.log");
        let counter = Arc::new(AtomicUsize::new(0));
        let received = run_file_source(
            &config,
            false,
            NoAcks,
            LogNamespace::Legacy,
            Some(Arc::clone(&counter)),
            async {
                {
                    let mut file = TestLogSink::create(&path, gzip).unwrap();
                    file.write_all(&[0xff, 0xfe]).unwrap();
                    file.write_all(&utf16le_bytes("hello utf sixteen\n")).unwrap();
                    file.flush().unwrap();
                }
                wait_for_atomic_usize_timeout_ms(Arc::clone(&counter), |n| n >= 1, 5_000).await;
            },
        )
        .await;

        let received = extract_messages_string(received);
        assert_eq!(received, vec!["hello utf sixteen".to_string()]);
        assert!(!received[0].contains('\u{feff}'));
        assert!(!received[0].contains('\0'));
    }

    encoding_auto_plain_and_gzip!(
        test_encoding_auto_utf16le_bom,
        test_encoding_auto_utf16le_bom_gzip,
        encoding_auto_utf16le_bom_impl
    );

    #[tokio::test]
    async fn test_encoding_auto_resume_mid_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("resume.log");
        let data_dir = dir.path().join(".data");
        fs::create_dir_all(&data_dir).unwrap();

        let make_config = |include: Vec<PathBuf>| file::FileConfig {
            include,
            encoding: Some(EncodingConfig {
                auto_detect_min_bytes: Some(32),
                ..EncodingConfig::auto()
            }),
            data_dir: Some(data_dir.clone()),
            glob_minimum_cooldown_ms: Duration::from_millis(100),
            fingerprint: FingerprintConfig::Checksum {
                ignored_header_bytes: 0,
                lines: 1,
            },
            internal_metrics: FileInternalMetricsConfig {
                include_file_tag: true,
            },
            ..Default::default()
        };

        // First run: ingest both UTF-16 lines with acks so checkpoints advance.
        {
            let mut file = File::create(&path).unwrap();
            let line1 = utf16le_bytes(&format!("{}\n", "r".repeat(40)));
            let line2 = utf16le_bytes(&format!("{}\n", "s".repeat(40)));
            file.write_all(&line1).unwrap();
            file.write_all(&line2).unwrap();
            file.flush().unwrap();

            let received = run_file_source(
                &make_config(vec![path.clone()]),
                true,
                Acks,
                LogNamespace::Legacy,
                None,
                sleep_500_millis(),
            )
            .await;
            let msgs = extract_messages_string(received);
            assert!(msgs.iter().any(|m| m.contains('r')));
            assert!(msgs.iter().any(|m| m.contains('s')));
            assert!(msgs.iter().all(|m| !m.contains('\0')));
        }

        // Second run: append a third line; peek-restore must not re-emit prior lines
        // or NUL-mangle UTF-16 after re-detecting from offset 0.
        {
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap();
            let line3 = utf16le_bytes(&format!("{}\n", "t".repeat(40)));
            file.write_all(&line3).unwrap();
            file.flush().unwrap();

            let received = run_file_source(
                &make_config(vec![path.clone()]),
                false,
                NoAcks,
                LogNamespace::Legacy,
                None,
                sleep_500_millis(),
            )
            .await;
            let msgs = extract_messages_string(received);
            assert!(
                msgs.iter().any(|m| m.contains('t')),
                "expected newly appended line after resume, got {msgs:?}"
            );
            assert!(
                msgs.iter().all(|m| !m.contains('r') && !m.contains('s')),
                "must not re-read checkpointed lines after peek-restore, got {msgs:?}"
            );
            assert!(msgs.iter().all(|m| !m.contains('\0')));
        }
    }

    async fn encoding_auto_fallback_charset_impl(gzip: bool) {
        let dir = tempdir().unwrap();
        let config = file::FileConfig {
            include: vec![dir.path().join("*")],
            encoding: Some(EncodingConfig {
                // Prove the knob: a single-byte fallback can frame raw `\n` bytes that
                // are neither UTF-8 nor UTF-16.
                fallback_charset: Some(encoding_rs::WINDOWS_1252),
                auto_detect_min_bytes: Some(32),
                // Disable reject so inconclusive windows still ingest via fallback.
                max_replacement_ratio: Some(0.0),
                ..EncodingConfig::auto()
            }),
            ..test_default_file_config(&dir)
        };

        // Invalid UTF-8, not BOM, and not UTF-16 NUL-parity: forces fallback_charset.
        let path = dir.path().join("fallback.log");
        let counter = Arc::new(AtomicUsize::new(0));
        let received = run_file_source(
            &config,
            false,
            NoAcks,
            LogNamespace::Legacy,
            Some(Arc::clone(&counter)),
            async {
                {
                    let mut file = TestLogSink::create(&path, gzip).unwrap();
                    let mut bytes = vec![0x80u8; 80];
                    bytes.push(b'\n');
                    assert!(std::str::from_utf8(&bytes).is_err());
                    file.write_all(&bytes).unwrap();
                    file.flush().unwrap();
                }
                wait_for_atomic_usize_timeout_ms(Arc::clone(&counter), |n| n >= 1, 5_000).await;
            },
        )
        .await;

        assert!(
            !received.is_empty(),
            "fallback must still ingest when reject disabled"
        );
    }

    encoding_auto_plain_and_gzip!(
        test_encoding_auto_fallback_charset,
        test_encoding_auto_fallback_charset_gzip,
        encoding_auto_fallback_charset_impl
    );

    async fn encoding_auto_pending_until_min_then_emit_impl(gzip: bool) {
        // Lifecycle: stay Pending across sub-min appends; only emit after size crosses min.
        let dir = tempdir().unwrap();
        let config = file::FileConfig {
            include: vec![dir.path().join("*")],
            encoding: Some(EncodingConfig {
                auto_detect_min_bytes: Some(64),
                ..EncodingConfig::auto()
            }),
            ..test_default_file_config(&dir)
        };

        let path = dir.path().join("drip.log");
        let counter = Arc::new(AtomicUsize::new(0));
        let received = run_file_source(
            &config,
            false,
            NoAcks,
            LogNamespace::Legacy,
            Some(Arc::clone(&counter)),
            async {
                // Empty file: below min.
                write_whole(&path, b"", gzip);
                sleep(Duration::from_millis(200)).await;
                assert_eq!(counter.load(Ordering::SeqCst), 0);

                // Sub-min UTF-16, newline-terminated so the file fingerprints and
                // gets a watcher: "stays Pending" is then enforced by the encoding
                // gate, not by the fingerprinter refusing to watch. Once watched,
                // a gzip file must grow by appended members (a rewrite would leave
                // the watcher replaying its buffered generation-one bytes), while
                // plain growth keeps the whole-file rewrite model.
                if gzip {
                    append_gzip_member(&path, &utf16le_bytes("abcdefghij\n"));
                } else {
                    write_whole(&path, &utf16le_bytes("abcdefghij\n"), false);
                }
                sleep(Duration::from_millis(400)).await;
                assert_eq!(
                    counter.load(Ordering::SeqCst),
                    0,
                    "must stay Pending below auto_detect_min_bytes"
                );

                // Cross min with a second complete line (same first line keeps the
                // fingerprint stable).
                if gzip {
                    append_gzip_member(&path, &utf16le_bytes(&format!("{}\n", "k".repeat(40))));
                } else {
                    let mut payload = utf16le_bytes("abcdefghij\n");
                    payload.extend(utf16le_bytes(&format!("{}\n", "k".repeat(40))));
                    write_whole(&path, &payload, false);
                }
                wait_for_atomic_usize_timeout_ms(Arc::clone(&counter), |n| n >= 2, 5_000).await;
            },
        )
        .await;

        let received = extract_messages_string(received);
        assert_eq!(received.len(), 2, "both lines drain after deciding");
        assert_eq!(received[0], "abcdefghij");
        assert!(received[1].contains('k'));
        assert!(received.iter().all(|m| !m.contains('\0')));
    }

    encoding_auto_plain_and_gzip!(
        test_encoding_auto_pending_until_min_then_emit,
        test_encoding_auto_pending_until_min_then_emit_gzip,
        encoding_auto_pending_until_min_then_emit_impl
    );

    async fn encoding_auto_ratio_under_threshold_allows_impl(gzip: bool) {
        // Sparse invalid UTF-8 → fallback decode with some U+FFFD, ratio well under 0.33.
        let dir = tempdir().unwrap();
        let config = file::FileConfig {
            include: vec![dir.path().join("*")],
            encoding: Some(EncodingConfig {
                auto_detect_min_bytes: Some(32),
                ..EncodingConfig::auto()
            }),
            ..test_default_file_config(&dir)
        };

        let path = dir.path().join("sparse_bad.log");
        let received = run_file_source(&config, false, NoAcks, LogNamespace::Legacy, None, async {
            {
                let mut file = TestLogSink::create(&path, gzip).unwrap();
                let mut bytes = vec![b'a'; 90];
                bytes.extend(std::iter::repeat(0x80u8).take(10));
                bytes.push(b'\n');
                assert!(std::str::from_utf8(&bytes).is_err());
                file.write_all(&bytes).unwrap();
                file.flush().unwrap();
            }
            sleep_500_millis().await;
        })
        .await;

        // Assert on raw message bytes: `to_string_lossy` would introduce U+FFFD at
        // display time and mask whether the decode path actually sanitized the line.
        let received = extract_messages_value(received);
        assert_eq!(
            received.len(),
            1,
            "under-threshold FFFD must not Reject: {received:?}"
        );
        let bytes = received[0].as_bytes().expect("message must be bytes");
        let text = std::str::from_utf8(bytes)
            .expect("fallback-decided UTF-8 must be decoded, not passed through raw");
        assert!(
            text.contains('a'),
            "expected ASCII payload to survive: {text:?}"
        );
        assert!(
            text.contains('\u{FFFD}'),
            "fixture should surface replacements (proves allow-path, not reject): {text:?}"
        );
    }

    encoding_auto_plain_and_gzip!(
        test_encoding_auto_ratio_under_threshold_allows,
        test_encoding_auto_ratio_under_threshold_allows_gzip,
        encoding_auto_ratio_under_threshold_allows_impl
    );

    async fn encoding_auto_sanitize_utf8_replaces_invalid_impl(gzip: bool) {
        // A file detected as UTF-8 can still contain invalid bytes past the
        // detection window (capped at 64 bytes here, inside the clean first
        // line). With `sanitize_utf8` those lines are decoded (U+FFFD
        // substitution) instead of passed through raw. The plain variant grows
        // the file after the decision; the gzip variant writes the malformed
        // tail up front because a gzip reader latches EOF once it has decoded
        // every complete member on disk and never sees later appends.
        let dir = tempdir().unwrap();
        let config = file::FileConfig {
            include: vec![dir.path().join("*")],
            encoding: Some(EncodingConfig {
                auto_detect_min_bytes: Some(32),
                auto_detect_max_bytes: Some(64),
                sanitize_utf8: true,
                ..EncodingConfig::auto()
            }),
            ..test_default_file_config(&dir)
        };

        let path = dir.path().join("sanitize.log");
        let counter = Arc::new(AtomicUsize::new(0));
        let received = run_file_source(
            &config,
            false,
            NoAcks,
            LogNamespace::Legacy,
            Some(Arc::clone(&counter)),
            async {
                let mut file = TestLogSink::create(&path, gzip).unwrap();
                // Valid UTF-8 filling the whole detection window: detection
                // decides via strict validation and never sees the bad bytes.
                let clean = format!("{}\n", "a".repeat(64));
                write!(&mut file, "{clean}").unwrap();
                if gzip {
                    file.write_all(b"bad \x80\x81 bytes\n").unwrap();
                    drop(file);
                    wait_for_atomic_usize_timeout_ms(Arc::clone(&counter), |n| n >= 2, 5_000).await;
                } else {
                    file.flush().unwrap();
                    wait_for_atomic_usize_timeout_ms(Arc::clone(&counter), |n| n >= 1, 5_000).await;

                    // Invalid bytes arrive only after the file was decided as UTF-8.
                    file.write_all(b"bad \x80\x81 bytes\n").unwrap();
                    file.flush().unwrap();
                    wait_for_atomic_usize_timeout_ms(Arc::clone(&counter), |n| n >= 2, 5_000).await;
                }
            },
        )
        .await;

        // Raw-bytes assertions: `to_string_lossy` would fabricate U+FFFD at display
        // time and hide an unsanitized pass-through.
        let received = extract_messages_value(received);
        assert_eq!(received.len(), 2, "expected both lines: {received:?}");
        for value in &received {
            let bytes = value.as_bytes().expect("message must be bytes");
            std::str::from_utf8(bytes)
                .expect("sanitize_utf8 must guarantee valid UTF-8 output lines");
        }
        let second = std::str::from_utf8(received[1].as_bytes().unwrap()).unwrap();
        assert!(
            second.contains('\u{FFFD}'),
            "invalid bytes must be replaced at decode time: {second:?}"
        );
        assert!(second.starts_with("bad ") && second.ends_with(" bytes"));
    }

    encoding_auto_plain_and_gzip!(
        test_encoding_auto_sanitize_utf8_replaces_invalid,
        test_encoding_auto_sanitize_utf8_replaces_invalid_gzip,
        encoding_auto_sanitize_utf8_replaces_invalid_impl
    );

    #[tokio::test]
    async fn test_encoding_auto_sanitize_utf8_bom_matches_explicit_utf8() {
        // A UTF-8 BOM file with an invalid byte: `sanitize_utf8` must route it
        // through the decoder so the BOM is stripped and the invalid byte gets
        // U+FFFD, identical to what an explicit `charset: utf-8` run produces.
        const FIXTURE: &[u8] = b"\xEF\xBB\xBFbom line \x80 tail\n";

        async fn run_once(encoding: EncodingConfig) -> Vec<Value> {
            let dir = tempdir().unwrap();
            let config = file::FileConfig {
                include: vec![dir.path().join("*")],
                encoding: Some(encoding),
                ..test_default_file_config(&dir)
            };
            let path = dir.path().join("bom.log");
            write_whole(&path, FIXTURE, false);

            let counter = Arc::new(AtomicUsize::new(0));
            let received = run_file_source(
                &config,
                false,
                NoAcks,
                LogNamespace::Legacy,
                Some(Arc::clone(&counter)),
                async {
                    wait_for_atomic_usize_timeout_ms(Arc::clone(&counter), |n| n >= 1, 5_000).await;
                },
            )
            .await;
            extract_messages_value(received)
        }

        let auto = run_once(EncodingConfig {
            sanitize_utf8: true,
            ..EncodingConfig::auto()
        })
        .await;
        let explicit = run_once(EncodingConfig::explicit(encoding_rs::UTF_8)).await;

        assert_eq!(auto.len(), 1, "expected one sanitized line: {auto:?}");
        assert_eq!(auto, explicit, "auto+sanitize must match explicit utf-8");

        let bytes = auto[0].as_bytes().expect("message must be bytes");
        let text = std::str::from_utf8(bytes).expect("sanitized line must be valid UTF-8");
        assert!(
            !text.starts_with('\u{FEFF}'),
            "BOM must be stripped: {text:?}"
        );
        assert!(
            text.contains('\u{FFFD}'),
            "invalid byte must be replaced: {text:?}"
        );
        assert!(text.starts_with("bom line ") && text.ends_with(" tail"));
    }

    async fn encoding_auto_ignored_header_bytes_compatible_impl(gzip: bool) {
        // Fingerprint skips a fixed header; encoding auto still peeks at offset 0.
        // UTF-16 header + body keeps detection on the UTF-16 ladder for the whole sniff.
        let dir = tempdir().unwrap();
        let path = dir.path().join("hdr.log");
        let data_dir = dir.path().join(".data");
        fs::create_dir_all(&data_dir).unwrap();
        let phase2_data_dir = dir.path().join(".data_phase2");
        fs::create_dir_all(&phase2_data_dir).unwrap();

        // "HEADER!!!\n" is 10 UTF-16 code units → 20 bytes.
        const HEADER_BYTES: usize = 20;
        let header_a = utf16le_bytes("HEADER!!!\n");
        let header_b = utf16le_bytes("HEADER###\n");
        assert_eq!(header_a.len(), HEADER_BYTES);
        assert_eq!(header_b.len(), HEADER_BYTES);

        let make_config = |include: Vec<PathBuf>, data_dir: PathBuf| file::FileConfig {
            include,
            encoding: Some(EncodingConfig {
                auto_detect_min_bytes: Some(32),
                ..EncodingConfig::auto()
            }),
            data_dir: Some(data_dir),
            glob_minimum_cooldown_ms: Duration::from_millis(100),
            fingerprint: FingerprintConfig::Checksum {
                ignored_header_bytes: HEADER_BYTES,
                lines: 1,
            },
            internal_metrics: FileInternalMetricsConfig {
                include_file_tag: true,
            },
            ..Default::default()
        };

        {
            {
                let mut file = TestLogSink::create(&path, gzip).unwrap();
                file.write_all(&header_a).unwrap();
                file.write_all(&utf16le_bytes(&format!("{}\n", "p".repeat(40))))
                    .unwrap();
                file.write_all(&utf16le_bytes(&format!("{}\n", "q".repeat(40))))
                    .unwrap();
                file.flush().unwrap();
            }

            let counter = Arc::new(AtomicUsize::new(0));
            let received = run_file_source(
                &make_config(vec![path.clone()], data_dir.clone()),
                true,
                Acks,
                LogNamespace::Legacy,
                Some(Arc::clone(&counter)),
                async {
                    wait_for_atomic_usize_timeout_ms(Arc::clone(&counter), |n| n >= 3, 5_000).await;
                },
            )
            .await;
            let msgs = extract_messages_string(received);
            // Header line is still ingested (ignore is fingerprint-only).
            assert!(
                msgs.iter().any(|m| m.contains("HEADER!!!")),
                "header line should still be read as content: {msgs:?}"
            );
            assert!(msgs.iter().any(|m| m.contains('p')));
            assert!(msgs.iter().any(|m| m.contains('q')));
            assert!(msgs.iter().all(|m| !m.contains('\0')));
        }

        // Same fingerprint body after a different header; append a new line only.
        {
            let body = {
                let mut b = Vec::new();
                b.extend_from_slice(&utf16le_bytes(&format!("{}\n", "p".repeat(40))));
                b.extend_from_slice(&utf16le_bytes(&format!("{}\n", "q".repeat(40))));
                b.extend_from_slice(&utf16le_bytes(&format!("{}\n", "r".repeat(40))));
                b
            };
            {
                let mut file = TestLogSink::create(&path, gzip).unwrap();
                file.write_all(&header_b).unwrap();
                file.write_all(&body).unwrap();
                file.flush().unwrap();
            }

            let received = run_file_source(
                &make_config(
                    vec![path.clone()],
                    if gzip {
                        phase2_data_dir.clone()
                    } else {
                        data_dir.clone()
                    },
                ),
                false,
                NoAcks,
                LogNamespace::Legacy,
                None,
                sleep_500_millis(),
            )
            .await;
            let msgs = extract_messages_string(received);
            if gzip {
                // Gzip checkpoints are not resumed from a non-zero offset; phase two
                // re-reads the whole member and still auto-detects UTF-16 past the header.
                assert!(
                    msgs.iter().any(|m| m.contains('r')),
                    "gzip rewrite must still emit new body line: {msgs:?}"
                );
                assert!(
                    msgs.iter().any(|m| m.contains("HEADER###")),
                    "gzip rewrite must still read header as content: {msgs:?}"
                );
            } else {
                assert!(
                    msgs.iter().any(|m| m.contains('r')),
                    "checkpoint+fingerprint must resume after header change: {msgs:?}"
                );
                assert!(
                    msgs.iter()
                        .all(|m| !m.contains('p') && !m.contains('q') && !m.contains("HEADER")),
                    "must not re-emit checkpointed header/body lines: {msgs:?}"
                );
            }
            assert!(msgs.iter().all(|m| !m.contains('\0')));
        }
    }

    encoding_auto_plain_and_gzip!(
        test_encoding_auto_ignored_header_bytes_compatible,
        test_encoding_auto_ignored_header_bytes_compatible_gzip,
        encoding_auto_ignored_header_bytes_compatible_impl
    );

    async fn encoding_auto_idle_timeout_force_decide_impl(gzip: bool) {
        let dir = tempdir().unwrap();
        let config = file::FileConfig {
            include: vec![dir.path().join("*")],
            encoding: Some(EncodingConfig {
                auto_detect_min_bytes: Some(1024),
                auto_detect_idle_timeout_secs: Some(0),
                ..EncodingConfig::auto()
            }),
            glob_minimum_cooldown_ms: Duration::from_millis(100),
            ..test_default_file_config(&dir)
        };

        let path = dir.path().join("idle.log");
        let received = run_file_source(&config, false, NoAcks, LogNamespace::Legacy, None, async {
            {
                let mut file = TestLogSink::create(&path, gzip).unwrap();
                writeln!(&mut file, "small idle-timeout line").unwrap();
                file.flush().unwrap();
            }
            sleep_500_millis().await;
        })
        .await;

        let received = extract_messages_string(received);
        assert!(
            received.iter().any(|m| m.contains("idle-timeout")),
            "expected idle-timeout force-decide emit, got {received:?}"
        );
    }

    encoding_auto_plain_and_gzip!(
        test_encoding_auto_idle_timeout_force_decide,
        test_encoding_auto_idle_timeout_force_decide_gzip,
        encoding_auto_idle_timeout_force_decide_impl
    );

    async fn encoding_auto_pending_delete_quiet_impl(gzip: bool) {
        let dir = tempdir().unwrap();
        let config = file::FileConfig {
            include: vec![dir.path().join("*")],
            encoding: Some(EncodingConfig {
                auto_detect_min_bytes: Some(1024),
                auto_detect_idle_timeout_secs: Some(3600),
                ..EncodingConfig::auto()
            }),
            glob_minimum_cooldown_ms: Duration::from_millis(100),
            ..test_default_file_config(&dir)
        };

        let path = dir.path().join("gone.log");
        let decoy = dir.path().join("ok.log");
        let decoy2 = dir.path().join("ok2.log");
        let counter = Arc::new(AtomicUsize::new(0));
        let received = run_file_source(
            &config,
            false,
            NoAcks,
            LogNamespace::Legacy,
            Some(Arc::clone(&counter)),
            async {
                {
                    let mut file = TestLogSink::create(&path, gzip).unwrap();
                    // Newline-terminated so the checksum fingerprinter creates a
                    // watcher; without one the file never enters the Pending state
                    // this test exists to exercise.
                    writeln!(&mut file, "tiny").unwrap();
                    file.flush().unwrap();
                }

                // Causal checkpoint: the decoy is written only after the fixture
                // exists, so its emit proves a full server pass has seen (and
                // watched) the still-Pending fixture. No timing guess. Each decoy
                // is a closed, self-contained file: a gzip member only becomes
                // decodable once its trailer is written, and a gzip reader never
                // sees lines appended after it reached EOF.
                {
                    let mut ok = TestLogSink::create(&decoy, gzip).unwrap();
                    writeln!(&mut ok, "{}", "z".repeat(1100)).unwrap();
                    ok.flush().unwrap();
                }
                wait_for_atomic_usize_timeout_ms(Arc::clone(&counter), |n| n >= 1, 5_000).await;

                std::fs::remove_file(&path).unwrap();

                // Second decoy file: its emit proves at least one further full
                // pass ran after the deletion, so the zero assert below is not
                // vacuously early. Distinct content keeps its checksum
                // fingerprint separate from the first decoy's.
                {
                    let mut ok2 = TestLogSink::create(&decoy2, gzip).unwrap();
                    writeln!(&mut ok2, "{}", "y".repeat(1100)).unwrap();
                    ok2.flush().unwrap();
                }
                wait_for_atomic_usize_timeout_ms(Arc::clone(&counter), |n| n >= 2, 5_000).await;
            },
        )
        .await;

        let received = extract_messages_string(received);
        assert!(
            received.iter().any(|m| m.contains('z')),
            "first decoy line must emit: {received:?}"
        );
        assert!(
            received.iter().any(|m| m.contains('y')),
            "second decoy line must emit: {received:?}"
        );
        assert!(
            !received.iter().any(|m| m.contains("tiny")),
            "deleted Pending file must not emit lines: {received:?}"
        );
    }

    encoding_auto_plain_and_gzip!(
        test_encoding_auto_pending_delete_quiet,
        test_encoding_auto_pending_delete_quiet_gzip,
        encoding_auto_pending_delete_quiet_impl
    );

    async fn encoding_auto_remove_after_pending_ships_then_removes_impl(gzip: bool) {
        // A sub-min Pending file must get its idle-timeout decision (and ship
        // its content) before remove_after may delete it, even when the grace
        // period is shorter than the idle timeout. After the decision, the
        // regular remove_after path reaps the file.
        let dir = tempdir().unwrap();
        let path = dir.path().join("pending_remove.log");
        let config = file::FileConfig {
            include: vec![dir.path().join("*")],
            remove_after_secs: Some(0),
            encoding: Some(EncodingConfig {
                auto_detect_min_bytes: Some(4096),
                auto_detect_max_bytes: Some(8192),
                auto_detect_idle_timeout_secs: Some(1),
                ..EncodingConfig::auto()
            }),
            glob_minimum_cooldown_ms: Duration::from_millis(50),
            ..test_default_file_config(&dir)
        };

        // Newline-terminated so the fingerprinter creates a watcher and the file
        // actually reaches the Pending state whose deletion floor is under test.
        write_whole(&path, b"ships before removal\n", gzip);

        let counter = Arc::new(AtomicUsize::new(0));
        let received = run_file_source(
            &config,
            false,
            NoAcks,
            LogNamespace::Legacy,
            Some(Arc::clone(&counter)),
            async {
                // The idle force-decide must fire and ship the line first.
                // Generous bound: Pending re-peeks are throttled like read
                // attempts and can take a full throttle interval to land.
                wait_for_atomic_usize_timeout_ms(Arc::clone(&counter), |n| n >= 1, 15_000).await;
                for _ in 0..100 {
                    if !path.exists() {
                        break;
                    }
                    sleep(Duration::from_millis(100)).await;
                }
            },
        )
        .await;

        let received = extract_messages_string(received);
        assert!(
            received.iter().any(|m| m.contains("ships before removal")),
            "sub-min content must decide and ship before removal: {received:?}"
        );
        assert!(!path.exists(), "remove_after must delete the file once it shipped");
    }

    encoding_auto_plain_and_gzip!(
        test_encoding_auto_remove_after_pending_ships_then_removes,
        test_encoding_auto_remove_after_pending_ships_then_removes_gzip,
        encoding_auto_remove_after_pending_ships_then_removes_impl
    );

    async fn encoding_auto_remove_after_rejected_impl(gzip: bool) {
        // Rejected files skip reading but must still honor remove_after.
        let dir = tempdir().unwrap();
        let path = dir.path().join("bin.dat");
        let decoy = dir.path().join("ok.log");
        let config = file::FileConfig {
            include: vec![dir.path().join("*")],
            remove_after_secs: Some(0),
            encoding: Some(EncodingConfig {
                auto_detect_min_bytes: Some(32),
                ..EncodingConfig::auto()
            }),
            glob_minimum_cooldown_ms: Duration::from_millis(50),
            ..test_default_file_config(&dir)
        };

        let received = run_file_source(&config, false, NoAcks, LogNamespace::Legacy, None, async {
            {
                let mut good = TestLogSink::create(&decoy, gzip).unwrap();
                writeln!(&mut good, "{}", "ok".repeat(32)).unwrap();
                good.flush().unwrap();
            }
            {
                let mut file = TestLogSink::create(&path, gzip).unwrap();
                // High-entropy bytes: invalid UTF-8, not UTF-16-looking, rejected
                // by the replacement-ratio gate. The pattern contains a 0x0A so
                // the file fingerprints and gets a watcher.
                let mut bytes = vec![0u8; 256];
                for (i, b) in bytes.iter_mut().enumerate() {
                    *b = (i as u8).wrapping_mul(37).wrapping_add(0x80);
                }
                file.write_all(&bytes).unwrap();
                file.flush().unwrap();
            }
            for _ in 0..50 {
                if !path.exists() {
                    break;
                }
                sleep(Duration::from_millis(100)).await;
            }
        })
        .await;

        let received = extract_messages_string(received);
        assert!(
            received.iter().all(|m| m.contains("ok")),
            "only the utf-8 companion file should emit: {received:?}"
        );
        assert!(!path.exists(), "remove_after must reap Rejected files");
    }

    encoding_auto_plain_and_gzip!(
        test_encoding_auto_remove_after_rejected,
        test_encoding_auto_remove_after_rejected_gzip,
        encoding_auto_remove_after_rejected_impl
    );

    async fn remove_after_fixed_charset_ships_then_removes_impl(gzip: bool) {
        // Reap-parity sibling: the same short file that stays quiet under auto
        // detection (Pending) ships its content under a fixed charset and is then
        // removed after the grace period.
        let dir = tempdir().unwrap();
        let path = dir.path().join("pending_remove.log");
        let config = file::FileConfig {
            include: vec![dir.path().join("*")],
            remove_after_secs: Some(1),
            encoding: Some(EncodingConfig::explicit(encoding_rs::UTF_8)),
            glob_minimum_cooldown_ms: Duration::from_millis(50),
            ..test_default_file_config(&dir)
        };

        write_whole(&path, b"stay pending\n", gzip);

        let counter = Arc::new(AtomicUsize::new(0));
        let received = run_file_source(
            &config,
            false,
            NoAcks,
            LogNamespace::Legacy,
            Some(Arc::clone(&counter)),
            async {
                wait_for_atomic_usize_timeout_ms(Arc::clone(&counter), |n| n >= 1, 5_000).await;
                for _ in 0..100 {
                    if !path.exists() {
                        break;
                    }
                    sleep(Duration::from_millis(100)).await;
                }
            },
        )
        .await;

        let received = extract_messages_string(received);
        assert!(
            received.iter().any(|m| m.contains("stay pending")),
            "fixed charset must read the content before removal: {received:?}"
        );
        assert!(
            !path.exists(),
            "remove_after must remove the file after it shipped"
        );
    }

    encoding_auto_plain_and_gzip!(
        test_remove_after_fixed_charset_ships_then_removes,
        test_remove_after_fixed_charset_ships_then_removes_gzip,
        remove_after_fixed_charset_ships_then_removes_impl
    );

    // A sub-min Pending file whose mtime predates the `remove_after` grace period
    // must still get its idle-timeout decision (and ship its content) before any
    // deletion: the grace clock is anchored on watch start, not on mtime.
    #[cfg(unix)] // uses unix-specific `futimes` to backdate the mtime
    #[tokio::test]
    async fn test_encoding_auto_remove_after_backdated_mtime_ships_first() {
        use std::{os::unix::io::AsRawFd, time::SystemTime};

        let dir = tempdir().unwrap();
        let config = file::FileConfig {
            include: vec![dir.path().join("*")],
            remove_after_secs: Some(30),
            encoding: Some(EncodingConfig {
                auto_detect_min_bytes: Some(1024),
                auto_detect_idle_timeout_secs: Some(1),
                ..EncodingConfig::auto()
            }),
            glob_minimum_cooldown_ms: Duration::from_millis(100),
            ..test_default_file_config(&dir)
        };

        let path = dir.path().join("old.log");
        {
            let mut file = File::create(&path).unwrap();
            writeln!(&mut file, "backdated but alive").unwrap();
            file.flush().unwrap();

            // Backdate the mtime well beyond the remove_after grace period.
            let old = SystemTime::now() - std::time::Duration::from_secs(120);
            let old_time = libc::timeval {
                tv_sec: old
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as _,
                tv_usec: 0,
            };
            let old_times = [old_time, old_time];
            unsafe {
                libc::futimes(file.as_raw_fd(), old_times.as_ptr());
            }
            file.sync_all().unwrap();
        }

        let counter = Arc::new(AtomicUsize::new(0));
        let received = run_file_source(
            &config,
            false,
            NoAcks,
            LogNamespace::Legacy,
            Some(Arc::clone(&counter)),
            async {
                // Re-peeks of a Pending file are throttled like read attempts, so
                // the idle decision can take a full throttle interval to land.
                wait_for_atomic_usize_timeout_ms(Arc::clone(&counter), |n| n >= 1, 15_000).await;
            },
        )
        .await;

        let received = extract_messages_string(received);
        assert!(
            received.iter().any(|m| m.contains("backdated")),
            "sub-min file must ship via idle decide before remove_after: {received:?}"
        );
        assert!(
            path.exists(),
            "grace anchored on watch start must not have elapsed yet"
        );
    }

    // After a rename rotation the Pending watcher's path can point at a different
    // file; `remove_after` must never delete that file based on the old watcher's
    // state and clocks.
    #[tokio::test]
    async fn test_encoding_auto_remove_after_skips_replaced_path() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("watched.log");
        let decoy = dir.path().join("decoy.log");
        // Staged outside the glob (subdirectories are not matched).
        let staging = dir.path().join(".data").join("replacement.log");
        let config = file::FileConfig {
            include: vec![dir.path().join("*.log")],
            remove_after_secs: Some(2),
            encoding: Some(EncodingConfig {
                auto_detect_min_bytes: Some(1024),
                auto_detect_idle_timeout_secs: Some(3600),
                ..EncodingConfig::auto()
            }),
            glob_minimum_cooldown_ms: Duration::from_millis(100),
            ..test_default_file_config(&dir)
        };

        let counter = Arc::new(AtomicUsize::new(0));
        let received = run_file_source(
            &config,
            false,
            NoAcks,
            LogNamespace::Legacy,
            Some(Arc::clone(&counter)),
            async {
                std::fs::write(&path, b"tiny pending\n").unwrap();
                {
                    let mut decoy_file = File::create(&decoy).unwrap();
                    writeln!(&mut decoy_file, "{}", "d".repeat(1100)).unwrap();
                }
                // Decoy emission proves a full server pass ran: the watched file
                // has a watcher by now and stays Pending (sub-min, huge idle).
                wait_for_atomic_usize_timeout_ms(Arc::clone(&counter), |n| n >= 1, 5_000).await;

                // Atomically replace the watched path with a different file: the
                // old watcher's inode is unlinked and the path now belongs to the
                // replacement (which gets its own watcher and emits).
                std::fs::write(&staging, format!("{}\n", "r".repeat(1100))).unwrap();
                std::fs::rename(&staging, &path).unwrap();
                wait_for_atomic_usize_timeout_ms(Arc::clone(&counter), |n| n >= 2, 5_000).await;

                // Outlive the old watcher's grace period; periodic appends keep
                // the replacement's own remove_after clock fresh.
                let mut keep_alive = std::fs::OpenOptions::new()
                    .append(true)
                    .open(&path)
                    .unwrap();
                for i in 0..10 {
                    writeln!(&mut keep_alive, "keep alive {i}").unwrap();
                    keep_alive.flush().unwrap();
                    sleep(Duration::from_millis(300)).await;
                }
            },
        )
        .await;

        let received = extract_messages_string(received);
        assert!(
            received.iter().any(|m| m.contains('r')),
            "replacement file must emit through its own watcher: {received:?}"
        );
        assert!(
            !received.iter().any(|m| m.contains("tiny")),
            "the replaced Pending file was never decided and must not emit: {received:?}"
        );
        assert!(
            path.exists(),
            "old Pending watcher must not delete the file now occupying its path"
        );
    }

    #[tokio::test]
    async fn test_encoding_auto_gzip_rotation_while_pending() {
        // Auto-detect on a gzip stream still below min_bytes, then rotate before
        // deciding; generation two must emit without rejecting during the inode change.
        let dir = tempdir().unwrap();
        let config = file::FileConfig {
            include: vec![dir.path().join("app.log"), dir.path().join("decoy.log")],
            encoding: Some(EncodingConfig {
                auto_detect_min_bytes: Some(64),
                ..EncodingConfig::auto()
            }),
            ..test_default_file_config(&dir)
        };

        let path = dir.path().join("app.log");
        let rotated = dir.path().join("app.log.1");
        let decoy = dir.path().join("decoy.log");
        let counter = Arc::new(AtomicUsize::new(0));
        let received = run_file_source(
            &config,
            false,
            NoAcks,
            LogNamespace::Legacy,
            Some(Arc::clone(&counter)),
            async {
                {
                    let mut gen1 = TestLogSink::create(&path, true).unwrap();
                    // Newline-terminated so gen1 fingerprints and actually enters
                    // Pending; still below min_bytes.
                    writeln!(&mut gen1, "{}", "x".repeat(20)).unwrap();
                    gen1.flush().unwrap();
                }
                // Causal checkpoint: a decoy written after gen1 emits only once a
                // full server pass has processed both files, so asserting the
                // counter afterwards proves gen1 stayed Pending (no timing guess).
                {
                    let mut decoy_sink = TestLogSink::create(&decoy, true).unwrap();
                    writeln!(&mut decoy_sink, "{}", "d".repeat(70)).unwrap();
                    decoy_sink.flush().unwrap();
                }
                wait_for_atomic_usize_timeout_ms(Arc::clone(&counter), |n| n >= 1, 5_000).await;
                assert_eq!(
                    counter.load(Ordering::SeqCst),
                    1,
                    "sub-min pending gzip must not emit; only the decoy may"
                );

                std::fs::rename(&path, &rotated).unwrap();

                {
                    let mut gen2 = TestLogSink::create(&path, true).unwrap();
                    let payload = utf16le_bytes(&format!("{}\n", "q".repeat(64)));
                    gen2.write_all(&payload).unwrap();
                    gen2.flush().unwrap();
                }
                wait_for_atomic_usize_timeout_ms(Arc::clone(&counter), |n| n >= 2, 5_000).await;
            },
        )
        .await;

        let received = extract_messages_string(received);
        assert!(
            received.iter().any(|m| m.contains('q')),
            "rotated generation must emit utf-16 line: {received:?}"
        );
        assert!(
            received.iter().all(|m| !m.contains('\u{FFFD}')),
            "must not reject during rotation: {received:?}"
        );
        assert!(counter.load(Ordering::SeqCst) >= 2);
    }

    #[tokio::test]
    async fn test_encoding_auto_validation_errors() {
        let err = EncodingConfig {
            fallback_charset: Some(encoding_rs::UTF_8),
            ..EncodingConfig::explicit(UTF_16LE)
        }
        .validate_and_resolve();
        assert!(err.is_err());

        let err = EncodingConfig {
            sanitize_utf8: true,
            ..EncodingConfig::explicit(UTF_16LE)
        }
        .validate_and_resolve();
        assert!(err.is_err());

        let ok = EncodingConfig {
            fallback_charset: Some(encoding_rs::UTF_8),
            auto_detect_min_bytes: Some(64),
            auto_detect_max_bytes: Some(1024),
            max_replacement_ratio: Some(0.5),
            sanitize_utf8: true,
            ..EncodingConfig::auto()
        }
        .validate_and_resolve();
        assert!(ok.is_ok());
    }

    #[tokio::test]
    async fn remove_file() {
        let n = 5;
        let remove_after_secs = 1;

        let dir = tempdir().unwrap();
        let config = file::FileConfig {
            include: vec![dir.path().join("*")],
            remove_after_secs: Some(remove_after_secs),
            ..test_default_file_config(&dir)
        };

        let path = dir.path().join("file");
        let received = run_file_source(&config, false, Acks, LogNamespace::Legacy, None, async {
            let mut file = File::create(&path).unwrap();

            for i in 0..n {
                writeln!(&mut file, "{i}").unwrap();
            }
            file.flush().unwrap();
            drop(file);

            for _ in 0..10 {
                // Wait for remove grace period to end.
                sleep(Duration::from_secs(remove_after_secs + 1)).await;

                if File::open(&path).is_err() {
                    break;
                }
            }
        })
        .await;

        assert_eq!(received.len(), n);

        match File::open(&path) {
            Ok(_) => panic!("File wasn't removed"),
            Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::NotFound),
        }
    }

    #[derive(Clone, Copy, Eq, PartialEq)]
    enum AckingMode {
        NoAcks,      // No acknowledgement handling and no finalization
        Unfinalized, // Acknowledgement handling but no finalization
        Acks,        // Full acknowledgements and proper finalization
    }
    use AckingMode::*;
    use vector_lib::lookup::OwnedTargetPath;

    async fn run_file_source(
        config: &FileConfig,
        wait_shutdown: bool,
        acking_mode: AckingMode,
        log_namespace: LogNamespace,
        // When `Some`, events are relayed through an unbounded channel and the
        // counter is incremented for each event received.  The inner future can
        // call `wait_for_atomic_usize` on this counter to gate writes on
        // observed events instead of relying on wall-clock sleeps.
        event_counter: Option<Arc<AtomicUsize>>,
        inner: impl Future<Output = ()>,
    ) -> Vec<Event> {
        assert_source_compliance(&FILE_SOURCE_TAGS, async move {
            let (tx, rx) = match acking_mode {
                Acks => {
                    let (tx, rx) = SourceSender::new_test_finalize(EventStatus::Delivered);
                    (tx, rx.boxed())
                }
                Unfinalized => {
                    // Use Rejected so that events are finalized but checkpoints
                    // are NOT updated (only Delivered triggers checkpoint updates).
                    // This avoids a race where the default Delivered status on drop
                    // could leak checkpoint writes into the next run.
                    let (tx, rx) = SourceSender::new_test_finalize(EventStatus::Rejected);
                    (tx, rx.boxed())
                }
                NoAcks => {
                    let (tx, rx) = SourceSender::new_test();
                    (tx, rx.boxed())
                }
            };

            let (trigger_shutdown, shutdown, shutdown_done) = ShutdownSignal::new_wired();
            let data_dir = config.data_dir.clone().unwrap();
            let acks = !matches!(acking_mode, NoAcks);
            let resolved_auto = config
                .encoding
                .as_ref()
                .and_then(|e| e.validate_and_resolve().expect("test config"));
            let resolved_encoding =
                file::resolve_file_encoding(config, resolved_auto).expect("test config");

            tokio::spawn(file::file_source(
                config,
                data_dir,
                shutdown,
                tx,
                acks,
                log_namespace,
                resolved_encoding,
            ));

            let result = if let Some(counter) = event_counter {
                // Relay mode: a background task forwards events and increments
                // the counter so `inner` can observe them without arbitrary sleeps.
                let (relay_tx, mut relay_rx) = tokio::sync::mpsc::unbounded_channel::<Event>();
                tokio::spawn(async move {
                    let mut rx = rx;
                    while let Some(event) = rx.next().await {
                        counter.fetch_add(1, Ordering::SeqCst);
                        relay_tx.send(event).ok(); // receiver gone means pipeline is shutting down
                    }
                });

                inner.await;
                drop(trigger_shutdown);

                timeout(Duration::from_secs(5), async move {
                    let mut events = Vec::new();
                    while let Some(event) = relay_rx.recv().await {
                        events.push(event);
                    }
                    events
                })
                .await
                .expect("Unclosed channel: may indicate file-server could not shutdown gracefully.")
            } else {
                inner.await;
                drop(trigger_shutdown);

                if acking_mode == Unfinalized {
                    rx.take_until(tokio::time::sleep(Duration::from_secs(5)))
                        .collect::<Vec<_>>()
                        .await
                } else {
                    timeout(Duration::from_secs(5), rx.collect::<Vec<_>>())
                        .await
                        .expect(
                            "Unclosed channel: may indicate file-server could not shutdown gracefully.",
                        )
                }
            };

            if wait_shutdown {
                shutdown_done.await;
            }

            result
        })
        .await
    }

    fn extract_messages_string(received: Vec<Event>) -> Vec<String> {
        received
            .into_iter()
            .map(Event::into_log)
            .map(|log| log.get_message().unwrap().to_string_lossy().into_owned())
            .collect()
    }

    fn extract_messages_value(received: Vec<Event>) -> Vec<Value> {
        received
            .into_iter()
            .map(Event::into_log)
            .map(|log| log.get_message().unwrap().clone())
            .collect()
    }
}
