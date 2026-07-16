//! Optional per-file character-set auto-detection for the file source.
//!
//! The detection ladder lives in the Vector crate (`encoding_detect`); this
//! module only carries the per-file lifecycle state and a `FileEncodingDetector`
//! trait that the Vector crate implements. That split is deliberate: it keeps
//! `file-source` free of an `encoding_rs` dependency, so charsets cross the
//! boundary as opaque `&'static str` names and line delimiters as pre-encoded
//! `Bytes`. The trait implementation in the Vector crate owns the delimiter
//! encoding and the UTF-8 zero-copy decision.

use std::sync::Arc;

use bytes::Bytes;

/// Result of running auto-detection on a sniff window.
#[derive(Debug, Clone, PartialEq)]
pub enum EncodingDetectOutcome {
    /// Need more bytes before deciding.
    Pending,
    /// Charset chosen; use `encoding_name` and `line_delimiter` from now on.
    Decided {
        /// `None` when bytes are already UTF-8 (zero-copy downstream).
        encoding_name: Option<&'static str>,
        via: &'static str,
        line_delimiter: Bytes,
        /// Leading BOM bytes to skip on the held reader when `encoding_name` is `None`.
        bom_skip_bytes: u16,
    },
    /// Sniff rejected as garbage under the chosen charset.
    Rejected {
        encoding_name: &'static str,
        via: &'static str,
        ratio: f64,
    },
}

/// Implemented by the Vector file source to run charset detection without
/// pulling `encoding_rs` into this crate.
pub trait FileEncodingDetector: Send + Sync {
    /// Maximum bytes to peek from offset 0.
    fn max_peek_bytes(&self) -> usize;

    /// Idle timeout before force-deciding with `min_bytes` waived.
    fn idle_timeout_secs(&self) -> u64;

    /// Run detection on a sniff window that starts at file/stream offset 0.
    ///
    /// When `waive_min` is true, sub-`min_bytes` windows may still decide (idle timeout).
    fn detect(&self, sniff: &[u8], waive_min: bool) -> EncodingDetectOutcome;
}

/// How the file server handles character encoding for framing.
#[derive(Clone)]
pub enum FileEncodingMode {
    /// Fixed line delimiter for every file. Optional name annotates each `Line`
    /// for transcoding in the Vector file source.
    Fixed { encoding_name: Option<&'static str> },
    /// Per-file auto-detection; delimiter is set after `Decided`.
    Auto {
        detector: Arc<dyn FileEncodingDetector>,
    },
}

impl std::fmt::Debug for FileEncodingMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fixed { encoding_name } => f
                .debug_struct("Fixed")
                .field("encoding_name", encoding_name)
                .finish(),
            Self::Auto { .. } => f.debug_struct("Auto").finish_non_exhaustive(),
        }
    }
}

/// Per-file encoding lifecycle while watching.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileEncodingState {
    /// Not using encoding / fixed mode (no pending detect).
    Inactive,
    /// Waiting for enough bytes (or a BOM) to decide.
    Pending,
    /// Charset chosen; `encoding_name` is an Encoding Standard name when transcoding is required.
    Decided {
        encoding_name: Option<&'static str>,
        bom_skip_bytes: u16,
    },
    /// Permanently skip this fingerprint after reject gate.
    Rejected,
}

impl FileEncodingState {
    pub const fn encoding_name(&self) -> Option<&'static str> {
        match self {
            Self::Decided { encoding_name, .. } => *encoding_name,
            _ => None,
        }
    }
}
