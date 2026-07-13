//! Character-set detection helpers for the file source `charset = "auto"` mode.
//!
//! Detection is deliberately limited to BOM, UTF-16 (NUL-parity + strict decode),
//! and strict UTF-8. Legacy single-byte codepages are not guessed.

#![allow(missing_docs)]

use encoding_rs::{Encoding, UTF_8, UTF_16BE, UTF_16LE};

/// Defaults and clamps for auto-detection knobs.
pub const DEFAULT_AUTO_DETECT_MIN_BYTES: usize = 128;
pub const DEFAULT_AUTO_DETECT_MAX_BYTES: usize = 2048;
pub const DEFAULT_MAX_REPLACEMENT_RATIO: f64 = 0.33;
pub const MIN_AUTO_DETECT_MIN_BYTES: usize = 32;
pub const MAX_AUTO_DETECT_MAX_BYTES: usize = 65536;

/// How a charset was chosen for a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectVia {
    Bom,
    Utf16Heuristic,
    Utf8Valid,
    Fallback,
}

impl DetectVia {
    /// Stable label for internal events / logs.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bom => "bom",
            Self::Utf16Heuristic => "utf16-heuristic",
            Self::Utf8Valid => "utf8-valid",
            Self::Fallback => "fallback",
        }
    }
}

/// Tunables used when `charset = "auto"`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AutoDetectConfig {
    pub fallback: &'static Encoding,
    pub min_bytes: usize,
    pub max_bytes: usize,
    /// `0.0` disables the replacement reject gate.
    pub max_replacement_ratio: f64,
}

impl AutoDetectConfig {
    /// Build from validated, already-clamped values.
    pub const fn new(
        fallback: &'static Encoding,
        min_bytes: usize,
        max_bytes: usize,
        max_replacement_ratio: f64,
    ) -> Self {
        Self {
            fallback,
            min_bytes,
            max_bytes,
            max_replacement_ratio,
        }
    }
}

/// Outcome of running the detection ladder (+ optional reject gate) on a sniff window.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DetectOutcome {
    /// Need more bytes (no BOM and sniff shorter than `min_bytes`).
    Pending,
    /// Charset chosen; safe to frame and decode.
    Decided {
        encoding: &'static Encoding,
        via: DetectVia,
    },
    /// Charset was chosen but the sniff looks like garbage under that charset.
    Rejected {
        encoding: &'static Encoding,
        via: DetectVia,
        ratio: f64,
    },
}

/// Detect charset for a sniff window starting at file offset 0.
///
/// Order is load-bearing: BOM first; below `min_bytes` without BOM stays Pending;
/// at/above `min_bytes`, UTF-16 heuristic runs before strict UTF-8 (UTF-16LE ASCII is
/// byte-valid UTF-8). Then the replacement-ratio reject gate may Reject.
pub fn detect_charset(sniff: &[u8], config: &AutoDetectConfig) -> DetectOutcome {
    if let Some((encoding, _bom_len)) = Encoding::for_bom(sniff) {
        return apply_reject_gate(sniff, encoding, DetectVia::Bom, config);
    }

    if sniff.len() < config.min_bytes {
        return DetectOutcome::Pending;
    }

    let window = &sniff[..sniff.len().min(config.max_bytes)];

    if let Some(encoding) = detect_utf16_nul_parity(window) {
        return apply_reject_gate(window, encoding, DetectVia::Utf16Heuristic, config);
    }

    if std::str::from_utf8(window).is_ok() {
        return apply_reject_gate(window, UTF_8, DetectVia::Utf8Valid, config);
    }

    apply_reject_gate(window, config.fallback, DetectVia::Fallback, config)
}

fn apply_reject_gate(
    sniff: &[u8],
    encoding: &'static Encoding,
    via: DetectVia,
    config: &AutoDetectConfig,
) -> DetectOutcome {
    if config.max_replacement_ratio <= 0.0 {
        return DetectOutcome::Decided { encoding, via };
    }

    let ratio = replacement_ratio(sniff, encoding);
    if ratio >= config.max_replacement_ratio {
        DetectOutcome::Rejected {
            encoding,
            via,
            ratio,
        }
    } else {
        DetectOutcome::Decided { encoding, via }
    }
}

/// Fraction of decoded codepoints that are U+FFFD under `encoding`.
///
/// Skips a leading BOM (via `Encoding::for_bom`) so BOM bytes are excluded from
/// the ratio. Incomplete trailing multi-byte / UTF-16 sequences are not counted
/// (decode with `last = false`).
pub fn replacement_ratio(sniff: &[u8], encoding: &'static Encoding) -> f64 {
    let bom_len = Encoding::for_bom(sniff).map(|(_, len)| len).unwrap_or(0);
    let after_bom = &sniff[bom_len.min(sniff.len())..];
    if after_bom.is_empty() {
        return 0.0;
    }

    let mut decoder = encoding.new_decoder_without_bom_handling();
    let mut output = String::with_capacity(after_bom.len());
    let (_result, _read, _had_errors) = decoder.decode_to_string(after_bom, &mut output, false);

    let total = output.chars().count();
    if total == 0 {
        return 0.0;
    }
    let replacements = output.chars().filter(|&c| c == '\u{FFFD}').count();
    replacements as f64 / total as f64
}

/// UTF-16 without BOM: NUL bytes concentrated on one parity, plus strict decode.
///
/// Thresholds favor ASCII-heavy UTF-16 (typical Windows logs). Retune only with
/// failing fixtures that still match that class.
fn detect_utf16_nul_parity(bytes: &[u8]) -> Option<&'static Encoding> {
    // Need an even window for UTF-16 code units.
    let len = bytes.len() & !1;
    if len < 4 {
        return None;
    }
    let window = &bytes[..len];
    let units = len / 2;

    let mut even_nul = 0usize;
    let mut odd_nul = 0usize;
    for (i, &b) in window.iter().enumerate() {
        if b == 0 {
            if i % 2 == 0 {
                even_nul += 1;
            } else {
                odd_nul += 1;
            }
        }
    }

    // At least ~25% of code units show a NUL on the expected parity, and that
    // parity dominates the other by 4x. UTF-16LE ASCII puts NULs on odd indexes;
    // UTF-16BE ASCII puts NULs on even indexes.
    let min_nuls = units / 4;
    let candidate = if odd_nul >= min_nuls && odd_nul > even_nul.saturating_mul(4) {
        Some(UTF_16LE)
    } else if even_nul >= min_nuls && even_nul > odd_nul.saturating_mul(4) {
        Some(UTF_16BE)
    } else {
        None
    }?;

    candidate
        .decode_without_bom_handling_and_without_replacement(window)
        .map(|_| candidate)
}

#[cfg(test)]
mod tests {
    use encoding_rs::{UTF_8, UTF_16BE, UTF_16LE};

    use super::*;

    fn cfg(min: usize, max: usize, ratio: f64, fallback: &'static Encoding) -> AutoDetectConfig {
        AutoDetectConfig::new(fallback, min, max, ratio)
    }

    fn utf16le_ascii(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
    }

    fn utf16be_ascii(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(|u| u.to_be_bytes()).collect()
    }

    #[test]
    fn bom_utf8() {
        let sniff = [0xef, 0xbb, 0xbf, b'h', b'i', b'\n'];
        let outcome = detect_charset(&sniff, &cfg(128, 2048, 0.33, UTF_8));
        match outcome {
            DetectOutcome::Decided { encoding, via } => {
                assert_eq!(encoding, UTF_8);
                assert_eq!(via, DetectVia::Bom);
            }
            other => panic!("expected Decided UTF-8 BOM, got {other:?}"),
        }
    }

    #[test]
    fn bom_utf16le_any_size() {
        let mut sniff = vec![0xff, 0xfe];
        sniff.extend(utf16le_ascii("a"));
        let outcome = detect_charset(&sniff, &cfg(128, 2048, 0.33, UTF_8));
        match outcome {
            DetectOutcome::Decided { encoding, via } => {
                assert_eq!(encoding, UTF_16LE);
                assert_eq!(via, DetectVia::Bom);
            }
            other => panic!("expected Decided UTF-16LE BOM, got {other:?}"),
        }
    }

    #[test]
    fn bom_utf16be_any_size() {
        let mut sniff = vec![0xfe, 0xff];
        sniff.extend(utf16be_ascii("a"));
        let outcome = detect_charset(&sniff, &cfg(128, 2048, 0.33, UTF_8));
        match outcome {
            DetectOutcome::Decided { encoding, via } => {
                assert_eq!(encoding, UTF_16BE);
                assert_eq!(via, DetectVia::Bom);
            }
            other => panic!("expected Decided UTF-16BE BOM, got {other:?}"),
        }
    }

    #[test]
    fn sub_min_no_bom_stays_pending() {
        let sniff = b"hello world\n"; // well under 128, valid utf-8
        let outcome = detect_charset(sniff, &cfg(128, 2048, 0.33, UTF_8));
        assert_eq!(outcome, DetectOutcome::Pending);
    }

    #[test]
    fn sub_min_utf16_no_bom_stays_pending() {
        let sniff = utf16le_ascii("short");
        assert!(sniff.len() < 128);
        let outcome = detect_charset(&sniff, &cfg(128, 2048, 0.33, UTF_8));
        assert_eq!(outcome, DetectOutcome::Pending);
    }

    #[test]
    fn ordering_trap_utf16le_ascii_not_utf8() {
        // UTF-16LE of ASCII is byte-valid UTF-8; UTF-16 must win.
        let text = "A".repeat(80); // 160 bytes as UTF-16LE
        let sniff = utf16le_ascii(&text);
        assert!(sniff.len() >= 128);
        assert!(std::str::from_utf8(&sniff).is_ok());
        let outcome = detect_charset(&sniff, &cfg(128, 2048, 0.33, UTF_8));
        match outcome {
            DetectOutcome::Decided { encoding, via } => {
                assert_eq!(encoding, UTF_16LE);
                assert_eq!(via, DetectVia::Utf16Heuristic);
            }
            other => panic!("expected UTF-16LE heuristic, got {other:?}"),
        }
    }

    #[test]
    fn utf16be_heuristic_at_min() {
        let text = "B".repeat(80);
        let sniff = utf16be_ascii(&text);
        let outcome = detect_charset(&sniff, &cfg(128, 2048, 0.33, UTF_8));
        match outcome {
            DetectOutcome::Decided { encoding, via } => {
                assert_eq!(encoding, UTF_16BE);
                assert_eq!(via, DetectVia::Utf16Heuristic);
            }
            other => panic!("expected UTF-16BE heuristic, got {other:?}"),
        }
    }

    #[test]
    fn strict_utf8_at_min() {
        let sniff = b"x".repeat(128);
        let outcome = detect_charset(&sniff, &cfg(128, 2048, 0.33, UTF_8));
        match outcome {
            DetectOutcome::Decided { encoding, via } => {
                assert_eq!(encoding, UTF_8);
                assert_eq!(via, DetectVia::Utf8Valid);
            }
            other => panic!("expected UTF-8 valid, got {other:?}"),
        }
    }

    #[test]
    fn binary_high_fffd_rejected() {
        // High-entropy bytes that are invalid UTF-8 and produce many FFFD under UTF-8.
        let mut sniff = vec![0u8; 256];
        for (i, b) in sniff.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(37).wrapping_add(0x80);
        }
        // Ensure not valid UTF-8 and not UTF-16-looking.
        assert!(std::str::from_utf8(&sniff).is_err());
        let outcome = detect_charset(&sniff, &cfg(128, 2048, 0.33, UTF_8));
        match outcome {
            DetectOutcome::Rejected { encoding, .. } => assert_eq!(encoding, UTF_8),
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    #[test]
    fn ratio_zero_disables_reject() {
        let mut sniff = vec![0u8; 256];
        for (i, b) in sniff.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(37).wrapping_add(0x80);
        }
        let outcome = detect_charset(&sniff, &cfg(128, 2048, 0.0, UTF_8));
        match outcome {
            DetectOutcome::Decided { encoding, via } => {
                assert_eq!(encoding, UTF_8);
                assert_eq!(via, DetectVia::Fallback);
            }
            other => panic!("expected fallback Decided, got {other:?}"),
        }
    }

    #[test]
    fn empty_sniff_pending() {
        assert_eq!(
            detect_charset(b"", &cfg(128, 2048, 0.33, UTF_8)),
            DetectOutcome::Pending
        );
    }

    #[test]
    fn odd_length_utf16_window() {
        let mut sniff = utf16le_ascii(&"C".repeat(70));
        sniff.push(0x41); // odd trailing byte
        assert!(sniff.len() >= 128);
        let outcome = detect_charset(&sniff, &cfg(128, 2048, 0.33, UTF_8));
        match outcome {
            DetectOutcome::Decided { encoding, via } => {
                assert_eq!(encoding, UTF_16LE);
                assert_eq!(via, DetectVia::Utf16Heuristic);
            }
            other => panic!("expected UTF-16LE heuristic, got {other:?}"),
        }
    }

    #[test]
    fn replacement_ratio_excludes_bom() {
        // UTF-8 BOM + clean ASCII: ratio must be 0 (BOM not counted as FFFD).
        let mut sniff = vec![0xef, 0xbb, 0xbf];
        sniff.extend(b"hello world, this is clean ascii text\n");
        let ratio = replacement_ratio(&sniff, UTF_8);
        assert_eq!(ratio, 0.0);
    }

    #[test]
    fn clamp_constants() {
        assert_eq!(MIN_AUTO_DETECT_MIN_BYTES, 32);
        assert_eq!(MAX_AUTO_DETECT_MAX_BYTES, 65536);
        assert_eq!(DEFAULT_AUTO_DETECT_MIN_BYTES, 128);
        assert_eq!(DEFAULT_AUTO_DETECT_MAX_BYTES, 2048);
    }
}
