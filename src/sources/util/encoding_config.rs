use std::cell::RefCell;

use encoding_rs::{Encoding, UTF_8};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use vector_lib::configurable::{
    Configurable, GenerateError, Metadata, ToValue, configurable_component,
    schema::{SchemaGenerator, SchemaObject, generate_string_schema},
};

use crate::encoding_detect::{
    AutoDetectConfig, DEFAULT_AUTO_DETECT_IDLE_TIMEOUT_SECS, DEFAULT_AUTO_DETECT_MAX_BYTES,
    DEFAULT_AUTO_DETECT_MIN_BYTES, DEFAULT_MAX_REPLACEMENT_RATIO, MAX_AUTO_DETECT_MAX_BYTES,
    MIN_AUTO_DETECT_MIN_BYTES,
};

/// Character set for the file source: an Encoding Standard label, or `auto`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CharsetMode {
    /// Detect per file (BOM, UTF-16 heuristic, UTF-8, then fallback).
    Auto,
    /// Fixed encoding for every file matched by the source.
    Explicit(&'static Encoding),
}

impl Serialize for CharsetMode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Auto => serializer.serialize_str("auto"),
            Self::Explicit(encoding) => serializer.serialize_str(encoding.name()),
        }
    }
}

impl<'de> Deserialize<'de> for CharsetMode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let label = String::deserialize(deserializer)?;
        if label.eq_ignore_ascii_case("auto") {
            return Ok(Self::Auto);
        }
        Encoding::for_label(label.as_bytes())
            .map(Self::Explicit)
            .ok_or_else(|| {
                serde::de::Error::custom(format!(
                    "unknown encoding charset `{label}` (use an Encoding Standard label or `auto`)"
                ))
            })
    }
}

impl Configurable for CharsetMode {
    fn referenceable_name() -> Option<&'static str> {
        Some("sources::file::CharsetMode")
    }

    fn metadata() -> Metadata {
        let mut metadata = Metadata::default();
        metadata.set_description(
            "An Encoding Standard label, or `auto` for per-file detection (BOM / UTF-16 / UTF-8).",
        );
        metadata
    }

    fn generate_schema(_: &RefCell<SchemaGenerator>) -> Result<SchemaObject, GenerateError> {
        Ok(generate_string_schema())
    }
}

impl ToValue for CharsetMode {
    fn to_value(&self) -> Value {
        match self {
            Self::Auto => Value::String("auto".into()),
            Self::Explicit(encoding) => Value::String(encoding.name().into()),
        }
    }
}

/// Character set encoding.
#[configurable_component]
#[derive(Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EncodingConfig {
    /// Encoding of the source messages.
    ///
    /// Takes one of the encoding [label strings](https://encoding.spec.whatwg.org/#concept-encoding-get)
    /// defined as part of the [Encoding Standard](https://encoding.spec.whatwg.org/), or the special
    /// value `auto` to detect the encoding per file (BOM, then UTF-16, then UTF-8, then
    /// `fallback_charset`).
    ///
    /// When set to an explicit label, the messages are transcoded from the specified encoding to
    /// UTF-8, which is the encoding that is assumed internally for string-like data. Enable this
    /// transcoding operation if you need your data to be in UTF-8 for further processing. At the
    /// time of transcoding, any malformed sequences (that can't be mapped to UTF-8) is replaced
    /// with the Unicode [REPLACEMENT
    /// CHARACTER](https://en.wikipedia.org/wiki/Specials_(Unicode_block)#Replacement_character) and
    /// warnings are logged.
    ///
    /// When set to `auto`, a leading BOM is stripped from decoded output (same behavior as an
    /// explicit charset that goes through the decoder).
    #[configurable(metadata(docs::examples = "utf-16le"))]
    #[configurable(metadata(docs::examples = "utf-16be"))]
    #[configurable(metadata(docs::examples = "auto"))]
    pub charset: CharsetMode,

    /// Fallback encoding used when `charset` is `auto` and detection is inconclusive.
    ///
    /// Only valid when `charset` is `auto`. Defaults to `utf-8`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[configurable(metadata(docs::examples = "utf-8"))]
    pub fallback_charset: Option<&'static Encoding>,

    /// Minimum number of bytes (from offset 0) required before non-BOM auto-detection decides.
    ///
    /// Below this size without a BOM, the file stays pending (no lines emitted) until it grows.
    /// Only valid when `charset` is `auto`. Defaults to 128. Clamped to at least 32.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[configurable(metadata(docs::type_unit = "bytes"))]
    #[configurable(metadata(docs::examples = 128))]
    #[configurable(metadata(docs::examples = 1024))]
    pub auto_detect_min_bytes: Option<usize>,

    /// Maximum number of bytes peeked from offset 0 for auto-detection.
    ///
    /// Only valid when `charset` is `auto`. Defaults to 2048. Clamped to at most 65536.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[configurable(metadata(docs::type_unit = "bytes"))]
    #[configurable(metadata(docs::examples = 2048))]
    #[configurable(metadata(docs::examples = 8192))]
    pub auto_detect_max_bytes: Option<usize>,

    /// Reject a file when the fraction of U+FFFD replacements in the sniff window meets or exceeds
    /// this ratio under the chosen charset.
    ///
    /// Set to `0` to disable the reject gate. Only valid when `charset` is `auto`. Defaults to
    /// `0.33`. A leading BOM is excluded from the replacement-ratio calculation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[configurable(metadata(docs::examples = 0.33))]
    #[configurable(metadata(docs::examples = 0.0))]
    pub max_replacement_ratio: Option<f64>,

    /// Seconds a file may stay Pending (below `auto_detect_min_bytes`) before force-deciding.
    ///
    /// Only valid when `charset` is `auto`. Defaults to 30. Post-timeout decisions use a
    /// best-effort sniff window and may be lower confidence than a full `min_bytes` window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[configurable(metadata(docs::type_unit = "seconds"))]
    #[configurable(metadata(docs::examples = 30))]
    pub auto_detect_idle_timeout_secs: Option<u64>,

    /// Decode files detected as UTF-8 through the transcoder so malformed sequences are
    /// replaced with the Unicode REPLACEMENT CHARACTER (U+FFFD).
    ///
    /// By default, files detected as UTF-8 are passed through unchanged for efficiency, so
    /// invalid sequences appearing after the detection window are shipped as-is. When `true`,
    /// UTF-8-detected files (including files with a UTF-8 BOM) are decoded the same way as an
    /// explicit `charset: utf-8`, guaranteeing that every emitted line is valid UTF-8.
    ///
    /// Only valid when `charset` is `auto`. Defaults to `false`.
    #[serde(default)]
    pub sanitize_utf8: bool,
}

impl EncodingConfig {
    /// Explicit fixed charset (tests / call sites that previously used `charset: UTF_16LE`).
    pub const fn explicit(charset: &'static Encoding) -> Self {
        Self {
            charset: CharsetMode::Explicit(charset),
            fallback_charset: None,
            auto_detect_min_bytes: None,
            auto_detect_max_bytes: None,
            max_replacement_ratio: None,
            auto_detect_idle_timeout_secs: None,
            sanitize_utf8: false,
        }
    }

    /// Auto-detection with every knob at its default.
    pub const fn auto() -> Self {
        Self {
            charset: CharsetMode::Auto,
            fallback_charset: None,
            auto_detect_min_bytes: None,
            auto_detect_max_bytes: None,
            max_replacement_ratio: None,
            auto_detect_idle_timeout_secs: None,
            sanitize_utf8: false,
        }
    }

    /// Validate auto-only fields and clamps; returns the resolved auto-detect config when auto.
    pub fn validate_and_resolve(&self) -> crate::Result<Option<AutoDetectConfig>> {
        let auto_only_set = self.fallback_charset.is_some()
            || self.auto_detect_min_bytes.is_some()
            || self.auto_detect_max_bytes.is_some()
            || self.max_replacement_ratio.is_some()
            || self.auto_detect_idle_timeout_secs.is_some()
            || self.sanitize_utf8;

        match self.charset {
            CharsetMode::Explicit(_) => {
                if auto_only_set {
                    return Err(
                        "encoding.fallback_charset, auto_detect_min_bytes, auto_detect_max_bytes, max_replacement_ratio, auto_detect_idle_timeout_secs, and sanitize_utf8 are only valid when encoding.charset is \"auto\""
                            .into(),
                    );
                }
                Ok(None)
            }
            CharsetMode::Auto => {
                let fallback = self.fallback_charset.unwrap_or(UTF_8);
                let mut min_bytes = self
                    .auto_detect_min_bytes
                    .unwrap_or(DEFAULT_AUTO_DETECT_MIN_BYTES);
                let mut max_bytes = self
                    .auto_detect_max_bytes
                    .unwrap_or(DEFAULT_AUTO_DETECT_MAX_BYTES);
                let max_replacement_ratio = self
                    .max_replacement_ratio
                    .unwrap_or(DEFAULT_MAX_REPLACEMENT_RATIO);
                let idle_timeout_secs = self
                    .auto_detect_idle_timeout_secs
                    .unwrap_or(DEFAULT_AUTO_DETECT_IDLE_TIMEOUT_SECS);

                if min_bytes < MIN_AUTO_DETECT_MIN_BYTES {
                    min_bytes = MIN_AUTO_DETECT_MIN_BYTES;
                }
                if max_bytes > MAX_AUTO_DETECT_MAX_BYTES {
                    max_bytes = MAX_AUTO_DETECT_MAX_BYTES;
                }
                if min_bytes > max_bytes {
                    return Err(format!(
                        "encoding.auto_detect_min_bytes ({min_bytes}) must be <= encoding.auto_detect_max_bytes ({max_bytes})"
                    )
                    .into());
                }
                if !(0.0..=1.0).contains(&max_replacement_ratio) {
                    return Err(
                        "encoding.max_replacement_ratio must be between 0.0 and 1.0 inclusive"
                            .into(),
                    );
                }

                Ok(Some(AutoDetectConfig::new(
                    fallback,
                    min_bytes,
                    max_bytes,
                    max_replacement_ratio,
                    idle_timeout_secs,
                )))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use encoding_rs::UTF_16LE;
    use indoc::indoc;

    use super::*;

    #[test]
    fn deserialize_explicit() {
        let config: EncodingConfig = serde_yaml::from_str(indoc! {
            r#"
            charset: utf-16le
            "#
        })
        .unwrap();
        assert_eq!(config.charset, CharsetMode::Explicit(UTF_16LE));
        assert!(config.validate_and_resolve().unwrap().is_none());
    }

    #[test]
    fn deserialize_auto_defaults() {
        let config: EncodingConfig = serde_yaml::from_str(indoc! {
            r#"
            charset: auto
            "#
        })
        .unwrap();
        let auto = config.validate_and_resolve().unwrap().unwrap();
        assert_eq!(auto.fallback, UTF_8);
        assert_eq!(auto.min_bytes, DEFAULT_AUTO_DETECT_MIN_BYTES);
        assert_eq!(auto.max_bytes, DEFAULT_AUTO_DETECT_MAX_BYTES);
        assert_eq!(auto.max_replacement_ratio, DEFAULT_MAX_REPLACEMENT_RATIO);
    }

    #[test]
    fn fallback_without_auto_errors() {
        let config: EncodingConfig = serde_yaml::from_str(indoc! {
            r#"
            charset: utf-16le
            fallback_charset: utf-8
            "#
        })
        .unwrap();
        assert!(config.validate_and_resolve().is_err());
    }

    #[test]
    fn sanitize_utf8_without_auto_errors() {
        let config: EncodingConfig = serde_yaml::from_str(indoc! {
            r#"
            charset: utf-16le
            sanitize_utf8: true
            "#
        })
        .unwrap();
        assert!(config.validate_and_resolve().is_err());
    }

    #[test]
    fn sanitize_utf8_with_auto_resolves() {
        let config: EncodingConfig = serde_yaml::from_str(indoc! {
            r#"
            charset: auto
            sanitize_utf8: true
            "#
        })
        .unwrap();
        assert!(config.sanitize_utf8);
        assert!(config.validate_and_resolve().unwrap().is_some());
    }

    #[test]
    fn sanitize_utf8_defaults_false() {
        let config: EncodingConfig = serde_yaml::from_str(indoc! {
            r#"
            charset: auto
            "#
        })
        .unwrap();
        assert!(!config.sanitize_utf8);
    }

    #[test]
    fn clamps_min_and_max() {
        let config: EncodingConfig = serde_yaml::from_str(indoc! {
            r#"
            charset: auto
            auto_detect_min_bytes: 1
            auto_detect_max_bytes: 999999
            "#
        })
        .unwrap();
        let auto = config.validate_and_resolve().unwrap().unwrap();
        assert_eq!(auto.min_bytes, MIN_AUTO_DETECT_MIN_BYTES);
        assert_eq!(auto.max_bytes, MAX_AUTO_DETECT_MAX_BYTES);
    }

    #[test]
    fn min_greater_than_max_errors() {
        let config: EncodingConfig = serde_yaml::from_str(indoc! {
            r#"
            charset: auto
            auto_detect_min_bytes: 4096
            auto_detect_max_bytes: 1024
            "#
        })
        .unwrap();
        assert!(config.validate_and_resolve().is_err());
    }
}
