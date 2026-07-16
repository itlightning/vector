The `file` source `encoding.charset` option now accepts `auto` to detect each
file's character encoding (BOM, UTF-16, then UTF-8, then an optional
`fallback_charset`). Optional knobs: `auto_detect_min_bytes`,
`auto_detect_max_bytes`, `max_replacement_ratio` (reject binary-looking
files), `auto_detect_idle_timeout_secs` (force a best-effort decision for
files that stay below `auto_detect_min_bytes`), and `sanitize_utf8` (decode
UTF-8-detected files so every emitted line is valid UTF-8). A leading BOM is
stripped from decoded output; BOM bytes are excluded from the
replacement-ratio calculation.

authors: klondikedragon
