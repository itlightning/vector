The `file` source `encoding.charset` option now accepts `auto` to detect each
file's character encoding (BOM, UTF-16, then UTF-8, then an optional
`fallback_charset`). Optional knobs: `auto_detect_min_bytes`,
`auto_detect_max_bytes`, and `max_replacement_ratio` (reject binary-looking
files). A leading BOM is stripped from decoded output; BOM bytes are excluded
from the replacement-ratio calculation.

authors: klondikedragon
