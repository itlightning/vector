The `DecoderMalformedReplacement` internal event now includes an optional
`file` field so operators can locate which file produced malformed byte
sequences during charset transcoding (especially useful with directory globs
and `encoding.charset = "auto"`).

authors: klondikedragon
