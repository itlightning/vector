VRL programs can now read the id of the source component an event came from at `%vector.source_id`, beside the existing `%vector.source_type`. The path is available under both log namespaces, is read-only like the rest of `%vector`, and resolves to `null` for an event that did not come from a source (for example one constructed by a unit test). Vector already tracked the id on every event; nothing is added to the event, so events no program reads it from are unaffected.

authors: klondikedragon
