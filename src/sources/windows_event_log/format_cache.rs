//! Publisher display-name tables, with NO Win32 in this module.
//!
//! # Why this is its own module
//!
//! `EvtFormatMessage` with `EvtFormatMessageTask` (and opcode / keyword) reads
//! the value off the EVENT HANDLE, not off any key we pass. A cache filled from
//! that call and keyed on `(publisher, flag, value)` is asserting that
//! resolution is a pure function of the key, which the API does not guarantee.
//! A wrong entry stores a real display name belonging to a different task, so
//! the corruption is invisible in the data and persists for every later event
//! with that key. That is the 1.7.7 `task_name` defect.
//!
//! The display name is determined by `(publisher identity, metadata version,
//! locale, numeric value)`. Winlogbeat builds that function by enumerating the
//! publisher's own static tables and formatting each message ID with a null
//! event handle. This module is that map: lookup, miss policy, and refresh.
//! Filling the tables is the caller's job (Win32 in production, a fixture in
//! tests). The table is written ONLY from enumeration. A per-event
//! `EvtFormatMessage` fallback may be used on a miss; its answer is returned
//! and is never inserted.
//!
//! # The invariant
//!
//! For a fixed publisher, locale, and field, a numeric value must never resolve
//! to the name of a different value via the table. Fallback answers are
//! one-shot and cannot poison a later lookup.

use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

use lru::LruCache;

/// Locale value passed to `EvtOpenPublisherMetadata`. Zero is the system /
/// thread default, which is what this source uses everywhere.
pub(super) const SYSTEM_DEFAULT_LOCALE: u32 = 0;

/// Pick the table display string for one publisher-metadata row.
///
/// `message_id == u32::MAX` (`-1`) means the entry has no message; the
/// symbolic name is then the display string. Any other ID is the formatted
/// message. A present ID that failed to format is omitted, never replaced
/// by the symbolic name: that would store TaskName/OpcodeName for a row
/// that had a message-file string.
pub(super) fn choose_table_display(
    message_id: u32,
    formatted: Option<String>,
    symbolic: Option<String>,
) -> Option<String> {
    if message_id != u32::MAX {
        return formatted.filter(|s| !s.is_empty());
    }
    symbolic.filter(|s| !s.is_empty())
}

/// Names enumerated from one publisher's metadata for one locale.
///
/// Display strings, not symbolic names: the caller resolves each message ID
/// and falls back to the symbolic name only when the ID is absent.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct PublisherNames {
    pub(super) tasks: HashMap<u16, String>,
    pub(super) opcodes: HashMap<u8, String>,
    /// Keyword bit masks in enumeration order. An event's keyword field is a
    /// mask; a table entry matches when `(event & bit) == bit` and `bit != 0`.
    pub(super) keywords: Vec<(u64, String)>,
    pub(super) levels: HashMap<u8, String>,
}

/// Scalar field stored in a [`PublisherNames`] table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum NameField {
    Task,
    Opcode,
    Level,
}

/// Outcome of one scalar lookup. Test-only: the ship path uses [`FormatCache::get_scalar`].
///
/// `hit` means the table served the name (including a present empty table
/// returning `name: None` without fallback). `table_miss` means the value was
/// absent after a fresh-enough table and the fallback ran. The two are never
/// both true. Miss A (publisher unopenable) is `hit: false, table_miss: false`.
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Lookup {
    pub(super) name: Option<String>,
    pub(super) hit: bool,
    pub(super) table_miss: bool,
}

/// Outcome of a keyword-mask lookup. Same hit / miss flags as [`Lookup`].
/// Test-only: the ship path uses [`FormatCache::get_keywords`].
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct KeywordLookup {
    pub(super) names: Vec<String>,
    pub(super) hit: bool,
    pub(super) table_miss: bool,
}

#[derive(Debug)]
enum Entry {
    Ready {
        names: PublisherNames,
        enumerated_at: Instant,
    },
    /// Publisher metadata could not be opened. Retried only after `refresh`.
    Unopenable { at: Instant },
}

/// What [`FormatCache::prepare`] says the caller must do before a lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Prepare {
    /// A fresh-enough table is resident.
    Ready,
    /// Absent or stale: caller must enumerate (or record unopenable).
    NeedEnumerate,
    /// Miss A, still inside the refresh window. Emit nothing; do not open.
    Unopenable,
}

/// Map from `(casefolded publisher, locale)` to an enumerated name table.
///
/// BOUNDED. A rich provider's table is hundreds of display strings, and the key
/// space is "every publisher this host has ever emitted an event from", which
/// grows for the life of the process. Unbounded, that shape reads as a slow leak
/// over a long soak, which is indistinguishable from a real one on a graph.
pub(super) struct FormatCache {
    entries: LruCache<(String, u32), Entry>,
}

impl std::fmt::Debug for FormatCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FormatCache")
            .field("entries", &self.entries.len())
            .finish()
    }
}

fn cache_key(publisher: &str, locale: u32) -> (String, u32) {
    (publisher.to_ascii_lowercase(), locale)
}

fn stale(at: Instant, now: Instant, refresh: Duration) -> bool {
    now.saturating_duration_since(at) >= refresh
}

impl FormatCache {
    /// Capacity for a cache whose only caller is a test.
    #[cfg(test)]
    pub(super) fn new() -> Self {
        Self::with_capacity(512)
    }

    pub(super) fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: LruCache::new(
                NonZeroUsize::new(capacity).expect("format cache capacity is not zero"),
            ),
        }
    }

    /// Resident publisher entries. Test and diagnostic use only.
    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.entries.len()
    }

    pub(super) fn prepare(
        &mut self,
        publisher: &str,
        locale: u32,
        now: Instant,
        refresh: Duration,
    ) -> Prepare {
        match self.entries.get(&cache_key(publisher, locale)) {
            Some(Entry::Ready { enumerated_at, .. }) if !stale(*enumerated_at, now, refresh) => {
                Prepare::Ready
            }
            Some(Entry::Unopenable { at }) if !stale(*at, now, refresh) => Prepare::Unopenable,
            _ => Prepare::NeedEnumerate,
        }
    }

    pub(super) fn store_table(
        &mut self,
        publisher: &str,
        locale: u32,
        now: Instant,
        names: PublisherNames,
    ) {
        self.entries.put(
            cache_key(publisher, locale),
            Entry::Ready {
                names,
                enumerated_at: now,
            },
        );
    }

    pub(super) fn store_unopenable(&mut self, publisher: &str, locale: u32, now: Instant) {
        self.entries
            .put(cache_key(publisher, locale), Entry::Unopenable { at: now });
    }

    /// One scalar display name, OWNED.
    ///
    /// Owned rather than borrowed because the only caller reads this through a
    /// process-global lock, and a borrow cannot outlive the guard.
    pub(super) fn get_scalar(
        &mut self,
        publisher: &str,
        locale: u32,
        field: NameField,
        value: u64,
    ) -> Option<String> {
        match self.entries.get(&cache_key(publisher, locale)) {
            Some(Entry::Ready { names, .. }) => {
                Self::scalar_from_table(names, field, value).map(str::to_owned)
            }
            _ => None,
        }
    }

    pub(super) fn get_keywords(
        &mut self,
        publisher: &str,
        locale: u32,
        mask: u64,
    ) -> Option<Vec<String>> {
        match self.entries.get(&cache_key(publisher, locale)) {
            Some(Entry::Ready { names, .. }) => Some(
                names
                    .keywords
                    .iter()
                    .filter(|(bit, _)| *bit != 0 && (mask & *bit) == *bit)
                    .map(|(_, name)| name.clone())
                    .collect(),
            ),
            _ => None,
        }
    }

    #[cfg(test)]
    fn ensure_table<E>(
        &mut self,
        key: &(String, u32),
        now: Instant,
        refresh: Duration,
        enumerate: E,
    ) -> bool
    where
        E: FnOnce() -> Option<PublisherNames>,
    {
        match self.entries.get(key) {
            Some(Entry::Ready { enumerated_at, .. }) if !stale(*enumerated_at, now, refresh) => {
                return true;
            }
            Some(Entry::Unopenable { at }) if !stale(*at, now, refresh) => {
                return false;
            }
            _ => {}
        }

        match enumerate() {
            Some(names) => {
                self.entries.put(
                    key.clone(),
                    Entry::Ready {
                        names,
                        enumerated_at: now,
                    },
                );
                true
            }
            None => {
                self.entries.put(key.clone(), Entry::Unopenable { at: now });
                false
            }
        }
    }

    fn scalar_from_table(
        names: &PublisherNames,
        field: NameField,
        value: u64,
    ) -> Option<&str> {
        match field {
            NameField::Task => names.tasks.get(&(value as u16)).map(String::as_str),
            NameField::Opcode => names.opcodes.get(&(value as u8)).map(String::as_str),
            NameField::Level => names.levels.get(&(value as u8)).map(String::as_str),
        }
    }

    /// Look up one scalar display name.
    ///
    /// `enumerate` runs when the table is absent or older than `refresh`.
    /// `None` is miss A: cached until `refresh` elapses. `fallback` runs only
    /// on miss B (table present, value absent) and its answer is never stored.
    ///
    /// Test-only. Production uses [`Self::prepare`] plus [`Self::get_scalar`]
    /// so the Win32 caller never holds two `&mut` maps in one closure.
    #[cfg(test)]
    pub(super) fn lookup<E, F>(
        &mut self,
        publisher: &str,
        locale: u32,
        field: NameField,
        value: u64,
        now: Instant,
        refresh: Duration,
        enumerate: E,
        fallback: F,
    ) -> Lookup
    where
        E: FnOnce() -> Option<PublisherNames>,
        F: FnOnce() -> Option<String>,
    {
        let key = cache_key(publisher, locale);
        if !self.ensure_table(&key, now, refresh, enumerate) {
            return Lookup {
                name: None,
                hit: false,
                table_miss: false,
            };
        }

        if let Some(Entry::Ready { names, .. }) = self.entries.get(&key) {
            if let Some(name) = Self::scalar_from_table(names, field, value) {
                return Lookup {
                    name: Some(name.to_string()),
                    hit: true,
                    table_miss: false,
                };
            }
        }

        Lookup {
            name: fallback(),
            hit: false,
            table_miss: true,
        }
    }

    /// Look up keyword display names for an event's keyword mask.
    ///
    /// Matching bits come from the table in enumeration order. A mask with no
    /// matching bits on a present table is miss B and runs `fallback`, which
    /// returns the `EvtFormatMessageKeyword` semicolon-separated string.
    /// Test-only. Production uses [`Self::prepare`] plus [`Self::get_keywords`].
    #[cfg(test)]
    pub(super) fn lookup_keywords<E, F>(
        &mut self,
        publisher: &str,
        locale: u32,
        mask: u64,
        now: Instant,
        refresh: Duration,
        enumerate: E,
        fallback: F,
    ) -> KeywordLookup
    where
        E: FnOnce() -> Option<PublisherNames>,
        F: FnOnce() -> Option<String>,
    {
        let key = cache_key(publisher, locale);
        if !self.ensure_table(&key, now, refresh, enumerate) {
            return KeywordLookup {
                names: Vec::new(),
                hit: false,
                table_miss: false,
            };
        }

        if let Some(Entry::Ready { names, .. }) = self.entries.get(&key) {
            let matched: Vec<String> = names
                .keywords
                .iter()
                .filter(|(bit, _)| *bit != 0 && (mask & *bit) == *bit)
                .map(|(_, name)| name.clone())
                .collect();
            if !matched.is_empty() || mask == 0 {
                return KeywordLookup {
                    names: matched,
                    hit: true,
                    table_miss: false,
                };
            }
        }

        let names = fallback()
            .map(|s| {
                s.split(';')
                    .map(|k| k.trim().to_string())
                    .filter(|k| !k.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        KeywordLookup {
            names,
            hit: false,
            table_miss: true,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    const HOUR: Duration = Duration::from_secs(3600);
    const SECURITY: &str = "Microsoft-Windows-Security-Auditing";

    fn security_names() -> PublisherNames {
        let mut names = PublisherNames::default();
        names.tasks.insert(13312, "Process Creation".into());
        names.tasks.insert(13313, "Process Termination".into());
        names
            .tasks
            .insert(13317, "Token Right Adjusted Events".into());
        names.tasks.insert(12800, "File System".into());
        names.opcodes.insert(0, "Info".into());
        names.levels.insert(0, "Information".into());
        names.levels.insert(2, "Error".into());
        names.levels.insert(16, "Custom-16".into());
        names
            .keywords
            .push((0x0020_0000_0000_0000, "Audit Success".into()));
        names
            .keywords
            .push((0x8000_0000_0000_0000, "Classic".into()));
        names
    }

    fn lookup_task(
        cache: &mut FormatCache,
        publisher: &str,
        value: u16,
        now: Instant,
        refresh: Duration,
        enumerate: impl FnOnce() -> Option<PublisherNames>,
        fallback: impl FnOnce() -> Option<String>,
    ) -> Lookup {
        cache.lookup(
            publisher,
            SYSTEM_DEFAULT_LOCALE,
            NameField::Task,
            u64::from(value),
            now,
            refresh,
            enumerate,
            fallback,
        )
    }

    /// RULE: a table row is the name of THAT value. Interleaving the Security
    /// tasks that 1.7.7 transposed must never swap them.
    #[test]
    fn a_value_never_resolves_to_another_values_name() {
        let mut cache = FormatCache::new();
        let t0 = Instant::now();
        let values = [13312u16, 13313, 13317, 12800];
        let enumerations = AtomicUsize::new(0);
        let fallbacks = AtomicUsize::new(0);

        for pass in 0..250 {
            let value = values[pass % values.len()];
            let got = lookup_task(
                &mut cache,
                SECURITY,
                value,
                t0,
                HOUR,
                || {
                    enumerations.fetch_add(1, Ordering::SeqCst);
                    Some(security_names())
                },
                || {
                    fallbacks.fetch_add(1, Ordering::SeqCst);
                    panic!("table hit must not fall back")
                },
            );
            let expected = security_names().tasks.get(&value).cloned();
            assert_eq!(
                got.name, expected,
                "task {value} resolved to another task's name on pass {pass}"
            );
            assert!(got.hit);
            assert!(!got.table_miss);
        }
        assert_eq!(enumerations.load(Ordering::SeqCst), 1);
        assert_eq!(fallbacks.load(Ordering::SeqCst), 0);
        assert_eq!(cache.len(), 1);
    }

    /// RULE: miss A (publisher unopenable) emits nothing, caches the negative,
    /// and does not retry until refresh. otel-contrib caches this failure the
    /// same way. There is no fallback: `EvtFormatMessage` needs the same handle.
    #[test]
    fn unopenable_publisher_is_cached_until_refresh() {
        let mut cache = FormatCache::new();
        let t0 = Instant::now();
        let enumerations = AtomicUsize::new(0);
        let fallbacks = AtomicUsize::new(0);

        let first = lookup_task(
            &mut cache,
            "Missing-Provider",
            1,
            t0,
            HOUR,
            || {
                enumerations.fetch_add(1, Ordering::SeqCst);
                None
            },
            || {
                fallbacks.fetch_add(1, Ordering::SeqCst);
                Some("must-not-run".into())
            },
        );
        assert!(first.name.is_none());
        assert!(!first.hit);
        assert!(!first.table_miss);

        let second = lookup_task(
            &mut cache,
            "Missing-Provider",
            1,
            t0 + Duration::from_secs(1),
            HOUR,
            || panic!("negative must not re-enumerate before refresh"),
            || panic!("miss A must not fall back"),
        );
        assert!(second.name.is_none());
        assert_eq!(enumerations.load(Ordering::SeqCst), 1);
        assert_eq!(fallbacks.load(Ordering::SeqCst), 0);

        let after = lookup_task(
            &mut cache,
            "Missing-Provider",
            13312,
            t0 + HOUR,
            HOUR,
            || {
                enumerations.fetch_add(1, Ordering::SeqCst);
                Some(security_names())
            },
            || panic!("re-enumerated table must serve the value"),
        );
        assert_eq!(after.name.as_deref(), Some("Process Creation"));
        assert!(after.hit);
        assert_eq!(enumerations.load(Ordering::SeqCst), 2);
    }

    /// RULE: miss B uses the fallback answer and NEVER writes it into the table.
    /// A later lookup of the same value still misses the table.
    #[test]
    fn fallback_answer_is_not_inserted_into_the_table() {
        let mut cache = FormatCache::new();
        let t0 = Instant::now();
        let fallbacks = AtomicUsize::new(0);
        let names = security_names();

        let first = lookup_task(
            &mut cache,
            SECURITY,
            9999,
            t0,
            HOUR,
            || Some(names.clone()),
            || {
                fallbacks.fetch_add(1, Ordering::SeqCst);
                Some("from-event-handle".into())
            },
        );
        assert_eq!(first.name.as_deref(), Some("from-event-handle"));
        assert!(!first.hit);
        assert!(first.table_miss);

        let second = lookup_task(
            &mut cache,
            SECURITY,
            9999,
            t0 + Duration::from_secs(1),
            HOUR,
            || panic!("fresh table must not re-enumerate"),
            || {
                fallbacks.fetch_add(1, Ordering::SeqCst);
                Some("from-event-handle-again".into())
            },
        );
        assert_eq!(second.name.as_deref(), Some("from-event-handle-again"));
        assert!(second.table_miss);
        assert_eq!(fallbacks.load(Ordering::SeqCst), 2);

        let known = lookup_task(
            &mut cache,
            SECURITY,
            13312,
            t0 + Duration::from_secs(2),
            HOUR,
            || panic!("fresh table must not re-enumerate"),
            || panic!("known table row must not fall back"),
        );
        assert_eq!(known.name.as_deref(), Some("Process Creation"));
        assert!(known.hit);
    }

    /// Guard on the guard: if a fallback were inserted, the second lookup of
    /// 9999 would be a hit with the fallback string and this test would fail.
    /// Restoring an insert-on-fallback makes this red; that is the proof the
    /// miss-B rule is observable.
    #[test]
    fn inserting_a_fallback_would_make_the_next_lookup_a_hit() {
        let mut cache = FormatCache::new();
        let t0 = Instant::now();
        _ = lookup_task(
            &mut cache,
            SECURITY,
            9999,
            t0,
            HOUR,
            || Some(security_names()),
            || Some("poison".into()),
        );
        let later = lookup_task(
            &mut cache,
            SECURITY,
            9999,
            t0,
            HOUR,
            || panic!("must not re-enumerate"),
            || Some("still-missing".into()),
        );
        assert!(
            later.table_miss,
            "a fallback must not become a table row; if this is a hit the \
             insert-on-fallback defect is back"
        );
        assert_eq!(later.name.as_deref(), Some("still-missing"));
    }

    /// RULE: a stale table that still misses after re-enumeration falls back
    /// once; a stale table that gains the value on re-enumeration serves it
    /// without fallback.
    #[test]
    fn stale_miss_re_enumerates_once_before_fallback() {
        let mut cache = FormatCache::new();
        let t0 = Instant::now();
        let enumerations = AtomicUsize::new(0);

        _ = lookup_task(
            &mut cache,
            SECURITY,
            13312,
            t0,
            HOUR,
            || {
                enumerations.fetch_add(1, Ordering::SeqCst);
                Some(security_names())
            },
            || panic!("present row"),
        );

        let mut grown = security_names();
        grown.tasks.insert(42, "Grown".into());
        let later = lookup_task(
            &mut cache,
            SECURITY,
            42,
            t0 + HOUR,
            HOUR,
            || {
                enumerations.fetch_add(1, Ordering::SeqCst);
                Some(grown.clone())
            },
            || panic!("re-enumerated table contains 42"),
        );
        assert_eq!(later.name.as_deref(), Some("Grown"));
        assert!(later.hit);
        assert_eq!(enumerations.load(Ordering::SeqCst), 2);

        let still_absent = lookup_task(
            &mut cache,
            SECURITY,
            7,
            t0 + HOUR + Duration::from_secs(1),
            HOUR,
            || panic!("table is fresh after the re-enumeration"),
            || Some("fallback-7".into()),
        );
        assert_eq!(still_absent.name.as_deref(), Some("fallback-7"));
        assert!(still_absent.table_miss);
    }

    /// Publishers and locales partition the map. Casefolding means two
    /// spellings of one publisher share a table.
    #[test]
    fn publisher_and_locale_partition_the_map_and_names_are_casefolded() {
        let mut cache = FormatCache::new();
        let t0 = Instant::now();

        let a = lookup_task(
            &mut cache,
            "Publisher-A",
            1,
            t0,
            HOUR,
            || {
                let mut n = PublisherNames::default();
                n.tasks.insert(1, "A".into());
                Some(n)
            },
            || panic!("present"),
        );
        let b = lookup_task(
            &mut cache,
            "Publisher-B",
            1,
            t0,
            HOUR,
            || {
                let mut n = PublisherNames::default();
                n.tasks.insert(1, "B".into());
                Some(n)
            },
            || panic!("present"),
        );
        assert_eq!(a.name.as_deref(), Some("A"));
        assert_eq!(b.name.as_deref(), Some("B"));

        let folded = lookup_task(
            &mut cache,
            "publisher-a",
            1,
            t0,
            HOUR,
            || panic!("casefolded publisher must share the table"),
            || panic!("present"),
        );
        assert_eq!(folded.name.as_deref(), Some("A"));
        assert!(folded.hit);

        let other_locale = cache.lookup(
            "Publisher-A",
            0x0409,
            NameField::Task,
            1,
            t0,
            HOUR,
            || {
                let mut n = PublisherNames::default();
                n.tasks.insert(1, "en-US".into());
                Some(n)
            },
            || panic!("present"),
        );
        assert_eq!(other_locale.name.as_deref(), Some("en-US"));
        assert_eq!(cache.len(), 3);
    }

    /// Custom levels at 16+ come from the table; a missing level is miss B
    /// (the caller applies the hardcoded English fallback).
    #[test]
    fn custom_levels_come_from_the_table() {
        let mut cache = FormatCache::new();
        let t0 = Instant::now();
        let custom = cache.lookup(
            SECURITY,
            SYSTEM_DEFAULT_LOCALE,
            NameField::Level,
            16,
            t0,
            HOUR,
            || Some(security_names()),
            || panic!("16 is in the table"),
        );
        assert_eq!(custom.name.as_deref(), Some("Custom-16"));
        assert!(custom.hit);

        let missing = cache.lookup(
            SECURITY,
            SYSTEM_DEFAULT_LOCALE,
            NameField::Level,
            99,
            t0,
            HOUR,
            || panic!("fresh"),
            || None,
        );
        assert!(missing.name.is_none());
        assert!(missing.table_miss);
    }

    #[test]
    fn keyword_bits_match_in_enumeration_order() {
        let mut cache = FormatCache::new();
        let t0 = Instant::now();
        let mask = 0x8020_0000_0000_0000;
        let got = cache.lookup_keywords(
            SECURITY,
            SYSTEM_DEFAULT_LOCALE,
            mask,
            t0,
            HOUR,
            || Some(security_names()),
            || panic!("bits are in the table"),
        );
        assert_eq!(
            got.names,
            vec!["Audit Success".to_string(), "Classic".to_string()]
        );
        assert!(got.hit);
        assert!(!got.table_miss);
    }

    #[test]
    fn keyword_miss_falls_back_and_does_not_insert() {
        let mut cache = FormatCache::new();
        let t0 = Instant::now();
        let got = cache.lookup_keywords(
            SECURITY,
            SYSTEM_DEFAULT_LOCALE,
            0x0001,
            t0,
            HOUR,
            || Some(security_names()),
            || Some("Alpha; Beta".into()),
        );
        assert_eq!(got.names, vec!["Alpha".to_string(), "Beta".to_string()]);
        assert!(got.table_miss);

        let again = cache.lookup_keywords(
            SECURITY,
            SYSTEM_DEFAULT_LOCALE,
            0x0001,
            t0,
            HOUR,
            || panic!("fresh"),
            || Some("Alpha; Beta".into()),
        );
        assert!(again.table_miss);
    }

    /// A present message ID that failed to format must not become the
    /// symbolic name. That is how TaskName would leak into the table.
    #[test]
    fn a_failed_format_of_a_real_message_id_is_omitted_not_symbolic() {
        assert_eq!(
            choose_table_display(42, None, Some("TaskName".into())),
            None
        );
        assert_eq!(
            choose_table_display(42, Some("Formatted".into()), Some("TaskName".into())).as_deref(),
            Some("Formatted")
        );
        assert_eq!(
            choose_table_display(u32::MAX, None, Some("TaskName".into())).as_deref(),
            Some("TaskName")
        );
        assert_eq!(
            choose_table_display(u32::MAX, Some("ignored".into()), Some("TaskName".into()))
                .as_deref(),
            Some("TaskName"),
            "when the ID is absent the formatted argument is not consulted"
        );
        assert_eq!(
            choose_table_display(u32::MAX, None, Some(String::new())),
            None
        );
        assert_eq!(
            choose_table_display(7, Some(String::new()), Some("X".into())),
            None
        );
    }
}
