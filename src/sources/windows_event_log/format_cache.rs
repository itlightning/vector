//! Bounded LRU for `EvtFormatMessage` display-name results, with NO Win32 in it.
//!
//! # Why this is its own module
//!
//! `EvtFormatMessage(metadata, event, .., EvtFormatMessageTask, ..)` resolves the
//! task name from the EVENT HANDLE. The `(publisher, flag, value)` triple is only
//! the cache key. So the cache is accurate exactly when the value it is keyed on
//! is the value the handle carries, and WRONG in a specific, nasty way when it is
//! not: the stored name is a real display name belonging to a different task, so
//! the corruption is invisible in the data (every name is a name that exists) and
//! it persists for every later event with that key.
//!
//! That property cannot be argued into safety, it has to be tested, and it cannot
//! be tested while the lookup logic is welded to an FFI call that only runs on a
//! live Windows host against a real publisher manifest. Hence this module: the
//! lookup, insert and eviction logic is pure Rust over a caller-supplied
//! resolver, so the tests below drive it with a resolver that MODELS the Win32
//! contract (name comes from the handle, not the key) and can therefore
//! construct the poisoning that production showed.
//!
//! # The invariant
//!
//! For a fixed publisher and flag, a value must never resolve to the name of a
//! different value. [`FormatCache::get_or_insert_with`] upholds it as long as the
//! resolver it is handed answers for the same event the key was built from, which
//! is why the resolver closure is constructed at the one call site that holds
//! both (`super::metadata::resolve_event_metadata`).
//!
//! # Why the key is built in here
//!
//! The previous shape had the CALLER own a `(String, u32, u64)` and mutate it in
//! place across the three lookups of an event, to spend one publisher-name
//! allocation per event instead of three. That is the same allocation saving this
//! module gets from its private probe scratch, except the mutable key no longer
//! crosses a module boundary, cannot be held across a call, and cannot be
//! inserted by accident.

use std::num::NonZeroUsize;

use lru::LruCache;

/// Cache key for one `EvtFormatMessage` result: publisher name, message flag
/// (task / opcode / keyword), and the raw field value.
///
/// The publisher is part of the key rather than a level above it, which is what
/// lets a SINGLE LRU serve every publisher. The previous shape was an unbounded
/// `HashMap<String, LruCache<..>>`, so each distinct publisher preallocated its
/// own 10k-entry hashbrown table (measured 272 KiB) on its first event and held
/// it for the life of the process.
type FormatCacheKey = (String, u32, u64);

/// Outcome of one lookup: the display name (`None` is a cached negative, which
/// is a real answer and must not re-enter the FFI) and whether it was already
/// resident.
///
/// `hit` is returned rather than counted in here so the cache stays free of the
/// metrics registry; the caller owns its counters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Lookup {
    pub(super) name: Option<String>,
    pub(super) hit: bool,
}

/// Every publisher's `EvtFormatMessage` results in one bounded LRU, so cold
/// publishers age out instead of each owning a table forever.
#[derive(Debug)]
pub(super) struct FormatCache {
    entries: LruCache<FormatCacheKey, Option<String>>,
    /// Scratch key for the allocation-free probe, owned by the cache and never
    /// inserted. Reusing one `String` is what keeps a hit allocation-free;
    /// keeping it private is what keeps the old caller-mutated-key hazard out
    /// of reach. Its contents between calls are meaningless by construction.
    probe: FormatCacheKey,
}

impl FormatCache {
    pub(super) fn new(capacity: NonZeroUsize) -> Self {
        Self {
            entries: LruCache::new(capacity),
            probe: (String::new(), 0, 0),
        }
    }

    /// Resolve `(publisher, flag, value)`, calling `resolve` only on a miss.
    ///
    /// `resolve` MUST answer for the same event the key was built from. That is
    /// the whole contract: see the module docs.
    pub(super) fn get_or_insert_with<F>(
        &mut self,
        publisher: &str,
        flag: u32,
        value: u64,
        resolve: F,
    ) -> Lookup
    where
        F: FnOnce() -> Option<String>,
    {
        // Reuse the scratch String's allocation rather than allocating a key per
        // lookup: three lookups per event on a flooded channel is the hot path.
        self.probe.0.clear();
        self.probe.0.push_str(publisher);
        self.probe.1 = flag;
        self.probe.2 = value;

        // `get`, not `peek`: with one shared LRU across every publisher,
        // promotion is what keeps a hot publisher's entries resident while cold
        // ones age out.
        if let Some(cached) = self.entries.get(&self.probe) {
            return Lookup {
                name: cached.clone(),
                hit: true,
            };
        }

        let name = resolve();
        self.entries.put(self.probe.clone(), name.clone());
        Lookup { name, hit: false }
    }

    /// Resident entry count. Test and diagnostic use only.
    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use proptest::prelude::*;

    use super::*;

    const TASK: u32 = 3;
    const OPCODE: u32 = 4;
    const KEYWORD: u32 = 5;

    fn cap(n: usize) -> NonZeroUsize {
        NonZeroUsize::new(n).unwrap()
    }

    /// The Win32 contract, modelled.
    ///
    /// `EvtFormatMessage` reads the field value off the EVENT, not off our key,
    /// so this resolver is deliberately given the event's value SEPARATELY from
    /// the key the cache is asked about. Handing it a value that disagrees with
    /// the key is exactly the production defect, and the tests below do both.
    struct Publisher {
        /// value -> display name, per flag. A manifest, in other words.
        names: HashMap<(u32, u64), &'static str>,
        calls: AtomicUsize,
    }

    impl Publisher {
        fn security() -> Self {
            let mut names = HashMap::new();
            // Real Microsoft-Windows-Security-Auditing task values; the first
            // three are the ones the field report showed transposed.
            names.insert((TASK, 13312), "Process Creation");
            names.insert((TASK, 13313), "Process Termination");
            names.insert((TASK, 13317), "Token Right Adjusted Events");
            names.insert((TASK, 12800), "File System");
            names.insert((OPCODE, 0), "Info");
            Self {
                names,
                calls: AtomicUsize::new(0),
            }
        }

        /// Resolve as the API does: from the event, ignoring any key.
        fn format(&self, flag: u32, event_value: u64) -> Option<String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.names
                .get(&(flag, event_value))
                .map(|s| (*s).to_string())
        }

        fn expected(&self, flag: u32, value: u64) -> Option<String> {
            self.names.get(&(flag, value)).map(|s| (*s).to_string())
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    /// REGRESSION GATE for the `task_name` corruption.
    ///
    /// The production call shape: the key and the event agree, because both come
    /// from the same event. Every value must keep its own name across a long
    /// interleaved run, which is the invariant the field data violated.
    #[test]
    fn a_value_never_resolves_to_another_values_name() {
        let publisher = Publisher::security();
        let mut cache = FormatCache::new(cap(64));
        let values = [13312u64, 13313, 13317, 12800];

        // Interleave the four tasks many times over. A cache that carried a
        // name across keys would surface it within a few passes.
        for pass in 0..250 {
            let value = values[pass % values.len()];
            let got = cache.get_or_insert_with(
                "Microsoft-Windows-Security-Auditing",
                TASK,
                value,
                || publisher.format(TASK, value),
            );
            assert_eq!(
                got.name,
                publisher.expected(TASK, value),
                "task {value} resolved to another task's name on pass {pass}"
            );
        }

        // Four distinct values, so four FFI calls total no matter the traffic.
        assert_eq!(publisher.calls(), values.len());
    }

    /// Guard on the guard: if the resolver is answered from a DIFFERENT event
    /// than the key was built from, the cache stores a real name under the wrong
    /// value and every later event with that value inherits it.
    ///
    /// This is the defect, reproduced. It exists to prove the gate above can
    /// actually see the failure rather than being green by construction, and to
    /// state in executable form the one thing the call site must not do.
    #[test]
    fn mismatched_key_and_event_poisons_the_entry_permanently() {
        let publisher = Publisher::security();
        let mut cache = FormatCache::new(cap(64));

        // Key says 13317; the event handed to the resolver is 13313.
        let poisoned =
            cache.get_or_insert_with("Microsoft-Windows-Security-Auditing", TASK, 13317, || {
                publisher.format(TASK, 13313)
            });
        assert_eq!(poisoned.name.as_deref(), Some("Process Termination"));

        // The entry is now wrong for everyone. A correctly-paired lookup does
        // not repair it: it never reaches the resolver at all.
        let later =
            cache.get_or_insert_with("Microsoft-Windows-Security-Auditing", TASK, 13317, || {
                publisher.format(TASK, 13317)
            });
        assert!(later.hit);
        assert_eq!(
            later.name.as_deref(),
            Some("Process Termination"),
            "a poisoned entry is permanent, which is why the pairing is the \
             call site's responsibility and is asserted there"
        );
        assert_eq!(publisher.calls(), 1);
    }

    /// Flags partition the namespace: task 5 and keyword 5 are different rows.
    #[test]
    fn flags_do_not_collide_on_equal_values() {
        let mut cache = FormatCache::new(cap(64));
        let same_value = 5u64;
        let task = cache.get_or_insert_with("P", TASK, same_value, || Some("task-name".into()));
        let opcode =
            cache.get_or_insert_with("P", OPCODE, same_value, || Some("opcode-name".into()));
        let keyword =
            cache.get_or_insert_with("P", KEYWORD, same_value, || Some("keyword-name".into()));
        assert_eq!(task.name.as_deref(), Some("task-name"));
        assert_eq!(opcode.name.as_deref(), Some("opcode-name"));
        assert_eq!(keyword.name.as_deref(), Some("keyword-name"));
        assert_eq!(cache.len(), 3);
    }

    /// Publishers partition it too: task values are manifest-local, so one table
    /// serving every publisher is only sound because the name is in the key.
    #[test]
    fn publishers_do_not_collide_on_equal_task_values() {
        let mut cache = FormatCache::new(cap(64));
        let a = cache.get_or_insert_with("Publisher-A", TASK, 13312, || Some("A task".into()));
        let b = cache.get_or_insert_with("Publisher-B", TASK, 13312, || Some("B task".into()));
        assert_eq!(a.name.as_deref(), Some("A task"));
        assert_eq!(b.name.as_deref(), Some("B task"));
        let a_again = cache.get_or_insert_with("Publisher-A", TASK, 13312, || {
            panic!("resident entry must not re-enter the resolver")
        });
        assert!(a_again.hit);
        assert_eq!(a_again.name.as_deref(), Some("A task"));
    }

    /// A resolved `None` is an answer, not a gap. Publishers with no task table
    /// are common, and re-asking the API per event for them is what a flooded
    /// channel cannot afford.
    #[test]
    fn a_negative_result_is_cached_and_not_re_resolved() {
        let mut cache = FormatCache::new(cap(64));
        let first = cache.get_or_insert_with("P", TASK, 99, || None);
        assert!(first.name.is_none());
        assert!(!first.hit);
        let second = cache.get_or_insert_with("P", TASK, 99, || panic!("negative must be cached"));
        assert!(second.name.is_none());
        assert!(second.hit);
    }

    /// Eviction must lose entries, never rewrite them. An evicted key that comes
    /// back is re-resolved from the API and gets its own name again.
    #[test]
    fn eviction_re_resolves_rather_than_returning_a_neighbours_name() {
        let publisher = Publisher::security();
        let mut cache = FormatCache::new(cap(2));
        let values = [13312u64, 13313, 13317];

        // Capacity 2 against 3 hot values: every lookup evicts.
        for pass in 0..90 {
            let value = values[pass % values.len()];
            let got = cache.get_or_insert_with(
                "Microsoft-Windows-Security-Auditing",
                TASK,
                value,
                || publisher.format(TASK, value),
            );
            assert_eq!(
                got.name,
                publisher.expected(TASK, value),
                "eviction handed task {value} the wrong name on pass {pass}"
            );
        }
        assert_eq!(cache.len(), 2);
        // Thrashing, as expected, and the point: it is SLOW, never wrong.
        assert_eq!(publisher.calls(), 90);
    }

    /// The scratch key must never become an entry. If it ever did, a later probe
    /// mutating it would corrupt the map's hashing, which is the failure the
    /// caller-owned key made reachable.
    #[test]
    fn the_probe_key_is_never_the_stored_key() {
        let mut cache = FormatCache::new(cap(8));
        _ = cache.get_or_insert_with("Publisher-A", TASK, 1, || Some("one".into()));
        // A probe for a different, absent key mutates the scratch in place.
        _ = cache.get_or_insert_with("Publisher-BBBBBBBBBBBBBBBB", KEYWORD, u64::MAX, || None);
        // If the stored key had aliased the scratch, this lookup would miss.
        let again = cache.get_or_insert_with("Publisher-A", TASK, 1, || {
            panic!("stored key must not alias the probe scratch")
        });
        assert!(again.hit);
        assert_eq!(again.name.as_deref(), Some("one"));
    }

    proptest! {
        /// Over arbitrary traffic and an arbitrary capacity, the cache must
        /// behave exactly like the manifest it is caching: every answer equals
        /// what the resolver would have said for that key, hit or miss.
        ///
        /// This is the general statement of the field defect. It covers key
        /// shapes the hand-written cases do not (empty publisher names, shared
        /// prefixes, `u64::MAX` values, capacity 1) because those are precisely
        /// where a key-construction bug hides.
        #[test]
        fn cached_answers_always_equal_the_uncached_ones(
            capacity in 1usize..32,
            traffic in prop::collection::vec(
                (
                    prop::sample::select(vec![
                        String::new(),
                        "P".to_string(),
                        "PP".to_string(),
                        "Microsoft-Windows-Security-Auditing".to_string(),
                    ]),
                    prop::sample::select(vec![TASK, OPCODE, KEYWORD]),
                    prop::sample::select(vec![0u64, 1, 13312, 13313, 13317, u64::MAX]),
                ),
                1..400,
            ),
        ) {
            // Truth: the name a resolver would produce for this exact key.
            let truth = |publisher: &str, flag: u32, value: u64| -> Option<String> {
                if value == 0 {
                    None
                } else {
                    Some(format!("{publisher}/{flag}/{value}"))
                }
            };

            let mut cache = FormatCache::new(cap(capacity));
            for (publisher, flag, value) in traffic {
                let got = cache.get_or_insert_with(&publisher, flag, value, || {
                    truth(&publisher, flag, value)
                });
                prop_assert_eq!(got.name, truth(&publisher, flag, value));
            }
            prop_assert!(cache.len() <= capacity);
        }
    }
}
