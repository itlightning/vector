//! Property tests for the pure decision layer: the `(API call, code)`
//! classifier, the resume ladder, and the backoff schedule.
//!
//! # Why properties rather than more cases
//!
//! The classifier is this design's premise. Unknown codes rebuild, so a missing
//! constant costs one rebuild rather than a permanent wedge, and the whole
//! recovery model leans on that polarity holding for inputs nobody enumerated:
//! Windows returns codes we have never seen, and the enumerated tests can only
//! speak for the codes someone thought to write down. These assert the
//! invariants over randomly generated `(call site, code, returned count)`
//! triples instead, which is exactly the population the enumerated tests miss.
//!
//! Everything here is a pure function, so no Windows, no subscription, and no
//! seam is involved and the module runs anywhere.
//!
//! # Runtime
//!
//! The default budget is deliberately small so the unit suite does not slow
//! down. Two environment variables change that:
//!
//! * `WEL_PROPTEST_CASES` sets the cases per property (default
//!   [`DEFAULT_CASES`]). A soak run is `WEL_PROPTEST_CASES=200000`.
//! * `WEL_PROPTEST_SEED` pins the RNG seed as 64 hex characters.
//!
//! Every property prints the case count and the seed it ran under, so a soak
//! run produces a number worth recording (`-- --nocapture` to see it), and a
//! failure prints the exact command that reproduces that run.

use std::sync::atomic::{AtomicUsize, Ordering};

use chrono::{DateTime, Utc};
use proptest::prelude::*;
use proptest::test_runner::{Config, TestCaseError, TestError, TestRng, TestRunner};

use super::recovery::{Backoff, ResumeState, Rung, TimeRung};
use super::win32_errors::{
    DrainOutcome, INHERITED_UNDOCUMENTED_16953, QueryOrigin, RenderDisposition, SubscribeOutcome,
    classify_evt_next, classify_render, classify_subscribe,
};

/// Cases per property when nothing is set. Small on purpose: the whole module
/// is well under a second, so `cargo test` stays fast.
const DEFAULT_CASES: u32 = 256;

/// Backoff ceiling from the design (1s doubling to 60s). Restated here rather
/// than imported so the assertion has an oracle of its own.
const BACKOFF_CAP_SECS: u64 = 60;
/// Largest fraction of the computed delay that jitter may subtract.
const JITTER_FRACTION: f64 = 0.25;

fn case_budget() -> u32 {
    std::env::var("WEL_PROPTEST_CASES")
        .ok()
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(DEFAULT_CASES)
}

/// Seed for this run: the pinned one if `WEL_PROPTEST_SEED` is set, otherwise a
/// fresh one that is printed and can be pinned to reproduce.
fn run_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    if let Some(hex) = std::env::var("WEL_PROPTEST_SEED")
        .ok()
        .filter(|s| s.len() == 64)
    {
        // Chunk the bytes rather than slice by index: the filter above only
        // guarantees 64 CHARS, and a non-ASCII one would put a byte slice
        // inside a codepoint.
        let bytes = hex.as_bytes();
        for (index, byte) in seed.iter_mut().enumerate() {
            let pair = std::str::from_utf8(&bytes[index * 2..index * 2 + 2]).unwrap_or("");
            *byte = u8::from_str_radix(pair, 16).unwrap_or(0);
        }
        return seed;
    }
    // No `rand` in scope here and none needed: the clock only has to differ
    // between runs, and the value is printed so any run is reproducible.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64);
    let mut state = nanos | 1;
    for byte in &mut seed {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *byte = (state >> 24) as u8;
    }
    seed
}

fn hex(seed: &[u8; 32]) -> String {
    seed.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Run one property, reporting the case count and printing a reproduction
/// command on failure.
///
/// The success line goes to stdout deliberately. Soak runs are judged by the
/// seed and the case count of the runs that PASSED, so routing it through
/// tracing (off by default under `cargo test`) would lose the only record of
/// what was actually exercised.
#[allow(clippy::print_stdout, reason = "seed reporting for soak reproduction")]
fn check<S: Strategy>(name: &str, strategy: S, body: impl Fn(S::Value) -> Result<(), TestCaseError>)
where
    S::Value: std::fmt::Debug,
{
    let seed = run_seed();
    let cases = case_budget();
    let executed = AtomicUsize::new(0);

    let mut runner = TestRunner::new_with_rng(
        Config {
            cases,
            // Do not write regression files into the source tree: the seed
            // below reproduces a failure exactly and needs no artifact.
            failure_persistence: None,
            ..Config::default()
        },
        TestRng::from_seed(proptest::test_runner::RngAlgorithm::ChaCha, &seed),
    );

    let outcome = runner.run(&strategy, |value| {
        executed.fetch_add(1, Ordering::Relaxed);
        body(value)
    });
    let executed = executed.load(Ordering::Relaxed);

    match outcome {
        Ok(()) => println!(
            "property {name}: {executed} cases passed (seed {})",
            hex(&seed)
        ),
        Err(TestError::Abort(reason)) => panic!("property {name} aborted: {reason}"),
        Err(failure) => panic!(
            "property {name} failed after {executed} cases: {failure}\n\
             reproduce this exact run with:\n    \
             WEL_PROPTEST_SEED={} WEL_PROPTEST_CASES={cases} cargo test \
             --no-default-features --features sources-windows_event_log --lib \
             property_tests::{name}",
            hex(&seed),
        ),
    }
}

/// Where a Win32 code was observed. Classification is a matrix of `(API call,
/// code)` and never the code alone, so the call site is generated input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CallSite {
    EvtNext,
    EvtSubscribe,
    Render,
}

fn call_site() -> impl Strategy<Value = CallSite> {
    prop_oneof![
        Just(CallSite::EvtNext),
        Just(CallSite::EvtSubscribe),
        Just(CallSite::Render),
    ]
}

fn query_origin() -> impl Strategy<Value = QueryOrigin> {
    prop_oneof![Just(QueryOrigin::Operator), Just(QueryOrigin::Generated)]
}

/// Codes biased toward the interesting neighborhoods (EVT 15000s, RPC 1700s,
/// the small Win32 range) but still covering the whole `u32` space, because
/// "an input nobody enumerated" is the population these properties exist for.
fn win32_code() -> impl Strategy<Value = u32> {
    prop_oneof![
        3 => 0u32..=200,
        3 => 1100u32..=1900,
        3 => 4200u32..=4400,
        4 => 14990u32..=15100,
        2 => 16900u32..=17000,
        5 => any::<u32>(),
    ]
}

/// The codes the drain classifier names. Everything outside this set is an
/// unknown code and must rebuild.
fn drain_code_is_named(code: u32) -> bool {
    matches!(code, 259 | 4317 | 1223 | 15000 | 15009 | 5 | 15001 | 1734)
}

/// The codes the subscribe classifier names.
fn subscribe_code_is_named(code: u32) -> bool {
    matches!(code, 15000 | 15009 | 5 | 15001 | 1168 | 15011 | 15012)
        || code == INHERITED_UNDOCUMENTED_16953
}

/// Whether an outcome tells the drain loop to keep using the handle it already
/// has.
///
/// The answer is false for every variant, and that is the point: the wedge this
/// whole design exists to prevent is retrying a dead subscription handle. A
/// future variant that reused the handle would have to be added here, and the
/// property below would fail the moment it did.
const fn reuses_the_same_handle(outcome: DrainOutcome) -> bool {
    match outcome {
        // The channel is drained for now; the next pull re-enters through the
        // factory like every other path.
        DrainOutcome::Drained => false,
        DrainOutcome::SkipChannel(_) => false,
        // Reopens from the bookmark with a smaller batch.
        DrainOutcome::ReduceBatch => false,
        DrainOutcome::Rebuild => false,
    }
}

/// Whether a render-path disposition can cost more than the event it came from.
///
/// False for every variant by construction: `RenderDisposition` has no rebuild
/// arm, which is how `ERROR_INSUFFICIENT_BUFFER` (122), routine on every size
/// probe, is kept structurally incapable of tearing down a subscription.
const fn tears_down_the_subscription(disposition: RenderDisposition) -> bool {
    match disposition {
        RenderDisposition::UseBuffer => false,
        RenderDisposition::GrowBuffer => false,
        RenderDisposition::DropEvent => false,
    }
}

/// Every `(call site, code, returned count)` triple produces a decision, the
/// same decision every time, and never a panic.
#[test]
fn classification_is_total_and_pure() {
    check(
        "classification_is_total_and_pure",
        (call_site(), win32_code(), any::<u32>(), query_origin()),
        |(site, code, returned, origin)| {
            match site {
                CallSite::EvtNext => {
                    let first = classify_evt_next(code, returned, origin);
                    prop_assert_eq!(first, classify_evt_next(code, returned, origin));
                }
                CallSite::EvtSubscribe => {
                    let first = classify_subscribe(code, origin);
                    prop_assert_eq!(first, classify_subscribe(code, origin));
                }
                CallSite::Render => {
                    let first = classify_render(code);
                    prop_assert_eq!(first, classify_render(code));
                }
            }
            Ok(())
        },
    );
}

/// No input to the drain classifier ever says "retry the same handle".
///
/// That is the wedge class: a production agent spent nine hours retrying a dead
/// subscription handle against a channel that provably existed. It is also why
/// `Drained` must stay confined to the two benign terminators: treating an
/// error that carried handles as a clean drain is the same bug wearing a
/// different name, because on 1734 the API cursor advances even when the call
/// fails and the events in those handles are gone.
#[test]
fn no_drain_input_retries_the_same_handle() {
    check(
        "no_drain_input_retries_the_same_handle",
        (win32_code(), any::<u32>(), query_origin()),
        |(code, returned, origin)| {
            let outcome = classify_evt_next(code, returned, origin);
            prop_assert!(!reuses_the_same_handle(outcome));
            if outcome == DrainOutcome::Drained {
                prop_assert!(
                    code == 259 || (code == 4317 && returned == 0),
                    "only ERROR_NO_MORE_ITEMS and a zero-count 4317 are benign \
                     drain terminators, but {code} with {returned} returned was \
                     treated as a clean drain"
                );
            }
            Ok(())
        },
    );
}

/// Unknown codes rebuild, at both call sites. This is the inverted polarity the
/// whole design rests on: a missed constant costs one rebuild from the
/// checkpoint, never a wedge.
#[test]
fn unknown_codes_rebuild() {
    check(
        "unknown_codes_rebuild",
        (win32_code(), any::<u32>(), query_origin()),
        |(code, returned, origin)| {
            if !drain_code_is_named(code) {
                prop_assert_eq!(
                    classify_evt_next(code, returned, origin),
                    DrainOutcome::Rebuild
                );
            }
            if !subscribe_code_is_named(code) {
                prop_assert_eq!(classify_subscribe(code, origin), SubscribeOutcome::Retry);
            }
            Ok(())
        },
    );
}

/// A render-path code can never cost a subscription, whatever it is.
#[test]
fn render_codes_never_rebuild_a_subscription() {
    check(
        "render_codes_never_rebuild_a_subscription",
        win32_code(),
        |code| {
            let disposition = classify_render(code);
            prop_assert!(!tears_down_the_subscription(disposition));
            // 122 is routine on every size probe, so it is the one code whose
            // routing is worth naming here.
            if code == 122 {
                prop_assert_eq!(disposition, RenderDisposition::GrowBuffer);
            }
            Ok(())
        },
    );
}

/// 4317 is `ERROR_INVALID_OPERATION`, fires roughly 46 times per 3 minutes on a
/// healthy channel, and is discriminated on the returned count by four
/// independent collectors. Zero is benign; anything else is not.
#[test]
fn invalid_operation_is_benign_only_with_a_zero_count() {
    check(
        "invalid_operation_is_benign_only_with_a_zero_count",
        (any::<u32>(), query_origin()),
        |(returned, origin)| {
            let outcome = classify_evt_next(4317, returned, origin);
            if returned == 0 {
                prop_assert_eq!(outcome, DrainOutcome::Drained);
            } else {
                prop_assert_eq!(outcome, DrainOutcome::Rebuild);
            }
            Ok(())
        },
    );
}

fn time_rung() -> impl Strategy<Value = TimeRung> {
    prop_oneof![
        Just(TimeRung::BoundaryTick),
        Just(TimeRung::OneSecond),
        Just(TimeRung::TenSeconds),
        Just(TimeRung::OneMinute),
        Just(TimeRung::FiveMinutes),
        Just(TimeRung::ThirtyMinutes),
    ]
}

fn rung() -> impl Strategy<Value = Rung> {
    prop_oneof![
        Just(Rung::Bookmark),
        Just(Rung::IsolateOne),
        Just(Rung::SkipRecord),
        time_rung().prop_map(Rung::TimeAdvance),
        Just(Rung::FutureOnly),
    ]
}

fn a_time() -> DateTime<Utc> {
    DateTime::from_timestamp(1_700_000_000, 0).expect("valid timestamp")
}

fn resume_state(
    start: Rung,
    identity_usable: bool,
    record_id: Option<u64>,
    have_time: bool,
) -> ResumeState {
    let mut resume = ResumeState::new(identity_usable);
    resume.rung = start;
    resume.last_record_id = record_id;
    if have_time {
        resume.last_event_time = Some(a_time());
    }
    resume
}

/// The ladder terminates from every starting state, and never cycles.
///
/// Each rung is deliberate data loss, so walking one twice would discard a
/// window twice, and a cycle would mean a channel that escapes a poison event
/// forever without ever reaching the terminal rung that says so out loud.
#[test]
fn the_resume_ladder_always_terminates() {
    check(
        "the_resume_ladder_always_terminates",
        (
            rung(),
            any::<bool>(),
            proptest::option::of(any::<u64>()),
            any::<bool>(),
        ),
        |(start, identity_usable, record_id, have_time)| {
            // Longest possible walk: bookmark, isolate, skip, six time rungs,
            // future-only. Anything longer is a repeat.
            const LADDER_HEIGHT: usize = 10;

            let mut resume = resume_state(start, identity_usable, record_id, have_time);
            let mut seen = vec![resume.rung];

            for step in 0..LADDER_HEIGHT {
                let next = resume.advance_rung();
                if next == Rung::FutureOnly {
                    // Terminal: it must stay there however often it is pushed.
                    for _ in 0..4 {
                        prop_assert_eq!(resume.advance_rung(), Rung::FutureOnly);
                    }
                    return Ok(());
                }
                prop_assert!(
                    !seen.contains(&next),
                    "rung {:?} repeated at step {} from start {:?}: the ladder cycled",
                    next,
                    step,
                    start
                );
                seen.push(next);
            }
            prop_assert!(
                false,
                "the ladder did not reach FutureOnly within {} advances from {:?}",
                LADDER_HEIGHT,
                start
            );
            Ok(())
        },
    );
}

/// Bookmark death is a different entry point into the same ladder, and it must
/// terminate too: it is reached by a code path that never walks the poison
/// rungs, so its termination is not implied by the property above.
#[test]
fn bookmark_death_also_reaches_the_terminal_rung() {
    check(
        "bookmark_death_also_reaches_the_terminal_rung",
        (
            rung(),
            any::<bool>(),
            proptest::option::of(any::<u64>()),
            any::<bool>(),
        ),
        |(start, identity_usable, record_id, have_time)| {
            let mut resume = resume_state(start, identity_usable, record_id, have_time);
            for _ in 0..10 {
                let rung = resume.bookmark_dead();
                if rung == Rung::FutureOnly {
                    prop_assert_eq!(resume.bookmark_dead(), Rung::FutureOnly);
                    return Ok(());
                }
                prop_assert!(
                    matches!(rung, Rung::TimeAdvance(_)),
                    "a dead bookmark must resume by time or go future-only, never \
                     walk the poison rungs, but it produced {:?}",
                    rung
                );
            }
            prop_assert!(false, "repeated bookmark death never reached future-only");
            Ok(())
        },
    );
}

/// A batch as the API delivers it: record numbers ascending, times arbitrary.
///
/// Times are drawn over a wide range including values before the epoch and are
/// NOT sorted, which is the whole point. Generating ordered times is how 16
/// million property cases missed an admission gate that discarded every event
/// whose provider-written time went backwards.
fn arbitrary_batch() -> impl Strategy<Value = Vec<(DateTime<Utc>, u64)>> {
    proptest::collection::vec(
        (-2_000_000_000i64..4_000_000_000i64, 0u32..1_000_000_000),
        1..64usize,
    )
    .prop_map(|times| {
        times
            .into_iter()
            .enumerate()
            .map(|(index, (secs, nanos))| {
                let time = DateTime::from_timestamp(secs, nanos).unwrap_or_else(a_time);
                (time, 1_000 + index as u64)
            })
            .collect()
    })
}

/// Replay one batch through the source's delivery decision, returning the
/// record numbers sent and the record numbers withheld.
fn replay(resume: &mut ResumeState, batch: &[(DateTime<Utc>, u64)]) -> (Vec<u64>, Vec<u64>) {
    let mut sent = Vec::new();
    let mut withheld = Vec::new();
    for (time, record_id) in batch {
        // The drain loop, rule for rule: the poison one-shot is the only thing
        // consulted, and a sent event updates the stored position.
        if resume.take_poison_skip() {
            withheld.push(*record_id);
            continue;
        }
        sent.push(*record_id);
        resume.observe_event(*time, *record_id);
    }
    (sent, withheld)
}

/// Over arbitrary times: every event in the batch is sent, and the poison
/// one-shot is the only thing that can withhold one.
///
/// The render skip is not reachable from the pure layer, so this property
/// speaks for the poison one-shot and for the absence of any other exception.
#[test]
fn every_event_is_sent_unless_the_poison_one_shot_withholds_it() {
    check(
        "every_event_is_sent_unless_the_poison_one_shot_withholds_it",
        (
            rung(),
            any::<bool>(),
            any::<bool>(),
            any::<bool>(),
            arbitrary_batch(),
        ),
        |(start, identity_usable, have_time, armed, batch)| {
            let mut resume = resume_state(start, identity_usable, Some(500), have_time);
            resume.skip_next_record = armed;

            let (sent, withheld) = replay(&mut resume, &batch);

            prop_assert_eq!(
                sent.len() + withheld.len(),
                batch.len(),
                "every delivered record is either sent or explicitly withheld; \
                 nothing may disappear between the two"
            );
            prop_assert_eq!(
                withheld.len(),
                usize::from(armed),
                "the one-shot withholds exactly one record when armed and none \
                 when not, whatever the times are"
            );
            let expected: Vec<u64> = batch
                .iter()
                .map(|(_, record_id)| *record_id)
                .skip(usize::from(armed))
                .collect();
            prop_assert_eq!(sent, expected, "the rest of the batch is sent in order");
            Ok(())
        },
    );
}

/// The total claim: the event times have NO effect.
///
/// Two batches with the same record numbers and completely different times
/// produce the same delivery decisions. A single comparison on an event time
/// anywhere in the path breaks this, whatever form it takes and whichever
/// direction it points.
#[test]
fn changing_every_event_time_changes_nothing_about_delivery() {
    check(
        "changing_every_event_time_changes_nothing_about_delivery",
        (
            rung(),
            any::<bool>(),
            any::<bool>(),
            any::<bool>(),
            arbitrary_batch(),
            arbitrary_batch(),
        ),
        |(start, identity_usable, have_time, armed, first, second)| {
            // Same record numbers, different times: only the times differ.
            let restamped: Vec<(DateTime<Utc>, u64)> = first
                .iter()
                .enumerate()
                .map(|(index, (_, record_id))| {
                    let (time, _) = second[index % second.len()];
                    (time, *record_id)
                })
                .collect();

            let mut left = resume_state(start, identity_usable, Some(500), have_time);
            left.skip_next_record = armed;
            let mut right = resume_state(start, identity_usable, Some(500), have_time);
            right.skip_next_record = armed;

            prop_assert_eq!(
                replay(&mut left, &first),
                replay(&mut right, &restamped),
                "the same records under different times must produce the same \
                 sent and withheld sets"
            );
            Ok(())
        },
    );
}

/// Backoff is bounded by the 60s cap, non-decreasing in its computed delay, and
/// jitter stays inside the stated band.
///
/// The band matters as much as the cap: jitter exists to stop every channel
/// rebuilding in lockstep after an EventLog service restart, so a jitter that
/// collapsed to zero, or one that could grow a delay past the cap, would each
/// break a property the design states.
#[test]
fn backoff_is_bounded_monotonic_and_jittered() {
    check(
        "backoff_is_bounded_monotonic_and_jittered",
        (any::<u64>(), 1usize..24),
        |(seed, steps)| {
            let mut backoff = Backoff::new(seed);
            let mut previous_ceiling = 0f64;

            for attempt in 0..steps {
                let delay = backoff.next_delay().as_secs_f64();

                // Independent oracle: the schedule as documented, not as
                // implemented. 1s doubling, capped at 60s.
                let ceiling = (2f64.powi(attempt.min(6) as i32)).min(BACKOFF_CAP_SECS as f64);
                let floor = ceiling * (1.0 - JITTER_FRACTION);

                prop_assert!(
                    delay <= BACKOFF_CAP_SECS as f64,
                    "delay {delay}s exceeded the {BACKOFF_CAP_SECS}s cap"
                );
                prop_assert!(
                    delay <= ceiling + f64::EPSILON,
                    "delay {delay}s exceeded the scheduled {ceiling}s at attempt {attempt}"
                );
                prop_assert!(
                    delay >= floor - f64::EPSILON,
                    "delay {delay}s fell below the jitter band floor {floor}s at attempt {attempt}"
                );
                prop_assert!(
                    ceiling >= previous_ceiling,
                    "the schedule went backwards at attempt {attempt}"
                );
                previous_ceiling = ceiling;
            }

            // A reset returns to the bottom of the schedule rather than
            // continuing where the failures left off.
            backoff.reset();
            let after_reset = backoff.next_delay().as_secs_f64();
            prop_assert!(
                after_reset <= 1.0 + f64::EPSILON,
                "after a reset the first delay must be back at the 1s base, was {after_reset}s"
            );
            Ok(())
        },
    );
}
