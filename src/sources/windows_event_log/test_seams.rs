//! Exclusive access to the source's process-global fault-injection seams.
//!
//! # Why this exists
//!
//! The recovery design is driven in tests through seams that must be process
//! globals: the `EvtNext` and `EvtSubscribe` scripts, the render and bookmark
//! failure switches, the request and flag logs, the returned-record oracle, the
//! handle-close counters, and the render-path call counters in
//! [`super::metadata`]. Win32 handles are owned by the subscription and moved
//! between threads by ownership transfer, so there is no object a test can
//! reach in to configure: the injection point is inside the call path and has
//! to be reachable from wherever that path runs.
//!
//! `cargo test` runs tests on many threads by default. Two tests touching any
//! of those globals at the same time corrupt each other, and because the
//! corruption depends on interleaving, the failure is intermittent: green
//! locally, red on a maintainer's first run.
//!
//! # Why it is a guard and not an annotation
//!
//! The usual answer is `#[serial_test::serial]`, and that is what this source
//! used. It failed, because it is a rule you have to remember:
//!
//! * a test that installs no seam of its own but drives a real subscription
//!   still perturbs seams, since every `EvtNext` appends to the request log,
//!   bumps the returned-record oracle and consumes any installed script. Those
//!   tests carried no annotation, nothing said they needed one, and they ran
//!   concurrently with the tests that did;
//! * forgetting the annotation costs nothing at compile time and usually
//!   nothing on the run where it was forgotten.
//!
//! So the requirement is enforced instead of documented:
//!
//! 1. Every seam installer takes `&SeamSession`, so no script, log or failure
//!    switch can be installed without holding one.
//! 2. [`SeamSession::assert_held`] runs inside `EventLogSubscription::new`
//!    under `cfg(test)`. A test that drives a real subscription without the
//!    session panics on the spot with an explanation, whether or not it
//!    installs a seam. That is the case the annotation regime missed.
//! 3. Acquiring resets every seam, and so does dropping, so no test can inherit
//!    or leak seam state even if it panics mid-way.
//!
//! A future test that needs a seam gets a compile error; a future test that
//! drives a subscription gets a deterministic panic naming this file. Neither
//! can silently reintroduce the race.

use std::sync::{Mutex, MutexGuard};
use std::thread::ThreadId;

use super::{metadata, subscription};

/// Process-wide exclusion over every seam listed in the module docs.
static SEAM_LOCK: Mutex<()> = Mutex::new(());

/// Thread currently holding the session, or `None`. Read by
/// [`SeamSession::assert_held`], which is why the check is against the calling
/// thread rather than a bare "someone holds it" flag: another test holding the
/// session must not satisfy the requirement for a test that forgot it.
static SEAM_OWNER: Mutex<Option<ThreadId>> = Mutex::new(None);

/// Exclusive, self-resetting access to the fault-injection seams.
pub(super) struct SeamSession {
    /// Held for the lifetime of the session. Never read.
    _lock: MutexGuard<'static, ()>,
}

impl SeamSession {
    /// Block until no other test holds the seams, then hand them over reset.
    pub(super) fn acquire() -> Self {
        // A panicking test poisons the lock. The poison carries no information
        // here, because the next holder resets every seam on entry anyway, and
        // propagating it would turn one real failure into a cascade of
        // unrelated ones.
        let lock = SEAM_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let session = Self { _lock: lock };
        reset_all();
        *lock_owner() = Some(std::thread::current().id());
        session
    }

    /// Panic unless the calling thread holds the session.
    ///
    /// Called from `EventLogSubscription::new`. Driving a real subscription is
    /// enough to corrupt another test's seams, so "installs a seam" is the
    /// wrong trigger for the requirement and "creates a subscription" is the
    /// right one.
    pub(super) fn assert_held() {
        let owner = *lock_owner();
        assert_eq!(
            owner,
            Some(std::thread::current().id()),
            "this test creates an EventLogSubscription, which reads and mutates \
             the process-global fault-injection seams (EvtNext script, request \
             log, returned-record oracle, handle counters). Start the test with \
             `let _seams = SeamSession::acquire();` and keep that binding alive \
             for the whole test. See src/sources/windows_event_log/test_seams.rs"
        );
    }
}

impl Drop for SeamSession {
    fn drop(&mut self) {
        *lock_owner() = None;
        // Leave the seams pristine for the next holder as well as resetting on
        // entry: either end alone would be enough, both together mean a test
        // that panics between them still cannot leak state.
        reset_all();
    }
}

fn lock_owner() -> MutexGuard<'static, Option<ThreadId>> {
    SEAM_OWNER
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Return every seam to its shipped-binary behavior.
///
/// Adding a seam without adding it here is the one remaining way to leak state
/// between tests, which is why the seams and this function live in the module
/// docs above as one list.
fn reset_all() {
    use std::sync::atomic::Ordering::SeqCst;

    macro_rules! clear {
        ($static:path) => {
            *$static
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
        };
    }

    clear!(subscription::EVT_NEXT_SCRIPT);
    clear!(subscription::EVT_SUBSCRIBE_SCRIPT);
    clear!(subscription::EVT_NEXT_REQUESTS);
    clear!(subscription::EVT_SUBSCRIBE_FLAG_LOG);
    clear!(subscription::DRAIN_STEP_HOOK);

    subscription::FAIL_ALL_RENDERS.store(false, SeqCst);
    subscription::FAIL_ALL_BOOKMARK_UPDATES.store(false, SeqCst);
    subscription::EVT_NEXT_RETURNED_TOTAL.store(0, SeqCst);
    subscription::PUBLISHER_HANDLE_CLOSES.store(0, SeqCst);
    subscription::SUBSCRIPTION_HANDLE_CLOSES.store(0, SeqCst);
    subscription::SUBSCRIPTION_TEARDOWN_CLOSES.store(0, SeqCst);

    metadata::seam::reset();
}

#[cfg(test)]
mod tests {
    use super::SeamSession;

    /// The enforcement has to be live, not merely present.
    ///
    /// Deleting the `assert_held` call from `EventLogSubscription::new`, or
    /// weakening the check to "somebody holds it", leaves every other test in
    /// this source passing: the whole failure mode being fixed here is that a
    /// test which forgets the session looks fine until an unrelated test
    /// happens to interleave with it. This asserts the guard rejects the
    /// unheld case and accepts the held one, so the requirement cannot decay
    /// back into a convention without a red test.
    #[test]
    fn the_session_requirement_is_enforced_not_merely_documented() {
        let previous = std::panic::take_hook();
        // The panic below is expected; its backtrace would only be noise.
        std::panic::set_hook(Box::new(|_| {}));
        let unheld = std::panic::catch_unwind(SeamSession::assert_held);
        std::panic::set_hook(previous);
        assert!(
            unheld.is_err(),
            "assert_held must reject a thread that does not hold the session"
        );

        let _seams = SeamSession::acquire();
        SeamSession::assert_held();
    }
}
