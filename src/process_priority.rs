//! The priority class the process settles at once its topology is running.
//!
//! A supervisor that wants Vector at a lower priority in steady state cannot set it
//! from outside at start: startup (config load, VRL compilation, topology build) is
//! the burst that most needs the CPU, and a lowered class there can starve it on a
//! busy host. So the process starts at whatever class it was given and lowers itself
//! here, once, after it has started.
//!
//! There is no raise around a reload. A reload compiles a new config inside the
//! running process, and would run at the steady class.

use vector_lib::config::SteadyPriority;

/// Where the priority class is applied: the current process in production, a
/// recorder in tests.
trait PriorityClassSetter {
    /// Apply `priority` to this process.
    fn set(&self, priority: SteadyPriority) -> std::io::Result<()>;
}

/// The current process, through `SetPriorityClass`.
struct CurrentProcess;

impl PriorityClassSetter for CurrentProcess {
    fn set(&self, priority: SteadyPriority) -> std::io::Result<()> {
        use windows_sys::Win32::System::Threading::{
            BELOW_NORMAL_PRIORITY_CLASS, GetCurrentProcess, NORMAL_PRIORITY_CLASS, SetPriorityClass,
        };

        let class = match priority {
            SteadyPriority::BelowNormal => BELOW_NORMAL_PRIORITY_CLASS,
            SteadyPriority::Normal => NORMAL_PRIORITY_CLASS,
        };
        // SAFETY: `GetCurrentProcess` returns a pseudo-handle that is always valid for
        // the calling process and is never closed; no pointer crosses the boundary.
        let ok = unsafe { SetPriorityClass(GetCurrentProcess(), class) };
        if ok == 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

/// Settle the process at `priority`, the `steady_priority` global option. `None`
/// leaves the priority class as the process was started with.
///
/// Best-effort: a refused change is a warning, never a failed start.
pub(crate) fn settle(priority: Option<SteadyPriority>) {
    settle_with(priority, &CurrentProcess);
}

fn settle_with(priority: Option<SteadyPriority>, setter: &impl PriorityClassSetter) {
    let Some(priority) = priority else {
        return;
    };
    match setter.set(priority) {
        Ok(()) => tracing::info!(
            message = "Settled the process priority class.",
            steady_priority = priority.as_str(),
        ),
        Err(error) => tracing::warn!(
            message = "Could not settle the process priority class; it stays as started.",
            steady_priority = priority.as_str(),
            %error,
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    #[derive(Default)]
    struct Recorder {
        calls: Mutex<Vec<SteadyPriority>>,
        refuse: bool,
    }

    impl PriorityClassSetter for Recorder {
        fn set(&self, priority: SteadyPriority) -> std::io::Result<()> {
            self.calls.lock().unwrap().push(priority);
            if self.refuse {
                Err(std::io::Error::from_raw_os_error(5))
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn absent_leaves_the_priority_alone() {
        let recorder = Recorder::default();
        settle_with(None, &recorder);
        assert!(recorder.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn a_configured_priority_is_applied_once() {
        for priority in [SteadyPriority::BelowNormal, SteadyPriority::Normal] {
            let recorder = Recorder::default();
            settle_with(Some(priority), &recorder);
            assert_eq!(*recorder.calls.lock().unwrap(), vec![priority]);
        }
    }

    #[test]
    fn a_refused_change_does_not_panic_or_retry() {
        let recorder = Recorder {
            refuse: true,
            ..Recorder::default()
        };
        settle_with(Some(SteadyPriority::BelowNormal), &recorder);
        assert_eq!(recorder.calls.lock().unwrap().len(), 1);
    }

    /// The production setter against this test process: lowered, then restored,
    /// read back with `GetPriorityClass` each time.
    #[test]
    fn the_current_process_takes_the_class() {
        use windows_sys::Win32::System::Threading::{
            BELOW_NORMAL_PRIORITY_CLASS, GetCurrentProcess, GetPriorityClass,
            NORMAL_PRIORITY_CLASS, SetPriorityClass,
        };

        // SAFETY: the pseudo-handle is always valid for the calling process.
        let class = || unsafe { GetPriorityClass(GetCurrentProcess()) };
        let before = class();

        CurrentProcess.set(SteadyPriority::BelowNormal).unwrap();
        assert_eq!(class(), BELOW_NORMAL_PRIORITY_CLASS);
        CurrentProcess.set(SteadyPriority::Normal).unwrap();
        assert_eq!(class(), NORMAL_PRIORITY_CLASS);

        // Leave the test process as it was started.
        // SAFETY: as above; `before` came from `GetPriorityClass`.
        unsafe { SetPriorityClass(GetCurrentProcess(), before) };
    }
}
