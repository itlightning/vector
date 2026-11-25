//! Process working set and private bytes (Windows).
//!
//! Everything else this build measures is allocator-level: mimalloc's committed and reserved
//! totals, the sampled live set, per-component live bytes from the tracing allocator. None of
//! those is what an operator or a support case actually asks about, which is how much memory the
//! process is holding according to the OS. Working set and private bytes are that number, and the
//! gap between them and the allocator's committed total is the part of the answer that allocator
//! data alone can never supply.
//!
//! Two ways in, and neither adds a knob to the shipped default:
//!
//! - In a `mimalloc-pprof` profiling build the sample rides along with each periodic heap snapshot
//!   ([`crate::heap_profile::dump`]), always on, so the working set lands next to the allocator
//!   statistics for the same instant.
//! - Otherwise (and in a profiling build that is not writing heap profiles) [`spawn`] runs a timer,
//!   off unless `SPARKLOGS_RSS_LOG_INTERVAL_SECS` names a nonzero number of seconds. That path is
//!   safe in production: a couple of counter reads per interval, and nothing at all when unset.
//!
//! `K32GetProcessMemoryInfo` is used rather than `GetProcessMemoryInfo` so the binary imports
//! kernel32 only and never links psapi. It has been exported from kernel32 since Windows 7, well
//! under the agent's NT 6.3 floor, so it is imported statically instead of being resolved at run
//! time the way `heap_reclaim` has to resolve its Windows 8 entry points.

use std::ffi::c_ulong;
use std::mem::{size_of, zeroed};
use std::sync::OnceLock;
use std::thread;
use std::time::Duration;

/// Seconds between samples on the standalone timer. Unset, empty, or 0 means the timer never
/// starts, which is the shipped default.
const INTERVAL_ENV: &str = "SPARKLOGS_RSS_LOG_INTERVAL_SECS";

type Handle = isize;
type Bool = i32;

/// `PROCESS_MEMORY_COUNTERS_EX`. `cb` carries the caller's struct size, so a layout that
/// disagreed with the running system's would be rejected rather than misread. On x64 the two
/// `u32`s pack into the first 8 bytes and every `usize` that follows is naturally aligned, so the
/// declaration matches the C layout with no padding of its own.
#[repr(C)]
#[derive(Clone, Copy)]
struct ProcessMemoryCountersEx {
    cb: u32,
    page_fault_count: u32,
    peak_working_set_size: usize,
    working_set_size: usize,
    quota_peak_paged_pool_usage: usize,
    quota_paged_pool_usage: usize,
    quota_peak_non_paged_pool_usage: usize,
    quota_non_paged_pool_usage: usize,
    pagefile_usage: usize,
    peak_pagefile_usage: usize,
    private_usage: usize,
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetCurrentProcess() -> Handle;
    fn K32GetProcessMemoryInfo(
        process: Handle,
        counters: *mut ProcessMemoryCountersEx,
        cb: c_ulong,
    ) -> Bool;
}

/// One reading of the OS's view of this process.
#[derive(Clone, Copy)]
pub(crate) struct Sample {
    /// Physical memory currently mapped in for the process.
    pub working_set_bytes: u64,
    /// The largest working set the process has held since it started.
    pub peak_working_set_bytes: u64,
    /// Committed private (non-shareable) bytes: `PrivateUsage`, what Task Manager calls
    /// "Commit size". Unlike the working set this does not fall when pages are trimmed out to
    /// the pagefile, so it is the better retention signal of the two.
    pub private_bytes: u64,
    /// `PagefileUsage`, kept beside `private_bytes` because the two are equal in the ordinary
    /// case and a divergence says the process holds committed memory the counter attributes
    /// differently.
    pub pagefile_bytes: u64,
    /// Peak of the above.
    pub peak_pagefile_bytes: u64,
    /// Lifetime page fault count; its rate across two samples is what distinguishes a process
    /// growing into new memory from one being trimmed and faulting the same pages back.
    pub page_faults: u64,
}

/// Read the counters, or `None` if the call failed (nothing here is worth failing a process
/// over, and a missed sample is simply a gap in the series).
pub(crate) fn sample() -> Option<Sample> {
    // SAFETY: an all-zero struct is valid; `cb` then tells the API its size.
    let mut counters: ProcessMemoryCountersEx = unsafe { zeroed() };
    counters.cb = size_of::<ProcessMemoryCountersEx>() as u32;
    // SAFETY: GetCurrentProcess returns a pseudo-handle that needs no closing, and `counters` is
    // a live, correctly sized out-parameter.
    let ok = unsafe {
        K32GetProcessMemoryInfo(
            GetCurrentProcess(),
            &mut counters,
            size_of::<ProcessMemoryCountersEx>() as c_ulong,
        )
    };
    (ok != 0).then(|| Sample {
        working_set_bytes: counters.working_set_size as u64,
        peak_working_set_bytes: counters.peak_working_set_size as u64,
        private_bytes: counters.private_usage as u64,
        pagefile_bytes: counters.pagefile_usage as u64,
        peak_pagefile_bytes: counters.peak_pagefile_usage as u64,
        page_faults: u64::from(counters.page_fault_count),
    })
}

/// Log one sample. `trigger` names what asked for it (`heap_profile` for the line emitted next to
/// the allocator statistics, `timer` for the standalone interval), so the two series stay
/// distinguishable when both are running.
///
/// Rate limiting is off: a short interval would otherwise trip the internal limiter and drop the
/// samples the operator asked for, exactly as for the allocator statistics line.
pub(crate) fn log_sample(trigger: &'static str) {
    let Some(sample) = sample() else {
        debug!(
            message = "Could not read process memory counters.",
            trigger,
            internal_log_rate_limit = false,
        );
        return;
    };

    info!(
        message = "Process memory.",
        trigger,
        working_set_bytes = sample.working_set_bytes,
        peak_working_set_bytes = sample.peak_working_set_bytes,
        private_bytes = sample.private_bytes,
        pagefile_bytes = sample.pagefile_bytes,
        peak_pagefile_bytes = sample.peak_pagefile_bytes,
        page_faults = sample.page_faults,
        internal_log_rate_limit = false,
    );
}

/// Start the standalone sampling timer if `SPARKLOGS_RSS_LOG_INTERVAL_SECS` is set to a nonzero
/// number of seconds. A no-op otherwise, which is the shipped default.
///
/// An unparseable value is reported and treated as off rather than as some default: this path is
/// compiled into the production binary, so a typo must not switch on periodic logging nobody
/// asked for.
pub(crate) fn spawn() {
    let Some(interval) = interval() else {
        return;
    };

    info!(
        message = "Process memory logging enabled.",
        variable = INTERVAL_ENV,
        interval_secs = interval.as_secs(),
    );

    // Detached, so it cannot hold up shutdown: the process exits when main returns and this
    // thread goes with it, wherever in the sleep it happens to be.
    let spawned = thread::Builder::new()
        .name("vector-process-memory".to_string())
        .spawn(move || {
            loop {
                thread::sleep(interval);
                log_sample("timer");
            }
        });

    if let Err(error) = spawned {
        warn!(message = "Could not start process memory logging.", %error);
    }
}

/// Whether memory logging is armed, which is this module's standalone-timer gate. Other periodic
/// Windows memory diagnostics reuse it (see [`crate::heap_reclaim`]) so that one variable arms all
/// of them and the shipped default stays silent.
pub(crate) fn logging_enabled() -> bool {
    interval().is_some()
}

/// The configured sampling interval, or `None` when logging is off. Resolved once: the gate is
/// consulted from more than one timer, and the warning below has to be a single line rather than
/// one per consultation.
fn interval() -> Option<Duration> {
    static INTERVAL: OnceLock<Option<Duration>> = OnceLock::new();
    *INTERVAL.get_or_init(resolve_interval)
}

fn resolve_interval() -> Option<Duration> {
    let value = std::env::var(INTERVAL_ENV).ok()?;
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    match value.parse::<u64>() {
        Ok(0) => None,
        Ok(secs) => Some(Duration::from_secs(secs)),
        Err(error) => {
            warn!(
                message = "Ignoring unparseable process memory log interval; logging stays off.",
                variable = INTERVAL_ENV,
                value = %value,
                %error,
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn samples_the_current_process() {
        let sample = sample().expect("K32GetProcessMemoryInfo should succeed for the caller");
        assert!(sample.working_set_bytes > 0);
        assert!(sample.private_bytes > 0);
        assert!(sample.peak_working_set_bytes >= sample.working_set_bytes);
    }
}
