//! Periodic reclaim of free-but-committed process heap space (Windows).
//!
//! An ingest burst churns the low-fragmentation heap hard enough that the heap keeps tens
//! of megabytes of committed-but-free space once the burst is over. `HeapSetInformation`
//! with `HeapOptimizeResources` coalesces free blocks and decommits whole free subsegments.
//! It does no liveness tracing, since the heap already knows what is free, so its cost
//! tracks the number of free blocks and subsegments rather than heap size or live objects.
//!
//! The real hazard is not the pause but decommit and recommit thrash: pages handed back
//! return as zero-fill faults the next time the process grows. Two gates protect against
//! that. There must be enough free space for the reclaim to be worth its faults, and that
//! must hold across two consecutive samples, which a pipeline still moving events will not
//! do because it churns its free space between ticks.
//!
//! The kernel32 surface is declared here rather than pulled from windows-sys, which this
//! crate depends on with a narrow feature set. Two of the four entry points have to be
//! resolved at run time anyway (see [`HeapApi::resolve`]), and keeping the whole surface
//! local means this file is the only thing a reader has to check.
//!
//! This whole file is a no-op in any `mimalloc-pprof` build. It operates on the NT process
//! heap, which mimalloc replaces wholesale, so the summary reports a heap nothing allocates
//! from and the optimize call has nothing to release. Whatever this reclaims can therefore
//! only be measured on a system-allocator build, which is what ships.

use std::ffi::{c_ulong, c_void};
use std::mem::{size_of, transmute, zeroed};
use std::thread;
use std::time::{Duration, Instant};

/// How often the heap is sampled. Two consecutive samples have to agree before any work
/// happens, so a reclaim follows the start of a quiet period by at least twice this.
const SAMPLE_INTERVAL: Duration = Duration::from_secs(30);

/// Free-but-committed bytes below which a reclaim is not worth the zero-fill faults the
/// returned pages cost the next time the process grows.
const MIN_RECLAIMABLE_BYTES: usize = 5 * 1024 * 1024;

/// `HEAP_INFORMATION_CLASS::HeapOptimizeResources`.
const HEAP_OPTIMIZE_RESOURCES: i32 = 3;

/// `HEAP_OPTIMIZE_RESOURCES_INFORMATION`: a version field that must be 1, and a flags
/// field that must be 0.
#[repr(C)]
struct OptimizeResourcesInformation {
    version: u32,
    flags: u32,
}

/// `HEAP_SUMMARY`. `cb` is an in-parameter carrying the caller's struct size, so a layout
/// that disagreed with the running system's would be rejected rather than misread.
#[repr(C)]
#[derive(Clone, Copy)]
struct HeapSummary {
    cb: u32,
    allocated: usize,
    committed: usize,
    reserved: usize,
    max_reserve: usize,
}

type Handle = isize;
type Bool = i32;
type ProcAddress = unsafe extern "system" fn() -> isize;

type HeapSummaryFn = unsafe extern "system" fn(Handle, u32, *mut HeapSummary) -> Bool;
type HeapSetInformationFn = unsafe extern "system" fn(Handle, i32, *const c_void, usize) -> Bool;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetProcessHeap() -> Handle;
    fn GetModuleHandleW(module_name: *const u16) -> Handle;
    fn GetProcAddress(module: Handle, proc_name: *const u8) -> Option<ProcAddress>;
    fn GetLastError() -> c_ulong;
}

/// The two kernel32 entry points the reclaim needs, resolved at run time.
#[derive(Clone, Copy)]
struct HeapApi {
    summary: HeapSummaryFn,
    set_information: HeapSetInformationFn,
}

impl HeapApi {
    /// Resolve the entry points instead of importing them. `HeapSummary` arrived in
    /// Windows 8 and the `HeapOptimizeResources` class in Windows 8.1; a static import
    /// would refuse to load the process at all on an older host, where the right answer
    /// is to skip the reclaim and carry on.
    fn resolve() -> Option<Self> {
        let module_name: Vec<u16> = "kernel32.dll\0".encode_utf16().collect();
        // SAFETY: kernel32 is always loaded, and the name is a NUL-terminated UTF-16
        // buffer that outlives the call.
        let module = unsafe { GetModuleHandleW(module_name.as_ptr()) };
        if module == 0 {
            return None;
        }
        // SAFETY: `module` is a live module handle and both names are NUL-terminated.
        let (summary, set_information) = unsafe {
            (
                GetProcAddress(module, c"HeapSummary".as_ptr().cast())?,
                GetProcAddress(module, c"HeapSetInformation".as_ptr().cast())?,
            )
        };
        Some(Self {
            // SAFETY: both addresses came from kernel32 under their documented names, so
            // the signatures above are the ones the exports actually have.
            summary: unsafe { transmute::<ProcAddress, HeapSummaryFn>(summary) },
            set_information: unsafe {
                transmute::<ProcAddress, HeapSetInformationFn>(set_information)
            },
        })
    }

    /// Read the heap's committed and allocated totals. `HeapSummary` reads counters the
    /// heap already maintains, so unlike `HeapWalk` it does not traverse the heap.
    fn summary(&self, heap: Handle) -> Option<HeapSummary> {
        // SAFETY: an all-zero HeapSummary is valid; `cb` then tells the API its size.
        let mut summary: HeapSummary = unsafe { zeroed() };
        summary.cb = size_of::<HeapSummary>() as u32;
        // SAFETY: `heap` is the process heap and `summary` is a live, sized-out struct.
        let ok = unsafe { (self.summary)(heap, 0, &mut summary) };
        (ok != 0).then_some(summary)
    }

    /// Ask the heap to coalesce free blocks and decommit free subsegments. Returns false
    /// on a host whose heap does not know the `HeapOptimizeResources` class.
    fn optimize(&self, heap: Handle) -> bool {
        let info = OptimizeResourcesInformation {
            version: 1,
            flags: 0,
        };
        // SAFETY: `heap` is the process heap; `info` matches the class's documented
        // structure and outlives the call.
        let ok = unsafe {
            (self.set_information)(
                heap,
                HEAP_OPTIMIZE_RESOURCES,
                (&raw const info).cast(),
                size_of::<OptimizeResourcesInformation>(),
            )
        };
        ok != 0
    }
}

/// Start the reclaim thread. A no-op on a host without the APIs.
pub(crate) fn spawn() {
    let Some(api) = HeapApi::resolve() else {
        debug!("Heap resource reclaim is unavailable on this version of Windows.");
        return;
    };
    // SAFETY: no arguments, and the returned handle stays owned by the process.
    let heap = unsafe { GetProcessHeap() };
    if heap == 0 {
        return;
    }
    let builder = thread::Builder::new().name("vector-heap-reclaim".to_string());
    if let Err(error) = builder.spawn(move || run(api, heap)) {
        debug!(%error, "Could not start the heap resource reclaim thread.");
    }
}

fn run(api: HeapApi, heap: Handle) {
    let mut previous_free: Option<usize> = None;
    loop {
        thread::sleep(SAMPLE_INTERVAL);
        let Some(before) = api.summary(heap) else {
            continue;
        };
        let free = before.committed.saturating_sub(before.allocated);
        let was_idle = previous_free.is_some_and(|previous| previous >= MIN_RECLAIMABLE_BYTES);
        previous_free = Some(free);
        if !was_idle || free < MIN_RECLAIMABLE_BYTES {
            continue;
        }

        let started = Instant::now();
        if !api.optimize(heap) {
            // SAFETY: no arguments, and this thread made the failing call.
            let last_error = unsafe { GetLastError() };
            debug!(
                last_error,
                "Heap resource reclaim is not supported on this host; stopping."
            );
            return;
        }
        let elapsed_ms = started.elapsed().as_millis();
        let Some(after) = api.summary(heap) else {
            debug!("Reclaimed free heap resources; the heap summary afterwards could not be read.");
            previous_free = None;
            continue;
        };
        log_reclaim(&before, &after, elapsed_ms);
        // Start the two-sample count over so the next reclaim needs a fresh quiet period.
        previous_free = None;
    }
}

/// Report what one reclaim achieved.
///
/// Every invocation is logged, not only one that released something. A reclaim that returned
/// nothing is the denominator: without it, a measurement cannot tell a timer that never fired
/// from one that fired and achieved nothing, which is the exact ambiguity this line exists to
/// remove.
///
/// The gate is [`crate::process_memory::logging_enabled`], the same variable that arms that
/// module's standalone timer, so this stays silent in normal operation and appears only when
/// memory logging is on. Under that gate the line is emitted at the same level and with the same
/// rate limiting as `Process memory.`, and carries `private_bytes` under that line's own field
/// name, so a reclaim can be lined up against the OS-level numbers around it. Without the gate it
/// falls back to `debug`, which is where this used to live.
fn log_reclaim(before: &HeapSummary, after: &HeapSummary, elapsed_ms: u128) {
    let free_bytes_before = before.committed.saturating_sub(before.allocated);
    let free_bytes_after = after.committed.saturating_sub(after.allocated);
    let freed_bytes = free_bytes_before.saturating_sub(free_bytes_after);
    let decommitted_bytes = before.committed.saturating_sub(after.committed);

    if !crate::process_memory::logging_enabled() {
        debug!(
            free_bytes_before,
            free_bytes_after,
            freed_bytes,
            decommitted_bytes,
            elapsed_ms,
            "Heap resources reclaimed."
        );
        return;
    }

    // Tracing levels are compile-time constants, so the armed line is written out separately
    // rather than selected at run time.
    let private_bytes = crate::process_memory::sample().map_or(0, |sample| sample.private_bytes);
    info!(
        message = "Heap resources reclaimed.",
        trigger = "heap_reclaim",
        free_bytes_before,
        free_bytes_after,
        freed_bytes,
        decommitted_bytes,
        private_bytes,
        elapsed_ms,
        internal_log_rate_limit = false,
    );
}
