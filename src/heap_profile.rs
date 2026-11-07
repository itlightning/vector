//! Opt-in sampled heap profiling, built only into profiling flavors.
//!
//! One switch controls everything: `SPARKLOGS_HEAP_PROFILE_DIR`. When it names a
//! directory the profiler runs and pprof dumps are written into that directory; when it is
//! unset or empty the profiler never starts and nothing is logged. No `MIMALLOC_*`
//! variable is read or written, because mimalloc's own `MIMALLOC_PROF` auto-start arms the
//! profiler at the first allocation and then rejects the explicit start below, discarding
//! the configuration with it.
//!
//! Dumps are periodic, every `SPARKLOGS_HEAP_PROFILE_INTERVAL_SECS` seconds (60 by
//! default, 0 for shutdown only), plus one final dump on the shutdown path. A retention
//! question needs the curve, not the endpoint: by the time the topology has stopped and
//! components have been dropped, whatever was being held is already released, so a
//! shutdown-only dump reports a small live set for a process that was using far more.
//!
//! Each dump is followed by mimalloc's own allocator-level counters. The pprof file
//! carries sampled allocation data only; the allocator knows what it has actually taken
//! from the OS and not returned. The gap between sampled live bytes and committed bytes is
//! what separates retention or fragmentation inside mimalloc from a leak in Vector.
//!
//! The shutdown dump is taken explicitly rather than through mimalloc's `dump_at_exit`
//! hook: that hook rides on CRT `atexit`, which Windows skips whenever the process leaves
//! through `ExitProcess`, so console Ctrl+C runs produced no file at all.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

use mimalloc_pprof::{ProfConfig, ProfConfigMode, prof};

/// Names the directory that heap profiles are written to, and switches profiling on.
const PROFILE_DIR_ENV: &str = "SPARKLOGS_HEAP_PROFILE_DIR";

/// Seconds between periodic dumps. Unset means [`DEFAULT_INTERVAL_SECS`]; 0 means no
/// periodic dumps at all, leaving only the one taken at shutdown.
const PROFILE_INTERVAL_ENV: &str = "SPARKLOGS_HEAP_PROFILE_INTERVAL_SECS";

const DEFAULT_INTERVAL_SECS: u64 = 60;

/// Outcome of [`start`], read back by [`log_started`] and [`dump`].
enum Status {
    /// The switch was unset or empty: no profiler, no output, no logging.
    Off,
    /// Profiling is running; dumps go into this directory.
    On(PathBuf),
    /// The switch was set but profiling could not be armed.
    Failed(String),
}

static STATUS: OnceLock<Status> = OnceLock::new();

/// Arm the heap profiler if `SPARKLOGS_HEAP_PROFILE_DIR` is set.
///
/// Call this as early in `main` as possible: allocations made before it are never
/// sampled, so anything later widens the blind spot at startup.
///
/// Logging is not initialized this early, so the outcome is recorded and reported by
/// [`log_started`] instead of being logged here.
pub fn start() {
    STATUS.get_or_init(|| {
        let dir = match std::env::var_os(PROFILE_DIR_ENV) {
            Some(dir) if !dir.is_empty() => PathBuf::from(dir),
            _ => return Status::Off,
        };

        // A missing directory would otherwise swallow every dump.
        if let Err(error) = std::fs::create_dir_all(&dir) {
            return Status::Failed(format!(
                "could not create heap profile directory {}: {error}",
                dir.display()
            ));
        }

        // OVERRIDE so these settings beat any ambient mimalloc option. The dump format is
        // not set here: it only governs mimalloc's own at-exit dump, which is deliberately
        // left unregistered; `dump` picks the pprof format at the call site instead.
        let mut config = ProfConfig::default();
        config.mode = ProfConfigMode::Override;

        if mimalloc_pprof::enable_heap_profiling_with(&config) {
            Status::On(dir)
        } else {
            Status::Failed("mimalloc rejected the heap profiler start request".to_string())
        }
    });
}

/// Report what [`start`] did, and begin periodic dumps. Call once logging is initialized.
pub fn log_started() {
    let dir = match STATUS.get() {
        Some(Status::On(dir)) => dir,
        Some(Status::Failed(error)) => {
            warn!(message = "Heap profiling requested but not started.", %error);
            return;
        }
        Some(Status::Off) | None => return,
    };

    let interval = interval();
    info!(
        message = "Heap profiling enabled.",
        directory = %dir.display(),
        interval_secs = interval.map_or(0, |interval| interval.as_secs()),
    );

    let Some(interval) = interval else {
        return;
    };

    // Detached, so it cannot hold up shutdown: the process exits when main returns and
    // this thread goes with it, wherever in the sleep it happens to be.
    let spawned = std::thread::Builder::new()
        .name("heap-profile".to_string())
        .spawn(move || {
            loop {
                std::thread::sleep(interval);
                dump();
            }
        });

    if let Err(error) = spawned {
        warn!(
            message = "Could not start periodic heap profile dumps; only the shutdown dump will be written.",
            %error,
        );
    }
}

/// Seconds between periodic dumps, or `None` when they are switched off.
///
/// An unparseable value is reported and treated as the default rather than as off, so a
/// typo does not silently reduce the run to a single shutdown sample.
fn interval() -> Option<Duration> {
    let secs = match std::env::var(PROFILE_INTERVAL_ENV) {
        Ok(value) if !value.trim().is_empty() => match value.trim().parse::<u64>() {
            Ok(secs) => secs,
            Err(error) => {
                warn!(
                    message = "Ignoring unparseable heap profile interval.",
                    variable = PROFILE_INTERVAL_ENV,
                    value = %value,
                    %error,
                    default_secs = DEFAULT_INTERVAL_SECS,
                );
                DEFAULT_INTERVAL_SECS
            }
        },
        _ => DEFAULT_INTERVAL_SECS,
    };

    (secs > 0).then(|| Duration::from_secs(secs))
}

/// Write one pprof heap profile and log the allocator's own counters, if profiling is
/// running.
///
/// Called on the timer and again on the shutdown path, where it runs for a normal
/// shutdown, a service stop and a console interrupt alike.
pub fn dump() {
    let Some(Status::On(dir)) = STATUS.get() else {
        return;
    };

    // The name is chosen per dump, not at startup, so the directory accumulates a time
    // series rather than one file overwriting the last.
    let path = dir.join(format!(
        "vector-heap-{}.pb",
        chrono::Utc::now().format("%Y%m%dT%H%M%S%3fZ")
    ));

    // Rate limiting is off on every line here: a short interval otherwise trips the
    // internal limiter and drops the samples the operator asked for.
    match prof::dump_proto_file(&path) {
        Ok(()) => info!(
            message = "Wrote heap profile.",
            path = %path.display(),
            bytes = file_size(&path),
            internal_log_rate_limit = false,
        ),
        // Warn and carry on: one unwritable file must not end the timer or the process.
        Err(error) => warn!(
            message = "Failed to write heap profile.",
            path = %path.display(),
            %error,
            internal_log_rate_limit = false,
        ),
    }

    log_allocator_stats();
    // Always, and with no variable of its own: every allocator number logged above is
    // allocator-internal, and the working set is the only one that says what the OS thinks the
    // process is holding. It follows the allocator line immediately, so the two read as one
    // snapshot.
    #[cfg(windows)]
    crate::process_memory::log_sample("heap_profile");
}

/// Log mimalloc's exact counters next to the sampled ones.
///
/// `sampled_live_bytes` is what the profiler believes Vector is holding; `committed_bytes`
/// is what mimalloc has taken from the OS and not given back. A large gap between them is
/// allocator retention or fragmentation, not a Vector leak.
fn log_allocator_stats() {
    let stats = prof::stats();
    let heap = &stats.heap;

    info!(
        message = "Allocator statistics.",
        sampled_live_bytes = stats.live_bytes,
        committed_bytes = heap.committed,
        reserved_bytes = heap.reserved,
        purged_bytes = heap.purged,
        // Exact application-requested bytes, but only tracked in detailed builds; the flag
        // separates "requested nothing" from "this build does not count that".
        malloc_requested_bytes = heap.malloc_requested,
        detailed_stats = heap.detailed,
        pages = heap.pages,
        pages_abandoned = heap.pages_abandoned,
        heaps = heap.heaps,
        theaps = heap.theaps,
        // Lifetime totals rather than live ones when the operator set MIMALLOC_PROF_ACCUM.
        accum = stats.accum,
        live_samples = stats.live_samples,
        unique_stacks = stats.unique_stacks,
        dropped_samples = stats.dropped_samples,
        internal_log_rate_limit = false,
    );
}

fn file_size(path: &Path) -> u64 {
    std::fs::metadata(path).map(|meta| meta.len()).unwrap_or(0)
}
