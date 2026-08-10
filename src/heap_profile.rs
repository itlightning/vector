//! Opt-in sampled heap profiling, built only into profiling flavors.
//!
//! One switch controls everything: `SPARKLOGS_HEAP_PROFILE_DIR`. When it names a
//! directory the profiler runs and one pprof dump per process run is written into that
//! directory; when it is unset or empty the profiler never starts and nothing is logged.
//! No `MIMALLOC_*` variable is read or written, because mimalloc's own `MIMALLOC_PROF`
//! auto-start arms the profiler at the first allocation and then rejects the explicit
//! start below, discarding the configuration with it.
//!
//! The dump is taken explicitly on the shutdown path rather than through mimalloc's
//! `dump_at_exit` hook: that hook rides on CRT `atexit`, which Windows skips whenever the
//! process leaves through `ExitProcess`, so console Ctrl+C runs produced no file at all.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use mimalloc_pprof::{ProfConfig, ProfConfigMode, prof};

/// Names the directory that heap profiles are written to, and switches profiling on.
const PROFILE_DIR_ENV: &str = "SPARKLOGS_HEAP_PROFILE_DIR";

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

        // A missing directory would otherwise swallow the dump at shutdown.
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

/// Report what [`start`] did. Call once logging is initialized.
pub fn log_started() {
    match STATUS.get() {
        Some(Status::On(dir)) => {
            info!(
                message = "Heap profiling enabled; a profile will be written at shutdown.",
                directory = %dir.display(),
            );
        }
        Some(Status::Failed(error)) => {
            warn!(message = "Heap profiling requested but not started.", %error);
        }
        Some(Status::Off) | None => {}
    }
}

/// Write one pprof heap profile, if profiling is running.
///
/// Call this on the shutdown path, where it runs for a normal shutdown, a service stop
/// and a console interrupt alike.
pub fn dump() {
    let Some(Status::On(dir)) = STATUS.get() else {
        return;
    };

    // The name is chosen here, not at startup, so repeated runs accumulate rather than
    // overwrite each other.
    let path = dir.join(format!(
        "vector-heap-{}.pb",
        chrono::Utc::now().format("%Y%m%dT%H%M%S%3fZ")
    ));

    match prof::dump_proto_file(&path) {
        Ok(()) => info!(
            message = "Wrote heap profile.",
            path = %path.display(),
            bytes = file_size(&path),
        ),
        Err(error) => warn!(
            message = "Failed to write heap profile.",
            path = %path.display(),
            %error,
        ),
    }
}

fn file_size(path: &Path) -> u64 {
    std::fs::metadata(path).map(|meta| meta.len()).unwrap_or(0)
}
