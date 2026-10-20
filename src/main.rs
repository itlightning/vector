#![deny(warnings)]

extern crate vector;
use std::process::ExitCode;

use vector::{app::Application, extra_context::ExtraContext};

#[cfg(unix)]
fn main() -> ExitCode {
    // At this point, we make the following assumption:
    // The heap does not contain any allocations that have a shorter lifetime than the program.
    // Both entry points arm tracking here, before anything long-lived is allocated.
    #[cfg(feature = "allocation-tracing")]
    vector::internal_telemetry::allocations::init_tracing_from_cli();

    #[cfg(feature = "mimalloc-pprof")]
    vector::heap_profile::start();

    let exit_code = Application::run(ExtraContext::default())
        .code()
        .unwrap_or(exitcode::UNAVAILABLE) as u8;
    ExitCode::from(exit_code)
}

#[cfg(windows)]
pub fn main() -> ExitCode {
    // Same startup ordering constraint as the unix entry point: arm tracking before the
    // service or console path allocates anything long-lived.
    #[cfg(feature = "allocation-tracing")]
    vector::internal_telemetry::allocations::init_tracing_from_cli();

    // Before either the service or the console path allocates, so the unsampled window is
    // as small as it can be.
    #[cfg(feature = "mimalloc-pprof")]
    vector::heap_profile::start();

    // We need to be able to run vector in User Interactive mode. We first try
    // to run vector as a service. If we fail, we consider that we are in
    // interactive mode and then fallback to console mode.  See
    // https://docs.microsoft.com/en-us/dotnet/api/system.environment.userinteractive?redirectedfrom=MSDN&view=netcore-3.1#System_Environment_UserInteractive
    let exit_code = vector::vector_windows::run().unwrap_or_else(|_| {
        Application::run(ExtraContext::default())
            .code()
            .unwrap_or(exitcode::UNAVAILABLE)
    });
    ExitCode::from(exit_code as u8)
}
