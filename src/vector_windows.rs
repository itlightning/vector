#![allow(missing_docs)]
use std::{
    ffi::OsString,
    sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock, PoisonError},
    thread::{self, JoinHandle},
    time::Duration,
};

use exitcode::ExitCode;
use tokio::runtime::Runtime;
use windows_service::{
    Result, define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{ServiceControlHandlerResult, ServiceStatusHandle},
    service_dispatcher,
};

use crate::{
    app::{Application, StartedApplication},
    signal::SignalTo,
};

const SERVICE_NAME: &str = "vector";
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

const NO_ERROR: u32 = 0;
const ERROR: u32 = 121;

/// Checkpoint reported with the first STOP_PENDING status; each later report adds one.
const FIRST_STOP_CHECKPOINT: u32 = 1;
/// How often the stop checkpoint is advanced while the topology drains.
const STOP_CHECKPOINT_INTERVAL: Duration = Duration::from_secs(1);
/// Added to the graceful shutdown limit when reporting the stop wait hint, so a drain that
/// legitimately runs to the limit is not read as a hung stop.
const STOP_WAIT_HINT_MARGIN: Duration = Duration::from_secs(5);
/// Stands in for the graceful shutdown limit when the limit is disabled. Matches the default
/// of `--graceful-shutdown-limit-secs`; with no limit the drain is unbounded, and it is the
/// advancing checkpoint rather than the hint that keeps a stop client waiting.
const UNBOUNDED_STOP_WAIT_HINT: Duration = Duration::from_secs(60);

pub mod service_control {
    use std::{ffi::OsString, fmt, fmt::Formatter, time::Duration};

    use snafu::ResultExt;
    use windows_service::{
        Result,
        service::{
            ServiceAccess, ServiceErrorControl, ServiceExitCode, ServiceInfo, ServiceStartType,
            ServiceState, ServiceStatus,
        },
        service_manager::{ServiceManager, ServiceManagerAccess},
    };

    use crate::{
        internal_events::{
            WindowsServiceDoesNotExistError, WindowsServiceInstall, WindowsServiceRestart,
            WindowsServiceStart, WindowsServiceStop, WindowsServiceUninstall,
        },
        vector_windows::{NO_ERROR, SERVICE_TYPE},
    };

    struct ErrorDisplay<'a> {
        error: &'a windows_service::Error,
    }

    impl fmt::Display for ErrorDisplay<'_> {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            if let windows_service::Error::Winapi(win_error) = &self.error {
                write!(f, "{win_error}")
            } else {
                write!(f, "{}", &self.error)
            }
        }
    }

    const fn error_display(error: &windows_service::Error) -> ErrorDisplay<'_> {
        ErrorDisplay { error }
    }

    #[derive(Debug, snafu::Snafu)]
    pub enum Error {
        #[snafu(display("{}", error_display(source)))]
        Service {
            #[snafu(source)]
            source: windows_service::Error,
        },
        #[snafu(display(
            "Timeout occurred after {:?} while waiting for state to become {:?}, but was {:?}",
            timeout,
            expected_state,
            state
        ))]
        PollTimeout {
            state: ServiceState,
            expected_state: ServiceState,
            timeout: Duration,
        },
    }

    #[derive(Debug, Copy, Clone, PartialEq)]
    pub enum ControlAction {
        Install,
        Uninstall { stop_timeout: Duration },
        Start,
        Stop { stop_timeout: Duration },
        Restart { stop_timeout: Duration },
    }

    #[derive(Debug, Clone, PartialEq)]
    enum PollStatus {
        NoTimeout(ServiceStatus),
        Timeout(ServiceStatus),
    }

    impl fmt::Display for ControlAction {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "{:?}", self)
        }
    }

    pub struct ServiceDefinition {
        pub name: OsString,
        pub display_name: OsString,
        pub description: OsString,

        pub executable_path: std::path::PathBuf,
        pub launch_arguments: Vec<OsString>,
    }

    impl std::str::FromStr for ControlAction {
        type Err = String;

        fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
            match s {
                "install" => Ok(ControlAction::Install),
                "uninstall" => Ok(ControlAction::Uninstall {
                    stop_timeout: Duration::from_secs(10),
                }),
                "start" => Ok(ControlAction::Start),
                "stop" => Ok(ControlAction::Stop {
                    stop_timeout: Duration::from_secs(10),
                }),
                _ => Err(format!("invalid option {} for ControlAction", s)),
            }
        }
    }

    pub fn control(service_def: &ServiceDefinition, action: ControlAction) -> crate::Result<()> {
        match action {
            ControlAction::Start => start_service(service_def),
            ControlAction::Stop { stop_timeout } => stop_service(service_def, stop_timeout),
            ControlAction::Restart { stop_timeout } => restart_service(service_def, stop_timeout),
            ControlAction::Install => install_service(service_def),
            ControlAction::Uninstall { stop_timeout } => {
                uninstall_service(service_def, stop_timeout)
            }
        }
    }

    fn start_service(service_def: &ServiceDefinition) -> crate::Result<()> {
        let service_access = ServiceAccess::QUERY_STATUS | ServiceAccess::START;
        let service = open_service(service_def, service_access)?;
        let service_status = service.query_status().context(ServiceSnafu)?;

        if service_status.current_state != ServiceState::StartPending
            && service_status.current_state != ServiceState::Running
        {
            service.start(&[] as &[OsString]).context(ServiceSnafu)?;
            emit!(WindowsServiceStart {
                name: &service_def.name.to_string_lossy(),
                already_started: false,
            });
        } else {
            emit!(WindowsServiceStart {
                name: &service_def.name.to_string_lossy(),
                already_started: true,
            });
        }

        Ok(())
    }

    fn stop_service(service_def: &ServiceDefinition, stop_timeout: Duration) -> crate::Result<()> {
        let service_access = ServiceAccess::QUERY_STATUS | ServiceAccess::STOP;
        let service = open_service(service_def, service_access)?;
        let service_status = service.query_status().context(ServiceSnafu)?;
        let already_stopped = service_status.current_state == ServiceState::Stopped;

        if service_status.current_state != ServiceState::StopPending && !already_stopped {
            service.stop().context(ServiceSnafu)?;
        }

        if !already_stopped {
            let service_status = ensure_state(
                &service,
                ServiceState::Stopped,
                stop_timeout,
                Duration::from_secs(1),
            )?;
            handle_service_exit_code(service_status.exit_code);
        }

        emit!(WindowsServiceStop {
            name: &service_def.name.to_string_lossy(),
            already_stopped,
        });

        Ok(())
    }

    fn restart_service(
        service_def: &ServiceDefinition,
        stop_timeout: Duration,
    ) -> crate::Result<()> {
        let service_access =
            ServiceAccess::QUERY_STATUS | ServiceAccess::START | ServiceAccess::STOP;
        let service = open_service(service_def, service_access)?;
        let service_status = service.query_status().context(ServiceSnafu)?;

        if service_status.current_state == ServiceState::StartPending
            || service_status.current_state == ServiceState::Running
        {
            service.stop()?;
        }

        let service_status = ensure_state(
            &service,
            ServiceState::Stopped,
            stop_timeout,
            Duration::from_secs(1),
        )?;
        handle_service_exit_code(service_status.exit_code);

        service.start(&[] as &[OsString]).context(ServiceSnafu)?;
        emit!(WindowsServiceRestart {
            name: &service_def.name.to_string_lossy()
        });
        Ok(())
    }

    fn install_service(service_def: &ServiceDefinition) -> crate::Result<()> {
        let manager_access = ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE;
        let service_manager =
            ServiceManager::local_computer(None::<&str>, manager_access).context(ServiceSnafu)?;

        let service_info = ServiceInfo {
            name: service_def.name.clone(),
            display_name: service_def.display_name.clone(),
            service_type: SERVICE_TYPE,
            start_type: ServiceStartType::OnDemand,
            error_control: ServiceErrorControl::Normal,
            executable_path: service_def.executable_path.clone(),
            launch_arguments: service_def.launch_arguments.clone(),
            dependencies: vec![],
            account_name: None,
            account_password: None,
        };

        service_manager
            .create_service(&service_info, ServiceAccess::empty())
            .context(ServiceSnafu)?;

        emit!(WindowsServiceInstall {
            name: &service_def.name.to_string_lossy(),
        });

        // TODO: It is currently not possible to change the description of the service.
        // Waiting for the following PR to get merged in
        // https://github.com/mullvad/windows-service-rs/pull/32
        //
        // service.set_description(&self.description);
        Ok(())
    }

    fn uninstall_service(
        service_def: &ServiceDefinition,
        stop_timeout: Duration,
    ) -> crate::Result<()> {
        let service_access =
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE;
        let service = open_service(service_def, service_access)?;

        let service_status = service.query_status().context(ServiceSnafu)?;
        if service_status.current_state != ServiceState::Stopped {
            service.stop().context(ServiceSnafu)?;
            emit!(WindowsServiceStop {
                name: &service_def.name.to_string_lossy(),
                already_stopped: false,
            });
        }

        let service_status = ensure_state(
            &service,
            ServiceState::Stopped,
            stop_timeout,
            Duration::from_secs(1),
        )?;
        handle_service_exit_code(service_status.exit_code);

        service.delete().context(ServiceSnafu)?;

        emit!(WindowsServiceUninstall {
            name: &service_def.name.to_string_lossy(),
        });
        Ok(())
    }

    pub(super) fn open_service(
        service_def: &ServiceDefinition,
        access: windows_service::service::ServiceAccess,
    ) -> crate::Result<windows_service::service::Service> {
        let manager_access = ServiceManagerAccess::CONNECT;
        let service_manager =
            ServiceManager::local_computer(None::<&str>, manager_access).context(ServiceSnafu)?;

        let service = service_manager
            .open_service(&service_def.name, access)
            .inspect_err(|_| {
                emit!(WindowsServiceDoesNotExistError {
                    name: &service_def.name.to_string_lossy(),
                });
            })
            .context(ServiceSnafu)?;
        Ok(service)
    }

    fn handle_service_exit_code(exit_code: windows_service::service::ServiceExitCode) {
        debug!(message="Service stopped.", exit_code = ?exit_code);

        match exit_code {
            ServiceExitCode::Win32(ec) if ec != NO_ERROR => {
                warn!(message = "Service stopped with error.", exit_code = ec);
            }
            ServiceExitCode::ServiceSpecific(ec) => {
                warn!(message = "Service stopped with error.", exit_code = ec);
            }
            _ => {}
        };
    }

    fn poll_state(
        service: &windows_service::service::Service,
        state: ServiceState,
        timeout: Duration,
        wait_hint: Duration,
    ) -> Result<PollStatus> {
        let mut wait_index = 1;
        let mut wait_time = Duration::default();

        let poll_status = loop {
            let service_status = service.query_status()?;
            if service_status.current_state == state {
                break PollStatus::NoTimeout(service_status);
            }
            debug!(
                message = "Waiting for service to transition.", to = ?state, wait_index = %wait_index
            );
            wait_index += 1;

            wait_time += wait_hint;
            if wait_time >= timeout {
                break PollStatus::Timeout(service_status);
            }

            std::thread::sleep(wait_hint);
        };

        Ok(poll_status)
    }

    fn ensure_state(
        service: &windows_service::service::Service,
        state: ServiceState,
        timeout: Duration,
        wait_hint: Duration,
    ) -> crate::Result<ServiceStatus> {
        let poll_status = poll_state(service, state, timeout, wait_hint)?;

        match poll_status {
            PollStatus::Timeout(status) => Err(Error::PollTimeout {
                state: status.current_state,
                expected_state: state,
                timeout,
            }
            .into()),
            PollStatus::NoTimeout(status) => Ok(status),
        }
    }
}

define_windows_service!(ffi_service_main, win_main);

fn win_main(arguments: Vec<OsString>) {
    if let Err(_e) = run_service(arguments) {}
}

pub fn run() -> Result<i32> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main).map(|()| 0_i32)
    // Always returns 0 exit code as errors are handled by the service dispatcher.
}

/// Sink for service status reports.
///
/// The stop sequence is driven through this rather than through the SCM handle directly so it
/// can be exercised without a service control manager.
trait StatusReporter: Send + Sync + 'static {
    fn report(&self, status: ServiceStatus) -> Result<()>;
}

/// Reports through the registered SCM handle.
///
/// The control handler closure has to be built before `register` hands back the handle, so the
/// handle is installed once it exists; reports made before that are dropped.
#[derive(Default)]
struct ScmReporter(OnceLock<ServiceStatusHandle>);

impl ScmReporter {
    fn install(&self, handle: ServiceStatusHandle) {
        _ = self.0.set(handle);
    }
}

impl StatusReporter for ScmReporter {
    fn report(&self, status: ServiceStatus) -> Result<()> {
        match self.0.get() {
            Some(handle) => handle.set_service_status(status),
            None => Ok(()),
        }
    }
}

const fn stop_pending_status(checkpoint: u32, wait_hint: Duration) -> ServiceStatus {
    ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::StopPending,
        // A service that has begun stopping accepts no further controls.
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(NO_ERROR),
        checkpoint,
        wait_hint,
        process_id: None,
    }
}

/// Wait hint to report with each STOP_PENDING status for the given graceful shutdown limit.
fn stop_wait_hint(graceful_shutdown_duration: Option<Duration>) -> Duration {
    graceful_shutdown_duration
        .unwrap_or(UNBOUNDED_STOP_WAIT_HINT)
        .saturating_add(STOP_WAIT_HINT_MARGIN)
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[derive(Default)]
struct StopTicker {
    started: bool,
    handle: Option<JoinHandle<()>>,
}

/// Keeps the service control manager informed while the topology drains.
///
/// A stop control is answered with STOP_PENDING and a wait hint covering the graceful shutdown
/// limit, then the checkpoint advances on a timer until the drain ends. Without those reports
/// the service stays in the running state for the entire drain and a stop client, seeing no
/// state change and no progress, concludes the service never acted on the request.
struct StopProgress {
    reporter: Arc<dyn StatusReporter>,
    wait_hint: Duration,
    checkpoint_interval: Duration,
    ticker: Mutex<StopTicker>,
    /// Set once the drain is over, to end the checkpoint timer.
    drained: Arc<(Mutex<bool>, Condvar)>,
}

impl StopProgress {
    fn new(
        reporter: Arc<dyn StatusReporter>,
        wait_hint: Duration,
        checkpoint_interval: Duration,
    ) -> Self {
        Self {
            reporter,
            wait_hint,
            checkpoint_interval,
            ticker: Mutex::new(StopTicker::default()),
            drained: Arc::new((Mutex::new(false), Condvar::new())),
        }
    }

    /// Report the first STOP_PENDING status and start advancing the checkpoint.
    ///
    /// Repeat stop controls are ignored: the checkpoint has to keep moving forward, so a second
    /// request must not restart it at the beginning.
    fn begin(&self) {
        let mut ticker = lock(&self.ticker);
        if ticker.started {
            return;
        }
        ticker.started = true;

        _ = self
            .reporter
            .report(stop_pending_status(FIRST_STOP_CHECKPOINT, self.wait_hint));

        let reporter = Arc::clone(&self.reporter);
        let drained = Arc::clone(&self.drained);
        let wait_hint = self.wait_hint;
        let interval = self.checkpoint_interval;
        ticker.handle = thread::Builder::new()
            .name("vector-stop-progress".to_string())
            .spawn(move || advance_stop_checkpoints(&*reporter, &drained, wait_hint, interval))
            .ok();
    }

    /// End the checkpoint timer and wait for it to exit.
    ///
    /// Joining is what guarantees no STOP_PENDING report lands after the final STOPPED report.
    /// Does nothing when no stop control was received, which is the case when the process shuts
    /// down for its own reasons.
    fn finish(&self) {
        let Some(handle) = lock(&self.ticker).handle.take() else {
            return;
        };
        let (drained, wake) = &*self.drained;
        *lock(drained) = true;
        wake.notify_all();
        _ = handle.join();
    }
}

fn advance_stop_checkpoints(
    reporter: &dyn StatusReporter,
    drained: &(Mutex<bool>, Condvar),
    wait_hint: Duration,
    interval: Duration,
) {
    let (done, wake) = drained;
    let mut checkpoint = FIRST_STOP_CHECKPOINT;
    let mut guard = lock(done);
    while !*guard {
        let (next, timeout) = wake
            .wait_timeout(guard, interval)
            .unwrap_or_else(PoisonError::into_inner);
        guard = next;
        if *guard {
            break;
        }
        if timeout.timed_out() {
            checkpoint = checkpoint.saturating_add(1);
            _ = reporter.report(stop_pending_status(checkpoint, wait_hint));
        }
    }
}

/// `Application::prepare_start`, additionally reporting the graceful shutdown limit the
/// application was started with, which bounds the drain and so sets the stop wait hint.
fn prepare_start_with_shutdown_limit()
-> std::result::Result<(Runtime, StartedApplication, Option<Duration>), ExitCode> {
    let (runtime, app) = Application::prepare(Default::default())?;
    let graceful_shutdown_duration = app.root_opts.graceful_shutdown_duration();
    let app = app.start(runtime.handle())?;
    Ok((runtime, app, graceful_shutdown_duration))
}

fn run_service(_arguments: Vec<OsString>) -> Result<()> {
    match prepare_start_with_shutdown_limit() {
        Ok((runtime, app, graceful_shutdown_duration)) => {
            let reporter = Arc::new(ScmReporter::default());
            let stop_progress = Arc::new(StopProgress::new(
                Arc::clone(&reporter) as Arc<dyn StatusReporter>,
                stop_wait_hint(graceful_shutdown_duration),
                STOP_CHECKPOINT_INTERVAL,
            ));

            let signal_tx = app.signals.handler.clone_tx();
            let handler_stop_progress = Arc::clone(&stop_progress);
            let event_handler = move |control_event| -> ServiceControlHandlerResult {
                match control_event {
                    // Notifies a service to report its current status information to the service
                    // control manager. Always return NoError even if not implemented.
                    ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,

                    // Handle stop
                    ServiceControl::Stop => {
                        // Report STOP_PENDING before the signal goes out. The drain may take
                        // the whole graceful shutdown limit, and until a pending state with a
                        // wait hint is reported the service still reads as running.
                        handler_stop_progress.begin();
                        while signal_tx.send(SignalTo::Shutdown(None)).is_err() {}
                        ServiceControlHandlerResult::NoError
                    }

                    _ => ServiceControlHandlerResult::NotImplemented,
                }
            };

            let status_handle =
                windows_service::service_control_handler::register(SERVICE_NAME, event_handler)?;
            reporter.install(status_handle);

            status_handle.set_service_status(ServiceStatus {
                service_type: SERVICE_TYPE,
                current_state: ServiceState::Running,
                controls_accepted: ServiceControlAccept::STOP,
                exit_code: ServiceExitCode::Win32(NO_ERROR),
                checkpoint: 0,
                wait_hint: Duration::default(),
                process_id: None,
            })?;

            let program_completion_status = runtime.block_on(app.run());

            // The drain is over: end the checkpoint timer first, so no pending report can land
            // after the stopped one below.
            stop_progress.finish();

            // Tell the system that service has stopped.
            status_handle.set_service_status(ServiceStatus {
                service_type: SERVICE_TYPE,
                current_state: ServiceState::Stopped,
                controls_accepted: ServiceControlAccept::empty(),
                exit_code: {
                    if program_completion_status.success() {
                        ServiceExitCode::Win32(NO_ERROR)
                    } else {
                        // we didn't gracefully shutdown within grace period.
                        ServiceExitCode::Win32(ERROR)
                    }
                },
                checkpoint: 0,
                wait_hint: Duration::default(),
                process_id: None,
            })?;

            Ok(())
        }
        Err(exit_code) => {
            // Startup failed (for example, an invalid configuration). Register a control
            // handler and report SERVICE_STOPPED with a nonzero exit code: if ServiceMain
            // returns without ever reporting a status, the service is left stuck in the
            // START_PENDING state and configured recovery actions never run.
            let event_handler = move |_control_event| ServiceControlHandlerResult::NoError;
            let status_handle =
                windows_service::service_control_handler::register(SERVICE_NAME, event_handler)?;
            status_handle.set_service_status(ServiceStatus {
                service_type: SERVICE_TYPE,
                current_state: ServiceState::Stopped,
                controls_accepted: ServiceControlAccept::empty(),
                exit_code: ServiceExitCode::ServiceSpecific(exit_code.unsigned_abs()),
                checkpoint: 0,
                wait_hint: Duration::default(),
                process_id: None,
            })?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;

    const TEST_INTERVAL: Duration = Duration::from_millis(20);
    const TEST_WAIT_HINT: Duration = Duration::from_secs(13);
    const TEST_DEADLINE: Duration = Duration::from_secs(10);

    #[derive(Default)]
    struct RecordingReporter(Mutex<Vec<ServiceStatus>>);

    impl RecordingReporter {
        fn statuses(&self) -> Vec<ServiceStatus> {
            lock(&self.0).clone()
        }
    }

    impl StatusReporter for RecordingReporter {
        fn report(&self, status: ServiceStatus) -> Result<()> {
            lock(&self.0).push(status);
            Ok(())
        }
    }

    fn progress(reporter: &Arc<RecordingReporter>) -> StopProgress {
        StopProgress::new(
            Arc::clone(reporter) as Arc<dyn StatusReporter>,
            TEST_WAIT_HINT,
            TEST_INTERVAL,
        )
    }

    /// Block until the reporter has seen at least `count` statuses, or the deadline passes.
    fn await_statuses(reporter: &RecordingReporter, count: usize) -> Vec<ServiceStatus> {
        let deadline = Instant::now() + TEST_DEADLINE;
        loop {
            let statuses = reporter.statuses();
            if statuses.len() >= count || Instant::now() >= deadline {
                return statuses;
            }
            thread::sleep(TEST_INTERVAL);
        }
    }

    #[test]
    fn reports_stop_pending_with_an_advancing_checkpoint() {
        let reporter = Arc::new(RecordingReporter::default());
        let progress = progress(&reporter);

        progress.begin();
        let statuses = await_statuses(&reporter, 3);
        progress.finish();

        assert!(statuses.len() >= 3, "no checkpoints advanced: {statuses:?}");
        for (index, status) in statuses.iter().enumerate() {
            assert_eq!(status.current_state, ServiceState::StopPending);
            assert_eq!(status.controls_accepted, ServiceControlAccept::empty());
            assert_eq!(status.wait_hint, TEST_WAIT_HINT);
            assert_eq!(status.checkpoint, FIRST_STOP_CHECKPOINT + index as u32);
        }
    }

    #[test]
    fn stops_reporting_once_the_drain_is_over() {
        let reporter = Arc::new(RecordingReporter::default());
        let progress = progress(&reporter);

        progress.begin();
        await_statuses(&reporter, 2);
        progress.finish();

        // `finish` joins the timer, so the count is final the moment it returns.
        let settled = reporter.statuses().len();
        thread::sleep(TEST_INTERVAL * 5);
        assert_eq!(reporter.statuses().len(), settled);
    }

    #[test]
    fn a_repeat_stop_control_does_not_restart_the_checkpoint() {
        let reporter = Arc::new(RecordingReporter::default());
        let progress = progress(&reporter);

        progress.begin();
        await_statuses(&reporter, 2);
        progress.begin();
        progress.finish();

        let checkpoints: Vec<u32> = reporter.statuses().iter().map(|s| s.checkpoint).collect();
        let restarts = checkpoints
            .iter()
            .filter(|checkpoint| **checkpoint == FIRST_STOP_CHECKPOINT)
            .count();
        assert_eq!(restarts, 1, "checkpoint restarted: {checkpoints:?}");
    }

    #[test]
    fn the_wait_hint_covers_the_graceful_shutdown_limit() {
        assert_eq!(
            stop_wait_hint(Some(Duration::from_secs(8))),
            Duration::from_secs(8) + STOP_WAIT_HINT_MARGIN
        );
        assert_eq!(
            stop_wait_hint(None),
            UNBOUNDED_STOP_WAIT_HINT + STOP_WAIT_HINT_MARGIN
        );
    }
}
