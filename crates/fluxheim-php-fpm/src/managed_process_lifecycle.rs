use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::managed_config::managed_php_fpm_restart_backoff_secs;
use crate::managed_process::ManagedPhpFpmSpawnPlan;
use crate::managed_spawn::{
    ensure_managed_php_fpm_binary_spawn_safe, managed_php_fpm_path_env,
    wait_for_managed_php_fpm_socket,
};

const MANAGED_PHP_FPM_STABLE_RESTART_SECS: u64 = 30;

pub(super) fn spawn_managed_php_fpm_cleanup(
    child: std::process::Child,
    socket: PathBuf,
    config_path: PathBuf,
    pid_path: PathBuf,
) {
    let child = Arc::new(Mutex::new(Some(child)));
    let cleanup_child = Arc::clone(&child);
    let cleanup_socket = socket.clone();
    let cleanup_config_path = config_path.clone();
    let cleanup_pid_path = pid_path.clone();

    match std::thread::Builder::new()
        .name("fluxheim-php-fpm-stop".to_owned())
        .spawn(move || {
            let child = match cleanup_child.lock() {
                Ok(mut guard) => guard.take(),
                Err(poisoned) => poisoned.into_inner().take(),
            };
            if let Some(mut child) = child {
                terminate_managed_php_fpm_child(&mut child);
            }
            cleanup_managed_php_fpm_files(&cleanup_socket, &cleanup_config_path, &cleanup_pid_path);
        }) {
        Ok(_) => {}
        Err(error) => {
            log::warn!(
                target: "fluxheim::php_fpm",
                "failed to spawn managed php-fpm cleanup thread; sending managed php-fpm kill inline without blocking wait: {error}"
            );
            let child = match child.lock() {
                Ok(mut guard) => guard.take(),
                Err(poisoned) => poisoned.into_inner().take(),
            };
            if let Some(mut child) = child {
                // Drop can run on a Tokio worker after the last request releases an
                // old runtime snapshot. If cleanup-thread creation fails, do not
                // block that worker on Child::wait().
                let _ = child.kill();
            }
            cleanup_managed_php_fpm_files(&socket, &config_path, &pid_path);
        }
    }
}

pub(super) fn cleanup_managed_php_fpm_files(socket: &Path, config_path: &Path, pid_path: &Path) {
    let _ = std::fs::remove_file(socket);
    let _ = std::fs::remove_file(config_path);
    let _ = std::fs::remove_file(pid_path);
}

pub(super) fn terminate_managed_php_fpm_child(child: &mut std::process::Child) {
    match child.try_wait() {
        Ok(Some(_)) => return,
        Ok(None) => {}
        Err(_) => {
            let _ = child.kill();
            let _ = child.wait();
            return;
        }
    }

    let _ = rustix::process::kill_process(
        rustix::process::Pid::from_child(child),
        rustix::process::Signal::TERM,
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(100));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return;
            }
        }
    }
}

pub(super) fn spawn_managed_php_fpm_child(
    plan: &ManagedPhpFpmSpawnPlan,
    shutdown: Option<&AtomicBool>,
) -> io::Result<(std::process::Child, Instant)> {
    ensure_managed_php_fpm_binary_spawn_safe(&plan.scope, &plan.binary)?;
    let _ = std::fs::remove_file(&plan.socket);
    let _ = std::fs::remove_file(&plan.pid_path);

    let mut child = std::process::Command::new(&plan.binary)
        .arg("-F")
        .arg("-y")
        .arg(&plan.config_path)
        .env_clear()
        .env("PATH", managed_php_fpm_path_env())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "{}: failed to start managed php-fpm binary {}: {error}",
                    plan.scope,
                    plan.binary.display()
                ),
            )
        })?;

    match wait_for_managed_php_fpm_socket(
        &mut child,
        &plan.socket,
        plan.connect_timeout_secs,
        shutdown,
    ) {
        Ok(()) => Ok((child, Instant::now())),
        Err(error) => {
            terminate_managed_php_fpm_child(&mut child);
            let _ = std::fs::remove_file(&plan.socket);
            let _ = std::fs::remove_file(&plan.pid_path);
            Err(io::Error::new(
                error.kind(),
                format!(
                    "{}: managed php-fpm failed to become ready: {error}",
                    plan.scope
                ),
            ))
        }
    }
}

pub(super) fn spawn_managed_php_fpm_watchdog(
    child: Arc<Mutex<Option<std::process::Child>>>,
    shutdown: Arc<AtomicBool>,
    plan: Arc<ManagedPhpFpmSpawnPlan>,
    started_at: Instant,
) -> io::Result<()> {
    std::thread::Builder::new()
        .name("fluxheim-php-fpm-watchdog".to_owned())
        .spawn(move || run_managed_php_fpm_watchdog(child, shutdown, plan, started_at))
        .map(|_| ())
        .map_err(|error| {
            io::Error::other(format!("failed to start managed php-fpm watchdog: {error}"))
        })
}

fn run_managed_php_fpm_watchdog(
    child: Arc<Mutex<Option<std::process::Child>>>,
    shutdown: Arc<AtomicBool>,
    plan: Arc<ManagedPhpFpmSpawnPlan>,
    started_at: Instant,
) {
    let mut restart_failures = 0_usize;
    let mut last_started = started_at;
    loop {
        if managed_php_fpm_shutdown_requested(&shutdown) {
            return;
        }
        std::thread::sleep(Duration::from_secs(1));
        if managed_php_fpm_shutdown_requested(&shutdown) {
            return;
        }

        let exited = {
            let mut guard = match child.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            match guard.as_mut().map(std::process::Child::try_wait) {
                Some(Ok(Some(status))) => {
                    *guard = None;
                    Some(format!("exited with status {status}"))
                }
                Some(Ok(None)) => None,
                Some(Err(error)) => {
                    *guard = None;
                    Some(format!("status check failed: {error}"))
                }
                None => Some("missing child process handle".to_owned()),
            }
        };

        let Some(reason) = exited else {
            if last_started.elapsed() >= Duration::from_secs(MANAGED_PHP_FPM_STABLE_RESTART_SECS) {
                restart_failures = 0;
            }
            continue;
        };

        if managed_php_fpm_shutdown_requested(&shutdown) {
            return;
        }

        log::warn!(
            target: "fluxheim::php_fpm",
            "{}: managed php-fpm stopped ({reason}); attempting restart",
            plan.scope
        );

        if last_started.elapsed() < Duration::from_secs(MANAGED_PHP_FPM_STABLE_RESTART_SECS) {
            restart_failures = restart_failures.saturating_add(1);
        } else {
            restart_failures = 0;
        }

        if !managed_php_fpm_sleep_until_restart(&shutdown, restart_failures) {
            return;
        }

        match spawn_managed_php_fpm_child(&plan, Some(shutdown.as_ref())) {
            Ok((new_child, started_at)) => {
                let mut guard = match child.lock() {
                    Ok(guard) => guard,
                    Err(poisoned) => poisoned.into_inner(),
                };
                if managed_php_fpm_shutdown_requested(&shutdown) {
                    drop(guard);
                    let mut new_child = new_child;
                    terminate_managed_php_fpm_child(&mut new_child);
                    return;
                }
                *guard = Some(new_child);
                last_started = started_at;
                log::info!(
                    target: "fluxheim::php_fpm",
                    "{}: managed php-fpm restarted",
                    plan.scope
                );
            }
            Err(error) => {
                restart_failures = restart_failures.saturating_add(1);
                log::error!(
                    target: "fluxheim::php_fpm",
                    "{}: managed php-fpm restart failed: {error}",
                    plan.scope
                );
            }
        }
    }
}

fn managed_php_fpm_shutdown_requested(shutdown: &AtomicBool) -> bool {
    shutdown.load(Ordering::Acquire)
}

fn managed_php_fpm_sleep_until_restart(shutdown: &AtomicBool, restart_failures: usize) -> bool {
    let delay = Duration::from_secs(managed_php_fpm_restart_backoff_secs(restart_failures));
    let deadline = Instant::now() + delay;
    loop {
        if managed_php_fpm_shutdown_requested(shutdown) {
            return false;
        }
        let now = Instant::now();
        if now >= deadline {
            return true;
        }
        std::thread::sleep((deadline - now).min(Duration::from_millis(100)));
    }
}
