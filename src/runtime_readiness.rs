use std::io;

#[cfg(unix)]
pub(super) fn notify_ready() -> io::Result<()> {
    notify(&[
        libsystemd::daemon::NotifyState::Ready,
        libsystemd::daemon::NotifyState::Status("Fluxheim native runtime ready".to_owned()),
    ])
}

#[cfg(not(unix))]
pub(super) fn notify_ready() -> io::Result<()> {
    Ok(())
}

pub(super) fn notify_stopping() {
    if let Err(error) = notify_stopping_inner() {
        log::warn!(
            target: "fluxheim::native_runtime",
            "failed to notify service manager that Fluxheim is stopping: {error}"
        );
    }
}

#[cfg(unix)]
fn notify_stopping_inner() -> io::Result<()> {
    notify(&[
        libsystemd::daemon::NotifyState::Stopping,
        libsystemd::daemon::NotifyState::Status("Fluxheim native runtime draining".to_owned()),
    ])
}

#[cfg(not(unix))]
fn notify_stopping_inner() -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn notify(states: &[libsystemd::daemon::NotifyState]) -> io::Result<()> {
    let configured = std::env::var_os("NOTIFY_SOCKET");
    if let Some(value) = configured.as_ref()
        && value.to_str().is_none()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "NOTIFY_SOCKET is not valid Unicode",
        ));
    }
    let sent = libsystemd::daemon::notify(false, states)
        .map_err(|error| io::Error::other(error.to_string()))?;
    if configured.is_some() && !sent {
        return Err(io::Error::other(
            "NOTIFY_SOCKET was configured but no readiness datagram was sent",
        ));
    }
    Ok(())
}
