use std::io;

#[cfg(target_os = "linux")]
fn main() -> io::Result<()> {
    match std::env::args().nth(1).as_deref() {
        Some("concurrent") => concurrent_claim_probe(),
        Some("repeat") => repeat_claim_probe(),
        Some("failed-validation-retry") => failed_validation_retry_probe(),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected concurrent, repeat, or failed-validation-retry probe",
        )),
    }
}

#[cfg(target_os = "linux")]
fn concurrent_claim_probe() -> io::Result<()> {
    use std::sync::{Arc, Barrier};

    let barrier = Arc::new(Barrier::new(3));
    let jobs = (0..2)
        .map(|_| {
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                fluxheim_systemd::receive_tcp_listeners(1)
            })
        })
        .collect::<Vec<_>>();
    barrier.wait();

    let mut listener = None;
    let mut rejected = 0;
    for job in jobs {
        match job
            .join()
            .map_err(|_| io::Error::other("probe thread panicked"))?
        {
            Ok(received) => {
                if listener.is_some() || received.len() != 1 {
                    return Err(io::Error::other("multiple activation claims succeeded"));
                }
                listener = received.into_iter().next();
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => rejected += 1,
            Err(error) => return Err(error),
        }
    }
    if rejected != 1 {
        return Err(io::Error::other(
            "exactly one concurrent activation claim must be rejected",
        ));
    }
    listener
        .ok_or_else(|| io::Error::other("activation listener was not returned"))?
        .local_addr()?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn repeat_claim_probe() -> io::Result<()> {
    let listener = fluxheim_systemd::receive_tcp_listeners(1)?
        .into_iter()
        .next()
        .ok_or_else(|| io::Error::other("activation listener was not returned"))?;
    let error = match fluxheim_systemd::receive_tcp_listeners(1) {
        Ok(_) => return Err(io::Error::other("a second activation claim succeeded")),
        Err(error) => error,
    };
    if error.kind() != io::ErrorKind::AlreadyExists {
        return Err(error);
    }
    listener.local_addr()?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn failed_validation_retry_probe() -> io::Result<()> {
    use std::os::fd::AsRawFd as _;

    let error = match fluxheim_systemd::receive_tcp_listeners(2) {
        Ok(_) => {
            return Err(io::Error::other(
                "a non-socket activation descriptor passed validation",
            ));
        }
        Err(error) => error,
    };
    if error.kind() != io::ErrorKind::InvalidInput {
        return Err(error);
    }

    let first = std::net::TcpListener::bind("127.0.0.1:0")?;
    let second = std::net::TcpListener::bind("127.0.0.1:0")?;
    if (first.as_raw_fd(), second.as_raw_fd()) != (3, 4) {
        return Err(io::Error::other(
            "validation failure did not close the complete inherited FD set",
        ));
    }

    let retry = match fluxheim_systemd::receive_tcp_listeners(2) {
        Ok(_) => return Err(io::Error::other("a failed activation was retryable")),
        Err(error) => error,
    };
    if retry.kind() != io::ErrorKind::AlreadyExists {
        return Err(retry);
    }
    first.local_addr()?;
    second.local_addr()?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "systemd activation probes require Linux",
    ))
}
