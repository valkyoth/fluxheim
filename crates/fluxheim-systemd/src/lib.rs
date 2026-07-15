#![deny(unsafe_op_in_unsafe_fn)]
#![cfg_attr(not(target_os = "linux"), forbid(unsafe_code))]

use std::io;
use std::net::TcpListener;

#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(target_os = "linux")]
static ACTIVATION_CONSUMED: AtomicBool = AtomicBool::new(false);

#[cfg(target_os = "linux")]
const MAX_ACTIVATION_LISTENERS: usize = 128;

#[cfg(target_os = "linux")]
pub fn receive_tcp_listeners(expected: usize) -> io::Result<Vec<TcpListener>> {
    use std::os::fd::{FromRawFd as _, IntoRawFd as _, OwnedFd};

    use libsystemd::activation::{IsType as _, receive_descriptors};

    ACTIVATION_CONSUMED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::AlreadyExists,
                "systemd activation descriptors were already consumed",
            )
        })?;

    validate_declared_count(expected, activation_listener_declaration()?.as_deref())?;

    // `false` is security-critical: environment mutation is unsound once other
    // process threads can concurrently read libc's environment storage.
    let descriptors =
        receive_descriptors(false).map_err(|error| io::Error::other(error.to_string()))?;
    // Establish ownership of the complete set before fallible validation. This
    // makes every error close all declared descriptors and prevents a retry
    // from adopting a partially consumed or subsequently reused FD number.
    let owned = descriptors
        .into_iter()
        .map(|descriptor| {
            let is_inet = descriptor.is_inet();
            let raw = descriptor.into_raw_fd();
            // SAFETY: the process-wide claim above permits exactly one transfer
            // of the inherited FD3+ set. Every descriptor is consumed here and
            // placed under `OwnedFd` before any fallible validation occurs.
            let owned = unsafe { OwnedFd::from_raw_fd(raw) };
            (is_inet, owned)
        })
        .collect::<Vec<_>>();
    if owned.len() != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "expected {expected} inherited listener(s), received {}",
                owned.len()
            ),
        ));
    }

    owned
        .into_iter()
        .enumerate()
        .map(|(index, (is_inet, owned))| {
            if !is_inet {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("descriptor index {index} is not a socket in the internet family"),
                ));
            }
            validated_tcp_listener(index, owned)
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn validated_tcp_listener(index: usize, owned: std::os::fd::OwnedFd) -> io::Result<TcpListener> {
    validate_tcp_listener_properties(
        index,
        rustix::net::sockopt::socket_type(&owned)?,
        rustix::net::sockopt::socket_protocol(&owned)?,
        rustix::net::sockopt::socket_acceptconn(&owned)?,
    )?;
    Ok(TcpListener::from(owned))
}

#[cfg(target_os = "linux")]
fn validate_tcp_listener_properties(
    index: usize,
    socket_type: rustix::net::SocketType,
    protocol: Option<rustix::net::Protocol>,
    listening: bool,
) -> io::Result<()> {
    if socket_type != rustix::net::SocketType::STREAM {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("descriptor index {index} is not a stream socket"),
        ));
    }
    if protocol != Some(rustix::net::ipproto::TCP) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("descriptor index {index} does not use TCP"),
        ));
    }
    if !listening {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("descriptor index {index} is not in listening state"),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn activation_listener_declaration() -> io::Result<Option<String>> {
    std::env::var_os("LISTEN_FDS")
        .map(|value| {
            value.into_string().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "LISTEN_FDS is not valid Unicode",
                )
            })
        })
        .transpose()
}

#[cfg(target_os = "linux")]
fn validate_declared_count(expected: usize, declared: Option<&str>) -> io::Result<()> {
    if !(1..=MAX_ACTIVATION_LISTENERS).contains(&expected) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected listener count must be between 1 and 128",
        ));
    }
    let declared = declared
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "LISTEN_FDS is missing"))?
        .parse::<usize>()
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "LISTEN_FDS is not a valid integer",
            )
        })?;
    if declared != expected || declared > MAX_ACTIVATION_LISTENERS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "expected {expected} inherited listener(s), but LISTEN_FDS declares {declared}"
            ),
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn receive_tcp_listeners(_expected: usize) -> io::Result<Vec<TcpListener>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "systemd socket activation is only supported on Linux",
    ))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::os::fd::OwnedFd;

    use super::*;

    #[test]
    fn accepts_owned_listening_tcp_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let expected = listener.local_addr().unwrap();
        let listener = validated_tcp_listener(0, OwnedFd::from(listener)).unwrap();

        assert_eq!(listener.local_addr().unwrap(), expected);
    }

    #[test]
    fn rejects_non_tcp_stream_protocol() {
        let error = validate_tcp_listener_properties(
            2,
            rustix::net::SocketType::STREAM,
            Some(rustix::net::ipproto::UDP),
            true,
        )
        .unwrap_err();

        assert!(error.to_string().contains("index 2 does not use TCP"));
    }

    #[test]
    fn bounds_declared_listener_count_before_descriptor_receipt() {
        assert!(validate_declared_count(1, Some("1")).is_ok());
        assert!(validate_declared_count(0, Some("0")).is_err());
        assert!(validate_declared_count(129, Some("129")).is_err());
        assert!(validate_declared_count(1, None).is_err());
        assert!(validate_declared_count(1, Some("invalid")).is_err());
        assert!(validate_declared_count(1, Some("2")).is_err());
        assert!(
            validate_declared_count(1, Some("184467440737095516160000000000000000000")).is_err()
        );
    }

    #[test]
    fn rejects_owned_connected_tcp_stream() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (_server, _) = listener.accept().unwrap();
        let error = validated_tcp_listener(3, OwnedFd::from(client)).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("index 3 is not in listening state")
        );
    }
}
