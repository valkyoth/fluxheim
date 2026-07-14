#![deny(unsafe_op_in_unsafe_fn)]
#![cfg_attr(not(target_os = "linux"), forbid(unsafe_code))]

use std::io;
use std::net::TcpListener;

#[cfg(target_os = "linux")]
pub fn receive_tcp_listeners(expected: usize) -> io::Result<Vec<TcpListener>> {
    use std::os::fd::{FromRawFd as _, IntoRawFd as _, OwnedFd};

    use libsystemd::activation::{IsType as _, receive_descriptors};

    // `false` is security-critical: environment mutation is unsound once other
    // process threads can concurrently read libc's environment storage.
    let descriptors =
        receive_descriptors(false).map_err(|error| io::Error::other(error.to_string()))?;
    if descriptors.len() != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "expected {expected} inherited listener(s), received {}",
                descriptors.len()
            ),
        ));
    }

    descriptors
        .into_iter()
        .enumerate()
        .map(|(index, descriptor)| {
            if !descriptor.is_inet() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("descriptor index {index} is not a socket in the internet family"),
                ));
            }
            let raw = descriptor.into_raw_fd();
            // SAFETY: `receive_descriptors(false)` validated this systemd-owned
            // descriptor and returns each FD3+ slot exactly once. This function
            // consumes every descriptor and transfers that unique ownership to
            // `OwnedFd` without cloning or closing it elsewhere.
            let owned = unsafe { OwnedFd::from_raw_fd(raw) };
            validated_tcp_listener(index, owned)
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn validated_tcp_listener(index: usize, owned: std::os::fd::OwnedFd) -> io::Result<TcpListener> {
    if rustix::net::sockopt::socket_type(&owned)? != rustix::net::SocketType::STREAM {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("descriptor index {index} is not a TCP stream socket"),
        ));
    }
    if !rustix::net::sockopt::socket_acceptconn(&owned)? {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("descriptor index {index} is not in listening state"),
        ));
    }
    Ok(TcpListener::from(owned))
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
