use std::time::Duration;

use socket2::{SockRef, TcpKeepalive};
use tokio::net::{TcpSocket, TcpStream};

use super::NativeTcpKeepalivePolicy;
use crate::NativeHttp1Error;

pub(super) async fn connect_upstream(
    authority: &str,
    recv_buffer_size: Option<u32>,
    dscp: Option<u8>,
    tcp_keepalive: Option<NativeTcpKeepalivePolicy>,
    tcp_user_timeout: Option<Duration>,
) -> Result<TcpStream, NativeHttp1Error> {
    let mut addresses = tokio::net::lookup_host(authority)
        .await
        .map_err(NativeHttp1Error::Io)?;
    let address = addresses.next().ok_or_else(|| {
        NativeHttp1Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "upstream authority did not resolve",
        ))
    })?;
    let socket = if address.is_ipv4() {
        TcpSocket::new_v4()
    } else {
        TcpSocket::new_v6()
    }
    .map_err(NativeHttp1Error::Io)?;
    if let Some(size) = recv_buffer_size {
        socket
            .set_recv_buffer_size(size)
            .map_err(NativeHttp1Error::Io)?;
    }
    if let Some(dscp) = dscp {
        set_socket_dscp(&socket, address, dscp)?;
    }
    if let Some(tcp_keepalive) = tcp_keepalive {
        set_socket_tcp_keepalive(&socket, tcp_keepalive)?;
    }
    if let Some(tcp_user_timeout) = tcp_user_timeout {
        set_socket_tcp_user_timeout(&socket, tcp_user_timeout)?;
    }
    socket.connect(address).await.map_err(NativeHttp1Error::Io)
}

fn set_socket_tcp_keepalive(
    socket: &TcpSocket,
    keepalive: NativeTcpKeepalivePolicy,
) -> Result<(), NativeHttp1Error> {
    let keepalive = TcpKeepalive::new()
        .with_time(keepalive.idle())
        .with_interval(keepalive.interval())
        .with_retries(keepalive.count());
    SockRef::from(socket)
        .set_tcp_keepalive(&keepalive)
        .map_err(NativeHttp1Error::Io)
}

#[cfg(any(
    target_os = "android",
    target_os = "fuchsia",
    target_os = "linux",
    target_os = "cygwin",
))]
fn set_socket_tcp_user_timeout(
    socket: &TcpSocket,
    timeout: Duration,
) -> Result<(), NativeHttp1Error> {
    SockRef::from(socket)
        .set_tcp_user_timeout(Some(timeout))
        .map_err(NativeHttp1Error::Io)
}

#[cfg(not(any(
    target_os = "android",
    target_os = "fuchsia",
    target_os = "linux",
    target_os = "cygwin",
)))]
fn set_socket_tcp_user_timeout(
    _socket: &TcpSocket,
    _timeout: Duration,
) -> Result<(), NativeHttp1Error> {
    Err(NativeHttp1Error::Io(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "native HTTP/1 upstream TCP user timeout is not supported on this target",
    )))
}

fn set_socket_dscp(
    socket: &TcpSocket,
    address: std::net::SocketAddr,
    dscp: u8,
) -> Result<(), NativeHttp1Error> {
    let traffic_class = u32::from(dscp) << 2;
    if address.is_ipv4() {
        return set_socket_dscp_v4(socket, traffic_class);
    }
    set_socket_dscp_v6(socket, traffic_class)
}

#[cfg(not(any(
    target_os = "fuchsia",
    target_os = "redox",
    target_os = "solaris",
    target_os = "illumos",
    target_os = "haiku",
    target_os = "wasi",
)))]
fn set_socket_dscp_v4(socket: &TcpSocket, traffic_class: u32) -> Result<(), NativeHttp1Error> {
    socket
        .set_tos_v4(traffic_class)
        .map_err(NativeHttp1Error::Io)
}

#[cfg(any(
    target_os = "fuchsia",
    target_os = "redox",
    target_os = "solaris",
    target_os = "illumos",
    target_os = "haiku",
    target_os = "wasi",
))]
fn set_socket_dscp_v4(_socket: &TcpSocket, _traffic_class: u32) -> Result<(), NativeHttp1Error> {
    unsupported_dscp_error()
}

#[cfg(any(
    target_os = "android",
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "fuchsia",
    target_os = "linux",
    target_os = "macos",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "cygwin",
))]
fn set_socket_dscp_v6(socket: &TcpSocket, traffic_class: u32) -> Result<(), NativeHttp1Error> {
    socket
        .set_tclass_v6(traffic_class)
        .map_err(NativeHttp1Error::Io)
}

#[cfg(not(any(
    target_os = "android",
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "fuchsia",
    target_os = "linux",
    target_os = "macos",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "cygwin",
)))]
fn set_socket_dscp_v6(_socket: &TcpSocket, _traffic_class: u32) -> Result<(), NativeHttp1Error> {
    unsupported_dscp_error()
}

#[cfg(any(
    target_os = "fuchsia",
    target_os = "redox",
    target_os = "solaris",
    target_os = "illumos",
    target_os = "haiku",
    target_os = "wasi",
    not(any(
        target_os = "android",
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "fuchsia",
        target_os = "linux",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "cygwin",
    )),
))]
fn unsupported_dscp_error() -> Result<(), NativeHttp1Error> {
    Err(NativeHttp1Error::Io(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "native HTTP/1 upstream DSCP is not supported on this target",
    )))
}
