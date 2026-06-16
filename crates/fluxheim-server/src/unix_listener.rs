use std::io;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::Mutex;

const PRIVATE_UNIX_LISTENER_BACKLOG: i32 = 128;
const PRIVATE_UNIX_LISTENER_MODE: rustix::fs::Mode =
    rustix::fs::Mode::RUSR.union(rustix::fs::Mode::WUSR);
const PRIVATE_UNIX_LISTENER_UMASK: rustix::fs::Mode =
    rustix::fs::Mode::XUSR.union(rustix::fs::Mode::RWXG.union(rustix::fs::Mode::RWXO));

static UMASK_LOCK: Mutex<()> = Mutex::new(());

pub fn replace_private_unix_listener(path: &Path) -> io::Result<UnixListener> {
    match rustix::fs::lstat(path) {
        Ok(metadata) if rustix::fs::FileType::from_raw_mode(metadata.st_mode).is_socket() => {
            rustix::fs::unlink(path).map_err(io::Error::from)?;
        }
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "private Unix listener path {} already exists and is not a socket",
                    path.display()
                ),
            ));
        }
        Err(error) if error == rustix::io::Errno::NOENT => {}
        Err(error) => return Err(error.into()),
    }

    let listener = bind_private_unix_listener(path)?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

fn bind_private_unix_listener(path: &Path) -> io::Result<UnixListener> {
    let address = rustix::net::SocketAddrUnix::new(path)?;
    let socket = rustix::net::socket(
        rustix::net::AddressFamily::UNIX,
        rustix::net::SocketType::STREAM,
        None,
    )?;
    bind_private_socket_path(&socket, &address)?;
    if let Err(error) = rustix::fs::fchmod(&socket, PRIVATE_UNIX_LISTENER_MODE) {
        let _ = rustix::fs::unlink(path);
        return Err(error.into());
    }
    if let Err(error) = rustix::net::listen(&socket, PRIVATE_UNIX_LISTENER_BACKLOG) {
        let _ = rustix::fs::unlink(path);
        return Err(error.into());
    }
    Ok(UnixListener::from(socket))
}

fn bind_private_socket_path(
    socket: &rustix::fd::OwnedFd,
    address: &rustix::net::SocketAddrUnix,
) -> io::Result<()> {
    let _guard = UMASK_LOCK
        .lock()
        .map_err(|_| io::Error::other("private Unix listener umask lock poisoned"))?;
    // Unix socket pathname permissions are derived from the process umask at
    // bind time. Hold the global umask lock so the socket is private before
    // any path-visible chmod/fchmod step can run.
    let previous_umask = rustix::process::umask(PRIVATE_UNIX_LISTENER_UMASK);
    let bind_result = rustix::net::bind(socket, address);
    rustix::process::umask(previous_umask);
    bind_result.map_err(io::Error::from)
}
