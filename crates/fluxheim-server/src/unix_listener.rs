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

struct UmaskGuard(rustix::fs::Mode);

impl Drop for UmaskGuard {
    fn drop(&mut self) {
        rustix::process::umask(self.0);
    }
}

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
    let metadata = match rustix::fs::lstat(path) {
        Ok(metadata) => metadata,
        Err(error) => {
            let _ = rustix::fs::unlink(path);
            return Err(error.into());
        }
    };
    if metadata.st_mode & 0o777 != PRIVATE_UNIX_LISTENER_MODE.bits() {
        let _ = rustix::fs::unlink(path);
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private Unix listener was not created with mode 0600",
        ));
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
    // bind time. This lock only serializes Fluxheim callers of this helper;
    // the listener is created during startup before worker services run.
    let _umask = UmaskGuard(rustix::process::umask(PRIVATE_UNIX_LISTENER_UMASK));
    rustix::net::bind(socket, address).map_err(io::Error::from)
}
