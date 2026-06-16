use std::io;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::Path;

const PRIVATE_UNIX_LISTENER_BACKLOG: i32 = 128;
const PRIVATE_UNIX_LISTENER_MODE: u32 = 0o600;

pub fn replace_private_unix_listener(path: &Path) -> io::Result<UnixListener> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => {
            std::fs::remove_file(path)?;
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
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
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
    rustix::net::bind(&socket, &address)?;
    if let Err(error) = std::fs::set_permissions(
        path,
        std::fs::Permissions::from_mode(PRIVATE_UNIX_LISTENER_MODE),
    ) {
        let _ = std::fs::remove_file(path);
        return Err(error);
    }
    if let Err(error) = rustix::net::listen(&socket, PRIVATE_UNIX_LISTENER_BACKLOG) {
        let _ = std::fs::remove_file(path);
        return Err(error.into());
    }
    Ok(UnixListener::from(socket))
}
