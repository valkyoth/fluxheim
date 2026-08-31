#[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl"))]
use std::io;

#[cfg(all(
    any(feature = "tls-rustls-backend", feature = "tls-openssl"),
    target_os = "linux"
))]
const UPSTREAM_TLS_O_NOFOLLOW: i32 = 0o400000;

#[cfg(all(
    any(feature = "tls-rustls-backend", feature = "tls-openssl"),
    any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    )
))]
const UPSTREAM_TLS_O_NOFOLLOW: i32 = 0x0100;

#[cfg(all(
    unix,
    any(feature = "tls-rustls-backend", feature = "tls-openssl"),
    not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))
))]
compile_error!(
    "O_NOFOLLOW is unknown on this Unix platform; audit upstream TLS file opening before building Fluxheim"
);

#[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl"))]
const MAX_UPSTREAM_TLS_FILE_BYTES: u64 = 1024 * 1024;

#[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl"))]
pub(crate) fn read_upstream_tls_file(path: &std::path::Path) -> io::Result<Vec<u8>> {
    read_upstream_tls_input(path, false)
}

#[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl"))]
pub(crate) fn read_upstream_tls_secret_file(path: &std::path::Path) -> io::Result<Vec<u8>> {
    read_upstream_tls_input(path, true)
}

#[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl"))]
fn read_upstream_tls_input(path: &std::path::Path, confidential: bool) -> io::Result<Vec<u8>> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "upstream TLS path is not a regular file: {}",
                path.display()
            ),
        ));
    }

    #[cfg(windows)]
    let file = if confidential {
        fluxheim_config::fs_trust::open_confidential_file(path)?
    } else {
        fluxheim_config::fs_trust::open_regular_file(path)?
    };
    #[cfg(not(windows))]
    let file = {
        let _ = confidential;
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(UPSTREAM_TLS_O_NOFOLLOW);
        }
        options.open(path)?
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "upstream TLS path is not a regular file: {}",
                path.display()
            ),
        ));
    }
    if metadata.len() > MAX_UPSTREAM_TLS_FILE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "upstream TLS file {} exceeds {} bytes",
                path.display(),
                MAX_UPSTREAM_TLS_FILE_BYTES
            ),
        ));
    }

    let mut contents = Vec::new();
    let mut limited = std::io::Read::take(file, MAX_UPSTREAM_TLS_FILE_BYTES.saturating_add(1));
    std::io::Read::read_to_end(&mut limited, &mut contents)?;
    if contents.len() as u64 > MAX_UPSTREAM_TLS_FILE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "upstream TLS file {} exceeds {} bytes",
                path.display(),
                MAX_UPSTREAM_TLS_FILE_BYTES
            ),
        ));
    }
    Ok(contents)
}
