use std::fs::OpenOptions;
use std::io::{self, Read, Seek};

use fluxheim_common::{FluxError, FluxResult};
use fluxheim_web::SafeRelativePath;

use super::{StaticFile, StaticResponseBody};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

#[cfg(any(target_os = "linux", target_os = "android"))]
const O_NOFOLLOW: i32 = 0o400000;

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
const O_NOFOLLOW: i32 = 0x0100;

#[cfg(all(
    unix,
    not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))
))]
compile_error!(
    "O_NOFOLLOW is unknown on this Unix platform; audit symlink-safe file opening before building Fluxheim"
);

pub const MAX_STATIC_BUFFERED_BODY_BYTES: u64 = 64 * 1024 * 1024;

pub(crate) fn read_static_response_body(
    file: &StaticFile,
    body: StaticResponseBody,
) -> FluxResult<bytes::Bytes> {
    match body {
        StaticResponseBody::None => Ok(bytes::Bytes::new()),
        StaticResponseBody::Full => {
            if file.len > MAX_STATIC_BUFFERED_BODY_BYTES {
                return Err(FluxError::io(
                    "static file exceeds buffered response limit",
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "static file exceeds buffered response limit",
                    ),
                ));
            }
            let mut reader = open_static_body_file(file)?;
            let capacity = usize::try_from(file.len).map_err(|_| {
                FluxError::io(
                    "static file too large",
                    io::Error::new(io::ErrorKind::InvalidInput, "static file too large"),
                )
            })?;
            let mut body = Vec::with_capacity(capacity);
            let mut bounded_reader = reader.by_ref().take(file.len.saturating_add(1));
            bounded_reader
                .read_to_end(&mut body)
                .map_err(|error| FluxError::io("read static file body", error))?;
            if body.len() as u64 != file.len {
                return Err(FluxError::io(
                    "static file changed during body read",
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "static file changed during body read",
                    ),
                ));
            }
            Ok(bytes::Bytes::from(body))
        }
        StaticResponseBody::Range { start, len } => {
            if len > MAX_STATIC_BUFFERED_BODY_BYTES {
                return Err(FluxError::io(
                    "static range exceeds buffered response limit",
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "static range exceeds buffered response limit",
                    ),
                ));
            }
            let len = usize::try_from(len).map_err(|_| {
                FluxError::io(
                    "static range too large",
                    io::Error::new(io::ErrorKind::InvalidInput, "static range too large"),
                )
            })?;
            let mut reader = open_static_body_file(file)?;
            reader
                .seek(io::SeekFrom::Start(start))
                .map_err(|error| FluxError::io("seek static file body", error))?;
            let mut body = vec![0; len];
            reader
                .read_exact(&mut body)
                .map_err(|error| FluxError::io("read static range body", error))?;
            Ok(bytes::Bytes::from(body))
        }
    }
}

fn open_static_body_file(file: &StaticFile) -> FluxResult<std::fs::File> {
    let relative = SafeRelativePath::from_rooted(&file.root, &file.path).ok_or_else(|| {
        FluxError::io(
            "static body path escaped web root",
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "static body path escaped web root",
            ),
        )
    })?;
    if file.path != file.root.join(relative.as_path()) {
        return Err(FluxError::io(
            "static body path contains a symlink",
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "static body path contains a symlink",
            ),
        ));
    }

    let canonical = file
        .path
        .canonicalize()
        .map_err(|error| FluxError::io("canonicalize static body path", error))?;
    if !canonical.starts_with(&file.root) {
        return Err(FluxError::io(
            "static body path escaped web root",
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "static body path escaped web root",
            ),
        ));
    }

    let metadata = std::fs::symlink_metadata(&canonical)
        .map_err(|error| FluxError::io("stat static body path", error))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(FluxError::io(
            "static body path is not a regular file",
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "static body path is not a regular file",
            ),
        ));
    }

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(O_NOFOLLOW);

    let file_handle = options
        .open(&canonical)
        .map_err(|error| FluxError::io("open static body file", error))?;
    let metadata = file_handle
        .metadata()
        .map_err(|error| FluxError::io("stat static body handle", error))?;
    if !metadata.is_file() {
        return Err(FluxError::io(
            "static body handle is not a regular file",
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "static body handle is not a regular file",
            ),
        ));
    }
    #[cfg(unix)]
    if metadata.dev() != file.device || metadata.ino() != file.inode {
        return Err(FluxError::io(
            "static file identity changed before body read",
            io::Error::new(
                io::ErrorKind::InvalidData,
                "static file identity changed before body read",
            ),
        ));
    }
    if metadata.len() != file.len {
        return Err(FluxError::io(
            "static file changed before body read",
            io::Error::new(
                io::ErrorKind::InvalidData,
                "static file changed before body read",
            ),
        ));
    }

    Ok(file_handle)
}
