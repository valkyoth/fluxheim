//! A pathname socket needs a stable name even after bind. Every containing
//! directory must therefore be protected from replacement by another UID.
use rustix::fs::{CWD, Mode, OFlags, fstat, mkdirat, openat};
use rustix::io::Errno;
use std::ffi::OsStr;
use std::io;
use std::path::{Component, Path};

pub(super) fn check(storage: &Path, create: bool) -> io::Result<()> {
    if !storage.is_absolute() || storage.components().any(|c| c == Component::ParentDir) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ACME ALPN storage needs an absolute directory path",
        ));
    }
    let parent = storage.parent().ok_or(io::ErrorKind::InvalidInput)?;
    let leaf = storage.file_name().ok_or(io::ErrorKind::InvalidInput)?;
    let uid = rustix::process::geteuid().as_raw();
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut fd = openat(CWD, "/", flags, Mode::empty())?;
    let anchor = fstat(&fd)?;
    // An unmapped owner can have the same displayed UID as unrelated owners.
    // Never derive an ancestor allowlist from the UID returned for "/".
    if anchor.st_uid != 0 && anchor.st_uid != uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "ACME TLS-ALPN cannot verify the owner of /; use a namespace with trusted root ownership or use HTTP-01",
        ));
    }
    check_owner(&anchor, uid, false)?;
    let parents = parent.components().skip(1).map(|c| (c, false));
    let private_dirs = [leaf, OsStr::new(".alpn")].map(|name| (Component::Normal(name), true));
    for (part, private) in parents.chain(private_dirs) {
        let Component::Normal(name) = part else {
            return Err(io::ErrorKind::InvalidInput.into());
        };
        fd = match openat(&fd, name, flags, Mode::empty()) {
            Err(Errno::NOENT) if create => {
                match mkdirat(&fd, name, Mode::RWXU) {
                    Ok(()) | Err(Errno::EXIST) => (),
                    Err(e) => return Err(e.into()),
                }
                openat(&fd, name, flags, Mode::empty())?
            }
            other => other?,
        };
        check_owner(&fstat(&fd)?, uid, private)?;
    }
    Ok(())
}

fn check_owner(stat: &rustix::fs::Stat, uid: u32, private: bool) -> io::Result<()> {
    let trusted = if private {
        stat.st_uid == uid && stat.st_mode & 0o777 == 0o700
    } else {
        (stat.st_uid == 0 || stat.st_uid == uid) && stat.st_mode & 0o022 == 0
    };
    if !trusted {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "ACME ALPN requires trusted ancestors and service-owned 0700 storage and .alpn directories",
        ));
    }
    Ok(())
}
