use std::fs::File;
use std::io;
use std::path::Path;

pub(super) fn open(path: &Path) -> io::Result<File> {
    fluxheim_config::config_path::validate_required_process_path("logging.crash_file", path)
        .map_err(|_| io::Error::new(io::ErrorKind::PermissionDenied, "unsafe crash log path"))?;
    #[cfg(unix)]
    let file = {
        use rustix::fs::{Mode, OFlags};
        File::from(rustix::fs::open(
            path,
            OFlags::CREATE
                | OFlags::WRONLY
                | OFlags::APPEND
                | OFlags::CLOEXEC
                | OFlags::NOFOLLOW
                | OFlags::NONBLOCK,
            Mode::RUSR | Mode::WUSR,
        )?)
    };
    #[cfg(windows)]
    let file = fluxheim_config::fs_trust::open_or_create_confidential_file(path)?;
    if !file.metadata()?.is_file()
        || fluxheim_config::fs_trust::opened_file_has_insecure_confidential_permissions(&file)?
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "crash log must be a private regular file",
        ));
    }
    file.sync_data()?;
    Ok(file)
}

pub(super) fn require_distinct(crash: &File, ordinary: &File) -> io::Result<()> {
    #[cfg(windows)]
    let same = same_file::Handle::from_file(crash.try_clone()?)?
        == same_file::Handle::from_file(ordinary.try_clone()?)?;
    #[cfg(unix)]
    let same = {
        use std::os::unix::fs::MetadataExt as _;
        let a = crash.metadata()?;
        let b = ordinary.metadata()?;
        (a.dev(), a.ino()) == (b.dev(), b.ino())
    };
    if same {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "crash log must be separate from ordinary log",
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "runtime_crash_log_tests.rs"]
mod tests;
