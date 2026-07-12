#[cfg(unix)]
use std::io;
#[cfg(unix)]
use std::path::{Component, Path};

#[cfg(unix)]
pub(crate) fn create_private_directory_all(path: &Path) -> io::Result<rustix::fd::OwnedFd> {
    walk_directory(path, true)
}

#[cfg(unix)]
pub(crate) fn open_directory_no_symlinks(path: &Path) -> io::Result<rustix::fd::OwnedFd> {
    walk_directory(path, false)
}

#[cfg(unix)]
fn walk_directory(path: &Path, create: bool) -> io::Result<rustix::fd::OwnedFd> {
    let mut directory = rustix::fs::openat(
        rustix::fs::CWD,
        if path.is_absolute() {
            Path::new("/")
        } else {
            Path::new(".")
        },
        directory_open_flags(),
        rustix::fs::Mode::empty(),
    )?;

    for component in path.components() {
        let name = match component {
            Component::RootDir | Component::CurDir => continue,
            Component::Normal(name) => name,
            Component::ParentDir | Component::Prefix(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "ACME directory path contains a non-normal component",
                ));
            }
        };
        if create {
            match rustix::fs::mkdirat(
                &directory,
                name,
                rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR | rustix::fs::Mode::XUSR,
            ) {
                Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                Err(error) => return Err(error.into()),
            }
        }
        directory = rustix::fs::openat(
            &directory,
            name,
            directory_open_flags(),
            rustix::fs::Mode::empty(),
        )?;
    }

    if create {
        rustix::fs::fchmod(
            &directory,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR | rustix::fs::Mode::XUSR,
        )?;
    }
    Ok(directory)
}

#[cfg(unix)]
fn directory_open_flags() -> rustix::fs::OFlags {
    rustix::fs::OFlags::RDONLY
        | rustix::fs::OFlags::DIRECTORY
        | rustix::fs::OFlags::NOFOLLOW
        | rustix::fs::OFlags::CLOEXEC
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn directory_walker_rejects_symlinked_component() {
        let root = fluxheim_common::test_support::unique_temp_path("acme-directory-walker");
        let real = root.join("real");
        let linked = root.join("linked");
        std::fs::create_dir_all(&real).unwrap();
        std::os::unix::fs::symlink(&real, &linked).unwrap();

        assert!(create_private_directory_all(&linked.join("child")).is_err());
        assert!(!real.join("child").exists());
    }

    #[test]
    fn directory_walker_handles_concurrent_creation() {
        let root = fluxheim_common::test_support::unique_temp_path("acme-directory-concurrent");
        let target = root.join("one/two/three");
        let workers: Vec<_> = (0..8)
            .map(|_| {
                let target = target.clone();
                std::thread::spawn(move || create_private_directory_all(&target))
            })
            .collect();

        for worker in workers {
            assert!(worker.join().unwrap().is_ok());
        }
        assert!(target.is_dir());
    }
}
