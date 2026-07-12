#[cfg(unix)]
use std::io;
#[cfg(unix)]
use std::path::{Component, Path};

#[cfg(unix)]
pub(crate) fn create_private_directory_all(path: &Path) -> io::Result<rustix::fd::OwnedFd> {
    create_private_directory_all_with_owner(path, None)
}

#[cfg(unix)]
pub(crate) fn create_private_directory_all_with_owner(
    path: &Path,
    owner: Option<(u32, u32)>,
) -> io::Result<rustix::fd::OwnedFd> {
    walk_directory(path, true, owner)
}

#[cfg(unix)]
pub(crate) fn open_directory_no_symlinks(path: &Path) -> io::Result<rustix::fd::OwnedFd> {
    walk_directory(path, false, None)
}

#[cfg(unix)]
fn walk_directory(
    path: &Path,
    create: bool,
    owner: Option<(u32, u32)>,
) -> io::Result<rustix::fd::OwnedFd> {
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
        let created = if create {
            match rustix::fs::mkdirat(
                &directory,
                name,
                rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR | rustix::fs::Mode::XUSR,
            ) {
                Ok(()) => true,
                Err(rustix::io::Errno::EXIST) => false,
                Err(error) => return Err(error.into()),
            }
        } else {
            false
        };
        directory = rustix::fs::openat(
            &directory,
            name,
            directory_open_flags(),
            rustix::fs::Mode::empty(),
        )?;
        if created && let Some((uid, gid)) = owner {
            rustix::fs::fchown(
                &directory,
                Some(rustix::fs::Uid::from_raw(uid)),
                Some(rustix::fs::Gid::from_raw(gid)),
            )?;
        }
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

    #[test]
    fn owned_directory_walker_assigns_every_created_component() {
        const CHILD_PATH: &str = "FLUXHEIM_ACME_OWNER_TEST_PATH";
        if let Some(path) = std::env::var_os(CHILD_PATH) {
            open_directory_no_symlinks(Path::new(&path)).unwrap();
            return;
        }
        if !rustix::process::geteuid().is_root() {
            return;
        }

        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        use std::os::unix::process::CommandExt as _;

        let root = fluxheim_common::test_support::unique_temp_path("acme-directory-owner");
        std::fs::create_dir_all(&root).unwrap();
        let target = root.join("one/two/three");
        let owner = (65_534, 65_534);
        create_private_directory_all_with_owner(&target, Some(owner)).unwrap();

        for component in [root.join("one"), root.join("one/two"), target.clone()] {
            let metadata = std::fs::symlink_metadata(component).unwrap();
            assert_eq!((metadata.uid(), metadata.gid()), owner);
            assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
        }

        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "acme_directory::tests::owned_directory_walker_assigns_every_created_component",
            ])
            .env(CHILD_PATH, &target)
            .uid(owner.0)
            .gid(owner.1)
            .status()
            .unwrap();
        assert!(status.success());
    }
}
