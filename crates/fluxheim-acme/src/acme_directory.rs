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
pub(crate) fn reconcile_private_directory_subtree(
    boundary: &Path,
    boundary_directory: &rustix::fd::OwnedFd,
    target: &Path,
    owner: (u32, u32),
) -> io::Result<rustix::fd::OwnedFd> {
    let relative = target.strip_prefix(boundary).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "ACME managed directory target escapes its ownership boundary",
        )
    })?;
    let components = relative
        .components()
        .map(|component| match component {
            Component::CurDir => Ok(None),
            Component::Normal(name) => Ok(Some(name)),
            Component::RootDir | Component::ParentDir | Component::Prefix(_) => {
                Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "ACME managed directory target contains a non-normal component",
                ))
            }
        })
        .collect::<io::Result<Vec<_>>>()?;

    let boundary_device = rustix::fs::fstat(boundary_directory)?.st_dev;
    let mut directory = rustix::io::dup(boundary_directory)?;
    for name in components.into_iter().flatten() {
        match rustix::fs::mkdirat(&directory, name, private_directory_mode()) {
            Ok(()) | Err(rustix::io::Errno::EXIST) => {}
            Err(error) => return Err(error.into()),
        }
        let next = open_reconciliation_descendant(&directory, name)?;
        if rustix::fs::fstat(&next)?.st_dev != boundary_device {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "ACME managed directory target crosses a filesystem boundary",
            ));
        }
        directory = next;
        rustix::fs::fchown(
            &directory,
            Some(rustix::fs::Uid::from_raw(owner.0)),
            Some(rustix::fs::Gid::from_raw(owner.1)),
        )?;
        rustix::fs::fchmod(&directory, private_directory_mode())?;
    }
    Ok(directory)
}

#[cfg(target_os = "linux")]
fn open_reconciliation_descendant(
    directory: &rustix::fd::OwnedFd,
    name: &std::ffi::OsStr,
) -> io::Result<rustix::fd::OwnedFd> {
    rustix::fs::openat2(
        directory,
        name,
        directory_open_flags(),
        rustix::fs::Mode::empty(),
        rustix::fs::ResolveFlags::BENEATH
            | rustix::fs::ResolveFlags::NO_SYMLINKS
            | rustix::fs::ResolveFlags::NO_MAGICLINKS
            | rustix::fs::ResolveFlags::NO_XDEV,
    )
    .map_err(Into::into)
}

#[cfg(all(unix, not(target_os = "linux")))]
fn open_reconciliation_descendant(
    directory: &rustix::fd::OwnedFd,
    name: &std::ffi::OsStr,
) -> io::Result<rustix::fd::OwnedFd> {
    rustix::fs::openat(
        directory,
        name,
        directory_open_flags(),
        rustix::fs::Mode::empty(),
    )
    .map_err(Into::into)
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
            match rustix::fs::mkdirat(&directory, name, private_directory_mode()) {
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
        rustix::fs::fchmod(&directory, private_directory_mode())?;
    }
    Ok(directory)
}

#[cfg(unix)]
fn private_directory_mode() -> rustix::fs::Mode {
    rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR | rustix::fs::Mode::XUSR
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
    fn owned_directory_reconciliation_updates_preexisting_components() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let root = fluxheim_common::test_support::unique_temp_path("acme-directory-reconcile");
        let boundary = root.join("storage");
        let stranded = boundary.join("one");
        std::fs::create_dir_all(&stranded).unwrap();
        std::fs::set_permissions(&stranded, std::fs::Permissions::from_mode(0o755)).unwrap();
        let target = stranded.join("two");
        let owner = (
            rustix::process::geteuid().as_raw(),
            rustix::process::getegid().as_raw(),
        );

        let boundary_directory = open_directory_no_symlinks(&boundary).unwrap();
        reconcile_private_directory_subtree(&boundary, &boundary_directory, &target, owner)
            .unwrap();

        for component in [stranded, target] {
            let metadata = std::fs::symlink_metadata(component).unwrap();
            assert_eq!((metadata.uid(), metadata.gid()), owner);
            assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
        }
    }

    #[test]
    fn owned_directory_reconciliation_repairs_interrupted_handoff() {
        const CHILD_PATH: &str = "FLUXHEIM_ACME_OWNER_TEST_PATH";
        if let Some(path) = std::env::var_os(CHILD_PATH) {
            open_directory_no_symlinks(Path::new(&path)).unwrap();
            return;
        }
        if !rustix::process::geteuid().is_root() {
            eprintln!("root-only ACME ownership recovery test skipped");
            return;
        }

        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        use std::os::unix::process::CommandExt as _;

        let root = fluxheim_common::test_support::unique_temp_path("acme-directory-owner");
        std::fs::create_dir_all(&root).unwrap();
        let boundary = root.join("storage");
        std::fs::create_dir(&boundary).unwrap();
        let owner = (65_534, 65_534);
        rustix::fs::chown(
            &boundary,
            Some(rustix::fs::Uid::from_raw(owner.0)),
            Some(rustix::fs::Gid::from_raw(owner.1)),
        )
        .unwrap();
        std::fs::set_permissions(&boundary, std::fs::Permissions::from_mode(0o700)).unwrap();

        let stranded = boundary.join("one");
        std::fs::create_dir(&stranded).unwrap();
        std::fs::set_permissions(&stranded, std::fs::Permissions::from_mode(0o700)).unwrap();
        let target = stranded.join("two/three");
        let boundary_directory = open_directory_no_symlinks(&boundary).unwrap();
        reconcile_private_directory_subtree(&boundary, &boundary_directory, &target, owner)
            .unwrap();

        for component in [stranded, boundary.join("one/two"), target.clone()] {
            let metadata = std::fs::symlink_metadata(component).unwrap();
            assert_eq!((metadata.uid(), metadata.gid()), owner);
            assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
        }

        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "acme_directory::tests::owned_directory_reconciliation_repairs_interrupted_handoff",
            ])
            .env(CHILD_PATH, &target)
            .uid(owner.0)
            .gid(owner.1)
            .status()
            .unwrap();
        assert!(status.success());
    }

    #[test]
    fn owned_directory_reconciliation_rejects_target_outside_boundary() {
        let root = fluxheim_common::test_support::unique_temp_path("acme-directory-boundary");
        let boundary = root.join("storage");
        let outside = root.join("outside/child");
        std::fs::create_dir_all(&boundary).unwrap();

        let boundary_directory = open_directory_no_symlinks(&boundary).unwrap();
        let error = reconcile_private_directory_subtree(
            &boundary,
            &boundary_directory,
            &outside,
            (
                rustix::process::geteuid().as_raw(),
                rustix::process::getegid().as_raw(),
            ),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(!outside.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn owned_directory_reconciliation_rejects_bind_mount() {
        // Run only inside an isolated privileged mount namespace.
        const ENABLED: &str = "FLUXHEIM_ACME_MOUNT_BOUNDARY_TEST";
        if std::env::var_os(ENABLED).as_deref() != Some(std::ffi::OsStr::new("1")) {
            eprintln!("privileged ACME mount-boundary test skipped");
            return;
        }
        if !rustix::process::geteuid().is_root() {
            panic!("privileged ACME mount-boundary test requires root");
        }

        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        struct BindMount(std::path::PathBuf);
        impl Drop for BindMount {
            fn drop(&mut self) {
                let _ = rustix::mount::unmount(&self.0, rustix::mount::UnmountFlags::DETACH);
            }
        }

        let root = fluxheim_common::test_support::unique_temp_path("acme-directory-mount");
        let boundary = root.join("storage");
        let mount_point = boundary.join("mounted");
        let outside = root.join("outside");
        std::fs::create_dir_all(&mount_point).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o755)).unwrap();
        let original = std::fs::symlink_metadata(&outside).unwrap();
        rustix::mount::mount_bind(&outside, &mount_point).unwrap();
        let _mount = BindMount(mount_point.clone());

        let boundary_directory = open_directory_no_symlinks(&boundary).unwrap();
        assert!(
            reconcile_private_directory_subtree(
                &boundary,
                &boundary_directory,
                &mount_point.join("child"),
                (65_534, 65_534),
            )
            .is_err()
        );

        let after = std::fs::symlink_metadata(&outside).unwrap();
        assert_eq!((after.uid(), after.gid()), (original.uid(), original.gid()));
        assert_eq!(
            after.permissions().mode() & 0o777,
            original.permissions().mode() & 0o777
        );
        assert!(!outside.join("child").exists());
    }
}
