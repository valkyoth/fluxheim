use std::fs::File;
use std::io;
use std::path::Path;

const ACME_MUTATION_LOCK_FILE: &str = ".fluxheim-acme.lock";

#[cfg(unix)]
fn open_mutation_lock(directory: &Path) -> io::Result<rustix::fd::OwnedFd> {
    let directory = crate::acme_directory::open_directory_no_symlinks(directory)?;
    let flags =
        rustix::fs::OFlags::RDWR | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC;
    // Separate creation from opening an existing lock: concurrent O_CREAT
    // opens can return ENOENT on macOS even though the parent remains pinned.
    match rustix::fs::openat(
        &directory,
        ACME_MUTATION_LOCK_FILE,
        flags | rustix::fs::OFlags::CREATE | rustix::fs::OFlags::EXCL,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    ) {
        Ok(lock) => Ok(lock),
        Err(rustix::io::Errno::EXIST) => rustix::fs::openat(
            &directory,
            ACME_MUTATION_LOCK_FILE,
            flags,
            rustix::fs::Mode::empty(),
        )
        .map_err(Into::into),
        Err(error) => Err(error.into()),
    }
}

pub(crate) struct AcmeMutationLock {
    file: File,
}

pub struct AcmeCertificateReadLock {
    file: File,
}

pub fn lock_managed_certificate_pair(
    certificate: &Path,
    private_key: &Path,
) -> io::Result<AcmeCertificateReadLock> {
    let directory = certificate.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "certificate path has no parent",
        )
    })?;
    if private_key.parent() != Some(directory) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "managed certificate and key do not share a directory",
        ));
    }
    AcmeCertificateReadLock::acquire(directory)
}

impl AcmeCertificateReadLock {
    fn acquire(directory: &Path) -> io::Result<Self> {
        #[cfg(unix)]
        {
            let lock = open_mutation_lock(directory)?;
            rustix::fs::flock(&lock, rustix::fs::FlockOperation::LockShared)?;
            Ok(Self { file: lock.into() })
        }

        #[cfg(not(unix))]
        {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(directory.join(ACME_MUTATION_LOCK_FILE))?;
            file.lock_shared()?;
            Ok(Self { file })
        }
    }
}

impl Drop for AcmeCertificateReadLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

impl AcmeMutationLock {
    pub(crate) fn acquire(directory: &Path) -> io::Result<Self> {
        #[cfg(unix)]
        {
            let lock = open_mutation_lock(directory)?;
            rustix::fs::flock(&lock, rustix::fs::FlockOperation::LockExclusive)?;
            Ok(Self { file: lock.into() })
        }

        #[cfg(not(unix))]
        {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(directory.join(ACME_MUTATION_LOCK_FILE))?;
            file.lock()?;
            Ok(Self { file })
        }
    }

    #[cfg(any(feature = "acme-client", test))]
    pub(crate) fn try_acquire(directory: &Path) -> io::Result<Option<Self>> {
        #[cfg(unix)]
        {
            let lock = open_mutation_lock(directory)?;
            match rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
                Ok(()) => Ok(Some(Self { file: lock.into() })),
                Err(error) if error == rustix::io::Errno::AGAIN => Ok(None),
                Err(error) => Err(error.into()),
            }
        }

        #[cfg(not(unix))]
        {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(directory.join(ACME_MUTATION_LOCK_FILE))?;
            match file.try_lock() {
                Ok(()) => Ok(Some(Self { file })),
                Err(std::fs::TryLockError::WouldBlock) => Ok(None),
                Err(std::fs::TryLockError::Error(error)) => Err(error),
            }
        }
    }
}

impl Drop for AcmeMutationLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

pub(crate) fn unique_transaction_id() -> io::Result<String> {
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).map_err(io::Error::other)?;
    let mut id = String::with_capacity(random.len() * 2);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in random {
        id.push(HEX[(byte >> 4) as usize] as char);
        id.push(HEX[(byte & 0x0f) as usize] as char);
    }
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn concurrent_lock_creation_keeps_one_inode() {
        let root = fluxheim_common::test_support::unique_temp_path("acme-lock-creation");
        std::fs::create_dir_all(&root).unwrap();
        for round in 0..32 {
            let directory = root.join(round.to_string());
            std::fs::create_dir(&directory).unwrap();
            let barrier = std::sync::Arc::new(std::sync::Barrier::new(4));
            let workers: Vec<_> = (0..4)
                .map(|_| {
                    let directory = directory.clone();
                    let barrier = barrier.clone();
                    std::thread::spawn(move || {
                        barrier.wait();
                        open_mutation_lock(&directory)
                    })
                })
                .collect();
            let results: Vec<_> = workers.into_iter().map(|worker| worker.join()).collect();
            let locks: Vec<_> = results
                .into_iter()
                .map(|result| result.unwrap().unwrap())
                .collect();
            let expected = rustix::fs::fstat(&locks[0]).unwrap();
            for lock in &locks {
                let actual = rustix::fs::fstat(lock).unwrap();
                assert_eq!(
                    (actual.st_dev, actual.st_ino),
                    (expected.st_dev, expected.st_ino)
                );
                assert_eq!(actual.st_mode & 0o777, 0o600);
            }
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn lock_creation_preserves_existing_file_and_rejects_symlinks() {
        let directory = fluxheim_common::test_support::unique_temp_path("acme-lock-link");
        std::fs::create_dir_all(&directory).unwrap();
        let lock_path = directory.join(ACME_MUTATION_LOCK_FILE);
        let target = directory.join("target");
        std::fs::write(&lock_path, b"existing lock").unwrap();
        drop(open_mutation_lock(&directory).unwrap());
        assert_eq!(std::fs::read(&lock_path).unwrap(), b"existing lock");
        std::fs::rename(&lock_path, &target).unwrap();
        std::os::unix::fs::symlink(&target, &lock_path).unwrap();
        assert!(AcmeMutationLock::acquire(&directory).is_err());
        assert!(AcmeMutationLock::try_acquire(&directory).is_err());
        assert!(AcmeCertificateReadLock::acquire(&directory).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"existing lock");
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn certificate_read_lease_blocks_a_writer() {
        let directory =
            fluxheim_common::test_support::unique_temp_path("acme-certificate-read-lock");
        std::fs::create_dir_all(&directory).unwrap();
        let certificate = directory.join("fullchain.pem");
        let key = directory.join("privkey.pem");
        let read_lock = lock_managed_certificate_pair(&certificate, &key).unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        let writer_directory = directory.clone();
        let writer = std::thread::spawn(move || {
            let _lock = AcmeMutationLock::acquire(&writer_directory).unwrap();
            sender.send(()).unwrap();
        });

        assert!(
            receiver
                .recv_timeout(std::time::Duration::from_millis(50))
                .is_err()
        );
        drop(read_lock);
        receiver
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        writer.join().unwrap();
    }

    #[test]
    fn nonblocking_mutation_lock_reports_contention() {
        let directory = fluxheim_common::test_support::unique_temp_path("acme-try-lock");
        std::fs::create_dir_all(&directory).unwrap();
        let lock = AcmeMutationLock::acquire(&directory).unwrap();

        assert!(AcmeMutationLock::try_acquire(&directory).unwrap().is_none());
        drop(lock);
        assert!(AcmeMutationLock::try_acquire(&directory).unwrap().is_some());
    }
}
