use std::fs::File;
use std::io;
use std::path::Path;

const ACME_MUTATION_LOCK_FILE: &str = ".fluxheim-acme.lock";

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
            let directory = rustix::fs::openat(
                rustix::fs::CWD,
                directory,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )?;
            let lock = rustix::fs::openat(
                &directory,
                ACME_MUTATION_LOCK_FILE,
                rustix::fs::OFlags::RDWR
                    | rustix::fs::OFlags::CREATE
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
            )?;
            rustix::fs::flock(&lock, rustix::fs::FlockOperation::LockShared)?;
            Ok(Self { file: lock.into() })
        }

        #[cfg(not(unix))]
        {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
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
            let directory = rustix::fs::openat(
                rustix::fs::CWD,
                directory,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )?;
            let lock = rustix::fs::openat(
                &directory,
                ACME_MUTATION_LOCK_FILE,
                rustix::fs::OFlags::RDWR
                    | rustix::fs::OFlags::CREATE
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
            )?;
            rustix::fs::flock(&lock, rustix::fs::FlockOperation::LockExclusive)?;
            Ok(Self { file: lock.into() })
        }

        #[cfg(not(unix))]
        {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .open(directory.join(ACME_MUTATION_LOCK_FILE))?;
            file.lock()?;
            Ok(Self { file })
        }
    }

    #[cfg(any(feature = "acme-client", test))]
    pub(crate) fn try_acquire(directory: &Path) -> io::Result<Option<Self>> {
        #[cfg(unix)]
        {
            let directory = rustix::fs::openat(
                rustix::fs::CWD,
                directory,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )?;
            let lock = rustix::fs::openat(
                &directory,
                ACME_MUTATION_LOCK_FILE,
                rustix::fs::OFlags::RDWR
                    | rustix::fs::OFlags::CREATE
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
            )?;
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
                .open(directory.join(ACME_MUTATION_LOCK_FILE))?;
            match file.try_lock() {
                Ok(()) => Ok(Some(Self { file })),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(None),
                Err(error) => Err(error),
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
