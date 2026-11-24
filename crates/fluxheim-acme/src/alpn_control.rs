//! Local, filesystem-protected publication channel. Only names and digests
//! cross the socket; certificate generation and private keys stay in the gateway.
use crate::acme_certificate_install::fs_ops::{
    ensure_safe_directory, managed_certificate_ownership,
};
pub use crate::acme_tls_alpn::tls_alpn_01_certificate;
use socket2::{Domain, SockAddr, Socket, Type};
use std::{
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

const TICK: Duration = Duration::from_millis(20);
const SETUP: Duration = Duration::from_secs(5);
pub const LIFETIME: Duration = Duration::from_secs(180);
const MAX_SESSIONS: usize = 128;
const MAX_FRAME: usize = 1 + 253 + 32;
type Publish = dyn Fn(&str, &[u8; 32]) -> io::Result<Box<dyn Send>> + Send + Sync;

fn socket() -> io::Result<Socket> {
    Socket::new(Domain::UNIX, Type::STREAM, None)
}
fn endpoint(storage: &Path) -> PathBuf {
    storage.join(".alpn").join("s")
}
fn is_socket(path: &Path) -> io::Result<bool> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        Ok(std::fs::symlink_metadata(path)?.file_type().is_socket())
    }
    #[cfg(windows)]
    {
        fluxheim_windows_security::is_local_socket(path)
    }
}

pub struct Broker {
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}
impl Broker {
    pub fn bind(storage: &Path, publish: Arc<Publish>) -> io::Result<Self> {
        let dir = storage.join(".alpn");
        let owner = managed_certificate_ownership(storage).map_err(io::Error::other)?;
        ensure_safe_directory(&dir, &owner).map_err(io::Error::other)?;
        let lock = crate::AcmeMutationLock::try_acquire(&dir)?.ok_or(io::ErrorKind::AddrInUse)?;
        let path = endpoint(storage);
        let addr = SockAddr::unix(&path)?;
        match is_socket(&path) {
            Ok(true) => std::fs::remove_file(&path)?,
            Ok(false) => return Err(io::ErrorKind::AlreadyExists.into()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => (),
            Err(e) => return Err(e),
        }
        let listener = socket()?;
        listener.bind(&addr)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
        listener.listen(32)?;
        listener.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let worker = thread::Builder::new()
            .name("acme-alpn".into())
            .spawn(move || {
                let mut sessions = Vec::new();
                while !stopping.load(Ordering::Acquire) {
                    for _ in 0..8 {
                        let Ok((stream, _)) = listener.accept() else {
                            break;
                        };
                        if sessions.len() < MAX_SESSIONS && stream.set_nonblocking(true).is_ok() {
                            sessions.push(Session::new(stream));
                        }
                    }
                    sessions.retain_mut(|s| s.step(&*publish).unwrap_or(false));
                    thread::park_timeout(TICK);
                }
                drop(sessions);
                drop(listener);
                let _ = std::fs::remove_file(path);
                drop(lock);
            })?;
        Ok(Self {
            stop,
            worker: Some(worker),
        })
    }
}
impl Drop for Broker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            worker.thread().unpark();
            let _ = worker.join();
        }
    }
}

struct Session {
    stream: Socket,
    frame: [u8; MAX_FRAME],
    used: usize,
    start: Instant,
    lease: Option<Box<dyn Send>>,
}
impl Session {
    fn new(stream: Socket) -> Self {
        Self {
            stream,
            frame: [0; MAX_FRAME],
            used: 0,
            start: Instant::now(),
            lease: None,
        }
    }
    fn step(&mut self, publish: &Publish) -> io::Result<bool> {
        let active = self.lease.is_some();
        if self.start.elapsed() >= if active { LIFETIME } else { SETUP } {
            return Ok(false);
        }
        let mut end = [0; 1];
        let buf = if active {
            &mut end[..]
        } else {
            &mut self.frame[self.used..]
        };
        let n = match self.stream.read(buf) {
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(true),
            result => result?,
        };
        if active {
            self.lease.take();
            if n == 1 && end[0] == 0 {
                self.stream.write_all(&[1])?;
            }
            return Ok(false);
        }
        if n == 0 {
            return Ok(false);
        }
        self.used += n;
        let name_len = usize::from(self.frame[0]);
        if name_len == 0 && self.used == 1 {
            self.stream.write_all(&[1])?;
            return Ok(false);
        }
        if name_len == 0 || name_len > 253 {
            return Ok(false);
        }
        let expected = 1 + name_len + 32;
        if self.used < expected {
            return Ok(true);
        }
        if self.used != expected {
            return Ok(false);
        }
        let name = std::str::from_utf8(&self.frame[1..1 + name_len])
            .map_err(|_| io::ErrorKind::InvalidData)?;
        let digest = self.frame[1 + name_len..expected]
            .try_into()
            .map_err(|_| io::ErrorKind::InvalidData)?;
        self.lease = Some(publish(name, digest)?);
        self.stream.write_all(&[1])?;
        Ok(true)
    }
}

pub(crate) struct Publication(Socket);
pub async fn probe(storage: &Path) -> io::Result<()> {
    Publication::open(storage, None).await.map(drop)
}
impl Publication {
    pub(crate) async fn open(storage: &Path, request: Option<(&str, &[u8])>) -> io::Result<Self> {
        let mut frame = vec![0];
        if let Some((domain, digest)) = request {
            if domain.is_empty() || domain.len() > 253 || digest.len() != 32 {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            frame[0] = domain.len() as u8;
            frame.extend_from_slice(domain.as_bytes());
            frame.extend_from_slice(digest);
        }
        let path = endpoint(storage);
        tokio::task::spawn_blocking(move || {
            if fluxheim_config::fs_trust::existing_parent_has_insecure_write_permissions(&path)?
                || !is_socket(&path)?
            {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            let mut stream = socket()?;
            stream.connect_timeout(&SockAddr::unix(path)?, SETUP)?;
            stream.set_nonblocking(true)?;
            exchange(&mut stream, &frame)?;
            Ok(Self(stream))
        })
        .await
        .map_err(io::Error::other)?
    }
    pub(crate) async fn close(mut self) -> io::Result<()> {
        tokio::task::spawn_blocking(move || exchange(&mut self.0, &[0]))
            .await
            .map_err(io::Error::other)?
    }
}
fn exchange(stream: &mut Socket, mut bytes: &[u8]) -> io::Result<()> {
    let start = Instant::now();
    loop {
        if start.elapsed() >= SETUP {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let result = if bytes.is_empty() {
            let mut ack = [0];
            match stream.read(&mut ack) {
                Ok(1) if ack == [1] => return Ok(()),
                Ok(_) => return Err(io::ErrorKind::InvalidData.into()),
                Err(e) => Err(e),
            }
        } else {
            match stream.write(bytes) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(n) => {
                    bytes = &bytes[n..];
                    continue;
                }
                Err(e) => Err(e),
            }
        };
        match result {
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => thread::sleep(TICK),
            other => return other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Active(Arc<AtomicBool>);
    impl Drop for Active {
        fn drop(&mut self) {
            self.0.store(false, Ordering::Release);
        }
    }
    #[test]
    fn native_publication_acknowledges_install_release_death_and_restart() {
        let root =
            fluxheim_common::test_support::test_root().join(format!("a{:x}", std::process::id()));
        let active = Arc::new(AtomicBool::new(false));
        let observed = active.clone();
        let publish: Arc<Publish> = Arc::new(move |name, digest| {
            if name != "site.example"
                || digest != &[42; 32]
                || observed.swap(true, Ordering::AcqRel)
            {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            Ok(Box::new(Active(observed.clone())))
        });
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        for _ in 0..2 {
            let broker = Broker::bind(&root, publish.clone()).unwrap();
            assert!(Broker::bind(&root, publish.clone()).is_err());
            rt.block_on(probe(&root)).unwrap();
            rt.block_on(async {
                assert!(
                    Publication::open(&root, Some(("other.example", &[42; 32])))
                        .await
                        .is_err()
                );
                let first = Publication::open(&root, Some(("site.example", &[42; 32])))
                    .await
                    .unwrap();
                assert!(active.load(Ordering::Acquire));
                first.close().await.unwrap();
                assert!(!active.load(Ordering::Acquire));
                drop(
                    Publication::open(&root, Some(("site.example", &[42; 32])))
                        .await
                        .unwrap(),
                );
                let start = Instant::now();
                while active.load(Ordering::Acquire) {
                    assert!(start.elapsed() < SETUP);
                    thread::sleep(TICK);
                }
            });
            drop(broker);
            assert!(rt.block_on(probe(&root)).is_err());
        }
        std::fs::write(endpoint(&root), b"unowned").unwrap();
        assert!(Broker::bind(&root, publish).is_err());
        assert_eq!(std::fs::read(endpoint(&root)).unwrap(), b"unowned");
        std::fs::remove_dir_all(root).unwrap();
    }
}
