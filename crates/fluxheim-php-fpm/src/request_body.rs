use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};

use zeroize::Zeroizing;

static PHP_REQUEST_BODY_SPOOL_COUNTER: AtomicUsize = AtomicUsize::new(0);
const PHP_SPOOL_POSITIONAL_READ_BYTES: usize = 64 * 1024;
type PhpSpoolReadTask = tokio::task::JoinHandle<io::Result<(Vec<u8>, usize)>>;

pub struct PhpRequestBody {
    inner: Arc<PhpRequestBodyInner>,
    len: usize,
}

enum PhpRequestBodyInner {
    Memory(Zeroizing<Vec<u8>>),
    Spool(PhpRequestBodySpool),
}

struct PhpRequestBodySpool {
    file: Arc<std::fs::File>,
}

struct PhpSpoolReader {
    file: Arc<std::fs::File>,
    offset: u64,
    pending: Option<PhpSpoolReadTask>,
    ready: Vec<u8>,
    ready_start: usize,
}

impl PhpRequestBody {
    pub fn memory(body: Vec<u8>) -> Self {
        Self::memory_zeroizing(Zeroizing::new(body))
    }

    pub fn memory_zeroizing(body: Zeroizing<Vec<u8>>) -> Self {
        Self {
            len: body.len(),
            inner: Arc::new(PhpRequestBodyInner::Memory(body)),
        }
    }

    pub async fn spooled(file: tokio::fs::File, len: usize) -> io::Result<Self> {
        let file = file.into_std().await;
        Ok(Self {
            len,
            inner: Arc::new(PhpRequestBodyInner::Spool(PhpRequestBodySpool {
                file: Arc::new(file),
            })),
        })
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub async fn reader(
        &self,
    ) -> io::Result<Box<dyn fastcgi_client::io::AsyncRead + Unpin + Send>> {
        match self.inner.as_ref() {
            PhpRequestBodyInner::Memory(body) => {
                Ok(Box::new(fastcgi_client::io::Cursor::new(body.clone())))
            }
            PhpRequestBodyInner::Spool(spool) => Ok(Box::new(PhpSpoolReader {
                file: Arc::clone(&spool.file),
                offset: 0,
                pending: None,
                ready: Vec::new(),
                ready_start: 0,
            })),
        }
    }
}

impl fastcgi_client::io::AsyncRead for PhpSpoolReader {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        use std::future::Future as _;

        let this = self.get_mut();
        if buffer.is_empty() {
            return Poll::Ready(Ok(0));
        }
        loop {
            if this.ready_start < this.ready.len() {
                let available = &this.ready[this.ready_start..];
                let copied = available.len().min(buffer.len());
                buffer[..copied].copy_from_slice(&available[..copied]);
                this.ready_start += copied;
                if this.ready_start == this.ready.len() {
                    this.ready.clear();
                    this.ready_start = 0;
                }
                return Poll::Ready(Ok(copied));
            }
            if let Some(pending) = this.pending.as_mut() {
                let result = match Pin::new(pending).poll(context) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(result) => result,
                };
                this.pending = None;
                let (bytes, read) = result.map_err(|error| {
                    io::Error::other(format!("PHP spool read task failed: {error}"))
                })??;
                if read > bytes.len() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "PHP spool positional read returned an invalid length",
                    )));
                }
                let read_len = read;
                let Ok(read) = u64::try_from(read_len) else {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "PHP spool positional read length is not representable",
                    )));
                };
                let Some(next_offset) = this.offset.checked_add(read) else {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "PHP spool read offset overflow",
                    )));
                };
                this.offset = next_offset;
                this.ready = bytes;
                this.ready.truncate(read_len);
                this.ready_start = 0;
                if read_len == 0 {
                    return Poll::Ready(Ok(0));
                }
                continue;
            }

            let file = Arc::clone(&this.file);
            let offset = this.offset;
            let read_len = buffer.len().min(PHP_SPOOL_POSITIONAL_READ_BYTES);
            this.pending = Some(tokio::task::spawn_blocking(move || {
                use std::os::unix::fs::FileExt as _;

                let mut bytes = vec![0_u8; read_len];
                let read = file.read_at(&mut bytes, offset)?;
                Ok((bytes, read))
            }));
        }
    }
}

#[cfg(not(unix))]
fn php_request_body_spool_path(spool_dir: &Path) -> io::Result<PathBuf> {
    Ok(spool_dir.join(php_request_body_spool_filename()?))
}

fn php_request_body_spool_filename() -> io::Result<String> {
    let counter = PHP_REQUEST_BODY_SPOOL_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut random = [0_u8; 8];
    getrandom::fill(&mut random).map_err(|error| {
        io::Error::other(format!(
            "failed to generate PHP spool filename entropy: {error}"
        ))
    })?;
    let random = u64::from_le_bytes(random);
    Ok(format!(
        ".fluxheim-php-body-{}-{counter}-{random:016x}.tmp",
        std::process::id()
    ))
}

pub async fn create_php_request_body_spool_file(spool_dir: &Path) -> io::Result<tokio::fs::File> {
    create_php_request_body_spool_dir(spool_dir).await?;
    ensure_php_request_body_spool_dir(spool_dir)?;

    #[cfg(unix)]
    {
        create_php_request_body_spool_file_at(spool_dir)
    }

    #[cfg(not(unix))]
    {
        create_php_request_body_spool_file_by_path(spool_dir).await
    }
}

#[cfg(unix)]
async fn create_php_request_body_spool_dir(spool_dir: &Path) -> io::Result<()> {
    create_php_request_body_spool_dir_sync(spool_dir)
}

#[cfg(not(unix))]
async fn create_php_request_body_spool_dir(spool_dir: &Path) -> io::Result<()> {
    tokio::fs::create_dir_all(spool_dir).await
}

#[cfg(unix)]
pub fn create_php_request_body_spool_dir_sync(spool_dir: &Path) -> io::Result<()> {
    use rustix::fs::Mode;

    if spool_dir.as_os_str().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "PHP request body spool directory cannot be empty",
        ));
    }

    let mut current = PathBuf::new();
    for component in spool_dir.components() {
        current.push(component.as_os_str());
        match rustix::fs::mkdir(&current, Mode::from_raw_mode(0o700)) {
            Ok(()) => {}
            Err(rustix::io::Errno::EXIST) => {}
            Err(error) => return Err(io::Error::from(error)),
        }
    }
    Ok(())
}

#[cfg(not(unix))]
async fn create_php_request_body_spool_file_by_path(
    spool_dir: &Path,
) -> io::Result<tokio::fs::File> {
    let mut last_error = None;
    for _ in 0..16 {
        let path = php_request_body_spool_path(spool_dir)?;
        let mut options = tokio::fs::OpenOptions::new();
        options.read(true).write(true).create_new(true);
        match options.open(&path).await {
            Ok(file) => {
                tokio::fs::remove_file(&path).await?;
                return Ok(file);
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                last_error = Some(error);
            }
            Err(error) => return Err(error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate PHP request body spool file",
        )
    }))
}

#[cfg(unix)]
fn create_php_request_body_spool_file_at(spool_dir: &Path) -> io::Result<tokio::fs::File> {
    use rustix::fs::{Mode, OFlags};

    let directory = rustix::fs::openat(
        rustix::fs::CWD,
        spool_dir,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(io::Error::from)?;
    ensure_php_request_body_spool_dir_fd(&directory)?;

    let mut last_error = None;
    for _ in 0..16 {
        let filename = php_request_body_spool_filename()?;
        match rustix::fs::openat(
            &directory,
            filename.as_str(),
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        ) {
            Ok(file) => {
                if let Err(error) = rustix::fs::unlinkat(
                    &directory,
                    filename.as_str(),
                    rustix::fs::AtFlags::empty(),
                ) {
                    drop(file);
                    let _ = rustix::fs::unlinkat(
                        &directory,
                        filename.as_str(),
                        rustix::fs::AtFlags::empty(),
                    );
                    return Err(io::Error::from(error));
                }
                let file = tokio::fs::File::from_std(std::fs::File::from(file));
                return Ok(file);
            }
            Err(error) if error == rustix::io::Errno::EXIST => {
                last_error = Some(io::Error::from(error));
            }
            Err(error) => return Err(io::Error::from(error)),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate PHP request body spool file",
        )
    }))
}

#[cfg(unix)]
fn ensure_php_request_body_spool_dir_fd<Fd: rustix::fd::AsFd>(directory: Fd) -> io::Result<()> {
    let stat = rustix::fs::fstat(directory).map_err(io::Error::from)?;
    if stat.st_mode & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "PHP request body spool directory is group/world writable",
        ));
    }
    Ok(())
}

pub fn ensure_php_request_body_spool_dir(spool_dir: &Path) -> io::Result<()> {
    let metadata = std::fs::symlink_metadata(spool_dir)?;
    if !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "PHP request body spool path is not a directory",
        ));
    }
    #[cfg(unix)]
    if fluxheim_config::fs_trust::existing_path_or_parent_has_insecure_write_permissions(spool_dir)?
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "PHP request body spool directory is group/world writable",
        ));
    }
    Ok(())
}
