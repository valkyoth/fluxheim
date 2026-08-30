use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};

use sanitization::SecretVec;

static PHP_REQUEST_BODY_SPOOL_COUNTER: AtomicUsize = AtomicUsize::new(0);
const PHP_SPOOL_POSITIONAL_READ_BYTES: usize = 64 * 1024;
type PhpSpoolReadTask = tokio::task::JoinHandle<io::Result<(SecretVec, usize)>>;

pub struct PhpRequestBody {
    inner: Arc<PhpRequestBodyInner>,
    len: usize,
}

enum PhpRequestBodyInner {
    Memory(Arc<SecretVec>),
    Spool(PhpRequestBodySpool),
}

struct PhpRequestBodySpool {
    file: Arc<std::fs::File>,
}

struct PhpSpoolReader {
    file: Arc<std::fs::File>,
    offset: u64,
    pending: Option<PhpSpoolReadTask>,
    ready: SecretVec,
    ready_start: usize,
    ready_len: usize,
}

struct PhpMemoryReader {
    body: Arc<SecretVec>,
    offset: usize,
}

impl PhpRequestBody {
    pub fn memory(body: Vec<u8>) -> Self {
        Self::memory_secret(SecretVec::from_vec(body))
    }

    pub fn memory_secret(body: SecretVec) -> Self {
        Self {
            len: body.len(),
            inner: Arc::new(PhpRequestBodyInner::Memory(Arc::new(body))),
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
            PhpRequestBodyInner::Memory(body) => Ok(Box::new(PhpMemoryReader {
                body: Arc::clone(body),
                offset: 0,
            })),
            PhpRequestBodyInner::Spool(spool) => Ok(Box::new(PhpSpoolReader {
                file: Arc::clone(&spool.file),
                offset: 0,
                pending: None,
                ready: SecretVec::empty(),
                ready_start: 0,
                ready_len: 0,
            })),
        }
    }
}

impl fastcgi_client::io::AsyncRead for PhpMemoryReader {
    fn poll_read(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        buffer: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let copied = this.body.with_secret(|body| {
            let available = body.get(this.offset..).unwrap_or_default();
            let copied = available.len().min(buffer.len());
            buffer[..copied].copy_from_slice(&available[..copied]);
            copied
        });
        this.offset = this.offset.saturating_add(copied);
        Poll::Ready(Ok(copied))
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
            if this.ready_start < this.ready_len {
                let copied = this.ready.with_secret(|ready| {
                    let available = &ready[this.ready_start..this.ready_len];
                    let copied = available.len().min(buffer.len());
                    buffer[..copied].copy_from_slice(&available[..copied]);
                    copied
                });
                this.ready_start += copied;
                if this.ready_start == this.ready_len {
                    this.ready.clear_secret();
                    this.ready_start = 0;
                    this.ready_len = 0;
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
                this.ready_start = 0;
                this.ready_len = read_len;
                if read_len == 0 {
                    this.ready.clear_secret();
                    return Poll::Ready(Ok(0));
                }
                continue;
            }

            let file = Arc::clone(&this.file);
            let offset = this.offset;
            let read_len = buffer.len().min(PHP_SPOOL_POSITIONAL_READ_BYTES);
            this.pending = Some(tokio::task::spawn_blocking(move || {
                let mut bytes = SecretVec::from_fn(read_len, |_| 0);
                let read = bytes.with_secret_mut(|bytes| {
                    read_php_request_body_spool_at(&file, bytes, offset)
                })?;
                Ok((bytes, read))
            }));
        }
    }
}

#[cfg(unix)]
fn read_php_request_body_spool_at(
    file: &std::fs::File,
    buffer: &mut [u8],
    offset: u64,
) -> io::Result<usize> {
    use std::os::unix::fs::FileExt as _;

    file.read_at(buffer, offset)
}

#[cfg(windows)]
fn read_php_request_body_spool_at(
    file: &std::fs::File,
    buffer: &mut [u8],
    offset: u64,
) -> io::Result<usize> {
    use std::os::windows::fs::FileExt as _;

    file.seek_read(buffer, offset)
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

#[cfg(all(not(unix), not(windows)))]
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

#[cfg(windows)]
async fn create_php_request_body_spool_file_by_path(
    spool_dir: &Path,
) -> io::Result<tokio::fs::File> {
    use std::os::windows::fs::OpenOptionsExt as _;

    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_TEMPORARY, FILE_FLAG_DELETE_ON_CLOSE, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let mut last_error = None;
    for _ in 0..16 {
        let path = php_request_body_spool_path(spool_dir)?;
        let mut options = std::fs::OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create_new(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(
                FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE | FILE_FLAG_OPEN_REPARSE_POINT,
            );
        match options.open(&path) {
            Ok(mut file) => {
                fluxheim_config::fs_trust::harden_confidential_file(&mut file)?;
                return Ok(tokio::fs::File::from_std(file));
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
    if fluxheim_config::fs_trust::existing_path_or_parent_has_insecure_write_permissions(spool_dir)?
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "PHP request body spool directory is group/world writable",
        ));
    }
    #[cfg(windows)]
    fluxheim_config::fs_trust::harden_private_directory(spool_dir)?;
    Ok(())
}
