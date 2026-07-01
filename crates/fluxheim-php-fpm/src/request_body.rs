use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use zeroize::Zeroizing;

static PHP_REQUEST_BODY_SPOOL_COUNTER: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone)]
pub struct PhpRequestBody {
    inner: Arc<PhpRequestBodyInner>,
    len: usize,
}

enum PhpRequestBodyInner {
    Memory(Zeroizing<Vec<u8>>),
    Spool(PhpRequestBodySpool),
}

struct PhpRequestBodySpool {
    path: PathBuf,
}

impl Drop for PhpRequestBodySpool {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
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

    pub fn spooled(path: PathBuf, len: usize) -> Self {
        Self {
            len,
            inner: Arc::new(PhpRequestBodyInner::Spool(PhpRequestBodySpool { path })),
        }
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
            PhpRequestBodyInner::Spool(spool) => {
                let file = tokio::fs::File::open(&spool.path).await?;
                Ok(Box::new(
                    fastcgi_client::io::TokioAsyncReadCompatExt::compat(file),
                ))
            }
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

pub async fn create_php_request_body_spool_file(
    spool_dir: &Path,
) -> io::Result<(PathBuf, tokio::fs::File)> {
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
) -> io::Result<(PathBuf, tokio::fs::File)> {
    let mut last_error = None;
    for _ in 0..16 {
        let path = php_request_body_spool_path(spool_dir)?;
        let mut options = tokio::fs::OpenOptions::new();
        options.write(true).create_new(true);
        match options.open(&path).await {
            Ok(file) => return Ok((path, file)),
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
fn create_php_request_body_spool_file_at(
    spool_dir: &Path,
) -> io::Result<(PathBuf, tokio::fs::File)> {
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
        let path = spool_dir.join(&filename);
        match rustix::fs::openat(
            &directory,
            filename.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        ) {
            Ok(file) => {
                let file = tokio::fs::File::from_std(std::fs::File::from(file));
                return Ok((path, file));
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
