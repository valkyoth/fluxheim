use std::fs;
use std::io;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use sanitization::SecretVec;

#[cfg(target_os = "linux")]
use super::UNIX_O_NOFOLLOW;
use super::{
    AcmeAccountCredentialsPath, AcmeAccountStoreError, MAX_ACCOUNT_CREDENTIALS_BYTES,
    managed_certificate_segment,
};

const ACME_ACCOUNT_DIR: &str = "accounts";
const ACME_ACCOUNT_CREDENTIALS_FILE: &str = "credentials.json";

pub fn account_credentials_path(storage: &Path, issuer_name: &str) -> AcmeAccountCredentialsPath {
    AcmeAccountCredentialsPath {
        path: storage
            .join(ACME_ACCOUNT_DIR)
            .join(managed_certificate_segment(issuer_name))
            .join(ACME_ACCOUNT_CREDENTIALS_FILE),
    }
}

pub fn load_account_credentials(
    storage: &Path,
    issuer_name: &str,
) -> Result<Option<instant_acme::AccountCredentials>, AcmeAccountStoreError> {
    let path = account_credentials_path(storage, issuer_name).path;
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(account_store_io_error(&path, error)),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(AcmeAccountStoreError::UnsafePath {
            path,
            message: "credentials path is not a real file".to_owned(),
        });
    }
    if metadata.len() > MAX_ACCOUNT_CREDENTIALS_BYTES {
        return Err(AcmeAccountStoreError::Oversized {
            path,
            max_bytes: MAX_ACCOUNT_CREDENTIALS_BYTES,
        });
    }

    let file = open_regular_account_credentials_file(&path)
        .map_err(|error| account_store_io_error(&path, error))?;
    let mut contents = Vec::new();
    file.take(MAX_ACCOUNT_CREDENTIALS_BYTES.saturating_add(1))
        .read_to_end(&mut contents)
        .map_err(|error| account_store_io_error(&path, error))?;
    if contents.len() as u64 > MAX_ACCOUNT_CREDENTIALS_BYTES {
        return Err(AcmeAccountStoreError::Oversized {
            path,
            max_bytes: MAX_ACCOUNT_CREDENTIALS_BYTES,
        });
    }

    serde_json::from_slice(&contents)
        .map(Some)
        .map_err(|error| AcmeAccountStoreError::Deserialize {
            path,
            message: error.to_string(),
        })
}

pub fn store_account_credentials(
    storage: &Path,
    issuer_name: &str,
    credentials: &instant_acme::AccountCredentials,
) -> Result<AcmeAccountCredentialsPath, AcmeAccountStoreError> {
    let credentials_path = account_credentials_path(storage, issuer_name);
    let directory =
        credentials_path
            .path
            .parent()
            .ok_or_else(|| AcmeAccountStoreError::UnsafePath {
                path: credentials_path.path.clone(),
                message: "credentials path has no parent directory".to_owned(),
            })?;
    ensure_safe_account_directory(directory)?;
    ensure_safe_account_destination(&credentials_path.path)?;

    let contents = SecretVec::from_vec(serde_json::to_vec(credentials).map_err(|error| {
        AcmeAccountStoreError::Serialize {
            message: error.to_string(),
        }
    })?);
    if contents.len() as u64 > MAX_ACCOUNT_CREDENTIALS_BYTES {
        return Err(AcmeAccountStoreError::Oversized {
            path: credentials_path.path.clone(),
            max_bytes: MAX_ACCOUNT_CREDENTIALS_BYTES,
        });
    }

    let tmp_path = directory.join(".credentials.json.tmp");
    let result = (|| {
        contents.with_secret(|contents| write_account_credentials_file(&tmp_path, contents))?;
        fs::rename(&tmp_path, &credentials_path.path)
            .map_err(|error| account_store_io_error(&credentials_path.path, error))?;
        sync_account_directory(directory)?;
        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }

    result?;
    Ok(credentials_path)
}

fn ensure_safe_account_directory(directory: &Path) -> Result<(), AcmeAccountStoreError> {
    reject_existing_symlink_in_account_path(directory)?;
    fs::create_dir_all(directory).map_err(|error| account_store_io_error(directory, error))?;
    reject_existing_symlink_in_account_path(directory)?;
    let metadata = fs::symlink_metadata(directory)
        .map_err(|error| account_store_io_error(directory, error))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(AcmeAccountStoreError::UnsafePath {
            path: directory.to_path_buf(),
            message: "path is not a real directory".to_owned(),
        });
    }

    Ok(())
}

fn ensure_safe_account_destination(path: &Path) -> Result<(), AcmeAccountStoreError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(AcmeAccountStoreError::UnsafePath {
                path: path.to_path_buf(),
                message: "credentials path is not a real file".to_owned(),
            })
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(account_store_io_error(path, error)),
    }
}

fn reject_existing_symlink_in_account_path(path: &Path) -> Result<(), AcmeAccountStoreError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(AcmeAccountStoreError::UnsafePath {
                    path: current,
                    message: "path contains a symlink".to_owned(),
                });
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(account_store_io_error(&current, error)),
        }
    }

    Ok(())
}

fn write_account_credentials_file(
    path: &Path,
    contents: &[u8],
) -> Result<(), AcmeAccountStoreError> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options
        .open(path)
        .map_err(|error| account_store_io_error(path, error))?;
    file.write_all(contents)
        .map_err(|error| account_store_io_error(path, error))?;
    file.sync_all()
        .map_err(|error| account_store_io_error(path, error))
}

fn sync_account_directory(path: &Path) -> Result<(), AcmeAccountStoreError> {
    fs::File::open(path)
        .map_err(|error| account_store_io_error(path, error))?
        .sync_all()
        .map_err(|error| account_store_io_error(path, error))
}

#[cfg(target_os = "linux")]
fn open_regular_account_credentials_file(path: &Path) -> io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(UNIX_O_NOFOLLOW)
        .open(path)
}

#[cfg(not(target_os = "linux"))]
fn open_regular_account_credentials_file(path: &Path) -> io::Result<std::fs::File> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }

    std::fs::File::open(path)
}

fn account_store_io_error(path: &Path, error: io::Error) -> AcmeAccountStoreError {
    AcmeAccountStoreError::Io {
        path: path.to_path_buf(),
        error,
    }
}
