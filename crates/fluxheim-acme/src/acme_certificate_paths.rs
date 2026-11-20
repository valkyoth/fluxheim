use std::io;
use std::io::Read;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(target_os = "linux")]
use super::UNIX_O_NOFOLLOW;
use super::{
    AcmeCertificatePaths, AcmeRenewalTarget, CertificateObservation, MAX_CERTIFICATE_CHAIN_BYTES,
    managed_certificate_segment,
};

const MANAGED_CERTIFICATE_DIR: &str = "certificates";
pub(super) const MANAGED_FULLCHAIN_FILE: &str = "fullchain.pem";
pub(super) const MANAGED_PRIVATE_KEY_FILE: &str = "privkey.pem";

pub fn managed_certificate_paths(storage: &Path, vhost_name: &str) -> AcmeCertificatePaths {
    let directory = storage
        .join(MANAGED_CERTIFICATE_DIR)
        .join(managed_certificate_segment(vhost_name));

    AcmeCertificatePaths {
        cert_path: directory.join(MANAGED_FULLCHAIN_FILE),
        key_path: directory.join(MANAGED_PRIVATE_KEY_FILE),
    }
}

pub fn observe_target_certificate(
    target: &AcmeRenewalTarget,
) -> io::Result<Option<CertificateObservation>> {
    load_certificate_not_after(&target.certificate.cert_path).map(|not_after| {
        not_after.map(|not_after| CertificateObservation {
            vhost_name: target.vhost_name.clone(),
            not_after,
        })
    })
}

pub fn load_certificate_not_after(path: &Path) -> io::Result<Option<SystemTime>> {
    let Some(contents) = read_bounded_certificate_file(path)? else {
        return Ok(None);
    };

    let timestamp = leaf_validity(&contents)?.not_after.timestamp();
    if timestamp < 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "certificate expiration is before the Unix epoch",
        ));
    }

    Ok(Some(UNIX_EPOCH + Duration::from_secs(timestamp as u64)))
}

/// Inspect only the installed leaf's validity interval; never read the key or schedule renewal.
pub fn inspect_managed_leaf_validity(target: &AcmeRenewalTarget) -> io::Result<Option<(i64, i64)>> {
    let file = match fluxheim_config::fs_trust::open_regular_file(&target.certificate.cert_path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let validity = leaf_validity(&read_bounded_open_file(file)?)?;
    let start = validity.not_before.timestamp();
    let end = validity.not_after.timestamp();
    if end < start {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    Ok(Some((start, end)))
}

fn leaf_validity(contents: &[u8]) -> io::Result<x509_parser::certificate::Validity> {
    let (_, pem) = x509_parser::pem::parse_x509_pem(contents).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "certificate file does not contain a valid PEM certificate",
        )
    })?;
    let certificate = pem.parse_x509().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "certificate file does not contain a valid X.509 certificate",
        )
    })?;
    Ok(certificate.validity().clone())
}

pub(super) fn read_bounded_certificate_file(path: &Path) -> io::Result<Option<Vec<u8>>> {
    let file = match open_regular_certificate_file(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    read_bounded_open_file(file).map(Some)
}

fn read_bounded_open_file(file: std::fs::File) -> io::Result<Vec<u8>> {
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "certificate path is not a real file",
        ));
    }
    if metadata.len() > MAX_CERTIFICATE_CHAIN_BYTES as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "certificate file is too large",
        ));
    }
    let mut contents = Vec::with_capacity(metadata.len() as usize);
    file.take((MAX_CERTIFICATE_CHAIN_BYTES as u64).saturating_add(1))
        .read_to_end(&mut contents)?;
    if contents.len() > MAX_CERTIFICATE_CHAIN_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "certificate file is too large",
        ));
    }
    Ok(contents)
}

#[cfg(target_os = "linux")]
fn open_regular_certificate_file(path: &Path) -> io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(UNIX_O_NOFOLLOW)
        .open(path)
}

#[cfg(not(target_os = "linux"))]
fn open_regular_certificate_file(path: &Path) -> io::Result<std::fs::File> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }

    std::fs::File::open(path)
}
