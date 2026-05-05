use std::fmt::{Display, Formatter};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::config::{AcmeConfig, Config, StaticCertificateConfig};

pub const PRIVATE_KEY_MODE: u32 = 0o600;
pub const ACME_STORAGE_MODE: u32 = 0o700;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TlsStorageCheck {
    pub issues: Vec<TlsStorageIssue>,
}

impl TlsStorageCheck {
    pub fn is_secure(&self) -> bool {
        self.issues.is_empty()
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum TlsStorageIssue {
    CertificateReadFailed {
        scope: String,
        path: PathBuf,
        message: String,
    },
    CertificatePathIsNotFile {
        scope: String,
        path: PathBuf,
    },
    PrivateKeyReadFailed {
        scope: String,
        path: PathBuf,
        message: String,
    },
    PrivateKeyPathIsNotFile {
        scope: String,
        path: PathBuf,
    },
    InsecurePrivateKeyPermissions {
        scope: String,
        path: PathBuf,
        mode: u32,
    },
    AcmeStorageReadFailed {
        path: PathBuf,
        message: String,
    },
    AcmeStoragePathIsNotDirectory {
        path: PathBuf,
    },
    InsecureAcmeStoragePermissions {
        path: PathBuf,
        mode: u32,
    },
}

impl Display for TlsStorageIssue {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CertificateReadFailed {
                scope,
                path,
                message,
            } => write!(
                formatter,
                "{scope}.cert_path {} cannot be read: {message}",
                path.display()
            ),
            Self::CertificatePathIsNotFile { scope, path } => write!(
                formatter,
                "{scope}.cert_path {} is not a regular file",
                path.display()
            ),
            Self::PrivateKeyReadFailed {
                scope,
                path,
                message,
            } => write!(
                formatter,
                "{scope}.key_path {} cannot be read: {message}",
                path.display()
            ),
            Self::PrivateKeyPathIsNotFile { scope, path } => write!(
                formatter,
                "{scope}.key_path {} is not a regular file",
                path.display()
            ),
            Self::InsecurePrivateKeyPermissions { scope, path, mode } => write!(
                formatter,
                "{scope}.key_path {} has insecure mode {mode:o}; use {:o}",
                path.display(),
                PRIVATE_KEY_MODE
            ),
            Self::AcmeStorageReadFailed { path, message } => write!(
                formatter,
                "tls.acme.storage {} cannot be read: {message}",
                path.display()
            ),
            Self::AcmeStoragePathIsNotDirectory { path } => write!(
                formatter,
                "tls.acme.storage {} is not a directory",
                path.display()
            ),
            Self::InsecureAcmeStoragePermissions { path, mode } => write!(
                formatter,
                "tls.acme.storage {} has insecure mode {mode:o}; use {:o}",
                path.display(),
                ACME_STORAGE_MODE
            ),
        }
    }
}

pub fn validate_tls_storage(config: &Config) -> TlsStorageCheck {
    let mut issues = Vec::new();

    for (index, certificate) in config.tls.certificates.iter().enumerate() {
        validate_static_certificate_storage(
            &format!("tls.certificates[{index}]"),
            certificate,
            &mut issues,
        );
    }

    for vhost in &config.vhosts {
        if let Some(certificate) = &vhost.tls.certificate {
            validate_static_certificate_storage(
                &format!("vhosts.{}.tls.certificate", vhost.name),
                certificate,
                &mut issues,
            );
        }
    }

    validate_acme_storage(&config.tls.acme, &mut issues);

    TlsStorageCheck { issues }
}

pub fn secure_private_key_mode(mode: u32) -> bool {
    mode & 0o077 == 0
}

pub fn secure_acme_storage_mode(mode: u32) -> bool {
    mode & 0o077 == 0
}

pub fn recommended_private_key_mode() -> u32 {
    PRIVATE_KEY_MODE
}

pub fn recommended_acme_storage_mode() -> u32 {
    ACME_STORAGE_MODE
}

pub fn default_downstream_certificate(config: &Config) -> Option<&StaticCertificateConfig> {
    config.tls.certificates.first()
}

fn validate_static_certificate_storage(
    scope: &str,
    certificate: &StaticCertificateConfig,
    issues: &mut Vec<TlsStorageIssue>,
) {
    match fs::metadata(&certificate.cert_path) {
        Ok(metadata) if !metadata.is_file() => {
            issues.push(TlsStorageIssue::CertificatePathIsNotFile {
                scope: scope.to_owned(),
                path: certificate.cert_path.clone(),
            })
        }
        Ok(_) => {}
        Err(error) => issues.push(TlsStorageIssue::CertificateReadFailed {
            scope: scope.to_owned(),
            path: certificate.cert_path.clone(),
            message: error_message(error),
        }),
    }

    match fs::metadata(&certificate.key_path) {
        Ok(metadata) if !metadata.is_file() => {
            issues.push(TlsStorageIssue::PrivateKeyPathIsNotFile {
                scope: scope.to_owned(),
                path: certificate.key_path.clone(),
            })
        }
        Ok(metadata) => validate_key_permissions(scope, &certificate.key_path, &metadata, issues),
        Err(error) => issues.push(TlsStorageIssue::PrivateKeyReadFailed {
            scope: scope.to_owned(),
            path: certificate.key_path.clone(),
            message: error_message(error),
        }),
    }
}

fn validate_acme_storage(acme: &AcmeConfig, issues: &mut Vec<TlsStorageIssue>) {
    if !acme.enabled {
        return;
    }

    let Some(path) = &acme.storage else {
        return;
    };

    match fs::metadata(path) {
        Ok(metadata) if !metadata.is_dir() => {
            issues.push(TlsStorageIssue::AcmeStoragePathIsNotDirectory { path: path.clone() })
        }
        Ok(metadata) => validate_acme_storage_permissions(path, &metadata, issues),
        Err(error) => issues.push(TlsStorageIssue::AcmeStorageReadFailed {
            path: path.clone(),
            message: error_message(error),
        }),
    }
}

#[cfg(unix)]
fn validate_key_permissions(
    scope: &str,
    path: &Path,
    metadata: &fs::Metadata,
    issues: &mut Vec<TlsStorageIssue>,
) {
    use std::os::unix::fs::PermissionsExt;

    let mode = metadata.permissions().mode() & 0o777;
    if !secure_private_key_mode(mode) {
        issues.push(TlsStorageIssue::InsecurePrivateKeyPermissions {
            scope: scope.to_owned(),
            path: path.to_path_buf(),
            mode,
        });
    }
}

#[cfg(not(unix))]
fn validate_key_permissions(
    _scope: &str,
    _path: &Path,
    _metadata: &fs::Metadata,
    _issues: &mut Vec<TlsStorageIssue>,
) {
}

#[cfg(unix)]
fn validate_acme_storage_permissions(
    path: &Path,
    metadata: &fs::Metadata,
    issues: &mut Vec<TlsStorageIssue>,
) {
    use std::os::unix::fs::PermissionsExt;

    let mode = metadata.permissions().mode() & 0o777;
    if !secure_acme_storage_mode(mode) {
        issues.push(TlsStorageIssue::InsecureAcmeStoragePermissions {
            path: path.to_path_buf(),
            mode,
        });
    }
}

#[cfg(not(unix))]
fn validate_acme_storage_permissions(
    _path: &Path,
    _metadata: &fs::Metadata,
    _issues: &mut Vec<TlsStorageIssue>,
) {
}

fn error_message(error: io::Error) -> String {
    error.to_string()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::config::{AcmeConfig, Config, StaticCertificateConfig, TlsConfig};

    use super::{
        TlsStorageIssue, recommended_acme_storage_mode, recommended_private_key_mode,
        secure_acme_storage_mode, secure_private_key_mode, validate_tls_storage,
    };

    #[test]
    fn accepts_owner_only_private_key_and_acme_storage() {
        let dir = TestDir::new("tls-storage-secure");
        let cert = dir.file("fullchain.pem", 0o644);
        let key = dir.file("key.pem", recommended_private_key_mode());
        let acme = dir.dir("acme", recommended_acme_storage_mode());
        let config = tls_config(cert, key, acme);

        let check = validate_tls_storage(&config);

        assert_eq!(check.issues, Vec::new());
        assert!(check.is_secure());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_group_readable_private_key() {
        let dir = TestDir::new("tls-storage-key-mode");
        let cert = dir.file("fullchain.pem", 0o644);
        let key = dir.file("key.pem", 0o640);
        let acme = dir.dir("acme", recommended_acme_storage_mode());
        let config = tls_config(cert, key.clone(), acme);

        let check = validate_tls_storage(&config);

        assert_eq!(
            check.issues,
            vec![TlsStorageIssue::InsecurePrivateKeyPermissions {
                scope: "tls.certificates[0]".to_owned(),
                path: key,
                mode: 0o640
            }]
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_world_accessible_acme_storage() {
        let dir = TestDir::new("tls-storage-acme-mode");
        let cert = dir.file("fullchain.pem", 0o644);
        let key = dir.file("key.pem", recommended_private_key_mode());
        let acme = dir.dir("acme", 0o755);
        let config = tls_config(cert, key, acme.clone());

        let check = validate_tls_storage(&config);

        assert_eq!(
            check.issues,
            vec![TlsStorageIssue::InsecureAcmeStoragePermissions {
                path: acme,
                mode: 0o755
            }]
        );
    }

    #[test]
    fn reports_missing_certificate_files() {
        let dir = TestDir::new("tls-storage-missing");
        let cert = dir.path().join("missing-fullchain.pem");
        let key = dir.path().join("missing-key.pem");
        let acme = dir.dir("acme", recommended_acme_storage_mode());
        let config = tls_config(cert.clone(), key.clone(), acme);

        let check = validate_tls_storage(&config);

        assert!(matches!(
            &check.issues[0],
            TlsStorageIssue::CertificateReadFailed { path, .. } if path == &cert
        ));
        assert!(matches!(
            &check.issues[1],
            TlsStorageIssue::PrivateKeyReadFailed { path, .. } if path == &key
        ));
    }

    #[test]
    fn permission_predicates_allow_only_owner_access() {
        assert!(secure_private_key_mode(0o600));
        assert!(secure_private_key_mode(0o400));
        assert!(!secure_private_key_mode(0o640));
        assert!(secure_acme_storage_mode(0o700));
        assert!(secure_acme_storage_mode(0o500));
        assert!(!secure_acme_storage_mode(0o750));
    }

    #[test]
    fn formats_storage_issues_for_cli_output() {
        let issue = TlsStorageIssue::InsecurePrivateKeyPermissions {
            scope: "tls.certificates[0]".to_owned(),
            path: PathBuf::from("/tmp/key.pem"),
            mode: 0o640,
        };

        assert_eq!(
            issue.to_string(),
            "tls.certificates[0].key_path /tmp/key.pem has insecure mode 640; use 600"
        );
    }

    fn tls_config(cert_path: PathBuf, key_path: PathBuf, acme_storage: PathBuf) -> Config {
        Config {
            tls: TlsConfig {
                enabled: true,
                certificates: vec![StaticCertificateConfig {
                    cert_path,
                    key_path,
                }],
                acme: AcmeConfig {
                    enabled: true,
                    storage: Some(acme_storage),
                    ..AcmeConfig::default()
                },
                ..TlsConfig::default()
            },
            ..Config::default()
        }
    }

    struct TestDir {
        path: PathBuf,
    }

    impl TestDir {
        fn new(name: &str) -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock after Unix epoch")
                .as_nanos();
            let path = std::env::temp_dir().join(format!("fluxheim-{name}-{nonce}"));
            fs::create_dir(&path).expect("create test directory");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }

        fn file(&self, name: &str, mode: u32) -> PathBuf {
            let path = self.path.join(name);
            fs::write(&path, "test").expect("write test file");
            set_mode(&path, mode);
            path
        }

        fn dir(&self, name: &str, mode: u32) -> PathBuf {
            let path = self.path.join(name);
            fs::create_dir(&path).expect("create child directory");
            set_mode(&path, mode);
            path
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[cfg(unix)]
    fn set_mode(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("set mode");
    }

    #[cfg(not(unix))]
    fn set_mode(_path: &Path, _mode: u32) {}
}
