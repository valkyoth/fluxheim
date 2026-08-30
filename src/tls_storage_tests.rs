use std::fs;
use std::path::{Path, PathBuf};

use crate::config::{AcmeConfig, Config, StaticCertificateConfig, TlsConfig};
#[cfg(unix)]
use crate::config::{AcmeExternalAccountBindingConfig, AcmeIssuerConfig};
use fluxheim_common::test_support::{safe_child_path, unique_temp_path};
#[cfg(unix)]
use fluxheim_common::test_support::{unique_group_writable_child, unique_world_writable_child};

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

#[cfg(unix)]
#[test]
fn rejects_symlinked_certificate_files_and_acme_storage() {
    let dir = TestDir::new("tls-storage-symlink");
    let real_cert = dir.file("real-fullchain.pem", 0o644);
    let real_key = dir.file("real-key.pem", recommended_private_key_mode());
    let real_acme = dir.dir("real-acme", recommended_acme_storage_mode());
    let cert = dir.path().join("fullchain.pem");
    let key = dir.path().join("key.pem");
    let acme = dir.path().join("acme");
    std::os::unix::fs::symlink(&real_cert, &cert).unwrap();
    std::os::unix::fs::symlink(&real_key, &key).unwrap();
    std::os::unix::fs::symlink(&real_acme, &acme).unwrap();
    let config = tls_config(cert.clone(), key.clone(), acme.clone());

    let check = validate_tls_storage(&config);

    assert_eq!(
        check.issues,
        vec![
            TlsStorageIssue::CertificatePathIsNotFile {
                scope: "tls.certificates[0]".to_owned(),
                path: cert,
            },
            TlsStorageIssue::PrivateKeyPathIsNotFile {
                scope: "tls.certificates[0]".to_owned(),
                path: key,
            },
            TlsStorageIssue::AcmeStoragePathIsNotDirectory { path: acme },
        ]
    );
}

#[cfg(unix)]
#[test]
fn rejects_tls_storage_below_symlinked_directory() {
    let dir = TestDir::new("tls-storage-parent-symlink");
    let real_dir = dir.dir("real", 0o700);
    let linked_dir = dir.path().join("linked");
    std::os::unix::fs::symlink(&real_dir, &linked_dir).unwrap();
    let cert = linked_dir.join("fullchain.pem");
    let key = linked_dir.join("key.pem");
    let acme = linked_dir.join("acme");
    fs::write(real_dir.join("fullchain.pem"), "test").unwrap();
    fs::write(real_dir.join("key.pem"), "test").unwrap();
    fs::create_dir(real_dir.join("acme")).unwrap();
    set_mode(&real_dir.join("key.pem"), recommended_private_key_mode());
    set_mode(&real_dir.join("acme"), recommended_acme_storage_mode());
    let config = tls_config(cert.clone(), key.clone(), acme.clone());

    let check = validate_tls_storage(&config);

    assert_eq!(
        check.issues,
        vec![
            TlsStorageIssue::CertificatePathIsNotFile {
                scope: "tls.certificates[0]".to_owned(),
                path: cert,
            },
            TlsStorageIssue::PrivateKeyPathIsNotFile {
                scope: "tls.certificates[0]".to_owned(),
                path: key,
            },
            TlsStorageIssue::AcmeStoragePathIsNotDirectory { path: acme },
        ]
    );
}

#[cfg(unix)]
#[test]
fn rejects_tls_storage_below_world_writable_parent() {
    let cert = unique_world_writable_child("tls-world-writable-parent", "fullchain.pem");
    let key = unique_world_writable_child("tls-world-writable-parent-key", "key.pem");
    let acme = unique_world_writable_child("tls-world-writable-parent-acme", "acme");
    let config = tls_config(cert.clone(), key.clone(), acme.clone());

    let check = validate_tls_storage(&config);

    assert_eq!(
        check.issues,
        vec![
            TlsStorageIssue::CertificatePathHasWorldWritableParent {
                scope: "tls.certificates[0]".to_owned(),
                path: cert,
            },
            TlsStorageIssue::PrivateKeyPathHasWorldWritableParent {
                scope: "tls.certificates[0]".to_owned(),
                path: key,
            },
            TlsStorageIssue::AcmeStoragePathHasWorldWritableParent { path: acme },
        ]
    );
}

#[cfg(unix)]
#[test]
fn rejects_tls_storage_below_group_writable_parent() {
    let cert = unique_group_writable_child("tls-group-writable-parent", "fullchain.pem");
    let key = unique_group_writable_child("tls-group-writable-parent-key", "key.pem");
    let acme = unique_group_writable_child("tls-group-writable-parent-acme", "acme");
    let config = tls_config(cert.clone(), key.clone(), acme.clone());

    let check = validate_tls_storage(&config);

    assert_eq!(
        check.issues,
        vec![
            TlsStorageIssue::CertificatePathHasWorldWritableParent {
                scope: "tls.certificates[0]".to_owned(),
                path: cert,
            },
            TlsStorageIssue::PrivateKeyPathHasWorldWritableParent {
                scope: "tls.certificates[0]".to_owned(),
                path: key,
            },
            TlsStorageIssue::AcmeStoragePathHasWorldWritableParent { path: acme },
        ]
    );
}

#[cfg(unix)]
#[test]
fn validates_acme_eab_secret_files() {
    let dir = TestDir::new("tls-storage-eab");
    let cert = dir.file("fullchain.pem", 0o644);
    let key = dir.file("key.pem", recommended_private_key_mode());
    let acme = dir.dir("acme", recommended_acme_storage_mode());
    let key_id = dir.file("key-id", 0o640);
    let real_hmac = dir.file("real-hmac", recommended_private_key_mode());
    let hmac = dir.path().join("hmac");
    std::os::unix::fs::symlink(&real_hmac, &hmac).unwrap();
    let mut config = tls_config(cert, key, acme);
    config.tls.acme.issuers = vec![AcmeIssuerConfig {
        name: "actalis".to_owned(),
        directory_url: "https://acme-api.actalis.com/acme/directory".to_owned(),
        terms_of_service_agreed: false,
        terms_of_service_url: None,
        allow_unadvertised_terms_of_service: false,
        ca_bundle_file: None,
        eab: Some(AcmeExternalAccountBindingConfig {
            key_id_env: None,
            key_id_file: Some(key_id.clone()),
            key_id_credential: None,
            hmac_key_env: None,
            hmac_key_file: Some(hmac.clone()),
            hmac_key_credential: None,
        }),
    }];

    let check = validate_tls_storage(&config);

    assert_eq!(
        check.issues,
        vec![
            TlsStorageIssue::InsecureAcmeEabSecretPermissions {
                issuer: "actalis".to_owned(),
                field: "key_id",
                path: key_id,
                mode: 0o640,
            },
            TlsStorageIssue::AcmeEabSecretPathIsNotFile {
                issuer: "actalis".to_owned(),
                field: "hmac_key",
                path: hmac,
            },
        ]
    );
}

#[cfg(unix)]
#[test]
fn rejects_acme_eab_secret_below_world_writable_parent() {
    let dir = TestDir::new("tls-storage-eab-world-writable");
    let cert = dir.file("fullchain.pem", 0o644);
    let key = dir.file("key.pem", recommended_private_key_mode());
    let acme = dir.dir("acme", recommended_acme_storage_mode());
    let key_id = unique_world_writable_child("tls-eab-kid", "key-id");
    let mut config = tls_config(cert, key, acme);
    config.tls.acme.issuers = vec![AcmeIssuerConfig {
        name: "actalis".to_owned(),
        directory_url: "https://acme-api.actalis.com/acme/directory".to_owned(),
        terms_of_service_agreed: false,
        terms_of_service_url: None,
        allow_unadvertised_terms_of_service: false,
        ca_bundle_file: None,
        eab: Some(AcmeExternalAccountBindingConfig {
            key_id_env: None,
            key_id_file: Some(key_id.clone()),
            key_id_credential: None,
            hmac_key_env: Some("FLUXHEIM_ACTALIS_EAB_HMAC_KEY".to_owned()),
            hmac_key_file: None,
            hmac_key_credential: None,
        }),
    }];

    let check = validate_tls_storage(&config);

    assert_eq!(
        check.issues,
        vec![TlsStorageIssue::AcmeEabSecretPathHasWorldWritableParent {
            issuer: "actalis".to_owned(),
            field: "key_id",
            path: key_id,
        }]
    );
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
    let path = PathBuf::from("target/fluxheim-test-tmp/key.pem");
    let issue = TlsStorageIssue::InsecurePrivateKeyPermissions {
        scope: "tls.certificates[0]".to_owned(),
        path: path.clone(),
        mode: 0o640,
    };

    assert_eq!(
        issue.to_string(),
        format!(
            "tls.certificates[0].key_path {} has insecure mode 640; use 600",
            path.display()
        )
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
        let path = unique_temp_path(name);
        fs::create_dir(&path).expect("create test directory");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn file(&self, name: &str, mode: u32) -> PathBuf {
        let path = safe_child_path(&self.path, name);
        fs::write(&path, "test").expect("write test file");
        set_mode(&path, mode);
        path
    }

    fn dir(&self, name: &str, mode: u32) -> PathBuf {
        let path = safe_child_path(&self.path, name);
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
