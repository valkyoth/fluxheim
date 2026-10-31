use super::*;
use fluxheim_config::{Config, TlsConfig};
use std::os::unix::fs::{PermissionsExt as _, symlink};

fn private_directory() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix(".tls-contract-")
        .tempdir_in(std::env::current_dir().unwrap().canonicalize().unwrap())
        .unwrap()
}

fn write_pair(directory: &Path) -> (StaticCertificateConfig, Vec<u8>) {
    std::fs::create_dir_all(directory).unwrap();
    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    let material = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let pair = StaticCertificateConfig {
        cert_path: directory.join("cert.pem"),
        key_path: directory.join("key.pem"),
    };
    for (path, contents) in [
        (&pair.cert_path, material.cert.pem()),
        (&pair.key_path, material.signing_key.serialize_pem()),
    ] {
        std::fs::write(path, contents).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    (pair, material.cert.der().to_vec())
}

#[test]
fn unix_reload_currently_accepts_linked_replacement_rejected_by_config() {
    for parent_link in [false, true] {
        let temp = private_directory();
        let root = temp.path().canonicalize().unwrap();
        let (pair, first_der) = write_pair(&root.join("active"));
        let (replacement, second_der) = write_pair(&root.join("replacement"));
        let config = Config {
            tls: TlsConfig {
                enabled: true,
                certificates: vec![pair.clone()],
                ..TlsConfig::default()
            },
            ..Config::default()
        };
        config.tls.validate().unwrap();
        let selector = DownstreamCertificateSelector::from_config(&config).unwrap();
        let resolver = RustlsDownstreamCertificateResolver::new(&selector).unwrap();
        assert_eq!(
            resolver.resolve_static_certificate(None).unwrap().cert[0].as_ref(),
            first_der
        );

        if parent_link {
            std::fs::rename(root.join("active"), root.join("old")).unwrap();
            symlink(root.join("replacement"), root.join("active")).unwrap();
        } else {
            for (active, new) in [
                (&pair.cert_path, &replacement.cert_path),
                (&pair.key_path, &replacement.key_path),
            ] {
                std::fs::remove_file(active).unwrap();
                symlink(new, active).unwrap();
            }
        }
        assert!(
            config.tls.validate().is_err(),
            "configuration must reject links"
        );
        // documented contract: reload reopens paths without the configuration trust checks.
        resolver.reload().unwrap();
        assert_eq!(
            resolver.resolve_static_certificate(None).unwrap().cert[0].as_ref(),
            second_der
        );
    }
}

#[test]
fn unix_reload_currently_accepts_group_writable_parent_drift() {
    let temp = private_directory();
    let root = temp.path().canonicalize().unwrap();
    let (pair, _) = write_pair(&root.join("active"));
    let config = Config {
        tls: TlsConfig {
            enabled: true,
            certificates: vec![pair],
            ..TlsConfig::default()
        },
        ..Config::default()
    };
    config.tls.validate().unwrap();
    let resolver = RustlsDownstreamCertificateResolver::new(
        &DownstreamCertificateSelector::from_config(&config).unwrap(),
    )
    .unwrap();
    std::fs::set_permissions(root.join("active"), std::fs::Permissions::from_mode(0o770)).unwrap();
    assert!(config.tls.validate().is_err());
    resolver.reload().unwrap();
}

#[test]
fn invalid_replacement_keeps_previous_rustls_certificate_generation() {
    let temp = private_directory();
    let (pair, first_der) = write_pair(temp.path());
    let config = Config {
        tls: TlsConfig {
            enabled: true,
            certificates: vec![pair.clone()],
            ..TlsConfig::default()
        },
        ..Config::default()
    };
    let resolver = RustlsDownstreamCertificateResolver::new(
        &DownstreamCertificateSelector::from_config(&config).unwrap(),
    )
    .unwrap();
    std::fs::write(&pair.cert_path, b"not a certificate").unwrap();
    assert!(resolver.reload().is_err());
    assert_eq!(
        resolver.resolve_static_certificate(None).unwrap().cert[0].as_ref(),
        first_der
    );
}
