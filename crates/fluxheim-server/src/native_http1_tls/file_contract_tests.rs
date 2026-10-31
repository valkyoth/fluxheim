use super::*;
use std::os::unix::fs::{PermissionsExt as _, symlink};

fn fixture() -> (tempfile::TempDir, fluxheim_config::Config) {
    let root = tempfile::Builder::new()
        .prefix(".upstream-trust-")
        .tempdir_in(std::env::current_dir().unwrap().canonicalize().unwrap())
        .unwrap();
    let parent = root.path().join("active");
    std::fs::create_dir(&parent).unwrap();
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = parent.join("ca.pem");
    std::fs::write(&path, b"original trust input").unwrap();
    let mut config = fluxheim_config::Config::default();
    config.proxy.upstream = Some("127.0.0.1:9443".into());
    config.proxy.upstream_tls = true;
    config.proxy.upstream_sni = Some("origin.example.test".into());
    config.proxy.upstream_ca_path = Some(path);
    config.proxy.validate().unwrap();
    (root, config)
}

#[test]
fn upstream_reader_currently_follows_parent_link_rejected_by_config() {
    let (root, config) = fixture();
    let active = root.path().join("active");
    let replacement = root.path().join("replacement");
    std::fs::create_dir(&replacement).unwrap();
    std::fs::write(replacement.join("ca.pem"), b"replacement trust input").unwrap();
    std::fs::rename(&active, root.path().join("old")).unwrap();
    symlink(&replacement, &active).unwrap();
    assert!(config.proxy.validate().is_err());
    // documented contract: canonicalizing the parent hides the rejected link.
    assert_eq!(
        read_upstream_tls_file(config.proxy.upstream_ca_path.as_deref().unwrap()).unwrap(),
        b"replacement trust input"
    );
}

#[test]
fn upstream_reader_currently_accepts_parent_permission_drift() {
    let (root, config) = fixture();
    std::fs::set_permissions(
        root.path().join("active"),
        std::fs::Permissions::from_mode(0o770),
    )
    .unwrap();
    assert!(config.proxy.validate().is_err());
    assert_eq!(
        read_upstream_tls_file(config.proxy.upstream_ca_path.as_deref().unwrap()).unwrap(),
        b"original trust input"
    );
}
