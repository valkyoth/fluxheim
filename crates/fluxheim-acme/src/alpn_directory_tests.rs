use super::*;
use std::fs;
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _, symlink};

fn private_dir(path: &Path) {
    fs::DirBuilder::new().mode(0o700).create(path).unwrap();
}

fn rejected(storage: &Path) -> io::Error {
    Broker::bind(storage, Arc::new(|_, _| unreachable!()))
        .err()
        .expect("broker accepted untrusted storage")
}

#[test]
fn existing_permissions_are_rejected_without_repair_or_lock_creation() {
    let storage = fluxheim_common::test_support::unique_temp_path("alpn-policy");
    private_dir(&storage);
    let dir = storage.join(".alpn");
    for mode in [0o750, 0o770] {
        fs::set_permissions(&storage, fs::Permissions::from_mode(mode)).unwrap();
        assert_eq!(rejected(&storage).kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(fs::metadata(&storage).unwrap().mode() & 0o777, mode);
        assert!(!dir.exists());
    }
    fs::set_permissions(&storage, fs::Permissions::from_mode(0o700)).unwrap();
    private_dir(&dir);
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(rejected(&storage).kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(fs::metadata(&dir).unwrap().mode() & 0o777, 0o755);
    assert_eq!(fs::read_dir(&dir).unwrap().count(), 0);
    fs::remove_dir_all(storage).unwrap();
}

#[test]
fn neither_bind_nor_probe_follows_aliases_or_creates_below_untrusted_parents() {
    let root = fluxheim_common::test_support::unique_temp_path("alpn-parents");
    private_dir(&root);
    let real = root.join("real");
    private_dir(&real);
    let alias = root.join("alias");
    symlink(&real, &alias).unwrap();
    for path in [&alias, &alias.join("child")] {
        rejected(path);
    }
    symlink(&real, real.join(".alpn")).unwrap();
    rejected(&real);
    assert!(real.join(".alpn").is_symlink());
    assert!(!real.join("s").exists());
    assert!(!real.join("child").exists());
    fs::set_permissions(&root, fs::Permissions::from_mode(0o770)).unwrap();
    let missing = root.join("missing");
    assert_eq!(rejected(&missing).kind(), io::ErrorKind::PermissionDenied);
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    assert_eq!(
        rt.block_on(probe(&missing)).unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
    assert!(!missing.exists());
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[ignore = "requires root in a disposable user namespace with a second mapped UID"]
fn root_broker_refuses_foreign_owner_without_modifying_storage() {
    assert!(rustix::process::geteuid().is_root());
    let uid = rustix::fs::Uid::from_raw(65534);
    let storage = fluxheim_common::test_support::unique_temp_path("alpn-ownership");
    private_dir(&storage);
    rustix::fs::chown(&storage, Some(uid), None).unwrap();
    assert_eq!(rejected(&storage).kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(fs::metadata(&storage).unwrap().uid(), uid.as_raw());
    assert_eq!(fs::read_dir(&storage).unwrap().count(), 0);
    let nested = storage.join("missing");
    assert_eq!(rejected(&nested).kind(), io::ErrorKind::PermissionDenied);
    assert!(!nested.exists());
    rustix::fs::chown(&storage, Some(rustix::process::geteuid()), None).unwrap();
    let dir = storage.join(".alpn");
    private_dir(&dir);
    rustix::fs::chown(&dir, Some(uid), None).unwrap();
    assert_eq!(rejected(&storage).kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(fs::metadata(&dir).unwrap().uid(), uid.as_raw());
    assert_eq!(fs::read_dir(&dir).unwrap().count(), 0);
    fs::remove_dir_all(storage).unwrap();
}
