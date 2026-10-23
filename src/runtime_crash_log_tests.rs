use super::*;
use std::io::Write as _;

fn path() -> std::path::PathBuf {
    fluxheim_common::test_support::unique_temp_path("crash-log")
}

#[test]
fn private_crash_file_is_not_truncated_and_rejects_aliases() {
    let path = path();
    let mut file = open(&path).unwrap();
    file.write_all(b"previous diagnostic\n").unwrap();
    drop(file);
    let file = open(&path).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"previous diagnostic\n");
    let alias = path.with_extension("alias");
    std::fs::hard_link(&path, &alias).unwrap();
    let alias_file = open(&alias).unwrap();
    assert!(require_distinct(&file, &alias_file).is_err());
    let other_path = path.with_extension("other");
    let other = open(&other_path).unwrap();
    require_distinct(&file, &other).unwrap();
    drop((file, alias_file, other));
    for p in [&path, &alias, &other_path] {
        std::fs::remove_file(p).unwrap();
    }
}

#[test]
fn crash_file_rejects_directories_and_missing_parents() {
    let path = path();
    assert!(open(&path.join("absent")).is_err());
    std::fs::create_dir(&path).unwrap();
    assert!(open(&path).is_err());
    std::fs::remove_dir(path).unwrap();
}

#[test]
fn unsafe_crash_file_fails_startup_before_workers_are_installed() {
    let path = path();
    let mut config = crate::config::Config::default();
    config.logging.crash_file = Some(path.join("no-parent"));
    assert!(super::super::init_logging(&config).is_err());
    assert!(super::super::status().is_none());
    assert!(fluxheim_observability::operational::status().is_none());
}

#[test]
fn runtime_abort_sites_cannot_bypass_fatal_diagnostics() {
    fn scan(path: &Path) {
        for entry in std::fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                if path.file_name().unwrap() != "target" {
                    scan(&path);
                }
            } else if path.extension().is_some_and(|ext| ext == "rs")
                && !path.ends_with("fluxheim-common/src/fatal.rs")
            {
                let source = std::fs::read_to_string(&path).unwrap();
                assert!(
                    !source.contains(concat!("process::", "abort(")),
                    "route invariant aborts through the fatal reason vocabulary: {}",
                    path.display()
                );
            }
        }
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    scan(&root.join("src"));
    scan(&root.join("crates"));
}

#[test]
#[cfg(not(feature = "privacy-mode"))]
fn aliased_sink_fails_startup_without_truncating_crash_file() {
    let path = path();
    let mut file = open(&path).unwrap();
    file.write_all(b"keep diagnostic\n").unwrap();
    drop(file);
    let mut config = crate::config::Config::default();
    config.logging.crash_file = Some(path.clone());
    config.logging.file.enabled = true;
    config.logging.file.append = false;
    config.logging.file.path = Some(path.clone());
    let error = super::super::init_logging(&config).err().unwrap();
    assert!(error.to_string().contains("separate"), "{error}");
    assert_eq!(std::fs::read(&path).unwrap(), b"keep diagnostic\n");
    assert!(super::super::status().is_none());
    std::fs::remove_file(path).unwrap();
}

#[cfg(feature = "privacy-mode")]
#[test]
fn privacy_crash_sink_is_refused_before_file_creation() {
    let path = path();
    let mut config = crate::config::Config::default();
    config.logging.crash_file = Some(path.clone());
    let error = super::super::init_logging(&config).err().unwrap();
    assert!(error.to_string().contains("privacy mode"));
    assert!(!path.exists());
    assert!(super::super::status().is_none());
}

#[cfg(unix)]
#[test]
fn crash_file_rejects_public_permissions_symlinks_and_fifo_without_blocking() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    let path = path();
    let file = open(&path).unwrap();
    assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
    drop(file);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(open(&path).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let link = path.with_extension("link");
    symlink(&path, &link).unwrap();
    assert!(open(&link).is_err());
    let fifo = path.with_extension("fifo");
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        &fifo,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )
    .unwrap();
    assert!(open(&fifo).is_err());
    let untrusted =
        fluxheim_common::test_support::unique_world_writable_child("crash-parent", "fatal.log");
    assert!(open(&untrusted).is_err());
    assert!(!untrusted.exists());
    for p in [&path, &link, &fifo] {
        std::fs::remove_file(p).unwrap();
    }
    std::fs::remove_dir(untrusted.parent().unwrap()).unwrap();
}
