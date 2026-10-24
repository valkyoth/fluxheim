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
fn runtime_termination_sites_cannot_bypass_fatal_diagnostics() {
    fn scan(root: &Path, path: &Path) {
        let path = path.canonicalize().unwrap();
        assert!(path.starts_with(root), "source scan escaped repository");
        let text = path.to_str().unwrap();
        assert!(!text.contains(".."), "ambiguous source path");
        for entry in std::fs::read_dir(text).unwrap() {
            let entry = entry.unwrap();
            let kind = entry.file_type().unwrap();
            assert!(
                !kind.is_symlink(),
                "source inventory must not follow symlinks"
            );
            let path = entry.path().canonicalize().unwrap();
            assert!(path.starts_with(root), "source scan escaped repository");
            let text = path.to_str().unwrap();
            assert!(!text.contains(".."), "ambiguous source path");
            if kind.is_dir() {
                if path.file_name().unwrap() != "target" {
                    scan(root, &path);
                }
            } else if path.extension().is_some_and(|ext| ext == "rs")
                && !path.ends_with("fluxheim-common/src/fatal.rs")
            {
                assert!(kind.is_file(), "source inventory requires regular files");
                let source = std::fs::read_to_string(text).unwrap();
                assert!(
                    !source.contains(concat!("process::", "abort(")),
                    "route invariant aborts through the fatal reason vocabulary: {}",
                    path.display()
                );
                let cli_entrypoint = [
                    "src/main.rs",
                    "src/bin/fluxheim-acme.rs",
                    "src/bin/fluxheim-config-tester.rs",
                ]
                .iter()
                .any(|relative| path == root.join(relative));
                assert!(
                    cli_entrypoint || !source.contains(concat!("process::", "exit(")),
                    "runtime exits must use a finite fatal reason: {}",
                    path.display()
                );
            }
        }
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .canonicalize()
        .unwrap();
    scan(&root, &root.join("src"));
    scan(&root, &root.join("crates"));

    let fixture = tempfile::tempdir().unwrap();
    let fixture_root = fixture.path().canonicalize().unwrap();
    let outside = tempfile::tempdir().unwrap();
    assert!(std::panic::catch_unwind(|| scan(&fixture_root, outside.path())).is_err());
    #[cfg(unix)]
    {
        let source = fixture_root.join("source");
        std::fs::create_dir(&source).unwrap();
        for target in [outside.path(), source.as_path()] {
            let link = fixture_root.join("link");
            std::os::unix::fs::symlink(target, &link).unwrap();
            assert!(std::panic::catch_unwind(|| scan(&fixture_root, &fixture_root)).is_err());
            std::fs::remove_file(link).unwrap();
        }
    }
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
    #[cfg(not(target_os = "macos"))]
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        &fifo,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )
    .unwrap();
    #[cfg(target_os = "macos")]
    assert!(
        std::process::Command::new("/usr/bin/mkfifo")
            .args(["-m", "600"])
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    use std::os::unix::fs::FileTypeExt as _;
    assert!(
        std::fs::symlink_metadata(&fifo)
            .unwrap()
            .file_type()
            .is_fifo()
    );
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
