#![allow(clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEST_PATH: AtomicU64 = AtomicU64::new(0);

pub fn unique_temp_path(label: &str) -> PathBuf {
    assert_safe_label(label);
    let root = test_root();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_nanos();
    safe_relative_path(
        &root,
        &format!(
            "fluxheim-test-{}-{}-{}",
            std::process::id(),
            nanos,
            NEXT_TEST_PATH.fetch_add(1, Ordering::Relaxed)
        ),
    )
}

pub fn test_root() -> PathBuf {
    let root = PathBuf::from("target/fluxheim-test-tmp");
    std::fs::create_dir_all(&root).expect("create repository-local test root");
    root.canonicalize()
        .expect("canonicalize repository-local test root")
}

pub fn safe_child_path(base: &Path, name: &str) -> PathBuf {
    assert_safe_label(name);
    base.join(name)
}

pub fn safe_relative_path(base: &Path, relative: &str) -> PathBuf {
    assert!(!relative.is_empty(), "test relative path cannot be empty");
    assert!(
        !relative.starts_with('/') && !relative.starts_with('\\'),
        "test relative path must stay relative: {relative:?}"
    );
    let mut path = base.to_path_buf();
    for component in relative.split('/') {
        assert_safe_label(component);
        path.push(component);
    }
    path
}

#[cfg(unix)]
pub fn unique_world_writable_child(label: &str, child: &str) -> PathBuf {
    let parent = unique_temp_path(label);
    std::fs::create_dir_all(&parent).expect("create world-writable test parent");
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o777))
        .expect("mark test parent world-writable");
    safe_relative_path(&parent, child)
}

#[cfg(unix)]
pub fn unique_group_writable_child(label: &str, child: &str) -> PathBuf {
    let parent = unique_temp_path(label);
    std::fs::create_dir_all(&parent).expect("create group-writable test parent");
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o770))
        .expect("mark test parent group-writable");
    safe_relative_path(&parent, child)
}

fn assert_safe_label(label: &str) {
    assert!(!label.is_empty(), "test path label cannot be empty");
    assert!(
        label.len() <= 128,
        "test path label is too long: {} bytes",
        label.len()
    );
    assert!(
        label
            .bytes()
            .all(|byte| { byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-') }),
        "test path label must be a single ASCII-safe path component: {label:?}"
    );
    assert!(
        !label.contains(".."),
        "test path label must not contain parent-directory markers: {label:?}"
    );
}

#[cfg(test)]
mod tests {
    use super::{safe_child_path, safe_relative_path, unique_temp_path};

    #[test]
    fn unique_temp_path_does_not_embed_label() {
        let path = unique_temp_path("example-label");
        assert!(!path.display().to_string().contains("example-label"));
    }

    #[test]
    fn safe_relative_path_allows_nested_safe_components() {
        let path = safe_relative_path(
            std::path::Path::new("target/fluxheim-test-tmp"),
            "logs/fluxheim.log",
        );
        assert_eq!(
            path,
            std::path::Path::new("target/fluxheim-test-tmp/logs/fluxheim.log")
        );
    }

    #[test]
    #[should_panic(expected = "single ASCII-safe path component")]
    fn rejects_unsafe_labels() {
        let _ = safe_child_path(
            std::path::Path::new("target/fluxheim-test-tmp"),
            "../escape",
        );
    }
}
