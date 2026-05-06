use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEST_PATH: AtomicU64 = AtomicU64::new(0);

pub(crate) fn unique_temp_path(label: &str) -> PathBuf {
    assert_safe_label(label);
    std::env::temp_dir().join(format!(
        "fluxheim-test-{}-{}",
        std::process::id(),
        NEXT_TEST_PATH.fetch_add(1, Ordering::Relaxed)
    ))
}

pub(crate) fn safe_child_path(base: &Path, name: &str) -> PathBuf {
    assert_safe_label(name);
    base.join(name)
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
    use super::{safe_child_path, unique_temp_path};

    #[test]
    fn unique_temp_path_does_not_embed_label() {
        let path = unique_temp_path("example-label");
        assert!(!path.display().to_string().contains("example-label"));
    }

    #[test]
    #[should_panic(expected = "single ASCII-safe path component")]
    fn rejects_unsafe_labels() {
        let _ = safe_child_path(std::path::Path::new("/tmp"), "../escape");
    }
}
