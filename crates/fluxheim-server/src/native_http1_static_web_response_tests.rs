use std::sync::Arc;
use std::time::{Duration, Instant};

#[cfg(unix)]
use tempfile::TempDir;

use super::native_static_cache_expires_at;
#[cfg(unix)]
use super::open_static_body_file;
use crate::NativeHttp1Response;
use crate::native_http1_cache::{
    NativeMemoryCacheEntry, NativeMemoryCacheState, native_cache_entry_weight,
    prune_native_memory_cache,
};
#[cfg(unix)]
use crate::native_http1_static_web::NativeStaticFile;

#[test]
fn static_cache_entry_weight_includes_entry_overhead() {
    let response =
        NativeHttp1Response::new(200, "OK", b"hello").with_header("cache-control", "max-age=60");
    let raw_bytes = 5_u64 + "cache-control".len() as u64 + "max-age=60".len() as u64 + 4;
    let weight = native_cache_entry_weight("cache-key", &response, 5);
    assert!(weight >= raw_bytes + 256 + "cache-key".len() as u64 + "OK".len() as u64);
}

#[test]
fn static_cache_expiry_rejects_unrepresentable_ttl() {
    assert!(native_static_cache_expires_at(Instant::now(), Duration::MAX).is_none());
}

#[test]
fn prune_static_cache_removes_expired_and_oldest_entries() {
    let now = Instant::now();
    let mut state = NativeMemoryCacheState::default();
    state.objects.insert(
        "expired".to_owned(),
        cache_entry(
            now - Duration::from_secs(30),
            now - Duration::from_secs(1),
            100,
        ),
    );
    state.objects.insert(
        "old".to_owned(),
        cache_entry(
            now - Duration::from_secs(20),
            now + Duration::from_secs(60),
            100,
        ),
    );
    state.objects.insert(
        "new".to_owned(),
        cache_entry(
            now - Duration::from_secs(10),
            now + Duration::from_secs(60),
            100,
        ),
    );
    state.bytes = 300;
    prune_native_memory_cache(&mut state, 150);
    assert!(!state.objects.contains_key("expired"));
    assert!(!state.objects.contains_key("old"));
    assert!(state.objects.contains_key("new"));
    assert_eq!(state.bytes, 100);
}

fn cache_entry(stored_at: Instant, expires_at: Instant, weight: u64) -> NativeMemoryCacheEntry {
    NativeMemoryCacheEntry {
        status: 200,
        reason: "OK".to_owned(),
        headers: Vec::new(),
        content_length: Some(1),
        body: Arc::from(*b"x"),
        body_sha256: Arc::new(crate::native_http1_cache::native_cache_body_sha256(b"x")),
        expires_at,
        stale_while_revalidate_until: None,
        stale_if_error_until: None,
        stale_reuse_forbidden: false,
        stored_at,
        weight,
    }
}

#[cfg(unix)]
#[test]
fn open_static_body_file_rejects_symlink_swapped_after_resolution() {
    use std::time::SystemTime;

    let root = TempDir::new().unwrap();
    let asset = root.path().join("asset.txt");
    let outside = root.path().join("outside.txt");
    std::fs::write(&asset, b"safe").unwrap();
    std::fs::write(&outside, b"outside").unwrap();
    let root_path = root.path().canonicalize().unwrap();
    let file = NativeStaticFile {
        root: root_path.clone(),
        path: root_path.join("asset.txt"),
        mime: "text/plain; charset=utf-8",
        len: 4,
        modified: Some(SystemTime::UNIX_EPOCH),
        device: 0,
        inode: 0,
    };
    std::fs::remove_file(&asset).unwrap();
    std::os::unix::fs::symlink(&outside, &asset).unwrap();
    assert!(open_static_body_file(&file).is_err());
    root.close().unwrap();
}
