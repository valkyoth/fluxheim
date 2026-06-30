use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;

use crate::object::{
    DISK_CACHE_MAGIC_V5, DiskCacheEntry, DiskCacheObjectKey, DiskObjectIndex, DiskObjectLruKey,
    FluxCacheMissFinish, FluxCachePurgeType, SerializedCacheObject, disk_cache_header_overhead,
    encode_disk_cache_object, parse_disk_cache_object,
};

#[test]
fn cache_storage_interface_enums_are_stable() {
    assert_eq!(FluxCachePurgeType::Eviction, FluxCachePurgeType::Eviction);
    assert_eq!(
        FluxCacheMissFinish::Appended(10, Some(128)),
        FluxCacheMissFinish::Appended(10, Some(128))
    );
}

#[test]
fn serialized_cache_object_preserves_storage_envelope() {
    let object = SerializedCacheObject {
        combined_key: Some("combined".to_owned()),
        primary_key: Some("primary".to_owned()),
        user_tag: Some("tag".to_owned()),
        index_path: Some("/asset.png".to_owned()),
        cache_tags: vec!["asset".to_owned()],
        internal_meta: vec![1, 2],
        response_header: vec![3, 4],
        body: Arc::from([5_u8, 6].as_slice()),
        weight: 6,
    };

    assert_eq!(object.combined_key.as_deref(), Some("combined"));
    assert_eq!(object.primary_key.as_deref(), Some("primary"));
    assert_eq!(object.user_tag.as_deref(), Some("tag"));
    assert_eq!(object.index_path.as_deref(), Some("/asset.png"));
    assert_eq!(object.cache_tags, ["asset"]);
    assert_eq!(object.internal_meta, [1, 2]);
    assert_eq!(object.response_header, [3, 4]);
    assert_eq!(object.body.as_ref(), [5, 6]);
    assert_eq!(object.weight, 6);
}

#[test]
fn disk_cache_object_envelope_round_trips_v5_fields() {
    let key = DiskCacheObjectKey {
        combined: "combined-key".to_owned(),
        primary: "primary-key".to_owned(),
        user_tag: "vhost".to_owned(),
        index_path: Some("/asset.png".to_owned()),
        cache_tags: vec!["asset".to_owned(), "blue".to_owned()],
    };
    let internal_meta = b"internal";
    let response_header = b"headers";
    let body = b"body";

    let encoded = encode_disk_cache_object(&key, internal_meta, response_header, body).unwrap();
    let parsed =
        parse_disk_cache_object(&encoded, fluxheim_config::ByteSize::from_bytes(1024)).unwrap();

    assert!((disk_cache_header_overhead(&key) as usize) > DISK_CACHE_MAGIC_V5.len());
    assert!((disk_cache_header_overhead(&key) as usize) < encoded.len() - body.len());
    assert_eq!(parsed.combined_key.as_deref(), Some("combined-key"));
    assert_eq!(parsed.primary_key.as_deref(), Some("primary-key"));
    assert_eq!(parsed.user_tag.as_deref(), Some("vhost"));
    assert_eq!(parsed.index_path.as_deref(), Some("/asset.png"));
    assert_eq!(parsed.cache_tags, ["asset", "blue"]);
    assert_eq!(parsed.internal_meta, internal_meta);
    assert_eq!(parsed.response_header, response_header);
    assert_eq!(parsed.body.as_ref(), body);
}

#[test]
fn disk_object_lru_key_matches_entry_ordering_fields() {
    let modified = SystemTime::UNIX_EPOCH;
    let accessed = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(5);
    let entry = DiskCacheEntry {
        combined_key: Some("combined".to_owned()),
        path: PathBuf::from("/cache/object"),
        size: 42,
        modified,
        accessed,
    };

    let key = DiskObjectLruKey::from_entry(&entry);

    assert_eq!(key.accessed, accessed);
    assert_eq!(key.modified, modified);
    assert_eq!(key.path, PathBuf::from("/cache/object"));
}

#[test]
fn disk_object_index_tracks_size_and_lru_eviction_candidates() {
    let first_path = PathBuf::from("/cache/first");
    let second_path = PathBuf::from("/cache/second");
    let index = DiskObjectIndex::new();
    index.upsert(DiskCacheEntry {
        combined_key: Some("first".to_owned()),
        path: first_path.clone(),
        size: 10,
        modified: SystemTime::UNIX_EPOCH,
        accessed: SystemTime::UNIX_EPOCH,
    });
    index.upsert(DiskCacheEntry {
        combined_key: Some("second".to_owned()),
        path: second_path.clone(),
        size: 20,
        modified: SystemTime::UNIX_EPOCH,
        accessed: SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1),
    });

    assert_eq!(index.stats(), (2, 30));
    assert_eq!(
        index
            .oldest_entries_to_free(&PathBuf::from("/cache/ignored"), 1)
            .first()
            .and_then(|entry| entry.combined_key.as_deref()),
        Some("first")
    );

    index.touch(
        &first_path,
        SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(2),
    );
    assert_eq!(
        index
            .oldest_entries_to_free(&PathBuf::from("/cache/ignored"), 1)
            .first()
            .and_then(|entry| entry.combined_key.as_deref()),
        Some("second")
    );
    assert_eq!(index.remove(&second_path).map(|entry| entry.size), Some(20));
    assert_eq!(index.stats(), (1, 10));
}
