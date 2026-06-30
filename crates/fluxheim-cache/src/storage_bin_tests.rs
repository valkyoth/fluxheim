use std::time::SystemTime;

use fluxheim_config::{
    ByteSize, CacheDiskBackend, CacheDiskEncryptionConfig, CacheDiskStorageBinConfig,
};

use crate::DiskTierPlan;
use crate::storage_bin::{
    STORAGE_BIN_DATA_DIR, STORAGE_BIN_MANIFEST_FILENAME, StorageBinFileSet, StorageBinFreeMap,
    StorageBinFreeRange, StorageBinIndexEntry, StorageBinLayoutPlan, StorageBinManifest,
    StorageBinObjectLocation, prepare_storage_bin_layout, read_storage_bin_index,
    storage_bin_index_path, write_storage_bin_index,
};

fn storage_bin_plan() -> DiskTierPlan {
    DiskTierPlan {
        path: std::path::PathBuf::from("/tmp/cache"),
        max_size_bytes: ByteSize::from_bytes(128),
        max_object_bytes: ByteSize::from_bytes(64),
        backend: CacheDiskBackend::StorageBin,
        storage_bin: CacheDiskStorageBinConfig {
            bin_size_bytes: ByteSize::from_bytes(32),
            preallocate: false,
            max_open_bins: 4,
        },
        encryption: CacheDiskEncryptionConfig::default(),
        cache_tag_headers: Vec::new(),
    }
}

#[test]
fn storage_bin_manifest_round_trips() {
    let manifest = StorageBinManifest {
        bin_size_bytes: ByteSize::from_bytes(64),
        max_size_bytes: ByteSize::from_bytes(512),
        preallocate: true,
        max_open_bins: 8,
    };

    let decoded = StorageBinManifest::decode(&manifest.encode()).unwrap();

    assert_eq!(decoded, manifest);
}

#[test]
fn storage_bin_free_map_allocates_and_reuses_ranges() {
    let layout = StorageBinLayoutPlan::from_disk_plan(&storage_bin_plan()).unwrap();
    let mut free_map = StorageBinFreeMap::new(&layout);

    let first = free_map.allocate(16).unwrap().unwrap();
    let second = free_map.allocate(8).unwrap().unwrap();

    assert_eq!(
        first,
        StorageBinObjectLocation {
            bin_id: 0,
            offset: 0,
            len: 16
        }
    );
    assert_eq!(
        second,
        StorageBinObjectLocation {
            bin_id: 0,
            offset: 16,
            len: 8
        }
    );
    assert_eq!(
        free_map.free_ranges(0),
        &[StorageBinFreeRange { offset: 24, len: 8 }]
    );

    free_map.release(first).unwrap();
    let reused = free_map.allocate(10).unwrap().unwrap();

    assert_eq!(reused.bin_id, 0);
    assert_eq!(reused.offset, 0);
    assert_eq!(reused.len, 10);
}

#[test]
fn storage_bin_free_map_rebuilds_from_occupied_entries() {
    let layout = StorageBinLayoutPlan::from_disk_plan(&storage_bin_plan()).unwrap();
    let entries = vec![StorageBinIndexEntry {
        combined_key: "key".to_owned(),
        location: StorageBinObjectLocation {
            bin_id: 0,
            offset: 8,
            len: 8,
        },
        accessed: SystemTime::UNIX_EPOCH,
    }];

    let free_map = StorageBinFreeMap::from_occupied(&layout, &entries).unwrap();

    assert_eq!(
        free_map.free_ranges(0)[0],
        StorageBinFreeRange { offset: 0, len: 8 }
    );
    assert_eq!(
        free_map.free_ranges(0)[1],
        StorageBinFreeRange {
            offset: 16,
            len: 16
        }
    );
}

#[test]
fn storage_bin_file_set_writes_reads_and_preallocates_bins() {
    let root = tempfile::tempdir().unwrap();
    let plan = DiskTierPlan {
        path: root.path().to_path_buf(),
        max_size_bytes: ByteSize::from_bytes(128),
        max_object_bytes: ByteSize::from_bytes(64),
        backend: CacheDiskBackend::StorageBin,
        storage_bin: CacheDiskStorageBinConfig {
            bin_size_bytes: ByteSize::from_bytes(64),
            preallocate: true,
            max_open_bins: 4,
        },
        encryption: CacheDiskEncryptionConfig::default(),
        cache_tag_headers: Vec::new(),
    };
    let layout = StorageBinLayoutPlan::from_disk_plan(&plan).unwrap();
    let files = StorageBinFileSet::new(layout.clone());
    let location = StorageBinObjectLocation {
        bin_id: 0,
        offset: 8,
        len: 12,
    };

    files.write_object(location, b"hello-native").unwrap();

    assert_eq!(files.read_object(location).unwrap(), b"hello-native");
    assert_eq!(std::fs::metadata(layout.bin_path(0)).unwrap().len(), 64);
}

#[test]
fn storage_bin_layout_and_index_io_round_trip() {
    let root = tempfile::tempdir().unwrap();
    let plan = DiskTierPlan {
        path: root.path().join("cache"),
        max_size_bytes: ByteSize::from_bytes(128),
        max_object_bytes: ByteSize::from_bytes(64),
        backend: CacheDiskBackend::StorageBin,
        storage_bin: CacheDiskStorageBinConfig {
            bin_size_bytes: ByteSize::from_bytes(64),
            preallocate: false,
            max_open_bins: 4,
        },
        encryption: CacheDiskEncryptionConfig::default(),
        cache_tag_headers: Vec::new(),
    };
    let mut layout = StorageBinLayoutPlan::from_disk_plan(&plan).unwrap();
    prepare_storage_bin_layout(&layout).unwrap();
    let root = layout.root.canonicalize().unwrap();
    layout = StorageBinLayoutPlan {
        root: root.clone(),
        manifest_path: root.join(STORAGE_BIN_MANIFEST_FILENAME),
        data_dir: root.join(STORAGE_BIN_DATA_DIR),
        ..layout
    };
    let entries = vec![StorageBinIndexEntry {
        combined_key: "combined-key".to_owned(),
        location: StorageBinObjectLocation {
            bin_id: 0,
            offset: 4,
            len: 12,
        },
        accessed: SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(42),
    }];

    write_storage_bin_index(&layout, &entries).unwrap();

    assert!(storage_bin_index_path(&root).is_file());
    assert_eq!(read_storage_bin_index(&layout).unwrap(), entries);
}
