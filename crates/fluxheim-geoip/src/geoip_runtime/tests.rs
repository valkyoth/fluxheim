use super::{
    GeoIpLoadLimits, GeoIpPolicyUsage, GeoIpRuntime, admitted_geoip_total, normalized_country,
    open_verified_mmdb, read_verified_mmdb_with_post_read,
};
use fluxheim_config::{GeoIpConfig, GeoIpDatabaseConfig, GeoIpProvider};

fn test_database(path: &std::path::Path) -> GeoIpDatabaseConfig {
    GeoIpDatabaseConfig {
        provider: GeoIpProvider::Maxmind,
        path: path.to_path_buf(),
    }
}

fn trusted_test_file(label: &str, contents: &[u8]) -> std::path::PathBuf {
    let directory = fluxheim_common::test_support::unique_temp_path(label);
    std::fs::create_dir_all(&directory).unwrap();
    let path = fluxheim_common::test_support::safe_child_path(&directory, "test.mmdb");
    std::fs::write(&path, contents).unwrap();
    path
}

#[test]
fn normalizes_country_codes() {
    assert_eq!(normalized_country("se").as_deref(), Some("SE"));
    assert_eq!(normalized_country(" USA "), None);
    assert_eq!(normalized_country("1A"), None);
    assert_eq!(normalized_country(&"A".repeat(4096)), None);
}

#[test]
fn aggregate_limit_rejects_before_mmdb_parse() {
    let path = trusted_test_file("geoip-aggregate-limit", b"not-a-valid-mmdb");
    let config = GeoIpConfig {
        enabled: true,
        fallback_enabled: true,
        databases: vec![test_database(&path)],
    };

    let error = GeoIpRuntime::from_config_with_limits(
        &config,
        GeoIpPolicyUsage::default(),
        GeoIpLoadLimits {
            max_database_bytes: 64,
            max_total_bytes: 8,
            max_databases: 8,
        },
    )
    .unwrap_err();

    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    assert!(error.to_string().contains("total GeoIP database size"));
    assert!(!error.to_string().contains("failed to parse"));
}

#[test]
fn aggregate_limit_rejects_database_exceeding_remaining_allowance() {
    assert_eq!(admitted_geoip_total(6, 4, 10).unwrap(), 10);
    let error = admitted_geoip_total(6, 5, 10).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
}

#[test]
fn runtime_boundary_rejects_excessive_database_count() {
    let config = GeoIpConfig {
        enabled: true,
        fallback_enabled: true,
        databases: (0..=fluxheim_config::config_geoip::MAX_GEOIP_DATABASES)
            .map(|_| test_database(std::path::Path::new("/missing.mmdb")))
            .collect(),
    };

    let error = GeoIpRuntime::from_config(&config, GeoIpPolicyUsage::default()).unwrap_err();

    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    assert!(error.to_string().contains("GeoIP requires 1..=8 databases"));
}

#[cfg(unix)]
#[test]
fn rejects_writable_database_and_parent() {
    use std::os::unix::fs::PermissionsExt as _;

    let file = trusted_test_file("geoip-writable-file", b"database");
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o666)).unwrap();
    let file_error = open_verified_mmdb(&file, 64).unwrap_err();
    assert_eq!(file_error.kind(), std::io::ErrorKind::PermissionDenied);

    let parent = fluxheim_common::test_support::unique_temp_path("geoip-writable-parent");
    std::fs::create_dir_all(&parent).unwrap();
    let child = fluxheim_common::test_support::safe_child_path(&parent, "test.mmdb");
    std::fs::write(&child, b"database").unwrap();
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o777)).unwrap();
    let parent_error = open_verified_mmdb(&child, 64).unwrap_err();
    assert_eq!(parent_error.kind(), std::io::ErrorKind::PermissionDenied);
}

#[test]
fn rejects_database_modified_during_read() {
    let path = trusted_test_file("geoip-read-change", b"first-database");
    let verified = open_verified_mmdb(&path, 64).unwrap();
    let error = read_verified_mmdb_with_post_read(verified, || {
        std::fs::write(&path, b"other-database").unwrap();
    })
    .unwrap_err();

    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert!(error.to_string().contains("changed while reading"));
}
