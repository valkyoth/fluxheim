use std::path::Path;
use std::time::UNIX_EPOCH;

use fluxheim_common::test_support::{safe_child_path, unique_temp_path};

use super::{
    ByteRangeParse, DirectoryEntry, DirectoryListing, SafeRelativePath, StaticCacheIdentity,
    StaticResponseBody, StaticResponseConditions, StaticResponseFile,
    configured_web_path_contains_symlink, directory_listing_path, parse_single_byte_range,
    plan_static_response, render_directory_listing, static_cache_identity,
};

#[test]
fn renders_escaped_directory_listing() {
    let listing = DirectoryListing {
        path: "/repo/<root>/".to_owned(),
        entries: vec![DirectoryEntry {
            name: "a&b.txt".to_owned(),
            is_dir: false,
            size: Some(1),
            modified: None,
        }],
        local_time: false,
    };

    let html = render_directory_listing(&listing);

    assert!(html.contains("Index of /repo/&lt;root&gt;/"));
    assert!(html.contains("a&amp;b.txt"));
}

#[test]
fn directory_listing_local_time_uses_local_timestamp_shape() {
    let listing = DirectoryListing {
        path: "/".to_owned(),
        entries: vec![DirectoryEntry {
            name: "asset.txt".to_owned(),
            is_dir: false,
            size: Some(1),
            modified: Some(UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000)),
        }],
        local_time: true,
    };

    let html = render_directory_listing(&listing);

    assert!(
        html.contains("2023-11-14") || html.contains("2023-11-15"),
        "{html}"
    );
    assert!(!html.contains("GMT"));
}

#[test]
fn safe_relative_path_rejects_non_normal_components() {
    assert!(SafeRelativePath::from_path(Path::new("assets/app.css")).is_some());
    assert!(SafeRelativePath::from_path(Path::new("../secret")).is_none());
    assert!(SafeRelativePath::from_path(Path::new("/absolute")).is_none());
}

#[test]
fn safe_relative_path_detects_prefixed_components() {
    let path = SafeRelativePath::from_path(Path::new(".well-known/acme-challenge"))
        .expect("relative path should parse");

    assert!(path.contains_component_starting_with('.'));
}

#[test]
fn formats_directory_listing_paths_with_trailing_slash() {
    assert_eq!(directory_listing_path(Path::new("")), "/");
    assert_eq!(
        directory_listing_path(Path::new("assets/css")),
        "/assets/css/"
    );
}

#[test]
fn configured_web_path_rejects_dot_segments() {
    assert!(configured_web_path_contains_symlink(Path::new("assets/../public")).unwrap());
}

#[test]
fn configured_web_path_allows_missing_plain_path() {
    let missing = unique_temp_path("fluxheim-web-missing");

    assert!(!configured_web_path_contains_symlink(&missing).unwrap());
}

#[cfg(unix)]
#[test]
fn configured_web_path_detects_symlinked_parent() {
    let root = unique_temp_path("fluxheim-web-symlink-parent");
    let real = safe_child_path(&root, "real");
    let linked = safe_child_path(&root, "linked");
    let real_public = safe_child_path(&real, "public");
    let public = safe_child_path(&linked, "public");
    std::fs::create_dir_all(&real_public).unwrap();
    std::os::unix::fs::symlink(&real, &linked).unwrap();

    assert!(configured_web_path_contains_symlink(&public).unwrap());

    let _ = std::fs::remove_file(&linked);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn parses_single_byte_ranges() {
    assert_eq!(
        parse_single_byte_range("bytes=10-19", 100),
        ByteRangeParse::Single { start: 10, len: 10 }
    );
    assert_eq!(
        parse_single_byte_range("bytes=90-", 100),
        ByteRangeParse::Single { start: 90, len: 10 }
    );
    assert_eq!(
        parse_single_byte_range("bytes=-5", 100),
        ByteRangeParse::Single { start: 95, len: 5 }
    );
    assert_eq!(
        parse_single_byte_range("bytes=0-999", 10),
        ByteRangeParse::Single { start: 0, len: 10 }
    );
}

#[test]
fn rejects_unsatisfiable_or_multi_ranges() {
    assert_eq!(
        parse_single_byte_range("bytes=100-101", 100),
        ByteRangeParse::Unsatisfiable
    );
    assert_eq!(
        parse_single_byte_range("bytes=0-1,2-3", 100),
        ByteRangeParse::Ignore
    );
    assert_eq!(
        parse_single_byte_range("items=0-1", 100),
        ByteRangeParse::Unsatisfiable
    );
}

#[test]
fn plans_static_etag_revalidation() {
    let modified = UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
    let file = StaticResponseFile {
        len: 42,
        modified: Some(modified),
    };
    let first = plan_static_response(file, "GET", StaticResponseConditions::default());

    assert_eq!(first.status, 200);
    assert_eq!(first.content_length, Some(42));
    assert_eq!(first.response_body_bytes, 42);

    let revalidated = plan_static_response(
        file,
        "GET",
        StaticResponseConditions {
            if_none_match: Some(&first.etag),
            ..StaticResponseConditions::default()
        },
    );

    assert_eq!(revalidated.status, 304);
    assert_eq!(revalidated.content_length, None);
    assert_eq!(revalidated.body, StaticResponseBody::None);
    assert_eq!(revalidated.response_body_bytes, 0);
}

#[test]
fn forced_refresh_ignores_static_revalidation() {
    let modified = UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
    let file = StaticResponseFile {
        len: 42,
        modified: Some(modified),
    };
    let first = plan_static_response(file, "GET", StaticResponseConditions::default());

    let refreshed = plan_static_response(
        file,
        "GET",
        StaticResponseConditions {
            if_none_match: Some(&first.etag),
            cache_refresh_forced: true,
            ..StaticResponseConditions::default()
        },
    );

    assert_eq!(refreshed.status, 200);
    assert_eq!(refreshed.body, StaticResponseBody::Full);
}

#[test]
fn formats_static_cache_identity() {
    let modified = UNIX_EPOCH + std::time::Duration::new(10, 20);
    assert_eq!(
        static_cache_identity(StaticCacheIdentity {
            path: Path::new("/srv/site/app.js"),
            len: 123,
            modified: Some(modified),
            device_inode: None,
        }),
        "/srv/site/app.js:123:10:20"
    );
    assert_eq!(
        static_cache_identity(StaticCacheIdentity {
            path: Path::new("/srv/site/app.js"),
            len: 123,
            modified: Some(modified),
            device_inode: Some((7, 9)),
        }),
        "/srv/site/app.js:7:9:123:10:20"
    );
}
