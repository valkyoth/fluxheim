use std::fs;
use std::io;
use std::time::UNIX_EPOCH;

#[cfg(unix)]
use fluxheim_common::test_support::safe_child_path;
use fluxheim_common::test_support::unique_temp_path;

use super::{ResolveResult, StaticFileServer};
use crate::config::WebConfig;

use super::tests_support::{TestDir, server};

#[test]
fn resolves_index_file() {
    let root = TestDir::new("index");
    fs::write(root.child("index.html"), "<h1>ok</h1>").unwrap();

    let server = server(root.path());
    let resolved = server.resolve("/").unwrap();

    assert!(matches!(resolved, ResolveResult::Found(file) if file.mime == "text/html"));
}

#[test]
fn rejects_traversal() {
    let root = TestDir::new("traversal");
    fs::write(root.child("index.html"), "ok").unwrap();

    let server = server(root.path());

    assert_eq!(
        server.resolve("/../secret.txt").unwrap(),
        ResolveResult::Forbidden
    );
    assert_eq!(
        server.resolve("/%2e%2e/secret.txt").unwrap(),
        ResolveResult::Forbidden
    );
}

#[test]
fn rejects_dotfiles_by_default() {
    let root = TestDir::new("dotfiles");
    fs::write(root.child(".env"), "secret").unwrap();

    let server = server(root.path());

    assert_eq!(server.resolve("/.env").unwrap(), ResolveResult::Forbidden);
}

#[test]
fn directory_listing_is_disabled_by_default() {
    let root = TestDir::new("directory-listing-disabled");
    fs::write(root.child("asset.txt"), "ok").unwrap();

    let server = server(root.path());

    assert_eq!(server.resolve("/").unwrap(), ResolveResult::NotFound);
}

#[test]
fn resolves_directory_listing_when_enabled() {
    let root = TestDir::new("directory-listing");
    fs::write(root.child("alpha.txt"), "hello").unwrap();
    fs::write(root.child(".secret"), "hidden").unwrap();
    fs::create_dir_all(root.child("nested")).unwrap();

    let server = StaticFileServer::from_config(&WebConfig {
        root: Some(root.path().to_owned()),
        directory_listing: crate::config::DirectoryListingConfig {
            enabled: true,
            exact_size: true,
            local_time: false,
        },
        ..WebConfig::default()
    })
    .unwrap()
    .unwrap();

    let ResolveResult::DirectoryListing(listing) = server.resolve("/").unwrap() else {
        panic!("expected directory listing")
    };

    assert_eq!(listing.path, "/");
    assert!(!listing.local_time);
    assert_eq!(
        listing
            .entries
            .iter()
            .map(|entry| (entry.name.as_str(), entry.is_dir, entry.size))
            .collect::<Vec<_>>(),
        vec![("nested", true, None), ("alpha.txt", false, Some(5))]
    );
}

#[test]
fn renders_escaped_directory_listing() {
    let listing = super::DirectoryListing {
        path: "/repo/<root>/".to_owned(),
        entries: vec![super::DirectoryEntry {
            name: "a&b.txt".to_owned(),
            is_dir: false,
            size: Some(1),
            modified: None,
        }],
        local_time: false,
    };

    let html = super::render_directory_listing(&listing);

    assert!(html.contains("Index of /repo/&lt;root&gt;/"));
    assert!(html.contains("a&amp;b.txt"));
}

#[test]
fn directory_listing_local_time_uses_local_timestamp_shape() {
    let listing = super::DirectoryListing {
        path: "/".to_owned(),
        entries: vec![super::DirectoryEntry {
            name: "asset.txt".to_owned(),
            is_dir: false,
            size: Some(1),
            modified: Some(UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000)),
        }],
        local_time: true,
    };

    let html = super::render_directory_listing(&listing);

    assert!(
        html.contains("2023-11-14") || html.contains("2023-11-15"),
        "{html}"
    );
    assert!(!html.contains("GMT"));
}

#[test]
fn stores_configured_static_cache_headers() {
    let root = TestDir::new("static-cache-headers");
    fs::write(root.child("index.html"), "ok").unwrap();

    let server = StaticFileServer::from_config(&WebConfig {
        root: Some(root.path().to_owned()),
        cache_control: "public, max-age=31536000, immutable".to_owned(),
        expires: Some("Wed, 21 Oct 2030 07:28:00 GMT".to_owned()),
        ..WebConfig::default()
    })
    .unwrap()
    .unwrap();

    assert_eq!(server.cache_control, "public, max-age=31536000, immutable");
    assert_eq!(
        server.expires.as_deref(),
        Some("Wed, 21 Oct 2030 07:28:00 GMT")
    );
}

#[cfg(unix)]
#[test]
fn rejects_symlinked_static_root() {
    let target = TestDir::new("root-symlink-target");
    let root = unique_temp_path("web-root-symlink");
    std::os::unix::fs::symlink(target.path(), &root).unwrap();

    let error = StaticFileServer::from_config(&WebConfig {
        root: Some(root.clone()),
        index_files: vec!["index.html".to_owned()],
        deny_dotfiles: true,
        ..WebConfig::default()
    })
    .unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    let _ = fs::remove_file(root);
}

#[test]
fn rejects_missing_static_root() {
    let root = unique_temp_path("web-root-missing");

    let error = StaticFileServer::from_config(&WebConfig {
        root: Some(root.clone()),
        index_files: vec!["index.html".to_owned()],
        deny_dotfiles: true,
        ..WebConfig::default()
    })
    .unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert!(error.to_string().contains("web root does not exist"));
    assert!(error.to_string().contains(&root.display().to_string()));
}

#[cfg(unix)]
#[test]
fn rejects_static_root_below_symlinked_directory() {
    let dir = TestDir::new("root-parent-symlink");
    let real = dir.child("real");
    let linked = dir.child("linked");
    fs::create_dir_all(safe_child_path(&real, "public")).unwrap();
    std::os::unix::fs::symlink(&real, &linked).unwrap();

    let error = StaticFileServer::from_config(&WebConfig {
        root: Some(safe_child_path(&linked, "public")),
        index_files: vec!["index.html".to_owned()],
        deny_dotfiles: true,
        ..WebConfig::default()
    })
    .unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert!(error.to_string().contains("symlinked directory"));
}

#[test]
fn blocks_symlink_escape() {
    #[cfg(unix)]
    {
        let root = TestDir::new("symlink");
        let outside = TestDir::new("outside");
        fs::write(outside.child("secret.txt"), "secret").unwrap();
        std::os::unix::fs::symlink(outside.child("secret.txt"), root.child("link")).unwrap();

        let server = server(root.path());

        assert_eq!(server.resolve("/link").unwrap(), ResolveResult::NotFound);
    }
}

#[test]
fn rejects_static_symlinks_inside_root() {
    #[cfg(unix)]
    {
        let root = TestDir::new("inside-symlink");
        let real = root.child("real");
        fs::create_dir_all(&real).unwrap();
        fs::write(safe_child_path(&real, "asset.txt"), "ok").unwrap();
        std::os::unix::fs::symlink(
            safe_child_path(&real, "asset.txt"),
            root.child("asset-link.txt"),
        )
        .unwrap();
        std::os::unix::fs::symlink(&real, root.child("dir-link")).unwrap();

        let server = server(root.path());

        assert_eq!(
            server.resolve("/asset-link.txt").unwrap(),
            ResolveResult::NotFound
        );
        assert_eq!(
            server.resolve("/dir-link/asset.txt").unwrap(),
            ResolveResult::NotFound
        );
    }
}
