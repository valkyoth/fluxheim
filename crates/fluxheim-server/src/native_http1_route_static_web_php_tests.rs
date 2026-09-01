use std::fs;

use tempfile::TempDir;

use crate::native_http1_php::NativePhpScriptResolve;
use crate::native_http1_route_static_web_tests::native_static_web;

fn php_config() -> fluxheim_config::PhpConfig {
    fluxheim_config::PhpConfig {
        enabled: true,
        path_info: fluxheim_config::PhpPathInfoMode::Split,
        ..Default::default()
    }
}

#[test]
fn native_static_web_resolves_explicit_php_script_for_native_adapter() {
    let root = TempDir::new().unwrap();
    fs::write(root.path().join("index.php"), b"<?php echo 'ok';").unwrap();
    let web = native_static_web(root.path());

    let resolution = web
        .resolve_php_script(&php_config(), "/index.php/user", false)
        .unwrap();

    let NativePhpScriptResolve::Execute(resolution) = resolution else {
        panic!("expected executable PHP script");
    };
    assert_eq!(resolution.local_path, root.path().join("index.php"));
    assert_eq!(resolution.script_name, "/index.php");
    assert_eq!(resolution.path_info, "/user");

    root.close().unwrap();
}

#[test]
fn native_static_web_php_front_controller_uses_index_when_missing_path() {
    let root = TempDir::new().unwrap();
    fs::write(root.path().join("index.php"), b"<?php echo 'ok';").unwrap();
    let web = native_static_web(root.path());

    let resolution = web
        .resolve_php_script(&php_config(), "/missing/page", false)
        .unwrap();

    let NativePhpScriptResolve::Execute(resolution) = resolution else {
        panic!("expected front-controller PHP script");
    };
    assert_eq!(resolution.local_path, root.path().join("index.php"));
    assert_eq!(resolution.script_name, "/index.php");
    assert!(resolution.path_info.is_empty());

    root.close().unwrap();
}

#[test]
fn native_static_web_php_resolver_declines_existing_static_when_configured() {
    let root = TempDir::new().unwrap();
    fs::write(root.path().join("asset.txt"), b"static").unwrap();
    fs::write(root.path().join("index.php"), b"<?php echo 'ok';").unwrap();
    let web = native_static_web(root.path());

    let resolution = web
        .resolve_php_script(&php_config(), "/asset.txt", true)
        .unwrap();

    assert_eq!(resolution, NativePhpScriptResolve::Decline);

    root.close().unwrap();
}

#[test]
fn native_static_web_php_resolver_rejects_denied_prefix() {
    let root = TempDir::new().unwrap();
    fs::create_dir(root.path().join("admin")).unwrap();
    fs::write(root.path().join("admin/index.php"), b"<?php echo 'no';").unwrap();
    let web = native_static_web(root.path());
    let php = fluxheim_config::PhpConfig {
        enabled: true,
        deny_path_prefixes: vec!["/admin".to_owned()],
        ..php_config()
    };

    let resolution = web
        .resolve_php_script(&php, "/admin/index.php", false)
        .unwrap();

    assert_eq!(resolution, NativePhpScriptResolve::Forbidden);

    root.close().unwrap();
}

#[test]
fn native_static_web_php_resolver_rejects_windows_namespace_aliases() {
    let root = TempDir::new().unwrap();
    fs::write(root.path().join("index.php"), b"<?php echo 'ok';").unwrap();
    let web = native_static_web(root.path());

    for request_path in [
        "/index.php:payload.php",
        "/index.php%3Apayload.php",
        "/index.php/COM1.txt",
        "/index.php/file%2E",
        "/index.php/file%20",
    ] {
        let resolution = web
            .resolve_php_script(&php_config(), request_path, false)
            .unwrap();
        assert_eq!(
            resolution,
            NativePhpScriptResolve::Forbidden,
            "unsafe PHP namespace request was not rejected: {request_path}"
        );
    }

    root.close().unwrap();
}
