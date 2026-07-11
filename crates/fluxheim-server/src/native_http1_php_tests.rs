use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::AtomicUsize;

use fluxheim_protocol::Http1Version;

use super::{
    NativeHttp1Request, native_php_execute_fpm, native_php_request_body, native_php_request_plan,
    native_php_response_plan,
};

fn request(target: &str) -> NativeHttp1Request {
    NativeHttp1Request {
        method: "POST".to_owned(),
        peer_addr: Some(SocketAddr::from(([192, 0, 2, 10], 43123))),
        local_addr: Some(SocketAddr::from(([127, 0, 0, 1], 8443))),
        effective_client_addr: Some(SocketAddr::from(([203, 0, 113, 7], 52444))),
        downstream_tls: true,
        tls_identity: None,
        geo_context: None,
        target: target.to_owned(),
        version: Http1Version::Http11,
        headers: vec![
            ("host".to_owned(), "app.example".to_owned()),
            (
                "content-type".to_owned(),
                "application/x-www-form-urlencoded".to_owned(),
            ),
            ("cookie".to_owned(), "a=1".to_owned()),
            ("cookie".to_owned(), "b=2".to_owned()),
            ("x-test".to_owned(), "one".to_owned()),
            ("x-test".to_owned(), "two".to_owned()),
            ("proxy".to_owned(), "drop-me".to_owned()),
        ],
        trailers: Vec::new(),
        body: zeroize::Zeroizing::new(b"name=fluxheim".to_vec()),
    }
}

fn php_config() -> fluxheim_config::PhpConfig {
    fluxheim_config::PhpConfig {
        enabled: true,
        path_info: fluxheim_config::PhpPathInfoMode::Split,
        params: BTreeMap::from([
            ("APP_ENV".to_owned(), "test".to_owned()),
            ("SCRIPT_FILENAME".to_owned(), "/tmp/bypass.php".to_owned()),
        ]),
        ..Default::default()
    }
}

#[test]
fn native_php_request_plan_maps_core_fastcgi_params() {
    let plan = native_php_request_plan(
        &request("/index.php/user?id=1"),
        &php_config(),
        Path::new("/srv/www"),
        Path::new("/var/www/html"),
        Path::new("/srv/www/index.php"),
        "fallback.example",
        "443",
    )
    .unwrap();

    assert_eq!(plan.script_name, "/index.php");
    assert_eq!(plan.path_info, "/user");
    assert_eq!(plan.script_filename, "/var/www/html/index.php");
    assert_eq!(plan.path_translated.as_deref(), Some("/var/www/html/user"));
    assert_eq!(plan.param("REQUEST_METHOD"), Some("POST"));
    assert_eq!(plan.param("SERVER_PROTOCOL"), Some("HTTP/1.1"));
    assert_eq!(plan.param("QUERY_STRING"), Some("id=1"));
    assert_eq!(plan.param("REQUEST_URI"), Some("/index.php/user?id=1"));
    assert_eq!(plan.param("REMOTE_ADDR"), Some("203.0.113.7"));
    assert_eq!(plan.param("REMOTE_PORT"), Some("52444"));
    assert_eq!(plan.param("SERVER_ADDR"), Some("127.0.0.1"));
    assert_eq!(plan.param("SERVER_PORT"), Some("443"));
    assert_eq!(plan.param("SERVER_NAME"), Some("app.example"));
    assert_eq!(plan.param("CONTENT_LENGTH"), Some("13"));
    assert_eq!(
        plan.param("CONTENT_TYPE"),
        Some("application/x-www-form-urlencoded")
    );
    assert_eq!(plan.param("REQUEST_SCHEME"), Some("https"));
    assert_eq!(plan.param("HTTPS"), Some("on"));
    assert_eq!(plan.param("HTTP_COOKIE"), Some("a=1; b=2"));
    assert_eq!(plan.param("HTTP_X_TEST"), Some("one, two"));
    assert_eq!(plan.param("HTTP_PROXY"), None);
    assert_eq!(plan.param("APP_ENV"), Some("test"));
    assert_eq!(
        plan.param("SCRIPT_FILENAME"),
        Some("/var/www/html/index.php")
    );
    assert_eq!(plan.dropped_custom_params, vec!["SCRIPT_FILENAME"]);
}

#[test]
fn native_php_request_plan_rejects_denied_scripts() {
    let php = fluxheim_config::PhpConfig {
        enabled: true,
        deny_path_prefixes: vec!["/admin".to_owned()],
        ..Default::default()
    };
    let error = native_php_request_plan(
        &request("/admin/index.php"),
        &php,
        Path::new("/srv/www"),
        Path::new("/var/www/html"),
        Path::new("/srv/www/admin/index.php"),
        "fallback.example",
        "443",
    )
    .unwrap_err();

    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
}

#[test]
fn native_php_request_plan_rejects_unsafe_path_info() {
    let php = fluxheim_config::PhpConfig {
        enabled: true,
        path_info: fluxheim_config::PhpPathInfoMode::Split,
        ..Default::default()
    };
    let error = native_php_request_plan(
        &request("/index.php/%2e%2e/secret"),
        &php,
        Path::new("/srv/www"),
        Path::new("/var/www/html"),
        Path::new("/srv/www/index.php"),
        "fallback.example",
        "443",
    )
    .unwrap_err();

    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
}

#[tokio::test]
async fn native_php_request_body_uses_memory_below_spool_threshold() {
    let body = native_php_request_body(
        &request("/index.php"),
        &fluxheim_config::PhpConfig {
            enabled: true,
            request_body_spool_threshold_bytes: Some(fluxheim_config::ByteSize::from_bytes(1024)),
            request_body_spool_dir: Some(std::path::PathBuf::from("/unused")),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    assert_eq!(body.len(), b"name=fluxheim".len());
}

#[tokio::test]
async fn native_php_request_body_spools_and_cleans_up_large_body() {
    let test_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target");
    std::fs::create_dir_all(&test_root).unwrap();
    let spool_dir = tempfile::TempDir::new_in(test_root).unwrap();
    let body = native_php_request_body(
        &request("/index.php"),
        &fluxheim_config::PhpConfig {
            enabled: true,
            request_body_spool_threshold_bytes: Some(fluxheim_config::ByteSize::from_bytes(4)),
            request_body_spool_dir: Some(spool_dir.path().to_path_buf()),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    assert_eq!(body.len(), b"name=fluxheim".len());
    assert_eq!(
        std::fs::read_dir(spool_dir.path()).unwrap().count(),
        0,
        "spool file should be unlinked while the request body is alive"
    );
    drop(body);
    assert_eq!(
        std::fs::read_dir(spool_dir.path()).unwrap().count(),
        0,
        "spool file should be removed when the request body is dropped"
    );

    spool_dir.close().unwrap();
}

#[tokio::test]
async fn native_php_request_body_rejects_configured_limit() {
    let result = native_php_request_body(
        &request("/index.php"),
        &fluxheim_config::PhpConfig {
            enabled: true,
            max_request_body_bytes: Some(fluxheim_config::ByteSize::from_bytes(4)),
            ..Default::default()
        },
    )
    .await;
    let Err(error) = result else {
        panic!("expected PHP request body limit error");
    };

    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
}

#[tokio::test]
async fn native_php_execute_fpm_rejects_missing_endpoint() {
    let php = php_config();
    let plan = native_php_request_plan(
        &request("/index.php"),
        &php,
        Path::new("/srv/www"),
        Path::new("/var/www/html"),
        Path::new("/srv/www/index.php"),
        "fallback.example",
        "443",
    )
    .unwrap();
    let result = native_php_execute_fpm(
        &php,
        &plan,
        fluxheim_php_fpm::PhpRequestBody::memory(Vec::new()),
        &[],
        &AtomicUsize::new(0),
    )
    .await;
    let Err(error) = result else {
        panic!("expected missing PHP-FPM endpoint error");
    };

    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
}

#[test]
fn native_php_response_plan_strips_owned_and_hidden_headers() {
    let php = fluxheim_config::PhpConfig {
        enabled: true,
        hide_response_headers: vec!["x-powered-by".to_owned()],
        ..Default::default()
    };
    let plan = native_php_response_plan(
        b"Status: 201 Created\r\n\
              Content-Type: text/plain\r\n\
              Content-Length: 999\r\n\
              Connection: x-internal\r\n\
              X-Internal: secret\r\n\
              X-Powered-By: php\r\n\
              X-Accel-Redirect: /private\r\n\
              X-Sendfile: /private/file\r\n\
              X-Accel-Expires: 60\r\n\
              \r\n\
              hello",
        &php,
        "GET",
    )
    .unwrap();

    assert_eq!(plan.intercept_status, None);
    assert_eq!(plan.response.status(), 201);
    assert_eq!(plan.response.content_length(), Some(5));
    assert_eq!(plan.response.body(), b"hello");
    assert!(plan.response.headers().iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("content-type") && value == "text/plain"
    }));
    for stripped in [
        "content-length",
        "connection",
        "x-internal",
        "x-powered-by",
        "x-accel-redirect",
        "x-sendfile",
        "x-accel-expires",
    ] {
        assert!(
            !plan
                .response
                .headers()
                .iter()
                .any(|(name, _)| name.eq_ignore_ascii_case(stripped)),
            "{stripped} should be stripped"
        );
    }
}

#[test]
fn native_php_response_plan_keeps_head_length_without_body() {
    let plan = native_php_response_plan(
        b"Content-Type: text/plain\r\n\r\nhello",
        &fluxheim_config::PhpConfig {
            enabled: true,
            ..Default::default()
        },
        "HEAD",
    )
    .unwrap();

    assert_eq!(plan.response.status(), 200);
    assert_eq!(plan.response.content_length(), Some(5));
    assert!(plan.response.body().is_empty());
}

#[test]
fn native_php_response_plan_marks_intercepted_statuses() {
    let php = fluxheim_config::PhpConfig {
        enabled: true,
        intercept_error_statuses: vec![404],
        ..Default::default()
    };
    let plan =
        native_php_response_plan(b"Status: 404 Not Found\r\n\r\nmissing", &php, "GET").unwrap();

    assert_eq!(plan.intercept_status, Some(404));
    assert_eq!(plan.response.status(), 404);
}
