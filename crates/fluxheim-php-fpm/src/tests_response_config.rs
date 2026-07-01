use std::io;
use std::path::Path;

use fluxheim_config::{PhpFpmConfig, PhpFpmProcessManager};

use crate::{
    managed_php_fpm_config, parse_php_status, split_first_colon, split_php_response, trim_ascii,
    trim_ascii_cr,
};

#[test]
fn php_static_offload_policy_rejects_controls_and_script_targets() {
    let allowed = vec!["php".to_owned()];

    assert_eq!(
        crate::php_static_offload_uri_target("/style.css").unwrap(),
        "/style.css"
    );
    assert!(crate::php_static_offload_uri_target("/style.css\nbad").is_err());
    assert!(crate::php_static_offload_file_allowed(
        Path::new("/srv/www/style.css"),
        &allowed
    ));
    assert!(!crate::php_static_offload_file_allowed(
        Path::new("/srv/www/app.PHP"),
        &allowed
    ));
    assert!(!crate::php_static_offload_file_allowed(
        Path::new("/srv/www/wp-config"),
        &allowed
    ));
    assert!(!crate::php_static_offload_file_allowed(
        Path::new("/srv/www/file."),
        &allowed
    ));
}

#[test]
fn php_x_sendfile_targets_map_from_fpm_root_to_local_root() {
    let root = Path::new("/srv/www");
    let fpm_root = Path::new("/app/public");

    assert_eq!(
        crate::php_static_offload_x_sendfile_local_path(
            root,
            fpm_root,
            "/app/public/assets/style.css"
        )
        .unwrap(),
        Path::new("/srv/www/assets/style.css")
    );
    assert_eq!(
        crate::php_static_offload_x_sendfile_local_path(
            root,
            fpm_root,
            "/app/public/../secret.txt"
        )
        .unwrap_err()
        .kind(),
        io::ErrorKind::PermissionDenied
    );
    assert_eq!(
        crate::php_static_offload_x_sendfile_local_path(root, fpm_root, "/other/style.css")
            .unwrap_err()
            .kind(),
        io::ErrorKind::PermissionDenied
    );
    assert_eq!(
        crate::php_static_offload_x_sendfile_local_path(
            root,
            fpm_root,
            "/app/public/style.css\nbad"
        )
        .unwrap_err()
        .kind(),
        io::ErrorKind::InvalidInput
    );
}

#[test]
fn php_x_accel_expires_ttl_parser_is_bounded() {
    let future = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 60;
    let ttl = crate::php_x_accel_expires_ttl_secs(&format!("@{future}")).unwrap();

    assert!(ttl <= 60);
    assert!(ttl > 0);
    assert_eq!(crate::php_x_accel_expires_ttl_secs("120"), Some(120));
    assert_eq!(crate::php_x_accel_expires_ttl_secs("0"), Some(0));
    assert_eq!(crate::php_x_accel_expires_ttl_secs("-1"), Some(0));
    assert_eq!(crate::php_x_accel_expires_ttl_secs("bad"), None);
}

#[test]
fn php_origin_cache_policy_detects_restrictive_directives() {
    assert!(crate::php_origin_cache_policy_is_restrictive(
        ["public, private=max-age=1"],
        []
    ));
    assert!(crate::php_origin_cache_policy_is_restrictive(
        ["public, no-store"],
        []
    ));
    assert!(crate::php_origin_cache_policy_is_restrictive(
        ["public"],
        ["no-cache"]
    ));
    assert!(!crate::php_origin_cache_policy_is_restrictive(
        ["public, max-age=60"],
        []
    ));
}

#[test]
fn php_response_header_strip_policy_includes_connection_tokens_and_hidden_names() {
    let hidden = vec!["x-powered-by".to_owned()];
    let headers = crate::php_response_headers_to_strip(["x-hop, keep-alive, bad token"], &hidden);

    assert!(headers.iter().any(|header| header == "connection"));
    assert!(headers.iter().any(|header| header == "transfer-encoding"));
    assert!(headers.iter().any(|header| header == "x-hop"));
    assert!(headers.iter().any(|header| header == "keep-alive"));
    assert!(!headers.iter().any(|header| header == "bad token"));
    assert!(headers.iter().any(|header| header == "x-powered-by"));
}

#[test]
fn php_static_offload_header_names_are_shared_policy() {
    assert_eq!(
        crate::PHP_STATIC_OFFLOAD_RESPONSE_HEADERS,
        &["x-accel-redirect", "x-sendfile"]
    );
}

#[test]
fn php_error_page_or_intercept_status_enables_interception() {
    assert!(crate::php_should_intercept_error_status(502, [502], &[]));
    assert!(crate::php_should_intercept_error_status(503, [], &[503]));
    assert!(!crate::php_should_intercept_error_status(
        404,
        [502],
        &[503]
    ));
}

#[test]
fn php_response_primitives_parse_headers_status_and_body() {
    let (headers, body) = split_php_response(b"Status: 201 Created\r\nX-Test: ok\r\n\r\nbody")
        .expect("response should split");
    assert_eq!(headers, b"Status: 201 Created\r\nX-Test: ok");
    assert_eq!(body, b"body");
    assert_eq!(parse_php_status(b"201 Created").unwrap(), 201);
    assert_eq!(trim_ascii_cr(b"value\r"), b"value");
    assert_eq!(trim_ascii(b" \tvalue\t "), b"value");
    assert_eq!(
        split_first_colon(b"x-test: value"),
        Some((&b"x-test"[..], &b" value"[..]))
    );
}

#[test]
fn php_response_primitives_reject_invalid_status() {
    assert!(split_php_response(b"missing terminator").is_err());
    assert!(parse_php_status(b"99").is_err());
    assert!(parse_php_status(b"600").is_err());
    assert!(parse_php_status(b"not-a-status").is_err());
    assert!(parse_php_status(&[0xff]).is_err());
}

#[test]
fn php_response_parser_returns_plain_status_headers_and_body() {
    let response = crate::parse_php_response(
        b"X-Before: yes\r\nStatus: 201 Created\r\nX-After: ok\r\n\r\nbody",
        64 * 1024,
        64 * 1024,
    )
    .expect("PHP response should parse");

    assert_eq!(response.status, 201);
    assert_eq!(response.body, b"body");
    assert_eq!(
        response.headers,
        vec![
            ("X-Before".to_owned(), "yes".to_owned()),
            ("X-After".to_owned(), "ok".to_owned())
        ]
    );
}

#[test]
fn php_response_parser_rejects_unsafe_headers_and_size_overflow() {
    let error = crate::parse_php_response(b"X-Test: ok\rbad\r\n\r\nbody", 64 * 1024, 64 * 1024)
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);

    let error = crate::parse_php_response(b"Content-Type: text/plain\r\n\r\nbody", 8, 64 * 1024)
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);

    let error = crate::parse_php_response(
        b"X-Very-Long-Header: abc\r\n\r\nbody",
        64 * 1024,
        "X-Very-Long-Header: abc".len() as u64 - 1,
    )
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
}

#[test]
fn managed_php_fpm_config_contains_private_pool_settings() {
    let fpm = PhpFpmConfig {
        process_manager: PhpFpmProcessManager::Dynamic,
        workers: 8,
        min_spare_servers: Some(2),
        max_spare_servers: Some(6),
        start_servers: Some(4),
        max_spawn_rate: Some(16),
        listen_backlog: Some(128),
        listen_owner: Some("fluxheim".to_owned()),
        listen_group: Some("www-data".to_owned()),
        listen_mode: Some("0660".to_owned()),
        user: Some("fluxheim".to_owned()),
        group: Some("www-data".to_owned()),
        request_terminate_timeout_secs: Some(30),
        request_terminate_timeout_track_finished: true,
        request_slowlog_timeout_secs: Some(5),
        session_save_path: Some(Path::new("/run/fluxheim/php/session").to_path_buf()),
        upload_tmp_dir: Some(Path::new("/run/fluxheim/php/upload").to_path_buf()),
        clear_env: false,
        ..PhpFpmConfig::default()
    };

    let config = managed_php_fpm_config(
        Path::new("/run/fluxheim/php/php-fpm.sock"),
        Path::new("/run/fluxheim/php/php-fpm.pid"),
        Path::new("/run/fluxheim/php/php-fpm.log"),
        Some(Path::new("/run/fluxheim/php/php-fpm.slow.log")),
        &fpm,
    )
    .expect("managed php-fpm config should render");

    assert!(config.contains("listen.mode = 0660\n"));
    assert!(config.contains("listen.owner = fluxheim\n"));
    assert!(config.contains("listen.group = www-data\n"));
    assert!(config.contains("listen.backlog = 128\n"));
    assert!(config.contains("user = fluxheim\n"));
    assert!(config.contains("group = www-data\n"));
    assert!(config.contains("pm = dynamic\n"));
    assert!(config.contains("pm.max_children = 8\n"));
    assert!(config.contains("pm.start_servers = 4\n"));
    assert!(config.contains("pm.min_spare_servers = 2\n"));
    assert!(config.contains("pm.max_spare_servers = 6\n"));
    assert!(config.contains("pm.max_spawn_rate = 16\n"));
    assert!(config.contains("request_terminate_timeout = 30s\n"));
    assert!(config.contains("request_terminate_timeout_track_finished = yes\n"));
    assert!(config.contains("request_slowlog_timeout = 5s\n"));
    assert!(config.contains("slowlog = /run/fluxheim/php/php-fpm.slow.log\n"));
    assert!(config.contains("clear_env = no\n"));
    assert!(config.contains("catch_workers_output = yes\n"));
    assert!(config.contains("decorate_workers_output = yes\n"));
    assert!(config.contains("security.limit_extensions = .php\n"));
    assert!(config.contains("php_value[session.save_path] = /run/fluxheim/php/session\n"));
    assert!(config.contains("php_admin_value[upload_tmp_dir] = /run/fluxheim/php/upload\n"));
}

#[test]
fn managed_php_fpm_config_rejects_unsafe_path_bytes() {
    let error = managed_php_fpm_config(
        Path::new("/run/fluxheim/php/php-fpm.sock"),
        Path::new("/run/fluxheim/php/php-fpm.pid"),
        Path::new("/run/fluxheim/php/php-fpm\".log"),
        None,
        &PhpFpmConfig::default(),
    )
    .expect_err("unsafe config paths should be rejected");

    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
}
