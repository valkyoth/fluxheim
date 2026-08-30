use std::path::Path;

use fluxheim_config::PhpPathInfoMode;

use crate::{
    MAX_PHP_PARAM_VALUE_BYTES, php_content_type_param_value, php_custom_params,
    php_fpm_path_translated, php_fpm_script_filename, php_header_param_name, php_host_param,
    php_request_header_params, php_script_name_denied, php_script_name_for_request,
    php_segment_has_allowed_extension, php_server_name_param, php_should_redirect_directory_index,
    php_static_file_script_name, safe_php_header_name, safe_php_header_value, safe_php_param_value,
};

#[test]
fn php_header_guards_reject_injection_bytes() {
    assert!(safe_php_header_name(b"X-PHP-Header"));
    assert!(safe_php_header_name(b"X_PHP.Token"));
    assert!(!safe_php_header_name(b""));
    assert!(!safe_php_header_name(b"bad:name"));
    assert!(!safe_php_header_name(b"bad name"));

    assert!(safe_php_header_value(b"session=ok; Path=/"));
    assert!(safe_php_header_value(b"tab\tallowed"));
    assert!(!safe_php_header_value(b"bad\x0binject"));
    assert!(!safe_php_header_value(b"bad\x7fdelete"));
    assert!(!safe_php_header_value(b"bad\r\ninject"));
    assert!(!safe_php_header_value("bad-é".as_bytes()));
}

#[test]
fn php_param_values_are_bounded_and_control_free() {
    assert!(safe_php_param_value("content-type-value"));
    assert!(safe_php_param_value(&"a".repeat(MAX_PHP_PARAM_VALUE_BYTES)));
    assert!(!safe_php_param_value(
        &"a".repeat(MAX_PHP_PARAM_VALUE_BYTES + 1)
    ));
    assert!(!safe_php_param_value("bad\nvalue"));
    assert!(!safe_php_param_value("bad\x7fvalue"));
}

#[test]
fn php_header_param_names_are_bounded_and_predictable() {
    assert_eq!(
        php_header_param_name("x-request-id").as_deref(),
        Some("HTTP_X_REQUEST_ID")
    );
    assert_eq!(php_header_param_name("proxy"), None);
    assert_eq!(php_header_param_name("content-type"), None);
    assert_eq!(php_header_param_name("content-length"), None);
    assert_eq!(php_header_param_name("bad name"), None);
    assert_eq!(php_header_param_name("bad_name"), None);
}

#[test]
fn php_server_name_prefers_safe_host_then_safe_fallback() {
    assert_eq!(
        php_server_name_param("example.test", "fallback.test"),
        "example.test"
    );
    assert_eq!(
        php_server_name_param("bad\nhost", "fallback.test"),
        "fallback.test"
    );
    assert_eq!(
        php_server_name_param("bad\nhost", "bad\rfallback"),
        "localhost"
    );
}

#[test]
fn php_request_header_params_join_duplicate_headers_and_block_proxy() {
    let params = php_request_header_params([
        ("cookie", "wordpress_logged_in=abc"),
        ("cookie", "wordpress_sec=def"),
        ("proxy", "http://attacker.invalid"),
        ("x-request-id", "req-1"),
        ("x-request-id", "req-2"),
    ]);

    assert_eq!(
        params,
        vec![
            (
                "HTTP_COOKIE".to_owned(),
                "wordpress_logged_in=abc; wordpress_sec=def".to_owned()
            ),
            ("HTTP_X_REQUEST_ID".to_owned(), "req-1, req-2".to_owned())
        ]
    );
}

#[test]
fn php_request_header_params_cap_joined_values() {
    let cookie = "a".repeat(MAX_PHP_PARAM_VALUE_BYTES / 2);
    let params = php_request_header_params([
        ("cookie", cookie.as_str()),
        ("cookie", cookie.as_str()),
        ("cookie", cookie.as_str()),
    ]);
    let (_, value) = params
        .iter()
        .find(|(name, _)| name == "HTTP_COOKIE")
        .expect("cookie param should be present");
    assert!(value.len() <= MAX_PHP_PARAM_VALUE_BYTES);
}

#[test]
fn php_host_content_type_and_custom_params_share_runtime_policy() {
    assert_eq!(
        php_host_param("example.test"),
        Some(("HTTP_HOST".to_owned(), "example.test".to_owned()))
    );
    assert_eq!(php_host_param("bad\nhost"), None);
    assert_eq!(
        php_content_type_param_value(["text/plain", "charset=utf-8"]),
        "text/plain, charset=utf-8"
    );
    assert_eq!(php_content_type_param_value(["text/plain\nbad"]), "");
    assert_eq!(
        php_content_type_param_value(["a".repeat(MAX_PHP_PARAM_VALUE_BYTES + 1).as_str()]),
        ""
    );
    let half = "a".repeat(MAX_PHP_PARAM_VALUE_BYTES / 2);
    assert_eq!(
        php_content_type_param_value([half.as_str(), half.as_str(), half.as_str()]),
        ""
    );

    let (accepted, dropped) = php_custom_params([
        ("SAFE_PARAM", "ok"),
        ("SCRIPT_FILENAME", "/tmp/bypass.php"),
        ("PHP_VALUE", "memory_limit=256M"),
        ("BAD_VALUE", "bad\nvalue"),
    ]);
    assert_eq!(accepted, vec![("SAFE_PARAM".to_owned(), "ok".to_owned())]);
    assert_eq!(
        dropped,
        vec![
            "SCRIPT_FILENAME".to_owned(),
            "PHP_VALUE".to_owned(),
            "BAD_VALUE".to_owned()
        ]
    );
}

#[test]
fn php_fpm_path_mapping_supports_split_container_roots_and_rejects_unsafe_path_info() {
    let root = Path::new("site/root");
    let fpm_root = Path::new("container/root");
    let local_script = Path::new("site/root/public/index.php");

    assert_eq!(
        php_fpm_script_filename(root, fpm_root, local_script).as_deref(),
        Some("container/root/public/index.php")
    );
    assert_eq!(
        php_fpm_script_filename(Path::new("other/root"), fpm_root, local_script),
        None
    );
    assert_eq!(
        php_fpm_path_translated(fpm_root, "/uploads/file.txt").as_deref(),
        Some("container/root/uploads/file.txt")
    );
    assert!(php_fpm_path_translated(fpm_root, "/uploads/../wp-config.php").is_none());
    assert!(php_fpm_path_translated(fpm_root, "/uploads/.secret").is_none());
    assert!(php_fpm_path_translated(fpm_root, "/uploads\\wp-config.php").is_none());
    assert!(php_fpm_path_translated(fpm_root, "/uploads/file\x01.txt").is_none());

    #[cfg(windows)]
    assert_eq!(
        php_fpm_path_translated(Path::new(r"C:\app\public"), "/uploads/file.txt").as_deref(),
        Some(r"C:\app\public\uploads\file.txt")
    );
}

#[test]
fn php_script_name_parser_accepts_direct_script_and_front_controller() {
    let allowed = vec!["php".to_owned()];

    let direct =
        php_script_name_for_request("/app.php", "index.php", PhpPathInfoMode::Disabled, &allowed)
            .expect("direct PHP script should parse");
    assert_eq!(direct.script_name, "/app.php");
    assert_eq!(direct.path_info, "");
    assert!(direct.explicit_php);

    let front = php_script_name_for_request(
        "/missing/page",
        "index.php",
        PhpPathInfoMode::Disabled,
        &allowed,
    )
    .expect("front controller fallback should parse");
    assert_eq!(front.script_name, "/index.php");
    assert_eq!(front.path_info, "");
    assert!(!front.explicit_php);
}

#[test]
fn php_script_name_parser_rejects_unsafe_segments_and_controls() {
    let allowed = vec!["php".to_owned()];

    assert!(
        php_script_name_for_request(
            "/../app.php",
            "index.php",
            PhpPathInfoMode::Disabled,
            &allowed
        )
        .is_none()
    );
    assert!(
        php_script_name_for_request(
            "/app.php/.hidden",
            "index.php",
            PhpPathInfoMode::Split,
            &allowed
        )
        .is_none()
    );
    assert!(
        php_script_name_for_request(
            "/app.php/user%01admin",
            "index.php",
            PhpPathInfoMode::Split,
            &allowed
        )
        .is_none()
    );
    assert!(
        php_script_name_for_request(
            "/app.php/user%7Fadmin",
            "index.php",
            PhpPathInfoMode::Split,
            &allowed
        )
        .is_none()
    );
}

#[test]
fn php_script_name_parser_respects_path_info_and_deny_prefixes() {
    let allowed = vec!["php".to_owned()];

    assert!(
        php_script_name_for_request(
            "/app.php/user/1",
            "index.php",
            PhpPathInfoMode::Disabled,
            &allowed
        )
        .is_none()
    );
    let split = php_script_name_for_request(
        "/app.php/user/1",
        "index.php",
        PhpPathInfoMode::Split,
        &allowed,
    )
    .expect("split PATH_INFO should parse");
    assert_eq!(split.script_name, "/app.php");
    assert_eq!(split.path_info, "/user/1");
    assert!(split.explicit_php);

    let deny = vec!["/wp-content/uploads/".to_owned()];
    assert!(php_script_name_denied(
        &deny,
        "/wp-content/uploads/shell.php"
    ));
    assert!(!php_script_name_denied(
        &deny,
        "/wp-content/uploads2/app.php"
    ));
    assert!(php_segment_has_allowed_extension("index.PHP", &allowed));
    assert!(!php_segment_has_allowed_extension("style.css", &allowed));
}

#[test]
fn php_static_file_script_names_are_rooted_and_hidden_safe() {
    let allowed = vec!["php".to_owned()];
    let root = Path::new("/srv/www");

    assert_eq!(
        php_static_file_script_name(root, Path::new("/srv/www/blog/index.php"), &allowed),
        Some("/blog/index.php".to_owned())
    );
    assert_eq!(
        php_static_file_script_name(root, Path::new("/srv/www/admin.PHP"), &allowed),
        Some("/admin.PHP".to_owned())
    );
    assert!(
        php_static_file_script_name(root, Path::new("/srv/www/assets/style.css"), &allowed)
            .is_none()
    );
    assert!(
        php_static_file_script_name(root, Path::new("/srv/www/.hidden/index.php"), &allowed)
            .is_none()
    );
    assert!(
        php_static_file_script_name(root, Path::new("/srv/other/index.php"), &allowed).is_none()
    );
}

#[test]
fn php_directory_index_redirect_policy_matches_runtime() {
    assert!(php_should_redirect_directory_index(
        "/blog",
        "/blog/index.php",
        "index.php"
    ));
    assert!(!php_should_redirect_directory_index(
        "/blog/",
        "/blog/index.php",
        "index.php"
    ));
    assert!(!php_should_redirect_directory_index(
        "/blog\\",
        "/blog/index.php",
        "index.php"
    ));
    assert!(!php_should_redirect_directory_index(
        "/blog",
        "/blog/admin.php",
        "index.php"
    ));
}
