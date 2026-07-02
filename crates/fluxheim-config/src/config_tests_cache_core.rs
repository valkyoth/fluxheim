use super::super::*;

#[test]
fn parses_cache_config() {
    let config: Config = toml::from_str(
        r#"
            [cache]
            preset = "wordpress"
            enabled = true
            local_static = true
            status_header = "X-Cache-Status"
            status_reason_header = "X-Cache-Reason"
            hide_response_headers = ["set-cookie"]
            tag_headers = ["Surrogate-Key", "X-App-Cache-Tags"]
            no_store_response_headers = ["x-fluxheim-no-store"]
            no_store_response_header_values = { x-app-cache = "private" }
            bypass_path_prefixes = ["/private/"]
            bypass_path_exact = ["/login"]
            bypass_request_headers = ["cookie", "authorization"]
            bypass_request_header_values = { x-preview-mode = "1" }
            bypass_cookie_names = ["sessionid", "wordpress_logged_in"]
            bypass_cookie_name_prefixes = ["wordpress_sec_"]
            bypass_cookie_values = { preview = "1" }
            bypass_query_params = ["preview", "token"]
            bypass_query_values = { mode = "private" }
            bypass_query = false
            allow_client_cache_refresh = true
            vary_request_headers = ["accept-encoding", "accept-language"]
            ignore_origin_cache_headers = true
            key_namespace = "repoheim-assets-v1"
            key_parts = ["method", "host", "path"]
            min_uses = 2
            pass_uncacheable_after = 3
            status_ttls = { "200" = 3600, "404" = 60 }
            default_status_ttl_secs = 15
            stale_while_revalidate_secs = 30
            stale_if_error_secs = 120
            stale_if_error_on = ["connect", "timeout", "connection-closed", "http-status"]
            stale_if_error_statuses = [500, 502, 503, 504]
            include_query = false
            content_types = ["image/*", "text/css"]
            extensions = ["jpg", "webp", "css"]
            methods = ["GET"]
            max_object_bytes = "4MiB"

            [cache.range]
            enabled = true
            max_bytes = "1MiB"

            [cache.range.slice]
            enabled = true
            size_bytes = "256KiB"
            max_slices = 4
            fill_missing = false

            [cache.memory]
            enabled = true
            max_size_bytes = "1GiB"

            [cache.disk]
            enabled = true
            path = "/var/cache/fluxheim"
            max_size_bytes = "10GiB"

            [cache.lock]
            enabled = false
            age_timeout_secs = 45
            wait_timeout_secs = 10

            [cache.predictor]
            enabled = true
            capacity = 8192
            "#,
    )
    .unwrap();

    assert!(config.cache.enabled);
    assert_eq!(config.cache.preset, CachePreset::WordPress);
    assert!(config.cache.local_static);
    assert_eq!(
        config.cache.status_header,
        Some("X-Cache-Status".to_owned())
    );
    assert_eq!(
        config.cache.status_reason_header,
        Some("X-Cache-Reason".to_owned())
    );
    assert_eq!(
        config.cache.hide_response_headers,
        ["set-cookie".to_owned()]
    );
    assert_eq!(
        config.cache.tag_headers,
        ["Surrogate-Key".to_owned(), "X-App-Cache-Tags".to_owned()]
    );
    assert_eq!(
        config.cache.no_store_response_headers,
        ["x-fluxheim-no-store".to_owned()]
    );
    assert_eq!(
        config
            .cache
            .no_store_response_header_values
            .get("x-app-cache"),
        Some(&"private".to_owned())
    );
    assert_eq!(config.cache.bypass_path_prefixes, ["/private/".to_owned()]);
    assert_eq!(config.cache.bypass_path_exact, ["/login".to_owned()]);
    assert_eq!(
        config.cache.bypass_request_headers,
        ["cookie".to_owned(), "authorization".to_owned()]
    );
    assert_eq!(
        config
            .cache
            .bypass_request_header_values
            .get("x-preview-mode"),
        Some(&"1".to_owned())
    );
    assert_eq!(
        config.cache.bypass_cookie_names,
        ["sessionid".to_owned(), "wordpress_logged_in".to_owned()]
    );
    assert_eq!(
        config.cache.bypass_cookie_name_prefixes,
        ["wordpress_sec_".to_owned()]
    );
    assert_eq!(
        config.cache.bypass_cookie_values.get("preview"),
        Some(&"1".to_owned())
    );
    assert_eq!(
        config.cache.bypass_query_params,
        ["preview".to_owned(), "token".to_owned()]
    );
    assert_eq!(
        config.cache.bypass_query_values.get("mode"),
        Some(&"private".to_owned())
    );
    assert!(!config.cache.bypass_query);
    assert!(config.cache.allow_client_cache_refresh);
    assert_eq!(
        config.cache.vary_request_headers,
        ["accept-encoding".to_owned(), "accept-language".to_owned()]
    );
    assert!(config.cache.ignore_origin_cache_headers);
    assert_eq!(
        config.cache.key_namespace,
        Some("repoheim-assets-v1".to_owned())
    );
    assert_eq!(
        config.cache.key_parts,
        [CacheKeyPart::Method, CacheKeyPart::Host, CacheKeyPart::Path]
    );
    assert_eq!(config.cache.min_uses, 2);
    assert_eq!(config.cache.pass_uncacheable_after, 3);
    assert_eq!(config.cache.status_ttls.get(&200), Some(&3600));
    assert_eq!(config.cache.status_ttls.get(&404), Some(&60));
    assert_eq!(config.cache.default_status_ttl_secs, Some(15));
    assert_eq!(config.cache.stale_while_revalidate_secs, Some(30));
    assert_eq!(config.cache.stale_if_error_secs, Some(120));
    assert_eq!(
        config.cache.stale_if_error_on,
        [
            CacheStaleErrorKind::Connect,
            CacheStaleErrorKind::Timeout,
            CacheStaleErrorKind::ConnectionClosed,
            CacheStaleErrorKind::HttpStatus
        ]
    );
    assert_eq!(config.cache.stale_if_error_statuses, [500, 502, 503, 504]);
    assert!(!config.cache.include_query);
    assert_eq!(
        config.cache.content_types,
        ["image/*".to_owned(), "text/css".to_owned()]
    );
    assert_eq!(
        config.cache.image_extensions,
        ["jpg".to_owned(), "webp".to_owned(), "css".to_owned()]
    );
    assert_eq!(config.cache.methods, ["GET".to_owned()]);
    let wordpress_cache = config.cache.with_presets();
    assert!(
        wordpress_cache
            .bypass_path_prefixes
            .contains(&"/wp-admin/".to_owned())
    );
    for path in [
        "/wp-login.php",
        "/wp-register.php",
        "/wp-mail.php",
        "/index.php",
        "/sitemap.xml",
        "/sitemap_index.xml",
    ] {
        assert!(
            wordpress_cache.bypass_path_exact.contains(&path.to_owned()),
            "missing WordPress bypass path {path}"
        );
    }
    assert!(
        wordpress_cache
            .bypass_cookie_name_prefixes
            .contains(&"wordpress_logged_in_".to_owned())
    );
    assert!(wordpress_cache.bypass_query);
    assert_eq!(
        config.cache.max_object_bytes,
        ByteSize::from_bytes(4 * 1024 * 1024)
    );
    assert!(config.cache.range.enabled);
    assert_eq!(
        config.cache.range.max_bytes,
        ByteSize::from_bytes(1024 * 1024)
    );
    assert!(config.cache.range.slice.enabled);
    assert_eq!(
        config.cache.range.slice.size_bytes,
        ByteSize::from_bytes(256 * 1024)
    );
    assert_eq!(config.cache.range.slice.max_slices, 4);
    assert!(!config.cache.range.slice.fill_missing);
    assert!(config.cache.memory.enabled);
    assert_eq!(
        config.cache.memory.max_size_bytes,
        ByteSize::from_bytes(1024 * 1024 * 1024)
    );
    assert_eq!(
        config.cache.disk.path,
        Some(PathBuf::from("/var/cache/fluxheim"))
    );
    assert_eq!(
        config.cache.disk.max_size_bytes,
        ByteSize::from_bytes(10 * 1024 * 1024 * 1024)
    );
    assert!(!config.cache.lock.enabled);
    assert_eq!(config.cache.lock.age_timeout_secs, 45);
    assert_eq!(config.cache.lock.wait_timeout_secs, 10);
    assert!(config.cache.predictor.enabled);
    assert_eq!(config.cache.predictor.capacity, 8192);
    config.cache.validate("cache").unwrap();
}
