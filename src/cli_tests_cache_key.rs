use super::*;
#[cfg(all(feature = "cache", feature = "proxy"))]
#[test]
fn cache_key_uri_accepts_separate_query() {
    assert_eq!(
        super::super::cache_key_uri("/assets/app.js", Some("v=1")).unwrap(),
        "/assets/app.js?v=1"
    );
    assert!(super::super::cache_key_uri("/assets/app.js?v=1", Some("x=2")).is_err());
    assert!(super::super::cache_key_uri("/assets/app.js", Some("?v=1")).is_err());
}

#[cfg(all(feature = "cache", feature = "proxy"))]
#[test]
fn cache_key_headers_accept_safe_variance_inputs() {
    assert_eq!(
        super::super::parse_cache_cli_header("cache-key", "Accept-Language: de, en;q=0.8").unwrap(),
        ("accept-language".to_owned(), "de, en;q=0.8".to_owned())
    );
    assert!(super::super::parse_cache_cli_header("cache-key", "Host: example.test").is_err());
    assert!(super::super::parse_cache_cli_header("cache-key", "Connection: close").is_err());
    assert!(super::super::parse_cache_cli_header("cache-key", "Bad Header: value").is_err());
    assert!(super::super::parse_cache_cli_header("cache-key", "X-Test: bad\r\nvalue").is_err());
}

#[cfg(not(feature = "cache"))]
#[test]
fn cache_warm_requires_cache_feature() {
    let error = run_from_args(["fluxheim", "cache-warm", "--path", "/"]).unwrap_err();

    assert!(error.to_string().contains("cache feature"));
}

#[cfg(not(feature = "cache"))]
#[test]
fn cache_key_requires_cache_feature() {
    let error = run_from_args(["fluxheim", "cache-key", "--path", "/"]).unwrap_err();

    assert!(error.to_string().contains("cache feature"));
}

#[cfg(not(feature = "cache"))]
#[test]
fn cache_lookup_requires_cache_feature() {
    let error = run_from_args(["fluxheim", "cache-lookup", "--path", "/"]).unwrap_err();

    assert!(error.to_string().contains("cache feature"));
}

#[cfg(all(feature = "proxy", not(feature = "web")))]
#[test]
fn validate_config_rejects_web_config_when_web_module_is_absent() {
    let dir = TestDir::new("cli-no-web-module");
    let root = dir.dir("public", 0o755);
    let config = dir.web_module_config("web-disabled.toml", &root);

    let error = run_from_args([
        "fluxheim",
        "--config",
        config.to_str().unwrap(),
        "--validate-config",
    ])
    .unwrap_err();

    assert!(error.to_string().contains("web module not compiled"));
}

#[cfg(all(feature = "proxy", not(feature = "cache")))]
#[test]
fn validate_config_rejects_enabled_cache_when_cache_module_is_absent() {
    let dir = TestDir::new("cli-no-cache-module");
    let config = dir.cache_module_config("cache-disabled.toml");

    let error = run_from_args([
        "fluxheim",
        "--config",
        config.to_str().unwrap(),
        "--validate-config",
    ])
    .unwrap_err();

    assert!(error.to_string().contains("cache module not compiled"));
}

#[cfg(all(feature = "proxy", not(feature = "php-fpm")))]
#[test]
fn validate_config_rejects_enabled_php_when_php_module_is_absent() {
    let dir = TestDir::new("cli-no-php-module");
    let root = dir.dir("php-root", 0o755);
    let config = dir.php_module_config("php-disabled.toml", &root);

    let error = run_from_args([
        "fluxheim",
        "--config",
        config.to_str().unwrap(),
        "--validate-config",
    ])
    .unwrap_err();

    assert!(error.to_string().contains("php-fpm module not compiled"));
}
