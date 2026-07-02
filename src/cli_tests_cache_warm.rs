#[cfg(feature = "cache")]
use super::*;
#[cfg(feature = "cache")]
#[test]
fn cache_warm_targets_accept_default_host_and_input_hosts() {
    let dir = TestDir::new("cli-cache-warm-targets");
    let input = dir.path.join("warm.txt");
    fs::write(
        &input,
        "\n# release preload\n/assets/app.css\ncdn.example /img/logo.png?v=1\n",
    )
    .unwrap();

    let targets =
        super::super::cache_warm_targets(Some("example.test"), &["/".to_owned()], Some(&input), 8)
            .unwrap();

    assert_eq!(
        targets,
        vec![
            super::super::CacheWarmTarget {
                host: "example.test".to_owned(),
                path: "/".to_owned(),
            },
            super::super::CacheWarmTarget {
                host: "example.test".to_owned(),
                path: "/assets/app.css".to_owned(),
            },
            super::super::CacheWarmTarget {
                host: "cdn.example".to_owned(),
                path: "/img/logo.png?v=1".to_owned(),
            },
        ]
    );
}

#[cfg(feature = "cache")]
#[test]
fn cache_warm_input_file_is_bounded() {
    let dir = TestDir::new("cli-cache-warm-input-bound");
    let input = dir.path.join("warm.txt");
    fs::write(
        &input,
        vec![b'#'; super::super::CACHE_WARM_INPUT_MAX_BYTES + 1],
    )
    .unwrap();

    let error = super::super::cache_warm_targets(Some("example.test"), &[], Some(&input), 8)
        .unwrap_err()
        .to_string();

    assert!(error.contains("cache-warm input file must be at most"));
}

#[cfg(feature = "cache")]
#[test]
fn cache_warm_dry_run_validates_targets_without_listener() {
    let dir = TestDir::new("cli-cache-warm-dry-run");
    let config = dir.simple_config("fluxheim.toml", "example", "example.test");

    run_from_args([
        "fluxheim",
        "--config",
        config.to_str().unwrap(),
        "cache-warm",
        "--path",
        "/assets/app.css",
        "--header",
        "Accept-Language: de",
        "--repeat",
        "2",
        "--expect-cache-status-sequence",
        "MISS,HIT",
        "--dry-run",
    ])
    .unwrap();
}

#[cfg(feature = "cache")]
#[test]
fn cache_warm_dry_run_rejects_unsafe_request_headers() {
    let dir = TestDir::new("cli-cache-warm-bad-header");
    let config = dir.simple_config("fluxheim.toml", "example", "example.test");

    let error = run_from_args([
        "fluxheim",
        "--config",
        config.to_str().unwrap(),
        "cache-warm",
        "--path",
        "/assets/app.css",
        "--header",
        "Host: other.example",
        "--dry-run",
    ])
    .unwrap_err();

    assert!(error.to_string().contains("cannot set Host"));
}

#[cfg(feature = "cache")]
#[test]
fn cache_warm_targets_reject_header_injection() {
    let error = super::super::cache_warm_target("example.test", "/ok\r\nx-bad: 1").unwrap_err();
    assert!(error.to_string().contains("path contains control"));

    let error = super::super::cache_warm_target("bad host", "/ok").unwrap_err();
    assert!(error.to_string().contains("Host header"));
}

#[cfg(feature = "cache")]
#[test]
fn cache_warm_listen_rewrites_unspecified_address_to_loopback() {
    let config = crate::config::Config {
        server: crate::config::ServerConfig {
            listen: vec!["0.0.0.0:8080".to_owned()],
            ..crate::config::ServerConfig::default()
        },
        ..crate::config::Config::default()
    };

    assert_eq!(
        super::super::cache_warm_listen_addr(&config, None).unwrap(),
        "127.0.0.1:8080".parse().unwrap()
    );
}

#[cfg(feature = "cache")]
#[test]
fn cache_warm_status_parser_reads_status_code() {
    assert_eq!(
        super::super::cache_warm_status_from_prefix(
            b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n"
        )
        .unwrap(),
        200
    );
    assert!(super::super::cache_warm_status_from_prefix(b"bad\r\n").is_err());
    assert_eq!(
        super::super::cache_warm_header_value_from_prefix(
            b"HTTP/1.1 200 OK\r\nX-Cache-Status: HIT\r\n\r\nbody",
            "x-cache-status"
        )
        .unwrap(),
        Some("HIT".to_owned())
    );
}

#[cfg(feature = "cache")]
#[test]
fn cache_warm_status_success_requires_success_or_explicit_allow() {
    assert!(super::super::cache_warm_status_is_success(200, &[]));
    assert!(super::super::cache_warm_status_is_success(302, &[]));
    assert!(!super::super::cache_warm_status_is_success(404, &[]));
    assert!(super::super::cache_warm_status_is_success(404, &[404]));
    assert!(super::super::validate_cache_warm_allow_statuses(&[200, 404]).is_ok());
    assert!(super::super::validate_cache_warm_allow_statuses(&[99]).is_err());
    assert!(super::super::validate_cache_warm_header_name("x-cache-status").is_ok());
    assert!(super::super::validate_cache_warm_header_name("bad header").is_err());
    assert!(
        super::super::validate_cache_warm_expected_statuses(&["HIT".to_owned(), "MISS".to_owned()])
            .is_ok()
    );
    assert!(
        super::super::cache_warm_expected_status_matches(Some("hit"), &["HIT".to_owned()]).is_ok()
    );
    assert!(
        super::super::cache_warm_expected_status_matches(Some("BYPASS"), &["HIT".to_owned()])
            .is_err()
    );
    assert!(super::super::cache_warm_expected_status_matches(None, &["HIT".to_owned()]).is_err());
    assert!(
        super::super::validate_cache_warm_expected_sequence(
            &[],
            &["MISS".to_owned(), "HIT".to_owned()],
            2
        )
        .is_ok()
    );
    assert!(
        super::super::validate_cache_warm_expected_sequence(&[], &["MISS".to_owned()], 2).is_err()
    );
    assert!(
        super::super::validate_cache_warm_expected_sequence(
            &["HIT".to_owned()],
            &["MISS".to_owned()],
            1
        )
        .is_err()
    );
    assert_eq!(
        super::super::cache_warm_expected_statuses_for_attempt(
            &[],
            &["MISS".to_owned(), "HIT".to_owned()],
            2
        ),
        &["HIT".to_owned()]
    );
}
