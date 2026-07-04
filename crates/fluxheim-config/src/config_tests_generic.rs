use super::*;
use crate::{
    DEFAULT_COMPRESSION_MAX_OUTPUT_BYTES, ForwardedClientIpHeaderMode, GeoIpConfig, LoggingFormat,
    LoggingLevel, StreamConfig, TlsConfig, UdpConfig,
};
use proptest::prelude::*;

#[test]
fn default_config_is_valid() {
    Config::default().validate().unwrap();
    assert_eq!(Config::default().logging.level, LoggingLevel::Info);
    assert_eq!(Config::default().logging.format, LoggingFormat::Json);
    assert!(Config::default().headers.request.enabled);
    assert!(
        Config::default()
            .headers
            .request
            .strip_inbound_client_ip_headers
    );
    #[cfg(not(feature = "privacy-mode"))]
    assert_eq!(
        Config::default().headers.request.x_forwarded_for,
        ForwardedClientIpHeaderMode::Replace
    );
    #[cfg(feature = "privacy-mode")]
    assert_eq!(
        Config::default().headers.request.x_forwarded_for,
        ForwardedClientIpHeaderMode::Off
    );
    assert_eq!(
        Config::default()
            .headers
            .response
            .x_content_type_options
            .as_deref(),
        Some("nosniff")
    );
    assert_eq!(
        Config::default()
            .headers
            .response
            .x_frame_options
            .as_deref(),
        Some("DENY")
    );
    assert_eq!(
        Config::default()
            .headers
            .response
            .referrer_policy
            .as_deref(),
        Some("no-referrer")
    );
    assert_eq!(Config::default().headers.response.unset, ["x-powered-by"]);
    assert_eq!(Config::default().web.cache_control, "public, max-age=60");
    assert_eq!(Config::default().server.process.threads, 1);
    assert_eq!(Config::default().server.process.listener_tasks_per_fd, 1);
    assert_eq!(Config::default().server.process.max_retries, 16);
    assert_eq!(
        Config::default().proxy.downstream_write_timeout_secs,
        Some(DEFAULT_PROXY_DOWNSTREAM_WRITE_TIMEOUT_SECS)
    );
    assert_eq!(
        Config::default()
            .proxy
            .downstream_total_response_timeout_secs,
        Some(DEFAULT_PROXY_DOWNSTREAM_TOTAL_RESPONSE_TIMEOUT_SECS)
    );
    assert!(!Config::default().compression.enabled);
    assert!(Config::default().compression.gzip);
    assert!(!Config::default().compression.zstd);
    assert!(!Config::default().compression.brotli);
    assert_eq!(
        Config::default().compression.max_output_bytes.as_u64(),
        DEFAULT_COMPRESSION_MAX_OUTPUT_BYTES
    );
    let default_issuers = Config::default().tls.acme.issuers;
    let issuer_names: Vec<&str> = default_issuers
        .iter()
        .map(|issuer| issuer.name.as_str())
        .collect();
    assert!(issuer_names.contains(&"google-trust-services"));
    assert!(issuer_names.contains(&"google-trust-services-staging"));
    let gts = default_issuers
        .iter()
        .find(|issuer| issuer.name == "google-trust-services")
        .unwrap();
    assert_eq!(
        gts.directory_url,
        "https://dv.acme-v02.api.pki.goog/directory"
    );
    assert_eq!(
        gts.eab.as_ref().unwrap().key_id_env.as_deref(),
        Some("FLUXHEIM_GTS_EAB_KID")
    );
    #[cfg(not(feature = "privacy-mode"))]
    assert!(Config::default().logging.access.enabled);
    #[cfg(feature = "privacy-mode")]
    assert!(!Config::default().logging.access.enabled);
}

#[test]
fn rejects_redirect_query_template_inside_url_authority() {
    assert!(!crate::config_route::valid_redirect_target_template(
        "https://{query}.example.test/"
    ));
    assert!(!crate::config_route::valid_redirect_target_template(
        "https://example..test{uri}"
    ));
    assert!(!crate::config_route::valid_redirect_target_template(
        "https://trusted%2finternal.example{uri}"
    ));
    assert!(!crate::config_route::valid_redirect_target_template(
        "https://example.test/{path}"
    ));
    assert!(!crate::config_route::valid_redirect_target_template(
        "https://example.test/files/{uri}"
    ));
    assert!(!crate::config_route::valid_redirect_target_template(
        "https://example.test/files/../admin{uri}"
    ));
    assert!(crate::config_route::valid_redirect_target_template(
        "https://example.test/search?next=/{uri}"
    ));
    assert!(crate::config_route::valid_redirect_target_template(
        "https://example.test/search?{query}"
    ));
}

#[test]
fn rejects_invalid_upstream() {
    let config = Config {
        server: ServerConfig::default(),
        admin: AdminConfig::default(),
        metrics: MetricsConfig::default(),
        tracing: TracingConfig::default(),
        logging: LoggingConfig::default(),
        headers: HeaderPolicyConfig::default(),
        tls: TlsConfig::default(),
        proxy: ProxyConfig {
            upstream: Some("https://origin.example.test".to_owned()),
            upstream_tls: true,
            upstream_sni: None,
            ..ProxyConfig::default()
        },
        compression: CompressionConfig::default(),
        cache: CacheConfig::default(),
        cache_purger: CachePurgerConfig::default(),
        web: WebConfig::default(),
        geoip: GeoIpConfig::default(),
        stream: StreamConfig::default(),
        udp: UdpConfig::default(),
        wasm: WasmConfig::default(),
        vhosts: vec![],
    };

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidUpstream {
            address: "https://origin.example.test".to_owned()
        })
    );
}

#[test]
fn vhost_section_errors_include_vhost_context() {
    let config: Config = toml::from_str(
        r#"
            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example"]

            [vhosts.proxy]
            upstream = "https://origin.example.test"
            "#,
    )
    .unwrap();

    let error = config.validate().unwrap_err();
    assert!(matches!(
        &error,
        ConfigError::VhostSection {
            vhost,
            section: "proxy",
            source,
        } if vhost == "gateway"
            && matches!(source.as_ref(), ConfigError::InvalidUpstream { .. })
    ));
    assert!(
        error
            .to_string()
            .contains("vhost \"gateway\" proxy: upstream must be host:port")
    );
}

#[test]
fn route_section_errors_include_vhost_and_route_context() {
    let config: Config = toml::from_str(
        r#"
            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example"]

            [[vhosts.routes]]
            name = "api"
            path_prefix = "/api/"

            [vhosts.routes.proxy]
            upstream = "https://api.example.test"
            "#,
    )
    .unwrap();

    let error = config.validate().unwrap_err();
    assert!(matches!(
        &error,
        ConfigError::RouteSection {
            vhost,
            route,
            section: "proxy",
            source,
        } if vhost == "gateway"
            && route == "api"
            && matches!(source.as_ref(), ConfigError::InvalidUpstream { .. })
    ));
    assert!(
        error
            .to_string()
            .contains("vhost \"gateway\" route \"api\" proxy: upstream must be host:port")
    );
}

#[test]
fn normalizes_host_names() {
    assert_eq!(
        normalize_host("Example.COM:443"),
        Some("example.com".to_owned())
    );
    assert_eq!(
        normalize_host("Example.COM.:443"),
        Some("example.com".to_owned())
    );
    assert_eq!(
        normalize_host("example.com."),
        Some("example.com".to_owned())
    );
    assert_eq!(normalize_host("[::1]:443"), Some("::1".to_owned()));
    assert_eq!(normalize_host("bad host"), None);
    assert_eq!(normalize_host("example.com?next=https://evil.test"), None);
    assert_eq!(normalize_host("example.com#fragment"), None);
    assert_eq!(normalize_host("user@example.com"), None);
    assert_eq!(normalize_host("trusted%2finternal.example"), None);
    assert_eq!(normalize_host("example..com"), None);
    assert_eq!(normalize_host("-example.com"), None);
    assert_eq!(normalize_host("example-.com"), None);
    assert_eq!(normalize_host("example.123"), None);
    assert_eq!(normalize_host("example.com\u{0001}"), None);
    assert_eq!(normalize_host("*.example.com"), None);
    assert_eq!(normalize_host("localhost"), Some("localhost".to_owned()));
    assert_eq!(normalize_host("php-fpm:9000"), Some("php-fpm".to_owned()));
    assert_eq!(
        normalize_host_pattern("*.Example.COM"),
        Some("*.example.com".to_owned())
    );
    assert_eq!(normalize_host_pattern("*bad.example.com"), None);
    assert!(!valid_authority("example..com:443"));
    assert!(!valid_authority("trusted%2finternal.example:443"));
    assert!(valid_authority("localhost:443"));
    assert!(valid_authority("php-fpm:9000"));
}

fn host_candidate() -> impl Strategy<Value = String> {
    prop::string::string_regex("[A-Za-z0-9.-]{1,64}").expect("valid host candidate regex")
}

fn header_template_fragment() -> impl Strategy<Value = String> {
    prop::string::string_regex("[A-Za-z0-9 _./:;=,?&-]{0,32}")
        .expect("valid header template fragment regex")
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn normalized_hosts_are_lowercase_and_idempotent(
        candidate in host_candidate(),
        port in prop::option::of(1u16..=u16::MAX),
    ) {
        let input = match port {
            Some(port) => format!("{candidate}:{port}"),
            None => candidate,
        };

        if let Some(normalized) = normalize_host(&input) {
            prop_assert!(!normalized.is_empty());
            let lowercase = normalized.to_ascii_lowercase();
            prop_assert_eq!(normalized.as_str(), lowercase.as_str());
            prop_assert!(!normalized.ends_with('.'));
            prop_assert!(!normalized.contains('*'));
            prop_assert!(!normalized.contains('/'));
            prop_assert!(!normalized.contains('\\'));
            prop_assert!(!normalized.contains('?'));
            prop_assert!(!normalized.contains('#'));
            prop_assert!(!normalized.contains('@'));
            let normalized_again = normalize_host(&normalized);
            prop_assert_eq!(normalized_again.as_deref(), Some(normalized.as_str()));
        }
    }

    #[test]
    fn host_normalization_rejects_forbidden_delimiters(
        prefix in host_candidate(),
        suffix in host_candidate(),
        delimiter in prop_oneof![
            Just('/'),
            Just('\\'),
            Just('?'),
            Just('#'),
            Just('@'),
            Just('*'),
            Just('%'),
            Just(' '),
        ],
    ) {
        let input = format!("{prefix}{delimiter}{suffix}");

        prop_assert_eq!(normalize_host(&input), None);
    }

    #[test]
    fn dynamic_header_templates_accept_supported_variables(
        prefix in header_template_fragment(),
        suffix in header_template_fragment(),
        variable in prop::sample::select(vec![
            "host",
            "remote_addr",
            "scheme",
            "uri",
            "path",
            "query",
            "request_id",
            "tls.cipher",
            "tls.version",
            "tls.client_cert_organization",
            "tls.client_cert_serial",
            "tls.client_cert_sha256",
            "route.regex.0",
            "route.regex.1",
            "route.regex.version",
            "http.upgrade",
            "http.x-forwarded-host",
        ]),
    ) {
        let template = format!("{prefix}{{{variable}}}{suffix}");

        prop_assert!(
            validate_dynamic_header_template("headers.request", "x-test", &template).is_ok()
        );
    }

    #[test]
    fn dynamic_header_templates_reject_unknown_variables(
        prefix in header_template_fragment(),
        variable in "[a-z_]{1,16}",
        suffix in header_template_fragment(),
    ) {
        prop_assume!(!valid_dynamic_header_variable(&variable));
        let template = format!("{prefix}{{{variable}}}{suffix}");
        let result = validate_dynamic_header_template("headers.request", "x-test", &template);

        prop_assert!(result.is_err());
    }
}

#[test]
fn dynamic_header_templates_validate_route_regex_capture_variables() {
    assert!(
        validate_dynamic_header_template(
            "headers.request",
            "x-version",
            "{route.regex.0}-{route.regex.15}-{route.regex.version}",
        )
        .is_ok()
    );
    assert_eq!(
        validate_dynamic_header_template("headers.request", "x-bad", "{route.regex.16}"),
        Err(ConfigError::InvalidHeaderTemplate {
            field: "headers.request",
            name: "x-bad".to_owned(),
            variable: "route.regex.16".to_owned(),
        })
    );
    assert_eq!(
        validate_dynamic_header_template("headers.request", "x-bad", "{route.regex.-1}"),
        Err(ConfigError::InvalidHeaderTemplate {
            field: "headers.request",
            name: "x-bad".to_owned(),
            variable: "route.regex.-1".to_owned(),
        })
    );
}
