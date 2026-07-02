use std::fs;
use std::path::Path;
use std::path::PathBuf;

#[cfg(not(feature = "privacy-mode"))]
use super::LoadBalanceManagedCookieSameSite;
use super::{
    AdminConfig, AdminHealthConfig, AdminHealthResponseMode, AdminRemoteTransportMode,
    AdminSelfHealingConfig, AdminTransportConfig, ByteSize, CacheConfig, CacheDiskBackend,
    CacheDiskEncryptionProvider, CacheKeyPart, CachePreset, CachePurgerConfig, CacheStaleErrorKind,
    CompressionConfig, Config, ConfigError, ConfigLoadError, DownstreamProxyProtocol,
    HeaderPolicyConfig, LoadBalanceHealthCheckProtocol, LoadBalancePersistenceMode,
    LoadBalanceSelection, LoggingConfig, MetricsConfig, ProxyConfig, RateLimitMode, ServerConfig,
    ServerLimitsConfig, StaticCertificateConfig, TlsAlpnPolicy, TlsCipherSuite, TlsClientAuthMode,
    TlsCurvePreference, TlsPolicyProfile, TlsProtocolVersion, TracingConfig, UpstreamHttpVersion,
    UpstreamProxyProtocol, VhostConfig, VhostHeaderPolicyConfig, VhostTlsConfig, WebConfig,
    normalize_host, normalize_host_pattern, valid_dynamic_header_variable,
    validate_dynamic_header_template,
};
#[cfg(feature = "cache")]
use super::{CacheOriginProtectionConfig, CachePeerConfig, CachePeerFillConfig};
use crate::config_net::valid_authority;
use crate::config_proxy::{
    DEFAULT_PROXY_DOWNSTREAM_TOTAL_RESPONSE_TIMEOUT_SECS,
    DEFAULT_PROXY_DOWNSTREAM_WRITE_TIMEOUT_SECS,
};
use crate::test_support::{safe_child_path, safe_relative_path, unique_temp_path};
#[cfg(unix)]
use crate::test_support::{unique_group_writable_child, unique_world_writable_child};
use proptest::prelude::*;

#[path = "config_tests_admin.rs"]
mod admin;
#[path = "config_tests_admin_security.rs"]
mod admin_security;
#[path = "config_tests_basic.rs"]
mod basic;
#[path = "config_tests_cache.rs"]
mod cache;
#[path = "config_tests_compression.rs"]
mod compression;
#[path = "config_tests_geoip.rs"]
mod geoip;
#[path = "config_tests_headers.rs"]
mod headers;
#[path = "config_tests_load_balance.rs"]
mod load_balance;
#[path = "config_tests_logging.rs"]
mod logging;
#[path = "config_tests_observability.rs"]
mod observability;
#[path = "config_tests_php.rs"]
mod php;
#[path = "config_tests_proxy.rs"]
mod proxy;
#[path = "config_tests_proxy_timeouts.rs"]
mod proxy_timeouts;
#[path = "config_tests_tls.rs"]
mod tls;

fn secure_test_dir(label: &str) -> PathBuf {
    let path = unique_temp_path(label);
    fs::create_dir_all(&path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    path
}

fn test_process_config_toml(label: &str) -> String {
    let root = secure_test_dir(label);
    format!(
        r#"
            [server.process]
            pid_file = "{}"
            upgrade_sock = "{}"
            certificate_reload_sock = "{}"
            "#,
        safe_child_path(&root, "fluxheim.pid").display(),
        safe_child_path(&root, "fluxheim-upgrade.sock").display(),
        safe_child_path(&root, "fluxheim-cert-reload.sock").display()
    )
}

#[test]
fn default_config_is_valid() {
    Config::default().validate().unwrap();
    assert_eq!(Config::default().logging.level, super::LoggingLevel::Info);
    assert_eq!(Config::default().logging.format, super::LoggingFormat::Json);
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
        super::ForwardedClientIpHeaderMode::Replace
    );
    #[cfg(feature = "privacy-mode")]
    assert_eq!(
        Config::default().headers.request.x_forwarded_for,
        super::ForwardedClientIpHeaderMode::Off
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
        super::DEFAULT_COMPRESSION_MAX_OUTPUT_BYTES
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
fn parses_request_header_policy() {
    let config: Config = toml::from_str(
        r#"
            [headers.request]
            enabled = true
            strip_inbound_client_ip_headers = true
            x_forwarded_for = "append"
            x_real_ip = true
            x_forwarded_host = false
            x_forwarded_proto = true
            forwarded = true
            unset = ["x-powered-by"]

            [headers.request.set]
            host = "backend.internal"
            x-proxy-by = "Fluxheim"

            [headers.request.append]
            via = "fluxheim"
            "#,
    )
    .unwrap();

    let policy = &config.headers.request;
    assert!(policy.enabled);
    assert!(policy.strip_inbound_client_ip_headers);
    assert_eq!(
        policy.x_forwarded_for,
        super::ForwardedClientIpHeaderMode::Append
    );
    assert!(policy.x_real_ip);
    assert!(!policy.x_forwarded_host);
    assert!(policy.x_forwarded_proto);
    assert!(policy.forwarded);
    assert_eq!(policy.unset, ["x-powered-by"]);
    assert_eq!(
        policy.set.get("host").map(String::as_str),
        Some("backend.internal")
    );
    assert_eq!(
        policy.set.get("x-proxy-by").map(String::as_str),
        Some("Fluxheim")
    );
    assert_eq!(
        policy
            .append
            .get("via")
            .and_then(|values| values.iter().next()),
        Some("fluxheim")
    );
    config.validate().unwrap();
}

#[test]
fn request_header_policy_default_matches_deserialization_for_real_ip() {
    let config: Config = toml::from_str(
        r#"
            [headers.request]
            enabled = true
            "#,
    )
    .unwrap();

    assert!(super::RequestHeaderPolicyConfig::default().x_real_ip);
    assert!(config.headers.request.x_real_ip);
    config.validate().unwrap();
}

#[test]
fn validates_dynamic_request_header_values() {
    let config: Config = toml::from_str(
        r#"
            [headers.request.add]
            host = "{host}"
            x-real-ip = "{remote_addr}"
            x-forwarded-proto = "{scheme}"
            x-original-uri = "{uri}"
            x-original-path = "{path}"
            x-original-query = "{query}"
            x-request-id = "{request_id}"
            upgrade = "{http.upgrade}"
            "#,
    )
    .unwrap();

    config.validate().unwrap();

    let config: Config = toml::from_str(
        r#"
            [headers.request.add]
            x-bad = "{client_ip}"
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidHeaderTemplate {
            field: "headers.request",
            name: "x-bad".to_owned(),
            variable: "client_ip".to_owned(),
        })
    );
}

#[test]
fn rejects_tls_identity_request_header_append() {
    let config: Config = toml::from_str(
        r#"
            [headers.request.append]
            x-client-cert-sha256 = "{tls.client_cert_sha256}"
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::UnsafeTlsHeaderAppend {
            field: "headers.request",
            name: "x-client-cert-sha256".to_owned(),
        })
    );
}

#[test]
fn parses_user_friendly_header_operations() {
    let config: Config = toml::from_str(
        r#"
            [headers.request]
            remove = ["x-powered-by"]

            [headers.request.add]
            x-internal-route = "true"

            [headers.request.operations]
            remove = ["server"]
            add = { x-extra-route = "edge" }

            [headers.response]
            remove = ["x-origin-banner"]

            [headers.response.operations]
            remove = ["x-debug"]
            add = { cache-control = "public, max-age=60" }
            "#,
    )
    .unwrap();

    config.validate().unwrap();
    assert_eq!(
        config.headers.request.effective_unset(),
        ["x-powered-by", "server"]
    );
    assert_eq!(
        config
            .headers
            .request
            .effective_set()
            .get("x-internal-route")
            .map(String::as_str),
        Some("true")
    );
    assert_eq!(
        config
            .headers
            .request
            .effective_set()
            .get("x-extra-route")
            .map(String::as_str),
        Some("edge")
    );
    assert!(
        config
            .headers
            .response
            .effective_unset()
            .contains(&"x-origin-banner".to_owned())
    );
    assert!(
        config
            .headers
            .response
            .effective_unset()
            .contains(&"x-debug".to_owned())
    );
    assert_eq!(
        config
            .headers
            .response
            .effective_set()
            .get("cache-control")
            .map(String::as_str),
        Some("public, max-age=60")
    );
}

#[test]
fn rejects_conflicting_header_add_aliases() {
    let config: Config = toml::from_str(
        r#"
            [headers.response.set]
            cache-control = "public, max-age=60"

            [headers.response.add]
            Cache-Control = "private, no-store"
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::ConflictingHeaderAdd {
            field: "headers.response",
            name: "Cache-Control".to_owned()
        })
    );

    let config: Config = toml::from_str(
        r#"
            [[vhosts]]
            name = "api"
            hosts = ["api.example.test"]

            [vhosts.headers.request.add]
            x-route = "api"

            [vhosts.headers.request.operations]
            add = { x-route = "legacy" }
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::VhostSection {
            vhost: "api".to_owned(),
            section: "headers",
            source: Box::new(ConfigError::ConflictingHeaderAdd {
                field: "vhosts.headers.request",
                name: "x-route".to_owned()
            })
        })
    );
}

#[test]
fn rejects_too_many_header_unset_operations() {
    let headers = (0..=super::MAX_HEADER_MUTATION_NAMES)
        .map(|index| format!("\"x-remove-{index}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let config: Config = toml::from_str(&format!(
        r#"
            [headers.request]
            remove = [{headers}]
            "#,
    ))
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidHeaderMutationLength {
            field: "headers.request",
            operation: "unset",
            max: super::MAX_HEADER_MUTATION_NAMES,
        })
    );
}

#[test]
fn rejects_too_many_header_set_operations() {
    let headers = (0..=super::MAX_HEADER_MUTATION_NAMES)
        .map(|index| format!("\"x-set-{index}\" = \"value\""))
        .collect::<Vec<_>>()
        .join("\n");
    let config: Config = toml::from_str(&format!(
        r#"
            [headers.response.add]
            {headers}
            "#,
    ))
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidHeaderMutationLength {
            field: "headers.response",
            operation: "set",
            max: super::MAX_HEADER_MUTATION_NAMES,
        })
    );
}

#[test]
fn rejects_too_many_header_append_operations() {
    let headers = (0..=super::MAX_HEADER_MUTATION_NAMES)
        .map(|index| format!("\"x-append-{index}\" = \"value\""))
        .collect::<Vec<_>>()
        .join("\n");
    let config: Config = toml::from_str(&format!(
        r#"
            [[vhosts]]
            name = "api"
            hosts = ["api.example.test"]

            [vhosts.headers.response.append]
            {headers}
            "#,
    ))
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::VhostSection {
            vhost: "api".to_owned(),
            section: "headers",
            source: Box::new(ConfigError::InvalidHeaderMutationLength {
                field: "vhosts.headers.response",
                operation: "append",
                max: super::MAX_HEADER_MUTATION_NAMES,
            })
        })
    );
}

#[test]
fn rejects_too_many_header_append_values() {
    let values = (0..=super::MAX_HEADER_APPEND_VALUES)
        .map(|index| format!("\"value-{index}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let config: Config = toml::from_str(&format!(
        r#"
            [headers.response.append]
            vary = [{values}]
            "#,
    ))
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidHeaderMutationLength {
            field: "headers.response",
            operation: "append values",
            max: super::MAX_HEADER_APPEND_VALUES,
        })
    );
}

#[test]
fn parses_response_header_policy() {
    let config: Config = toml::from_str(
        r#"
            [headers.response]
            enabled = true
            strict_transport_security = "max-age=31536000; includeSubDomains"
            content_security_policy = "default-src 'self'"
            x_content_type_options = "nosniff"
            x_frame_options = "SAMEORIGIN"
            referrer_policy = "strict-origin-when-cross-origin"
            unset = ["server", "x-powered-by"]

            [headers.response.set]
            cache-control = "public, max-age=60"
            access-control-allow-origin = "https://example.test"

            [headers.response.append]
            vary = ["Accept-Encoding", "Origin"]
            set-cookie = "fluxheim=1; HttpOnly; Secure; SameSite=Lax"

            [[headers.response.rewrite.location]]
            from = "http://backend.internal/"
            to = "https://example.test/"

            [[headers.response.rewrite.refresh]]
            from = "/legacy/"
            to = "/"

            [[headers.response.rewrite.cookie_domain]]
            from = "backend.internal"
            to = "example.test"

            [[headers.response.rewrite.cookie_path]]
            from = "/app/"
            to = "/"
            "#,
    )
    .unwrap();

    let policy = &config.headers.response;
    assert!(policy.enabled);
    assert_eq!(
        policy.strict_transport_security.as_deref(),
        Some("max-age=31536000; includeSubDomains")
    );
    assert_eq!(
        policy.content_security_policy.as_deref(),
        Some("default-src 'self'")
    );
    assert_eq!(policy.x_frame_options.as_deref(), Some("SAMEORIGIN"));
    assert_eq!(
        policy.referrer_policy.as_deref(),
        Some("strict-origin-when-cross-origin")
    );
    assert_eq!(policy.unset, ["server", "x-powered-by"]);
    assert_eq!(
        policy.set.get("cache-control").map(String::as_str),
        Some("public, max-age=60")
    );
    assert_eq!(
        policy
            .append
            .get("vary")
            .map(|values| values.iter().collect::<Vec<_>>()),
        Some(vec!["Accept-Encoding", "Origin"])
    );
    assert_eq!(
        policy.rewrite.location,
        [super::ResponseHeaderRewriteRuleConfig {
            from: "http://backend.internal/".to_owned(),
            to: "https://example.test/".to_owned()
        }]
    );
    assert_eq!(
        policy.rewrite.refresh,
        [super::ResponseHeaderRewriteRuleConfig {
            from: "/legacy/".to_owned(),
            to: "/".to_owned()
        }]
    );
    assert_eq!(
        policy.rewrite.cookie_domain,
        [super::ResponseHeaderRewriteRuleConfig {
            from: "backend.internal".to_owned(),
            to: "example.test".to_owned()
        }]
    );
    assert_eq!(
        policy.rewrite.cookie_path,
        [super::ResponseHeaderRewriteRuleConfig {
            from: "/app/".to_owned(),
            to: "/".to_owned()
        }]
    );
    config.validate().unwrap();
}

#[test]
fn rejects_invalid_response_header_rewrite_rules() {
    let config: Config = toml::from_str(
        r#"
            [[headers.response.rewrite.location]]
            from = "backend.internal/"
            to = "https://example.test/"
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidHeaderValue {
            field: "headers.response.rewrite",
            name: "location.from".to_owned()
        })
    );

    let config: Config = toml::from_str(
        r#"
            [[headers.response.rewrite.refresh]]
            from = "https://backend.internal/"
            to = "https://example.test/"

            [[headers.response.rewrite.refresh]]
            from = "https://backend.internal/"
            to = "https://example.test/other/"
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::ConflictingHeaderAdd {
            field: "headers.response.rewrite",
            name: "refresh.from".to_owned()
        })
    );

    let config: Config = toml::from_str(
        r#"
            [[headers.response.rewrite.cookie_domain]]
            from = "bad domain"
            to = "example.test"
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidHeaderValue {
            field: "headers.response.rewrite",
            name: "cookie_domain.from".to_owned()
        })
    );

    let config: Config = toml::from_str(
        r#"
            [[headers.response.rewrite.cookie_path]]
            from = "//backend"
            to = "/"
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidHeaderValue {
            field: "headers.response.rewrite",
            name: "cookie_path.from".to_owned()
        })
    );
}

#[test]
fn parses_structured_hsts_response_header_policy() {
    let config: Config = toml::from_str(
        r#"
            [headers.response.hsts]
            enabled = true
            max_age_secs = 63072000
            include_subdomains = true
            preload = true
            "#,
    )
    .unwrap();

    let hsts = config.headers.response.hsts.as_ref().unwrap();
    assert_eq!(
        hsts.header_value().as_deref(),
        Some("max-age=63072000; includeSubDomains; preload")
    );
    config.validate().unwrap();
}

#[test]
fn rejects_conflicting_hsts_response_header_policy() {
    let config: Config = toml::from_str(
        r#"
            [headers.response]
            strict_transport_security = "max-age=31536000"

            [headers.response.hsts]
            max_age_secs = 63072000
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidResponseHeaderValue {
            field: "headers.response.hsts"
        })
    );
}

#[test]
fn parses_vhost_header_policy_overlay() {
    let config: Config = toml::from_str(
        r#"
            [[vhosts]]
            name = "api"
            hosts = ["api.example.test"]

            [vhosts.headers.request]
            x_forwarded_for = "off"
            unset = ["x-powered-by"]
            remove = ["x-legacy-route"]

            [vhosts.headers.request.set]
            host = "api.internal"

            [vhosts.headers.request.operations]
            remove = ["x-old-api"]
            add = { x-api-route = "true" }

            [vhosts.headers.response]
            x_frame_options = "SAMEORIGIN"
            unset = ["server"]
            remove = ["x-origin-banner"]

            [vhosts.headers.response.set]
            access-control-allow-origin = "https://app.example.test"

            [vhosts.headers.response.append]
            vary = "Origin"

            [vhosts.headers.response.operations]
            remove = ["x-debug"]
            add = { x-response-route = "api" }
            "#,
    )
    .unwrap();

    let headers = &config.vhosts[0].headers;
    assert_eq!(
        headers.request.x_forwarded_for,
        Some(super::ForwardedClientIpHeaderMode::Off)
    );
    assert_eq!(headers.request.unset, ["x-powered-by"]);
    assert_eq!(
        headers.request.effective_unset(),
        ["x-powered-by", "x-legacy-route", "x-old-api"]
    );
    assert_eq!(
        headers.request.set.get("host").map(String::as_str),
        Some("api.internal")
    );
    assert_eq!(
        headers
            .request
            .effective_set()
            .get("x-api-route")
            .map(String::as_str),
        Some("true")
    );
    assert_eq!(
        headers
            .response
            .x_frame_options
            .as_ref()
            .and_then(Option::as_deref),
        Some("SAMEORIGIN")
    );
    assert_eq!(headers.response.unset, ["server"]);
    assert_eq!(
        headers.response.effective_unset(),
        ["server", "x-origin-banner", "x-debug"]
    );
    assert_eq!(
        headers
            .response
            .set
            .get("access-control-allow-origin")
            .map(String::as_str),
        Some("https://app.example.test")
    );
    assert_eq!(
        headers
            .response
            .append
            .get("vary")
            .and_then(|values| values.iter().next()),
        Some("Origin")
    );
    assert_eq!(
        headers
            .response
            .effective_set()
            .get("x-response-route")
            .map(String::as_str),
        Some("api")
    );
    config.validate().unwrap();
}

#[test]
fn parses_server_limits() {
    let config: Config = toml::from_str(
        r#"
            [server]
            trusted_proxies = ["127.0.0.1", "10.0.0.0/8", "2001:db8::/32", "2a06:98c0::/29"]
            proxy_protocol = "v2"

            [server.limits]
            max_request_header_bytes = "32KiB"
            max_uri_bytes = 4096
            max_request_headers = 32
            max_request_body_bytes = "2MiB"
            "#,
    )
    .unwrap();

    assert_eq!(
        config.server.limits.max_request_header_bytes,
        ByteSize::from_bytes(32 * 1024)
    );
    assert_eq!(
        config.server.limits.max_uri_bytes,
        ByteSize::from_bytes(4096)
    );
    assert_eq!(config.server.limits.max_request_headers, 32);
    assert_eq!(
        config.server.limits.max_request_body_bytes,
        ByteSize::from_bytes(2 * 1024 * 1024)
    );
    assert_eq!(
        config.server.trusted_proxies,
        ["127.0.0.1", "10.0.0.0/8", "2001:db8::/32", "2a06:98c0::/29"]
    );
    assert_eq!(config.server.proxy_protocol, DownstreamProxyProtocol::V2);
    config.validate().unwrap();
}

#[test]
fn rejects_invalid_trusted_proxy_range() {
    let config: Config = toml::from_str(
        r#"
            [server]
            trusted_proxies = ["10.0.0.0/99"]
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidTrustedProxy {
            value: "10.0.0.0/99".to_owned()
        })
    );
}

#[test]
fn rejects_overbroad_trusted_proxy_ranges() {
    for value in [
        "0.0.0.0/0",
        "0.0.0.0",
        "10.0.0.0/7",
        "::/0",
        "::",
        "2001:db8::/28",
    ] {
        let config: Config = toml::from_str(&format!(
            r#"
                [server]
                trusted_proxies = ["{value}"]
                "#
        ))
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidTrustedProxy {
                value: value.to_owned()
            })
        );
    }
}

#[test]
fn rejects_proxy_protocol_without_trusted_proxies() {
    let config: Config = toml::from_str(
        r#"
            [server]
            proxy_protocol = "v1"
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidServerProxyProtocolPolicy {
            reason: "server.proxy_protocol requires server.trusted_proxies so client identity cannot be spoofed by direct peers"
        })
    );
}

#[test]
fn rejects_zero_server_limits() {
    let config: Config = toml::from_str(
        r#"
            [server.limits]
            max_uri_bytes = 0
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidLimit {
            field: "server.limits.max_uri_bytes"
        })
    );
}

#[test]
fn rejects_empty_listeners() {
    let config = Config {
        server: ServerConfig {
            listen: vec![],
            tls_listen: Vec::new(),
            default_vhost: None,
            trusted_proxies: Vec::new(),
            limits: ServerLimitsConfig::default(),
            ..ServerConfig::default()
        },
        admin: AdminConfig::default(),
        metrics: MetricsConfig::default(),
        tracing: TracingConfig::default(),
        logging: LoggingConfig::default(),
        headers: HeaderPolicyConfig::default(),
        tls: super::TlsConfig::default(),
        proxy: ProxyConfig::default(),
        compression: CompressionConfig::default(),
        cache: CacheConfig::default(),
        cache_purger: CachePurgerConfig::default(),
        web: WebConfig::default(),
        geoip: super::GeoIpConfig::default(),
        stream: super::StreamConfig::default(),
        udp: super::UdpConfig::default(),
        vhosts: vec![],
    };

    assert_eq!(config.validate(), Err(ConfigError::EmptyListeners));
}

#[test]
fn parses_strict_host_routing_mode() {
    let config: Config = toml::from_str(
        r#"
            [server.host_routing]
            strict = true
            "#,
    )
    .unwrap();

    assert!(config.server.host_routing.strict);
    config.validate().unwrap();
}

#[test]
fn rejects_invalid_tls_listener() {
    let config = Config {
        server: ServerConfig {
            tls_listen: vec!["localhost:8443".to_owned()],
            ..ServerConfig::default()
        },
        ..Config::default()
    };

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidListenAddress {
            address: "localhost:8443".to_owned()
        })
    );
}

#[test]
fn parses_https_redirect_config() {
    let config: Config = toml::from_str(
        r#"
            [server]
            listen = ["127.0.0.1:8080"]
            tls_listen = ["127.0.0.1:8443"]

            [server.https_redirect]
            enabled = true
            status = 301
            target_port = 8443

            [tls]
            enabled = true

            [[tls.certificates]]
            cert_path = "fullchain.pem"
            key_path = "key.pem"
            "#,
    )
    .unwrap();

    config.validate().unwrap();
    assert!(config.server.https_redirect.enabled);
    assert_eq!(config.server.https_redirect.status, 301);
    assert_eq!(config.server.https_redirect.target_port, Some(8443));
}

#[test]
fn rejects_https_redirect_without_tls_listener() {
    let config: Config = toml::from_str(
        r#"
            [server.https_redirect]
            enabled = true
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::HttpsRedirectWithoutTlsListener)
    );
}

#[test]
fn rejects_invalid_https_redirect_status() {
    let config: Config = toml::from_str(
        r#"
            [server]
            tls_listen = ["127.0.0.1:8443"]

            [server.https_redirect]
            enabled = true
            status = 200
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidHttpsRedirectStatus { status: 200 })
    );
}

#[test]
fn rejects_invalid_https_redirect_target_port() {
    let config: Config = toml::from_str(
        r#"
            [server]
            tls_listen = ["127.0.0.1:8443"]

            [server.https_redirect]
            enabled = true
            target_port = 0
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidHttpsRedirectTargetPort)
    );
}

#[test]
fn rejects_tls_listener_without_tls_enabled() {
    let config = Config {
        server: ServerConfig {
            tls_listen: vec!["127.0.0.1:8443".to_owned()],
            ..ServerConfig::default()
        },
        ..Config::default()
    };

    assert_eq!(config.validate(), Err(ConfigError::TlsListenerWithoutTls));
}

#[test]
fn rejects_tls_listener_without_static_certificate() {
    let config = Config {
        server: ServerConfig {
            tls_listen: vec!["127.0.0.1:8443".to_owned()],
            ..ServerConfig::default()
        },
        tls: super::TlsConfig {
            enabled: true,
            ..super::TlsConfig::default()
        },
        ..Config::default()
    };

    assert_eq!(
        config.validate(),
        Err(ConfigError::TlsListenerWithoutStaticCertificate)
    );
}

#[test]
fn accepts_tls_listener_with_static_certificate() {
    let config = Config {
        server: ServerConfig {
            tls_listen: vec!["127.0.0.1:8443".to_owned()],
            ..ServerConfig::default()
        },
        tls: super::TlsConfig {
            enabled: true,
            certificates: vec![super::StaticCertificateConfig {
                cert_path: PathBuf::from("fullchain.pem"),
                key_path: PathBuf::from("key.pem"),
            }],
            ..super::TlsConfig::default()
        },
        ..Config::default()
    };

    config.validate().unwrap();
}

#[test]
fn accepts_tls_listener_with_default_vhost_static_certificate() {
    let certificate = StaticCertificateConfig {
        cert_path: PathBuf::from("fullchain.pem"),
        key_path: PathBuf::from("key.pem"),
    };
    let config = Config {
        server: ServerConfig {
            tls_listen: vec!["127.0.0.1:8443".to_owned()],
            default_vhost: Some("example".to_owned()),
            ..ServerConfig::default()
        },
        tls: super::TlsConfig {
            enabled: true,
            ..super::TlsConfig::default()
        },
        vhosts: vec![VhostConfig {
            name: "example".to_owned(),
            hosts: vec!["example.test".to_owned()],
            max_request_body_bytes: None,
            access: Default::default(),
            rate_limit: Default::default(),
            concurrency: Default::default(),
            tls: VhostTlsConfig {
                enabled: true,
                certificate: Some(certificate),
                ..VhostTlsConfig::default()
            },
            acme_challenge: super::VhostAcmeChallengeConfig::default(),
            redirect: super::VhostRedirectConfig::default(),
            proxy: ProxyConfig::default(),
            cache: CacheConfig::default(),
            compression: None,
            headers: VhostHeaderPolicyConfig::default(),
            php: crate::config::PhpConfig::default(),
            web: WebConfig::default(),
            routes: Vec::new(),
        }],
        ..Config::default()
    };

    config.validate().unwrap();
}

#[cfg(feature = "acme")]
#[test]
fn accepts_tls_listener_with_default_vhost_acme_certificate_source() {
    let storage = secure_test_dir("config-default-vhost-acme-source");
    let config = Config {
        server: ServerConfig {
            tls_listen: vec!["127.0.0.1:8443".to_owned()],
            default_vhost: Some("example".to_owned()),
            ..ServerConfig::default()
        },
        tls: super::TlsConfig {
            enabled: true,
            acme: super::AcmeConfig {
                enabled: true,
                storage: Some(storage),
                contact_email: Some("admin@example.test".to_owned()),
                ..super::AcmeConfig::default()
            },
            ..super::TlsConfig::default()
        },
        vhosts: vec![VhostConfig {
            name: "example".to_owned(),
            hosts: vec!["example.test".to_owned()],
            max_request_body_bytes: None,
            access: Default::default(),
            rate_limit: Default::default(),
            concurrency: Default::default(),
            tls: VhostTlsConfig {
                enabled: true,
                acme: super::VhostAcmeConfig {
                    enabled: true,
                    issuer: None,
                    domains: Vec::new(),
                },
                ..VhostTlsConfig::default()
            },
            acme_challenge: super::VhostAcmeChallengeConfig::default(),
            redirect: super::VhostRedirectConfig::default(),
            proxy: ProxyConfig::default(),
            cache: CacheConfig::default(),
            compression: None,
            headers: VhostHeaderPolicyConfig::default(),
            php: crate::config::PhpConfig::default(),
            web: WebConfig::default(),
            routes: Vec::new(),
        }],
        ..Config::default()
    };

    config.validate().unwrap();
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
        tls: super::TlsConfig::default(),
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
        geoip: super::GeoIpConfig::default(),
        stream: super::StreamConfig::default(),
        udp: super::UdpConfig::default(),
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
fn rejects_empty_index_files() {
    let config = Config {
        server: ServerConfig::default(),
        admin: AdminConfig::default(),
        metrics: MetricsConfig::default(),
        tracing: TracingConfig::default(),
        logging: LoggingConfig::default(),
        headers: HeaderPolicyConfig::default(),
        tls: super::TlsConfig::default(),
        proxy: ProxyConfig::default(),
        compression: CompressionConfig::default(),
        cache: CacheConfig::default(),
        cache_purger: CachePurgerConfig::default(),
        web: WebConfig {
            root: Some(PathBuf::from("public")),
            index_files: vec![],
            deny_dotfiles: true,
            ..WebConfig::default()
        },
        geoip: super::GeoIpConfig::default(),
        stream: super::StreamConfig::default(),
        udp: super::UdpConfig::default(),
        vhosts: vec![],
    };

    assert_eq!(config.validate(), Err(ConfigError::EmptyIndexFiles));
}

#[test]
fn rejects_too_many_index_files() {
    let index_files = (0..=super::MAX_WEB_INDEX_FILES)
        .map(|index| format!("index-{index}.html"))
        .collect::<Vec<_>>();
    let config = Config {
        server: ServerConfig::default(),
        admin: AdminConfig::default(),
        metrics: MetricsConfig::default(),
        tracing: TracingConfig::default(),
        logging: LoggingConfig::default(),
        headers: HeaderPolicyConfig::default(),
        tls: super::TlsConfig::default(),
        proxy: ProxyConfig::default(),
        compression: CompressionConfig::default(),
        cache: CacheConfig::default(),
        cache_purger: CachePurgerConfig::default(),
        web: WebConfig {
            root: Some(PathBuf::from("public")),
            index_files,
            deny_dotfiles: true,
            ..WebConfig::default()
        },
        geoip: super::GeoIpConfig::default(),
        stream: super::StreamConfig::default(),
        udp: super::UdpConfig::default(),
        vhosts: vec![],
    };

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidConfigListLength {
            field: "web.index_files".to_owned(),
            max: super::MAX_WEB_INDEX_FILES,
        })
    );
}

#[test]
fn route_web_wraps_too_many_index_files() {
    let index_files = (0..=super::MAX_WEB_INDEX_FILES)
        .map(|index| format!("\"index-{index}.html\""))
        .collect::<Vec<_>>()
        .join(", ");
    let config: Config = toml::from_str(&format!(
        r#"
            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example.test"]

            [[vhosts.routes]]
            name = "static"
            path_prefix = "/static/"

            [vhosts.routes.web]
            root = "public"
            index_files = [{index_files}]
            "#
    ))
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::RouteSection {
            vhost: "gateway".to_owned(),
            route: "static".to_owned(),
            section: "web",
            source: Box::new(ConfigError::InvalidConfigListLength {
                field: "web.index_files".to_owned(),
                max: super::MAX_WEB_INDEX_FILES,
            })
        })
    );
}

#[test]
fn rejects_nested_index_files() {
    let config = Config {
        server: ServerConfig::default(),
        admin: AdminConfig::default(),
        metrics: MetricsConfig::default(),
        tracing: TracingConfig::default(),
        logging: LoggingConfig::default(),
        headers: HeaderPolicyConfig::default(),
        tls: super::TlsConfig::default(),
        proxy: ProxyConfig::default(),
        compression: CompressionConfig::default(),
        cache: CacheConfig::default(),
        cache_purger: CachePurgerConfig::default(),
        web: WebConfig {
            root: Some(PathBuf::from("public")),
            index_files: vec!["pages/index.html".to_owned()],
            deny_dotfiles: true,
            ..WebConfig::default()
        },
        geoip: super::GeoIpConfig::default(),
        stream: super::StreamConfig::default(),
        udp: super::UdpConfig::default(),
        vhosts: vec![],
    };

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidIndexFile {
            file: "pages/index.html".to_owned()
        })
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

#[test]
fn parses_vhosts() {
    let config: Config = toml::from_str(
        r#"
            [[vhosts]]
            name = "example.com"
            hosts = ["example.com", "www.example.com"]

            [vhosts.proxy]
            upstream = "127.0.0.1:3001"

            [vhosts.web]
            root = "/srv/sites/example"

            [vhosts.cache]
            enabled = true

            [vhosts.cache.memory]
            enabled = true
            "#,
    )
    .unwrap();

    assert_eq!(config.vhosts.len(), 1);
    assert!(config.vhosts[0].cache.enabled);
    assert_eq!(
        config.vhosts[0].normalized_hosts(),
        ["example.com".to_owned(), "www.example.com".to_owned()]
    );
    config.validate().unwrap();
}

#[test]
fn parses_vhost_and_route_access_policy() {
    let config: Config = toml::from_str(
            r#"
            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example.test"]

            [vhosts.access]
            allow = ["10.0.0.0/8", "2001:db8::/32"]
            deny = ["10.9.0.0/16"]
            require_client_cert = true
            allow_client_cert_sha256 = ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]

            [vhosts.rate_limit]
            enabled = true
            requests_per_second = 10
            burst = 20
            mode = "delay"
            max_delay_ms = 250

            [vhosts.concurrency]
            enabled = true
            max_in_flight = 100
            max_queue = 300
            queue_timeout_ms = 100

            [[vhosts.routes]]
            name = "admin"
            path_prefix = "/admin/"

            [vhosts.routes.access]
            allow = ["10.1.2.3"]

            [vhosts.routes.rate_limit]
            enabled = true
            requests_per_second = 2
            burst = 4
            status = 429

            [vhosts.routes.concurrency]
            enabled = true
            max_in_flight = 10
            max_queue = 20
            queue_timeout_ms = 50

            [vhosts.routes.proxy]
            upstream = "127.0.0.1:3000"
            "#,
        )
        .unwrap();

    config.validate().unwrap();
    assert_eq!(
        config.vhosts[0].access.allow,
        ["10.0.0.0/8", "2001:db8::/32"]
    );
    assert_eq!(config.vhosts[0].access.deny, ["10.9.0.0/16"]);
    assert!(config.vhosts[0].access.require_client_cert);
    assert_eq!(
        config.vhosts[0].access.allow_client_cert_sha256,
        ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
    );
    assert_eq!(config.vhosts[0].routes[0].access.allow, ["10.1.2.3"]);
    assert_eq!(config.vhosts[0].rate_limit.requests_per_second, 10);
    assert_eq!(config.vhosts[0].rate_limit.mode, RateLimitMode::Delay);
    assert_eq!(config.vhosts[0].rate_limit.max_delay_ms, 250);
    assert_eq!(config.vhosts[0].routes[0].rate_limit.burst, 4);
    assert_eq!(config.vhosts[0].concurrency.max_in_flight, 100);
    assert_eq!(config.vhosts[0].concurrency.max_queue, 300);
    assert_eq!(config.vhosts[0].concurrency.queue_timeout_ms, 100);
    assert_eq!(config.vhosts[0].routes[0].concurrency.max_in_flight, 10);
    assert_eq!(config.vhosts[0].routes[0].concurrency.max_queue, 20);
    assert_eq!(config.vhosts[0].routes[0].concurrency.queue_timeout_ms, 50);
}

#[test]
fn rejects_invalid_vhost_access_rule() {
    let config: Config = toml::from_str(
        r#"
            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example.test"]

            [vhosts.access]
            allow = ["10.0.0.0/99"]

            [vhosts.proxy]
            upstream = "127.0.0.1:3000"
            "#,
    )
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("vhosts.access.allow"), "{error}");
}

#[test]
fn rejects_invalid_vhost_client_cert_access_fingerprint() {
    let config: Config = toml::from_str(
        r#"
            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example.test"]

            [vhosts.access]
            allow_client_cert_sha256 = ["not-a-sha256"]

            [vhosts.proxy]
            upstream = "127.0.0.1:3000"
            "#,
    )
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(
        error.contains("vhosts.access.allow_client_cert_sha256"),
        "{error}"
    );
}

#[test]
fn rejects_invalid_vhost_rate_limit() {
    let config: Config = toml::from_str(
        r#"
            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example.test"]

            [vhosts.rate_limit]
            enabled = true
            requests_per_second = 0

            [vhosts.proxy]
            upstream = "127.0.0.1:3000"
            "#,
    )
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(
        error.contains("vhosts.rate_limit.requests_per_second"),
        "{error}"
    );
}

#[test]
fn rejects_invalid_vhost_concurrency_limit() {
    let config: Config = toml::from_str(
        r#"
            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example.test"]

            [vhosts.concurrency]
            enabled = true
            max_in_flight = 0

            [vhosts.proxy]
            upstream = "127.0.0.1:3000"
            "#,
    )
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(
        error.contains("vhosts.concurrency.max_in_flight"),
        "{error}"
    );

    let config: Config = toml::from_str(
        r#"
            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example.test"]

            [vhosts.concurrency]
            enabled = true
            max_in_flight = 1
            max_queue = 1000001

            [vhosts.proxy]
            upstream = "127.0.0.1:3000"
            "#,
    )
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("vhosts.concurrency.max_queue"), "{error}");
}

#[test]
fn parses_vhost_routes() {
    let config: Config = toml::from_str(
        r#"
            [server]
            regex_enabled = true

            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example"]
            max_request_body_bytes = "128MiB"

            [vhosts.acme_challenge]
            enabled = true
            upstreams = ["127.0.0.1:8080"]

            [[vhosts.routes]]
            name = "chat"
            path_prefix = "/chat/"
            methods = ["GET", "HEAD"]
            https_redirect_exempt = true
            strip_prefix = "/chat/"
            rewrite_prefix = "/backend/chat/"

            [vhosts.routes.grpc]
            enabled = true

            [vhosts.routes.proxy]
            upstreams = ["127.0.0.1:6012"]
            upstream_http_version = "http2"
            connect_timeout_secs = 5
            read_timeout_secs = 600
            send_timeout_secs = 600

            [[vhosts.routes]]
            name = "repo"
            path_prefix = "/repo"
            strip_prefix = "/repo"

            [vhosts.routes.web]
            root = "/srv/repo"

            [[vhosts.routes]]
            name = "versioned-api"
            path_regex = "^/api/v(?P<version>[0-9]+)/(?P<rest>.*)$"
            rewrite_template = "/internal/v{route.regex.version}/{route.regex.rest}"

            [vhosts.routes.proxy]
            upstreams = ["127.0.0.1:6013"]

            [[vhosts.routes]]
            name = "fallback"
            fallback = true

            [vhosts.routes.redirect]
            to = "https://gateway.example{uri}"
            status = 308
            "#,
    )
    .unwrap();

    config.validate().unwrap();
    assert_eq!(config.vhosts[0].routes.len(), 4);
    assert_eq!(
        config.vhosts[0].max_request_body_bytes,
        Some(ByteSize::from_bytes(128 * 1024 * 1024))
    );
    assert!(config.vhosts[0].acme_challenge.enabled);
    assert_eq!(
        config.vhosts[0].acme_challenge.upstreams,
        ["127.0.0.1:8080"]
    );
    assert_eq!(config.vhosts[0].routes[0].name, "chat");
    assert_eq!(config.vhosts[0].routes[0].methods, ["GET", "HEAD"]);
    assert!(config.vhosts[0].routes[0].grpc.enabled);
    assert!(config.vhosts[0].routes[0].https_redirect_exempt);
    assert_eq!(
        config.vhosts[0].routes[0].rewrite_prefix.as_deref(),
        Some("/backend/chat/")
    );
    assert_eq!(
        config.vhosts[0].routes[2].rewrite_template.as_deref(),
        Some("/internal/v{route.regex.version}/{route.regex.rest}")
    );
    assert_eq!(
        config.vhosts[0].routes[0]
            .proxy
            .as_ref()
            .unwrap()
            .primary_upstream(),
        "127.0.0.1:6012"
    );
    assert_eq!(
        config.vhosts[0].routes[0]
            .proxy
            .as_ref()
            .unwrap()
            .read_timeout_secs,
        Some(600)
    );
    assert_eq!(
        config.vhosts[0].routes[0]
            .proxy
            .as_ref()
            .unwrap()
            .upstream_http_version,
        UpstreamHttpVersion::Http2
    );
    assert_eq!(
        config.vhosts[0].routes[3].redirect.as_ref().unwrap().status,
        308
    );
}

#[test]
fn validates_regex_route_opt_in() {
    let config: Config = toml::from_str(
        r#"
            [server]
            regex_enabled = true

            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example"]

            [[vhosts.routes]]
            name = "versioned-api"
            path_regex = "^/api/v[0-9]+/"

            [vhosts.routes.proxy]
            upstreams = ["127.0.0.1:6012"]
            "#,
    )
    .unwrap();

    config.validate().unwrap();
}

#[test]
fn rejects_regex_route_without_server_opt_in() {
    let config: Config = toml::from_str(
        r#"
            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example"]

            [[vhosts.routes]]
            name = "versioned-api"
            path_regex = "^/api/v[0-9]+/"

            [vhosts.routes.proxy]
            upstreams = ["127.0.0.1:6012"]
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::RouteRegexDisabled {
            vhost: "gateway".to_owned(),
            route: "versioned-api".to_owned(),
        })
    );
}

#[test]
fn rejects_invalid_regex_route_pattern() {
    let config: Config = toml::from_str(
        r#"
            [server]
            regex_enabled = true

            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example"]

            [[vhosts.routes]]
            name = "bad"
            path_regex = "["

            [vhosts.routes.proxy]
            upstreams = ["127.0.0.1:6012"]
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidRouteRegex {
            vhost: "gateway".to_owned(),
            route: "bad".to_owned(),
        })
    );
}

#[test]
fn rejects_grpc_route_without_http2_upstream() {
    let config: Config = toml::from_str(
        r#"
            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example"]

            [[vhosts.routes]]
            name = "grpc"
            path_prefix = "/grpc/"

            [vhosts.routes.grpc]
            enabled = true

            [vhosts.routes.proxy]
            upstream = "127.0.0.1:6012"
            "#,
    )
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(
        error.contains("grpc policy is invalid") && error.contains("upstream_http_version"),
        "{error}"
    );
}

#[test]
fn rejects_invalid_vhost_body_limit() {
    let config: Config = toml::from_str(
        r#"
            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example"]
            max_request_body_bytes = "0B"

            [vhosts.proxy]
            upstreams = ["127.0.0.1:6010"]
            "#,
    )
    .unwrap();

    assert!(matches!(
        config.validate(),
        Err(ConfigError::InvalidVhostLimit {
            vhost,
            field: "max_request_body_bytes"
        }) if vhost == "gateway"
    ));
}

#[test]
fn rejects_too_many_server_listeners() {
    let listen = (0..=super::MAX_SERVER_LISTENERS)
        .map(|index| format!("\"127.0.0.1:{}\"", 10_000 + index))
        .collect::<Vec<_>>()
        .join(", ");
    let config: Config = toml::from_str(&format!(
        r#"
            [server]
            listen = [{listen}]
            "#,
    ))
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidConfigListLength {
            field: "server.listen".to_owned(),
            max: super::MAX_SERVER_LISTENERS,
        })
    );
}

#[test]
fn rejects_too_many_tls_listeners() {
    let tls_listen = (0..=super::MAX_SERVER_LISTENERS)
        .map(|index| format!("\"127.0.0.1:{}\"", 20_000 + index))
        .collect::<Vec<_>>()
        .join(", ");
    let config: Config = toml::from_str(&format!(
        r#"
            [server]
            tls_listen = [{tls_listen}]
            "#,
    ))
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidConfigListLength {
            field: "server.tls_listen".to_owned(),
            max: super::MAX_SERVER_LISTENERS,
        })
    );
}

#[test]
fn rejects_too_many_trusted_proxies() {
    let trusted_proxies = (0..=super::MAX_TRUSTED_PROXIES)
        .map(|index| format!("\"10.{}.0.0/16\"", index % 256))
        .collect::<Vec<_>>()
        .join(", ");
    let config: Config = toml::from_str(&format!(
        r#"
            [server]
            trusted_proxies = [{trusted_proxies}]
            "#,
    ))
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidConfigListLength {
            field: "server.trusted_proxies".to_owned(),
            max: super::MAX_TRUSTED_PROXIES,
        })
    );
}

#[test]
fn rejects_too_many_vhosts() {
    let vhosts = (0..=super::MAX_VHOSTS)
        .map(|index| {
            format!(
                r#"
                    [[vhosts]]
                    name = "site-{index}"
                    hosts = ["site-{index}.example.test"]
                    "#
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let config: Config = toml::from_str(&vhosts).unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidConfigListLength {
            field: "vhosts".to_owned(),
            max: super::MAX_VHOSTS,
        })
    );
}

#[test]
fn rejects_oversized_vhost_name() {
    let name = "v".repeat(super::MAX_VHOST_NAME_BYTES + 1);
    let config: Config = toml::from_str(&format!(
        r#"
            [[vhosts]]
            name = {name:?}
            hosts = ["gateway.example.test"]
            "#,
    ))
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidConfigNameLength {
            field: "vhosts.name",
            max: super::MAX_VHOST_NAME_BYTES,
        })
    );
}

#[test]
fn rejects_too_many_vhost_hosts() {
    let hosts = (0..=super::MAX_VHOST_HOSTS)
        .map(|index| format!("\"alias-{index}.example.test\""))
        .collect::<Vec<_>>()
        .join(", ");
    let config: Config = toml::from_str(&format!(
        r#"
            [[vhosts]]
            name = "gateway"
            hosts = [{hosts}]
            "#,
    ))
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidConfigListLength {
            field: "vhost \"gateway\".hosts".to_owned(),
            max: super::MAX_VHOST_HOSTS,
        })
    );
}

#[test]
fn rejects_too_many_vhost_routes() {
    let routes = (0..=super::MAX_VHOST_ROUTES)
        .map(|index| {
            format!(
                r#"
                    [[vhosts.routes]]
                    name = "route-{index}"
                    path_prefix = "/route-{index}/"
                    "#
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let config: Config = toml::from_str(&format!(
        r#"
            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example.test"]
            {routes}
            "#,
    ))
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidConfigListLength {
            field: "vhost \"gateway\".routes".to_owned(),
            max: super::MAX_VHOST_ROUTES,
        })
    );
}

#[test]
fn rejects_oversized_route_name() {
    let route_name = "r".repeat(super::MAX_ROUTE_NAME_BYTES + 1);
    let config: Config = toml::from_str(&format!(
        r#"
            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example.test"]

            [[vhosts.routes]]
            name = {route_name:?}
            path_prefix = "/assets/"

            [vhosts.routes.web]
            root = "/srv/assets"
            "#,
    ))
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidConfigNameLength {
            field: "vhosts.routes.name",
            max: super::MAX_ROUTE_NAME_BYTES,
        })
    );
}

#[test]
fn rejects_enabled_acme_challenge_without_upstream() {
    let config: Config = toml::from_str(
        r#"
            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example"]

            [vhosts.acme_challenge]
            enabled = true
            "#,
    )
    .unwrap();

    assert!(matches!(
        config.validate(),
        Err(ConfigError::MissingAcmeChallengeUpstream { vhost }) if vhost == "gateway"
    ));
}

#[test]
fn rejects_too_many_acme_challenge_upstreams() {
    let upstreams = (0..=super::MAX_ACME_CHALLENGE_UPSTREAMS)
        .map(|index| format!("\"acme-{index}.example.test:8080\""))
        .collect::<Vec<_>>()
        .join(", ");
    let config: Config = toml::from_str(&format!(
        r#"
            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example"]

            [vhosts.acme_challenge]
            enabled = true
            upstreams = [{upstreams}]
            "#,
    ))
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::TooManyAcmeChallengeUpstreams {
            vhost: "gateway".to_owned(),
            max: super::MAX_ACME_CHALLENGE_UPSTREAMS,
        })
    );
}

#[test]
fn rejects_duplicate_acme_challenge_upstreams() {
    let config: Config = toml::from_str(
        r#"
            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example"]

            [vhosts.acme_challenge]
            enabled = true
            upstreams = ["acme.example.test:8080", "ACME.example.test:8080"]
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::DuplicateAcmeChallengeUpstream {
            vhost: "gateway".to_owned(),
            upstream: "ACME.example.test:8080".to_owned(),
        })
    );
}

#[test]
fn rejects_enabled_vhost_redirect_without_target() {
    let config: Config = toml::from_str(
        r#"
            [[vhosts]]
            name = "www"
            hosts = ["www.example.test"]

            [vhosts.redirect]
            enabled = true
            "#,
    )
    .unwrap();

    assert!(matches!(
        config.validate(),
        Err(ConfigError::MissingVhostRedirectTarget { vhost }) if vhost == "www"
    ));
}

#[test]
fn rejects_vhost_redirect_with_explicit_fallback_route() {
    let config: Config = toml::from_str(
        r#"
            [[vhosts]]
            name = "www"
            hosts = ["www.example.test"]

            [vhosts.redirect]
            enabled = true
            to = "https://example.test{uri}"

            [[vhosts.routes]]
            name = "fallback"
            fallback = true

            [vhosts.routes.proxy]
            upstreams = ["127.0.0.1:3000"]
            "#,
    )
    .unwrap();

    assert!(matches!(
        config.validate(),
        Err(ConfigError::VhostRedirectConflictsWithFallback { vhost }) if vhost == "www"
    ));
}

#[test]
fn rejects_invalid_vhost_routes() {
    let config: Config = toml::from_str(
        r#"
            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example"]

            [[vhosts.routes]]
            name = "bad"
            path_exact = "/one"
            path_prefix = "/one/"

            [vhosts.routes.proxy]
            upstreams = ["127.0.0.1:6012"]
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidRouteMatcher {
            vhost: "gateway".to_owned(),
            route: "bad".to_owned(),
        })
    );

    let config: Config = toml::from_str(
        r#"
            [server]
            regex_enabled = true

            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example"]

            [[vhosts.routes]]
            name = "bad"
            path_prefix = "/api/"
            path_regex = "^/api/v[0-9]+/"

            [vhosts.routes.proxy]
            upstreams = ["127.0.0.1:6012"]
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidRouteMatcher {
            vhost: "gateway".to_owned(),
            route: "bad".to_owned(),
        })
    );

    let config: Config = toml::from_str(
        r#"
            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example"]

            [[vhosts.routes]]
            name = "bad"
            path_prefix = "/api/"
            methods = ["GET", "get"]

            [vhosts.routes.proxy]
            upstreams = ["127.0.0.1:6012"]
            "#,
    )
    .unwrap();

    assert!(matches!(
        config.validate(),
        Err(ConfigError::InvalidRouteMethods {
            vhost,
            route,
            ..
        }) if vhost == "gateway" && route == "bad"
    ));

    let config: Config = toml::from_str(
        r#"
            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example"]

            [[vhosts.routes]]
            name = "bad"
            path_prefix = "/one/"

            [vhosts.routes.redirect]
            to = "https://gateway.example{uri}"

            [vhosts.routes.proxy]
            upstreams = ["127.0.0.1:6012"]
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidRouteAction {
            vhost: "gateway".to_owned(),
            route: "bad".to_owned(),
        })
    );

    let config: Config = toml::from_str(
        r#"
            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example"]

            [[vhosts.routes]]
            name = "bad"
            path_prefix = "/one/"
            rewrite_prefix = "/upstream/"

            [vhosts.routes.proxy]
            upstreams = ["127.0.0.1:6012"]
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidRouteRewritePrefix {
            vhost: "gateway".to_owned(),
            route: "bad".to_owned(),
        })
    );

    let config: Config = toml::from_str(
        r#"
            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example"]

            [[vhosts.routes]]
            name = "bad"
            path_prefix = "/one/"
            strip_prefix = "/one/"
            rewrite_prefix = "/upstream/%2e%2e/"

            [vhosts.routes.proxy]
            upstreams = ["127.0.0.1:6012"]
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidRouteRewritePrefix {
            vhost: "gateway".to_owned(),
            route: "bad".to_owned(),
        })
    );

    let config: Config = toml::from_str(
        r#"
            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example"]

            [[vhosts.routes]]
            name = "bad"
            path_prefix = "/one/"
            strip_prefix = "/one/"
            rewrite_prefix = "/upstream/./"

            [vhosts.routes.proxy]
            upstreams = ["127.0.0.1:6012"]
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidRouteRewritePrefix {
            vhost: "gateway".to_owned(),
            route: "bad".to_owned(),
        })
    );

    let config: Config = toml::from_str(
        r#"
            [server]
            regex_enabled = true

            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example"]

            [[vhosts.routes]]
            name = "bad"
            path_prefix = "/api/"
            rewrite_template = "/internal/{route.regex.1}"

            [vhosts.routes.proxy]
            upstreams = ["127.0.0.1:6012"]
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidRouteRewriteTemplate {
            vhost: "gateway".to_owned(),
            route: "bad".to_owned(),
        })
    );

    let config: Config = toml::from_str(
        r#"
            [server]
            regex_enabled = true

            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example"]

            [[vhosts.routes]]
            name = "bad"
            path_regex = "^/api/(.*)$"
            rewrite_template = "/internal/{path}"

            [vhosts.routes.proxy]
            upstreams = ["127.0.0.1:6012"]
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidRouteRewriteTemplate {
            vhost: "gateway".to_owned(),
            route: "bad".to_owned(),
        })
    );
}

#[test]
fn rejects_duplicate_vhost_hosts() {
    let config = Config {
        server: ServerConfig::default(),
        admin: AdminConfig::default(),
        metrics: MetricsConfig::default(),
        tracing: TracingConfig::default(),
        logging: LoggingConfig::default(),
        headers: HeaderPolicyConfig::default(),
        tls: super::TlsConfig::default(),
        proxy: ProxyConfig::default(),
        compression: CompressionConfig::default(),
        cache: CacheConfig::default(),
        cache_purger: CachePurgerConfig::default(),
        web: WebConfig::default(),
        geoip: super::GeoIpConfig::default(),
        stream: super::StreamConfig::default(),
        udp: super::UdpConfig::default(),
        vhosts: vec![
            VhostConfig {
                name: "first.example".to_owned(),
                hosts: vec!["Example.com".to_owned()],
                max_request_body_bytes: None,
                access: Default::default(),
                rate_limit: Default::default(),
                concurrency: Default::default(),
                acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                redirect: crate::config::VhostRedirectConfig::default(),
                tls: super::VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: CacheConfig::default(),
                compression: None,
                headers: VhostHeaderPolicyConfig::default(),
                php: crate::config::PhpConfig::default(),
                web: WebConfig::default(),
                routes: Vec::new(),
            },
            VhostConfig {
                name: "second.example".to_owned(),
                hosts: vec!["example.com:443".to_owned()],
                max_request_body_bytes: None,
                access: Default::default(),
                rate_limit: Default::default(),
                concurrency: Default::default(),
                acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                redirect: crate::config::VhostRedirectConfig::default(),
                tls: super::VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: CacheConfig::default(),
                compression: None,
                headers: VhostHeaderPolicyConfig::default(),
                php: crate::config::PhpConfig::default(),
                web: WebConfig::default(),
                routes: Vec::new(),
            },
        ],
    };

    assert_eq!(
        config.validate(),
        Err(ConfigError::DuplicateVhostHost {
            host: "example.com".to_owned()
        })
    );
}

#[test]
fn rejects_unknown_default_vhost() {
    let config = Config {
        server: ServerConfig {
            listen: vec!["127.0.0.1:8080".to_owned()],
            tls_listen: Vec::new(),
            default_vhost: Some("missing".to_owned()),
            trusted_proxies: Vec::new(),
            limits: ServerLimitsConfig::default(),
            ..ServerConfig::default()
        },
        vhosts: vec![VhostConfig {
            name: "known".to_owned(),
            hosts: vec!["known.example".to_owned()],
            max_request_body_bytes: None,
            access: Default::default(),
            rate_limit: Default::default(),
            concurrency: Default::default(),
            acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
            redirect: crate::config::VhostRedirectConfig::default(),
            tls: super::VhostTlsConfig::default(),
            proxy: ProxyConfig::default(),
            cache: CacheConfig::default(),
            compression: None,
            headers: VhostHeaderPolicyConfig::default(),
            php: crate::config::PhpConfig::default(),
            web: WebConfig::default(),
            routes: Vec::new(),
        }],
        ..Config::default()
    };

    assert_eq!(
        config.validate(),
        Err(ConfigError::UnknownDefaultVhost {
            name: "missing".to_owned()
        })
    );
    let message = config.validate().unwrap_err().to_string();
    assert!(message.contains("include_conf_d = true"));
    assert!(message.contains("validate the config directory"));
}

#[test]
fn accepts_wildcard_vhost_host() {
    let config = Config {
        vhosts: vec![VhostConfig {
            name: "wild".to_owned(),
            hosts: vec!["*.example.com".to_owned()],
            max_request_body_bytes: None,
            access: Default::default(),
            rate_limit: Default::default(),
            concurrency: Default::default(),
            acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
            redirect: crate::config::VhostRedirectConfig::default(),
            tls: super::VhostTlsConfig::default(),
            proxy: ProxyConfig::default(),
            cache: CacheConfig::default(),
            compression: None,
            headers: VhostHeaderPolicyConfig::default(),
            php: crate::config::PhpConfig::default(),
            web: WebConfig::default(),
            routes: Vec::new(),
        }],
        ..Config::default()
    };

    assert_eq!(
        config.vhosts[0].normalized_hosts(),
        ["*.example.com".to_owned()]
    );
    config.validate().unwrap();
}

#[test]
fn loads_config_directory_in_sorted_order() {
    let dir = TestDir::new("config-dir");
    fs::create_dir_all(dir.child("site")).unwrap();
    fs::write(
        dir.child("00-server.toml"),
        r#"
            [server]
            listen = ["127.0.0.1:19090"]
            default_vhost = "example"
            "#,
    )
    .unwrap();
    fs::write(
        dir.child("10-vhost.toml"),
        r#"
            [[vhosts]]
            name = "example"
            hosts = ["example.test"]

            [vhosts.web]
            root = "site"
            "#,
    )
    .unwrap();
    fs::write(dir.child(".ignored.toml"), "this is not toml").unwrap();
    fs::write(dir.child("ignored.txt"), "ignored").unwrap();

    let config = Config::load(Some(dir.path())).unwrap();

    assert_eq!(config.server.listen, ["127.0.0.1:19090"]);
    assert_eq!(config.server.default_vhost, Some("example".to_owned()));
    assert_eq!(config.vhosts.len(), 1);
    assert_eq!(config.vhosts[0].web.root, Some(dir.child("site")));
}

#[test]
fn loading_main_config_file_also_loads_sibling_conf_d() {
    let dir = TestDir::new("config-file-with-conf-d");
    fs::create_dir_all(dir.child("conf.d")).unwrap();
    fs::create_dir_all(dir.child("conf.d/site")).unwrap();
    fs::write(
        dir.child("fluxheim.toml"),
        r#"
            include_conf_d = true

            [server]
            listen = ["127.0.0.1:19090"]
            default_vhost = "example"
            "#,
    )
    .unwrap();
    fs::write(
        dir.child("conf.d/10-vhost.toml"),
        r#"
            [[vhosts]]
            name = "example"
            hosts = ["example.test"]

            [vhosts.web]
            root = "site"
            "#,
    )
    .unwrap();

    let config = Config::load(Some(&dir.child("fluxheim.toml"))).unwrap();

    assert_eq!(config.server.default_vhost, Some("example".to_owned()));
    assert_eq!(config.vhosts.len(), 1);
    assert_eq!(config.vhosts[0].web.root, Some(dir.child("conf.d/site")));
}

#[test]
fn conf_d_server_trusted_proxies_extend_without_replacing_main_list() {
    let dir = TestDir::new("config-file-with-conf-d-trusted-proxies");
    fs::create_dir_all(dir.child("conf.d")).unwrap();
    fs::write(
        dir.child("fluxheim.toml"),
        r#"
            include_conf_d = true

            [server]
            listen = ["127.0.0.1:19090"]
            trusted_proxies = ["10.0.0.1/32"]
            "#,
    )
    .unwrap();
    fs::write(
        dir.child("conf.d/10-proxies.toml"),
        r#"
            [server]
            trusted_proxies = ["10.0.0.2/32", "10.0.0.1/32"]
            "#,
    )
    .unwrap();

    let config = Config::load(Some(&dir.child("fluxheim.toml"))).unwrap();

    assert_eq!(
        config.server.trusted_proxies,
        ["10.0.0.1/32", "10.0.0.2/32"]
    );
}

#[test]
fn conf_d_server_trusted_proxies_reject_global_replacement_attempt() {
    let dir = TestDir::new("config-file-with-conf-d-global-trusted-proxy");
    fs::create_dir_all(dir.child("conf.d")).unwrap();
    fs::write(
        dir.child("fluxheim.toml"),
        r#"
            include_conf_d = true

            [server]
            listen = ["127.0.0.1:19090"]
            trusted_proxies = ["10.0.0.1/32"]
            "#,
    )
    .unwrap();
    fs::write(
        dir.child("conf.d/99-broad-trust.toml"),
        r#"
            [server]
            trusted_proxies = ["0.0.0.0/0"]
            "#,
    )
    .unwrap();

    let error = Config::load(Some(&dir.child("fluxheim.toml"))).unwrap_err();
    assert!(error.to_string().contains("0.0.0.0/0"));
}

#[test]
fn conf_d_proxy_fragment_extends_without_replacing_main_trust_policy() {
    let dir = TestDir::new("config-file-with-conf-d-proxy-fragment");
    fs::create_dir_all(dir.child("conf.d")).unwrap();
    fs::write(
        dir.child("fluxheim.toml"),
        r#"
            include_conf_d = true

            [proxy]
            upstream = "origin.example.test:443"
            upstream_tls = true
            upstream_sni = "origin.example.test"
            upstream_verify_cert = true
            upstream_verify_hostname = true

            [proxy.auth_request]
            enabled = true
            url = "https://auth.example.test/check"
            "#,
    )
    .unwrap();
    fs::write(
        dir.child("conf.d/20-proxy-timeouts.toml"),
        r#"
            [proxy]
            connect_timeout_secs = 5
            "#,
    )
    .unwrap();

    let config = Config::load(Some(&dir.child("fluxheim.toml"))).unwrap();

    assert_eq!(
        config.proxy.upstream.as_deref(),
        Some("origin.example.test:443")
    );
    assert!(config.proxy.upstream_tls);
    assert_eq!(
        config.proxy.upstream_sni.as_deref(),
        Some("origin.example.test")
    );
    assert!(config.proxy.upstream_verify_cert);
    assert!(config.proxy.upstream_verify_hostname);
    assert!(config.proxy.auth_request.enabled);
    assert_eq!(
        config.proxy.auth_request.url.as_deref(),
        Some("https://auth.example.test/check")
    );
    assert_eq!(config.proxy.connect_timeout_secs, Some(5));
}

#[test]
fn conf_d_proxy_nested_fragments_merge_without_replacing_security_policy() {
    let dir = TestDir::new("config-file-with-conf-d-proxy-nested-fragment");
    let runtime_state_file = safe_child_path(
        &secure_test_dir("config-conf-d-proxy-lb-state"),
        "state.json",
    );
    fs::create_dir_all(dir.child("conf.d")).unwrap();
    fs::write(
        dir.child("fluxheim.toml"),
        format!(
            r#"
            include_conf_d = true

            [proxy]
            upstreams = ["origin-a.example.test:443", "origin-b.example.test:443"]

            [proxy.auth_request]
            enabled = true
            url = "https://auth.example.test/check"
            forward_headers = ["x-request-id"]
            allow_response_headers = ["x-user"]
            connect_timeout_secs = 2
            read_timeout_secs = 5

            [proxy.mirror]
            enabled = false
            base_url = "https://mirror.example.test"
            sample_per_mille = 250
            methods = ["GET"]
            forward_headers = ["x-request-id"]
            timeout_secs = 2
            max_in_flight = 32

            [proxy.load_balance]
            selection = "header-hash"
            hash_header = "x-session"
            max_iterations = 16
            all_down_status = 503
            runtime_state_file = "{}"

            [proxy.load_balance.health_check]
            enabled = true
            protocol = "http"
            path = "/healthz"
            expected_statuses = [200]

            [proxy.load_balance.persistence]
            enabled = true
            mode = "header"
            header = "x-session"
            ttl_secs = 600

            [proxy.load_balance.retry]
            enabled = true
            statuses = [502]
            budget_per_window = 10

            [proxy.load_balance.queue]
            max_waiting = 32
            timeout_ms = 250
            "#,
            runtime_state_file.display()
        ),
    )
    .unwrap();
    fs::write(
        dir.child("conf.d/20-proxy-nested-policy.toml"),
        r#"
            [proxy.auth_request]
            read_timeout_secs = 7

            [proxy.mirror]
            timeout_secs = 4

            [proxy.load_balance.passive_health]
            enabled = true
            consecutive_failure = 4
            "#,
    )
    .unwrap();

    let config = Config::load(Some(&dir.child("fluxheim.toml"))).unwrap();

    assert!(config.proxy.auth_request.enabled);
    assert_eq!(
        config.proxy.auth_request.url.as_deref(),
        Some("https://auth.example.test/check")
    );
    assert_eq!(config.proxy.auth_request.forward_headers, ["x-request-id"]);
    assert_eq!(config.proxy.auth_request.allow_response_headers, ["x-user"]);
    assert_eq!(config.proxy.auth_request.connect_timeout_secs, 2);
    assert_eq!(config.proxy.auth_request.read_timeout_secs, 7);

    assert!(!config.proxy.mirror.enabled);
    assert_eq!(
        config.proxy.mirror.base_url.as_deref(),
        Some("https://mirror.example.test")
    );
    assert_eq!(config.proxy.mirror.sample_per_mille, 250);
    assert_eq!(config.proxy.mirror.methods, ["GET"]);
    assert_eq!(config.proxy.mirror.forward_headers, ["x-request-id"]);
    assert_eq!(config.proxy.mirror.timeout_secs, 4);
    assert_eq!(config.proxy.mirror.max_in_flight, 32);

    assert_eq!(
        config.proxy.load_balance.selection,
        LoadBalanceSelection::HeaderHash
    );
    assert_eq!(
        config.proxy.load_balance.hash_header.as_deref(),
        Some("x-session")
    );
    assert_eq!(config.proxy.load_balance.max_iterations, 16);
    assert_eq!(config.proxy.load_balance.all_down_status, 503);
    assert_eq!(
        config.proxy.load_balance.runtime_state_file.as_deref(),
        Some(runtime_state_file.as_path())
    );
    assert!(config.proxy.load_balance.health_check.enabled);
    assert_eq!(
        config.proxy.load_balance.health_check.protocol,
        LoadBalanceHealthCheckProtocol::Http
    );
    assert_eq!(config.proxy.load_balance.health_check.path, "/healthz");
    assert_eq!(
        config.proxy.load_balance.health_check.expected_statuses,
        [200]
    );
    assert!(config.proxy.load_balance.persistence.enabled);
    assert_eq!(
        config.proxy.load_balance.persistence.mode,
        LoadBalancePersistenceMode::Header
    );
    assert_eq!(
        config.proxy.load_balance.persistence.header.as_deref(),
        Some("x-session")
    );
    assert_eq!(config.proxy.load_balance.persistence.ttl_secs, 600);
    assert!(config.proxy.load_balance.retry.enabled);
    assert_eq!(config.proxy.load_balance.retry.statuses, [502]);
    assert_eq!(config.proxy.load_balance.retry.budget_per_window, 10);
    assert_eq!(config.proxy.load_balance.queue.max_waiting, 32);
    assert_eq!(config.proxy.load_balance.queue.timeout_ms, 250);
    assert!(config.proxy.load_balance.passive_health.enabled);
    assert_eq!(
        config.proxy.load_balance.passive_health.consecutive_failure,
        4
    );

    #[cfg(not(feature = "privacy-mode"))]
    config.validate().unwrap();
    #[cfg(feature = "privacy-mode")]
    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidLoadBalanceSelection {
            reason: "proxy.load_balance.persistence is not available in privacy-mode builds"
        })
    );
}

#[test]
fn conf_d_admin_fragment_extends_without_replacing_main_auth_policy() {
    let dir = TestDir::new("config-file-with-conf-d-admin-fragment");
    let snapshot_store = secure_test_dir("config-conf-d-admin-snapshots");
    fs::create_dir_all(dir.child("conf.d")).unwrap();
    fs::write(
        dir.child("fluxheim.toml"),
        format!(
            r#"
                include_conf_d = true

                [admin]
                enabled = true
                listen = "127.0.0.1:19090"
                token_env = "FLUXHEIM_ADMIN_TOKEN"
                snapshot_store = "{}"

                [admin.health]
                response = "minimal"

                [admin.auth_throttle]
                per_source_failures = 3
                global_failures = 50
                "#,
            snapshot_store.display()
        ),
    )
    .unwrap();
    fs::write(
        dir.child("conf.d/20-admin-ops.toml"),
        r#"
            [admin.ops_socket]
            path = "fluxheim-ops.sock"
            "#,
    )
    .unwrap();

    let config = Config::load(Some(&dir.child("fluxheim.toml"))).unwrap();

    assert!(config.admin.enabled);
    assert_eq!(config.admin.listen, "127.0.0.1:19090");
    assert_eq!(
        config.admin.token_env.as_deref(),
        Some("FLUXHEIM_ADMIN_TOKEN")
    );
    assert_eq!(
        config.admin.snapshot_store.as_deref(),
        Some(snapshot_store.as_path())
    );
    assert_eq!(
        config.admin.health.response,
        AdminHealthResponseMode::Minimal
    );
    assert_eq!(config.admin.auth_throttle.per_source_failures, 3);
    assert_eq!(config.admin.auth_throttle.global_failures, 50);
    assert_eq!(
        config.admin.ops_socket.path,
        dir.child("conf.d/fluxheim-ops.sock")
    );
}

#[test]
fn conf_d_compression_fragment_keeps_main_resource_limits() {
    let dir = TestDir::new("config-file-with-conf-d-compression-fragment");
    fs::create_dir_all(dir.child("conf.d")).unwrap();
    fs::write(
        dir.child("fluxheim.toml"),
        r#"
            include_conf_d = true

            [compression]
            enabled = true
            gzip = true
            brotli = false
            min_bytes = "1KiB"
            max_input_bytes = "64MiB"
            max_output_bytes = "128MiB"
            "#,
    )
    .unwrap();
    fs::write(
        dir.child("conf.d/20-compression.toml"),
        r#"
            [compression]
            brotli = true
            "#,
    )
    .unwrap();

    let config = Config::load(Some(&dir.child("fluxheim.toml"))).unwrap();

    assert!(config.compression.enabled);
    assert!(config.compression.gzip);
    assert!(config.compression.brotli);
    assert_eq!(
        config.compression.max_input_bytes,
        ByteSize::from_bytes(64 * 1024 * 1024)
    );
    assert_eq!(
        config.compression.max_output_bytes,
        ByteSize::from_bytes(128 * 1024 * 1024)
    );
}

#[test]
fn conf_d_cache_fragment_keeps_main_disk_encryption_policy() {
    let dir = TestDir::new("config-file-with-conf-d-cache-fragment");
    fs::create_dir_all(dir.child("conf.d")).unwrap();
    fs::create_dir_all(dir.child("cache")).unwrap();
    fs::write(dir.child("cache.key"), "local-cache-key").unwrap();
    fs::write(
        dir.child("fluxheim.toml"),
        r#"
            include_conf_d = true

            [cache]
            enabled = true
            max_object_bytes = "16MiB"

            [cache.disk]
            enabled = true
            path = "cache"
            max_size_bytes = "256MiB"

            [cache.disk.encryption]
            enabled = true
            provider = "local"
            key_file = "cache.key"
            "#,
    )
    .unwrap();
    fs::write(
        dir.child("conf.d/20-cache-policy.toml"),
        r#"
            [cache]
            default_status_ttl_secs = 60
            "#,
    )
    .unwrap();

    let config = Config::load(Some(&dir.child("fluxheim.toml"))).unwrap();

    assert!(config.cache.enabled);
    assert!(config.cache.disk.enabled);
    assert!(config.cache.disk.encryption.enabled);
    assert_eq!(
        config.cache.disk.path.as_deref(),
        Some(dir.child("cache").as_path())
    );
    assert_eq!(
        config.cache.disk.encryption.key_file.as_deref(),
        Some(dir.child("cache.key").as_path())
    );
    assert_eq!(config.cache.default_status_ttl_secs, Some(60));
}

#[test]
fn conf_d_web_fragment_keeps_main_static_root_and_dotfile_policy() {
    let dir = TestDir::new("config-file-with-conf-d-web-fragment");
    fs::create_dir_all(dir.child("conf.d")).unwrap();
    fs::create_dir_all(dir.child("site")).unwrap();
    fs::write(
        dir.child("fluxheim.toml"),
        r#"
            include_conf_d = true

            [web]
            root = "site"
            deny_dotfiles = true
            index_files = ["index.html", "index.htm"]
            "#,
    )
    .unwrap();
    fs::write(
        dir.child("conf.d/20-web-listing.toml"),
        r#"
            [web.directory_listing]
            enabled = true
            "#,
    )
    .unwrap();

    let config = Config::load(Some(&dir.child("fluxheim.toml"))).unwrap();

    assert_eq!(
        config.web.root.as_deref(),
        Some(dir.child("site").as_path())
    );
    assert!(config.web.deny_dotfiles);
    assert_eq!(config.web.index_files, ["index.html", "index.htm"]);
    assert!(config.web.directory_listing.enabled);
}

#[test]
#[cfg(feature = "stream-proxy")]
fn conf_d_stream_fragment_keeps_main_routes() {
    let dir = TestDir::new("config-file-with-conf-d-stream-fragment");
    fs::create_dir_all(dir.child("conf.d")).unwrap();
    fs::write(
        dir.child("fluxheim.toml"),
        r#"
            include_conf_d = true

            [stream]
            enabled = true

            [[stream.routes]]
            name = "database"
            listen = ["127.0.0.1:19091"]
            upstream = "127.0.0.1:5432"
            upstream_tls = true
            upstream_sni = "db.example.test"
            upstream_verify_cert = true
            "#,
    )
    .unwrap();
    fs::write(
        dir.child("conf.d/20-stream-enabled.toml"),
        r#"
            [stream]
            enabled = true
            "#,
    )
    .unwrap();

    let config = Config::load(Some(&dir.child("fluxheim.toml"))).unwrap();

    assert!(config.stream.enabled);
    assert_eq!(config.stream.routes.len(), 1);
    assert_eq!(config.stream.routes[0].name, "database");
    assert!(config.stream.routes[0].upstream_tls);
    assert_eq!(
        config.stream.routes[0].upstream_sni.as_deref(),
        Some("db.example.test")
    );
}

#[test]
fn rejects_stream_tls_verified_ip_upstream_without_explicit_sni() {
    let config: Config = toml::from_str(
        r#"
            [stream]
            enabled = true

            [[stream.routes]]
            name = "database"
            listen = ["127.0.0.1:19091"]
            upstream = "127.0.0.1:5432"
            upstream_tls = true
            upstream_verify_cert = true
            "#,
    )
    .unwrap();

    #[cfg(feature = "stream-proxy")]
    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidStreamProxyPolicy {
            field: "stream.routes.upstream_sni",
            reason: "IP-addressed upstreams with upstream_tls and upstream_verify_cert require explicit upstream_sni"
        })
    );
    #[cfg(not(feature = "stream-proxy"))]
    assert_eq!(config.validate(), Err(ConfigError::StreamProxyNotCompiled));
}

#[test]
fn conf_d_parse_error_reports_source_file() {
    let dir = TestDir::new("config-file-with-bad-conf-d");
    fs::create_dir_all(dir.child("conf.d")).unwrap();
    fs::write(
        dir.child("fluxheim.toml"),
        r#"
            include_conf_d = true

            [server]
            listen = ["127.0.0.1:19090"]
            "#,
    )
    .unwrap();
    let bad_config = dir.child("conf.d/10-bad.toml");
    fs::write(
        &bad_config,
        "[vhosts.proxy.error_pages.web]\nroot = \"/tmp\"\n",
    )
    .unwrap();

    let error = Config::load(Some(&dir.child("fluxheim.toml"))).unwrap_err();
    let message = error.to_string();

    assert!(message.contains(&bad_config.display().to_string()));
    assert!(message.contains("failed to parse config"));
    assert!(message.contains("define [[vhosts.proxy.error_pages]]"));
}

#[test]
fn config_parse_error_hints_route_proxy_error_page_array() {
    let dir = TestDir::new("config-route-proxy-error-page-table");
    let config = dir.child("fluxheim.toml");
    fs::write(
        &config,
        r#"
            [[vhosts]]
            name = "site"
            hosts = ["site.example"]

            [[vhosts.routes]]
            name = "app"
            path_prefix = "/"

            [vhosts.routes.proxy.error_pages.web]
            root = "/srv/fluxheim/errors"
            "#,
    )
    .unwrap();

    let error = Config::load(Some(&config)).unwrap_err();
    let message = error.to_string();

    assert!(message.contains("failed to parse config"), "{message}");
    assert!(
        message.contains("define [[vhosts.routes.proxy.error_pages]]"),
        "{message}"
    );
}

#[test]
fn config_parse_error_hints_singular_vhost_typo() {
    let dir = TestDir::new("config-singular-vhost-typo");
    let config = dir.child("fluxheim.toml");
    fs::write(
        &config,
        r#"
            [[vhost]]
            name = "bad"
            hosts = ["bad.example"]
            "#,
    )
    .unwrap();

    let error = Config::load(Some(&config)).unwrap_err();
    let message = error.to_string();

    assert!(message.contains("failed to parse config"));
    assert!(message.contains("hint: virtual hosts are configured with [[vhosts]]"));
}

#[test]
fn config_parse_error_hints_vhost_table_before_array() {
    let dir = TestDir::new("config-vhost-table-before-array");
    let config = dir.child("fluxheim.toml");
    fs::write(
        &config,
        r#"
            [vhosts.proxy]
            upstreams = ["127.0.0.1:3000"]
            "#,
    )
    .unwrap();

    let error = Config::load(Some(&config)).unwrap_err();
    let message = error.to_string();

    assert!(message.contains("failed to parse config"), "{message}");
    assert!(
        message.contains("start each virtual host with [[vhosts]]"),
        "{message}"
    );
}

#[test]
fn config_parse_error_hints_proxy_array_table() {
    let dir = TestDir::new("config-vhost-proxy-array-table");
    let config = dir.child("fluxheim.toml");
    fs::write(
        &config,
        r#"
            [[vhosts]]
            name = "site"
            hosts = ["site.example"]

            [[vhosts.proxy]]
            upstreams = ["127.0.0.1:3000"]
            "#,
    )
    .unwrap();

    let error = Config::load(Some(&config)).unwrap_err();
    let message = error.to_string();

    assert!(message.contains("failed to parse config"), "{message}");
    assert!(
        message.contains("uses [vhosts.proxy], not [[vhosts.proxy]]"),
        "{message}"
    );
}

#[test]
fn config_parse_error_hints_route_action_field() {
    let dir = TestDir::new("config-route-action-field");
    let config = dir.child("fluxheim.toml");
    fs::write(
        &config,
        r#"
            [[vhosts]]
            name = "site"
            hosts = ["site.example"]

            [[vhosts.routes]]
            name = "app"
            path_prefix = "/"
            action = "proxy"
            "#,
    )
    .unwrap();

    let error = Config::load(Some(&config)).unwrap_err();
    let message = error.to_string();

    assert!(message.contains("failed to parse config"), "{message}");
    assert!(
        message.contains("routes select their action by defining one nested table"),
        "{message}"
    );
}

#[test]
fn config_parse_error_hints_route_table_before_array() {
    let dir = TestDir::new("config-route-table-before-array");
    let config = dir.child("fluxheim.toml");
    fs::write(
        &config,
        r#"
            [[vhosts]]
            name = "site"
            hosts = ["site.example"]

            [vhosts.routes.proxy]
            upstreams = ["127.0.0.1:3000"]
            "#,
    )
    .unwrap();

    let error = Config::load(Some(&config)).unwrap_err();
    let message = error.to_string();

    assert!(message.contains("failed to parse config"), "{message}");
    assert!(
        message.contains("start each route with [[vhosts.routes]]"),
        "{message}"
    );
}

#[test]
fn config_parse_error_hints_route_web_table_before_array() {
    let dir = TestDir::new("config-route-web-table-before-array");
    let config = dir.child("fluxheim.toml");
    fs::write(
        &config,
        r#"
            [[vhosts]]
            name = "site"
            hosts = ["site.example"]

            [vhosts.routes.web]
            root = "/srv/sites/site"
            "#,
    )
    .unwrap();

    let error = Config::load(Some(&config)).unwrap_err();
    let message = error.to_string();

    assert!(message.contains("failed to parse config"), "{message}");
    assert!(
        message.contains("start each route with [[vhosts.routes]]"),
        "{message}"
    );
}

#[test]
fn config_parse_error_hints_route_proxy_array_table() {
    let dir = TestDir::new("config-route-proxy-array-table");
    let config = dir.child("fluxheim.toml");
    fs::write(
        &config,
        r#"
            [[vhosts]]
            name = "site"
            hosts = ["site.example"]

            [[vhosts.routes]]
            name = "app"
            path_prefix = "/"

            [[vhosts.routes.proxy]]
            upstreams = ["127.0.0.1:3000"]
            "#,
    )
    .unwrap();

    let error = Config::load(Some(&config)).unwrap_err();
    let message = error.to_string();

    assert!(message.contains("failed to parse config"), "{message}");
    assert!(
        message.contains("route action/config tables use single-bracket tables"),
        "{message}"
    );
}

#[test]
fn config_parse_error_hints_route_web_array_table() {
    let dir = TestDir::new("config-route-web-array-table");
    let config = dir.child("fluxheim.toml");
    fs::write(
        &config,
        r#"
            [[vhosts]]
            name = "site"
            hosts = ["site.example"]

            [[vhosts.routes]]
            name = "assets"
            path_prefix = "/assets/"

            [[vhosts.routes.web]]
            root = "/srv/sites/site/assets"
            "#,
    )
    .unwrap();

    let error = Config::load(Some(&config)).unwrap_err();
    let message = error.to_string();

    assert!(message.contains("failed to parse config"), "{message}");
    assert!(
        message.contains("route action/config tables use single-bracket tables"),
        "{message}"
    );
}

#[test]
fn config_parse_error_hints_plural_vhost_tls_certificate_table() {
    let dir = TestDir::new("config-plural-vhost-tls-certificates");
    let config = dir.child("fluxheim.toml");
    fs::write(
        &config,
        r#"
            [[vhosts]]
            name = "site"
            hosts = ["site.example"]

            [vhosts.tls]
            enabled = true

            [[vhosts.tls.certificates]]
            cert_path = "/etc/fluxheim/tls/site/fullchain.pem"
            key_path = "/etc/fluxheim/tls/site/privkey.pem"
            "#,
    )
    .unwrap();

    let error = Config::load(Some(&config)).unwrap_err();
    let message = error.to_string();

    assert!(message.contains("failed to parse config"));
    assert!(message.contains("hint: vhost TLS uses [vhosts.tls.certificate]"));
}

#[test]
fn conf_d_tls_acme_fragment_preserves_main_tls_settings() {
    let dir = TestDir::new("config-file-with-tls-acme-conf-d");
    fs::create_dir_all(dir.child("conf.d")).unwrap();
    fs::create_dir_all(dir.child("site")).unwrap();
    fs::write(dir.child("site/index.html"), "ok").unwrap();
    fs::write(
        dir.child("fluxheim.toml"),
        r#"
            include_conf_d = true

            [server]
            listen = ["127.0.0.1:19090"]
            default_vhost = "example"

            [tls]
            enabled = true
            backend = "rustls"
            "#,
    )
    .unwrap();
    fs::write(
        dir.child("conf.d/acme.toml"),
        format!(
            r#"
                [tls.acme]
                enabled = true
                storage = "{}"
                contact_email = "admin@example.test"
                default_issuer = "letsencrypt"
                challenge = "http-01"
                "#,
            dir.child("acme").display()
        ),
    )
    .unwrap();
    fs::write(
        dir.child("conf.d/vhost.toml"),
        format!(
            r#"
                [[vhosts]]
                name = "example"
                hosts = ["example.test"]

                [vhosts.tls]
                enabled = true

                [vhosts.tls.acme]
                enabled = true
                domains = ["example.test"]

                [vhosts.web]
                root = "{}"
                "#,
            dir.child("site").display()
        ),
    )
    .unwrap();

    let config = Config::load(Some(&dir.child("fluxheim.toml"))).unwrap();

    assert!(config.tls.enabled);
    assert!(config.tls.acme.enabled);
    assert_eq!(config.vhosts.len(), 1);
    assert!(config.vhosts[0].tls.enabled);
    assert!(config.vhosts[0].tls.acme.enabled);
}

#[test]
fn loading_main_config_file_does_not_load_conf_d_without_opt_in() {
    let dir = TestDir::new("config-file-with-conf-d-no-opt-in");
    fs::create_dir_all(dir.child("conf.d")).unwrap();
    fs::write(
        dir.child("fluxheim.toml"),
        r#"
            [server]
            listen = ["127.0.0.1:19090"]
            "#,
    )
    .unwrap();
    fs::write(
        dir.child("conf.d/10-vhost.toml"),
        r#"
            [[vhosts]]
            name = "example"
            hosts = ["example.test"]
            "#,
    )
    .unwrap();

    let config = Config::load(Some(&dir.child("fluxheim.toml"))).unwrap();

    assert!(config.vhosts.is_empty());
}

#[test]
fn loading_config_directory_also_loads_conf_d_after_top_level_files() {
    let dir = TestDir::new("config-dir-with-conf-d");
    fs::create_dir_all(dir.child("conf.d/site")).unwrap();
    fs::write(
        dir.child("00-server.toml"),
        r#"
            [server]
            listen = ["127.0.0.1:19090"]
            default_vhost = "example"
            "#,
    )
    .unwrap();
    fs::write(
        dir.child("conf.d/10-vhost.toml"),
        r#"
            [[vhosts]]
            name = "example"
            hosts = ["example.test"]

            [vhosts.web]
            root = "site"
            "#,
    )
    .unwrap();

    let config = Config::load(Some(dir.path())).unwrap();

    assert_eq!(config.server.default_vhost, Some("example".to_owned()));
    assert_eq!(config.vhosts.len(), 1);
    assert_eq!(config.vhosts[0].web.root, Some(dir.child("conf.d/site")));
}

#[test]
fn rejects_config_directory_with_too_many_toml_files() {
    let dir = TestDir::new("config-dir-too-many-files");
    for index in 0..=super::MAX_CONFIG_DIRECTORY_FILES {
        fs::write(dir.child(&format!("{index:03}.toml")), "[server]\n").unwrap();
    }

    let error = Config::load(Some(dir.path())).unwrap_err();

    assert!(
        matches!(error, ConfigLoadError::Read(error) if error.kind() == std::io::ErrorKind::InvalidData)
    );
}

#[test]
fn resolves_relative_cache_disk_paths_from_config_file() {
    let dir = TestDir::new("cache-path");
    fs::write(
        dir.child("fluxheim.toml"),
        r#"
            [cache.disk]
            enabled = true
            path = "cache"
            max_size_bytes = "1GiB"
            "#,
    )
    .unwrap();

    let config = Config::load(Some(&dir.child("fluxheim.toml"))).unwrap();

    assert_eq!(config.cache.disk.path, Some(dir.child("cache")));
}

#[test]
fn resolves_relative_server_process_paths_from_config_file() {
    let dir = TestDir::new("server-process-paths");
    fs::write(
        dir.child("fluxheim.toml"),
        r#"
            [server.process]
            error_log = "logs/error.log"
            pid_file = "run/fluxheim.pid"
            upgrade_sock = "run/fluxheim-upgrade.sock"
            "#,
    )
    .unwrap();

    let config = Config::load(Some(&dir.child("fluxheim.toml"))).unwrap();

    assert_eq!(
        config.server.process.error_log,
        Some(dir.child("logs/error.log"))
    );
    assert_eq!(
        config.server.process.pid_file,
        dir.child("run/fluxheim.pid")
    );
    assert_eq!(
        config.server.process.upgrade_sock,
        dir.child("run/fluxheim-upgrade.sock")
    );
}

#[test]
fn resolves_relative_logging_file_path_from_config_file() {
    let dir = TestDir::new("logging-file-path");
    fs::write(
        dir.child("fluxheim.toml"),
        r#"
            [logging.file]
            path = "logs/fluxheim.log"
            "#,
    )
    .unwrap();

    let config = Config::load(Some(&dir.child("fluxheim.toml"))).unwrap();

    assert_eq!(
        config.logging.file.path,
        Some(dir.child("logs/fluxheim.log"))
    );
}

#[test]
fn resolves_relative_tls_paths_from_config_file() {
    let dir = TestDir::new("tls-paths");
    fs::write(
        dir.child("fluxheim.toml"),
        r#"
            [[tls.certificates]]
            cert_path = "tls/fullchain.pem"
            key_path = "tls/key.pem"

            [tls.acme]
            storage = "acme"

            [[vhosts]]
            name = "example"
            hosts = ["example.test"]

            [vhosts.tls.certificate]
            cert_path = "vhosts/example/fullchain.pem"
            key_path = "vhosts/example/key.pem"
            "#,
    )
    .unwrap();

    let config = Config::load(Some(&dir.child("fluxheim.toml"))).unwrap();

    assert_eq!(
        config.tls.certificates[0].cert_path,
        dir.child("tls/fullchain.pem")
    );
    assert_eq!(config.tls.acme.storage, Some(dir.child("acme")));
    assert_eq!(
        config.vhosts[0].tls.certificate.as_ref().unwrap().key_path,
        dir.child("vhosts/example/key.pem")
    );
}

#[test]
fn rejects_config_relative_paths_with_parent_traversal() {
    let dir = TestDir::new("unsafe-paths");
    fs::write(
        dir.child("fluxheim.toml"),
        r#"
            [web]
            root = "../outside"
            "#,
    )
    .unwrap();

    let error = Config::load(Some(&dir.child("fluxheim.toml"))).unwrap_err();

    assert!(matches!(
        error,
        ConfigLoadError::Validate(ConfigError::UnsafePath { .. })
    ));
}

#[cfg(unix)]
#[test]
fn rejects_runtime_path_below_symlinked_directory() {
    let dir = TestDir::new("runtime-path-parent-symlink");
    let real_dir = dir.child("real");
    let symlink_dir = dir.child("linked");
    fs::create_dir_all(safe_child_path(&real_dir, "public")).unwrap();
    std::os::unix::fs::symlink(&real_dir, &symlink_dir).unwrap();
    fs::write(
        dir.child("fluxheim.toml"),
        r#"
            [web]
            root = "linked/public"
            "#,
    )
    .unwrap();

    let error = Config::load(Some(&dir.child("fluxheim.toml"))).unwrap_err();

    assert!(matches!(
        error,
        ConfigLoadError::Validate(ConfigError::UnsafePath { field, .. })
            if field == "web.root"
    ));
}

#[cfg(unix)]
#[test]
fn rejects_symlinked_runtime_path() {
    let dir = TestDir::new("runtime-path-symlink");
    let real_root = dir.child("public-real");
    let symlink_root = dir.child("public");
    fs::create_dir(&real_root).unwrap();
    std::os::unix::fs::symlink(&real_root, &symlink_root).unwrap();
    fs::write(
        dir.child("fluxheim.toml"),
        r#"
            [web]
            root = "public"
            "#,
    )
    .unwrap();

    let error = Config::load(Some(&dir.child("fluxheim.toml"))).unwrap_err();

    assert!(matches!(
        error,
        ConfigLoadError::Validate(ConfigError::UnsafePath { field, .. })
            if field == "web.root"
    ));
}

#[cfg(unix)]
#[test]
fn accepts_final_php_root_symlink_when_enabled() {
    let dir = TestDir::new("php-root-final-symlink");
    let real_root = dir.child("releases/current");
    let symlink_root = dir.child("public");
    fs::create_dir_all(&real_root).unwrap();
    std::os::unix::fs::symlink(&real_root, &symlink_root).unwrap();
    fs::write(
        dir.child("fluxheim.toml"),
        r#"
            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "public"
            resolve_root_symlink = true

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            allow_private_tcp_upstreams = true
            "#,
    )
    .unwrap();

    let config = Config::load(Some(&dir.child("fluxheim.toml"))).unwrap();

    assert_eq!(
        config.vhosts[0].php.root.as_deref(),
        Some(symlink_root.as_path())
    );
    assert!(config.vhosts[0].php.resolve_root_symlink);
}

#[cfg(unix)]
#[test]
fn rejects_existing_php_fpm_root_symlink() {
    let dir = TestDir::new("php-fpm-root-symlink");
    let local_root = dir.child("local-public");
    let fpm_real_root = dir.child("fpm-real-public");
    let fpm_symlink_root = dir.child("fpm-public");
    fs::create_dir_all(&local_root).unwrap();
    fs::create_dir_all(&fpm_real_root).unwrap();
    std::os::unix::fs::symlink(&fpm_real_root, &fpm_symlink_root).unwrap();
    fs::write(
        dir.child("fluxheim.toml"),
        r#"
            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "local-public"
            fpm_root = "fpm-public"

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            allow_private_tcp_upstreams = true
            "#,
    )
    .unwrap();

    let error = Config::load(Some(&dir.child("fluxheim.toml"))).unwrap_err();

    assert!(matches!(
        error,
        ConfigLoadError::Validate(ConfigError::VhostSection {
            vhost,
            section: "php",
            source,
        }) if vhost == "php"
            && matches!(
                *source,
                ConfigError::UnsafePath { ref field, .. } if field == "vhosts.php.fpm_root"
            )
    ));
}

#[cfg(unix)]
#[test]
fn rejects_php_root_below_symlinked_parent_when_final_symlink_enabled() {
    let dir = TestDir::new("php-root-parent-symlink");
    let real_dir = dir.child("real");
    let symlink_dir = dir.child("linked");
    fs::create_dir_all(safe_child_path(&real_dir, "public")).unwrap();
    std::os::unix::fs::symlink(&real_dir, &symlink_dir).unwrap();
    fs::write(
        dir.child("fluxheim.toml"),
        r#"
            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "linked/public"
            resolve_root_symlink = true

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            allow_private_tcp_upstreams = true
            "#,
    )
    .unwrap();

    let error = Config::load(Some(&dir.child("fluxheim.toml"))).unwrap_err();

    assert!(matches!(
        error,
        ConfigLoadError::Validate(ConfigError::VhostSection {
            vhost,
            section: "php",
            source,
        }) if vhost == "php"
            && matches!(
                *source,
                ConfigError::UnsafePath { ref field, .. } if field == "vhosts.php.root"
            )
    ));
}

#[test]
fn rejects_non_toml_config_file() {
    let dir = TestDir::new("non-toml-config");
    let path = dir.child("fluxheim.txt");
    fs::write(&path, "[server]\n").unwrap();

    let error = Config::load(Some(&path)).unwrap_err();

    assert!(matches!(error, ConfigLoadError::InvalidPath { .. }));
}

#[test]
fn rejects_oversized_config_file() {
    let dir = TestDir::new("oversized-config");
    let path = dir.child("fluxheim.toml");
    fs::write(
        &path,
        vec![b'#'; (super::MAX_CONFIG_FILE_BYTES + 1) as usize],
    )
    .unwrap();

    let error = Config::load(Some(&path)).unwrap_err();

    assert!(
        matches!(error, ConfigLoadError::Read(error) if error.kind() == std::io::ErrorKind::InvalidData)
    );
}

#[cfg(unix)]
#[test]
fn rejects_symlinked_config_file() {
    let dir = TestDir::new("config-file-symlink");
    let real_path = dir.child("real.toml");
    let symlink_path = dir.child("fluxheim.toml");
    fs::write(&real_path, "[server]\n").unwrap();
    std::os::unix::fs::symlink(&real_path, &symlink_path).unwrap();

    let error = Config::load(Some(&symlink_path)).unwrap_err();

    assert!(matches!(error, ConfigLoadError::InvalidPath { .. }));
}

#[cfg(unix)]
#[test]
fn rejects_symlinked_config_directory_source() {
    let dir = TestDir::new("config-dir-symlink");
    let real_dir = dir.child("real");
    let symlink_dir = dir.child("linked");
    fs::create_dir(&real_dir).unwrap();
    fs::write(safe_child_path(&real_dir, "fluxheim.toml"), "[server]\n").unwrap();
    std::os::unix::fs::symlink(&real_dir, &symlink_dir).unwrap();

    let error = Config::load(Some(&symlink_dir)).unwrap_err();

    assert!(matches!(error, ConfigLoadError::InvalidPath { .. }));
}

#[cfg(unix)]
#[test]
fn rejects_config_source_below_symlinked_directory() {
    let dir = TestDir::new("config-dir-parent-symlink");
    let real_dir = dir.child("real");
    let symlink_dir = dir.child("linked");
    fs::create_dir(&real_dir).unwrap();
    fs::write(safe_child_path(&real_dir, "fluxheim.toml"), "[server]\n").unwrap();
    std::os::unix::fs::symlink(&real_dir, &symlink_dir).unwrap();

    let error = Config::load(Some(&safe_child_path(&symlink_dir, "fluxheim.toml"))).unwrap_err();

    assert!(matches!(error, ConfigLoadError::InvalidPath { .. }));
}

#[cfg(unix)]
#[test]
fn ignores_symlinked_config_directory_entries() {
    let dir = TestDir::new("config-dir-entry-symlink");
    let outside_dir = TestDir::new("config-dir-entry-symlink-outside");
    let outside = outside_dir.child("outside.toml");
    fs::write(
        dir.child("00-server.toml"),
        r#"
            [server]
            listen = ["127.0.0.1:19090"]
            "#,
    )
    .unwrap();
    fs::write(
        &outside,
        r#"
            [[vhosts]]
            name = "linked"
            hosts = ["linked.example"]
            "#,
    )
    .unwrap();
    std::os::unix::fs::symlink(&outside, dir.child("10-linked.toml")).unwrap();

    let config = Config::load(Some(dir.path())).unwrap();

    assert_eq!(config.server.listen, ["127.0.0.1:19090"]);
    assert!(config.vhosts.is_empty());
}

struct TestDir {
    path: PathBuf,
}

impl TestDir {
    fn new(label: &str) -> Self {
        let path = unique_temp_path(label);
        fs::create_dir_all(&path).unwrap();
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn child(&self, name: &str) -> PathBuf {
        safe_relative_path(&self.path, name)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
