use std::fs;
use std::path::Path;
use std::path::PathBuf;

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
use super::{CachePeerConfig, CachePeerFillConfig};
use crate::test_support::{safe_child_path, safe_relative_path, unique_temp_path};
#[cfg(unix)]
use crate::test_support::{unique_group_writable_child, unique_world_writable_child};
use proptest::prelude::*;

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

#[cfg(feature = "geoip")]
#[test]
fn geoip_config_accepts_local_mmdb_providers() {
    let config: Config = toml::from_str(
        r#"
            [geoip]
            enabled = true
            fallback_enabled = true

            [[geoip.databases]]
            provider = "maxmind"
            path = "/var/lib/fluxheim/geo/GeoLite2-Country.mmdb"

            [[geoip.databases]]
            provider = "circl-geo-open"
            path = "/var/lib/fluxheim/geo/circl-country.mmdb"
            "#,
    )
    .unwrap();

    config.validate().unwrap();
}

#[cfg(not(feature = "geoip"))]
#[test]
fn geoip_enabled_requires_geoip_feature() {
    let config: Config = toml::from_str(
        r#"
            [geoip]
            enabled = true
            fallback_enabled = true

            [[geoip.databases]]
            provider = "maxmind"
            path = "/var/lib/fluxheim/geo/GeoLite2-Country.mmdb"
            "#,
    )
    .unwrap();

    assert!(matches!(
        config.validate(),
        Err(ConfigError::GeoIpNotCompiled)
    ));
}

#[test]
fn geoip_access_rules_require_global_geoip() {
    let config: Config = toml::from_str(
        r#"
            [[vhosts]]
            name = "app"
            hosts = ["example.test"]

            [vhosts.access]
            deny_countries = ["RU"]
            "#,
    )
    .unwrap();

    assert!(matches!(
        config.validate(),
        Err(ConfigError::InvalidGeoIpPolicy {
            field: "vhosts.access",
            ..
        })
    ));
}

#[test]
fn compression_config_validates_bounds() {
    let config: Config = toml::from_str(
        r#"
            [compression]
            enabled = true
            gzip = true
            zstd = true
            brotli = true
            min_bytes = "2KiB"
            max_input_bytes = "4KiB"
            max_output_bytes = "8KiB"
            gzip_level = 6
            zstd_level = 5
            brotli_quality = 5
            "#,
    )
    .unwrap();

    assert_eq!(config.compression.min_bytes.as_u64(), 2048);
    assert_eq!(config.compression.max_output_bytes.as_u64(), 8192);
    assert!(config.compression.zstd);
    assert!(config.compression.brotli);
    assert_eq!(config.compression.zstd_level, 5);
    assert_eq!(config.compression.brotli_quality, 5);
    config.validate().unwrap();

    let invalid_level: Config = toml::from_str(
        r#"
            [compression]
            enabled = true
            gzip_level = 10
            "#,
    )
    .unwrap();
    assert!(matches!(
        invalid_level.validate(),
        Err(ConfigError::InvalidCompressionPolicy {
            field: "compression.gzip_level"
        })
    ));

    let invalid_zstd_level: Config = toml::from_str(
        r#"
            [compression]
            enabled = true
            zstd_level = 20
            "#,
    )
    .unwrap();
    assert!(matches!(
        invalid_zstd_level.validate(),
        Err(ConfigError::InvalidCompressionPolicy {
            field: "compression.zstd_level"
        })
    ));

    let invalid_brotli_quality: Config = toml::from_str(
        r#"
            [compression]
            enabled = true
            brotli_quality = 12
            "#,
    )
    .unwrap();
    assert!(matches!(
        invalid_brotli_quality.validate(),
        Err(ConfigError::InvalidCompressionPolicy {
            field: "compression.brotli_quality"
        })
    ));

    let invalid_bounds: Config = toml::from_str(
        r#"
            [compression]
            enabled = true
            min_bytes = "8KiB"
            max_input_bytes = "4KiB"
            "#,
    )
    .unwrap();
    assert!(matches!(
        invalid_bounds.validate(),
        Err(ConfigError::InvalidCompressionPolicy {
            field: "compression.min_bytes"
        })
    ));

    let invalid_output_bounds: Config = toml::from_str(
        r#"
            [compression]
            enabled = true
            min_bytes = "8KiB"
            max_input_bytes = "16KiB"
            max_output_bytes = "4KiB"
            "#,
    )
    .unwrap();
    assert!(matches!(
        invalid_output_bounds.validate(),
        Err(ConfigError::InvalidCompressionPolicy {
            field: "compression.max_output_bytes"
        })
    ));

    let vhost_override: Config = toml::from_str(
        r#"
            [compression]
            enabled = false

            [[vhosts]]
            name = "docs"
            hosts = ["docs.example"]

            [vhosts.compression]
            enabled = true
            gzip = false
            zstd = true
            min_bytes = "1KiB"
            max_input_bytes = "2MiB"
            "#,
    )
    .unwrap();
    vhost_override.validate().unwrap();
    let compression = vhost_override.vhosts[0].compression.as_ref().unwrap();
    assert!(compression.enabled);
    assert!(!compression.gzip);
    assert!(compression.zstd);

    let route_override: Config = toml::from_str(
        r#"
            [compression]
            enabled = false

            [[vhosts]]
            name = "site"
            hosts = ["site.example"]

            [vhosts.compression]
            enabled = false

            [[vhosts.routes]]
            name = "uploads"
            path_prefix = "/wp-content/uploads/"

            [vhosts.routes.proxy]
            upstream = "127.0.0.1:8080"

            [vhosts.routes.compression]
            enabled = true
            gzip = true
            min_bytes = "1KiB"
            max_input_bytes = "2MiB"
            "#,
    )
    .unwrap();
    route_override.validate().unwrap();
    let route_compression = route_override.vhosts[0].routes[0]
        .compression
        .as_ref()
        .unwrap();
    assert!(route_compression.enabled);
    assert!(route_compression.gzip);
}

#[test]
fn parses_minimal_toml() {
    let config: Config = toml::from_str(
        r#"
            [server]
            listen = ["127.0.0.1:18080"]
            tls_listen = ["127.0.0.1:18443"]

            [proxy]
            upstream = "origin.example.test:443"
            upstream_tls = true
            upstream_sni = "origin.example.test"
            downstream_write_timeout_secs = 20
            downstream_min_send_rate_bytes_per_sec = 8192
            "#,
    )
    .unwrap();

    assert_eq!(config.server.listen, ["127.0.0.1:18080"]);
    assert_eq!(config.server.tls_listen, ["127.0.0.1:18443"]);
    assert_eq!(
        config.proxy.upstream.as_deref(),
        Some("origin.example.test:443")
    );
    assert!(config.proxy.upstream_tls);
    assert_eq!(config.proxy.upstream_sni(), "origin.example.test");
    assert_eq!(config.proxy.downstream_write_timeout_secs, Some(20));
    assert_eq!(
        config.proxy.downstream_min_send_rate_bytes_per_sec,
        Some(8192)
    );
}

#[test]
fn parses_server_process_settings() {
    let root = unique_temp_path("config-process-settings");
    fs::create_dir(&root).unwrap();
    let error_log = safe_child_path(&root, "error.log");
    let pid_file = safe_child_path(&root, "fluxheim.pid");
    let upgrade_sock = safe_child_path(&root, "fluxheim-upgrade.sock");
    let certificate_reload_sock = safe_child_path(&root, "fluxheim-cert-reload.sock");
    let config: Config = toml::from_str(&format!(
        r#"
            [server.process]
            daemon = false
            error_log = "{}"
            pid_file = "{}"
            upgrade_sock = "{}"
            certificate_reload_sock = "{}"
            threads = 4
            listener_tasks_per_fd = 2
            work_stealing = false
            upstream_keepalive_pool_size = 512
            max_retries = 8
            grace_period_seconds = 10
            graceful_shutdown_timeout_seconds = 30
            "#,
        error_log.display(),
        pid_file.display(),
        upgrade_sock.display(),
        certificate_reload_sock.display()
    ))
    .unwrap();

    assert!(!config.server.process.daemon);
    assert_eq!(
        config.server.process.error_log.as_deref(),
        Some(error_log.as_path())
    );
    assert_eq!(config.server.process.pid_file, pid_file);
    assert_eq!(config.server.process.upgrade_sock, upgrade_sock);
    assert_eq!(
        config.server.process.certificate_reload_sock,
        certificate_reload_sock
    );
    assert_eq!(config.server.process.threads, 4);
    assert_eq!(config.server.process.listener_tasks_per_fd, 2);
    assert!(!config.server.process.work_stealing);
    assert_eq!(config.server.process.upstream_keepalive_pool_size, 512);
    assert_eq!(config.server.process.max_retries, 8);
    assert_eq!(config.server.process.grace_period_seconds, Some(10));
    assert_eq!(
        config.server.process.graceful_shutdown_timeout_seconds,
        Some(30)
    );
    config.validate().unwrap();
}

#[test]
fn parses_static_cache_headers() {
    let config: Config = toml::from_str(
        r#"
            [web]
            root = "public"
            cache_control = "public, max-age=31536000, immutable"
            expires = "Wed, 21 Oct 2030 07:28:00 GMT"

            [web.directory_listing]
            enabled = true
            exact_size = true
            local_time = true
            "#,
    )
    .unwrap();

    assert_eq!(
        config.web.cache_control,
        "public, max-age=31536000, immutable"
    );
    assert_eq!(
        config.web.expires.as_deref(),
        Some("Wed, 21 Oct 2030 07:28:00 GMT")
    );
    assert!(config.web.directory_listing.enabled);
    assert!(config.web.directory_listing.exact_size);
    assert!(config.web.directory_listing.local_time);
}

#[test]
fn parses_proxy_upstream_pool() {
    let config: Config = toml::from_str(
        r#"
            [proxy]
            upstreams = ["127.0.0.1:3001", "127.0.0.1:3002", "127.0.0.1:3003"]
            upstream_weights = [1, 3, 1]
            upstream_priority_groups = [100, 50, 10]
            upstream_priority_group_min_active = 2
            upstream_localities = ["site-a", "site-b", "site-a"]
            preferred_upstream_localities = ["site-a"]
            upstream_max_in_flight = [10, 30, 5]
            upstream_aliases = ["app-a", "app-b", "app-c"]
            upstream_tags = [["blue", "primary"], ["blue"], ["canary"]]
            backup_upstreams = ["127.0.0.1:3002"]
            disabled_upstreams = ["127.0.0.1:3003"]
            connect_timeout_secs = 5
            upstream_total_connection_timeout_secs = 10
            upstream_idle_timeout_secs = 120
            upstream_tcp_keepalive_idle_secs = 30
            upstream_tcp_keepalive_interval_secs = 10
            upstream_tcp_keepalive_count = 3
            upstream_tcp_user_timeout_ms = 15000
            upstream_tcp_recv_buffer_bytes = "1MiB"
            upstream_dscp = 46
            upstream_tcp_fast_open = true
            read_timeout_secs = 60
            send_timeout_secs = 30
            upstream_tls = true
            upstream_sni = "origin.example.test"
            upstream_verify_cert = true
            upstream_verify_hostname = true
            upstream_alternative_cn = "fallback-origin.example.test"
            upstream_ca_path = "tests/fixtures/tls/localhost-cert.pem"
            upstream_client_cert_path = "tests/fixtures/tls/localhost-cert.pem"
            upstream_client_key_path = "tests/fixtures/tls/localhost-key.pem"
            upstream_proxy_protocol = "v2"
            upstream_http_version = "http1-and-http2"
            upstream_h2_max_streams = 64
            upstream_h2_ping_interval_secs = 30

            [proxy.load_balance]
            max_iterations = 16
            all_down_status = 503

            [proxy.load_balance.health_check]
            enabled = true
            protocol = "http"
            interval_secs = 2
            consecutive_success = 2
            consecutive_failure = 3
            parallel = true
            method = "HEAD"
            path = "/healthz"
            host = "app.internal"
            expected_statuses = [200, 204]
            expected_body_contains = ["ready"]
            reuse_connection = true
            port_override = 8081
            connect_timeout_secs = 1
            read_timeout_secs = 2

            [[proxy.load_balance.health_check.expected_headers]]
            name = "x-fluxheim-health"
            value = "ready"

            [[proxy.load_balance.health_check.expected_status_ranges]]
            start = 300
            end = 399

            [proxy.load_balance.slow_start]
            enabled = true
            duration_secs = 45

            [proxy.load_balance.persistence]
            enabled = true
            mode = "source-ip"
            ttl_secs = 600
            table_max_entries = 4096

            [proxy.load_balance.queue]
            max_waiting = 32
            timeout_ms = 250
            retry_interval_ms = 5

            [[proxy.error_pages]]
            status = 502
            path = "/502.html"

            [proxy.error_pages.web]
            root = "/srv/fluxheim/errors"
            "#,
    )
    .unwrap();

    assert_eq!(
        config.proxy.upstreams,
        [
            "127.0.0.1:3001".to_owned(),
            "127.0.0.1:3002".to_owned(),
            "127.0.0.1:3003".to_owned()
        ]
    );
    assert_eq!(config.proxy.upstream_weights, [1, 3, 1]);
    assert_eq!(config.proxy.upstream_priority_groups, [100, 50, 10]);
    assert_eq!(config.proxy.upstream_priority_group_min_active, 2);
    assert_eq!(
        config.proxy.upstream_localities,
        ["site-a", "site-b", "site-a"]
    );
    assert_eq!(config.proxy.preferred_upstream_localities, ["site-a"]);
    assert_eq!(config.proxy.upstream_max_in_flight, [10, 30, 5]);
    assert_eq!(config.proxy.upstream_aliases, ["app-a", "app-b", "app-c"]);
    assert_eq!(
        config.proxy.upstream_tags,
        [
            vec!["blue".to_owned(), "primary".to_owned()],
            vec!["blue".to_owned()],
            vec!["canary".to_owned()]
        ]
    );
    assert_eq!(config.proxy.backup_upstreams, ["127.0.0.1:3002"]);
    assert_eq!(config.proxy.disabled_upstreams, ["127.0.0.1:3003"]);
    assert_eq!(config.proxy.connect_timeout_secs, Some(5));
    assert_eq!(
        config.proxy.upstream_total_connection_timeout_secs,
        Some(10)
    );
    assert_eq!(config.proxy.upstream_idle_timeout_secs, Some(120));
    assert_eq!(config.proxy.upstream_tcp_keepalive_idle_secs, Some(30));
    assert_eq!(config.proxy.upstream_tcp_keepalive_interval_secs, Some(10));
    assert_eq!(config.proxy.upstream_tcp_keepalive_count, Some(3));
    assert_eq!(config.proxy.upstream_tcp_user_timeout_ms, Some(15000));
    assert_eq!(
        config
            .proxy
            .upstream_tcp_recv_buffer_bytes
            .map(ByteSize::as_u64),
        Some(1024 * 1024)
    );
    assert_eq!(config.proxy.upstream_dscp, Some(46));
    assert!(config.proxy.upstream_tcp_fast_open);
    assert_eq!(config.proxy.read_timeout_secs, Some(60));
    assert_eq!(config.proxy.send_timeout_secs, Some(30));
    assert!(config.proxy.upstream_tls);
    assert_eq!(
        config.proxy.upstream_sni.as_deref(),
        Some("origin.example.test")
    );
    assert!(config.proxy.upstream_verify_cert);
    assert!(config.proxy.upstream_verify_hostname);
    assert_eq!(
        config.proxy.upstream_alternative_cn.as_deref(),
        Some("fallback-origin.example.test")
    );
    assert_eq!(
        config.proxy.upstream_ca_path.as_deref(),
        Some(Path::new("tests/fixtures/tls/localhost-cert.pem"))
    );
    assert_eq!(
        config.proxy.upstream_client_cert_path.as_deref(),
        Some(Path::new("tests/fixtures/tls/localhost-cert.pem"))
    );
    assert_eq!(
        config.proxy.upstream_client_key_path.as_deref(),
        Some(Path::new("tests/fixtures/tls/localhost-key.pem"))
    );
    assert_eq!(
        config.proxy.upstream_proxy_protocol,
        UpstreamProxyProtocol::V2
    );
    assert_eq!(
        config.proxy.upstream_http_version,
        UpstreamHttpVersion::Http1AndHttp2
    );
    assert_eq!(config.proxy.upstream_h2_max_streams, Some(64));
    assert_eq!(config.proxy.upstream_h2_ping_interval_secs, Some(30));
    assert_eq!(config.proxy.error_pages.len(), 1);
    assert_eq!(config.proxy.error_pages[0].status, 502);
    assert_eq!(config.proxy.error_pages[0].path, "/502.html");
    assert_eq!(config.proxy.load_balance.max_iterations, 16);
    assert_eq!(config.proxy.load_balance.all_down_status, 503);
    assert!(config.proxy.load_balance.health_check.enabled);
    assert_eq!(
        config.proxy.load_balance.health_check.protocol,
        LoadBalanceHealthCheckProtocol::Http
    );
    assert_eq!(config.proxy.load_balance.health_check.interval_secs, 2);
    assert_eq!(
        config.proxy.load_balance.health_check.consecutive_success,
        2
    );
    assert_eq!(
        config.proxy.load_balance.health_check.consecutive_failure,
        3
    );
    assert!(config.proxy.load_balance.health_check.parallel);
    assert_eq!(config.proxy.load_balance.health_check.method, "HEAD");
    assert_eq!(config.proxy.load_balance.health_check.path, "/healthz");
    assert_eq!(
        config.proxy.load_balance.health_check.host.as_deref(),
        Some("app.internal")
    );
    assert_eq!(
        config.proxy.load_balance.health_check.expected_statuses,
        vec![200, 204]
    );
    assert_eq!(
        config.proxy.load_balance.health_check.expected_headers[0].name,
        "x-fluxheim-health"
    );
    assert_eq!(
        config.proxy.load_balance.health_check.expected_headers[0].value,
        "ready"
    );
    assert_eq!(
        config
            .proxy
            .load_balance
            .health_check
            .expected_body_contains,
        vec!["ready".to_owned()]
    );
    assert_eq!(
        config
            .proxy
            .load_balance
            .health_check
            .expected_status_ranges[0]
            .start,
        300
    );
    assert_eq!(
        config
            .proxy
            .load_balance
            .health_check
            .expected_status_ranges[0]
            .end,
        399
    );
    assert!(config.proxy.load_balance.health_check.reuse_connection);
    assert_eq!(
        config.proxy.load_balance.health_check.port_override,
        Some(8081)
    );
    assert_eq!(
        config.proxy.load_balance.health_check.connect_timeout_secs,
        Some(1)
    );
    assert_eq!(
        config.proxy.load_balance.health_check.read_timeout_secs,
        Some(2)
    );
    assert!(config.proxy.load_balance.slow_start.enabled);
    assert_eq!(config.proxy.load_balance.slow_start.duration_secs, 45);
    assert!(config.proxy.load_balance.persistence.enabled);
    assert_eq!(
        config.proxy.load_balance.persistence.mode,
        LoadBalancePersistenceMode::SourceIp
    );
    assert_eq!(config.proxy.load_balance.persistence.ttl_secs, 600);
    assert_eq!(
        config.proxy.load_balance.persistence.table_max_entries,
        4096
    );
    assert_eq!(config.proxy.load_balance.queue.max_waiting, 32);
    assert_eq!(config.proxy.load_balance.queue.timeout_ms, 250);
    assert_eq!(config.proxy.load_balance.queue.retry_interval_ms, 5);
    config.validate().unwrap();
}

#[cfg(feature = "load-balancer")]
#[test]
fn parses_proxy_upstreams_file() {
    let root = secure_test_dir("config-proxy-upstreams-file");
    let upstreams_file = root.join("upstreams.txt");
    fs::write(
        &upstreams_file,
        "# generated by service discovery\n127.0.0.1:3001\n127.0.0.1:3002\n",
    )
    .unwrap();
    let config: Config = toml::from_str(&format!(
        r#"
            [proxy]
            upstreams_file = "{}"
            upstreams_file_refresh_secs = 2
            "#,
        upstreams_file.display()
    ))
    .unwrap();

    assert_eq!(
        config.proxy.upstreams_file.as_deref(),
        Some(upstreams_file.as_path())
    );
    assert_eq!(config.proxy.upstreams_file_refresh_secs, 2);
    config.validate().unwrap();
}

#[cfg(feature = "load-balancer")]
#[test]
fn parses_proxy_upstream_dns_refresh() {
    let config: Config = toml::from_str(
        r#"
            [proxy]
            upstreams = ["localhost:3001"]
            upstream_dns_refresh_secs = 2
            "#,
    )
    .unwrap();

    assert_eq!(config.proxy.upstream_dns_refresh_secs, Some(2));
    config.validate().unwrap();
}

#[cfg(feature = "load-balancer")]
#[test]
fn rejects_invalid_proxy_upstreams_file_contents() {
    let root = secure_test_dir("config-proxy-upstreams-file-invalid");
    let upstreams_file = root.join("upstreams.txt");
    fs::write(&upstreams_file, "127.0.0.1:3001\n127.0.0.1:3001\n").unwrap();
    let config: Config = toml::from_str(&format!(
        r#"
            [proxy]
            upstreams_file = "{}"
            "#,
        upstreams_file.display()
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("proxy.upstreams_file"), "{error}");
}

#[test]
fn rejects_ambiguous_proxy_upstream_aliases() {
    let config: Config = toml::from_str(
        r#"
            [proxy]
            upstream = "127.0.0.1:3000"
            upstreams = ["127.0.0.1:3001"]
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::ConflictingProxyUpstreams)
    );
}

#[test]
fn rejects_invalid_proxy_upstream_weights() {
    let mismatch: Config = toml::from_str(
        r#"
            [proxy]
            upstreams = ["127.0.0.1:3001", "127.0.0.1:3002"]
            upstream_weights = [1]
            "#,
    )
    .unwrap();
    assert!(matches!(
        mismatch.validate(),
        Err(ConfigError::InvalidProxyUpstreamWeights { .. })
    ));

    let zero: Config = toml::from_str(
        r#"
            [proxy]
            upstreams = ["127.0.0.1:3001", "127.0.0.1:3002"]
            upstream_weights = [1, 0]
            "#,
    )
    .unwrap();
    assert!(matches!(
        zero.validate(),
        Err(ConfigError::InvalidProxyUpstreamWeights { .. })
    ));
}

#[test]
fn rejects_invalid_proxy_upstream_priority_groups() {
    let mismatch: Config = toml::from_str(
        r#"
            [proxy]
            upstreams = ["127.0.0.1:3001", "127.0.0.1:3002"]
            upstream_priority_groups = [100]
            "#,
    )
    .unwrap();
    assert!(matches!(
        mismatch.validate(),
        Err(ConfigError::InvalidProxyUpstreamPolicy {
            field: "proxy.upstream_priority_groups",
            ..
        })
    ));

    let too_large: Config = toml::from_str(
        r#"
            [proxy]
            upstreams = ["127.0.0.1:3001", "127.0.0.1:3002"]
            upstream_priority_groups = [100, 1001]
            "#,
    )
    .unwrap();
    assert!(matches!(
        too_large.validate(),
        Err(ConfigError::InvalidProxyUpstreamPolicy {
            field: "proxy.upstream_priority_groups",
            ..
        })
    ));

    let min_active_without_groups: Config = toml::from_str(
        r#"
            [proxy]
            upstreams = ["127.0.0.1:3001", "127.0.0.1:3002"]
            upstream_priority_group_min_active = 2
            "#,
    )
    .unwrap();
    assert!(matches!(
        min_active_without_groups.validate(),
        Err(ConfigError::InvalidProxyUpstreamPolicy {
            field: "proxy.upstream_priority_group_min_active",
            ..
        })
    ));

    let min_active_too_large: Config = toml::from_str(
        r#"
            [proxy]
            upstreams = ["127.0.0.1:3001", "127.0.0.1:3002"]
            upstream_priority_groups = [100, 50]
            upstream_priority_group_min_active = 3
            "#,
    )
    .unwrap();
    assert!(matches!(
        min_active_too_large.validate(),
        Err(ConfigError::InvalidProxyUpstreamPolicy {
            field: "proxy.upstream_priority_group_min_active",
            ..
        })
    ));
}

#[test]
fn rejects_invalid_proxy_upstream_localities() {
    let mismatch: Config = toml::from_str(
        r#"
            [proxy]
            upstreams = ["127.0.0.1:3001", "127.0.0.1:3002"]
            upstream_localities = ["site-a"]
            "#,
    )
    .unwrap();
    assert!(matches!(
        mismatch.validate(),
        Err(ConfigError::InvalidProxyUpstreamPolicy {
            field: "proxy.upstream_localities",
            ..
        })
    ));

    let invalid_label: Config = toml::from_str(
        r#"
            [proxy]
            upstreams = ["127.0.0.1:3001", "127.0.0.1:3002"]
            upstream_localities = ["site/a", "site-b"]
            "#,
    )
    .unwrap();
    assert!(matches!(
        invalid_label.validate(),
        Err(ConfigError::InvalidProxyUpstreamPolicy {
            field: "proxy.upstream_localities",
            ..
        })
    ));

    let preferred_without_localities: Config = toml::from_str(
        r#"
            [proxy]
            upstreams = ["127.0.0.1:3001", "127.0.0.1:3002"]
            preferred_upstream_localities = ["site-a"]
            "#,
    )
    .unwrap();
    assert!(matches!(
        preferred_without_localities.validate(),
        Err(ConfigError::InvalidProxyUpstreamPolicy {
            field: "proxy.preferred_upstream_localities",
            ..
        })
    ));

    let unknown_preferred: Config = toml::from_str(
        r#"
            [proxy]
            upstreams = ["127.0.0.1:3001", "127.0.0.1:3002"]
            upstream_localities = ["site-a", "site-b"]
            preferred_upstream_localities = ["site-c"]
            "#,
    )
    .unwrap();
    assert!(matches!(
        unknown_preferred.validate(),
        Err(ConfigError::InvalidProxyUpstreamPolicy {
            field: "proxy.preferred_upstream_localities",
            ..
        })
    ));

    let duplicate_preferred: Config = toml::from_str(
        r#"
            [proxy]
            upstreams = ["127.0.0.1:3001", "127.0.0.1:3002"]
            upstream_localities = ["site-a", "site-b"]
            preferred_upstream_localities = ["site-a", "SITE-A"]
            "#,
    )
    .unwrap();
    assert!(matches!(
        duplicate_preferred.validate(),
        Err(ConfigError::InvalidProxyUpstreamPolicy {
            field: "proxy.preferred_upstream_localities",
            ..
        })
    ));
}

#[test]
fn rejects_invalid_proxy_upstream_tags() {
    let mismatch: Config = toml::from_str(
        r#"
            [proxy]
            upstreams = ["127.0.0.1:3001", "127.0.0.1:3002"]
            upstream_tags = [["blue"]]
            "#,
    )
    .unwrap();
    assert!(matches!(
        mismatch.validate(),
        Err(ConfigError::InvalidProxyUpstreamPolicy {
            field: "proxy.upstream_tags",
            ..
        })
    ));

    let invalid_label: Config = toml::from_str(
        r#"
            [proxy]
            upstreams = ["127.0.0.1:3001", "127.0.0.1:3002"]
            upstream_tags = [["blue"], ["bad/tag"]]
            "#,
    )
    .unwrap();
    assert!(matches!(
        invalid_label.validate(),
        Err(ConfigError::InvalidProxyUpstreamPolicy {
            field: "proxy.upstream_tags",
            ..
        })
    ));

    let duplicate_tag: Config = toml::from_str(
        r#"
            [proxy]
            upstreams = ["127.0.0.1:3001", "127.0.0.1:3002"]
            upstream_tags = [["blue", "BLUE"], ["green"]]
            "#,
    )
    .unwrap();
    assert!(matches!(
        duplicate_tag.validate(),
        Err(ConfigError::InvalidProxyUpstreamPolicy {
            field: "proxy.upstream_tags",
            ..
        })
    ));
}

#[test]
fn rejects_invalid_proxy_upstream_max_in_flight() {
    let mismatch: Config = toml::from_str(
        r#"
            [proxy]
            upstreams = ["127.0.0.1:3001", "127.0.0.1:3002"]
            upstream_max_in_flight = [100]
            "#,
    )
    .unwrap();
    assert!(matches!(
        mismatch.validate(),
        Err(ConfigError::InvalidProxyUpstreamPolicy {
            field: "proxy.upstream_max_in_flight",
            ..
        })
    ));

    let zero: Config = toml::from_str(
        r#"
            [proxy]
            upstreams = ["127.0.0.1:3001", "127.0.0.1:3002"]
            upstream_max_in_flight = [100, 0]
            "#,
    )
    .unwrap();
    assert!(matches!(
        zero.validate(),
        Err(ConfigError::InvalidProxyUpstreamPolicy {
            field: "proxy.upstream_max_in_flight",
            ..
        })
    ));

    let too_large: Config = toml::from_str(
        r#"
            [proxy]
            upstreams = ["127.0.0.1:3001", "127.0.0.1:3002"]
            upstream_max_in_flight = [100, 1000001]
            "#,
    )
    .unwrap();
    assert!(matches!(
        too_large.validate(),
        Err(ConfigError::InvalidProxyUpstreamPolicy {
            field: "proxy.upstream_max_in_flight",
            ..
        })
    ));
}

#[test]
fn rejects_invalid_proxy_upstream_aliases() {
    let mismatch: Config = toml::from_str(
        r#"
            [proxy]
            upstreams = ["127.0.0.1:3001", "127.0.0.1:3002"]
            upstream_aliases = ["origin-a"]
            "#,
    )
    .unwrap();
    assert!(matches!(
        mismatch.validate(),
        Err(ConfigError::InvalidProxyUpstreamPolicy {
            field: "proxy.upstream_aliases",
            ..
        })
    ));

    let unsafe_alias: Config = toml::from_str(
        r#"
            [proxy]
            upstreams = ["127.0.0.1:3001", "127.0.0.1:3002"]
            upstream_aliases = ["origin/a", "origin-b"]
            "#,
    )
    .unwrap();
    assert!(matches!(
        unsafe_alias.validate(),
        Err(ConfigError::InvalidProxyUpstreamPolicy {
            field: "proxy.upstream_aliases",
            ..
        })
    ));

    let duplicate: Config = toml::from_str(
        r#"
            [proxy]
            upstreams = ["127.0.0.1:3001", "127.0.0.1:3002"]
            upstream_aliases = ["origin-a", "ORIGIN-A"]
            "#,
    )
    .unwrap();
    assert!(matches!(
        duplicate.validate(),
        Err(ConfigError::InvalidProxyUpstreamPolicy {
            field: "proxy.upstream_aliases",
            ..
        })
    ));
}

#[test]
fn rejects_invalid_proxy_upstream_tls_material_policy() {
    let without_tls: Config = toml::from_str(
        r#"
            [proxy]
            upstream = "127.0.0.1:3000"
            upstream_ca_path = "tests/fixtures/tls/localhost-cert.pem"
            "#,
    )
    .unwrap();
    assert_eq!(
        without_tls.validate(),
        Err(ConfigError::InvalidProxyTlsPolicy {
            reason: "upstream TLS trust roots or client certificates require upstream_tls = true"
        })
    );

    let incomplete_mtls: Config = toml::from_str(
        r#"
            [proxy]
            upstream = "127.0.0.1:3000"
            upstream_tls = true
            upstream_client_cert_path = "tests/fixtures/tls/localhost-cert.pem"
            "#,
    )
    .unwrap();
    assert_eq!(
        incomplete_mtls.validate(),
        Err(ConfigError::InvalidProxyTlsPolicy {
            reason: "upstream_client_cert_path and upstream_client_key_path must be configured together"
        })
    );
}

#[test]
fn rejects_invalid_proxy_upstream_policy() {
    let auth_request: Config = toml::from_str(
        r#"
            [proxy]
            upstream = "127.0.0.1:3001"

            [proxy.auth_request]
            enabled = true
            url = "http://127.0.0.1:4180/auth"
            forward_headers = ["authorization", "cookie"]
            allow_response_headers = ["x-auth-request-user"]
            "#,
    )
    .unwrap();
    assert!(auth_request.validate().is_ok());
    assert!(auth_request.proxy.auth_request.enabled);

    let auth_request_without_url: Config = toml::from_str(
        r#"
            [proxy]
            upstream = "127.0.0.1:3001"

            [proxy.auth_request]
            enabled = true
            "#,
    )
    .unwrap();
    assert_eq!(
        auth_request_without_url.validate(),
        Err(ConfigError::InvalidProxyUpstreamPolicy {
            field: "proxy.auth_request",
            reason: "enabled auth_request requires url",
        })
    );

    let mirror_without_url: Config = toml::from_str(
        r#"
            [proxy]
            upstream = "127.0.0.1:3001"

            [proxy.mirror]
            enabled = true
            "#,
    )
    .unwrap();
    #[cfg(feature = "traffic-mirror")]
    assert_eq!(
        mirror_without_url.validate(),
        Err(ConfigError::InvalidProxyUpstreamPolicy {
            field: "proxy.mirror",
            reason: "enabled traffic mirroring requires base_url",
        })
    );
    #[cfg(not(feature = "traffic-mirror"))]
    assert_eq!(
        mirror_without_url.validate(),
        Err(ConfigError::InvalidProxyUpstreamPolicy {
            field: "proxy.mirror",
            reason: "traffic mirroring requires building Fluxheim with the traffic-mirror feature",
        })
    );

    #[cfg(feature = "traffic-mirror")]
    {
        let mirror: Config = toml::from_str(
            r#"
                [proxy]
                upstream = "127.0.0.1:3001"

                [proxy.mirror]
                enabled = true
                base_url = "http://127.0.0.1:9000"
                sample_per_mille = 250
                methods = ["GET", "HEAD"]
                forward_headers = ["user-agent"]
                max_in_flight = 8
                "#,
        )
        .unwrap();
        assert!(mirror.validate().is_ok());
        assert!(mirror.proxy.mirror.enabled);
        assert_eq!(mirror.proxy.mirror.max_in_flight, 8);
    }

    let websocket: Config = toml::from_str(
        r#"
            [proxy]
            upstream = "127.0.0.1:3001"
            websocket = true
            "#,
    )
    .unwrap();
    assert!(websocket.validate().is_ok());
    assert!(websocket.proxy.websocket);

    let websocket_with_h2: Config = toml::from_str(
        r#"
            [proxy]
            upstream = "127.0.0.1:3001"
            websocket = true
            upstream_http_version = "http2"
            "#,
    )
    .unwrap();
    assert_eq!(
        websocket_with_h2.validate(),
        Err(ConfigError::InvalidProxyUpstreamPolicy {
            field: "proxy.websocket",
            reason: "HTTP/1.1 upgrade proxying requires upstream_http_version = \"http1\"",
        })
    );

    let unknown_backup: Config = toml::from_str(
        r#"
            [proxy]
            upstreams = ["127.0.0.1:3001", "127.0.0.1:3002"]
            backup_upstreams = ["127.0.0.1:3999"]
            "#,
    )
    .unwrap();
    assert!(matches!(
        unknown_backup.validate(),
        Err(ConfigError::InvalidProxyUpstreamPolicy { .. })
    ));

    let overlapping_policy: Config = toml::from_str(
        r#"
            [proxy]
            upstreams = ["127.0.0.1:3001", "127.0.0.1:3002"]
            backup_upstreams = ["127.0.0.1:3002"]
            drain_upstreams = ["127.0.0.1:3002"]
            "#,
    )
    .unwrap();
    assert!(matches!(
        overlapping_policy.validate(),
        Err(ConfigError::InvalidProxyUpstreamPolicy { .. })
    ));

    let disabled_overlap: Config = toml::from_str(
        r#"
            [proxy]
            upstreams = ["127.0.0.1:3001", "127.0.0.1:3002"]
            drain_upstreams = ["127.0.0.1:3002"]
            disabled_upstreams = ["127.0.0.1:3002"]
            "#,
    )
    .unwrap();
    assert!(matches!(
        disabled_overlap.validate(),
        Err(ConfigError::InvalidProxyUpstreamPolicy { .. })
    ));

    let no_primary: Config = toml::from_str(
        r#"
            [proxy]
            upstreams = ["127.0.0.1:3001", "127.0.0.1:3002", "127.0.0.1:3003"]
            backup_upstreams = ["127.0.0.1:3001"]
            drain_upstreams = ["127.0.0.1:3002"]
            disabled_upstreams = ["127.0.0.1:3003"]
            "#,
    )
    .unwrap();
    assert!(matches!(
        no_primary.validate(),
        Err(ConfigError::InvalidProxyUpstreamPolicy { .. })
    ));

    let h2_options_without_h2: Config = toml::from_str(
        r#"
            [proxy]
            upstream = "127.0.0.1:3001"
            upstream_h2_max_streams = 64
            "#,
    )
    .unwrap();
    assert!(matches!(
        h2_options_without_h2.validate(),
        Err(ConfigError::InvalidProxyUpstreamPolicy { .. })
    ));

    let too_many_h2_streams: Config = toml::from_str(
        r#"
            [proxy]
            upstream = "127.0.0.1:3001"
            upstream_http_version = "http2"
            upstream_h2_max_streams = 1025
            "#,
    )
    .unwrap();
    assert!(matches!(
        too_many_h2_streams.validate(),
        Err(ConfigError::InvalidProxyUpstreamPolicy { .. })
    ));

    let zero_h2_ping_interval: Config = toml::from_str(
        r#"
            [proxy]
            upstream = "127.0.0.1:3001"
            upstream_http_version = "http2"
            upstream_h2_ping_interval_secs = 0
            "#,
    )
    .unwrap();
    assert!(matches!(
        zero_h2_ping_interval.validate(),
        Err(ConfigError::InvalidProxyTimeout { .. })
    ));

    let zero_upstream_total_connection_timeout: Config = toml::from_str(
        r#"
            [proxy]
            upstream = "127.0.0.1:3001"
            upstream_total_connection_timeout_secs = 0
            "#,
    )
    .unwrap();
    assert!(matches!(
        zero_upstream_total_connection_timeout.validate(),
        Err(ConfigError::InvalidProxyTimeout { .. })
    ));

    let zero_upstream_idle_timeout: Config = toml::from_str(
        r#"
            [proxy]
            upstream = "127.0.0.1:3001"
            upstream_idle_timeout_secs = 0
            "#,
    )
    .unwrap();
    assert!(matches!(
        zero_upstream_idle_timeout.validate(),
        Err(ConfigError::InvalidProxyTimeout { .. })
    ));

    let incomplete_tcp_keepalive: Config = toml::from_str(
        r#"
            [proxy]
            upstream = "127.0.0.1:3001"
            upstream_tcp_keepalive_idle_secs = 30
            upstream_tcp_keepalive_count = 3
            "#,
    )
    .unwrap();
    assert!(matches!(
        incomplete_tcp_keepalive.validate(),
        Err(ConfigError::InvalidProxyUpstreamPolicy { .. })
    ));

    let invalid_tcp_keepalive_count: Config = toml::from_str(
        r#"
            [proxy]
            upstream = "127.0.0.1:3001"
            upstream_tcp_keepalive_idle_secs = 30
            upstream_tcp_keepalive_interval_secs = 10
            upstream_tcp_keepalive_count = 0
            "#,
    )
    .unwrap();
    assert!(matches!(
        invalid_tcp_keepalive_count.validate(),
        Err(ConfigError::InvalidProxyUpstreamPolicy { .. })
    ));

    let invalid_tcp_recv_buffer: Config = toml::from_str(
        r#"
            [proxy]
            upstream = "127.0.0.1:3001"
            upstream_tcp_recv_buffer_bytes = "512MiB"
            "#,
    )
    .unwrap();
    assert!(matches!(
        invalid_tcp_recv_buffer.validate(),
        Err(ConfigError::InvalidProxyUpstreamPolicy { .. })
    ));

    let invalid_dscp: Config = toml::from_str(
        r#"
            [proxy]
            upstream = "127.0.0.1:3001"
            upstream_dscp = 64
            "#,
    )
    .unwrap();
    assert!(matches!(
        invalid_dscp.validate(),
        Err(ConfigError::InvalidProxyUpstreamPolicy { .. })
    ));
}

#[test]
fn rejects_too_many_proxy_upstreams() {
    let upstreams = (0..=super::MAX_PROXY_UPSTREAMS)
        .map(|index| format!("\"origin-{index}.example.test:8080\""))
        .collect::<Vec<_>>()
        .join(", ");
    let config: Config = toml::from_str(&format!(
        r#"
            [proxy]
            upstreams = [{upstreams}]
            "#,
    ))
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::TooManyProxyUpstreams {
            max: super::MAX_PROXY_UPSTREAMS
        })
    );
}

#[test]
fn rejects_duplicate_proxy_upstreams() {
    let config: Config = toml::from_str(
        r#"
            [proxy]
            upstreams = ["origin.example.test:8080", "ORIGIN.example.test:8080"]
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::DuplicateProxyUpstream {
            upstream: "ORIGIN.example.test:8080".to_owned()
        })
    );
}

#[test]
fn rejects_inconsistent_proxy_upstream_tls_verification_policy() {
    let config: Config = toml::from_str(
        r#"
            [proxy]
            upstream_tls = true
            upstream_verify_cert = false
            upstream_verify_hostname = true
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidProxyTlsPolicy {
            reason: "upstream_verify_hostname must be false when upstream_verify_cert = false"
        })
    );
}

#[test]
fn rejects_invalid_proxy_upstream_alternative_cn() {
    let config: Config = toml::from_str(
        r#"
            [proxy]
            upstream_tls = true
            upstream_alternative_cn = "*.example.test"
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidProxyTlsPolicy {
            reason: "upstream_alternative_cn must not contain wildcards"
        })
    );
}

#[test]
fn vhost_without_proxy_does_not_inherit_legacy_default_upstream() {
    let config: Config = toml::from_str(
        r#"
            [[vhosts]]
            name = "static"
            hosts = ["static.example.test"]

            [vhosts.web]
            root = "/srv/static"
            "#,
    )
    .unwrap();

    assert!(!config.vhosts[0].proxy.has_configured_upstream());
    assert_eq!(config.proxy.primary_upstream(), "127.0.0.1:3000");
}

#[test]
fn rejects_zero_proxy_timeouts() {
    let config: Config = toml::from_str(
        r#"
            [proxy]
            upstream = "127.0.0.1:3000"
            read_timeout_secs = 0
            downstream_min_send_rate_bytes_per_sec = 1
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidProxyTimeout {
            field: "proxy.read_timeout_secs"
        })
    );

    let config: Config = toml::from_str(
        r#"
            [proxy]
            upstream = "127.0.0.1:3000"
            downstream_write_timeout_secs = 0
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidProxyTimeout {
            field: "proxy.downstream_write_timeout_secs"
        })
    );

    let config: Config = toml::from_str(
        r#"
            [proxy]
            upstream = "127.0.0.1:3000"
            downstream_min_send_rate_bytes_per_sec = 0
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidProxyTimeout {
            field: "proxy.downstream_min_send_rate_bytes_per_sec"
        })
    );
}

#[test]
fn rejects_invalid_proxy_error_pages() {
    let config: Config = toml::from_str(
        r#"
            [[proxy.error_pages]]
            status = 302
            path = "/302.html"

            [proxy.error_pages.web]
            root = "/srv/fluxheim/errors"
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidProxyErrorPageStatus { status: 302 })
    );

    let config: Config = toml::from_str(
        r#"
            [[proxy.error_pages]]
            status = 502
            path = "/502.html"
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::MissingProxyErrorPageRoot { status: 502 })
    );
}

#[test]
fn rejects_too_many_proxy_error_pages() {
    let error_pages = (0..=super::MAX_PROXY_ERROR_PAGES)
        .map(|index| super::ProxyErrorPageConfig {
            status: 400 + (index % 100) as u16,
            path: format!("/error-{index}.html"),
            web: WebConfig::default(),
        })
        .collect();
    let config = Config {
        proxy: ProxyConfig {
            error_pages,
            ..ProxyConfig::default()
        },
        ..Config::default()
    };

    assert_eq!(
        config.validate(),
        Err(ConfigError::TooManyProxyErrorPages {
            max: super::MAX_PROXY_ERROR_PAGES
        })
    );
}

#[test]
fn upstreams_can_be_used_as_primary_proxy_targets() {
    let config: Config = toml::from_str(
        r#"
            [proxy]
            upstreams = ["origin-a.example.test:443", "origin-b.example.test:443"]
            upstream_tls = true
            "#,
    )
    .unwrap();

    config.validate().unwrap();
    assert_eq!(config.proxy.primary_upstream(), "origin-a.example.test:443");
    assert_eq!(config.proxy.upstream_sni(), "origin-a.example.test");
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
fn rejects_invalid_response_header_value() {
    let config: Config = toml::from_str(
        r#"
            [headers.response]
            x_frame_options = "DENY\nx-bad: injected"
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidResponseHeaderValue {
            field: "headers.response.x_frame_options"
        })
    );
}

#[test]
fn rejects_invalid_static_cache_header_value() {
    let config: Config = toml::from_str(
        r#"
            [web]
            root = "public"
            cache_control = "public\nx-bad: injected"
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidResponseHeaderValue {
            field: "web.cache_control"
        })
    );
}

#[test]
fn rejects_invalid_server_process_settings() {
    let config: Config = toml::from_str(
        r#"
            [server.process]
            threads = 0
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidProcessSetting {
            field: "server.process.threads"
        })
    );

    let config: Config = toml::from_str(
        r#"
            [server.process]
            grace_period_seconds = 0
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidProcessSetting {
            field: "server.process.grace_period_seconds"
        })
    );

    let config: Config = toml::from_str(
        r#"
            [server.process]
            pid_file = ""
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::EmptyProcessPath {
            field: "server.process.pid_file"
        })
    );

    let config: Config = toml::from_str(
        r#"
            [server.process]
            upgrade_sock = "../fluxheim.sock"
            "#,
    )
    .unwrap();

    assert!(matches!(
        config.validate(),
        Err(ConfigError::UnsafePath { field, .. }) if field == "server.process.upgrade_sock"
    ));

    #[cfg(unix)]
    {
        let pid_file = unique_world_writable_child("config-process-world-writable", "fluxheim.pid");
        let config: Config = toml::from_str(&format!(
            r#"
                [server.process]
                pid_file = "{}"
                "#,
            pid_file.display()
        ))
        .unwrap();

        assert!(matches!(
            config.validate(),
            Err(ConfigError::UnsafePath { field, .. }) if field == "server.process.pid_file"
        ));
    }
}

#[test]
fn rejects_invalid_generic_header_name() {
    let config: Config = toml::from_str(
        r#"
            [headers.response.set]
            "bad header" = "value"
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidHeaderName {
            field: "headers.response",
            name: "bad header".to_owned()
        })
    );
}

#[test]
fn rejects_invalid_generic_header_value() {
    let config: Config = toml::from_str(
        r#"
            [headers.request.set]
            x-test = "ok\nx-bad: injected"
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidHeaderValue {
            field: "headers.request",
            name: "x-test".to_owned()
        })
    );
}

#[test]
fn rejects_invalid_load_balance_max_iterations() {
    let config: Config = toml::from_str(
        r#"
            [proxy.load_balance]
            max_iterations = 0
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidLoadBalanceMaxIterations)
    );
}

#[test]
fn validates_load_balance_hash_selection() {
    let config: Config = toml::from_str(
        r#"
            [proxy.load_balance]
            selection = "consistent-header-hash"
            hash_header = "x-session"
            "#,
    )
    .unwrap();
    config.validate().unwrap();

    let missing_header: Config = toml::from_str(
        r#"
            [proxy.load_balance]
            selection = "header-hash"
            "#,
    )
    .unwrap();
    assert!(matches!(
        missing_header.validate(),
        Err(ConfigError::InvalidLoadBalanceSelection { .. })
    ));

    let unused_header: Config = toml::from_str(
        r#"
            [proxy.load_balance]
            selection = "source-hash"
            hash_header = "x-session"
            "#,
    )
    .unwrap();
    assert!(matches!(
        unused_header.validate(),
        Err(ConfigError::InvalidLoadBalanceSelection { .. })
    ));

    let cookie: Config = toml::from_str(
        r#"
            [proxy.load_balance]
            selection = "cookie-hash"
            hash_cookie = "session"
            "#,
    )
    .unwrap();
    cookie.validate().unwrap();

    let missing_cookie: Config = toml::from_str(
        r#"
            [proxy.load_balance]
            selection = "consistent-cookie-hash"
            "#,
    )
    .unwrap();
    assert!(matches!(
        missing_cookie.validate(),
        Err(ConfigError::InvalidLoadBalanceSelection { .. })
    ));

    let power_of_two: Config = toml::from_str(
        r#"
            [proxy.load_balance]
            selection = "power-of-two"
            "#,
    )
    .unwrap();
    power_of_two.validate().unwrap();

    let power_of_two_alias: Config = toml::from_str(
        r#"
            [proxy.load_balance]
            selection = "power-of-two-choices"
            "#,
    )
    .unwrap();
    assert_eq!(
        power_of_two_alias.proxy.load_balance.selection,
        LoadBalanceSelection::PowerOfTwo
    );
    power_of_two_alias.validate().unwrap();

    let weighted_least_connections: Config = toml::from_str(
        r#"
            [proxy.load_balance]
            selection = "weighted-least-connections"
            "#,
    )
    .unwrap();
    weighted_least_connections.validate().unwrap();

    let ratio_least_connections: Config = toml::from_str(
        r#"
            [proxy.load_balance]
            selection = "ratio-least-connections"
            "#,
    )
    .unwrap();
    ratio_least_connections.validate().unwrap();

    let least_time: Config = toml::from_str(
        r#"
            [proxy.load_balance]
            selection = "least-time"
            "#,
    )
    .unwrap();
    least_time.validate().unwrap();

    let maglev_alias: Config = toml::from_str(
        r#"
            [proxy.load_balance]
            selection = "maglev"
            "#,
    )
    .unwrap();
    assert_eq!(
        maglev_alias.proxy.load_balance.selection,
        LoadBalanceSelection::MaglevSourceHash
    );
    maglev_alias.validate().unwrap();

    let maglev_uri: Config = toml::from_str(
        r#"
            [proxy.load_balance]
            selection = "maglev-uri-hash"
            "#,
    )
    .unwrap();
    assert_eq!(
        maglev_uri.proxy.load_balance.selection,
        LoadBalanceSelection::MaglevUriHash
    );
    maglev_uri.validate().unwrap();

    let maglev_header: Config = toml::from_str(
        r#"
            [proxy.load_balance]
            selection = "maglev-header-hash"
            hash_header = "x-session"
            "#,
    )
    .unwrap();
    maglev_header.validate().unwrap();

    let least_sessions: Config = toml::from_str(
        r#"
            [proxy.load_balance]
            selection = "least-sessions"

            [proxy.load_balance.persistence]
            enabled = true
            "#,
    )
    .unwrap();
    least_sessions.validate().unwrap();

    let least_sessions_without_persistence: Config = toml::from_str(
        r#"
            [proxy.load_balance]
            selection = "least-sessions"
            "#,
    )
    .unwrap();
    assert!(matches!(
        least_sessions_without_persistence.validate(),
        Err(ConfigError::InvalidLoadBalanceSelection { .. })
    ));
}

#[test]
fn rejects_maglev_for_dynamic_upstream_discovery() {
    let root = crate::test_support::unique_temp_path("maglev-dynamic");
    fs::create_dir_all(&root).unwrap();
    let upstreams_file = root.join("upstreams.txt");
    fs::write(&upstreams_file, "127.0.0.1:3001\n127.0.0.1:3002\n").unwrap();

    let file_config: Config = toml::from_str(&format!(
        r#"
            [proxy]
            upstreams_file = "{}"

            [proxy.load_balance]
            selection = "maglev-uri-hash"
            "#,
        upstreams_file.display()
    ))
    .unwrap();
    assert!(matches!(
        file_config.validate(),
        Err(ConfigError::InvalidLoadBalanceSelection { .. })
    ));

    let dns_config: Config = toml::from_str(
        r#"
            [proxy]
            upstreams = ["localhost:3001", "localhost:3002"]
            upstream_dns_refresh_secs = 5

            [proxy.load_balance]
            selection = "maglev-uri-hash"
            "#,
    )
    .unwrap();
    assert!(matches!(
        dns_config.validate(),
        Err(ConfigError::InvalidLoadBalanceSelection { .. })
    ));
}

#[test]
fn rejects_invalid_load_balance_all_down_status() {
    let config: Config = toml::from_str(
        r#"
            [proxy.load_balance]
            all_down_status = 404
            "#,
    )
    .unwrap();

    assert!(matches!(
        config.validate(),
        Err(ConfigError::InvalidLoadBalanceSelection { .. })
    ));
}

#[test]
fn rejects_invalid_load_balance_queue_policy() {
    let waiting_without_timeout: Config = toml::from_str(
        r#"
            [proxy.load_balance.queue]
            max_waiting = 10
            "#,
    )
    .unwrap();
    assert!(matches!(
        waiting_without_timeout.validate(),
        Err(ConfigError::InvalidLoadBalanceSelection { .. })
    ));

    let timeout_without_waiting: Config = toml::from_str(
        r#"
            [proxy.load_balance.queue]
            timeout_ms = 100
            "#,
    )
    .unwrap();
    assert!(matches!(
        timeout_without_waiting.validate(),
        Err(ConfigError::InvalidLoadBalanceSelection { .. })
    ));

    let invalid_retry_interval: Config = toml::from_str(
        r#"
            [proxy.load_balance.queue]
            max_waiting = 10
            timeout_ms = 100
            retry_interval_ms = 0
            "#,
    )
    .unwrap();
    assert!(matches!(
        invalid_retry_interval.validate(),
        Err(ConfigError::InvalidLoadBalanceSelection { .. })
    ));
}

#[test]
fn rejects_invalid_load_balance_health_check() {
    let config: Config = toml::from_str(
        r#"
            [proxy.load_balance.health_check]
            interval_secs = 0
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidLoadBalanceHealthCheck {
            field: "proxy.load_balance.health_check.interval_secs"
        })
    );

    let invalid_timeout: Config = toml::from_str(
        r#"
            [proxy.load_balance.health_check]
            connect_timeout_secs = 0
            "#,
    )
    .unwrap();

    assert_eq!(
        invalid_timeout.validate(),
        Err(ConfigError::InvalidProxyTimeout {
            field: "proxy.load_balance.health_check.connect_timeout_secs"
        })
    );
}

#[test]
fn rejects_invalid_http_load_balance_health_check() {
    let config: Config = toml::from_str(
        r#"
            [proxy.load_balance.health_check]
            protocol = "http"
            path = "relative"
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidLoadBalanceHealthCheck {
            field: "proxy.load_balance.health_check.path"
        })
    );

    let lowercase_method: Config = toml::from_str(
        r#"
            [proxy.load_balance.health_check]
            protocol = "http"
            method = "get"
            "#,
    )
    .unwrap();
    assert_eq!(
        lowercase_method.validate(),
        Err(ConfigError::InvalidLoadBalanceHealthCheck {
            field: "proxy.load_balance.health_check.method"
        })
    );

    let invalid_expected_header: Config = toml::from_str(
        r#"
            [proxy.load_balance.health_check]
            protocol = "http"

            [[proxy.load_balance.health_check.expected_headers]]
            name = "bad header"
            value = "ready"
            "#,
    )
    .unwrap();
    assert_eq!(
        invalid_expected_header.validate(),
        Err(ConfigError::InvalidLoadBalanceHealthCheck {
            field: "proxy.load_balance.health_check.expected_headers"
        })
    );

    let duplicate_expected_header: Config = toml::from_str(
        r#"
            [proxy.load_balance.health_check]
            protocol = "http"

            [[proxy.load_balance.health_check.expected_headers]]
            name = "x-health"
            value = "ready"

            [[proxy.load_balance.health_check.expected_headers]]
            name = "X-Health"
            value = "still-ready"
            "#,
    )
    .unwrap();
    assert_eq!(
        duplicate_expected_header.validate(),
        Err(ConfigError::InvalidLoadBalanceHealthCheck {
            field: "proxy.load_balance.health_check.expected_headers"
        })
    );

    let invalid_status_range: Config = toml::from_str(
        r#"
            [proxy.load_balance.health_check]
            protocol = "http"

            [[proxy.load_balance.health_check.expected_status_ranges]]
            start = 399
            end = 200
            "#,
    )
    .unwrap();
    assert_eq!(
        invalid_status_range.validate(),
        Err(ConfigError::InvalidLoadBalanceHealthCheck {
            field: "proxy.load_balance.health_check.expected_status_ranges"
        })
    );

    let invalid_body_substring: Config = toml::from_str(
        r#"
            [proxy.load_balance.health_check]
            protocol = "http"
            expected_body_contains = [""]
            "#,
    )
    .unwrap();
    assert_eq!(
        invalid_body_substring.validate(),
        Err(ConfigError::InvalidLoadBalanceHealthCheck {
            field: "proxy.load_balance.health_check.expected_body_contains"
        })
    );
}

#[test]
fn validates_load_balance_passive_health() {
    let config: Config = toml::from_str(
        r#"
            [proxy.load_balance.passive_health]
            enabled = true
            consecutive_failure = 2
            ejection_secs = 10
            failure_statuses = [500, 502, 503]
            failure_status_ranges = [{ start = 520, end = 529 }]
            max_latency_ms = 250
            "#,
    )
    .unwrap();
    config.validate().unwrap();
    assert_eq!(config.proxy.load_balance.passive_health.max_latency_ms, 250);
    assert_eq!(
        config
            .proxy
            .load_balance
            .passive_health
            .failure_status_ranges[0]
            .start,
        520
    );

    let invalid_status: Config = toml::from_str(
        r#"
            [proxy.load_balance.passive_health]
            enabled = true
            failure_statuses = [404]
            "#,
    )
    .unwrap();
    assert_eq!(
        invalid_status.validate(),
        Err(ConfigError::InvalidLoadBalancePassiveHealth {
            field: "proxy.load_balance.passive_health.failure_statuses"
        })
    );

    let invalid_status_range: Config = toml::from_str(
        r#"
            [proxy.load_balance.passive_health]
            enabled = true
            failure_status_ranges = [{ start = 499, end = 503 }]
            "#,
    )
    .unwrap();
    assert_eq!(
        invalid_status_range.validate(),
        Err(ConfigError::InvalidLoadBalancePassiveHealth {
            field: "proxy.load_balance.passive_health.failure_status_ranges"
        })
    );

    let invalid_latency: Config = toml::from_str(
        r#"
            [proxy.load_balance.passive_health]
            max_latency_ms = 600001
            "#,
    )
    .unwrap();
    assert_eq!(
        invalid_latency.validate(),
        Err(ConfigError::InvalidLoadBalancePassiveHealth {
            field: "proxy.load_balance.passive_health.max_latency_ms"
        })
    );
}

#[test]
fn rejects_invalid_load_balance_slow_start() {
    let config: Config = toml::from_str(
        r#"
            [proxy.load_balance.slow_start]
            enabled = true
            duration_secs = 0
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidLoadBalanceSlowStart {
            field: "proxy.load_balance.slow_start.duration_secs"
        })
    );
}

#[test]
fn rejects_invalid_load_balance_persistence() {
    let invalid_ttl: Config = toml::from_str(
        r#"
            [proxy.load_balance.persistence]
            enabled = true
            ttl_secs = 0
            "#,
    )
    .unwrap();
    assert_eq!(
        invalid_ttl.validate(),
        Err(ConfigError::InvalidLoadBalanceSelection {
            reason: "proxy.load_balance.persistence.ttl_secs must be between 1 and 86400"
        })
    );

    let invalid_table: Config = toml::from_str(
        r#"
            [proxy.load_balance.persistence]
            enabled = true
            table_max_entries = 0
            "#,
    )
    .unwrap();
    assert_eq!(
        invalid_table.validate(),
        Err(ConfigError::InvalidLoadBalanceSelection {
            reason: "proxy.load_balance.persistence.table_max_entries must be between 1 and 1000000"
        })
    );

    let missing_header: Config = toml::from_str(
        r#"
            [proxy.load_balance.persistence]
            enabled = true
            mode = "header"
            "#,
    )
    .unwrap();
    assert_eq!(
        missing_header.validate(),
        Err(ConfigError::InvalidLoadBalanceSelection {
            reason: "proxy.load_balance.persistence.header is required when mode = \"header\""
        })
    );

    let header_with_source_ip: Config = toml::from_str(
        r#"
            [proxy.load_balance.persistence]
            enabled = true
            mode = "source-ip"
            header = "x-session"
            "#,
    )
    .unwrap();
    assert_eq!(
        header_with_source_ip.validate(),
        Err(ConfigError::InvalidLoadBalanceSelection {
            reason: "proxy.load_balance.persistence.header can only be used with mode = \"header\""
        })
    );

    let invalid_header: Config = toml::from_str(
        r#"
            [proxy.load_balance.persistence]
            enabled = true
            mode = "header"
            header = "bad header"
            "#,
    )
    .unwrap();
    assert_eq!(
        invalid_header.validate(),
        Err(ConfigError::InvalidHeaderName {
            field: "proxy.load_balance.persistence.header",
            name: "bad header".to_owned()
        })
    );

    let missing_cookie: Config = toml::from_str(
        r#"
            [proxy.load_balance.persistence]
            enabled = true
            mode = "cookie"
            "#,
    )
    .unwrap();
    assert_eq!(
        missing_cookie.validate(),
        Err(ConfigError::InvalidLoadBalanceSelection {
            reason: "proxy.load_balance.persistence.cookie is required when mode = \"cookie\""
        })
    );

    let cookie_with_source_ip: Config = toml::from_str(
        r#"
            [proxy.load_balance.persistence]
            enabled = true
            mode = "source-ip"
            cookie = "sid"
            "#,
    )
    .unwrap();
    assert_eq!(
        cookie_with_source_ip.validate(),
        Err(ConfigError::InvalidLoadBalanceSelection {
            reason: "proxy.load_balance.persistence.cookie can only be used with mode = \"cookie\""
        })
    );

    let invalid_cookie: Config = toml::from_str(
        r#"
            [proxy.load_balance.persistence]
            enabled = true
            mode = "cookie"
            cookie = "bad cookie"
            "#,
    )
    .unwrap();
    assert_eq!(
        invalid_cookie.validate(),
        Err(ConfigError::InvalidLoadBalanceSelection {
            reason: "proxy.load_balance.persistence.cookie must be a valid cookie name"
        })
    );
}

#[test]
fn validates_load_balance_retry_policy() {
    let config: Config = toml::from_str(
        r#"
            [proxy.load_balance.retry]
            enabled = true
            max_retries = 2
            methods = ["GET", "HEAD"]
            statuses = [500, 502, 503]
            status_ranges = [{ start = 520, end = 529 }]
            budget_per_window = 100
            budget_window_secs = 10
            "#,
    )
    .unwrap();
    config.validate().unwrap();
    assert_eq!(config.proxy.load_balance.retry.budget_per_window, 100);
    assert_eq!(config.proxy.load_balance.retry.budget_window_secs, 10);
    assert_eq!(config.proxy.load_balance.retry.statuses, [500, 502, 503]);
    assert_eq!(config.proxy.load_balance.retry.status_ranges[0].start, 520);

    let unsafe_method: Config = toml::from_str(
        r#"
            [proxy.load_balance.retry]
            enabled = true
            methods = ["POST"]
            "#,
    )
    .unwrap();
    assert_eq!(
        unsafe_method.validate(),
        Err(ConfigError::InvalidLoadBalanceRetry {
            field: "proxy.load_balance.retry.methods"
        })
    );

    let invalid_budget: Config = toml::from_str(
        r#"
            [proxy.load_balance.retry]
            budget_window_secs = 0
            "#,
    )
    .unwrap();
    assert_eq!(
        invalid_budget.validate(),
        Err(ConfigError::InvalidLoadBalanceRetry {
            field: "proxy.load_balance.retry.budget_window_secs"
        })
    );

    let invalid_status: Config = toml::from_str(
        r#"
            [proxy.load_balance.retry]
            statuses = [404]
            "#,
    )
    .unwrap();
    assert_eq!(
        invalid_status.validate(),
        Err(ConfigError::InvalidLoadBalanceRetry {
            field: "proxy.load_balance.retry.statuses"
        })
    );

    let duplicate_status: Config = toml::from_str(
        r#"
            [proxy.load_balance.retry]
            statuses = [500, 500]
            "#,
    )
    .unwrap();
    assert_eq!(
        duplicate_status.validate(),
        Err(ConfigError::InvalidLoadBalanceRetry {
            field: "proxy.load_balance.retry.statuses"
        })
    );

    let invalid_status_range: Config = toml::from_str(
        r#"
            [proxy.load_balance.retry]
            status_ranges = [{ start = 499, end = 503 }]
            "#,
    )
    .unwrap();
    assert_eq!(
        invalid_status_range.validate(),
        Err(ConfigError::InvalidLoadBalanceRetry {
            field: "proxy.load_balance.retry.status_ranges"
        })
    );
}

#[test]
fn parses_server_limits() {
    let config: Config = toml::from_str(
        r#"
            [server]
            trusted_proxies = ["127.0.0.1", "10.0.0.0/8", "2001:db8::/32"]
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
        ["127.0.0.1", "10.0.0.0/8", "2001:db8::/32"]
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
fn parses_tls_acme_config_with_actalis_eab() {
    let storage = secure_test_dir("config-actalis-acme");
    let config: Config = toml::from_str(&format!(
        r#"
            [tls]
            enabled = true
            backend = "rustls"

            [tls.acme]
            enabled = true
            storage = "{}"
            contact_email = "admin@example.test"
            default_issuer = "actalis"
            challenge = "http-01"
            automation = "external"

            [tls.acme.renewal]
            enabled = true
            renew_before_secs = 2592000
            renew_after = 2026-06-01T00:00:00Z
            check_interval_secs = 3600
            retry_initial_secs = 300
            retry_max_secs = 86400
            reload_after_renewal = true
            zero_downtime_reload = true

            [[tls.acme.issuers]]
            name = "actalis"
            directory_url = "https://acme-api.actalis.com/acme/directory"

            [tls.acme.issuers.eab]
            key_id_env = "FLUXHEIM_ACTALIS_EAB_KID"
            hmac_key_env = "FLUXHEIM_ACTALIS_EAB_HMAC_KEY"
            "#,
        storage.display()
    ))
    .unwrap();

    assert!(config.tls.enabled);
    assert_eq!(config.tls.backend, super::TlsBackend::Rustls);
    assert!(config.tls.acme.enabled);
    assert_eq!(config.tls.acme.storage, Some(storage));
    assert_eq!(config.tls.acme.default_issuer, "actalis");
    assert_eq!(config.tls.acme.challenge, super::AcmeChallenge::Http01);
    assert_eq!(
        config.tls.acme.automation,
        super::AcmeAutomationMode::External
    );
    assert_eq!(config.tls.acme.renewal.renew_before_secs, 2_592_000);
    assert!(config.tls.acme.renewal.renew_after.is_some());
    config.validate().unwrap();
}

#[test]
fn accepts_tls_alpn_acme_with_rustls_tls_listener() {
    let storage = secure_test_dir("config-tls-alpn-acme");
    let config: Config = toml::from_str(&format!(
        r#"
            [server]
            tls_listen = ["127.0.0.1:8443"]

            [tls]
            enabled = true
            backend = "rustls"

            [[tls.certificates]]
            cert_path = "tests/fixtures/tls/localhost-cert.pem"
            key_path = "tests/fixtures/tls/localhost-key.pem"

            [tls.acme]
            enabled = true
            storage = "{}"
            contact_email = "admin@example.test"
            challenge = "tls-alpn-01"
            "#,
        storage.display()
    ))
    .unwrap();

    assert_eq!(config.tls.acme.challenge, super::AcmeChallenge::TlsAlpn01);
    config.validate().unwrap();
}

#[test]
fn rejects_tls_alpn_acme_without_tls_listener() {
    let storage = secure_test_dir("config-tls-alpn-no-listener");
    let config: Config = toml::from_str(&format!(
        r#"
            [tls]
            enabled = true
            backend = "rustls"

            [tls.acme]
            enabled = true
            storage = "{}"
            contact_email = "admin@example.test"
            challenge = "tls-alpn-01"
            "#,
        storage.display()
    ))
    .unwrap();

    assert!(matches!(
        config.validate(),
        Err(ConfigError::InvalidTlsPolicy {
            field: "tls.acme.challenge",
            ..
        })
    ));
}

#[test]
fn parses_tls_policy_config() {
    let config: Config = toml::from_str(
        r#"
            [tls]
            enabled = true
            profile = "modern"
            min_protocol = "tls1.3"
            alpn = "http2"
            curve_preferences = ["X25519", "CurveP256", "CurveP384"]
            cipher_suites = ["TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"]
            "#,
    )
    .unwrap();

    assert_eq!(config.tls.profile, TlsPolicyProfile::Modern);
    assert_eq!(
        config.tls.effective_min_protocol(),
        TlsProtocolVersion::Tls13
    );
    assert_eq!(config.tls.effective_alpn(), TlsAlpnPolicy::Http2);
    assert_eq!(
        config.tls.effective_curve_preferences(),
        [
            TlsCurvePreference::X25519,
            TlsCurvePreference::P256,
            TlsCurvePreference::P384
        ]
    );
    assert_eq!(
        config.tls.effective_cipher_suites(),
        [
            TlsCipherSuite::Tls13Aes256GcmSha384,
            TlsCipherSuite::Tls13Chacha20Poly1305Sha256
        ]
    );
    config.validate().unwrap();
}

#[test]
fn parses_tls_fips_config_and_requires_fips_capable_build() {
    let config: Config = toml::from_str(
        r#"
            [tls]
            enabled = true
            backend = "openssl"
            curve_preferences = ["CurveP256", "CurveP384"]
            cipher_suites = [
              "TLS_AES_256_GCM_SHA384",
              "TLS_AES_128_GCM_SHA256",
              "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            ]

            [tls.fips]
            required = true
            "#,
    )
    .unwrap();

    assert!(config.tls.fips.required);
    assert_eq!(config.tls.compliance_mode().label(), "FIPS 140-3");

    #[cfg(not(any(feature = "tls-rustls-fips", feature = "tls-openssl-fips")))]
    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidTlsPolicy {
            field: "tls.fips.required",
            reason: "FIPS-required mode requires a FIPS-capable TLS backend feature such as tls-rustls-fips or tls-openssl-fips; see docs/fips.md",
        })
    );

    #[cfg(feature = "tls-openssl-fips")]
    assert_eq!(config.validate(), Ok(()));

    #[cfg(all(feature = "tls-rustls-fips", not(feature = "tls-openssl-fips")))]
    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidTlsPolicy {
            field: "tls.backend",
            reason: "tls.fips.required requires a configured backend supported by this FIPS-capable build",
        })
    );
}

#[test]
fn parses_tls_iso19790_config_as_required_compliance_alias() {
    let config: Config = toml::from_str(
        r#"
            [tls]
            enabled = true
            backend = "openssl"
            curve_preferences = ["CurveP256", "CurveP384"]
            cipher_suites = [
              "TLS_AES_256_GCM_SHA384",
              "TLS_AES_128_GCM_SHA256",
              "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            ]

            [tls.iso19790]
            required = true
            "#,
    )
    .unwrap();

    assert!(config.tls.iso19790.required);
    assert_eq!(config.tls.compliance_mode().label(), "ISO/IEC 19790");

    #[cfg(not(any(feature = "tls-rustls-fips", feature = "tls-openssl-fips")))]
    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidTlsPolicy {
            field: "tls.iso19790.required",
            reason: "ISO/IEC 19790-required mode requires a FIPS/ISO-capable TLS backend feature such as tls-rustls-fips, tls-openssl-fips, or tls-openssl-iso19790; see docs/fips.md",
        })
    );

    #[cfg(feature = "tls-openssl-fips")]
    assert_eq!(config.validate(), Ok(()));

    #[cfg(all(feature = "tls-rustls-fips", not(feature = "tls-openssl-fips")))]
    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidTlsPolicy {
            field: "tls.backend",
            reason: "tls.iso19790.required requires a configured backend supported by this FIPS/ISO-capable build",
        })
    );
}

#[test]
#[cfg(any(feature = "tls-rustls-fips", feature = "tls-openssl-fips"))]
fn rejects_tls_fips_policy_with_unsupported_backend_for_build() {
    #[cfg(feature = "tls-openssl-fips")]
    let backend = "rustls";
    #[cfg(all(feature = "tls-rustls-fips", not(feature = "tls-openssl-fips")))]
    let backend = "openssl";
    let config: Config = toml::from_str(&format!(
        r#"
            [tls]
            enabled = true
            backend = "{backend}"
            curve_preferences = ["CurveP256", "CurveP384"]
            cipher_suites = ["TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256"]

            [tls.fips]
            required = true
            "#
    ))
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidTlsPolicy {
            field: "tls.backend",
            reason: "tls.fips.required requires a configured backend supported by this FIPS-capable build",
        })
    );
}

#[test]
fn rejects_tls_fips_policy_with_non_nist_group() {
    let config: Config = toml::from_str(
        r#"
            [tls]
            curve_preferences = ["X25519", "CurveP256"]

            [tls.fips]
            required = true
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidTlsPolicy {
            field: "tls.curve_preferences",
            reason: "tls.fips.required rejects non-NIST or unproven hybrid groups; use CurveP256 and/or CurveP384 until a validated provider supports more",
        })
    );
}

#[test]
fn rejects_tls_fips_policy_with_chacha20_cipher() {
    let config: Config = toml::from_str(
        r#"
            [tls]
            curve_preferences = ["CurveP256", "CurveP384"]
            cipher_suites = ["TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"]

            [tls.fips]
            required = true
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidTlsPolicy {
            field: "tls.cipher_suites",
            reason: "tls.fips.required rejects non-FIPS cipher suites such as ChaCha20; use AES-GCM/SHA-2 suites from the selected validated provider",
        })
    );
}

#[cfg(any(feature = "tls-rustls-fips", feature = "tls-openssl-fips"))]
fn fips_capable_backend_for_tests() -> &'static str {
    #[cfg(feature = "tls-openssl-fips")]
    {
        "openssl"
    }
    #[cfg(all(not(feature = "tls-openssl-fips"), feature = "tls-rustls-fips"))]
    {
        "rustls"
    }
}

#[test]
#[cfg(any(feature = "tls-rustls-fips", feature = "tls-openssl-fips"))]
fn fips_required_accepts_provider_backed_admin_auth() {
    let snapshot_store = secure_test_dir("config-fips-admin-snapshot-store");
    let backend = fips_capable_backend_for_tests();
    let config: Config = toml::from_str(&format!(
        r#"
            [admin]
            enabled = true
            token_env = "FLUXHEIM_ADMIN_TOKEN"
            snapshot_store = "{}"

            [tls]
            backend = "{backend}"
            curve_preferences = ["CurveP256", "CurveP384"]
            cipher_suites = ["TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256"]

            [tls.fips]
            required = true
            "#,
        snapshot_store.display()
    ))
    .unwrap();

    assert_eq!(config.validate(), Ok(()));
}

#[test]
#[cfg(any(feature = "tls-rustls-fips", feature = "tls-openssl-fips"))]
fn fips_required_rejects_managed_acme_internal_crypto() {
    let storage = secure_test_dir("config-fips-managed-acme");
    let backend = fips_capable_backend_for_tests();
    let config: Config = toml::from_str(&format!(
        r#"
            [tls]
            backend = "{backend}"
            curve_preferences = ["CurveP256", "CurveP384"]
            cipher_suites = ["TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256"]

            [tls.fips]
            required = true

            [tls.acme]
            enabled = true
            storage = "{}"
            contact_email = "admin@example.test"
            "#,
        storage.display()
    ))
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidCompliancePolicy {
            field: "tls.acme.enabled",
            reason: "FIPS/ISO-required mode currently rejects managed ACME because account key generation, JWS account signing, EAB handling, outbound ACME HTTPS transport, and TLS-ALPN challenge certificate generation are not fully routed through the selected validated provider; use externally issued static certificates or an externally evidenced renewal process for the FIPS evidence boundary",
        })
    );
}

#[test]
#[cfg(any(feature = "tls-rustls-fips", feature = "tls-openssl-fips"))]
fn fips_required_can_require_disk_cache_encryption() {
    let root = secure_test_dir("config-fips-require-disk-cache-encryption");
    let backend = fips_capable_backend_for_tests();
    let config: Config = toml::from_str(&format!(
        r#"
            [tls]
            backend = "{backend}"
            curve_preferences = ["CurveP256", "CurveP384"]
            cipher_suites = ["TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256"]

            [tls.fips]
            required = true
            require_disk_cache_encryption = true

            [cache]
            enabled = true

            [cache.disk]
            enabled = true
            path = "{}"
            "#,
        root.display()
    ))
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidCompliancePolicy {
            field: "cache",
            reason: "FIPS/ISO-required mode requires disk cache encryption because tls.fips.require_disk_cache_encryption or tls.iso19790.require_disk_cache_encryption is enabled",
        })
    );
}

#[test]
#[cfg(any(feature = "tls-rustls-fips", feature = "tls-openssl-fips"))]
fn fips_required_rejects_local_cache_encryption() {
    let root = secure_test_dir("config-fips-local-cache-encryption");
    let backend = fips_capable_backend_for_tests();
    let config: Config = toml::from_str(&format!(
        r#"
            [tls]
            backend = "{backend}"
            curve_preferences = ["CurveP256", "CurveP384"]
            cipher_suites = ["TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256"]

            [tls.fips]
            required = true

            [cache]
            enabled = true

            [cache.disk]
            enabled = true
            path = "{}"

            [cache.disk.encryption]
            enabled = true
            provider = "local"
            key_credential = "fluxheim-cache-key"
            "#,
        root.display()
    ))
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidCompliancePolicy {
            field: "cache",
            reason: "FIPS/ISO-required mode rejects local cache encryption because it currently uses ring AES-GCM; use provider = \"openbao-transit\" with external validation evidence or disable cache encryption",
        })
    );
}

#[test]
#[cfg(any(feature = "tls-rustls-fips", feature = "tls-openssl-fips"))]
fn fips_required_allows_openbao_transit_cache_encryption_boundary() {
    let root = secure_test_dir("config-fips-openbao-cache-encryption");
    let backend = fips_capable_backend_for_tests();
    let config: Config = toml::from_str(&format!(
        r#"
            [tls]
            backend = "{backend}"
            curve_preferences = ["CurveP256", "CurveP384"]
            cipher_suites = ["TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256"]

            [tls.fips]
            required = true

            [cache]
            enabled = true

            [cache.disk]
            enabled = true
            path = "{}"

            [cache.disk.encryption]
            enabled = true
            provider = "openbao-transit"

            [cache.disk.encryption.openbao]
            address = "http://127.0.0.1:8200"
            mount = "transit"
            key_name = "fluxheim-cache"
            token_credential = "openbao-token"
            "#,
        root.display()
    ))
    .unwrap();

    assert_eq!(config.validate(), Ok(()));
}

#[test]
#[cfg(any(feature = "tls-rustls-fips", feature = "tls-openssl-fips"))]
fn fips_required_rejects_remote_openbao_transit_cache_encryption_boundary() {
    let root = secure_test_dir("config-fips-remote-openbao-cache-encryption");
    let backend = fips_capable_backend_for_tests();
    let config: Config = toml::from_str(&format!(
        r#"
            [tls]
            backend = "{backend}"
            curve_preferences = ["CurveP256", "CurveP384"]
            cipher_suites = ["TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256"]

            [tls.fips]
            required = true

            [cache]
            enabled = true

            [cache.disk]
            enabled = true
            path = "{}"

            [cache.disk.encryption]
            enabled = true
            provider = "openbao-transit"

            [cache.disk.encryption.openbao]
            address = "https://openbao.internal.example"
            mount = "transit"
            key_name = "fluxheim-cache"
            token_credential = "openbao-token"
            "#,
        root.display()
    ))
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidCompliancePolicy {
            field: "cache",
            reason: "FIPS/ISO-required mode allows OpenBao Transit only through local http://127.0.0.1 or http://[::1] loopback; remote or HTTPS OpenBao transport needs provider-aligned outbound TLS evidence first",
        })
    );
}

#[test]
fn fips_otlp_local_collector_exception_accepts_loopback_http_only() {
    assert!(super::fips_allowed_local_otlp_endpoint(
        "http://127.0.0.1:4318/v1/traces"
    ));
    assert!(!super::fips_allowed_local_otlp_endpoint(
        "http://localhost/v1/traces"
    ));
    assert!(super::fips_allowed_local_otlp_endpoint(
        "http://[::1]:4318/v1/traces"
    ));
    assert!(!super::fips_allowed_local_otlp_endpoint(
        "https://127.0.0.1:4318/v1/traces"
    ));
    assert!(!super::fips_allowed_local_otlp_endpoint(
        "http://collector.example.test/v1/traces"
    ));
    assert!(!super::fips_allowed_local_otlp_endpoint(
        "http://[::1]example.test/v1/traces"
    ));
    assert!(!super::fips_allowed_local_otlp_endpoint(
        "http://127.0.0.1:0/v1/traces"
    ));
    assert!(!super::fips_allowed_local_otlp_endpoint(
        "http://127.0.0.1:4318/v1/traces?debug=true"
    ));
    assert!(!super::fips_allowed_local_otlp_endpoint(
        "http://127.0.0.1:4318/v1/traces#fragment"
    ));
    assert!(!super::fips_allowed_local_otlp_endpoint(
        "http://127.0.0.1:4318/v1/traces\n"
    ));
}

#[test]
fn fips_openbao_endpoint_accepts_numeric_loopback_http_only() {
    assert!(super::fips_allowed_local_openbao_endpoint(
        "http://127.0.0.1:8200"
    ));
    assert!(super::fips_allowed_local_openbao_endpoint(
        "http://[::1]:8200"
    ));
    assert!(!super::fips_allowed_local_openbao_endpoint(
        "http://localhost:8200"
    ));
    assert!(!super::fips_allowed_local_openbao_endpoint(
        "https://127.0.0.1:8200"
    ));
    assert!(!super::fips_allowed_local_openbao_endpoint(
        "https://openbao.internal.example"
    ));
    assert!(!super::fips_allowed_local_openbao_endpoint(
        "http://[::1]attacker.example.test"
    ));
}

#[test]
fn fips_auth_request_endpoint_accepts_numeric_loopback_http_only() {
    assert!(super::fips_allowed_local_auth_request_endpoint(
        "http://127.0.0.1:4180/auth"
    ));
    assert!(super::fips_allowed_local_auth_request_endpoint(
        "http://[::1]:4180/auth"
    ));
    assert!(!super::fips_allowed_local_auth_request_endpoint(
        "http://127.0.0.1:4180"
    ));
    assert!(!super::fips_allowed_local_auth_request_endpoint(
        "http://localhost:4180/auth"
    ));
    assert!(!super::fips_allowed_local_auth_request_endpoint(
        "https://127.0.0.1:4180/auth"
    ));
    assert!(!super::fips_allowed_local_auth_request_endpoint(
        "http://[::1]attacker.example.test/auth"
    ));
}

#[test]
fn fips_mirror_endpoint_accepts_numeric_loopback_http_only() {
    assert!(super::fips_allowed_local_mirror_endpoint(
        "http://127.0.0.1:9000"
    ));
    assert!(super::fips_allowed_local_mirror_endpoint(
        "http://[::1]:9000/shadow"
    ));
    assert!(!super::fips_allowed_local_mirror_endpoint(
        "http://localhost:9000"
    ));
    assert!(!super::fips_allowed_local_mirror_endpoint(
        "https://127.0.0.1:9000"
    ));
    assert!(!super::fips_allowed_local_mirror_endpoint(
        "http://[::1]attacker.example.test"
    ));
}

#[test]
fn rejects_too_many_tls_curve_preferences() {
    let curve_preferences = (0..=super::MAX_TLS_CURVE_PREFERENCES)
        .map(|_| "\"X25519\"")
        .collect::<Vec<_>>()
        .join(", ");
    let config: Config = toml::from_str(&format!(
        r#"
            [tls]
            curve_preferences = [{curve_preferences}]
            "#,
    ))
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidConfigListLength {
            field: "tls.curve_preferences".to_owned(),
            max: super::MAX_TLS_CURVE_PREFERENCES,
        })
    );
}

#[test]
fn rejects_too_many_tls_cipher_suites() {
    let cipher_suites = (0..=super::MAX_TLS_CIPHER_SUITES)
        .map(|_| "\"TLS_AES_256_GCM_SHA384\"")
        .collect::<Vec<_>>()
        .join(", ");
    let config: Config = toml::from_str(&format!(
        r#"
            [tls]
            cipher_suites = [{cipher_suites}]
            "#,
    ))
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidConfigListLength {
            field: "tls.cipher_suites".to_owned(),
            max: super::MAX_TLS_CIPHER_SUITES,
        })
    );
}

#[test]
fn rejects_too_many_tls_certificates() {
    let certificates = (0..=super::MAX_TLS_CERTIFICATES)
        .map(|index| {
            format!(
                r#"
                    [[tls.certificates]]
                    cert_path = "tests/fixtures/tls/cert-{index}.pem"
                    key_path = "tests/fixtures/tls/key-{index}.pem"
                    "#
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let config: Config = toml::from_str(&certificates).unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidConfigListLength {
            field: "tls.certificates".to_owned(),
            max: super::MAX_TLS_CERTIFICATES,
        })
    );
}

#[test]
fn accepts_tls_client_auth_required_with_ca_bundle() {
    let config: Config = toml::from_str(
        r#"
            [tls.client_auth]
            mode = "required"
            ca_path = "tests/fixtures/tls/localhost-cert.pem"
            "#,
    )
    .unwrap();

    config.validate().unwrap();
    assert_eq!(config.tls.client_auth.mode, TlsClientAuthMode::Required);
    assert_eq!(
        config.tls.client_auth.ca_path.as_deref(),
        Some(std::path::Path::new(
            "tests/fixtures/tls/localhost-cert.pem"
        ))
    );
}

#[test]
fn rejects_tls_client_auth_without_ca_bundle() {
    let config: Config = toml::from_str(
        r#"
            [tls.client_auth]
            mode = "optional"
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidTlsPolicy {
            field: "tls.client_auth.ca_path",
            reason: "tls.client_auth.mode requires a client CA bundle path"
        })
    );
}

#[test]
fn rejects_tls_client_auth_with_s2n_for_now() {
    let config: Config = toml::from_str(
        r#"
            [tls]
            backend = "s2n"

            [tls.client_auth]
            mode = "required"
            ca_path = "tests/fixtures/tls/localhost-cert.pem"
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidTlsPolicy {
            field: "tls.client_auth.mode",
            reason: "the s2n backend has mTLS primitives, but Fluxheim does not yet expose panic-free CA bundle loading for listener client auth; use rustls, OpenSSL, or BoringSSL for client certificate authentication"
        })
    );
}

#[test]
fn rejects_too_many_acme_issuers() {
    let issuers = (0..=super::MAX_ACME_ISSUERS)
        .map(|index| {
            format!(
                r#"
                    [[tls.acme.issuers]]
                    name = "issuer-{index}"
                    directory_url = "https://issuer-{index}.example.test/acme/directory"
                    "#
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let config: Config = toml::from_str(&issuers).unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidConfigListLength {
            field: "tls.acme.issuers".to_owned(),
            max: super::MAX_ACME_ISSUERS,
        })
    );
}

#[test]
fn rejects_too_many_vhost_acme_domains() {
    let storage = secure_test_dir("config-vhost-acme-too-many-domains");
    let domains = (0..=super::MAX_VHOST_ACME_DOMAINS)
        .map(|index| format!("\"alias-{index}.example.test\""))
        .collect::<Vec<_>>()
        .join(", ");
    let config: Config = toml::from_str(&format!(
        r#"
            [tls.acme]
            enabled = true
            storage = "{}"
            contact_email = "admin@example.test"
            default_issuer = "letsencrypt"

            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example.test"]

            [vhosts.tls]
            enabled = true

            [vhosts.tls.acme]
            enabled = true
            domains = [{domains}]
            "#,
        storage.display()
    ))
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::VhostSection {
            vhost: "gateway".to_owned(),
            section: "tls",
            source: Box::new(ConfigError::InvalidConfigListLength {
                field: "vhosts.tls.acme.domains".to_owned(),
                max: super::MAX_VHOST_ACME_DOMAINS,
            })
        })
    );
}

#[test]
fn rejects_modern_tls_policy_with_tls12_override() {
    let config: Config = toml::from_str(
        r#"
            [tls]
            profile = "modern"
            min_protocol = "tls1.2"
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidTlsPolicy {
            field: "tls.min_protocol",
            reason: "tls.profile = \"modern\" requires min_protocol = \"tls1.3\""
        })
    );
}

#[test]
fn rejects_tls12_cipher_suites_with_tls13_minimum() {
    let config: Config = toml::from_str(
        r#"
            [tls]
            min_protocol = "tls1.3"
            cipher_suites = ["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"]
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidTlsPolicy {
            field: "tls.cipher_suites",
            reason: "TLS 1.2 cipher suites cannot be used when min_protocol = \"tls1.3\""
        })
    );
}

#[test]
fn rejects_boringssl_explicit_tls13_cipher_suites() {
    let config: Config = toml::from_str(
        r#"
            [tls]
            backend = "boringssl"
            cipher_suites = ["TLS_AES_256_GCM_SHA384"]
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidTlsPolicy {
            field: "tls.cipher_suites",
            reason: "the BoringSSL backend does not expose Fluxheim-controlled TLS 1.3 cipher-suite allow-lists; omit TLS 1.3 cipher_suites or use the OpenSSL/rustls backend"
        })
    );
}

#[test]
fn allows_intermediate_profile_with_tls13_minimum_when_ciphers_are_implicit() {
    let config: Config = toml::from_str(
        r#"
            [tls]
            profile = "intermediate"
            min_protocol = "VersionTLS13"
            "#,
    )
    .unwrap();

    assert_eq!(config.tls.profile, TlsPolicyProfile::Intermediate);
    assert_eq!(
        config.tls.effective_min_protocol(),
        TlsProtocolVersion::Tls13
    );
    config.validate().unwrap();
}

#[cfg(unix)]
#[test]
fn rejects_tls_certificate_paths_under_world_writable_parent() {
    let cert_path = unique_world_writable_child("config-tls-world-writable", "fullchain.pem");
    let key_path = safe_child_path(&secure_test_dir("config-tls-world-writable-key"), "key.pem");
    let config: Config = toml::from_str(&format!(
        r#"
            [tls]
            enabled = true

            [[tls.certificates]]
            cert_path = "{}"
            key_path = "{}"
            "#,
        cert_path.display(),
        key_path.display()
    ))
    .unwrap();

    assert!(matches!(
        config.validate(),
        Err(ConfigError::UnsafePath { field, .. }) if field == "tls.certificates.cert_path"
    ));
}

#[cfg(unix)]
#[test]
fn rejects_tls_certificate_paths_under_group_writable_parent() {
    let cert_path = unique_group_writable_child("config-tls-group-writable", "fullchain.pem");
    let key_path = safe_child_path(&secure_test_dir("config-tls-group-writable-key"), "key.pem");
    let config: Config = toml::from_str(&format!(
        r#"
            [tls]
            enabled = true

            [[tls.certificates]]
            cert_path = "{}"
            key_path = "{}"
            "#,
        cert_path.display(),
        key_path.display()
    ))
    .unwrap();

    assert!(matches!(
        config.validate(),
        Err(ConfigError::UnsafePath { field, .. }) if field == "tls.certificates.cert_path"
    ));
}

#[cfg(unix)]
#[test]
fn rejects_acme_paths_under_world_writable_parent() {
    let storage = unique_world_writable_child("config-acme-world-writable", "acme");
    let config: Config = toml::from_str(&format!(
        r#"
            [tls.acme]
            enabled = true
            storage = "{}"
            contact_email = "admin@example.test"
            default_issuer = "actalis"

            [[tls.acme.issuers]]
            name = "actalis"
            directory_url = "https://acme-api.actalis.com/acme/directory"

            [tls.acme.issuers.eab]
            key_id_env = "FLUXHEIM_ACTALIS_EAB_KID"
            hmac_key_env = "FLUXHEIM_ACTALIS_EAB_HMAC_KEY"
            "#,
        storage.display()
    ))
    .unwrap();

    assert!(matches!(
        config.validate(),
        Err(ConfigError::UnsafePath { field, .. }) if field == "tls.acme.storage"
    ));
}

#[test]
fn path_inspection_error_mentions_permissions_and_service_user() {
    let error = ConfigError::PathInspectionFailed {
            field: "tls.acme.storage".to_owned(),
            path: PathBuf::from("/var/lib/fluxheim/acme"),
            reason: "permission denied while checking path ownership and symlinks: Permission denied (os error 13)".to_owned(),
        };
    let message = error.to_string();
    assert!(message.contains("could not be inspected"));
    assert!(message.contains("permission denied"));
    assert!(message.contains("Fluxheim service user"));
}

#[cfg(unix)]
#[test]
fn rejects_acme_eab_secret_paths_under_world_writable_parent() {
    let storage = secure_test_dir("config-acme-eab-storage");
    let key_id_file = unique_world_writable_child("config-acme-eab-world-writable", "key-id");
    let config: Config = toml::from_str(&format!(
        r#"
            [tls.acme]
            enabled = true
            storage = "{}"
            contact_email = "admin@example.test"
            default_issuer = "actalis"

            [[tls.acme.issuers]]
            name = "actalis"
            directory_url = "https://acme-api.actalis.com/acme/directory"

            [tls.acme.issuers.eab]
            key_id_file = "{}"
            hmac_key_env = "FLUXHEIM_ACTALIS_EAB_HMAC_KEY"
            "#,
        storage.display(),
        key_id_file.display()
    ))
    .unwrap();

    assert!(matches!(
        config.validate(),
        Err(ConfigError::UnsafePath { field, .. })
            if field == "tls.acme.issuers.actalis.eab.key_id_file"
    ));
}

#[test]
fn accepts_acme_eab_credential_sources() {
    let storage = secure_test_dir("config-acme-eab-credentials");
    let config: Config = toml::from_str(&format!(
        r#"
            [tls.acme]
            enabled = true
            storage = "{}"
            contact_email = "admin@example.test"
            default_issuer = "actalis"

            [[tls.acme.issuers]]
            name = "actalis"
            directory_url = "https://acme-api.actalis.com/acme/directory"

            [tls.acme.issuers.eab]
            key_id_credential = "actalis-eab-kid"
            hmac_key_credential = "actalis-eab-hmac-key"
            "#,
        storage.display()
    ))
    .unwrap();

    let eab = config.tls.acme.issuers[0].eab.as_ref().unwrap();
    assert_eq!(eab.key_id_credential.as_deref(), Some("actalis-eab-kid"));
    assert_eq!(
        eab.hmac_key_credential.as_deref(),
        Some("actalis-eab-hmac-key")
    );
    config.validate().unwrap();
}

#[test]
fn rejects_unsafe_acme_eab_credential_source() {
    let storage = secure_test_dir("config-acme-eab-unsafe-credential");
    let config: Config = toml::from_str(&format!(
        r#"
            [tls.acme]
            enabled = true
            storage = "{}"
            contact_email = "admin@example.test"
            default_issuer = "actalis"

            [[tls.acme.issuers]]
            name = "actalis"
            directory_url = "https://acme-api.actalis.com/acme/directory"

            [tls.acme.issuers.eab]
            key_id_credential = "../actalis-eab-kid"
            hmac_key_credential = "actalis-eab-hmac-key"
            "#,
        storage.display()
    ))
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidAcmeEabCredentialName {
            issuer: "actalis".to_owned(),
            field: "key_id",
            credential: "../actalis-eab-kid".to_owned(),
        })
    );
}

#[test]
fn rejects_zero_acme_renewal_duration() {
    let config: Config = toml::from_str(
        r#"
            [tls.acme.renewal]
            renew_before_secs = 0
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidAcmeRenewalDuration {
            field: "tls.acme.renewal.renew_before_secs"
        })
    );
}

#[test]
fn rejects_local_acme_renew_after_datetime() {
    let config: Config = toml::from_str(
        r#"
            [tls.acme.renewal]
            renew_after = 2026-06-01T00:00:00
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidAcmeRenewAfterDatetime)
    );
}

#[test]
fn rejects_acme_renewal_retry_initial_over_max() {
    let config: Config = toml::from_str(
        r#"
            [tls.acme.renewal]
            retry_initial_secs = 60
            retry_max_secs = 30
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::AcmeRenewalRetryInitialExceedsMax)
    );
}

#[test]
fn rejects_enabled_acme_without_storage() {
    let config: Config = toml::from_str(
        r#"
            [tls.acme]
            enabled = true
            contact_email = "admin@example.test"
            "#,
    )
    .unwrap();

    assert_eq!(config.validate(), Err(ConfigError::MissingAcmeStorage));
}

#[test]
fn rejects_vhost_tls_without_certificate_source() {
    let config: Config = toml::from_str(
        r#"
            [[vhosts]]
            name = "example"
            hosts = ["example.test"]

            [vhosts.tls]
            enabled = true
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::VhostSection {
            vhost: "example".to_owned(),
            section: "tls",
            source: Box::new(ConfigError::TlsEnabledWithoutCertificateSource {
                scope: "vhosts.tls"
            })
        })
    );
}

#[test]
fn rejects_vhost_acme_without_global_acme() {
    let config: Config = toml::from_str(
        r#"
            [[vhosts]]
            name = "example"
            hosts = ["example.test"]

            [vhosts.tls]
            enabled = true

            [vhosts.tls.acme]
            enabled = true
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::VhostSection {
            vhost: "example".to_owned(),
            section: "tls",
            source: Box::new(ConfigError::VhostAcmeWithoutGlobalAcme {
                scope: "vhosts.tls"
            })
        })
    );
}

#[test]
fn accepts_vhost_acme_inheriting_exact_hosts() {
    let storage = secure_test_dir("config-vhost-acme-exact-hosts");
    let config: Config = toml::from_str(&format!(
        r#"
            [tls.acme]
            enabled = true
            storage = "{}"
            contact_email = "admin@example.test"

            [[vhosts]]
            name = "example"
            hosts = ["example.test", "*.example.test"]

            [vhosts.tls]
            enabled = true

            [vhosts.tls.acme]
            enabled = true
            "#,
        storage.display()
    ))
    .unwrap();

    config.validate().unwrap();
}

#[cfg(feature = "acme")]
#[test]
fn accepts_tls_alias_vhost_covered_by_managed_acme_san() {
    let storage = secure_test_dir("config-vhost-acme-san-alias");
    let config: Config = toml::from_str(&format!(
        r#"
            [tls.acme]
            enabled = true
            storage = "{}"
            contact_email = "admin@example.test"

            [[vhosts]]
            name = "apex"
            hosts = ["example.test"]

            [vhosts.tls]
            enabled = true

            [vhosts.tls.acme]
            enabled = true
            domains = ["example.test", "www.example.test"]

            [[vhosts]]
            name = "www"
            hosts = ["www.example.test"]

            [vhosts.tls]
            enabled = true

            [vhosts.redirect]
            enabled = true
            to = "https://example.test{{uri}}"
            "#,
        storage.display()
    ))
    .unwrap();

    config.validate().unwrap();
}

#[test]
fn rejects_duplicate_vhost_acme_domains() {
    let storage = secure_test_dir("config-vhost-acme-duplicate-domains");
    let config: Config = toml::from_str(&format!(
        r#"
            [tls.acme]
            enabled = true
            storage = "{}"
            contact_email = "admin@example.test"

            [[vhosts]]
            name = "example"
            hosts = ["example.test"]

            [vhosts.tls]
            enabled = true

            [vhosts.tls.acme]
            enabled = true
            domains = ["Example.Test", "example.test"]
            "#,
        storage.display()
    ))
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::VhostSection {
            vhost: "example".to_owned(),
            section: "tls",
            source: Box::new(ConfigError::DuplicateVhostAcmeDomain {
                scope: "vhosts.tls",
                domain: "example.test".to_owned(),
            })
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
fn parses_php_fpm_vhost_config() {
    let root = unique_temp_path("config-php-fpm-root");
    std::fs::create_dir_all(&root).unwrap();
    let spool_dir = unique_temp_path("config-php-fpm-spool");
    std::fs::create_dir_all(&spool_dir).unwrap();
    let config: Config = toml::from_str(&format!(
        r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            preset = "wordpress"
            enabled = true
            runtime = "php-fpm"
            root = "{}"
            resolve_root_symlink = true
            fpm_root = "/app/public"
            index = "index.php"
            allowed_extensions = ["php"]
            deny_path_prefixes = ["/wp-content/uploads/", "/uploads"]
            try_files = "wordpress"
            pass_request_headers = false
            pass_request_body = false
            stderr_log = false
            stderr_log_level = "error"
            stderr_max_bytes = "4KiB"
            stderr_failure_patterns = ["PHP Fatal error:"]
            hide_response_headers = ["x-powered-by", "x-internal"]
            ignore_origin_cache_headers = true
            intercept_error_statuses = [404, 500, 502]
            request_timeout_secs = 30
            max_request_body_bytes = "16MiB"
            request_body_spool_threshold_bytes = "1MiB"
            request_body_spool_dir = "{}"
            max_response_bytes = "8MiB"
            max_response_header_bytes = "32KiB"
            path_info = "split"

            [[vhosts.php.error_pages]]
            status = 502
            path = "/502.html"

            [vhosts.php.error_pages.web]
            root = "{}"
            index_files = ["index.html"]

            [vhosts.php.params]
            APP_ENV = "production"
            PHP_VALUE = "memory_limit=256M"

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            keepalive = true
            pool_max_idle = 4
            idle_timeout_secs = 45
            max_retries = 2
            retry_timeout_secs = 5
            retry_methods = ["GET", "HEAD"]
            retry_invalid_response = true
            retry_statuses = [500, 502, 503]
            "#,
        test_process_config_toml("config-php-fpm-process"),
        root.display(),
        spool_dir.display(),
        root.display()
    ))
    .unwrap();

    config.validate().unwrap();
    let php = &config.vhosts[0].php;
    assert_eq!(php.preset, super::PhpPreset::WordPress);
    assert!(php.enabled);
    assert_eq!(php.runtime, super::PhpRuntime::PhpFpm);
    assert_eq!(php.root.as_deref(), Some(root.as_path()));
    assert!(php.resolve_root_symlink);
    assert_eq!(
        php.fpm_root.as_deref(),
        Some(std::path::Path::new("/app/public"))
    );
    assert_eq!(
        php.deny_path_prefixes,
        ["/wp-content/uploads/".to_owned(), "/uploads".to_owned()]
    );
    assert_eq!(php.try_files, super::PhpTryFilesMode::WordPress);
    assert!(!php.pass_request_headers);
    assert!(!php.pass_request_body);
    assert!(!php.stderr_log);
    assert_eq!(php.stderr_log_level, super::PhpStderrLogLevel::Error);
    assert_eq!(php.stderr_max_bytes.as_u64(), 4 * 1024);
    assert_eq!(php.stderr_failure_patterns, ["PHP Fatal error:".to_owned()]);
    assert_eq!(
        php.hide_response_headers,
        ["x-powered-by".to_owned(), "x-internal".to_owned()]
    );
    assert!(php.ignore_origin_cache_headers);
    assert_eq!(php.intercept_error_statuses, [404, 500, 502]);
    assert_eq!(php.error_pages.len(), 1);
    assert_eq!(php.error_pages[0].status, 502);
    assert_eq!(php.error_pages[0].path, "/502.html");
    assert_eq!(php.allowed_extensions, ["php"]);
    assert_eq!(
        php.max_request_body_bytes.unwrap().as_u64(),
        16 * 1024 * 1024
    );
    assert_eq!(
        php.request_body_spool_threshold_bytes.unwrap().as_u64(),
        1024 * 1024
    );
    assert_eq!(
        php.request_body_spool_dir.as_deref(),
        Some(spool_dir.as_path())
    );
    assert_eq!(php.max_response_bytes.as_u64(), 8 * 1024 * 1024);
    assert_eq!(php.max_response_header_bytes.as_u64(), 32 * 1024);
    assert_eq!(php.path_info, super::PhpPathInfoMode::Split);
    assert_eq!(
        php.params.get("APP_ENV").map(String::as_str),
        Some("production")
    );
    assert_eq!(
        php.params.get("PHP_VALUE").map(String::as_str),
        Some("memory_limit=256M")
    );
    assert_eq!(php.fpm.tcp.as_deref(), Some("127.0.0.1:9000"));
    assert!(php.fpm.tcp_upstreams.is_empty());
    assert!(php.fpm.keepalive);
    assert_eq!(php.fpm.pool_max_idle, 4);
    assert_eq!(php.fpm.idle_timeout_secs, 45);
    assert_eq!(php.fpm.max_retries, 2);
    assert_eq!(php.fpm.retry_timeout_secs, Some(5));
    assert_eq!(php.fpm.retry_methods, ["GET", "HEAD"]);
    assert!(php.fpm.retry_invalid_response);
    assert_eq!(php.fpm.retry_statuses, [500, 502, 503]);

    let mut wordpress_php = php.clone();
    wordpress_php.apply_preset_defaults();
    assert_eq!(wordpress_php.try_files, super::PhpTryFilesMode::WordPress);
    assert!(
        wordpress_php
            .deny_path_prefixes
            .contains(&"/wp-content/uploads/".to_owned())
    );
    assert!(
        wordpress_php
            .deny_path_prefixes
            .contains(&"/files/".to_owned())
    );
}

#[test]
fn parses_php_fpm_tcp_upstreams() {
    let root = unique_temp_path("config-php-fpm-upstreams-root");
    std::fs::create_dir_all(&root).unwrap();
    let config: Config = toml::from_str(&format!(
        r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"

            [vhosts.php.fpm]
            tcp_upstreams = ["127.0.0.1:9000", "127.0.0.1:9001"]
            "#,
        test_process_config_toml("config-php-fpm-upstreams-process"),
        root.display()
    ))
    .unwrap();

    config.validate().unwrap();
    assert_eq!(
        config.vhosts[0].php.fpm.tcp_upstreams,
        ["127.0.0.1:9000".to_owned(), "127.0.0.1:9001".to_owned()]
    );
}

#[cfg(unix)]
#[test]
fn parses_managed_php_fpm_config() {
    let root = secure_test_dir("config-php-fpm-managed-root");
    let socket_dir = secure_test_dir("config-php-fpm-managed-socket");
    let session_dir = secure_test_dir("config-php-fpm-managed-session");
    let upload_dir = secure_test_dir("config-php-fpm-managed-upload");
    let config: Config = toml::from_str(&format!(
        r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"

            [vhosts.php.fpm]
            mode = "managed"
            php_fpm_binary = "/bin/sh"
            socket_dir = "{}"
            workers = 4
            max_requests_per_worker = 250
            process_manager = "dynamic"
            start_servers = 2
            min_spare_servers = 1
            max_spare_servers = 3
            max_spawn_rate = 8
            listen_backlog = 128
            listen_owner = "fluxheim"
            listen_group = "php"
            listen_mode = "0660"
            request_terminate_timeout_secs = 30
            request_terminate_timeout_track_finished = true
            request_slowlog_timeout_secs = 5
            request_slowlog_trace_depth = 16
            decorate_workers_output = false
            session_save_path = "{}"
            upload_tmp_dir = "{}"
            user = "fluxheim"
            group = "fluxheim"
            "#,
        test_process_config_toml("config-php-fpm-managed-process"),
        root.display(),
        socket_dir.display(),
        session_dir.display(),
        upload_dir.display()
    ))
    .unwrap();

    config.validate().unwrap();
    let php = &config.vhosts[0].php;
    assert_eq!(php.fpm.mode, super::PhpFpmMode::Managed);
    assert_eq!(
        php.fpm.php_fpm_binary.as_deref(),
        Some(Path::new("/bin/sh"))
    );
    assert_eq!(php.fpm.socket_dir.as_deref(), Some(socket_dir.as_path()));
    assert_eq!(php.fpm.workers, 4);
    assert_eq!(php.fpm.max_requests_per_worker, 250);
    assert_eq!(
        php.fpm.process_manager,
        super::PhpFpmProcessManager::Dynamic
    );
    assert_eq!(php.fpm.start_servers, Some(2));
    assert_eq!(php.fpm.min_spare_servers, Some(1));
    assert_eq!(php.fpm.max_spare_servers, Some(3));
    assert_eq!(php.fpm.max_spawn_rate, Some(8));
    assert_eq!(php.fpm.listen_backlog, Some(128));
    assert_eq!(php.fpm.listen_owner.as_deref(), Some("fluxheim"));
    assert_eq!(php.fpm.listen_group.as_deref(), Some("php"));
    assert_eq!(php.fpm.listen_mode.as_deref(), Some("0660"));
    assert_eq!(php.fpm.request_terminate_timeout_secs, Some(30));
    assert!(php.fpm.request_terminate_timeout_track_finished);
    assert_eq!(php.fpm.request_slowlog_timeout_secs, Some(5));
    assert_eq!(php.fpm.request_slowlog_trace_depth, 16);
    assert!(!php.fpm.decorate_workers_output);
    assert_eq!(
        php.fpm.session_save_path.as_deref(),
        Some(session_dir.as_path())
    );
    assert_eq!(
        php.fpm.upload_tmp_dir.as_deref(),
        Some(upload_dir.as_path())
    );
    assert_eq!(php.fpm.user.as_deref(), Some("fluxheim"));
    assert_eq!(php.fpm.group.as_deref(), Some("fluxheim"));
    assert!(php.fpm.socket.is_none());
    assert!(php.fpm.tcp.is_none());
    assert!(php.fpm.tcp_upstreams.is_empty());
}

#[cfg(unix)]
#[test]
fn rejects_managed_php_fpm_dynamic_without_spare_bounds() {
    let root = secure_test_dir("config-php-fpm-managed-dynamic-root");
    let socket_dir = secure_test_dir("config-php-fpm-managed-dynamic-socket");
    let config: Config = toml::from_str(&format!(
        r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"

            [vhosts.php.fpm]
            mode = "managed"
            php_fpm_binary = "/bin/sh"
            socket_dir = "{}"
            process_manager = "dynamic"
            "#,
        test_process_config_toml("config-php-fpm-managed-dynamic-process"),
        root.display(),
        socket_dir.display()
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.fpm.min_spare_servers"), "{error}");
}

#[cfg(unix)]
#[test]
fn rejects_managed_php_fpm_dynamic_inverted_spare_bounds() {
    let root = secure_test_dir("config-php-fpm-managed-dynamic-inverted-root");
    let socket_dir = secure_test_dir("config-php-fpm-managed-dynamic-inverted-socket");
    let config: Config = toml::from_str(&format!(
        r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"

            [vhosts.php.fpm]
            mode = "managed"
            php_fpm_binary = "/bin/sh"
            socket_dir = "{}"
            workers = 4
            process_manager = "dynamic"
            min_spare_servers = 3
            max_spare_servers = 2
            "#,
        test_process_config_toml("config-php-fpm-managed-dynamic-inverted-process"),
        root.display(),
        socket_dir.display()
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.fpm.max_spare_servers"), "{error}");
    assert!(error.contains("min_spare_servers"), "{error}");
}

#[cfg(unix)]
#[test]
fn rejects_managed_php_fpm_with_external_endpoint() {
    let root = secure_test_dir("config-php-fpm-managed-endpoint-root");
    let socket_dir = secure_test_dir("config-php-fpm-managed-endpoint-socket");
    let config: Config = toml::from_str(&format!(
        r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"

            [vhosts.php.fpm]
            mode = "managed"
            php_fpm_binary = "/bin/sh"
            socket_dir = "{}"
            tcp = "127.0.0.1:9000"
            "#,
        test_process_config_toml("config-php-fpm-managed-endpoint-process"),
        root.display(),
        socket_dir.display()
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.fpm.mode"), "{error}");
    assert!(error.contains("private socket"), "{error}");
}

#[cfg(unix)]
#[test]
fn rejects_managed_php_fpm_user_without_group() {
    let root = secure_test_dir("config-php-fpm-managed-user-root");
    let socket_dir = secure_test_dir("config-php-fpm-managed-user-socket");
    let config: Config = toml::from_str(&format!(
        r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"

            [vhosts.php.fpm]
            mode = "managed"
            php_fpm_binary = "/bin/sh"
            socket_dir = "{}"
            user = "fluxheim"
            "#,
        test_process_config_toml("config-php-fpm-managed-user-process"),
        root.display(),
        socket_dir.display()
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.fpm.user"), "{error}");
    assert!(error.contains("user and group"), "{error}");
}

#[cfg(unix)]
#[test]
fn rejects_managed_php_fpm_listen_owner_without_group() {
    let root = secure_test_dir("config-php-fpm-managed-listen-owner-root");
    let socket_dir = secure_test_dir("config-php-fpm-managed-listen-owner-socket");
    let config: Config = toml::from_str(&format!(
        r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"

            [vhosts.php.fpm]
            mode = "managed"
            php_fpm_binary = "/bin/sh"
            socket_dir = "{}"
            listen_owner = "fluxheim"
            "#,
        test_process_config_toml("config-php-fpm-managed-listen-owner-process"),
        root.display(),
        socket_dir.display()
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.fpm.listen_owner"), "{error}");
    assert!(error.contains("listen_owner and listen_group"), "{error}");
}

#[cfg(unix)]
#[test]
fn rejects_managed_php_fpm_unsafe_listen_mode() {
    let root = secure_test_dir("config-php-fpm-managed-listen-mode-root");
    let socket_dir = secure_test_dir("config-php-fpm-managed-listen-mode-socket");
    let config: Config = toml::from_str(&format!(
        r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"

            [vhosts.php.fpm]
            mode = "managed"
            php_fpm_binary = "/bin/sh"
            socket_dir = "{}"
            listen_mode = "0666"
            "#,
        test_process_config_toml("config-php-fpm-managed-listen-mode-process"),
        root.display(),
        socket_dir.display()
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.fpm.listen_mode"), "{error}");
    assert!(error.contains("0600"), "{error}");
}

#[test]
fn rejects_external_php_fpm_with_managed_fields() {
    let root = secure_test_dir("config-php-fpm-external-managed-root");
    let config: Config = toml::from_str(&format!(
        r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            user = "fluxheim"
            "#,
        test_process_config_toml("config-php-fpm-external-managed-process"),
        root.display()
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.fpm.mode"), "{error}");
    assert!(error.contains("managed php-fpm fields"), "{error}");
}

#[test]
fn rejects_too_many_php_fpm_tcp_upstreams() {
    let root = unique_temp_path("config-php-fpm-too-many-upstreams-root");
    std::fs::create_dir_all(&root).unwrap();
    let upstreams = (0..=super::MAX_PHP_FPM_TCP_UPSTREAMS)
        .map(|index| format!("\"127.0.0.1:{}\"", 9000 + index))
        .collect::<Vec<_>>()
        .join(", ");
    let config: Config = toml::from_str(&format!(
        r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"

            [vhosts.php.fpm]
            tcp_upstreams = [{}]
            "#,
        test_process_config_toml("config-php-fpm-too-many-upstreams-process"),
        root.display(),
        upstreams,
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.fpm.tcp_upstreams"), "{error}");
    assert!(error.contains("at most 64 upstreams"), "{error}");
}

#[test]
fn rejects_duplicate_php_fpm_tcp_upstreams() {
    let root = unique_temp_path("config-php-fpm-duplicate-upstreams-root");
    std::fs::create_dir_all(&root).unwrap();
    let config: Config = toml::from_str(&format!(
        r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"

            [vhosts.php.fpm]
            tcp_upstreams = ["php-fpm-a:9000", "PHP-FPM-A:9000"]
            "#,
        test_process_config_toml("config-php-fpm-duplicate-upstreams-process"),
        root.display(),
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.fpm.tcp_upstreams"), "{error}");
    assert!(error.contains("duplicate upstreams"), "{error}");
}

#[test]
fn rejects_mixed_php_fpm_endpoint_modes() {
    let root = unique_temp_path("config-php-fpm-mixed-root");
    std::fs::create_dir_all(&root).unwrap();
    let config: Config = toml::from_str(&format!(
        r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            tcp_upstreams = ["127.0.0.1:9001"]
            "#,
        test_process_config_toml("config-php-fpm-mixed-process"),
        root.display()
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("socket, tcp, or tcp_upstreams"), "{error}");
}

#[test]
fn rejects_incomplete_php_request_body_spool_config() {
    let root = unique_temp_path("config-php-incomplete-spool-root");
    let spool_dir = unique_temp_path("config-php-incomplete-spool-dir");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::create_dir_all(&spool_dir).unwrap();
    let config: Config = toml::from_str(&format!(
        r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"
            request_body_spool_threshold_bytes = "1MiB"

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            "#,
        test_process_config_toml("config-php-spool-threshold-without-dir-process"),
        root.display(),
    ))
    .unwrap();
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.request_body_spool_dir"), "{error}");

    let config: Config = toml::from_str(&format!(
        r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"
            request_body_spool_dir = "{}"

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            "#,
        test_process_config_toml("config-php-spool-dir-without-threshold-process"),
        root.display(),
        spool_dir.display(),
    ))
    .unwrap();
    let error = config.validate().unwrap_err().to_string();
    assert!(
        error.contains("php.request_body_spool_threshold_bytes"),
        "{error}"
    );
}

#[test]
fn rejects_php_request_body_spool_threshold_at_or_above_body_limit() {
    let root = unique_temp_path("config-php-spool-threshold-over-limit-root");
    let spool_dir = unique_temp_path("config-php-spool-threshold-over-limit-dir");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::create_dir_all(&spool_dir).unwrap();
    let config: Config = toml::from_str(&format!(
        r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"
            max_request_body_bytes = "8MiB"
            request_body_spool_threshold_bytes = "8MiB"
            request_body_spool_dir = "{}"

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            "#,
        test_process_config_toml("config-php-spool-threshold-over-limit-process"),
        root.display(),
        spool_dir.display(),
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(
        error.contains("php.request_body_spool_threshold_bytes"),
        "{error}"
    );
    assert!(
        error.contains("less than php.max_request_body_bytes"),
        "{error}"
    );
}

#[test]
fn rejects_php_request_body_spool_path_that_is_not_directory() {
    let root = unique_temp_path("config-php-spool-file-root");
    let spool_path = unique_temp_path("config-php-spool-file");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(&spool_path, b"not a directory").unwrap();
    let config: Config = toml::from_str(&format!(
        r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"
            request_body_spool_threshold_bytes = "1MiB"
            request_body_spool_dir = "{}"

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            "#,
        test_process_config_toml("config-php-spool-file-process"),
        root.display(),
        spool_path.display(),
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.request_body_spool_dir"), "{error}");
    assert!(error.contains("must be a directory"), "{error}");
}

#[cfg(unix)]
#[test]
fn rejects_php_request_body_spool_dir_with_insecure_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let root = unique_temp_path("config-php-spool-insecure-root");
    let spool_dir = unique_temp_path("config-php-spool-insecure-dir");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::create_dir_all(&spool_dir).unwrap();
    std::fs::set_permissions(&spool_dir, std::fs::Permissions::from_mode(0o777)).unwrap();
    let config: Config = toml::from_str(&format!(
        r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"
            request_body_spool_threshold_bytes = "1MiB"
            request_body_spool_dir = "{}"

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            "#,
        test_process_config_toml("config-php-spool-insecure-process"),
        root.display(),
        spool_dir.display(),
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.request_body_spool_dir"), "{error}");
}

#[test]
fn rejects_zero_php_response_limit() {
    let root = unique_temp_path("config-php-zero-response-root");
    std::fs::create_dir_all(&root).unwrap();
    let config: Config = toml::from_str(&format!(
        r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"
            max_response_bytes = 0

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            "#,
        test_process_config_toml("config-php-zero-response-process"),
        root.display()
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.max_response_bytes"), "{error}");
}

#[test]
fn rejects_excessive_php_response_limit() {
    let root = unique_temp_path("config-php-excessive-response-root");
    std::fs::create_dir_all(&root).unwrap();
    let config: Config = toml::from_str(&format!(
        r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"
            max_response_bytes = "65MiB"

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            "#,
        test_process_config_toml("config-php-excessive-response-process"),
        root.display()
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.max_response_bytes"), "{error}");
    assert!(error.contains("less than or equal to 64MiB"), "{error}");
}

#[test]
fn rejects_zero_php_response_header_limit() {
    let root = unique_temp_path("config-php-zero-response-header-root");
    std::fs::create_dir_all(&root).unwrap();
    let config: Config = toml::from_str(&format!(
        r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"
            max_response_header_bytes = 0

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            "#,
        test_process_config_toml("config-php-zero-response-header-process"),
        root.display()
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.max_response_header_bytes"), "{error}");
}

#[test]
fn rejects_excessive_php_response_header_limit() {
    let root = unique_temp_path("config-php-excessive-response-header-root");
    std::fs::create_dir_all(&root).unwrap();
    let config: Config = toml::from_str(&format!(
        r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"
            max_response_header_bytes = "2MiB"

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            "#,
        test_process_config_toml("config-php-excessive-response-header-process"),
        root.display()
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.max_response_header_bytes"), "{error}");
}

#[test]
fn rejects_zero_php_stderr_limit() {
    let root = unique_temp_path("config-php-zero-stderr-root");
    std::fs::create_dir_all(&root).unwrap();
    let config: Config = toml::from_str(&format!(
        r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"
            stderr_max_bytes = 0

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            "#,
        test_process_config_toml("config-php-zero-stderr-process"),
        root.display()
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.stderr_max_bytes"), "{error}");
}

#[test]
fn rejects_invalid_php_stderr_failure_pattern() {
    let root = unique_temp_path("config-php-bad-stderr-pattern-root");
    std::fs::create_dir_all(&root).unwrap();
    let config: Config = toml::from_str(&format!(
        r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"
            stderr_failure_patterns = ["PHP\nFatal"]

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            "#,
        test_process_config_toml("config-php-bad-stderr-pattern-process"),
        root.display()
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.stderr_failure_patterns"), "{error}");
}

#[test]
fn rejects_too_many_php_stderr_failure_patterns() {
    let root = unique_temp_path("config-php-many-stderr-patterns-root");
    std::fs::create_dir_all(&root).unwrap();
    let patterns = (0..=super::MAX_PHP_STDERR_FAILURE_PATTERNS)
        .map(|index| format!("\"fatal-{index}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let config: Config = toml::from_str(&format!(
        r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"
            stderr_failure_patterns = [{}]

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            "#,
        test_process_config_toml("config-php-many-stderr-patterns-process"),
        root.display(),
        patterns,
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.stderr_failure_patterns"), "{error}");
    assert!(error.contains("at most 32 patterns"), "{error}");
}

#[test]
fn rejects_invalid_php_hidden_response_header() {
    let root = unique_temp_path("config-php-bad-hidden-header-root");
    std::fs::create_dir_all(&root).unwrap();
    let config: Config = toml::from_str(&format!(
        r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"
            hide_response_headers = ["bad header"]

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            "#,
        test_process_config_toml("config-php-bad-hidden-header-process"),
        root.display()
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.hide_response_headers"), "{error}");
}

#[test]
fn rejects_duplicate_php_hidden_response_header() {
    let root = unique_temp_path("config-php-duplicate-hidden-header-root");
    std::fs::create_dir_all(&root).unwrap();
    let config: Config = toml::from_str(&format!(
        r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"
            hide_response_headers = ["x-powered-by", "X-Powered-By"]

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            "#,
        test_process_config_toml("config-php-duplicate-hidden-header-process"),
        root.display()
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.hide_response_headers"), "{error}");
    assert!(error.contains("duplicate headers"), "{error}");
}

#[test]
fn rejects_too_many_php_hidden_response_headers() {
    let root = unique_temp_path("config-php-many-hidden-headers-root");
    std::fs::create_dir_all(&root).unwrap();
    let headers = (0..=super::MAX_PHP_HIDE_RESPONSE_HEADERS)
        .map(|index| format!("\"x-hidden-{index}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let config: Config = toml::from_str(&format!(
        r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"
            hide_response_headers = [{}]

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            "#,
        test_process_config_toml("config-php-many-hidden-headers-process"),
        root.display(),
        headers,
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.hide_response_headers"), "{error}");
    assert!(error.contains("at most 64 headers"), "{error}");
}

#[test]
fn rejects_invalid_php_intercept_error_status() {
    let root = unique_temp_path("config-php-bad-intercept-status-root");
    std::fs::create_dir_all(&root).unwrap();
    let config: Config = toml::from_str(&format!(
        r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"
            intercept_error_statuses = [302]

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            "#,
        test_process_config_toml("config-php-bad-intercept-status-process"),
        root.display()
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.intercept_error_statuses"), "{error}");
}

#[test]
fn rejects_duplicate_php_intercept_error_status() {
    let root = unique_temp_path("config-php-duplicate-intercept-status-root");
    std::fs::create_dir_all(&root).unwrap();
    let config: Config = toml::from_str(&format!(
        r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"
            intercept_error_statuses = [500, 500]

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            "#,
        test_process_config_toml("config-php-duplicate-intercept-status-process"),
        root.display()
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.intercept_error_statuses"), "{error}");
}

#[test]
fn rejects_too_many_php_intercept_error_statuses() {
    let root = unique_temp_path("config-php-many-intercept-statuses-root");
    std::fs::create_dir_all(&root).unwrap();
    let statuses = (0..=super::MAX_PHP_INTERCEPT_ERROR_STATUSES)
        .map(|index| (400 + index).to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let config: Config = toml::from_str(&format!(
        r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"
            intercept_error_statuses = [{}]

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            "#,
        test_process_config_toml("config-php-many-intercept-statuses-process"),
        root.display(),
        statuses,
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.intercept_error_statuses"), "{error}");
    assert!(error.contains("at most 200 statuses"), "{error}");
}

#[test]
fn rejects_duplicate_php_error_page_status() {
    let root = unique_temp_path("config-php-duplicate-error-page-root");
    std::fs::create_dir_all(&root).unwrap();
    let config: Config = toml::from_str(&format!(
        r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"

            [[vhosts.php.error_pages]]
            status = 502
            path = "/502.html"

            [vhosts.php.error_pages.web]
            root = "{}"

            [[vhosts.php.error_pages]]
            status = 502
            path = "/fallback.html"

            [vhosts.php.error_pages.web]
            root = "{}"

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            "#,
        test_process_config_toml("config-php-duplicate-error-page-process"),
        root.display(),
        root.display(),
        root.display()
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.error_pages.status"), "{error}");
}

#[test]
fn rejects_too_many_php_error_pages() {
    let root = unique_temp_path("config-php-many-error-pages-root");
    std::fs::create_dir_all(&root).unwrap();
    let error_pages = (0..=super::MAX_PHP_ERROR_PAGES)
        .map(|index| {
            format!(
                r#"
            [[vhosts.php.error_pages]]
            status = {}
            path = "/{}.html"

            [vhosts.php.error_pages.web]
            root = "{}"
                    "#,
                400 + index,
                400 + index,
                root.display()
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let config: Config = toml::from_str(&format!(
        r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"

            {}

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            "#,
        test_process_config_toml("config-php-many-error-pages-process"),
        root.display(),
        error_pages,
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.error_pages"), "{error}");
    assert!(error.contains("at most 64 error pages"), "{error}");
}

#[test]
fn rejects_php_fpm_with_socket_and_tcp() {
    let root = unique_temp_path("config-php-fpm-conflict-root");
    std::fs::create_dir_all(&root).unwrap();
    let config: Config = toml::from_str(&format!(
        r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"

            [vhosts.php.fpm]
            socket = "/run/php/php-fpm.sock"
            tcp = "127.0.0.1:9000"
            "#,
        test_process_config_toml("config-php-fpm-conflict-process"),
        root.display()
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(
        error.contains("configure only one of socket, tcp, or tcp_upstreams"),
        "{error}"
    );
}

#[test]
fn rejects_invalid_php_fpm_retry_policy() {
    let root = unique_temp_path("config-php-fpm-invalid-retries-root");
    std::fs::create_dir_all(&root).unwrap();
    let config: Config = toml::from_str(&format!(
        r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            max_retries = 11
            "#,
        test_process_config_toml("config-php-fpm-invalid-retries-process"),
        root.display()
    ))
    .unwrap();
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.fpm.max_retries"), "{error}");

    let config: Config = toml::from_str(&format!(
        r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            retry_methods = ["GET", "get"]
            "#,
        test_process_config_toml("config-php-fpm-invalid-retry-methods-process"),
        root.display()
    ))
    .unwrap();
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.fpm.retry_methods"), "{error}");

    let config: Config = toml::from_str(&format!(
        r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"
            server_port = 0

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            "#,
        test_process_config_toml("config-php-invalid-server-port-process"),
        root.display()
    ))
    .unwrap();
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.server_port"), "{error}");

    let config: Config = toml::from_str(&format!(
        r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"

            [vhosts.php.params]
            HTTP_AUTHORIZATION = "Bearer fixed"

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            "#,
        test_process_config_toml("config-php-http-param-process"),
        root.display()
    ))
    .unwrap();
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("HTTP_* request header"), "{error}");

    let config: Config = toml::from_str(&format!(
        r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            retry_methods = ["GET", "POST"]
            "#,
        test_process_config_toml("config-php-fpm-unsafe-retry-method-process"),
        root.display()
    ))
    .unwrap();
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("safe HTTP methods"), "{error}");

    let retry_methods = (0..=super::MAX_PHP_FPM_RETRY_METHODS)
        .map(|index| format!("\"M{index}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let config: Config = toml::from_str(&format!(
        r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            retry_methods = [{}]
            "#,
        test_process_config_toml("config-php-fpm-too-many-retry-methods-process"),
        root.display(),
        retry_methods,
    ))
    .unwrap();
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.fpm.retry_methods"), "{error}");
    assert!(error.contains("at most 16 methods"), "{error}");

    let config: Config = toml::from_str(&format!(
        r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            retry_timeout_secs = 0
            "#,
        test_process_config_toml("config-php-fpm-invalid-retry-timeout-process"),
        root.display()
    ))
    .unwrap();
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.fpm.retry_timeout_secs"), "{error}");

    let config: Config = toml::from_str(&format!(
        r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            retry_statuses = [404]
            "#,
        test_process_config_toml("config-php-fpm-invalid-retry-status-process"),
        root.display()
    ))
    .unwrap();
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.fpm.retry_statuses"), "{error}");

    let retry_statuses = (0..=super::MAX_PHP_FPM_RETRY_STATUSES)
        .map(|index| (500 + index).to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let config: Config = toml::from_str(&format!(
        r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            retry_statuses = [{}]
            "#,
        test_process_config_toml("config-php-fpm-too-many-retry-statuses-process"),
        root.display(),
        retry_statuses,
    ))
    .unwrap();
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.fpm.retry_statuses"), "{error}");
    assert!(error.contains("at most 100 statuses"), "{error}");

    let config: Config = toml::from_str(&format!(
        r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            retry_statuses = [500, 500]
            "#,
        test_process_config_toml("config-php-fpm-duplicate-retry-status-process"),
        root.display()
    ))
    .unwrap();
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.fpm.retry_statuses"), "{error}");
}

#[test]
fn rejects_php_fpm_keepalive_without_idle_capacity() {
    let root = unique_temp_path("config-php-fpm-keepalive-zero-pool");
    std::fs::create_dir_all(&root).unwrap();
    let config: Config = toml::from_str(&format!(
        r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            keepalive = true
            pool_max_idle = 0
            "#,
        test_process_config_toml("config-php-fpm-keepalive-process"),
        root.display()
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.fpm.pool_max_idle"), "{error}");
}

#[test]
fn rejects_php_param_that_overrides_script_filename() {
    let root = unique_temp_path("config-php-param-protected");
    std::fs::create_dir_all(&root).unwrap();
    let config: Config = toml::from_str(&format!(
        r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"

            [vhosts.php.params]
            SCRIPT_FILENAME = "/tmp/other.php"

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            "#,
        test_process_config_toml("config-php-param-protected-process"),
        root.display()
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.params"), "{error}");
    assert!(error.contains("managed by Fluxheim"), "{error}");
}

#[test]
fn rejects_php_param_control_character_value() {
    let root = unique_temp_path("config-php-param-control");
    std::fs::create_dir_all(&root).unwrap();
    let config: Config = toml::from_str(&format!(
        r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"

            [vhosts.php.params]
            APP_ENV = "production\u000a"

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            "#,
        test_process_config_toml("config-php-param-control-process"),
        root.display()
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("control characters"), "{error}");
}

#[test]
fn rejects_too_many_php_params() {
    let root = unique_temp_path("config-php-many-params");
    std::fs::create_dir_all(&root).unwrap();
    let params = (0..=super::MAX_PHP_PARAMS)
        .map(|index| format!("PARAM_{index} = \"value\""))
        .collect::<Vec<_>>()
        .join("\n");
    let config: Config = toml::from_str(&format!(
        r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"

            [vhosts.php.params]
            {}

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            "#,
        test_process_config_toml("config-php-many-params-process"),
        root.display(),
        params,
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.params"), "{error}");
    assert!(error.contains("at most 128 parameters"), "{error}");
}

#[test]
fn rejects_php_extension_with_leading_dot() {
    let root = unique_temp_path("config-php-extension-dot-root");
    std::fs::create_dir_all(&root).unwrap();
    let config: Config = toml::from_str(&format!(
        r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"
            allowed_extensions = [".php"]

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            "#,
        test_process_config_toml("config-php-extension-dot-process"),
        root.display()
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(
        error.contains("extensions must be plain extension names"),
        "{error}"
    );
}

#[test]
fn rejects_duplicate_php_allowed_extension() {
    let root = unique_temp_path("config-php-duplicate-extension-root");
    std::fs::create_dir_all(&root).unwrap();
    let config: Config = toml::from_str(&format!(
        r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"
            allowed_extensions = ["php", "PHP"]

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            "#,
        test_process_config_toml("config-php-duplicate-extension-process"),
        root.display()
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.allowed_extensions"), "{error}");
    assert!(error.contains("duplicate extensions"), "{error}");
}

#[test]
fn rejects_too_many_php_allowed_extensions() {
    let root = unique_temp_path("config-php-many-extensions-root");
    std::fs::create_dir_all(&root).unwrap();
    let extensions = (0..=super::MAX_PHP_ALLOWED_EXTENSIONS)
        .map(|index| format!("\"php{index}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let config: Config = toml::from_str(&format!(
        r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"
            allowed_extensions = [{}]

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            "#,
        test_process_config_toml("config-php-many-extensions-process"),
        root.display(),
        extensions,
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.allowed_extensions"), "{error}");
    assert!(error.contains("at most 16 extensions"), "{error}");
}

#[test]
fn rejects_invalid_php_deny_path_prefix() {
    let root = unique_temp_path("config-php-bad-deny-prefix-root");
    std::fs::create_dir_all(&root).unwrap();
    let config: Config = toml::from_str(&format!(
        r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"
            deny_path_prefixes = ["uploads/../secret"]

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            "#,
        test_process_config_toml("config-php-bad-deny-prefix-process"),
        root.display()
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.deny_path_prefixes"), "{error}");
}

#[test]
fn rejects_duplicate_php_deny_path_prefix() {
    let root = unique_temp_path("config-php-duplicate-deny-prefix-root");
    std::fs::create_dir_all(&root).unwrap();
    let config: Config = toml::from_str(&format!(
        r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"
            deny_path_prefixes = ["/uploads", "/uploads"]

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            "#,
        test_process_config_toml("config-php-duplicate-deny-prefix-process"),
        root.display()
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.deny_path_prefixes"), "{error}");
}

#[test]
fn rejects_too_many_php_deny_path_prefixes() {
    let root = unique_temp_path("config-php-many-deny-prefixes-root");
    std::fs::create_dir_all(&root).unwrap();
    let prefixes = (0..=super::MAX_PHP_DENY_PATH_PREFIXES)
        .map(|index| format!("\"/upload-{index}/\""))
        .collect::<Vec<_>>()
        .join(", ");
    let config: Config = toml::from_str(&format!(
        r#"
            {}

            [[vhosts]]
            name = "php"
            hosts = ["php.example.test"]

            [vhosts.php]
            enabled = true
            root = "{}"
            deny_path_prefixes = [{}]

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            "#,
        test_process_config_toml("config-php-many-deny-prefixes-process"),
        root.display(),
        prefixes,
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("php.deny_path_prefixes"), "{error}");
    assert!(error.contains("at most 128 prefixes"), "{error}");
}

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

#[test]
fn rejects_invalid_cache_status_header_name() {
    let config: Config = toml::from_str(
        r#"
            [cache]
            status_header = "bad header"
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidHeaderName {
            field: "cache",
            name: "bad header".to_owned()
        })
    );
}

#[test]
fn rejects_invalid_cache_status_reason_header_name() {
    let config: Config = toml::from_str(
        r#"
            [cache]
            status_reason_header = "bad header"
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidHeaderName {
            field: "cache",
            name: "bad header".to_owned()
        })
    );
}

#[test]
fn rejects_invalid_cache_hidden_response_header_name() {
    let config: Config = toml::from_str(
        r#"
            [cache]
            hide_response_headers = ["bad header"]
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidHeaderName {
            field: "cache",
            name: "bad header".to_owned()
        })
    );
}

#[test]
fn rejects_invalid_cache_bypass_request_header_name() {
    let config: Config = toml::from_str(
        r#"
            [cache]
            bypass_request_headers = ["bad header"]
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidHeaderName {
            field: "cache",
            name: "bad header".to_owned()
        })
    );
}

#[test]
fn rejects_invalid_cache_bypass_request_header_value() {
    for value in ["", " ", "bad\nvalue"] {
        let config: Config = toml::from_str(&format!(
            r#"
                [cache]
                bypass_request_header_values = {{ x-preview-mode = {value:?} }}
                "#,
        ))
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidCacheBypassRequestHeaderValue {
                scope: "cache",
                header: "x-preview-mode".to_owned(),
                value: value.to_owned()
            })
        );
    }
}

#[test]
fn rejects_invalid_cache_no_store_response_header_name() {
    let config: Config = toml::from_str(
        r#"
            [cache]
            no_store_response_headers = ["bad header"]
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidHeaderName {
            field: "cache",
            name: "bad header".to_owned()
        })
    );
}

#[test]
fn rejects_invalid_cache_no_store_response_header_value() {
    for value in ["", " ", "bad\nvalue"] {
        let config: Config = toml::from_str(&format!(
            r#"
                [cache]
                no_store_response_header_values = {{ x-app-cache = {value:?} }}
                "#,
        ))
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidCacheNoStoreResponseHeaderValue {
                scope: "cache",
                header: "x-app-cache".to_owned(),
                value: value.to_owned()
            })
        );
    }
}

#[test]
fn rejects_invalid_cache_bypass_query_param() {
    for param in ["", "bad param", "token=value", "a&b", "a?b"] {
        let config: Config = toml::from_str(&format!(
            r#"
                [cache]
                bypass_query_params = [{param:?}]
                "#,
        ))
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidCacheBypassQueryParam {
                scope: "cache",
                param: param.to_owned()
            })
        );
    }
}

#[test]
fn rejects_invalid_cache_bypass_query_value() {
    for value in ["", " ", "bad value", "bad&value", "bad\nvalue"] {
        let config: Config = toml::from_str(&format!(
            r#"
                [cache]
                bypass_query_values = {{ mode = {value:?} }}
                "#,
        ))
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidCacheBypassQueryValue {
                scope: "cache",
                param: "mode".to_owned(),
                value: value.to_owned()
            })
        );
    }
}

#[test]
fn rejects_invalid_cache_bypass_cookie_name() {
    for name in ["", "bad name", "session=value", "a;b", "a,b"] {
        let config: Config = toml::from_str(&format!(
            r#"
                [cache]
                bypass_cookie_names = [{name:?}]
                "#,
        ))
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidCacheBypassCookieName {
                scope: "cache",
                name: name.to_owned()
            })
        );
    }
}

#[test]
fn rejects_invalid_cache_bypass_cookie_value() {
    for value in ["bad;value", "bad,value", "bad\nvalue"] {
        let config: Config = toml::from_str(&format!(
            r#"
                [cache]
                bypass_cookie_values = {{ preview = {value:?} }}
                "#,
        ))
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidCacheBypassCookieValue {
                scope: "cache",
                name: "preview".to_owned(),
                value: value.to_owned()
            })
        );
    }
}

#[test]
fn rejects_invalid_cache_vary_request_header_name() {
    let config: Config = toml::from_str(
        r#"
            [cache]
            vary_request_headers = ["bad header"]
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidHeaderName {
            field: "cache",
            name: "bad header".to_owned()
        })
    );
}

#[test]
fn rejects_sensitive_cache_vary_request_header() {
    for header in ["cookie", "authorization", "proxy-authorization"] {
        let config: Config = toml::from_str(&format!(
            r#"
                [cache]
                vary_request_headers = [{header:?}]
                "#
        ))
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidCacheVaryRequestHeader {
                scope: "cache",
                header: header.to_owned(),
            }),
            "{header}"
        );
    }
}

#[test]
fn rejects_too_many_cache_bypass_paths() {
    let prefixes = (0..=super::MAX_CACHE_BYPASS_PATHS)
        .map(|index| format!("\"/private-{index}/\""))
        .collect::<Vec<_>>()
        .join(", ");
    let config: Config = toml::from_str(&format!(
        r#"
            [cache]
            bypass_path_prefixes = [{prefixes}]
            "#,
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("cache.bypass_path_prefixes"), "{error}");
    assert!(error.contains("at most 128 entries"), "{error}");
}

#[test]
fn rejects_too_many_cache_bypass_cookies() {
    let cookies = (0..=super::MAX_CACHE_BYPASS_COOKIES)
        .map(|index| format!("\"cookie_{index}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let config: Config = toml::from_str(&format!(
        r#"
            [cache]
            bypass_cookie_name_prefixes = [{cookies}]
            "#,
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(
        error.contains("cache.bypass_cookie_name_prefixes"),
        "{error}"
    );
    assert!(error.contains("at most 128 entries"), "{error}");
}

#[test]
fn rejects_too_many_cache_vary_headers() {
    let headers = (0..=super::MAX_CACHE_VARY_REQUEST_HEADERS)
        .map(|index| format!("\"x-vary-{index}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let config: Config = toml::from_str(&format!(
        r#"
            [cache]
            vary_request_headers = [{headers}]
            "#,
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("cache.vary_request_headers"), "{error}");
    assert!(error.contains("at most 32 entries"), "{error}");
}

#[test]
fn rejects_too_many_cache_status_ttls() {
    let status_ttls = (0..=super::MAX_CACHE_STATUS_TTLS)
        .map(|index| format!("\"{}\" = 60", 100 + index))
        .collect::<Vec<_>>()
        .join(", ");
    let config: Config = toml::from_str(&format!(
        r#"
            [cache]
            status_ttls = {{ {status_ttls} }}
            "#,
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("cache.status_ttls"), "{error}");
    assert!(error.contains("at most 128 entries"), "{error}");
}

#[test]
fn rejects_too_many_cache_content_types_extensions_and_methods() {
    let content_types = (0..=super::MAX_CACHE_CONTENT_TYPES)
        .map(|index| format!("\"application/x-{index}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let config: Config = toml::from_str(&format!(
        r#"
            [cache]
            content_types = [{content_types}]
            "#,
    ))
    .unwrap();
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("cache.content_types"), "{error}");
    assert!(error.contains("at most 64 entries"), "{error}");

    let extensions = (0..=super::MAX_CACHE_IMAGE_EXTENSIONS)
        .map(|index| format!("\"ext{index}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let config: Config = toml::from_str(&format!(
        r#"
            [cache]
            image_extensions = [{extensions}]
            "#,
    ))
    .unwrap();
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("cache.image_extensions"), "{error}");
    assert!(error.contains("at most 128 entries"), "{error}");

    let methods = (0..=super::MAX_CACHE_METHODS)
        .map(|index| format!("\"M{index}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let config: Config = toml::from_str(&format!(
        r#"
            [cache]
            methods = [{methods}]
            "#,
    ))
    .unwrap();
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("cache.methods"), "{error}");
    assert!(error.contains("at most 16 entries"), "{error}");
}

#[test]
fn rejects_invalid_cache_key_namespace() {
    for namespace in ["", "bad namespace", "bad/namespace", "bad;namespace"]
        .into_iter()
        .map(str::to_owned)
        .chain(std::iter::once("x".repeat(129)))
    {
        let config: Config = toml::from_str(&format!(
            r#"
                [cache]
                key_namespace = {namespace:?}
                "#
        ))
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidCacheKeyNamespace {
                scope: "cache",
                namespace: namespace.to_owned(),
            }),
            "{namespace:?}"
        );
    }
}

#[test]
fn rejects_empty_cache_key_parts() {
    let config: Config = toml::from_str(
        r#"
            [cache]
            key_parts = []
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::EmptyCacheKeyParts { scope: "cache" })
    );
}

#[test]
fn rejects_too_many_cache_key_parts() {
    let config: Config = toml::from_str(
        r#"
            [cache]
            key_parts = ["method", "host", "path", "query", "path"]
            "#,
    )
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("cache.key_parts"), "{error}");
    assert!(error.contains("at most 4 entries"), "{error}");
}

#[test]
fn route_cache_wraps_too_many_key_parts() {
    let config: Config = toml::from_str(
        r#"
            [[vhosts]]
            name = "gateway"
            hosts = ["gateway.example.test"]

            [[vhosts.routes]]
            name = "assets"
            path_prefix = "/assets/"

            [vhosts.routes.proxy]
            upstream = "127.0.0.1:3000"

            [vhosts.routes.cache]
            key_parts = ["method", "host", "path", "query", "path"]
            "#,
    )
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(
        error.contains("vhost \"gateway\" route \"assets\" cache:"),
        "{error}"
    );
    assert!(error.contains("vhosts.routes.cache.key_parts"), "{error}");
    assert!(error.contains("at most 4 entries"), "{error}");
}

#[test]
fn rejects_duplicate_cache_key_parts() {
    let config: Config = toml::from_str(
        r#"
            [cache]
            key_parts = ["method", "path", "path"]
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::DuplicateCacheKeyPart {
            scope: "cache",
            part: CacheKeyPart::Path,
        })
    );
}

#[test]
fn rejects_cache_key_parts_without_path() {
    let config: Config = toml::from_str(
        r#"
            [cache]
            key_parts = ["method", "host"]
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::MissingCacheKeyPath { scope: "cache" })
    );
}

#[test]
fn rejects_invalid_cache_status_ttl() {
    let config: Config = toml::from_str(
        r#"
            [cache]
            status_ttls = { "99" = 60 }
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidCacheStatusTtl {
            scope: "cache",
            status: 99,
            ttl_secs: 60,
        })
    );

    let config: Config = toml::from_str(
        r#"
            [cache]
            status_ttls = { "200" = 0 }
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidCacheStatusTtl {
            scope: "cache",
            status: 200,
            ttl_secs: 0,
        })
    );
}

#[test]
fn rejects_invalid_cache_min_uses() {
    let config: Config = toml::from_str(
        r#"
            [cache]
            min_uses = 0
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidCacheMinUses { scope: "cache" })
    );
}

#[test]
fn rejects_zero_cache_range_max_bytes() {
    let config: Config = toml::from_str(
        r#"
            [cache.range]
            max_bytes = 0
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidCacheRangePolicy {
            scope: "cache",
            field: "range.max_bytes",
            reason: "max bytes must be greater than zero",
        })
    );
}

#[test]
fn rejects_cache_range_larger_than_cache_object_limit() {
    let config: Config = toml::from_str(
        r#"
            [cache]
            max_object_bytes = "1MiB"

            [cache.range]
            enabled = true
            max_bytes = "2MiB"
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidCacheRangePolicy {
            scope: "cache",
            field: "range.max_bytes",
            reason: "max bytes must not exceed max_object_bytes",
        })
    );
}

#[test]
fn rejects_invalid_cache_default_status_ttl() {
    let config: Config = toml::from_str(
        r#"
            [cache]
            default_status_ttl_secs = 0
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidCacheDefaultStatusTtl { scope: "cache" })
    );
}

#[test]
fn rejects_invalid_cache_stale_if_error_ttl() {
    let config: Config = toml::from_str(
        r#"
            [cache]
            stale_if_error_secs = 0
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidCacheStaleIfErrorTtl { scope: "cache" })
    );
}

#[test]
fn rejects_empty_cache_stale_if_error_on_when_error_stale_is_enabled() {
    let config: Config = toml::from_str(
        r#"
            [cache]
            stale_if_error_secs = 30
            stale_if_error_on = []
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::EmptyCacheStaleIfErrorOn { scope: "cache" })
    );
}

#[test]
fn rejects_invalid_cache_stale_if_error_statuses() {
    let config: Config = toml::from_str(
        r#"
            [cache]
            stale_if_error_statuses = [404]
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidCacheStaleIfErrorStatus {
            scope: "cache",
            status: 404,
        })
    );
}

#[test]
fn rejects_invalid_cache_stale_while_revalidate_ttl() {
    let config: Config = toml::from_str(
        r#"
            [cache]
            stale_while_revalidate_secs = 0
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidCacheStaleWhileRevalidateTtl { scope: "cache" })
    );
}

#[test]
fn rejects_duplicate_cache_tag_headers() {
    let config: Config = toml::from_str(
        r#"
            [cache]
            tag_headers = ["Surrogate-Key", "surrogate-key"]
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::DuplicateCacheTagHeader {
            scope: "cache",
            header: "surrogate-key".to_owned(),
        })
    );
}

#[test]
fn rejects_invalid_cache_content_type() {
    let config: Config = toml::from_str(
        r#"
            [cache]
            content_types = []
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::EmptyCacheContentTypes { scope: "cache" })
    );

    for content_type in ["image", "*/json", "image/p*ng", "text/html; charset=utf-8"] {
        let config: Config = toml::from_str(&format!(
            r#"
                [cache]
                content_types = [{content_type:?}]
                "#
        ))
        .unwrap();

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidCacheContentType {
                scope: "cache",
                content_type: content_type.to_owned(),
            }),
            "{content_type}"
        );
    }
}

#[test]
fn rejects_invalid_cache_lock_timeout() {
    let config: Config = toml::from_str(
        r#"
            [cache.lock]
            age_timeout_secs = 0
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidCacheLockTimeout {
            field: "cache.lock.age_timeout_secs".to_owned()
        })
    );

    let config: Config = toml::from_str(
        r#"
            [cache.lock]
            wait_timeout_secs = 0
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidCacheLockTimeout {
            field: "cache.lock.wait_timeout_secs".to_owned()
        })
    );
}

#[test]
fn rejects_invalid_cache_predictor_capacity() {
    let config: Config = toml::from_str(
        r#"
            [cache.predictor]
            enabled = true
            capacity = 0
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidCachePredictorCapacity { scope: "cache" })
    );
}

#[test]
#[cfg(feature = "cache")]
fn parses_cache_peer_fill_config() {
    let config: Config = toml::from_str(
        r#"
            [cache]
            enabled = true

            [cache.disk]
            enabled = true
            path = "/var/cache/fluxheim/example"

            [cache.peer_fill]
            enabled = true
            connect_timeout_secs = 3
            read_timeout_secs = 12
            max_object_bytes = "64MiB"
            max_concurrent_requests = 32
            fail_open = false

            [[cache.peer_fill.peers]]
            name = "node-a"
            base_url = "https://node-a.example.internal:8443"

            [[cache.peer_fill.peers]]
            name = "local"
            base_url = "http://127.0.0.1:8080"
            "#,
    )
    .unwrap();

    assert_eq!(
        config.cache.peer_fill,
        CachePeerFillConfig {
            enabled: true,
            peers: vec![
                CachePeerConfig {
                    name: "node-a".to_owned(),
                    base_url: "https://node-a.example.internal:8443".to_owned(),
                },
                CachePeerConfig {
                    name: "local".to_owned(),
                    base_url: "http://127.0.0.1:8080".to_owned(),
                },
            ],
            connect_timeout_secs: 3,
            read_timeout_secs: 12,
            max_object_bytes: Some(ByteSize(64 * 1024 * 1024)),
            max_concurrent_requests: 32,
            allow_insecure_http: false,
            fail_open: false,
        }
    );
}

#[test]
#[cfg(feature = "cache")]
fn rejects_cache_peer_fill_without_enabled_cache_policy() {
    let config: Config = toml::from_str(
        r#"
            [cache.peer_fill]
            enabled = true

            [[cache.peer_fill.peers]]
            name = "node-a"
            base_url = "https://node-a.example.internal:8443"
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidCachePeerFillPolicy {
            scope: "cache",
            field: "peer_fill.enabled",
            reason: "peer fill requires the cache policy to be enabled",
        })
    );
}

#[test]
#[cfg(feature = "cache")]
fn rejects_unsafe_cache_peer_fill_peers() {
    let config: Config = toml::from_str(
        r#"
            [cache]
            enabled = true

            [cache.memory]
            enabled = true

            [cache.peer_fill]
            enabled = true

            [[cache.peer_fill.peers]]
            name = "node-a"
            base_url = "http://node-a.example.internal:8080"
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidCachePeerFillPeer {
            scope: "cache",
            peer: "node-a".to_owned(),
            reason: "http peer base_url is allowed only for loopback peers unless allow_insecure_http = true",
        })
    );

    let config: Config = toml::from_str(
        r#"
            [cache]
            enabled = true

            [cache.memory]
            enabled = true

            [cache.peer_fill]
            enabled = true
            allow_insecure_http = true

            [[cache.peer_fill.peers]]
            name = "node-a"
            base_url = "http://node-a.example.internal:8080"

            [[cache.peer_fill.peers]]
            name = "node-a"
            base_url = "https://node-b.example.internal:8443"
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::DuplicateCachePeerFillPeerName {
            scope: "cache",
            name: "node-a".to_owned(),
        })
    );
}

#[test]
#[cfg(feature = "cache")]
fn parses_cache_purger_config() {
    let config: Config = toml::from_str(
        r#"
            [cache_purger]
            enabled = true
            interval_secs = 60
            limit = 1000
            batches = 4
            "#,
    )
    .unwrap();

    assert_eq!(
        config.cache_purger,
        CachePurgerConfig {
            enabled: true,
            interval_secs: 60,
            limit: 1000,
            batches: 4,
        }
    );
    config.validate().unwrap();
}

#[test]
fn rejects_invalid_cache_purger_limits() {
    let config: Config = toml::from_str(
        r#"
            [cache_purger]
            interval_secs = 0
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidCachePurgerPolicy {
            field: "cache_purger.interval_secs",
            reason: "interval must be between 1 and 86400 seconds",
        })
    );

    let config: Config = toml::from_str(
        r#"
            [cache_purger]
            limit = 0
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidCachePurgerPolicy {
            field: "cache_purger.limit",
            reason: "limit must be between 1 and 100000 indexed entries",
        })
    );

    let config: Config = toml::from_str(
        r#"
            [cache_purger]
            batches = 0
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidCachePurgerPolicy {
            field: "cache_purger.batches",
            reason: "batches must be between 1 and 100",
        })
    );
}

#[test]
#[cfg(not(feature = "cache"))]
fn rejects_enabled_cache_purger_without_cache_feature() {
    let config: Config = toml::from_str(
        r#"
            [cache_purger]
            enabled = true
            "#,
    )
    .unwrap();

    assert_eq!(config.validate(), Err(ConfigError::CachePurgerNotCompiled));
}

#[test]
fn rejects_invalid_cache_method() {
    let config: Config = toml::from_str(
        r#"
            [cache]
            enabled = true
            methods = ["get"]
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidCacheMethod {
            scope: "cache",
            method: "get".to_owned()
        })
    );
}

#[test]
fn rejects_invalid_cache_extension() {
    let config: Config = toml::from_str(
        r#"
            [cache]
            enabled = true
            image_extensions = [".jpg"]
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidCacheImageExtension {
            scope: "cache",
            extension: ".jpg".to_owned()
        })
    );
}

#[test]
fn rejects_enabled_cache_without_storage_tier() {
    let config: Config = toml::from_str(
        r#"
            [cache]
            enabled = true
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::CacheEnabledWithoutStorageTier { scope: "cache" })
    );
}

#[test]
fn requires_disk_cache_path_when_enabled() {
    let config: Config = toml::from_str(
        r#"
            [cache.disk]
            enabled = true
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::MissingCacheDiskPath { scope: "cache" })
    );
}

#[test]
fn parses_filesystem_disk_cache_backend() {
    let root = unique_temp_path("config-cache-filesystem-backend");
    std::fs::create_dir_all(&root).unwrap();
    let config: Config = toml::from_str(&format!(
        r#"
            [cache]
            enabled = true

            [cache.disk]
            enabled = true
            backend = "filesystem"
            path = "{}"
            "#,
        root.display()
    ))
    .unwrap();

    assert_eq!(config.cache.disk.backend, CacheDiskBackend::Filesystem);
    assert_eq!(config.validate(), Ok(()));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn accepts_storage_bin_backend() {
    let root = unique_temp_path("config-cache-storage-bin-backend");
    std::fs::create_dir_all(&root).unwrap();
    let config: Config = toml::from_str(&format!(
        r#"
            [cache]
            enabled = true

            [cache.disk]
            enabled = true
            backend = "storage-bin"
            path = "{}"
            "#,
        root.display()
    ))
    .unwrap();

    assert_eq!(config.cache.disk.backend, CacheDiskBackend::StorageBin);
    assert_eq!(config.validate(), Ok(()));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn parses_reserved_storage_bin_backend_options() {
    let root = unique_temp_path("config-cache-storage-bin-options");
    std::fs::create_dir_all(&root).unwrap();
    let config: Config = toml::from_str(&format!(
        r#"
            [cache]
            enabled = true
            max_object_bytes = "32MiB"

            [cache.disk]
            enabled = true
            backend = "storage-bin"
            path = "{}"
            max_size_bytes = "2GiB"

            [cache.disk.storage_bin]
            bin_size_bytes = "512MiB"
            preallocate = true
            max_open_bins = 8
            "#,
        root.display()
    ))
    .unwrap();

    assert_eq!(config.cache.disk.backend, CacheDiskBackend::StorageBin);
    assert_eq!(
        config.cache.disk.storage_bin.bin_size_bytes,
        ByteSize::from_bytes(512 * 1024 * 1024)
    );
    assert!(config.cache.disk.storage_bin.preallocate);
    assert_eq!(config.cache.disk.storage_bin.max_open_bins, 8);
    assert_eq!(config.validate(), Ok(()));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn rejects_storage_bin_smaller_than_cache_object_limit() {
    let root = unique_temp_path("config-cache-storage-bin-too-small");
    std::fs::create_dir_all(&root).unwrap();
    let config: Config = toml::from_str(&format!(
        r#"
            [cache]
            enabled = true
            max_object_bytes = "64MiB"

            [cache.disk]
            enabled = true
            backend = "storage-bin"
            path = "{}"
            max_size_bytes = "2GiB"

            [cache.disk.storage_bin]
            bin_size_bytes = "32MiB"
            "#,
        root.display()
    ))
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::CacheStorageBinSmallerThanMaxObject { scope: "cache" })
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn rejects_zero_storage_bin_max_open_bins() {
    let root = unique_temp_path("config-cache-storage-bin-open-bins");
    std::fs::create_dir_all(&root).unwrap();
    let config: Config = toml::from_str(&format!(
        r#"
            [cache]
            enabled = true

            [cache.disk]
            enabled = true
            backend = "storage-bin"
            path = "{}"
            max_size_bytes = "2GiB"

            [cache.disk.storage_bin]
            max_open_bins = 0
            "#,
        root.display()
    ))
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidCacheStorageBinMaxOpenBins { scope: "cache" })
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn accepts_cache_disk_encryption_local_file() {
    let root = unique_temp_path("config-cache-encryption-local");
    let secrets = root.join("secrets");
    std::fs::create_dir_all(&secrets).unwrap();
    let config: Config = toml::from_str(&format!(
        r#"
            [cache]
            enabled = true

            [cache.disk]
            enabled = true
            path = "{}/cache"

            [cache.disk.encryption]
            enabled = true
            provider = "local"
            algorithm = "aes-256-gcm"
            key_id = "cache-v1"
            key_file = "{}/cache-key"
            "#,
        root.display(),
        secrets.display()
    ))
    .unwrap();

    assert!(config.cache.disk.encryption.enabled);
    assert_eq!(
        config.cache.disk.encryption.provider,
        CacheDiskEncryptionProvider::Local
    );
    assert_eq!(config.validate(), Ok(()));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn accepts_cache_disk_encryption_local_credential() {
    let root = unique_temp_path("config-cache-encryption-credential");
    std::fs::create_dir_all(&root).unwrap();
    let config: Config = toml::from_str(&format!(
        r#"
            [cache]
            enabled = true

            [cache.disk]
            enabled = true
            path = "{}"

            [cache.disk.encryption]
            enabled = true
            provider = "local"
            key_credential = "fluxheim-cache-key"
            "#,
        root.display()
    ))
    .unwrap();

    assert_eq!(config.validate(), Ok(()));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn rejects_enabled_cache_disk_encryption_without_secret_source() {
    let root = unique_temp_path("config-cache-encryption-missing-key");
    std::fs::create_dir_all(&root).unwrap();
    let config: Config = toml::from_str(&format!(
        r#"
            [cache]
            enabled = true

            [cache.disk]
            enabled = true
            path = "{}"

            [cache.disk.encryption]
            enabled = true
            provider = "local"
            "#,
        root.display()
    ))
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidCacheEncryptionPolicy {
            scope: "cache",
            field: "key",
            reason: "must be read from a file or systemd/container credential",
        })
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn rejects_conflicting_cache_disk_encryption_secret_sources() {
    let root = unique_temp_path("config-cache-encryption-conflict");
    let secrets = root.join("secrets");
    std::fs::create_dir_all(&secrets).unwrap();
    let config: Config = toml::from_str(&format!(
        r#"
            [cache]
            enabled = true

            [cache.disk]
            enabled = true
            path = "{}/cache"

            [cache.disk.encryption]
            enabled = true
            provider = "local"
            key_file = "{}/cache-key"
            key_credential = "fluxheim-cache-key"
            "#,
        root.display(),
        secrets.display()
    ))
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidCacheEncryptionPolicy {
            scope: "cache",
            field: "key",
            reason: "cannot use more than one secret source",
        })
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn rejects_unimplemented_local_cache_disk_encryption_algorithm() {
    let root = unique_temp_path("config-cache-encryption-local-algorithm");
    std::fs::create_dir_all(&root).unwrap();
    let config: Config = toml::from_str(&format!(
        r#"
            [cache]
            enabled = true

            [cache.disk]
            enabled = true
            path = "{}"

            [cache.disk.encryption]
            enabled = true
            provider = "local"
            algorithm = "xchacha20-poly1305"
            key_credential = "fluxheim-cache-key"
            "#,
        root.display()
    ))
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidCacheEncryptionPolicy {
            scope: "cache",
            field: "disk.encryption.algorithm",
            reason: "local provider currently supports only \"aes-256-gcm\"",
        })
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn accepts_cache_disk_encryption_openbao_transit_provider() {
    let root = unique_temp_path("config-cache-encryption-openbao");
    std::fs::create_dir_all(&root).unwrap();
    let config: Config = toml::from_str(&format!(
        r#"
            [cache]
            enabled = true

            [cache.disk]
            enabled = true
            path = "{}"

            [cache.disk.encryption]
            enabled = true
            provider = "openbao-transit"
            algorithm = "xchacha20-poly1305"

            [cache.disk.encryption.openbao]
            address = "https://openbao.internal.example"
            mount = "transit"
            key_name = "fluxheim-cache"
            token_credential = "openbao-token"
            "#,
        root.display()
    ))
    .unwrap();

    assert_eq!(
        config.cache.disk.encryption.provider,
        CacheDiskEncryptionProvider::OpenbaoTransit
    );
    assert_eq!(config.validate(), Ok(()));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn rejects_plain_http_openbao_non_loopback_address() {
    let root = unique_temp_path("config-cache-encryption-openbao-http");
    std::fs::create_dir_all(&root).unwrap();
    let config: Config = toml::from_str(&format!(
        r#"
            [cache]
            enabled = true

            [cache.disk]
            enabled = true
            path = "{}"

            [cache.disk.encryption]
            enabled = true
            provider = "openbao-transit"

            [cache.disk.encryption.openbao]
            address = "http://openbao.internal.example"
            mount = "transit"
            key_name = "fluxheim-cache"
            token_credential = "openbao-token"
            "#,
        root.display()
    ))
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidCacheEncryptionPolicy {
            scope: "cache",
            field: "disk.encryption.openbao.address",
            reason: "must be an http://127.0.0.1, http://[::1], or https:// URL without credentials, query, or fragment",
        })
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn rejects_plain_http_openbao_malformed_ipv6_loopback_authority() {
    let root = unique_temp_path("config-cache-encryption-openbao-ipv6-tail");
    std::fs::create_dir_all(&root).unwrap();
    let config: Config = toml::from_str(&format!(
        r#"
            [cache]
            enabled = true

            [cache.disk]
            enabled = true
            path = "{}"

            [cache.disk.encryption]
            enabled = true
            provider = "openbao-transit"

            [cache.disk.encryption.openbao]
            address = "http://[::1]attacker.example.test/v1"
            mount = "transit"
            key_name = "fluxheim-cache"
            token_credential = "openbao-token"
            "#,
        root.display()
    ))
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidCacheEncryptionPolicy {
            scope: "cache",
            field: "disk.encryption.openbao.address",
            reason: "must be an http://127.0.0.1, http://[::1], or https:// URL without credentials, query, or fragment",
        })
    );

    let _ = std::fs::remove_dir_all(root);
}

#[cfg(unix)]
#[test]
fn rejects_disk_cache_under_world_writable_parent() {
    let path = unique_world_writable_child("config-cache-world-writable", "cache");
    let config: Config = toml::from_str(&format!(
        r#"
            [cache.disk]
            enabled = true
            path = "{}"
            "#,
        path.display()
    ))
    .unwrap();

    assert!(matches!(
        config.validate(),
        Err(ConfigError::UnsafePath { field, .. }) if field == "cache.disk.path"
    ));
}

#[test]
fn rejects_zero_memory_cache_size_when_enabled() {
    let config: Config = toml::from_str(
        r#"
            [cache.memory]
            enabled = true
            max_size_bytes = 0
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidCacheTierMaxSize {
            field: "cache.memory.max_size_bytes".to_owned()
        })
    );
}

#[test]
fn rejects_cache_tier_smaller_than_max_object() {
    let config: Config = toml::from_str(
        r#"
            [cache]
            max_object_bytes = "64MiB"

            [cache.memory]
            enabled = true
            max_size_bytes = "32MiB"
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::CacheTierSmallerThanMaxObject {
            tier: "cache.memory".to_owned()
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
fn parses_admin_config_with_self_healing() {
    let snapshot_store = secure_test_dir("config-admin-self-healing-snapshots");
    let config: Config = toml::from_str(&format!(
        r#"
            [admin]
            enabled = true
            listen = "127.0.0.1:9090"
            token_env = "FLUXHEIM_ADMIN_TOKEN"
            snapshot_store = "{}"

            [admin.transport]
            mode = "local_only"

            [admin.health]
            unauthenticated = false
            response = "minimal"

            [admin.auth_throttle]
            enabled = true
            window_secs = 30
            per_source_failures = 3
            global_failures = 50
            base_lockout_secs = 10
            max_lockout_secs = 120
            max_sources = 1024

            [admin.client_certificate]
            required = true
            sha256_header = "x-client-cert-sha256"
            allow_sha256 = ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]

            [admin.self_healing]
            enabled = true
            validation_window_secs = 45
            health_path = "/_fluxheim/health"
            min_successful_checks = 2
            max_error_rate_per_mille = 50
            "#,
        snapshot_store.display()
    ))
    .unwrap();

    config.validate().unwrap();
    assert!(config.admin.enabled);
    assert!(config.admin.self_healing.enabled);
    assert_eq!(
        config.admin.snapshot_store.as_deref(),
        Some(snapshot_store.as_path())
    );
    assert_eq!(
        config.admin.health.response,
        AdminHealthResponseMode::Minimal
    );
    assert_eq!(
        config.admin.transport.mode,
        AdminRemoteTransportMode::LocalOnly
    );
    assert_eq!(config.admin.auth_throttle.per_source_failures, 3);
    assert_eq!(config.admin.auth_throttle.global_failures, 50);
    assert!(config.admin.client_certificate.required);
    assert_eq!(
        config.admin.client_certificate.allow_sha256,
        vec!["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
    );
}

#[cfg(unix)]
#[test]
fn parses_admin_read_only_ops_socket() {
    let snapshot_store = secure_test_dir("config-admin-ops-snapshots");
    let socket_dir = secure_test_dir("config-admin-ops-runtime");
    let config: Config = toml::from_str(&format!(
        r#"
            [admin]
            enabled = true
            listen = "127.0.0.1:9090"
            token_env = "FLUXHEIM_ADMIN_TOKEN"
            snapshot_store = "{}"

            [admin.ops_socket]
            enabled = true
            path = "{}/fluxheim-ops.sock"
            mode = "0660"
            "#,
        snapshot_store.display(),
        socket_dir.display()
    ))
    .unwrap();

    config.validate().unwrap();
    assert!(config.admin.ops_socket.enabled);
    assert_eq!(config.admin.ops_socket.mode_bits(), 0o660);
}

#[cfg(unix)]
#[test]
fn rejects_world_accessible_admin_ops_socket() {
    let snapshot_store = secure_test_dir("config-admin-ops-world-snapshots");
    let socket_dir = secure_test_dir("config-admin-ops-world-runtime");
    let config: Config = toml::from_str(&format!(
        r#"
            [admin]
            enabled = true
            listen = "127.0.0.1:9090"
            token_env = "FLUXHEIM_ADMIN_TOKEN"
            snapshot_store = "{}"

            [admin.ops_socket]
            enabled = true
            path = "{}/fluxheim-ops.sock"
            mode = "0666"
            "#,
        snapshot_store.display(),
        socket_dir.display()
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("admin.ops_socket.mode"), "{error}");
}

#[test]
fn rejects_invalid_admin_client_certificate_fingerprint() {
    let config: Config = toml::from_str(
        r#"
            [admin.client_certificate]
            allow_sha256 = ["not-a-sha256"]
            "#,
    )
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(
        error.contains("admin.client_certificate.allow_sha256"),
        "{error}"
    );
}

#[test]
fn rejects_remote_unauthenticated_admin_health() {
    let snapshot_store = secure_test_dir("config-admin-remote-health-snapshots");
    let config = Config {
        admin: AdminConfig {
            enabled: true,
            listen: "0.0.0.0:9090".to_owned(),
            require_loopback: false,
            token_env: Some("FLUXHEIM_ADMIN_TOKEN".to_owned()),
            snapshot_store: Some(snapshot_store),
            transport: AdminTransportConfig {
                mode: AdminRemoteTransportMode::TrustedTlsTerminator,
            },
            health: AdminHealthConfig {
                unauthenticated: true,
                ..AdminHealthConfig::default()
            },
            ..AdminConfig::default()
        },
        ..Config::default()
    };

    assert_eq!(
        config.validate(),
        Err(ConfigError::UnauthenticatedAdminHealthNotLoopback {
            address: "0.0.0.0:9090".to_owned()
        })
    );
}

#[test]
fn rejects_invalid_admin_auth_throttle() {
    let config: Config = toml::from_str(
        r#"
            [admin.auth_throttle]
            enabled = true
            max_lockout_secs = 1
            base_lockout_secs = 2
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidAdminAuthThrottle {
            field: "admin.auth_throttle.max_lockout_secs"
        })
    );
}

#[test]
fn parses_metrics_config() {
    let config: Config = toml::from_str(
        r#"
            [metrics]
            enabled = true
            listen = "127.0.0.1:9091"
            "#,
    )
    .unwrap();

    config.validate().unwrap();
    assert!(config.metrics.enabled);
    assert_eq!(config.metrics.listen, "127.0.0.1:9091");
}

#[cfg(feature = "metrics-otlp")]
#[test]
fn parses_otlp_metrics_export_config() {
    let config: Config = toml::from_str(
        r#"
            [metrics]
            enabled = true

            [metrics.otlp]
            enabled = true
            endpoint = "http://127.0.0.1:9090/api/v1/otlp/v1/metrics"
            service_name = "fluxheim-smoke"
            interval_secs = 1
            timeout_secs = 1
            "#,
    )
    .unwrap();

    config.validate().unwrap();
    assert!(config.metrics.otlp.enabled);
    assert_eq!(
        config.metrics.otlp.endpoint,
        "http://127.0.0.1:9090/api/v1/otlp/v1/metrics"
    );
    assert_eq!(config.metrics.otlp.service_name, "fluxheim-smoke");
    assert_eq!(config.metrics.otlp.interval_secs, 1);
}

#[cfg(feature = "metrics-otlp")]
#[test]
fn accepts_https_otlp_metrics_endpoint() {
    let config: Config = toml::from_str(
        r#"
            [metrics]
            enabled = true

            [metrics.otlp]
            enabled = true
            endpoint = "https://collector.example.test/v1/metrics"
            tls_ca_cert_path = "fixtures/private-ca.pem"
            "#,
    )
    .unwrap();

    config.validate().unwrap();
    assert_eq!(
        config.metrics.otlp.endpoint,
        "https://collector.example.test/v1/metrics"
    );
    assert_eq!(
        config.metrics.otlp.tls_ca_cert_path.as_deref(),
        Some(Path::new("fixtures/private-ca.pem"))
    );
}

#[cfg(not(feature = "metrics-otlp"))]
#[test]
fn rejects_otlp_metrics_export_without_feature() {
    let config: Config = toml::from_str(
        r#"
            [metrics]
            enabled = true

            [metrics.otlp]
            enabled = true
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::MetricsOtlpExportNotCompiled)
    );
}

#[cfg(feature = "otel-tracing")]
#[test]
fn parses_trace_context_config() {
    let config: Config = toml::from_str(
        r#"
            [tracing]
            enabled = true
            mode = "propagate_only"
            traceparent = true
            log_trace_id = true
            "#,
    )
    .unwrap();

    config.validate().unwrap();
    assert!(config.tracing.enabled);
    assert_eq!(config.tracing.mode, super::TracingMode::PropagateOnly);
}

#[cfg(all(feature = "otel-tracing", feature = "otel-otlp"))]
#[test]
fn parses_otlp_trace_export_config() {
    let config: Config = toml::from_str(
        r#"
            [tracing]
            enabled = true
            mode = "propagate_only"

            [tracing.otlp]
            enabled = true
            endpoint = "http://127.0.0.1:4318/v1/traces"
            service_name = "fluxheim-smoke"
            queue_size = 64
            timeout_secs = 1
            "#,
    )
    .unwrap();

    config.validate().unwrap();
    assert!(config.tracing.otlp.enabled);
    assert_eq!(
        config.tracing.otlp.endpoint,
        "http://127.0.0.1:4318/v1/traces"
    );
    assert_eq!(config.tracing.otlp.service_name, "fluxheim-smoke");
    assert_eq!(config.tracing.otlp.queue_size, 64);
}

#[cfg(all(feature = "otel-tracing", feature = "otel-otlp"))]
#[test]
fn accepts_https_otlp_trace_endpoint() {
    let config: Config = toml::from_str(
        r#"
            [tracing]
            enabled = true

            [tracing.otlp]
            enabled = true
            endpoint = "https://collector.example.test/v1/traces"
            tls_ca_cert_path = "fixtures/private-ca.pem"
            "#,
    )
    .unwrap();

    config.validate().unwrap();
    assert_eq!(
        config.tracing.otlp.endpoint,
        "https://collector.example.test/v1/traces"
    );
    assert_eq!(
        config.tracing.otlp.tls_ca_cert_path.as_deref(),
        Some(Path::new("fixtures/private-ca.pem"))
    );
}

#[cfg(all(feature = "otel-tracing", not(feature = "otel-otlp")))]
#[test]
fn rejects_otlp_trace_export_without_feature() {
    let config: Config = toml::from_str(
        r#"
            [tracing]
            enabled = true

            [tracing.otlp]
            enabled = true
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::OtlpTraceExportNotCompiled)
    );
}

#[cfg(not(feature = "otel-tracing"))]
#[test]
fn rejects_enabled_tracing_without_feature() {
    let config: Config = toml::from_str(
        r#"
            [tracing]
            enabled = true
            "#,
    )
    .unwrap();

    assert_eq!(config.validate(), Err(ConfigError::TracingNotCompiled));
}

#[test]
fn parses_access_logging_config() {
    let config: Config = toml::from_str(
        r#"
            [logging]
            level = "debug"
            format = "text"
            target = "stdout"

            [logging.access]
            enabled = false
            include_host = false
            include_client_ip = false
            include_cache_phase = false
            include_path = false
            include_route = false
            include_upstream = false
            request_id = false
            request_id_header = "x-correlation-id"
            "#,
    )
    .unwrap();

    config.validate().unwrap();
    assert_eq!(config.logging.level, super::LoggingLevel::Debug);
    assert_eq!(config.logging.format, super::LoggingFormat::Text);
    assert_eq!(config.logging.target, super::LoggingTarget::Stdout);
    assert!(!config.logging.access.enabled);
    assert!(!config.logging.access.include_host);
    assert!(!config.logging.access.include_client_ip);
    assert!(!config.logging.access.include_cache_phase);
    assert!(!config.logging.access.include_path);
    assert!(!config.logging.access.include_route);
    assert!(!config.logging.access.include_upstream);
    assert!(!config.logging.access.request_id);
    assert_eq!(config.logging.access.request_id_header, "x-correlation-id");
}

#[cfg(not(feature = "privacy-mode"))]
#[test]
fn parses_file_logging_config() {
    let log_path = unique_temp_path("config-file-logging").join("fluxheim.log");
    let config: Config = toml::from_str(&format!(
        r#"
            [logging.file]
            enabled = true
            path = "{}"
            append = false
            "#,
        log_path.display()
    ))
    .unwrap();

    config.validate().unwrap();
    assert!(config.logging.file.enabled);
    assert_eq!(
        config.logging.file.path.as_deref(),
        Some(log_path.as_path())
    );
    assert!(!config.logging.file.append);
}

#[cfg(not(feature = "privacy-mode"))]
#[test]
fn rejects_file_logging_without_path() {
    let config: Config = toml::from_str(
        r#"
            [logging.file]
            enabled = true
            "#,
    )
    .unwrap();

    assert_eq!(config.validate(), Err(ConfigError::MissingLoggingFilePath));
}

#[test]
fn rejects_empty_file_logging_path() {
    let config: Config = toml::from_str(
        r#"
            [logging.file]
            path = ""
            "#,
    )
    .unwrap();

    assert_eq!(config.validate(), Err(ConfigError::EmptyLoggingFilePath));
}

#[test]
fn rejects_file_logging_path_traversal() {
    let config: Config = toml::from_str(
        r#"
            [logging.file]
            path = "../fluxheim.log"
            "#,
    )
    .unwrap();

    assert!(matches!(
        config.validate(),
        Err(ConfigError::UnsafePath { field, .. }) if field == "logging.file.path"
    ));
}

#[cfg(all(not(feature = "privacy-mode"), unix))]
#[test]
fn rejects_file_logging_under_world_writable_parent() {
    let path = unique_world_writable_child("config-log-world-writable", "fluxheim.log");
    let config: Config = toml::from_str(&format!(
        r#"
            [logging.file]
            path = "{}"
            "#,
        path.display()
    ))
    .unwrap();

    assert!(matches!(
        config.validate(),
        Err(ConfigError::UnsafePath { field, .. }) if field == "logging.file.path"
    ));
}

#[test]
fn rejects_invalid_access_log_request_id_header() {
    let config: Config = toml::from_str(
        r#"
            [logging.access]
            request_id_header = "bad header"
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidHeaderName {
            field: "logging.access.request_id_header",
            name: "bad header".to_owned(),
        })
    );
}

#[cfg(feature = "privacy-mode")]
#[test]
fn privacy_mode_rejects_access_logging() {
    let config: Config = toml::from_str(
        r#"
            [logging.access]
            enabled = true
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::PrivacyModeAccessLogging)
    );
}

#[cfg(feature = "privacy-mode")]
#[test]
fn privacy_mode_rejects_file_logging() {
    let config: Config = toml::from_str(
        r#"
            [logging.file]
            enabled = true
            path = "/var/log/fluxheim.log"
            "#,
    )
    .unwrap();

    assert_eq!(config.validate(), Err(ConfigError::PrivacyModeFileLogging));
}

#[test]
fn rejects_remote_metrics_listener_by_default() {
    let config = Config {
        metrics: MetricsConfig {
            enabled: true,
            listen: "0.0.0.0:9091".to_owned(),
            ..MetricsConfig::default()
        },
        ..Config::default()
    };

    assert_eq!(
        config.validate(),
        Err(ConfigError::MetricsListenNotLoopback {
            address: "0.0.0.0:9091".to_owned()
        })
    );
}

#[test]
fn rejects_enabled_admin_without_auth() {
    let snapshot_store = secure_test_dir("config-admin-missing-auth-snapshots");
    let config = Config {
        admin: AdminConfig {
            enabled: true,
            snapshot_store: Some(snapshot_store),
            ..AdminConfig::default()
        },
        ..Config::default()
    };

    assert_eq!(config.validate(), Err(ConfigError::MissingAdminAuth));
}

#[test]
fn rejects_enabled_admin_without_snapshot_store() {
    let config = Config {
        admin: AdminConfig {
            enabled: true,
            token_env: Some("FLUXHEIM_ADMIN_TOKEN".to_owned()),
            ..AdminConfig::default()
        },
        ..Config::default()
    };

    assert_eq!(
        config.validate(),
        Err(ConfigError::MissingAdminSnapshotStore)
    );
}

#[test]
fn rejects_remote_admin_listener_by_default() {
    let snapshot_store = secure_test_dir("config-admin-remote-default-snapshots");
    let config = Config {
        admin: AdminConfig {
            enabled: true,
            listen: "0.0.0.0:9090".to_owned(),
            token_env: Some("FLUXHEIM_ADMIN_TOKEN".to_owned()),
            snapshot_store: Some(snapshot_store),
            ..AdminConfig::default()
        },
        ..Config::default()
    };

    assert_eq!(
        config.validate(),
        Err(ConfigError::AdminListenNotLoopback {
            address: "0.0.0.0:9090".to_owned()
        })
    );
}

#[test]
fn rejects_remote_admin_without_trusted_tls_terminator() {
    let snapshot_store = secure_test_dir("config-admin-remote-insecure-snapshots");
    let config = Config {
        admin: AdminConfig {
            enabled: true,
            listen: "0.0.0.0:9090".to_owned(),
            require_loopback: false,
            token_env: Some("FLUXHEIM_ADMIN_TOKEN".to_owned()),
            snapshot_store: Some(snapshot_store),
            ..AdminConfig::default()
        },
        ..Config::default()
    };

    assert_eq!(
        config.validate(),
        Err(ConfigError::RemoteAdminRequiresSecureTransport {
            address: "0.0.0.0:9090".to_owned()
        })
    );
}

#[test]
fn accepts_remote_admin_when_trusted_tls_terminator_is_explicit() {
    let snapshot_store = secure_test_dir("config-admin-remote-trusted-snapshots");
    let config = Config {
        admin: AdminConfig {
            enabled: true,
            listen: "0.0.0.0:9090".to_owned(),
            require_loopback: false,
            token_env: Some("FLUXHEIM_ADMIN_TOKEN".to_owned()),
            snapshot_store: Some(snapshot_store),
            transport: AdminTransportConfig {
                mode: AdminRemoteTransportMode::TrustedTlsTerminator,
            },
            ..AdminConfig::default()
        },
        ..Config::default()
    };

    config.validate().unwrap();
}

#[cfg(unix)]
#[test]
fn rejects_admin_paths_under_world_writable_parent() {
    let token_file = unique_world_writable_child("config-admin-token-world-writable", "token");
    let token_config = Config {
        admin: AdminConfig {
            token_file: Some(token_file),
            ..AdminConfig::default()
        },
        ..Config::default()
    };
    assert!(matches!(
        token_config.validate(),
        Err(ConfigError::UnsafePath { field, .. }) if field == "admin.token_file"
    ));

    let snapshot_store =
        unique_world_writable_child("config-admin-snapshot-world-writable", "snapshots");
    let snapshot_config = Config {
        admin: AdminConfig {
            snapshot_store: Some(snapshot_store),
            ..AdminConfig::default()
        },
        ..Config::default()
    };
    assert!(matches!(
        snapshot_config.validate(),
        Err(ConfigError::UnsafePath { field, .. }) if field == "admin.snapshot_store"
    ));
}

#[test]
fn rejects_invalid_admin_self_healing_window() {
    let config = Config {
        admin: AdminConfig {
            self_healing: AdminSelfHealingConfig {
                validation_window_secs: 0,
                ..AdminSelfHealingConfig::default()
            },
            ..AdminConfig::default()
        },
        ..Config::default()
    };

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidAdminSelfHealing {
            field: "admin.self_healing.validation_window_secs"
        })
    );
}

#[test]
fn rejects_unsafe_admin_health_paths() {
    for health_path in [
        "relative/path".to_owned(),
        "/_fluxheim/health query".to_owned(),
        "/_fluxheim/health\tbad".to_owned(),
        "/_fluxheim\\health".to_owned(),
        "/_fluxheim/health?ready=1".to_owned(),
        "/_fluxheim/health#ready".to_owned(),
        "/_fluxheim/status".to_owned(),
        "/_fluxheim/reload".to_owned(),
        "/".to_owned() + &"a".repeat(super::MAX_ADMIN_HEALTH_PATH_BYTES),
    ] {
        let config = Config {
            admin: AdminConfig {
                self_healing: AdminSelfHealingConfig {
                    health_path,
                    ..AdminSelfHealingConfig::default()
                },
                ..AdminConfig::default()
            },
            ..Config::default()
        };

        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidAdminHealthPath { .. })
        ));
    }
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
    assert_eq!(normalize_host("example.com\u{0001}"), None);
    assert_eq!(normalize_host("*.example.com"), None);
    assert_eq!(
        normalize_host_pattern("*.Example.COM"),
        Some("*.example.com".to_owned())
    );
    assert_eq!(normalize_host_pattern("*bad.example.com"), None);
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
    #[cfg(feature = "acme")]
    assert_eq!(crate::acme::renewal_targets(&config).len(), 1);
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
