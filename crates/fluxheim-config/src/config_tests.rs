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
    ServerLimitsConfig, TlsAlpnPolicy, TlsCipherSuite, TlsClientAuthMode, TlsCurvePreference,
    TlsPolicyProfile, TlsProtocolVersion, TracingConfig, UpstreamHttpVersion,
    UpstreamProxyProtocol, VhostConfig, VhostHeaderPolicyConfig, VhostTlsConfig, WasmConfig,
    WebConfig, normalize_host, normalize_host_pattern, valid_dynamic_header_variable,
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
#[path = "config_tests_generic.rs"]
mod generic;
#[path = "config_tests_geoip.rs"]
mod geoip;
#[path = "config_tests_headers.rs"]
mod headers;
#[path = "config_tests_limits.rs"]
mod limits;
#[path = "config_tests_load_balance.rs"]
mod load_balance;
#[path = "config_tests_loader_conf_d.rs"]
mod loader_conf_d;
#[path = "config_tests_loader_core.rs"]
mod loader_core;
#[path = "config_tests_loader_paths.rs"]
mod loader_paths;
#[path = "config_tests_loader_source_safety.rs"]
mod loader_source_safety;
#[path = "config_tests_logging.rs"]
mod logging;
#[path = "config_tests_observability.rs"]
mod observability;
#[path = "config_tests_parse_hints.rs"]
mod parse_hints;
#[path = "config_tests_php.rs"]
mod php;
#[path = "config_tests_proxy.rs"]
mod proxy;
#[path = "config_tests_proxy_timeouts.rs"]
mod proxy_timeouts;
#[path = "config_tests_server.rs"]
mod server;
#[path = "config_tests_tls.rs"]
mod tls;
#[path = "config_tests_vhost_acme_redirect.rs"]
mod vhost_acme_redirect;
#[path = "config_tests_vhost_core.rs"]
mod vhost_core;
#[path = "config_tests_vhost_hosts.rs"]
mod vhost_hosts;
#[path = "config_tests_vhost_route_errors.rs"]
mod vhost_route_errors;
#[path = "config_tests_vhost_routes.rs"]
mod vhost_routes;
#[path = "config_tests_wasm.rs"]
mod wasm;
#[path = "config_tests_web.rs"]
mod web;

fn secure_test_dir(label: &str) -> PathBuf {
    let path = portable_test_path(unique_temp_path(label));
    fs::create_dir_all(&path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    path
}

fn portable_test_path(path: PathBuf) -> PathBuf {
    #[cfg(windows)]
    {
        dunce::simplified(&path).to_path_buf()
    }
    #[cfg(not(windows))]
    {
        path
    }
}

fn test_process_config_toml(label: &str) -> String {
    let root = secure_test_dir(label);
    format!(
        r#"
            [server.process]
            pid_file = '{}'
            upgrade_sock = '{}'
            certificate_reload_sock = '{}'
            "#,
        safe_child_path(&root, "fluxheim.pid").display(),
        safe_child_path(&root, "fluxheim-upgrade.sock").display(),
        safe_child_path(&root, "fluxheim-cert-reload.sock").display()
    )
}

fn valid_exec_health_check_config() -> Config {
    let command = std::env::current_exe().unwrap().display().to_string();
    let mut config: Config = toml::from_str(
        r#"
            [proxy.load_balance.health_check]
            protocol = "exec"
            "#,
    )
    .unwrap();
    config.proxy.load_balance.health_check.exec_command = Some(command.clone());
    config.proxy.load_balance.health_check.exec_allowed_commands = vec![command];
    config
}

struct TestDir {
    path: PathBuf,
}

impl TestDir {
    fn new(label: &str) -> Self {
        let path = portable_test_path(unique_temp_path(label));
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
