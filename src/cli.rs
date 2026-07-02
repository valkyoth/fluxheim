use std::error::Error;
#[cfg(feature = "cache")]
use std::io::Read;
#[cfg(feature = "cache")]
use std::io::Write as _;
use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

use crate::config::Config;
#[cfg(all(feature = "cache", feature = "proxy"))]
use crate::http_types::NativeCachePreviewRequest;

mod acme_init_commands;
mod acme_renew_commands;
mod crypto_commands;
use acme_init_commands::run_acme_init_command;
use acme_renew_commands::run_acme_renew_command;
pub use crypto_commands::print_crypto_diagnostics;
use crypto_commands::{run_cache_keygen_command, run_crypto_diagnostics_command};

#[derive(Debug, Parser)]
#[command(version = env!("FLUXHEIM_VERSION"), about = "Fluxheim reverse proxy")]
pub struct Cli {
    /// Path to a Fluxheim TOML configuration file.
    #[arg(short, long, env = "FLUXHEIM_CONFIG")]
    pub config: Option<PathBuf>,

    /// Validate configuration and print the resolved config.
    #[arg(long)]
    pub check_config: bool,

    /// Validate configuration without printing the resolved config.
    #[arg(long, conflicts_with = "check_config")]
    pub validate_config: bool,

    /// Validate TLS certificate/key files and ACME storage permissions.
    #[arg(long)]
    pub check_tls_storage: bool,

    /// Classify whether OLD_CONFIG can be hot-reloaded into --config.
    #[arg(long, value_name = "OLD_CONFIG", conflicts_with_all = ["check_config", "validate_config", "check_tls_storage"])]
    pub reload_from: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Option<CliCommand>,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Subcommand)]
pub enum CliCommand {
    /// Store the validated effective config as a versioned snapshot.
    Snapshot {
        /// Snapshot store directory.
        #[arg(long, env = "FLUXHEIM_SNAPSHOT_STORE")]
        store: PathBuf,

        /// Optional human note for the snapshot metadata.
        #[arg(long)]
        message: Option<String>,
    },

    /// Move the current pointer to a validated snapshot.
    Rollback {
        /// Snapshot store directory.
        #[arg(long, env = "FLUXHEIM_SNAPSHOT_STORE")]
        store: PathBuf,

        /// Snapshot id to roll back to. Defaults to the previous snapshot.
        #[arg(long)]
        to: Option<String>,
    },

    /// List known config snapshots.
    Snapshots {
        /// Snapshot store directory.
        #[arg(long, env = "FLUXHEIM_SNAPSHOT_STORE")]
        store: PathBuf,
    },

    /// Print compiled crypto/TLS backend diagnostics.
    Crypto,

    /// Run ACME issuance/renewal once for all configured ACME vhosts.
    AcmeRenew {
        /// Force renewal for every configured ACME vhost, even when certificates are not due.
        #[arg(long)]
        force_renew: bool,
        /// Deprecated alias for --force-renew.
        #[arg(long, hide = true)]
        all: bool,
    },

    /// Initialize managed ACME issuer configuration and local secret storage.
    AcmeInit {
        /// ACME issuer to initialize.
        issuer: AcmeInitIssuer,

        /// Contact email for the ACME account.
        #[arg(long)]
        email: Option<String>,

        /// Read the External Account Binding key identifier from this file.
        #[arg(long, value_name = "PATH", requires = "hmac_key_file")]
        kid_file: Option<PathBuf>,

        /// Read the External Account Binding HMAC key from this file.
        #[arg(long, value_name = "PATH", requires = "kid_file")]
        hmac_key_file: Option<PathBuf>,

        /// Refuse interactive prompts when required values are missing.
        #[arg(long)]
        non_interactive: bool,

        /// Overwrite files created by a previous initializer run.
        #[arg(long)]
        force: bool,

        /// Do not create a systemd credential drop-in.
        #[arg(long)]
        no_systemd: bool,

        /// TOML file to write. The packaged default config loads conf.d files.
        #[arg(long, default_value = "/etc/fluxheim/conf.d/acme.toml")]
        output: PathBuf,

        /// ACME account and certificate storage directory.
        #[arg(long, default_value = "/var/lib/fluxheim/acme")]
        storage: PathBuf,

        /// Root-only directory for local issuer secrets.
        #[arg(long, default_value = "/etc/fluxheim/secrets")]
        secrets_dir: PathBuf,

        /// systemd drop-in directory for fluxheim.service.
        #[arg(long, default_value = "/etc/systemd/system/fluxheim.service.d")]
        systemd_dropin_dir: PathBuf,
    },

    /// Generate a 256-bit hex key for local disk cache encryption.
    CacheKeygen,

    /// Warm configured cache paths through a running local Fluxheim listener.
    CacheWarm {
        /// Local Fluxheim HTTP listener to connect to. Defaults to the first server.listen address.
        #[arg(long)]
        listen: Option<String>,

        /// Host header to use for --path entries. Defaults to the configured default vhost host.
        #[arg(long)]
        host: Option<String>,

        /// Additional request header for warming negotiated variants, as "Name: value". May be repeated.
        #[arg(long = "header", value_name = "HEADER")]
        headers: Vec<String>,

        /// Absolute request path to warm. May be repeated.
        #[arg(long = "path", value_name = "PATH")]
        paths: Vec<String>,

        /// Read warm targets from a file. Lines may be "/path" or "host.example /path".
        #[arg(long, value_name = "FILE")]
        input: Option<PathBuf>,

        /// Per-request socket timeout in seconds.
        #[arg(long, default_value_t = 10)]
        timeout_secs: u64,

        /// Maximum number of warm targets accepted from --path plus --input.
        #[arg(long, default_value_t = 256)]
        max_targets: usize,

        /// Stop on the first failed warm request.
        #[arg(long)]
        fail_fast: bool,

        /// Validate and print the warm plan without sending requests.
        #[arg(long)]
        dry_run: bool,

        /// Number of times to request each warm target.
        #[arg(long, default_value_t = 1)]
        repeat: usize,

        /// Additional HTTP status code to count as warmed. 2xx and 3xx are accepted by default.
        #[arg(long = "allow-status", value_name = "STATUS")]
        allow_statuses: Vec<u16>,

        /// Cache status header to inspect when --expect-cache-status is used.
        #[arg(long, default_value = "x-cache-status")]
        cache_status_header: String,

        /// Required cache status header value. May be repeated, for example MISS and HIT.
        #[arg(long = "expect-cache-status", value_name = "VALUE")]
        expect_cache_statuses: Vec<String>,

        /// Per-repeat cache status sequence, for example MISS,HIT.
        #[arg(
            long = "expect-cache-status-sequence",
            value_name = "VALUES",
            value_delimiter = ','
        )]
        expect_cache_status_sequence: Vec<String>,
    },

    /// Preview the cache key selected for one request without contacting upstream.
    CacheKey {
        /// Host header to route and key with. Defaults to the configured default vhost host.
        #[arg(long)]
        host: Option<String>,

        /// Additional request header for cache variance preview, as "Name: value". May be repeated.
        #[arg(long = "header", value_name = "HEADER")]
        headers: Vec<String>,

        /// HTTP method to preview.
        #[arg(long, default_value = "GET")]
        method: String,

        /// Absolute request path to preview. May include a query string.
        #[arg(long)]
        path: String,

        /// Query string to preview when --path does not already contain one.
        #[arg(long)]
        query: Option<String>,

        /// Require the selected request to be eligible for caching.
        #[arg(long)]
        expect_eligible: bool,

        /// Require the selected request to be ineligible for caching.
        #[arg(long)]
        expect_ineligible: bool,

        /// Required bounded ineligibility reason.
        #[arg(long = "expect-reason", value_name = "REASON")]
        expect_reason: Option<String>,

        /// Require the selected cache policy to have cache locking enabled.
        #[arg(long)]
        expect_cache_lock_enabled: bool,

        /// Required cache-lock wait timeout in seconds for the selected cache policy.
        #[arg(long = "expect-cache-lock-wait-timeout-secs", value_name = "SECONDS")]
        expect_cache_lock_wait_timeout_secs: Option<u64>,

        /// Require the selected cache policy to have the cacheability predictor enabled.
        #[arg(long)]
        expect_cache_predictor_enabled: bool,

        /// Require the selected cache policy to have origin protection enabled.
        #[arg(long)]
        expect_origin_protection_enabled: bool,

        /// Required origin-protection max concurrent fills for the selected cache policy.
        #[arg(
            long = "expect-origin-protection-max-concurrent-fills",
            value_name = "COUNT"
        )]
        expect_origin_protection_max_concurrent_fills: Option<usize>,

        /// Require the selected cache policy to have peer fill enabled.
        #[arg(long)]
        expect_peer_fill_enabled: bool,

        /// Required number of configured peer-fill peers for the selected cache policy.
        #[arg(long = "expect-peer-fill-peers", value_name = "COUNT")]
        expect_peer_fill_peers: Option<usize>,

        /// Required peer-fill max concurrent requests for the selected cache policy.
        #[arg(
            long = "expect-peer-fill-max-concurrent-requests",
            value_name = "COUNT"
        )]
        expect_peer_fill_max_concurrent_requests: Option<usize>,

        /// Require the selected cache policy to have a memory cache tier.
        #[arg(long)]
        expect_memory_tier_enabled: bool,

        /// Require the selected cache policy to have a disk cache tier.
        #[arg(long)]
        expect_disk_tier_enabled: bool,

        /// Required number of enabled storage tiers for the selected cache policy.
        #[arg(long = "expect-storage-tiers", value_name = "COUNT")]
        expect_storage_tiers: Option<u8>,

        /// Required selected cache policy scope: vhost or route.
        #[arg(long = "expect-scope", value_name = "SCOPE")]
        expect_scope: Option<String>,

        /// Required selected vhost name.
        #[arg(long = "expect-vhost", value_name = "VHOST")]
        expect_vhost: Option<String>,

        /// Required selected route name for route-scoped cache policies.
        #[arg(long = "expect-route", value_name = "ROUTE")]
        expect_route: Option<String>,

        /// Required cache key namespace for the selected cache policy.
        #[arg(long = "expect-namespace", value_name = "NAMESPACE")]
        expect_namespace: Option<String>,

        /// Required operator key namespace configured on the selected cache policy.
        #[arg(long = "expect-key-namespace", value_name = "KEY_NAMESPACE")]
        expect_key_namespace: Option<String>,

        /// Required cache purge user tag for the selected cache policy.
        #[arg(long = "expect-user-tag", value_name = "USER_TAG")]
        expect_user_tag: Option<String>,
    },

    /// Inspect cached object metadata for one request without dumping response bodies.
    CacheLookup {
        /// Host header to route and key with. Defaults to the configured default vhost host.
        #[arg(long)]
        host: Option<String>,

        /// Additional request header for cache variance lookup, as "Name: value". May be repeated.
        #[arg(long = "header", value_name = "HEADER")]
        headers: Vec<String>,

        /// HTTP method to look up.
        #[arg(long, default_value = "GET")]
        method: String,

        /// Absolute request path to look up. May include a query string.
        #[arg(long)]
        path: String,

        /// Query string to look up when --path does not already contain one.
        #[arg(long)]
        query: Option<String>,

        /// Fail when no cached object exists for the selected key.
        #[arg(long)]
        require_object: bool,

        /// Required number of matching cached objects across enabled tiers.
        #[arg(long = "expect-objects", value_name = "COUNT")]
        expect_objects: Option<usize>,

        /// Require the selected request to be ineligible for caching.
        #[arg(long)]
        expect_ineligible: bool,

        /// Required bounded ineligibility reason.
        #[arg(long = "expect-reason", value_name = "REASON")]
        expect_reason: Option<String>,

        /// Required cached-object freshness state. May be repeated: fresh, stale, expired.
        #[arg(long = "expect-freshness-state", value_name = "STATE")]
        expect_freshness_states: Vec<String>,

        /// Required cached-object HTTP status. May be repeated.
        #[arg(long = "expect-status", value_name = "STATUS")]
        expect_statuses: Vec<u16>,

        /// Required cached-object storage tier. May be repeated: memory, disk.
        #[arg(long = "expect-tier", value_name = "TIER")]
        expect_tiers: Vec<String>,

        /// Required cached-object fresh TTL in seconds. May be repeated.
        #[arg(long = "expect-fresh-ttl-secs", value_name = "SECONDS")]
        expect_fresh_ttl_secs: Vec<u64>,

        /// Required cached-object body size in bytes. May be repeated.
        #[arg(long = "expect-body-bytes", value_name = "BYTES")]
        expect_body_bytes: Vec<u64>,

        /// Required stored response header name. May be repeated.
        #[arg(long = "expect-header-name", value_name = "HEADER")]
        expect_header_names: Vec<String>,

        /// Required stored response header value, as "Name: value". May be repeated.
        #[arg(long = "expect-header", value_name = "HEADER")]
        expect_headers: Vec<String>,

        /// Required stored cache tag. May be repeated.
        #[arg(long = "expect-cache-tag", value_name = "TAG")]
        expect_cache_tags: Vec<String>,

        /// Require at least one matching cached object to be present in the purge index.
        #[arg(long)]
        expect_purge_indexed: bool,

        /// Require the selected cache policy to have cache locking enabled.
        #[arg(long)]
        expect_cache_lock_enabled: bool,

        /// Required cache-lock wait timeout in seconds for the selected cache policy.
        #[arg(long = "expect-cache-lock-wait-timeout-secs", value_name = "SECONDS")]
        expect_cache_lock_wait_timeout_secs: Option<u64>,

        /// Require the selected cache policy to have the cacheability predictor enabled.
        #[arg(long)]
        expect_cache_predictor_enabled: bool,

        /// Require the selected cache policy to have origin protection enabled.
        #[arg(long)]
        expect_origin_protection_enabled: bool,

        /// Required origin-protection max concurrent fills for the selected cache policy.
        #[arg(
            long = "expect-origin-protection-max-concurrent-fills",
            value_name = "COUNT"
        )]
        expect_origin_protection_max_concurrent_fills: Option<usize>,

        /// Require the selected cache policy to have peer fill enabled.
        #[arg(long)]
        expect_peer_fill_enabled: bool,

        /// Required number of configured peer-fill peers for the selected cache policy.
        #[arg(long = "expect-peer-fill-peers", value_name = "COUNT")]
        expect_peer_fill_peers: Option<usize>,

        /// Required peer-fill max concurrent requests for the selected cache policy.
        #[arg(
            long = "expect-peer-fill-max-concurrent-requests",
            value_name = "COUNT"
        )]
        expect_peer_fill_max_concurrent_requests: Option<usize>,

        /// Require the selected cache policy to have a memory cache tier.
        #[arg(long)]
        expect_memory_tier_enabled: bool,

        /// Require the selected cache policy to have a disk cache tier.
        #[arg(long)]
        expect_disk_tier_enabled: bool,

        /// Required number of enabled storage tiers for the selected cache policy.
        #[arg(long = "expect-storage-tiers", value_name = "COUNT")]
        expect_storage_tiers: Option<u8>,

        /// Required selected cache policy scope: vhost or route.
        #[arg(long = "expect-scope", value_name = "SCOPE")]
        expect_scope: Option<String>,

        /// Required selected vhost name.
        #[arg(long = "expect-vhost", value_name = "VHOST")]
        expect_vhost: Option<String>,

        /// Required selected route name for route-scoped cache policies.
        #[arg(long = "expect-route", value_name = "ROUTE")]
        expect_route: Option<String>,

        /// Required cache key namespace for the selected cache policy.
        #[arg(long = "expect-namespace", value_name = "NAMESPACE")]
        expect_namespace: Option<String>,

        /// Required operator key namespace configured on the selected cache policy.
        #[arg(long = "expect-key-namespace", value_name = "KEY_NAMESPACE")]
        expect_key_namespace: Option<String>,

        /// Required cache purge user tag for the selected cache policy.
        #[arg(long = "expect-user-tag", value_name = "USER_TAG")]
        expect_user_tag: Option<String>,

        /// Require at least one matching cached object to be eligible for stale-if-error serving.
        #[arg(long)]
        expect_serve_stale_if_error: bool,

        /// Require at least one matching cached object to be eligible for stale-while-revalidate serving.
        #[arg(long)]
        expect_serve_stale_while_revalidate: bool,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum AcmeInitIssuer {
    Actalis,
    Letsencrypt,
    LetsencryptStaging,
}

pub fn run_from_env() -> Result<(), Box<dyn Error + Send + Sync>> {
    run_from_args(std::env::args_os())
}

pub fn run_from_args<I, T>(args: I) -> Result<(), Box<dyn Error + Send + Sync>>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    #[cfg(all(feature = "tls-rustls-backend", not(feature = "tls-openssl")))]
    crate::tls::install_rustls_crypto_provider()?;

    let cli = Cli::parse_from(args);

    if let Some(command) = &cli.command {
        return run_command(command, cli.config.as_deref());
    }

    if let Some(old_config_path) = cli.reload_from.as_deref() {
        let old_config = Config::load(Some(old_config_path))?;
        old_config.validate()?;
        let new_config = Config::load(cli.config.as_deref())?;
        new_config.validate()?;
        let impact = fluxheim_config::reload::classify_reload(&old_config, &new_config);
        println!("reload impact: {}", impact.kind());
        if !impact.reasons().is_empty() {
            println!("reasons:");
            for reason in impact.reasons() {
                println!("- {reason}");
            }
        }
        if impact.is_snapshot_safe() {
            println!("action: snapshot reload is safe");
        } else {
            println!("action: use process restart or unsupported-runtime remediation");
        }
        return Ok(());
    }

    let config = Config::load(cli.config.as_deref())?;
    config.validate()?;

    if cli.check_config {
        println!("{config:#?}");
        return Ok(());
    }

    if cli.validate_config {
        validate_runtime_config(&config)?;
        return Ok(());
    }

    if cli.check_tls_storage {
        return check_tls_storage(&config);
    }

    crate::runtime::run(config)
}

pub fn validate_compiled_module_config(
    config: &Config,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    #[cfg(all(feature = "web", feature = "cache", feature = "php-fpm"))]
    let _ = config;
    #[cfg(not(feature = "web"))]
    validate_web_module_absent(config)?;
    #[cfg(not(feature = "cache"))]
    validate_cache_module_absent(config)?;
    #[cfg(not(feature = "php-fpm"))]
    validate_php_module_absent(config)?;
    Ok(())
}

#[cfg(not(feature = "web"))]
fn validate_web_module_absent(config: &Config) -> Result<(), Box<dyn Error + Send + Sync>> {
    if config.web.enabled() {
        return Err(
            "web module not compiled; remove [web] root config or build with the `web` feature"
                .into(),
        );
    }
    for vhost in &config.vhosts {
        if vhost.web.enabled() {
            return Err(format!(
                "web module not compiled; remove [vhosts.web] root config for vhost {:?} or build with the `web` feature",
                vhost.name
            )
            .into());
        }
        for route in &vhost.routes {
            if route
                .web
                .as_ref()
                .is_some_and(crate::config::WebConfig::enabled)
            {
                return Err(format!(
                    "web module not compiled; remove [vhosts.routes.web] config for vhost {:?} route {:?} or build with the `web` feature",
                    vhost.name, route.name
                )
                .into());
            }
        }
    }
    Ok(())
}

#[cfg(not(feature = "cache"))]
fn validate_cache_module_absent(config: &Config) -> Result<(), Box<dyn Error + Send + Sync>> {
    if cache_policy_requires_module(&config.cache) {
        return Err("cache module not compiled; remove enabled [cache] config or build with the `cache` feature".into());
    }
    for vhost in &config.vhosts {
        if cache_policy_requires_module(&vhost.cache) {
            return Err(format!(
                "cache module not compiled; remove enabled [vhosts.cache] config for vhost {:?} or build with the `cache` feature",
                vhost.name
            )
            .into());
        }
        for route in &vhost.routes {
            if route
                .cache
                .as_ref()
                .is_some_and(cache_policy_requires_module)
            {
                return Err(format!(
                    "cache module not compiled; remove enabled [vhosts.routes.cache] config for vhost {:?} route {:?} or build with the `cache` feature",
                    vhost.name, route.name
                )
                .into());
            }
        }
    }
    Ok(())
}

#[cfg(not(feature = "cache"))]
fn cache_policy_requires_module(config: &crate::config::CacheConfig) -> bool {
    config.enabled
        || config.local_static
        || config.memory.enabled
        || config.disk.enabled
        || config.peer_fill.enabled
}

#[cfg(not(feature = "php-fpm"))]
fn validate_php_module_absent(config: &Config) -> Result<(), Box<dyn Error + Send + Sync>> {
    for vhost in &config.vhosts {
        if vhost.php.enabled() {
            return Err(format!(
                "php-fpm module not compiled; remove enabled [vhosts.php] config for vhost {:?} or build with the `php-fpm` feature",
                vhost.name
            )
            .into());
        }
        for route in &vhost.routes {
            if route
                .php
                .as_ref()
                .is_some_and(crate::config::PhpConfig::enabled)
            {
                return Err(format!(
                    "php-fpm module not compiled; remove enabled [vhosts.routes.php] config for vhost {:?} route {:?} or build with the `php-fpm` feature",
                    vhost.name, route.name
                )
                .into());
            }
        }
    }
    Ok(())
}

#[cfg(feature = "proxy")]
pub fn validate_runtime_config(config: &Config) -> Result<(), Box<dyn Error + Send + Sync>> {
    config.validate()?;
    validate_compiled_module_config(config)?;
    validate_fips_runtime_config(config)?;
    #[cfg(feature = "web")]
    validate_web_runtime_config(config)?;
    fluxheim_server::NativeHttp1HostRouter::from_config(
        config,
        fluxheim_server::DownstreamHttp1Policy::default(),
        0,
    )
    .map_err(|error| format!("proxy runtime validation failed: {error}"))?;
    #[cfg(feature = "stream-proxy")]
    crate::stream_proxy::stream_services_from_config(config)?;
    Ok(())
}

#[cfg(feature = "web")]
fn validate_web_runtime_config(config: &Config) -> Result<(), Box<dyn Error + Send + Sync>> {
    validate_web_runtime_scope("global web", &config.web)?;
    for vhost in &config.vhosts {
        validate_web_runtime_scope(&format!("vhost {:?} web", vhost.name), &vhost.web)?;
        for route in &vhost.routes {
            if let Some(web) = &route.web {
                validate_web_runtime_scope(
                    &format!("vhost {:?} route {:?} web", vhost.name, route.name),
                    web,
                )?;
            }
        }
    }
    Ok(())
}

#[cfg(all(feature = "web", not(feature = "proxy")))]
pub fn validate_runtime_config(config: &Config) -> Result<(), Box<dyn Error + Send + Sync>> {
    config.validate()?;
    validate_compiled_module_config(config)?;
    validate_fips_runtime_config(config)?;
    validate_web_runtime_config(config)?;
    Ok(())
}

#[cfg(feature = "web")]
fn validate_web_runtime_scope(
    scope: &str,
    config: &crate::config::WebConfig,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    crate::web::StaticFileServer::from_config(config)
        .map_err(|error| format!("{scope}: {error}"))?;
    Ok(())
}

#[cfg(not(any(feature = "proxy", feature = "web")))]
pub fn validate_runtime_config(config: &Config) -> Result<(), Box<dyn Error + Send + Sync>> {
    config.validate()?;
    validate_compiled_module_config(config)?;
    validate_fips_runtime_config(config)?;
    Ok(())
}

fn validate_fips_runtime_config(config: &Config) -> Result<(), Box<dyn Error + Send + Sync>> {
    #[cfg(any(
        feature = "tls",
        feature = "tls-rustls-backend",
        feature = "tls-openssl"
    ))]
    {
        crate::tls::validate_fips_runtime_config(config)
    }

    #[cfg(not(any(
        feature = "tls",
        feature = "tls-rustls-backend",
        feature = "tls-openssl"
    )))]
    {
        let compliance_mode = config.tls.compliance_mode();
        if compliance_mode.required() {
            Err(format!(
                "{} required mode requires a FIPS/ISO-capable TLS backend feature such as tls-rustls-fips, tls-openssl-fips, or tls-openssl-iso19790",
                compliance_mode.label()
            )
            .into())
        } else {
            Ok(())
        }
    }
}

fn run_command(
    command: &CliCommand,
    config_path: Option<&std::path::Path>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    match command {
        CliCommand::Snapshot { store, message } => {
            let config = Config::load(config_path)?;
            let store = fluxheim_snapshot::SnapshotStore::new(store);
            let snapshot = store.snapshot_config(&config, message.as_deref())?;
            println!("snapshot: {}", snapshot.id);
            println!("config: {}", snapshot.config_path.display());
            println!("current: {}", store.root().join("current").display());
            Ok(())
        }
        CliCommand::Rollback { store, to } => {
            let store = fluxheim_snapshot::SnapshotStore::new(store);
            let snapshot = store.rollback_target(to.as_deref())?;
            println!("rollback target: {}", snapshot.id);
            println!("config: {}", snapshot.config_path.display());
            println!(
                "action: current pointer updated; reload classification is still required before live apply"
            );
            Ok(())
        }
        CliCommand::Snapshots { store } => {
            let store = fluxheim_snapshot::SnapshotStore::new(store);
            let current = store.current_id()?;
            for snapshot in store.list()? {
                let marker = if current.as_deref() == Some(snapshot.id.as_str()) {
                    "*"
                } else {
                    " "
                };
                let message = snapshot.metadata.message.as_deref().unwrap_or("no message");
                println!("{marker} {} {}", snapshot.id, message.replace('\n', " "));
            }
            Ok(())
        }
        CliCommand::Crypto => run_crypto_diagnostics_command(config_path),
        CliCommand::AcmeRenew { force_renew, all } => {
            if *all {
                eprintln!("warning: --all is deprecated; use --force-renew");
            }
            run_acme_renew_command(config_path, *force_renew || *all)
        }
        CliCommand::AcmeInit {
            issuer,
            email,
            kid_file,
            hmac_key_file,
            non_interactive,
            force,
            no_systemd,
            output,
            storage,
            secrets_dir,
            systemd_dropin_dir,
        } => run_acme_init_command(AcmeInitOptions {
            issuer: *issuer,
            email: email.clone(),
            kid_file: kid_file.clone(),
            hmac_key_file: hmac_key_file.clone(),
            non_interactive: *non_interactive,
            force: *force,
            no_systemd: *no_systemd,
            output: output.clone(),
            storage: storage.clone(),
            secrets_dir: secrets_dir.clone(),
            systemd_dropin_dir: systemd_dropin_dir.clone(),
        }),
        CliCommand::CacheKeygen => run_cache_keygen_command(),
        CliCommand::CacheWarm {
            listen,
            host,
            headers,
            paths,
            input,
            timeout_secs,
            max_targets,
            fail_fast,
            dry_run,
            repeat,
            allow_statuses,
            cache_status_header,
            expect_cache_statuses,
            expect_cache_status_sequence,
        } => run_cache_warm_command(CacheWarmOptions {
            config_path,
            listen: listen.clone(),
            host: host.clone(),
            headers: headers.clone(),
            paths: paths.clone(),
            input: input.clone(),
            timeout_secs: *timeout_secs,
            max_targets: *max_targets,
            fail_fast: *fail_fast,
            dry_run: *dry_run,
            repeat: *repeat,
            allow_statuses: allow_statuses.clone(),
            cache_status_header: cache_status_header.clone(),
            expect_cache_statuses: expect_cache_statuses.clone(),
            expect_cache_status_sequence: expect_cache_status_sequence.clone(),
        }),
        CliCommand::CacheKey {
            host,
            headers,
            method,
            path,
            query,
            expect_eligible,
            expect_ineligible,
            expect_reason,
            expect_cache_lock_enabled,
            expect_cache_lock_wait_timeout_secs,
            expect_cache_predictor_enabled,
            expect_origin_protection_enabled,
            expect_origin_protection_max_concurrent_fills,
            expect_peer_fill_enabled,
            expect_peer_fill_peers,
            expect_peer_fill_max_concurrent_requests,
            expect_memory_tier_enabled,
            expect_disk_tier_enabled,
            expect_storage_tiers,
            expect_scope,
            expect_vhost,
            expect_route,
            expect_namespace,
            expect_key_namespace,
            expect_user_tag,
        } => run_cache_key_command(CacheKeyOptions {
            config_path,
            host: host.clone(),
            headers: headers.clone(),
            method: method.clone(),
            path: path.clone(),
            query: query.clone(),
            expect_eligible: *expect_eligible,
            expect_ineligible: *expect_ineligible,
            expect_reason: expect_reason.clone(),
            expect_cache_lock_enabled: *expect_cache_lock_enabled,
            expect_cache_lock_wait_timeout_secs: *expect_cache_lock_wait_timeout_secs,
            expect_cache_predictor_enabled: *expect_cache_predictor_enabled,
            expect_origin_protection_enabled: *expect_origin_protection_enabled,
            expect_origin_protection_max_concurrent_fills:
                *expect_origin_protection_max_concurrent_fills,
            expect_peer_fill_enabled: *expect_peer_fill_enabled,
            expect_peer_fill_peers: *expect_peer_fill_peers,
            expect_peer_fill_max_concurrent_requests: *expect_peer_fill_max_concurrent_requests,
            expect_memory_tier_enabled: *expect_memory_tier_enabled,
            expect_disk_tier_enabled: *expect_disk_tier_enabled,
            expect_storage_tiers: *expect_storage_tiers,
            expect_scope: expect_scope.clone(),
            expect_vhost: expect_vhost.clone(),
            expect_route: expect_route.clone(),
            expect_namespace: expect_namespace.clone(),
            expect_key_namespace: expect_key_namespace.clone(),
            expect_user_tag: expect_user_tag.clone(),
        }),
        CliCommand::CacheLookup {
            host,
            headers,
            method,
            path,
            query,
            require_object,
            expect_objects,
            expect_ineligible,
            expect_reason,
            expect_freshness_states,
            expect_statuses,
            expect_tiers,
            expect_fresh_ttl_secs,
            expect_body_bytes,
            expect_header_names,
            expect_headers,
            expect_cache_tags,
            expect_purge_indexed,
            expect_cache_lock_enabled,
            expect_cache_lock_wait_timeout_secs,
            expect_cache_predictor_enabled,
            expect_origin_protection_enabled,
            expect_origin_protection_max_concurrent_fills,
            expect_peer_fill_enabled,
            expect_peer_fill_peers,
            expect_peer_fill_max_concurrent_requests,
            expect_memory_tier_enabled,
            expect_disk_tier_enabled,
            expect_storage_tiers,
            expect_scope,
            expect_vhost,
            expect_route,
            expect_namespace,
            expect_key_namespace,
            expect_user_tag,
            expect_serve_stale_if_error,
            expect_serve_stale_while_revalidate,
        } => run_cache_lookup_command(CacheLookupOptions {
            config_path,
            host: host.clone(),
            headers: headers.clone(),
            method: method.clone(),
            path: path.clone(),
            query: query.clone(),
            require_object: *require_object,
            expect_objects: *expect_objects,
            expect_ineligible: *expect_ineligible,
            expect_reason: expect_reason.clone(),
            expect_freshness_states: expect_freshness_states.clone(),
            expect_statuses: expect_statuses.clone(),
            expect_tiers: expect_tiers.clone(),
            expect_fresh_ttl_secs: expect_fresh_ttl_secs.clone(),
            expect_body_bytes: expect_body_bytes.clone(),
            expect_header_names: expect_header_names.clone(),
            expect_headers: expect_headers.clone(),
            expect_cache_tags: expect_cache_tags.clone(),
            expect_purge_indexed: *expect_purge_indexed,
            expect_cache_lock_enabled: *expect_cache_lock_enabled,
            expect_cache_lock_wait_timeout_secs: *expect_cache_lock_wait_timeout_secs,
            expect_cache_predictor_enabled: *expect_cache_predictor_enabled,
            expect_origin_protection_enabled: *expect_origin_protection_enabled,
            expect_origin_protection_max_concurrent_fills:
                *expect_origin_protection_max_concurrent_fills,
            expect_peer_fill_enabled: *expect_peer_fill_enabled,
            expect_peer_fill_peers: *expect_peer_fill_peers,
            expect_peer_fill_max_concurrent_requests: *expect_peer_fill_max_concurrent_requests,
            expect_memory_tier_enabled: *expect_memory_tier_enabled,
            expect_disk_tier_enabled: *expect_disk_tier_enabled,
            expect_storage_tiers: *expect_storage_tiers,
            expect_scope: expect_scope.clone(),
            expect_vhost: expect_vhost.clone(),
            expect_route: expect_route.clone(),
            expect_namespace: expect_namespace.clone(),
            expect_key_namespace: expect_key_namespace.clone(),
            expect_user_tag: expect_user_tag.clone(),
            expect_serve_stale_if_error: *expect_serve_stale_if_error,
            expect_serve_stale_while_revalidate: *expect_serve_stale_while_revalidate,
        }),
    }
}

#[derive(Debug)]
struct CacheWarmOptions<'a> {
    config_path: Option<&'a std::path::Path>,
    listen: Option<String>,
    host: Option<String>,
    headers: Vec<String>,
    paths: Vec<String>,
    input: Option<PathBuf>,
    timeout_secs: u64,
    max_targets: usize,
    fail_fast: bool,
    dry_run: bool,
    repeat: usize,
    allow_statuses: Vec<u16>,
    cache_status_header: String,
    expect_cache_statuses: Vec<String>,
    expect_cache_status_sequence: Vec<String>,
}

#[derive(Debug)]
struct CacheKeyOptions<'a> {
    config_path: Option<&'a std::path::Path>,
    host: Option<String>,
    headers: Vec<String>,
    method: String,
    path: String,
    query: Option<String>,
    expect_eligible: bool,
    expect_ineligible: bool,
    expect_reason: Option<String>,
    expect_cache_lock_enabled: bool,
    expect_cache_lock_wait_timeout_secs: Option<u64>,
    expect_cache_predictor_enabled: bool,
    expect_origin_protection_enabled: bool,
    expect_origin_protection_max_concurrent_fills: Option<usize>,
    expect_peer_fill_enabled: bool,
    expect_peer_fill_peers: Option<usize>,
    expect_peer_fill_max_concurrent_requests: Option<usize>,
    expect_memory_tier_enabled: bool,
    expect_disk_tier_enabled: bool,
    expect_storage_tiers: Option<u8>,
    expect_scope: Option<String>,
    expect_vhost: Option<String>,
    expect_route: Option<String>,
    expect_namespace: Option<String>,
    expect_key_namespace: Option<String>,
    expect_user_tag: Option<String>,
}

#[derive(Debug)]
struct CacheLookupOptions<'a> {
    config_path: Option<&'a std::path::Path>,
    host: Option<String>,
    headers: Vec<String>,
    method: String,
    path: String,
    query: Option<String>,
    require_object: bool,
    expect_objects: Option<usize>,
    expect_ineligible: bool,
    expect_reason: Option<String>,
    expect_freshness_states: Vec<String>,
    expect_statuses: Vec<u16>,
    expect_tiers: Vec<String>,
    expect_fresh_ttl_secs: Vec<u64>,
    expect_body_bytes: Vec<u64>,
    expect_header_names: Vec<String>,
    expect_headers: Vec<String>,
    expect_cache_tags: Vec<String>,
    expect_purge_indexed: bool,
    expect_cache_lock_enabled: bool,
    expect_cache_lock_wait_timeout_secs: Option<u64>,
    expect_cache_predictor_enabled: bool,
    expect_origin_protection_enabled: bool,
    expect_origin_protection_max_concurrent_fills: Option<usize>,
    expect_peer_fill_enabled: bool,
    expect_peer_fill_peers: Option<usize>,
    expect_peer_fill_max_concurrent_requests: Option<usize>,
    expect_memory_tier_enabled: bool,
    expect_disk_tier_enabled: bool,
    expect_storage_tiers: Option<u8>,
    expect_scope: Option<String>,
    expect_vhost: Option<String>,
    expect_route: Option<String>,
    expect_namespace: Option<String>,
    expect_key_namespace: Option<String>,
    expect_user_tag: Option<String>,
    expect_serve_stale_if_error: bool,
    expect_serve_stale_while_revalidate: bool,
}

#[cfg(feature = "cache")]
#[derive(Debug, Clone, Eq, PartialEq)]
struct CacheWarmTarget {
    host: String,
    path: String,
}

#[cfg(feature = "cache")]
const CACHE_WARM_INPUT_MAX_BYTES: usize = 1024 * 1024;

#[cfg(feature = "cache")]
fn run_cache_warm_command(
    options: CacheWarmOptions<'_>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let config = Config::load(options.config_path)?;
    config.validate()?;

    if options.timeout_secs == 0 {
        return Err("cache-warm --timeout-secs must be greater than zero".into());
    }
    if options.max_targets == 0 || options.max_targets > 4096 {
        return Err("cache-warm --max-targets must be between 1 and 4096".into());
    }
    if options.repeat == 0 || options.repeat > 16 {
        return Err("cache-warm --repeat must be between 1 and 16".into());
    }
    validate_cache_warm_allow_statuses(&options.allow_statuses)?;
    validate_cache_warm_header_name(&options.cache_status_header)?;
    validate_cache_warm_expected_statuses(&options.expect_cache_statuses)?;
    validate_cache_warm_expected_sequence(
        &options.expect_cache_statuses,
        &options.expect_cache_status_sequence,
        options.repeat,
    )?;
    let request_headers = parse_cache_cli_headers("cache-warm", &options.headers)?;

    let listen = cache_warm_listen_addr(&config, options.listen.as_deref())?;
    let default_host = match options.host {
        Some(host) => {
            validate_cache_warm_host(&host)?;
            Some(host)
        }
        None => cache_warm_default_host(&config),
    };
    let targets = cache_warm_targets(
        default_host.as_deref(),
        &options.paths,
        options.input.as_deref(),
        options.max_targets,
    )?;
    let total_requests = targets
        .len()
        .checked_mul(options.repeat)
        .ok_or("cache-warm request count overflow")?;
    if total_requests > 4096 {
        return Err("cache-warm total request count must be at most 4096".into());
    }

    println!("cache warm targets: {}", targets.len());
    println!("cache warm requests: {total_requests}");
    println!("cache warm listener: {listen}");
    if !request_headers.is_empty() {
        println!("cache warm headers: {}", request_headers.len());
    }
    if options.dry_run {
        for target in targets {
            println!(
                "would warm: host={} path={} repeat={}",
                target.host, target.path, options.repeat
            );
        }
        println!("cache warm dry run completed");
        return Ok(());
    }

    let timeout = std::time::Duration::from_secs(options.timeout_secs);
    let mut warmed = 0_usize;
    let mut failed = 0_usize;
    let mut response_statuses = std::collections::BTreeMap::new();
    let mut cache_statuses = std::collections::BTreeMap::new();
    let mut failure_reasons = std::collections::BTreeMap::new();
    'targets: for target in targets {
        for attempt in 1..=options.repeat {
            match cache_warm_request(
                &listen,
                &target,
                timeout,
                &options.cache_status_header,
                &request_headers,
            ) {
                Ok(result) => {
                    fluxheim_cache::cache_warm_increment_count(
                        &mut response_statuses,
                        result.status,
                    );
                    let cache_status =
                        fluxheim_cache::cache_warm_safe_label(result.cache_status.as_deref());
                    fluxheim_cache::cache_warm_increment_count(
                        &mut cache_statuses,
                        cache_status.clone(),
                    );
                    if cache_warm_status_is_success(result.status, &options.allow_statuses) {
                        let expected = cache_warm_expected_statuses_for_attempt(
                            &options.expect_cache_statuses,
                            &options.expect_cache_status_sequence,
                            attempt,
                        );
                        match cache_warm_expected_status_matches(
                            result.cache_status.as_deref(),
                            expected,
                        ) {
                            Ok(()) => {
                                warmed = warmed.saturating_add(1);
                                println!(
                                    "warmed: host={} path={} attempt={}/{} status={} bytes={} cache_status={}",
                                    target.host,
                                    target.path,
                                    attempt,
                                    options.repeat,
                                    result.status,
                                    result.bytes_read,
                                    cache_status
                                );
                            }
                            Err(error) => {
                                failed = failed.saturating_add(1);
                                fluxheim_cache::cache_warm_increment_count(
                                    &mut failure_reasons,
                                    "unexpected_cache_status",
                                );
                                eprintln!(
                                    "failed: host={} path={} attempt={}/{} status={} bytes={} cache_status={} error={}",
                                    target.host,
                                    target.path,
                                    attempt,
                                    options.repeat,
                                    result.status,
                                    result.bytes_read,
                                    cache_status,
                                    error
                                );
                                if options.fail_fast {
                                    break 'targets;
                                }
                            }
                        }
                    } else {
                        failed = failed.saturating_add(1);
                        fluxheim_cache::cache_warm_increment_count(
                            &mut failure_reasons,
                            "unexpected_status",
                        );
                        eprintln!(
                            "failed: host={} path={} attempt={}/{} status={} bytes={} cache_status={} error=unexpected warm response status",
                            target.host,
                            target.path,
                            attempt,
                            options.repeat,
                            result.status,
                            result.bytes_read,
                            cache_status
                        );
                        if options.fail_fast {
                            break 'targets;
                        }
                    }
                }
                Err(error) => {
                    failed = failed.saturating_add(1);
                    fluxheim_cache::cache_warm_increment_count(
                        &mut failure_reasons,
                        "request_error",
                    );
                    eprintln!(
                        "failed: host={} path={} attempt={}/{} error={}",
                        target.host,
                        target.path,
                        attempt,
                        options.repeat,
                        error.to_string().replace('\n', " ")
                    );
                    if options.fail_fast {
                        break 'targets;
                    }
                }
            }
        }
    }

    print_cache_warm_counts("cache warm response statuses", &response_statuses);
    print_cache_warm_counts("cache warm cache statuses", &cache_statuses);
    print_cache_warm_counts("cache warm failure reasons", &failure_reasons);
    println!("cache warm completed: warmed={warmed} failed={failed}");
    if failed > 0 {
        return Err(format!("cache warm failed for {failed} target(s)").into());
    }
    Ok(())
}

#[cfg(feature = "cache")]
fn print_cache_warm_counts<K: std::fmt::Display>(
    label: &str,
    counts: &std::collections::BTreeMap<K, usize>,
) {
    if let Some(summary) = fluxheim_cache::cache_warm_counts_summary(counts) {
        println!("{label}: {summary}");
    }
}

#[cfg(not(feature = "cache"))]
fn run_cache_warm_command(
    options: CacheWarmOptions<'_>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let CacheWarmOptions {
        config_path,
        listen,
        host,
        headers,
        paths,
        input,
        timeout_secs,
        max_targets,
        fail_fast,
        dry_run,
        repeat,
        allow_statuses,
        cache_status_header,
        expect_cache_statuses,
        expect_cache_status_sequence,
    } = options;
    let _ = (
        config_path,
        listen,
        host,
        headers,
        paths,
        input,
        timeout_secs,
        max_targets,
        fail_fast,
        dry_run,
        repeat,
        allow_statuses,
        cache_status_header,
        expect_cache_statuses,
        expect_cache_status_sequence,
    );
    Err("cache-warm requires the cache feature".into())
}

#[cfg(all(feature = "cache", feature = "proxy"))]
fn run_cache_key_command(options: CacheKeyOptions<'_>) -> Result<(), Box<dyn Error + Send + Sync>> {
    validate_cache_lookup_expected_storage_tiers(options.expect_storage_tiers)?;
    let expected_scope = parse_cache_key_preview_scope("cache-key", options.expect_scope.as_ref())?;
    let expected_vhost =
        parse_cache_key_preview_name("cache-key", "--expect-vhost", options.expect_vhost.as_ref())?;
    let expected_route = parse_cache_key_preview_route("cache-key", options.expect_route.as_ref())?;
    let expected_namespace = parse_cache_key_preview_value(
        "cache-key",
        "--expect-namespace",
        options.expect_namespace.as_ref(),
    )?;
    let expected_key_namespace = parse_cache_key_preview_value(
        "cache-key",
        "--expect-key-namespace",
        options.expect_key_namespace.as_ref(),
    )?;
    let expected_user_tag = parse_cache_key_preview_value(
        "cache-key",
        "--expect-user-tag",
        options.expect_user_tag.as_ref(),
    )?;
    let expected_reason = parse_cache_key_preview_reason(
        "cache-key",
        "--expect-reason",
        options.expect_reason.as_ref(),
    )?;
    let (config, request) = cache_key_command_request(&options)?;
    let proxy = crate::native_proxy::FluxProxy::from_config(&config)?;
    let preview = proxy
        .snapshot()
        .native_image_cache_key_preview_for_request(&request);
    validate_cache_key_preview_expectations(
        &preview,
        CacheKeyPreviewExpectations {
            expect_eligible: options.expect_eligible,
            expect_ineligible: options.expect_ineligible,
            expected_reason: expected_reason.as_deref(),
            expect_cache_lock_enabled: options.expect_cache_lock_enabled,
            expected_cache_lock_wait_timeout_secs: options.expect_cache_lock_wait_timeout_secs,
            expect_cache_predictor_enabled: options.expect_cache_predictor_enabled,
            expect_origin_protection_enabled: options.expect_origin_protection_enabled,
            expected_origin_protection_max_concurrent_fills: options
                .expect_origin_protection_max_concurrent_fills,
            expect_peer_fill_enabled: options.expect_peer_fill_enabled,
            expected_peer_fill_peers: options.expect_peer_fill_peers,
            expected_peer_fill_max_concurrent_requests: options
                .expect_peer_fill_max_concurrent_requests,
            expect_memory_tier_enabled: options.expect_memory_tier_enabled,
            expect_disk_tier_enabled: options.expect_disk_tier_enabled,
            expect_storage_tiers: options.expect_storage_tiers,
            expected_scope: expected_scope.as_deref(),
            expected_vhost: expected_vhost.as_deref(),
            expected_route: expected_route.as_deref(),
            expected_namespace: expected_namespace.as_deref(),
            expected_key_namespace: expected_key_namespace.as_deref(),
            expected_user_tag: expected_user_tag.as_deref(),
        },
    )?;

    println!("cache key preview:");
    println!("vhost: {}", preview.vhost);
    println!("scope: {}", preview.scope.as_str());
    if let Some(route) = preview.route.as_deref() {
        println!("route: {route}");
    }
    println!("eligible: {}", preview.eligible);
    println!("cache_lock_enabled: {}", preview.cache_lock_enabled);
    println!(
        "cache_lock_wait_timeout_secs: {}",
        preview.cache_lock_wait_timeout_secs
    );
    println!(
        "cache_predictor_enabled: {}",
        preview.cache_predictor_enabled
    );
    println!(
        "origin_protection_enabled: {}",
        preview.origin_protection_enabled
    );
    println!(
        "origin_protection_max_concurrent_fills: {}",
        preview.origin_protection_max_concurrent_fills
    );
    println!("peer_fill_enabled: {}", preview.peer_fill_enabled);
    println!("peer_fill_peers: {}", preview.peer_fill_peer_count);
    println!(
        "peer_fill_max_concurrent_requests: {}",
        preview.peer_fill_max_concurrent_requests
    );
    println!("peer_fill_fail_open: {}", preview.peer_fill_fail_open);
    println!("memory_tier_enabled: {}", preview.memory_tier_enabled);
    println!("disk_tier_enabled: {}", preview.disk_tier_enabled);
    println!("storage_tiers: {}", preview.storage_tiers);
    if let Some(reason) = preview.reason.as_deref() {
        println!("reason: {reason}");
    }
    if let Some(namespace) = preview.namespace.as_deref() {
        println!("namespace: {namespace}");
    }
    if let Some(key_namespace) = preview.key_namespace.as_deref() {
        println!("key_namespace: {key_namespace}");
    }
    if let Some(primary_key) = preview.primary_key.as_deref() {
        println!("primary_key: {primary_key}");
    }
    if let Some(primary_hash) = preview.primary_hash.as_deref() {
        println!("primary_hash: {primary_hash}");
    }
    if let Some(variance_hash) = preview.variance_hash.as_deref() {
        println!("variance_hash: {variance_hash}");
    }
    if let Some(combined_hash) = preview.combined_hash.as_deref() {
        println!("combined_hash: {combined_hash}");
    }
    if let Some(user_tag) = preview.user_tag.as_deref() {
        println!("user_tag: {user_tag}");
    }

    Ok(())
}

#[cfg(all(feature = "cache", feature = "proxy"))]
#[derive(Clone, Copy)]
struct CacheKeyPreviewExpectations<'a> {
    expect_eligible: bool,
    expect_ineligible: bool,
    expected_reason: Option<&'a str>,
    expect_cache_lock_enabled: bool,
    expected_cache_lock_wait_timeout_secs: Option<u64>,
    expect_cache_predictor_enabled: bool,
    expect_origin_protection_enabled: bool,
    expected_origin_protection_max_concurrent_fills: Option<usize>,
    expect_peer_fill_enabled: bool,
    expected_peer_fill_peers: Option<usize>,
    expected_peer_fill_max_concurrent_requests: Option<usize>,
    expect_memory_tier_enabled: bool,
    expect_disk_tier_enabled: bool,
    expect_storage_tiers: Option<u8>,
    expected_scope: Option<&'a str>,
    expected_vhost: Option<&'a str>,
    expected_route: Option<&'a str>,
    expected_namespace: Option<&'a str>,
    expected_key_namespace: Option<&'a str>,
    expected_user_tag: Option<&'a str>,
}

#[cfg(all(feature = "cache", feature = "proxy"))]
fn validate_cache_key_preview_expectations(
    preview: &fluxheim_cache::CacheKeyPreview,
    expectations: CacheKeyPreviewExpectations<'_>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    if expectations.expect_eligible && !preview.eligible {
        let reason = preview.reason.as_deref().unwrap_or("unknown");
        return Err(format!("cache-key expected eligible request, found false: {reason}").into());
    }
    if expectations.expect_ineligible && preview.eligible {
        return Err("cache-key expected ineligible request, found true".into());
    }
    if let Some(expected_reason) = expectations.expected_reason
        && preview.reason.as_deref() != Some(expected_reason)
    {
        let found = preview.reason.as_deref().unwrap_or("none");
        return Err(format!("cache-key expected reason {expected_reason}, found {found}").into());
    }
    if expectations.expect_cache_lock_enabled && !preview.cache_lock_enabled {
        return Err("cache-key expected cache lock enabled, found false".into());
    }
    if let Some(expected_timeout) = expectations.expected_cache_lock_wait_timeout_secs
        && preview.cache_lock_wait_timeout_secs != expected_timeout
    {
        return Err(format!(
            "cache-key expected cache lock wait timeout seconds {expected_timeout}, found {}",
            preview.cache_lock_wait_timeout_secs
        )
        .into());
    }
    if expectations.expect_cache_predictor_enabled && !preview.cache_predictor_enabled {
        return Err("cache-key expected cache predictor enabled, found false".into());
    }
    if expectations.expect_origin_protection_enabled && !preview.origin_protection_enabled {
        return Err("cache-key expected origin protection enabled, found false".into());
    }
    if let Some(expected_concurrency) = expectations.expected_origin_protection_max_concurrent_fills
        && preview.origin_protection_max_concurrent_fills != expected_concurrency
    {
        return Err(format!(
            "cache-key expected origin protection max concurrent fills {expected_concurrency}, found {}",
            preview.origin_protection_max_concurrent_fills
        )
        .into());
    }
    if expectations.expect_peer_fill_enabled && !preview.peer_fill_enabled {
        return Err("cache-key expected peer fill enabled, found false".into());
    }
    if let Some(expected_peers) = expectations.expected_peer_fill_peers
        && preview.peer_fill_peer_count != expected_peers
    {
        return Err(format!(
            "cache-key expected peer fill peers {expected_peers}, found {}",
            preview.peer_fill_peer_count
        )
        .into());
    }
    if let Some(expected_concurrency) = expectations.expected_peer_fill_max_concurrent_requests
        && preview.peer_fill_max_concurrent_requests != expected_concurrency
    {
        return Err(format!(
            "cache-key expected peer fill max concurrent requests {expected_concurrency}, found {}",
            preview.peer_fill_max_concurrent_requests
        )
        .into());
    }
    if expectations.expect_memory_tier_enabled && !preview.memory_tier_enabled {
        return Err("cache-key expected memory tier enabled, found false".into());
    }
    if expectations.expect_disk_tier_enabled && !preview.disk_tier_enabled {
        return Err("cache-key expected disk tier enabled, found false".into());
    }
    if let Some(expected_storage_tiers) = expectations.expect_storage_tiers
        && preview.storage_tiers != expected_storage_tiers
    {
        return Err(format!(
            "cache-key expected storage tiers {expected_storage_tiers}, found {}",
            preview.storage_tiers
        )
        .into());
    }
    if let Some(expected_scope) = expectations.expected_scope
        && preview.scope.as_str() != expected_scope
    {
        return Err(format!(
            "cache-key expected scope {expected_scope}, found {}",
            preview.scope.as_str()
        )
        .into());
    }
    if let Some(expected_vhost) = expectations.expected_vhost
        && preview.vhost != expected_vhost
    {
        return Err(format!(
            "cache-key expected vhost {expected_vhost}, found {}",
            preview.vhost
        )
        .into());
    }
    if let Some(expected_route) = expectations.expected_route
        && preview.route.as_deref() != Some(expected_route)
    {
        let found = preview.route.as_deref().unwrap_or("none");
        return Err(format!("cache-key expected route {expected_route}, found {found}").into());
    }
    if let Some(expected_namespace) = expectations.expected_namespace
        && preview.namespace.as_deref() != Some(expected_namespace)
    {
        let found = preview.namespace.as_deref().unwrap_or("none");
        return Err(
            format!("cache-key expected namespace {expected_namespace}, found {found}").into(),
        );
    }
    if let Some(expected_key_namespace) = expectations.expected_key_namespace
        && preview.key_namespace.as_deref() != Some(expected_key_namespace)
    {
        let found = preview.key_namespace.as_deref().unwrap_or("none");
        return Err(format!(
            "cache-key expected key namespace {expected_key_namespace}, found {found}"
        )
        .into());
    }
    if let Some(expected_user_tag) = expectations.expected_user_tag
        && preview.user_tag.as_deref() != Some(expected_user_tag)
    {
        let found = preview.user_tag.as_deref().unwrap_or("none");
        return Err(
            format!("cache-key expected user tag {expected_user_tag}, found {found}").into(),
        );
    }
    Ok(())
}

#[cfg(all(feature = "cache", feature = "proxy"))]
fn run_cache_lookup_command(
    options: CacheLookupOptions<'_>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let cache_key_options = CacheKeyOptions {
        config_path: options.config_path,
        host: options.host,
        headers: options.headers,
        method: options.method,
        path: options.path,
        query: options.query,
        expect_eligible: false,
        expect_ineligible: false,
        expect_reason: None,
        expect_cache_lock_enabled: false,
        expect_cache_lock_wait_timeout_secs: None,
        expect_cache_predictor_enabled: false,
        expect_origin_protection_enabled: false,
        expect_origin_protection_max_concurrent_fills: None,
        expect_peer_fill_enabled: false,
        expect_peer_fill_peers: None,
        expect_peer_fill_max_concurrent_requests: None,
        expect_memory_tier_enabled: false,
        expect_disk_tier_enabled: false,
        expect_storage_tiers: None,
        expect_scope: None,
        expect_vhost: None,
        expect_route: None,
        expect_namespace: None,
        expect_key_namespace: None,
        expect_user_tag: None,
    };
    let require_object = options.require_object;
    let expected_states = parse_cache_lookup_freshness_states(&options.expect_freshness_states)?;
    let expected_tiers = parse_cache_lookup_tiers(&options.expect_tiers)?;
    let expected_header_names = parse_cache_lookup_header_names(&options.expect_header_names)?;
    let expected_headers = parse_cache_lookup_headers(&options.expect_headers)?;
    let expected_cache_tags = parse_cache_lookup_cache_tags(&options.expect_cache_tags)?;
    let expected_scope =
        parse_cache_key_preview_scope("cache-lookup", options.expect_scope.as_ref())?;
    let expected_vhost = parse_cache_key_preview_name(
        "cache-lookup",
        "--expect-vhost",
        options.expect_vhost.as_ref(),
    )?;
    let expected_route =
        parse_cache_key_preview_route("cache-lookup", options.expect_route.as_ref())?;
    let expected_namespace = parse_cache_key_preview_value(
        "cache-lookup",
        "--expect-namespace",
        options.expect_namespace.as_ref(),
    )?;
    let expected_key_namespace = parse_cache_key_preview_value(
        "cache-lookup",
        "--expect-key-namespace",
        options.expect_key_namespace.as_ref(),
    )?;
    let expected_user_tag = parse_cache_key_preview_value(
        "cache-lookup",
        "--expect-user-tag",
        options.expect_user_tag.as_ref(),
    )?;
    let expected_reason = parse_cache_key_preview_reason(
        "cache-lookup",
        "--expect-reason",
        options.expect_reason.as_ref(),
    )?;
    validate_cache_lookup_expected_statuses(&options.expect_statuses)?;
    validate_cache_lookup_expected_fresh_ttls(&options.expect_fresh_ttl_secs)?;
    validate_cache_lookup_expected_body_bytes(&options.expect_body_bytes)?;
    validate_cache_lookup_expected_objects(options.expect_objects)?;
    validate_cache_lookup_expected_storage_tiers(options.expect_storage_tiers)?;
    let (config, request) = cache_key_command_request(&cache_key_options)?;
    let proxy = crate::native_proxy::FluxProxy::from_config(&config)?;
    let lookup = proxy
        .snapshot()
        .native_image_cache_object_lookup_for_request(&request)?;
    let expectations = CacheLookupExpectations {
        require_object,
        expected_states: &expected_states,
        expected_statuses: &options.expect_statuses,
        expected_tiers: &expected_tiers,
        expected_fresh_ttl_secs: &options.expect_fresh_ttl_secs,
        expected_body_bytes: &options.expect_body_bytes,
        expected_header_names: &expected_header_names,
        expected_headers: &expected_headers,
        expected_cache_tags: &expected_cache_tags,
        expected_objects: options.expect_objects,
        expect_purge_indexed: options.expect_purge_indexed,
        expect_ineligible: options.expect_ineligible,
        expected_reason: expected_reason.as_deref(),
        expect_cache_lock_enabled: options.expect_cache_lock_enabled,
        expected_cache_lock_wait_timeout_secs: options.expect_cache_lock_wait_timeout_secs,
        expect_cache_predictor_enabled: options.expect_cache_predictor_enabled,
        expect_origin_protection_enabled: options.expect_origin_protection_enabled,
        expected_origin_protection_max_concurrent_fills: options
            .expect_origin_protection_max_concurrent_fills,
        expect_peer_fill_enabled: options.expect_peer_fill_enabled,
        expected_peer_fill_peers: options.expect_peer_fill_peers,
        expected_peer_fill_max_concurrent_requests: options
            .expect_peer_fill_max_concurrent_requests,
        expect_memory_tier_enabled: options.expect_memory_tier_enabled,
        expect_disk_tier_enabled: options.expect_disk_tier_enabled,
        expect_storage_tiers: options.expect_storage_tiers,
        expected_scope: expected_scope.as_deref(),
        expected_vhost: expected_vhost.as_deref(),
        expected_route: expected_route.as_deref(),
        expected_namespace: expected_namespace.as_deref(),
        expected_key_namespace: expected_key_namespace.as_deref(),
        expected_user_tag: expected_user_tag.as_deref(),
        expect_serve_stale_if_error: options.expect_serve_stale_if_error,
        expect_serve_stale_while_revalidate: options.expect_serve_stale_while_revalidate,
    };
    validate_cache_lookup_expectations(&lookup, &expectations)?;

    println!("cache object lookup:");
    println!("vhost: {}", lookup.preview.vhost);
    println!("scope: {}", lookup.preview.scope.as_str());
    if let Some(route) = lookup.preview.route.as_deref() {
        println!("route: {route}");
    }
    println!("eligible: {}", lookup.preview.eligible);
    println!("cache_lock_enabled: {}", lookup.preview.cache_lock_enabled);
    println!(
        "cache_lock_wait_timeout_secs: {}",
        lookup.preview.cache_lock_wait_timeout_secs
    );
    println!(
        "cache_predictor_enabled: {}",
        lookup.preview.cache_predictor_enabled
    );
    println!(
        "origin_protection_enabled: {}",
        lookup.preview.origin_protection_enabled
    );
    println!(
        "origin_protection_max_concurrent_fills: {}",
        lookup.preview.origin_protection_max_concurrent_fills
    );
    println!("peer_fill_enabled: {}", lookup.preview.peer_fill_enabled);
    println!("peer_fill_peers: {}", lookup.preview.peer_fill_peer_count);
    println!(
        "peer_fill_max_concurrent_requests: {}",
        lookup.preview.peer_fill_max_concurrent_requests
    );
    println!(
        "peer_fill_fail_open: {}",
        lookup.preview.peer_fill_fail_open
    );
    println!(
        "memory_tier_enabled: {}",
        lookup.preview.memory_tier_enabled
    );
    println!("disk_tier_enabled: {}", lookup.preview.disk_tier_enabled);
    println!("storage_tiers: {}", lookup.preview.storage_tiers);
    if let Some(reason) = lookup.preview.reason.as_deref() {
        println!("reason: {reason}");
    }
    if let Some(combined_hash) = lookup.preview.combined_hash.as_deref() {
        println!("combined_hash: {combined_hash}");
    }
    if let Some(namespace) = lookup.preview.namespace.as_deref() {
        println!("namespace: {namespace}");
    }
    if let Some(key_namespace) = lookup.preview.key_namespace.as_deref() {
        println!("key_namespace: {key_namespace}");
    }
    if let Some(user_tag) = lookup.preview.user_tag.as_deref() {
        println!("user_tag: {user_tag}");
    }
    println!("objects: {}", lookup.objects.len());
    for object in lookup.objects {
        println!("object:");
        println!("  tier: {}", object.tier.as_str());
        println!("  purge_indexed: {}", object.purge_indexed);
        println!("  status: {}", object.status);
        println!("  fresh: {}", object.fresh);
        println!("  freshness_state: {}", object.freshness_state.as_str());
        println!(
            "  serve_stale_while_revalidate: {}",
            object.serve_stale_while_revalidate
        );
        println!("  serve_stale_if_error: {}", object.serve_stale_if_error);
        println!("  body_bytes: {}", object.body_bytes);
        println!("  weight_bytes: {}", object.weight_bytes);
        print_optional_unix("  created_unix_secs", object.created_unix_secs);
        print_optional_unix("  updated_unix_secs", object.updated_unix_secs);
        print_optional_unix("  fresh_until_unix_secs", object.fresh_until_unix_secs);
        println!("  age_secs: {}", object.age_secs);
        println!("  fresh_ttl_secs: {}", object.fresh_ttl_secs);
        println!(
            "  stale_while_revalidate_secs: {}",
            object.stale_while_revalidate_secs
        );
        println!("  stale_if_error_secs: {}", object.stale_if_error_secs);
        println!("  cache_tags: {}", object.cache_tags.join(","));
        println!("  header_names: {}", object.header_names.join(","));
    }

    Ok(())
}

#[cfg(all(feature = "cache", feature = "proxy"))]
fn parse_cache_lookup_freshness_states(
    states: &[String],
) -> Result<Vec<fluxheim_cache::CacheObjectFreshnessState>, Box<dyn Error + Send + Sync>> {
    states
        .iter()
        .map(|state| match state.trim().to_ascii_lowercase().as_str() {
            "fresh" => Ok(fluxheim_cache::CacheObjectFreshnessState::Fresh),
            "stale" => Ok(fluxheim_cache::CacheObjectFreshnessState::Stale),
            "expired" => Ok(fluxheim_cache::CacheObjectFreshnessState::Expired),
            other => Err(format!(
                "cache-lookup --expect-freshness-state must be fresh, stale, or expired; got {other:?}"
            )
            .into()),
        })
        .collect()
}

#[cfg(all(feature = "cache", feature = "proxy"))]
fn parse_cache_lookup_tiers(
    tiers: &[String],
) -> Result<Vec<fluxheim_cache::CacheObjectTier>, Box<dyn Error + Send + Sync>> {
    tiers
        .iter()
        .map(|tier| match tier.trim().to_ascii_lowercase().as_str() {
            "memory" => Ok(fluxheim_cache::CacheObjectTier::Memory),
            "disk" => Ok(fluxheim_cache::CacheObjectTier::Disk),
            other => Err(format!(
                "cache-lookup --expect-tier must be memory or disk; got {other:?}"
            )
            .into()),
        })
        .collect()
}

#[cfg(all(feature = "cache", feature = "proxy"))]
fn parse_cache_lookup_header_names(
    names: &[String],
) -> Result<Vec<String>, Box<dyn Error + Send + Sync>> {
    if names.len() > 32 {
        return Err("cache-lookup accepts at most 32 --expect-header-name values".into());
    }

    names
        .iter()
        .map(|name| {
            let name = name.trim();
            if name.is_empty() || name.len() > 64 || !fluxheim_protocol::http_token_valid(name) {
                return Err(format!(
                    "cache-lookup --expect-header-name must be a valid HTTP header name, got {name:?}"
                )
                .into());
            }
            Ok(name.to_ascii_lowercase())
        })
        .collect()
}

#[cfg(all(feature = "cache", feature = "proxy"))]
fn parse_cache_lookup_headers(
    headers: &[String],
) -> Result<Vec<(String, String)>, Box<dyn Error + Send + Sync>> {
    if headers.len() > 32 {
        return Err("cache-lookup accepts at most 32 --expect-header values".into());
    }
    headers
        .iter()
        .map(|header| parse_cache_lookup_header(header))
        .collect()
}

#[cfg(all(feature = "cache", feature = "proxy"))]
fn parse_cache_lookup_header(
    header: &str,
) -> Result<(String, String), Box<dyn Error + Send + Sync>> {
    if header.len() > 8192 {
        return Err("cache-lookup --expect-header must be at most 8192 bytes".into());
    }
    let (name, value) = header
        .split_once(':')
        .ok_or("cache-lookup --expect-header must use \"Name: value\" syntax")?;
    let name = name.trim();
    if name.is_empty() || name.len() > 64 || !fluxheim_protocol::http_token_valid(name) {
        return Err("cache-lookup --expect-header name must be a valid HTTP header name".into());
    }
    let value = value.trim();
    if value.len() > 8192 {
        return Err("cache-lookup --expect-header value must be at most 8192 bytes".into());
    }
    if value.bytes().any(|byte| byte.is_ascii_control()) {
        return Err("cache-lookup --expect-header value must not contain control bytes".into());
    }
    Ok((name.to_ascii_lowercase(), value.to_owned()))
}

#[cfg(all(feature = "cache", feature = "proxy"))]
fn parse_cache_lookup_cache_tags(
    tags: &[String],
) -> Result<Vec<String>, Box<dyn Error + Send + Sync>> {
    if tags.len() > 32 {
        return Err("cache-lookup accepts at most 32 --expect-cache-tag values".into());
    }

    tags.iter()
        .map(|tag| {
            let tag = tag.trim();
            if !is_cache_lookup_tag(tag) {
                return Err(format!(
                    "cache-lookup --expect-cache-tag must be a valid cache tag, got {tag:?}"
                )
                .into());
            }
            Ok(tag.to_owned())
        })
        .collect()
}

#[cfg(all(feature = "cache", feature = "proxy"))]
fn is_cache_lookup_tag(tag: &str) -> bool {
    !tag.is_empty()
        && tag.len() <= 128
        && tag.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':' | b'/' | b'=')
        })
}

#[cfg(all(feature = "cache", feature = "proxy"))]
#[derive(Clone, Copy)]
struct CacheLookupExpectations<'a> {
    require_object: bool,
    expected_states: &'a [fluxheim_cache::CacheObjectFreshnessState],
    expected_statuses: &'a [u16],
    expected_tiers: &'a [fluxheim_cache::CacheObjectTier],
    expected_fresh_ttl_secs: &'a [u64],
    expected_body_bytes: &'a [u64],
    expected_header_names: &'a [String],
    expected_headers: &'a [(String, String)],
    expected_cache_tags: &'a [String],
    expected_objects: Option<usize>,
    expect_purge_indexed: bool,
    expect_ineligible: bool,
    expected_reason: Option<&'a str>,
    expect_cache_lock_enabled: bool,
    expected_cache_lock_wait_timeout_secs: Option<u64>,
    expect_cache_predictor_enabled: bool,
    expect_origin_protection_enabled: bool,
    expected_origin_protection_max_concurrent_fills: Option<usize>,
    expect_peer_fill_enabled: bool,
    expected_peer_fill_peers: Option<usize>,
    expected_peer_fill_max_concurrent_requests: Option<usize>,
    expect_memory_tier_enabled: bool,
    expect_disk_tier_enabled: bool,
    expect_storage_tiers: Option<u8>,
    expected_scope: Option<&'a str>,
    expected_vhost: Option<&'a str>,
    expected_route: Option<&'a str>,
    expected_namespace: Option<&'a str>,
    expected_key_namespace: Option<&'a str>,
    expected_user_tag: Option<&'a str>,
    expect_serve_stale_if_error: bool,
    expect_serve_stale_while_revalidate: bool,
}

#[cfg(all(feature = "cache", feature = "proxy"))]
fn validate_cache_lookup_expectations(
    lookup: &fluxheim_cache::CacheObjectLookup,
    expectations: &CacheLookupExpectations<'_>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let CacheLookupExpectations {
        require_object,
        expected_states,
        expected_statuses,
        expected_tiers,
        expected_fresh_ttl_secs,
        expected_body_bytes,
        expected_header_names,
        expected_headers,
        expected_cache_tags,
        expected_objects,
        expect_purge_indexed,
        expect_ineligible,
        expected_reason,
        expect_cache_lock_enabled,
        expected_cache_lock_wait_timeout_secs,
        expect_cache_predictor_enabled,
        expect_origin_protection_enabled,
        expected_origin_protection_max_concurrent_fills,
        expect_peer_fill_enabled,
        expected_peer_fill_peers,
        expected_peer_fill_max_concurrent_requests,
        expect_memory_tier_enabled,
        expect_disk_tier_enabled,
        expect_storage_tiers,
        expected_scope,
        expected_vhost,
        expected_route,
        expected_namespace,
        expected_key_namespace,
        expected_user_tag,
        expect_serve_stale_if_error,
        expect_serve_stale_while_revalidate,
    } = expectations;

    validate_cache_key_preview_expectations(
        &lookup.preview,
        CacheKeyPreviewExpectations {
            expect_eligible: false,
            expect_ineligible: *expect_ineligible,
            expected_reason: *expected_reason,
            expect_cache_lock_enabled: *expect_cache_lock_enabled,
            expected_cache_lock_wait_timeout_secs: *expected_cache_lock_wait_timeout_secs,
            expect_cache_predictor_enabled: *expect_cache_predictor_enabled,
            expect_origin_protection_enabled: *expect_origin_protection_enabled,
            expected_origin_protection_max_concurrent_fills:
                *expected_origin_protection_max_concurrent_fills,
            expect_peer_fill_enabled: *expect_peer_fill_enabled,
            expected_peer_fill_peers: *expected_peer_fill_peers,
            expected_peer_fill_max_concurrent_requests: *expected_peer_fill_max_concurrent_requests,
            expect_memory_tier_enabled: *expect_memory_tier_enabled,
            expect_disk_tier_enabled: *expect_disk_tier_enabled,
            expect_storage_tiers: *expect_storage_tiers,
            expected_scope: *expected_scope,
            expected_vhost: *expected_vhost,
            expected_route: *expected_route,
            expected_namespace: *expected_namespace,
            expected_key_namespace: *expected_key_namespace,
            expected_user_tag: *expected_user_tag,
        },
    )
    .map_err(|error| {
        Box::<dyn Error + Send + Sync>::from(error.to_string().replacen(
            "cache-key expected",
            "cache-lookup expected",
            1,
        ))
    })?;

    if *require_object && lookup.objects.is_empty() {
        return Err("cache-lookup expected at least one cached object, found none".into());
    }
    if let Some(expected_objects) = expected_objects
        && lookup.objects.len() != *expected_objects
    {
        return Err(format!(
            "cache-lookup expected {expected_objects} cached objects, found {}",
            lookup.objects.len()
        )
        .into());
    }
    if !expected_states.is_empty() {
        let matched = lookup
            .objects
            .iter()
            .any(|object| expected_states.contains(&object.freshness_state));
        if !matched {
            let expected = expected_states
                .iter()
                .map(|state| state.as_str())
                .collect::<Vec<_>>()
                .join(",");
            let found = if lookup.objects.is_empty() {
                "none".to_owned()
            } else {
                lookup
                    .objects
                    .iter()
                    .map(|object| object.freshness_state.as_str())
                    .collect::<Vec<_>>()
                    .join(",")
            };
            return Err(
                format!("cache-lookup expected freshness state {expected}, found {found}").into(),
            );
        }
    }
    if !expected_statuses.is_empty() {
        let matched = lookup
            .objects
            .iter()
            .any(|object| expected_statuses.contains(&object.status));
        if !matched {
            let expected = expected_statuses
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(",");
            let found = if lookup.objects.is_empty() {
                "none".to_owned()
            } else {
                lookup
                    .objects
                    .iter()
                    .map(|object| object.status.to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            };
            return Err(format!("cache-lookup expected status {expected}, found {found}").into());
        }
    }
    if !expected_tiers.is_empty() {
        let matched = lookup
            .objects
            .iter()
            .any(|object| expected_tiers.contains(&object.tier));
        if !matched {
            let expected = expected_tiers
                .iter()
                .map(|tier| tier.as_str())
                .collect::<Vec<_>>()
                .join(",");
            let found = if lookup.objects.is_empty() {
                "none".to_owned()
            } else {
                lookup
                    .objects
                    .iter()
                    .map(|object| object.tier.as_str())
                    .collect::<Vec<_>>()
                    .join(",")
            };
            return Err(format!("cache-lookup expected tier {expected}, found {found}").into());
        }
    }
    if !expected_fresh_ttl_secs.is_empty() {
        let matched = lookup
            .objects
            .iter()
            .any(|object| expected_fresh_ttl_secs.contains(&object.fresh_ttl_secs));
        if !matched {
            let expected = expected_fresh_ttl_secs
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(",");
            let found = fluxheim_cache::cache_object_lookup_fresh_ttl_summary(lookup);
            return Err(format!(
                "cache-lookup expected fresh TTL seconds {expected}, found {found}"
            )
            .into());
        }
    }
    if !expected_body_bytes.is_empty() {
        let matched = lookup
            .objects
            .iter()
            .any(|object| expected_body_bytes.contains(&object.body_bytes));
        if !matched {
            let expected = expected_body_bytes
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(",");
            let found = fluxheim_cache::cache_object_lookup_body_bytes_summary(lookup);
            return Err(
                format!("cache-lookup expected body bytes {expected}, found {found}").into(),
            );
        }
    }
    for expected in *expected_header_names {
        let matched = lookup.objects.iter().any(|object| {
            object
                .header_names
                .iter()
                .any(|header| header.eq_ignore_ascii_case(expected))
        });
        if !matched {
            let found = fluxheim_cache::cache_object_lookup_header_names_summary(lookup);
            return Err(format!(
                "cache-lookup expected stored header name {expected}, found {found}"
            )
            .into());
        }
    }
    for (expected_name, expected_value) in *expected_headers {
        let matched = lookup.objects.iter().any(|object| {
            object.header_values.iter().any(|header| {
                header.name.eq_ignore_ascii_case(expected_name) && header.value == *expected_value
            })
        });
        if !matched {
            let found =
                fluxheim_cache::cache_object_lookup_header_values_summary(lookup, expected_name);
            return Err(format!(
                "cache-lookup expected stored header {expected_name}: {expected_value}, found {found}"
            )
            .into());
        }
    }
    for expected in *expected_cache_tags {
        let matched = lookup.objects.iter().any(|object| {
            object
                .cache_tags
                .iter()
                .any(|cache_tag| cache_tag == expected)
        });
        if !matched {
            let found = fluxheim_cache::cache_object_lookup_cache_tags_summary(lookup);
            return Err(
                format!("cache-lookup expected cache tag {expected}, found {found}").into(),
            );
        }
    }
    if *expect_purge_indexed && !lookup.objects.iter().any(|object| object.purge_indexed) {
        return Err("cache-lookup expected at least one purge-indexed object, found none".into());
    }
    if *expect_serve_stale_if_error
        && !lookup
            .objects
            .iter()
            .any(|object| object.serve_stale_if_error)
    {
        let found = fluxheim_cache::cache_object_lookup_bool_summary(lookup, |object| {
            object.serve_stale_if_error
        });
        return Err(
            format!("cache-lookup expected stale-if-error eligible object, found {found}").into(),
        );
    }
    if *expect_serve_stale_while_revalidate
        && !lookup
            .objects
            .iter()
            .any(|object| object.serve_stale_while_revalidate)
    {
        let found = fluxheim_cache::cache_object_lookup_bool_summary(lookup, |object| {
            object.serve_stale_while_revalidate
        });
        return Err(format!(
            "cache-lookup expected stale-while-revalidate eligible object, found {found}"
        )
        .into());
    }
    Ok(())
}

#[cfg(all(feature = "cache", feature = "proxy"))]
fn validate_cache_lookup_expected_statuses(
    statuses: &[u16],
) -> Result<(), Box<dyn Error + Send + Sync>> {
    for status in statuses {
        if !(100..=599).contains(status) {
            return Err(format!(
                "cache-lookup --expect-status must be an HTTP status code, got {status}"
            )
            .into());
        }
    }
    Ok(())
}

#[cfg(all(feature = "cache", feature = "proxy"))]
fn validate_cache_lookup_expected_fresh_ttls(
    ttls: &[u64],
) -> Result<(), Box<dyn Error + Send + Sync>> {
    if ttls.len() > 32 {
        return Err("cache-lookup accepts at most 32 --expect-fresh-ttl-secs values".into());
    }
    Ok(())
}

#[cfg(all(feature = "cache", feature = "proxy"))]
fn validate_cache_lookup_expected_body_bytes(
    sizes: &[u64],
) -> Result<(), Box<dyn Error + Send + Sync>> {
    if sizes.len() > 32 {
        return Err("cache-lookup accepts at most 32 --expect-body-bytes values".into());
    }
    Ok(())
}

#[cfg(all(feature = "cache", feature = "proxy"))]
fn validate_cache_lookup_expected_objects(
    objects: Option<usize>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    if let Some(objects) = objects
        && objects > 2
    {
        return Err(
            format!("cache-lookup --expect-objects must be 0, 1, or 2; got {objects}").into(),
        );
    }
    Ok(())
}

#[cfg(all(feature = "cache", feature = "proxy"))]
fn validate_cache_lookup_expected_storage_tiers(
    storage_tiers: Option<u8>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    if let Some(storage_tiers) = storage_tiers
        && storage_tiers > 2
    {
        return Err(format!(
            "cache-lookup --expect-storage-tiers must be 0, 1, or 2; got {storage_tiers}"
        )
        .into());
    }
    Ok(())
}

#[cfg(all(feature = "cache", feature = "proxy"))]
fn parse_cache_key_preview_scope(
    command: &str,
    scope: Option<&String>,
) -> Result<Option<String>, Box<dyn Error + Send + Sync>> {
    let Some(scope) = scope else {
        return Ok(None);
    };
    match scope.trim().to_ascii_lowercase().as_str() {
        "vhost" => Ok(Some("vhost".to_owned())),
        "route" => Ok(Some("route".to_owned())),
        other => {
            Err(format!("{command} --expect-scope must be vhost or route; got {other:?}").into())
        }
    }
}

#[cfg(all(feature = "cache", feature = "proxy"))]
fn parse_cache_key_preview_name(
    command: &str,
    flag: &str,
    name: Option<&String>,
) -> Result<Option<String>, Box<dyn Error + Send + Sync>> {
    let Some(name) = name else {
        return Ok(None);
    };
    let name = name.trim();
    if name.is_empty() || name.len() > 128 || name.chars().any(char::is_control) {
        return Err(format!("{command} {flag} must be a non-empty name").into());
    }
    Ok(Some(name.to_owned()))
}

#[cfg(all(feature = "cache", feature = "proxy"))]
fn parse_cache_key_preview_reason(
    command: &str,
    flag: &str,
    reason: Option<&String>,
) -> Result<Option<String>, Box<dyn Error + Send + Sync>> {
    let Some(reason) = reason else {
        return Ok(None);
    };
    let reason = reason.trim();
    if reason.is_empty() || reason.len() > 256 || reason.chars().any(char::is_control) {
        return Err(format!("{command} {flag} must be a non-empty bounded reason").into());
    }
    Ok(Some(reason.to_owned()))
}

#[cfg(all(feature = "cache", feature = "proxy"))]
fn parse_cache_key_preview_value(
    command: &str,
    flag: &str,
    value: Option<&String>,
) -> Result<Option<String>, Box<dyn Error + Send + Sync>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value.trim();
    if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
        return Err(format!("{command} {flag} must be a non-empty bounded value").into());
    }
    Ok(Some(value.to_owned()))
}

#[cfg(all(feature = "cache", feature = "proxy"))]
fn parse_cache_key_preview_route(
    command: &str,
    route: Option<&String>,
) -> Result<Option<String>, Box<dyn Error + Send + Sync>> {
    parse_cache_key_preview_name(command, "--expect-route", route)
}

#[cfg(not(all(feature = "cache", feature = "proxy")))]
fn run_cache_key_command(options: CacheKeyOptions<'_>) -> Result<(), Box<dyn Error + Send + Sync>> {
    let CacheKeyOptions {
        config_path,
        host,
        headers,
        method,
        path,
        query,
        expect_eligible,
        expect_ineligible,
        expect_reason,
        expect_cache_lock_enabled,
        expect_cache_lock_wait_timeout_secs,
        expect_cache_predictor_enabled,
        expect_origin_protection_enabled,
        expect_origin_protection_max_concurrent_fills,
        expect_memory_tier_enabled,
        expect_disk_tier_enabled,
        expect_storage_tiers,
        expect_scope,
        expect_vhost,
        expect_route,
        expect_namespace,
        expect_key_namespace,
        expect_user_tag,
        expect_peer_fill_enabled,
        expect_peer_fill_peers,
        expect_peer_fill_max_concurrent_requests,
    } = options;
    let _ = (
        config_path,
        host,
        headers,
        method,
        path,
        query,
        expect_eligible,
        expect_ineligible,
        expect_reason,
        expect_cache_lock_enabled,
        expect_cache_lock_wait_timeout_secs,
        expect_cache_predictor_enabled,
        expect_origin_protection_enabled,
        expect_origin_protection_max_concurrent_fills,
        expect_memory_tier_enabled,
        expect_disk_tier_enabled,
        expect_storage_tiers,
        expect_scope,
        expect_vhost,
        expect_route,
        expect_namespace,
        expect_key_namespace,
        expect_user_tag,
        expect_peer_fill_enabled,
        expect_peer_fill_peers,
        expect_peer_fill_max_concurrent_requests,
    );
    Err("cache-key requires the proxy and cache features".into())
}

#[cfg(not(all(feature = "cache", feature = "proxy")))]
fn run_cache_lookup_command(
    options: CacheLookupOptions<'_>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let CacheLookupOptions {
        config_path,
        host,
        headers,
        method,
        path,
        query,
        require_object,
        expect_objects,
        expect_ineligible,
        expect_reason,
        expect_freshness_states,
        expect_statuses,
        expect_tiers,
        expect_fresh_ttl_secs,
        expect_body_bytes,
        expect_header_names,
        expect_headers,
        expect_cache_tags,
        expect_purge_indexed,
        expect_cache_lock_enabled,
        expect_cache_lock_wait_timeout_secs,
        expect_cache_predictor_enabled,
        expect_origin_protection_enabled,
        expect_origin_protection_max_concurrent_fills,
        expect_memory_tier_enabled,
        expect_disk_tier_enabled,
        expect_storage_tiers,
        expect_scope,
        expect_vhost,
        expect_route,
        expect_namespace,
        expect_key_namespace,
        expect_user_tag,
        expect_serve_stale_if_error,
        expect_serve_stale_while_revalidate,
        expect_peer_fill_enabled,
        expect_peer_fill_peers,
        expect_peer_fill_max_concurrent_requests,
    } = options;
    let _ = (config_path, host, headers, method, path, query);
    let _ = (
        require_object,
        expect_objects,
        expect_ineligible,
        expect_reason,
        expect_freshness_states,
        expect_statuses,
        expect_tiers,
        expect_fresh_ttl_secs,
        expect_body_bytes,
        expect_header_names,
        expect_headers,
        expect_cache_tags,
        expect_purge_indexed,
        expect_cache_lock_enabled,
        expect_cache_lock_wait_timeout_secs,
        expect_cache_predictor_enabled,
        expect_origin_protection_enabled,
        expect_origin_protection_max_concurrent_fills,
        expect_memory_tier_enabled,
        expect_disk_tier_enabled,
        expect_storage_tiers,
        expect_scope,
        expect_vhost,
        expect_route,
        expect_namespace,
        expect_key_namespace,
        expect_user_tag,
        expect_serve_stale_if_error,
        expect_serve_stale_while_revalidate,
        expect_peer_fill_enabled,
        expect_peer_fill_peers,
        expect_peer_fill_max_concurrent_requests,
    );
    Err("cache-lookup requires the proxy and cache features".into())
}

#[cfg(all(feature = "cache", feature = "proxy"))]
fn cache_key_command_request(
    options: &CacheKeyOptions<'_>,
) -> Result<(Config, NativeCachePreviewRequest), Box<dyn Error + Send + Sync>> {
    let config = Config::load(options.config_path)?;
    config.validate()?;

    let host = match options.host.as_deref() {
        Some(host) => {
            validate_cache_warm_host(host)?;
            host.to_owned()
        }
        None => cache_warm_default_host(&config)
            .ok_or("cache-key requires --host when no default vhost host is configured")?,
    };
    let uri = cache_key_uri(&options.path, options.query.as_deref())?;
    validate_cache_key_method(&options.method)?;

    let mut request =
        NativeCachePreviewRequest::build(options.method.as_str(), uri.as_bytes(), None)?;
    request.insert_header("host", host.as_str())?;
    if options.headers.len() > 32 {
        return Err("cache-key accepts at most 32 --header values".into());
    }
    for (name, value) in parse_cache_cli_headers("cache-key", &options.headers)? {
        request.insert_header(name, value)?;
    }
    Ok((config, request))
}

#[cfg(all(feature = "cache", feature = "proxy"))]
fn print_optional_unix(label: &str, value: Option<u64>) {
    match value {
        Some(value) => println!("{label}: {value}"),
        None => println!("{label}: unavailable"),
    }
}

#[cfg(all(feature = "cache", feature = "proxy"))]
fn cache_key_uri(path: &str, query: Option<&str>) -> Result<String, Box<dyn Error + Send + Sync>> {
    validate_cache_warm_path(path)?;
    if path.contains('?') && query.is_some() {
        return Err("cache-key accepts query in either --path or --query, not both".into());
    }
    let Some(query) = query else {
        return Ok(path.to_owned());
    };
    validate_cache_key_query(query)?;
    Ok(format!("{path}?{query}"))
}

#[cfg(all(feature = "cache", feature = "proxy"))]
fn validate_cache_key_method(method: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
    if method.is_empty() || method.len() > 32 {
        return Err("method must be 1-32 bytes".into());
    }
    if method
        .bytes()
        .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err("method contains control or whitespace bytes".into());
    }
    Ok(())
}

#[cfg(all(feature = "cache", feature = "proxy"))]
fn validate_cache_key_query(query: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
    if query.len() > 8192 {
        return Err("query must be at most 8192 bytes".into());
    }
    if query
        .bytes()
        .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err("query contains control or whitespace bytes".into());
    }
    if query.starts_with('?') || query.contains('#') {
        return Err("query must not start with ? or contain #".into());
    }
    Ok(())
}

#[cfg(feature = "cache")]
fn parse_cache_cli_headers(
    command: &str,
    headers: &[String],
) -> Result<Vec<(String, String)>, Box<dyn Error + Send + Sync>> {
    if headers.len() > 32 {
        return Err(format!("{command} accepts at most 32 --header values").into());
    }
    headers
        .iter()
        .map(|header| parse_cache_cli_header(command, header))
        .collect()
}

#[cfg(feature = "cache")]
fn parse_cache_cli_header(
    command: &str,
    header: &str,
) -> Result<(String, String), Box<dyn Error + Send + Sync>> {
    if header.len() > 8192 {
        return Err(format!("{command} --header must be at most 8192 bytes").into());
    }
    let (name, value) = header
        .split_once(':')
        .ok_or_else(|| format!("{command} --header must use \"Name: value\" syntax"))?;
    let name = name.trim();
    if name.is_empty() || name.len() > 64 || !fluxheim_protocol::http_token_valid(name) {
        return Err(format!("{command} --header name must be a valid HTTP header name").into());
    }
    let normalized_name = name.to_ascii_lowercase();
    if matches!(
        normalized_name.as_str(),
        "host" | "connection" | "content-length" | "transfer-encoding"
    ) {
        return Err(format!(
            "{command} --header cannot set {name}; use explicit options or built-in request framing"
        )
        .into());
    }
    let value = value.trim();
    if value.len() > 8192 {
        return Err(format!("{command} --header value must be at most 8192 bytes").into());
    }
    if value.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(format!("{command} --header value must not contain control bytes").into());
    }
    Ok((normalized_name, value.to_owned()))
}

#[cfg(feature = "cache")]
#[derive(Debug, Clone, Eq, PartialEq)]
struct CacheWarmResult {
    status: u16,
    bytes_read: u64,
    cache_status: Option<String>,
}

#[cfg(feature = "cache")]
fn cache_warm_listen_addr(
    config: &Config,
    listen: Option<&str>,
) -> Result<std::net::SocketAddr, Box<dyn Error + Send + Sync>> {
    let candidate = listen
        .or_else(|| config.server.listen.first().map(String::as_str))
        .ok_or("cache-warm requires a server.listen address or --listen")?;
    let mut address: std::net::SocketAddr = candidate.parse()?;
    address.set_ip(match address.ip() {
        std::net::IpAddr::V4(ip) if ip.is_unspecified() => {
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        }
        std::net::IpAddr::V6(ip) if ip.is_unspecified() => {
            std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
        }
        ip => ip,
    });
    Ok(address)
}

#[cfg(feature = "cache")]
fn cache_warm_default_host(config: &Config) -> Option<String> {
    config
        .server
        .default_vhost
        .as_deref()
        .and_then(|name| config.vhosts.iter().find(|vhost| vhost.name == name))
        .and_then(|vhost| vhost.hosts.first())
        .cloned()
        .or_else(|| {
            config
                .vhosts
                .iter()
                .find_map(|vhost| vhost.hosts.first().cloned())
        })
}

#[cfg(feature = "cache")]
fn cache_warm_targets(
    default_host: Option<&str>,
    paths: &[String],
    input: Option<&std::path::Path>,
    max_targets: usize,
) -> Result<Vec<CacheWarmTarget>, Box<dyn Error + Send + Sync>> {
    let mut targets = Vec::new();
    for path in paths {
        let host = default_host.ok_or("cache-warm --host is required when warming --path")?;
        targets.push(cache_warm_target(host, path)?);
    }

    if let Some(input) = input {
        let content = read_cache_warm_input(input)?;
        for (line_number, line) in content.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let target = cache_warm_target_from_line(default_host, line).map_err(|error| {
                format!(
                    "invalid cache-warm input at {}:{}: {error}",
                    input.display(),
                    line_number + 1
                )
            })?;
            targets.push(target);
        }
    }

    if targets.is_empty() {
        return Err("cache-warm requires at least one --path or --input target".into());
    }
    if targets.len() > max_targets {
        return Err(format!(
            "cache-warm target count {} exceeds --max-targets {}",
            targets.len(),
            max_targets
        )
        .into());
    }
    Ok(targets)
}

#[cfg(feature = "cache")]
fn read_cache_warm_input(input: &std::path::Path) -> Result<String, Box<dyn Error + Send + Sync>> {
    let file = std::fs::File::open(input)?;
    let mut content = String::new();
    file.take((CACHE_WARM_INPUT_MAX_BYTES as u64) + 1)
        .read_to_string(&mut content)?;
    if content.len() > CACHE_WARM_INPUT_MAX_BYTES {
        return Err(format!(
            "cache-warm input file must be at most {} bytes",
            CACHE_WARM_INPUT_MAX_BYTES
        )
        .into());
    }
    Ok(content)
}

#[cfg(feature = "cache")]
fn cache_warm_target_from_line(
    default_host: Option<&str>,
    line: &str,
) -> Result<CacheWarmTarget, Box<dyn Error + Send + Sync>> {
    if line.starts_with('/') {
        let host = default_host.ok_or("host is required for path-only input lines")?;
        return cache_warm_target(host, line);
    }

    let mut parts = line.split_whitespace();
    let host = parts.next().ok_or("missing host")?;
    let path = parts.next().ok_or("missing path")?;
    if parts.next().is_some() {
        return Err("expected either /path or host /path".into());
    }
    cache_warm_target(host, path)
}

#[cfg(feature = "cache")]
fn cache_warm_target(
    host: &str,
    path: &str,
) -> Result<CacheWarmTarget, Box<dyn Error + Send + Sync>> {
    validate_cache_warm_host(host)?;
    validate_cache_warm_path(path)?;
    Ok(CacheWarmTarget {
        host: host.to_owned(),
        path: path.to_owned(),
    })
}

#[cfg(feature = "cache")]
fn validate_cache_warm_host(host: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
    if host.is_empty() || host.len() > 253 {
        return Err("host must be 1-253 bytes".into());
    }
    if host.bytes().any(|byte| {
        byte.is_ascii_control()
            || byte.is_ascii_whitespace()
            || matches!(byte, b'/' | b'\\' | b'?' | b'#')
    }) {
        return Err("host contains characters that cannot be used in an HTTP Host header".into());
    }
    Ok(())
}

#[cfg(feature = "cache")]
fn validate_cache_warm_path(path: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
    if !path.starts_with('/') {
        return Err("path must start with /".into());
    }
    if path.len() > 8192 {
        return Err("path must be at most 8192 bytes".into());
    }
    if path
        .bytes()
        .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err("path contains control or whitespace bytes".into());
    }
    Ok(())
}

#[cfg(feature = "cache")]
fn validate_cache_warm_allow_statuses(
    statuses: &[u16],
) -> Result<(), Box<dyn Error + Send + Sync>> {
    for status in statuses {
        if !(100..=599).contains(status) {
            return Err(format!(
                "cache-warm --allow-status must be an HTTP status code, got {status}"
            )
            .into());
        }
    }
    Ok(())
}

#[cfg(feature = "cache")]
fn validate_cache_warm_header_name(name: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
    if name.is_empty() || name.len() > 64 {
        return Err("cache-warm --cache-status-header must be 1-64 bytes".into());
    }
    if !fluxheim_protocol::http_token_valid(name) {
        return Err("cache-warm --cache-status-header must be a valid HTTP header name".into());
    }
    Ok(())
}

#[cfg(feature = "cache")]
fn validate_cache_warm_expected_statuses(
    statuses: &[String],
) -> Result<(), Box<dyn Error + Send + Sync>> {
    if statuses.len() > 16 {
        return Err("cache-warm accepts at most 16 --expect-cache-status values".into());
    }
    for status in statuses {
        if status.is_empty() || status.len() > 64 {
            return Err("cache-warm --expect-cache-status values must be 1-64 bytes".into());
        }
        if status
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        {
            return Err(
                "cache-warm --expect-cache-status values must not contain control or whitespace bytes"
                    .into(),
            );
        }
    }
    Ok(())
}

#[cfg(feature = "cache")]
fn validate_cache_warm_expected_sequence(
    allowed_statuses: &[String],
    sequence: &[String],
    repeat: usize,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    if !allowed_statuses.is_empty() && !sequence.is_empty() {
        return Err(
            "cache-warm cannot combine --expect-cache-status and --expect-cache-status-sequence"
                .into(),
        );
    }
    validate_cache_warm_expected_statuses(sequence)?;
    if !sequence.is_empty() && sequence.len() != repeat {
        return Err("cache-warm --expect-cache-status-sequence length must match --repeat".into());
    }
    Ok(())
}

#[cfg(feature = "cache")]
fn cache_warm_status_is_success(status: u16, allowed_extra: &[u16]) -> bool {
    (200..400).contains(&status) || allowed_extra.contains(&status)
}

#[cfg(feature = "cache")]
fn cache_warm_expected_statuses_for_attempt<'a>(
    allowed_statuses: &'a [String],
    sequence: &'a [String],
    attempt: usize,
) -> &'a [String] {
    if sequence.is_empty() {
        allowed_statuses
    } else {
        let index = attempt.saturating_sub(1);
        &sequence[index..=index]
    }
}

#[cfg(feature = "cache")]
fn cache_warm_expected_status_matches(
    actual: Option<&str>,
    expected: &[String],
) -> Result<(), String> {
    if expected.is_empty() {
        return Ok(());
    }
    let Some(actual) = actual else {
        return Err("missing expected cache status header".to_owned());
    };
    if expected
        .iter()
        .any(|expected| expected.eq_ignore_ascii_case(actual))
    {
        Ok(())
    } else {
        Err(format!("unexpected cache status {actual}"))
    }
}

#[cfg(feature = "cache")]
fn cache_warm_request(
    listen: &std::net::SocketAddr,
    target: &CacheWarmTarget,
    timeout: std::time::Duration,
    cache_status_header: &str,
    headers: &[(String, String)],
) -> Result<CacheWarmResult, Box<dyn Error + Send + Sync>> {
    let mut stream = std::net::TcpStream::connect_timeout(listen, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    write!(
        stream,
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: fluxheim-cache-warm/{}\r\nAccept: */*\r\n",
        target.path,
        target.host,
        env!("CARGO_PKG_VERSION")
    )?;
    for (name, value) in headers {
        write!(stream, "{name}: {value}\r\n")?;
    }
    write!(stream, "Connection: close\r\n\r\n")?;
    stream.flush()?;

    let mut bytes_read = 0_u64;
    let mut header_prefix = Vec::with_capacity(1024);
    let mut headers_complete = false;
    let mut buffer = [0_u8; 8192];
    loop {
        let read = stream.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        bytes_read = bytes_read.saturating_add(read as u64);
        if !headers_complete && header_prefix.len() < 64 * 1024 {
            let remaining = (64 * 1024) - header_prefix.len();
            header_prefix.extend_from_slice(&buffer[..read.min(remaining)]);
            headers_complete = header_prefix.windows(4).any(|window| window == b"\r\n\r\n");
        }
    }

    let status = cache_warm_status_from_prefix(&header_prefix)?;
    let cache_status = cache_warm_header_value_from_prefix(&header_prefix, cache_status_header)?;
    Ok(CacheWarmResult {
        status,
        bytes_read,
        cache_status,
    })
}

#[cfg(feature = "cache")]
fn cache_warm_status_from_prefix(prefix: &[u8]) -> Result<u16, Box<dyn Error + Send + Sync>> {
    let line_end = prefix
        .windows(2)
        .position(|window| window == b"\r\n")
        .ok_or("response did not include a complete HTTP status line")?;
    let status_line = std::str::from_utf8(&prefix[..line_end])?;
    let mut parts = status_line.split_whitespace();
    let protocol = parts.next().ok_or("missing HTTP protocol in status line")?;
    if !protocol.starts_with("HTTP/") {
        return Err("response status line does not start with HTTP/".into());
    }
    let status = parts
        .next()
        .ok_or("missing HTTP status code")?
        .parse::<u16>()?;
    Ok(status)
}

#[cfg(feature = "cache")]
fn cache_warm_header_value_from_prefix(
    prefix: &[u8],
    name: &str,
) -> Result<Option<String>, Box<dyn Error + Send + Sync>> {
    let Some(header_end) = prefix.windows(4).position(|window| window == b"\r\n\r\n") else {
        return Ok(None);
    };
    let headers = std::str::from_utf8(&prefix[..header_end])?;
    for line in headers.split("\r\n").skip(1) {
        let Some((candidate, value)) = line.split_once(':') else {
            continue;
        };
        if candidate.eq_ignore_ascii_case(name) {
            return Ok(Some(value.trim().to_owned()));
        }
    }
    Ok(None)
}

#[derive(Debug)]
struct AcmeInitOptions {
    issuer: AcmeInitIssuer,
    email: Option<String>,
    kid_file: Option<PathBuf>,
    hmac_key_file: Option<PathBuf>,
    non_interactive: bool,
    force: bool,
    no_systemd: bool,
    output: PathBuf,
    storage: PathBuf,
    secrets_dir: PathBuf,
    systemd_dropin_dir: PathBuf,
}

#[cfg(any(
    feature = "tls",
    feature = "tls-rustls-backend",
    feature = "tls-openssl"
))]
pub fn check_tls_storage(config: &Config) -> Result<(), Box<dyn Error + Send + Sync>> {
    let check = crate::tls::validate_tls_storage(config);
    if check.is_secure() {
        println!("TLS storage check passed");
        return Ok(());
    }

    for issue in &check.issues {
        eprintln!("TLS storage issue: {issue}");
    }

    Err(format!(
        "TLS storage check failed with {} issue(s)",
        check.issues.len()
    )
    .into())
}

#[cfg(not(any(
    feature = "tls",
    feature = "tls-rustls-backend",
    feature = "tls-openssl"
)))]
pub fn check_tls_storage(_config: &Config) -> Result<(), Box<dyn Error + Send + Sync>> {
    Err("TLS storage checks require a TLS feature".into())
}

#[cfg(all(
    test,
    any(
        feature = "tls",
        feature = "tls-rustls-backend",
        feature = "tls-openssl"
    )
))]
#[path = "cli_tests.rs"]
mod tests;
