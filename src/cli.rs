use std::error::Error;
use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

use crate::config::Config;

mod acme_init_commands;
mod acme_renew_commands;
#[cfg(feature = "cache")]
mod cache_common;
mod cache_key_command;
mod cache_lookup_command;
#[cfg(all(feature = "cache", feature = "proxy"))]
mod cache_lookup_expectations;
#[cfg(all(feature = "cache", feature = "proxy"))]
mod cache_lookup_parsing;
mod cache_warm_command;
mod cache_warm_support;
mod crypto_commands;
mod runtime_validation;
mod tls_storage_check;
use acme_init_commands::run_acme_init_command;
use acme_renew_commands::run_acme_renew_command;
use cache_key_command::run_cache_key_command;
use cache_lookup_command::run_cache_lookup_command;
use cache_warm_command::run_cache_warm_command;
pub use crypto_commands::print_crypto_diagnostics;
use crypto_commands::{run_cache_keygen_command, run_crypto_diagnostics_command};
pub use runtime_validation::{validate_compiled_module_config, validate_runtime_config};
pub use tls_storage_check::check_tls_storage;

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
