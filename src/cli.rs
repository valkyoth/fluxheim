use std::path::PathBuf;

use clap::{Parser, Subcommand};

mod acme_init_commands;
mod acme_init_issuer;
#[cfg(feature = "acme-client")]
mod acme_init_toml;
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
#[cfg(feature = "cache")]
mod cache_warm_support;
mod command_dispatch;
mod command_options;
mod crypto_commands;
mod entrypoint;
mod runtime_validation;
#[cfg(test)]
mod test_exports;
mod tls_storage_check;
pub use acme_init_issuer::AcmeInitIssuer;
pub use crypto_commands::print_crypto_diagnostics;
pub use entrypoint::{run_from_args, run_from_env};
pub use runtime_validation::{validate_compiled_module_config, validate_runtime_config};
#[cfg(test)]
#[allow(unused_imports)]
use test_exports::*;
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

        #[arg(long)]
        expect_serve_stale_while_revalidate: bool,
    },
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
