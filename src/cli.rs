use std::error::Error;
#[cfg(feature = "acme-client")]
use std::io::{self, Write};
#[cfg(feature = "cache")]
use std::io::{Read, Write as _};
#[cfg(feature = "acme-client")]
use std::path::Path;
use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

use crate::config::Config;

#[derive(Debug, Parser)]
#[command(version, about = "Fluxheim reverse proxy")]
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

        /// Required cached-object freshness state. May be repeated: fresh, stale, expired.
        #[arg(long = "expect-freshness-state", value_name = "STATE")]
        expect_freshness_states: Vec<String>,

        /// Required cached-object HTTP status. May be repeated.
        #[arg(long = "expect-status", value_name = "STATUS")]
        expect_statuses: Vec<u16>,

        /// Required cached-object storage tier. May be repeated: memory, disk.
        #[arg(long = "expect-tier", value_name = "TIER")]
        expect_tiers: Vec<String>,

        /// Required stored response header name. May be repeated.
        #[arg(long = "expect-header-name", value_name = "HEADER")]
        expect_header_names: Vec<String>,

        /// Require at least one matching cached object to be present in the purge index.
        #[arg(long)]
        expect_purge_indexed: bool,
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
    let cli = Cli::parse_from(args);

    if let Some(command) = &cli.command {
        return run_command(command, cli.config.as_deref());
    }

    if let Some(old_config_path) = cli.reload_from.as_deref() {
        let old_config = Config::load(Some(old_config_path))?;
        old_config.validate()?;
        let new_config = Config::load(cli.config.as_deref())?;
        new_config.validate()?;
        let impact = crate::reload::classify_reload(&old_config, &new_config);
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
            println!("action: use Pingora process upgrade");
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

#[cfg(feature = "proxy")]
fn validate_runtime_config(config: &Config) -> Result<(), Box<dyn Error + Send + Sync>> {
    crate::proxy::FluxProxy::from_config(config)?;
    Ok(())
}

#[cfg(all(feature = "web", not(feature = "proxy")))]
fn validate_runtime_config(config: &Config) -> Result<(), Box<dyn Error + Send + Sync>> {
    validate_web_runtime_config("global web", &config.web)?;
    for vhost in &config.vhosts {
        validate_web_runtime_config(&format!("vhost {:?} web", vhost.name), &vhost.web)?;
        for route in &vhost.routes {
            if let Some(web) = &route.web {
                validate_web_runtime_config(
                    &format!("vhost {:?} route {:?} web", vhost.name, route.name),
                    web,
                )?;
            }
        }
    }
    Ok(())
}

#[cfg(all(feature = "web", not(feature = "proxy")))]
fn validate_web_runtime_config(
    scope: &str,
    config: &crate::config::WebConfig,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    crate::web::StaticFileServer::from_config(config)
        .map_err(|error| format!("{scope}: {error}"))?;
    Ok(())
}

#[cfg(not(any(feature = "proxy", feature = "web")))]
fn validate_runtime_config(_config: &Config) -> Result<(), Box<dyn Error + Send + Sync>> {
    Ok(())
}

fn run_command(
    command: &CliCommand,
    config_path: Option<&std::path::Path>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    match command {
        CliCommand::Snapshot { store, message } => {
            let config = Config::load(config_path)?;
            let store = crate::snapshot::SnapshotStore::new(store);
            let snapshot = store.snapshot_config(&config, message.as_deref())?;
            println!("snapshot: {}", snapshot.id);
            println!("config: {}", snapshot.config_path.display());
            println!("current: {}", store.root().join("current").display());
            Ok(())
        }
        CliCommand::Rollback { store, to } => {
            let store = crate::snapshot::SnapshotStore::new(store);
            let snapshot = store.rollback_target(to.as_deref())?;
            println!("rollback target: {}", snapshot.id);
            println!("config: {}", snapshot.config_path.display());
            println!(
                "action: current pointer updated; reload classification is still required before live apply"
            );
            Ok(())
        }
        CliCommand::Snapshots { store } => {
            let store = crate::snapshot::SnapshotStore::new(store);
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
        } => run_cache_key_command(CacheKeyOptions {
            config_path,
            host: host.clone(),
            headers: headers.clone(),
            method: method.clone(),
            path: path.clone(),
            query: query.clone(),
        }),
        CliCommand::CacheLookup {
            host,
            headers,
            method,
            path,
            query,
            require_object,
            expect_freshness_states,
            expect_statuses,
            expect_tiers,
            expect_header_names,
            expect_purge_indexed,
        } => run_cache_lookup_command(CacheLookupOptions {
            config_path,
            host: host.clone(),
            headers: headers.clone(),
            method: method.clone(),
            path: path.clone(),
            query: query.clone(),
            require_object: *require_object,
            expect_freshness_states: expect_freshness_states.clone(),
            expect_statuses: expect_statuses.clone(),
            expect_tiers: expect_tiers.clone(),
            expect_header_names: expect_header_names.clone(),
            expect_purge_indexed: *expect_purge_indexed,
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
    expect_freshness_states: Vec<String>,
    expect_statuses: Vec<u16>,
    expect_tiers: Vec<String>,
    expect_header_names: Vec<String>,
    expect_purge_indexed: bool,
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
                    increment_cache_warm_count(&mut response_statuses, result.status);
                    let cache_status = cache_warm_safe_label(result.cache_status.as_deref());
                    increment_cache_warm_count(&mut cache_statuses, cache_status.clone());
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
                                increment_cache_warm_count(
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
                        increment_cache_warm_count(&mut failure_reasons, "unexpected_status");
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
                    increment_cache_warm_count(&mut failure_reasons, "request_error");
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
fn increment_cache_warm_count<K: Ord>(counts: &mut std::collections::BTreeMap<K, usize>, key: K) {
    let count = counts.entry(key).or_insert(0);
    *count = count.saturating_add(1);
}

#[cfg(feature = "cache")]
fn print_cache_warm_counts<K: std::fmt::Display>(
    label: &str,
    counts: &std::collections::BTreeMap<K, usize>,
) {
    if let Some(summary) = cache_warm_counts_summary(counts) {
        println!("{label}: {summary}");
    }
}

#[cfg(feature = "cache")]
fn cache_warm_counts_summary<K: std::fmt::Display>(
    counts: &std::collections::BTreeMap<K, usize>,
) -> Option<String> {
    if counts.is_empty() {
        return None;
    }

    Some(
        counts
            .iter()
            .map(|(key, count)| format!("{key}={count}"))
            .collect::<Vec<_>>()
            .join(" "),
    )
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
    let (config, request) = cache_key_command_request(&options)?;
    let proxy = crate::proxy::FluxProxy::from_config(&config)?;
    let preview = proxy
        .snapshot()
        .pingora_image_cache_key_preview_for_request_header(&request);

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
    println!("memory_tier_enabled: {}", preview.memory_tier_enabled);
    println!("disk_tier_enabled: {}", preview.disk_tier_enabled);
    println!("storage_tiers: {}", preview.storage_tiers);
    if let Some(reason) = preview.reason.as_deref() {
        println!("reason: {reason}");
    }
    if let Some(namespace) = preview.namespace.as_deref() {
        println!("namespace: {namespace}");
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
    };
    let require_object = options.require_object;
    let expected_states = parse_cache_lookup_freshness_states(&options.expect_freshness_states)?;
    let expected_tiers = parse_cache_lookup_tiers(&options.expect_tiers)?;
    let expected_header_names = parse_cache_lookup_header_names(&options.expect_header_names)?;
    validate_cache_lookup_expected_statuses(&options.expect_statuses)?;
    let (config, request) = cache_key_command_request(&cache_key_options)?;
    let proxy = crate::proxy::FluxProxy::from_config(&config)?;
    let lookup = proxy
        .snapshot()
        .pingora_image_cache_object_lookup_for_request_header(&request)?;
    validate_cache_lookup_expectations(
        &lookup,
        require_object,
        &expected_states,
        &options.expect_statuses,
        &expected_tiers,
        &expected_header_names,
        options.expect_purge_indexed,
    )?;

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
) -> Result<Vec<crate::cache::CacheObjectFreshnessState>, Box<dyn Error + Send + Sync>> {
    states
        .iter()
        .map(|state| match state.trim().to_ascii_lowercase().as_str() {
            "fresh" => Ok(crate::cache::CacheObjectFreshnessState::Fresh),
            "stale" => Ok(crate::cache::CacheObjectFreshnessState::Stale),
            "expired" => Ok(crate::cache::CacheObjectFreshnessState::Expired),
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
) -> Result<Vec<crate::cache::CacheObjectTier>, Box<dyn Error + Send + Sync>> {
    tiers
        .iter()
        .map(|tier| match tier.trim().to_ascii_lowercase().as_str() {
            "memory" => Ok(crate::cache::CacheObjectTier::Memory),
            "disk" => Ok(crate::cache::CacheObjectTier::Disk),
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
            if name.is_empty() || name.len() > 64 || !name.bytes().all(is_http_token_byte) {
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
fn validate_cache_lookup_expectations(
    lookup: &crate::proxy::CacheObjectLookup,
    require_object: bool,
    expected_states: &[crate::cache::CacheObjectFreshnessState],
    expected_statuses: &[u16],
    expected_tiers: &[crate::cache::CacheObjectTier],
    expected_header_names: &[String],
    expect_purge_indexed: bool,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    if require_object && lookup.objects.is_empty() {
        return Err("cache-lookup expected at least one cached object, found none".into());
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
    for expected in expected_header_names {
        let matched = lookup.objects.iter().any(|object| {
            object
                .header_names
                .iter()
                .any(|header| header.eq_ignore_ascii_case(expected))
        });
        if !matched {
            let found = cache_lookup_found_header_names(lookup);
            return Err(format!(
                "cache-lookup expected stored header name {expected}, found {found}"
            )
            .into());
        }
    }
    if expect_purge_indexed && !lookup.objects.iter().any(|object| object.purge_indexed) {
        return Err("cache-lookup expected at least one purge-indexed object, found none".into());
    }
    Ok(())
}

#[cfg(all(feature = "cache", feature = "proxy"))]
fn cache_lookup_found_header_names(lookup: &crate::proxy::CacheObjectLookup) -> String {
    let mut names = lookup
        .objects
        .iter()
        .flat_map(|object| object.header_names.iter().map(String::as_str))
        .collect::<Vec<_>>();
    if names.is_empty() {
        return "none".to_owned();
    }
    names.sort_unstable();
    names.dedup();
    names.join(",")
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

#[cfg(not(all(feature = "cache", feature = "proxy")))]
fn run_cache_key_command(options: CacheKeyOptions<'_>) -> Result<(), Box<dyn Error + Send + Sync>> {
    let CacheKeyOptions {
        config_path,
        host,
        headers,
        method,
        path,
        query,
    } = options;
    let _ = (config_path, host, headers, method, path, query);
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
        expect_freshness_states,
        expect_statuses,
        expect_tiers,
        expect_header_names,
        expect_purge_indexed,
    } = options;
    let _ = (config_path, host, headers, method, path, query);
    let _ = (
        require_object,
        expect_freshness_states,
        expect_statuses,
        expect_tiers,
        expect_header_names,
        expect_purge_indexed,
    );
    Err("cache-lookup requires the proxy and cache features".into())
}

#[cfg(all(feature = "cache", feature = "proxy"))]
fn cache_key_command_request(
    options: &CacheKeyOptions<'_>,
) -> Result<(Config, pingora::http::RequestHeader), Box<dyn Error + Send + Sync>> {
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
        pingora::http::RequestHeader::build(options.method.as_str(), uri.as_bytes(), None)?;
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
    if name.is_empty() || name.len() > 64 || !name.bytes().all(is_http_token_byte) {
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
    if !name.bytes().all(is_http_token_byte) {
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
fn cache_warm_safe_label(value: Option<&str>) -> String {
    let Some(value) = value else {
        return "-".to_owned();
    };
    if value.is_empty() || value.len() > 64 {
        return "other".to_owned();
    }
    if value
        .bytes()
        .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace() || byte == b'=')
    {
        return "other".to_owned();
    }
    value.to_owned()
}

#[cfg(feature = "cache")]
fn is_http_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
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

#[cfg(feature = "acme-client")]
fn run_acme_renew_command(
    config_path: Option<&std::path::Path>,
    force_renew: bool,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    crate::tls::install_rustls_crypto_provider();

    let config = Config::load(config_path)?;
    config.validate()?;
    validate_runtime_config(&config)?;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let now = std::time::SystemTime::now();
    let queue = if force_renew {
        crate::acme::plan_renewal_queue(&config, &[], now)
    } else {
        let observations = crate::acme::observe_configured_certificates(&config);
        crate::acme::plan_renewal_queue(&config, &observations, now)
    };
    println!("acme targets: {}", queue.len());
    for item in &queue {
        let target = &item.target;
        let status = if force_renew {
            "forced"
        } else if item.due_now {
            "due"
        } else {
            "skipped"
        };
        println!(
            "target: {} status={} issuer={} domains={} cert={} key={}",
            target.vhost_name,
            status,
            target.issuer,
            target.domains.join(","),
            target.certificate.cert_path.display(),
            target.certificate.key_path.display()
        );
    }
    if queue.is_empty() {
        println!(
            "acme state: tls_enabled={} acme_enabled={} renewal_enabled={} storage={} vhosts={}",
            config.tls.enabled,
            config.tls.acme.enabled,
            config.tls.acme.renewal.enabled,
            config
                .tls
                .acme
                .storage
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "<none>".to_owned()),
            config.vhosts.len()
        );
        for vhost in &config.vhosts {
            println!(
                "vhost-acme-state: {} tls_enabled={} acme_enabled={} hosts={}",
                vhost.name,
                vhost.tls.enabled,
                vhost.tls.acme.enabled,
                vhost.hosts.join(",")
            );
        }
    }

    let run = if force_renew {
        runtime.block_on(crate::acme::renew_all_instant_acme_targets(&config, now))?
    } else {
        runtime.block_on(crate::acme::renew_due_instant_acme_targets(&config, now))?
    };

    println!("acme attempted: {}", run.attempted);
    if force_renew && !queue.is_empty() && run.attempted == 0 {
        return Err(
            "ACME renewal planner produced targets, but --force-renew attempted none".into(),
        );
    }
    if !force_renew && run.attempted == 0 {
        println!("acme status: no certificates are missing or due for renewal");
    }
    for outcome in &run.renewed {
        println!(
            "renewed: {} issuer={} cert={} key={} challenges={}",
            outcome.vhost_name,
            outcome.issuer,
            outcome.certificate.cert_path.display(),
            outcome.certificate.key_path.display(),
            outcome.published_challenges
        );
    }
    for failure in &run.failed {
        println!(
            "failed: {} issuer={} domains={} error={}",
            failure.vhost_name,
            failure.issuer,
            failure.domains.join(","),
            failure.error.replace('\n', " ")
        );
    }
    if !run.failed.is_empty() {
        return Err(format!("ACME renewal failed for {} target(s)", run.failed.len()).into());
    }
    Ok(())
}

#[cfg(not(feature = "acme-client"))]
fn run_acme_renew_command(
    _config_path: Option<&std::path::Path>,
    _all: bool,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    Err("acme-renew requires the acme-client feature".into())
}

#[cfg(feature = "acme-client")]
fn run_acme_init_command(options: AcmeInitOptions) -> Result<(), Box<dyn Error + Send + Sync>> {
    let issuer_name = options.issuer.name();
    validate_acme_init_output_path("output", &options.output)?;
    validate_acme_init_directory_path("storage", &options.storage)?;
    if options.issuer.requires_eab() {
        validate_acme_init_directory_path("secrets-dir", &options.secrets_dir)?;
        if !options.no_systemd {
            validate_acme_init_directory_path("systemd-dropin-dir", &options.systemd_dropin_dir)?;
        }
    }

    let email = match options.email {
        Some(email) => validate_acme_contact_email(email)?,
        None if options.non_interactive => {
            return Err("--email is required with --non-interactive".into());
        }
        None => validate_acme_contact_email(prompt_line("ACME contact email: ")?)?,
    };

    create_parent_directory(&options.output)?;

    let mut created = Vec::new();
    if options.issuer.requires_eab() {
        create_secure_directory(&options.secrets_dir, 0o700)?;
        let kid = read_or_prompt_secret(
            options.kid_file.as_deref(),
            "Actalis EAB key id: ",
            options.non_interactive,
        )?;
        let hmac_key = read_or_prompt_secret(
            options.hmac_key_file.as_deref(),
            "Actalis EAB HMAC key: ",
            options.non_interactive,
        )?;

        let kid_path = options.secrets_dir.join("actalis-eab-kid");
        let hmac_key_path = options.secrets_dir.join("actalis-eab-hmac-key");
        write_secret_file(&kid_path, kid.trim(), options.force)?;
        write_secret_file(&hmac_key_path, hmac_key.trim(), options.force)?;
        created.push(kid_path);
        created.push(hmac_key_path);

        if !options.no_systemd {
            create_secure_directory(&options.systemd_dropin_dir, 0o755)?;
            let dropin_path = options.systemd_dropin_dir.join("actalis-eab.conf");
            write_file_checked(
                &dropin_path,
                include_str!("../packaging/systemd/actalis-eab.conf"),
                options.force,
                0o644,
            )?;
            created.push(dropin_path);
        }
    }

    let config_toml = build_acme_init_toml(
        options.issuer,
        &email,
        &options.storage,
        &options.secrets_dir,
        !options.no_systemd,
    )?;
    write_file_checked(&options.output, &config_toml, options.force, 0o644)?;
    created.push(options.output);

    println!("initialized ACME issuer: {issuer_name}");
    for path in created {
        println!("created: {}", path.display());
    }
    println!("next: add [vhosts.tls.acme] to each vhost that should receive a managed certificate");
    println!("next: run `systemctl daemon-reload` if a systemd drop-in was created");
    println!("next: run `fluxheim --config /etc/fluxheim/fluxheim.toml acme-renew`");
    Ok(())
}

#[cfg(not(feature = "acme-client"))]
fn run_acme_init_command(options: AcmeInitOptions) -> Result<(), Box<dyn Error + Send + Sync>> {
    let AcmeInitOptions {
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
    } = options;
    let _ = (
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
    );
    Err("acme-init requires the acme-client feature".into())
}

#[cfg(feature = "acme-client")]
impl AcmeInitIssuer {
    fn name(self) -> &'static str {
        match self {
            Self::Actalis => "actalis",
            Self::Letsencrypt => "letsencrypt",
            Self::LetsencryptStaging => "letsencrypt-staging",
        }
    }

    #[cfg(feature = "acme-client")]
    fn directory_url(self) -> &'static str {
        match self {
            Self::Actalis => "https://acme-api.actalis.com/acme/directory",
            Self::Letsencrypt => "https://acme-v02.api.letsencrypt.org/directory",
            Self::LetsencryptStaging => "https://acme-staging-v02.api.letsencrypt.org/directory",
        }
    }

    fn requires_eab(self) -> bool {
        matches!(self, Self::Actalis)
    }
}

#[cfg(feature = "acme-client")]
#[derive(serde::Serialize)]
struct AcmeInitToml {
    tls: AcmeInitTlsToml,
}

#[cfg(feature = "acme-client")]
#[derive(serde::Serialize)]
struct AcmeInitTlsToml {
    acme: AcmeInitAcmeToml,
}

#[cfg(feature = "acme-client")]
#[derive(serde::Serialize)]
struct AcmeInitAcmeToml {
    enabled: bool,
    storage: String,
    contact_email: String,
    default_issuer: String,
    challenge: String,
    automation: String,
    renewal: AcmeInitRenewalToml,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    issuers: Vec<AcmeInitIssuerToml>,
}

#[cfg(feature = "acme-client")]
#[derive(serde::Serialize)]
struct AcmeInitRenewalToml {
    enabled: bool,
    renew_before_secs: u64,
    check_interval_secs: u64,
    retry_initial_secs: u64,
    retry_max_secs: u64,
    reload_after_renewal: bool,
    zero_downtime_reload: bool,
}

#[cfg(feature = "acme-client")]
#[derive(serde::Serialize)]
struct AcmeInitIssuerToml {
    name: String,
    directory_url: String,
    eab: AcmeInitEabToml,
}

#[cfg(feature = "acme-client")]
#[derive(serde::Serialize)]
struct AcmeInitEabToml {
    #[serde(skip_serializing_if = "Option::is_none")]
    key_id_file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_id_credential: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hmac_key_file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hmac_key_credential: Option<String>,
}

#[cfg(feature = "acme-client")]
fn build_acme_init_toml(
    issuer: AcmeInitIssuer,
    email: &str,
    storage: &Path,
    secrets_dir: &Path,
    use_systemd_credentials: bool,
) -> Result<String, Box<dyn Error + Send + Sync>> {
    let issuers = if issuer.requires_eab() {
        let eab = if use_systemd_credentials {
            AcmeInitEabToml {
                key_id_file: None,
                key_id_credential: Some("actalis-eab-kid".to_owned()),
                hmac_key_file: None,
                hmac_key_credential: Some("actalis-eab-hmac-key".to_owned()),
            }
        } else {
            AcmeInitEabToml {
                key_id_file: Some(secrets_dir.join("actalis-eab-kid").display().to_string()),
                key_id_credential: None,
                hmac_key_file: Some(
                    secrets_dir
                        .join("actalis-eab-hmac-key")
                        .display()
                        .to_string(),
                ),
                hmac_key_credential: None,
            }
        };
        vec![AcmeInitIssuerToml {
            name: issuer.name().to_owned(),
            directory_url: issuer.directory_url().to_owned(),
            eab,
        }]
    } else {
        Vec::new()
    };

    let toml = AcmeInitToml {
        tls: AcmeInitTlsToml {
            acme: AcmeInitAcmeToml {
                enabled: true,
                storage: storage.display().to_string(),
                contact_email: email.to_owned(),
                default_issuer: issuer.name().to_owned(),
                challenge: "http-01".to_owned(),
                automation: if use_systemd_credentials {
                    "external".to_owned()
                } else {
                    "background".to_owned()
                },
                renewal: AcmeInitRenewalToml {
                    enabled: true,
                    renew_before_secs: 2_592_000,
                    check_interval_secs: 3_600,
                    retry_initial_secs: 300,
                    retry_max_secs: 86_400,
                    reload_after_renewal: true,
                    zero_downtime_reload: true,
                },
                issuers,
            },
        },
    };
    Ok(toml::to_string_pretty(&toml)?)
}

#[cfg(feature = "acme-client")]
fn prompt_line(prompt: &str) -> Result<String, Box<dyn Error + Send + Sync>> {
    print!("{prompt}");
    io::stdout().flush()?;
    let mut value = String::new();
    io::stdin().read_line(&mut value)?;
    Ok(value.trim().to_owned())
}

#[cfg(feature = "acme-client")]
fn read_or_prompt_secret(
    path: Option<&Path>,
    prompt: &str,
    non_interactive: bool,
) -> Result<String, Box<dyn Error + Send + Sync>> {
    if let Some(path) = path {
        validate_acme_init_output_path("secret input", path)?;
        return Ok(std::fs::read_to_string(path)?.trim().to_owned());
    }
    if non_interactive {
        return Err("EAB secret files are required with --non-interactive".into());
    }
    Ok(rpassword::prompt_password(prompt)?.trim().to_owned())
}

#[cfg(feature = "acme-client")]
fn validate_acme_contact_email(email: String) -> Result<String, Box<dyn Error + Send + Sync>> {
    let email = email.trim().to_owned();
    if email.len() > 254
        || !email.contains('@')
        || email.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err("ACME contact email must be a valid non-control email address".into());
    }
    Ok(email)
}

#[cfg(feature = "acme-client")]
fn validate_acme_init_output_path(
    field: &str,
    path: &Path,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    validate_acme_init_path(field, path, false)
}

#[cfg(feature = "acme-client")]
fn validate_acme_init_directory_path(
    field: &str,
    path: &Path,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    validate_acme_init_path(field, path, true)
}

#[cfg(feature = "acme-client")]
fn validate_acme_init_path(
    field: &str,
    path: &Path,
    allow_missing_leaf: bool,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    if !path.is_absolute() {
        return Err(format!("{field} must be an absolute path: {}", path.display()).into());
    }
    if path
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(format!(
            "{field} must not contain parent-directory traversal: {}",
            path.display()
        )
        .into());
    }
    if existing_prefix_contains_symlink(path, allow_missing_leaf)? {
        return Err(format!(
            "{field} must not contain symlinked path components: {}",
            path.display()
        )
        .into());
    }
    #[cfg(unix)]
    if existing_parent_is_world_writable(path)? {
        return Err(format!(
            "{field} must not be below a world-writable parent: {}",
            path.display()
        )
        .into());
    }
    Ok(())
}

#[cfg(feature = "acme-client")]
fn create_parent_directory(path: &Path) -> Result<(), Box<dyn Error + Send + Sync>> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("path has no parent: {}", path.display()))?;
    validate_acme_init_directory_path("directory", parent)?;
    if parent.exists() {
        return Ok(());
    }
    create_secure_directory(parent, 0o755)
}

#[cfg(feature = "acme-client")]
fn create_secure_directory(path: &Path, mode: u32) -> Result<(), Box<dyn Error + Send + Sync>> {
    validate_acme_init_directory_path("directory", path)?;
    std::fs::create_dir_all(path)?;
    set_mode(path, mode)?;
    Ok(())
}

#[cfg(feature = "acme-client")]
fn write_secret_file(
    path: &Path,
    value: &str,
    force: bool,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    if value.is_empty() || value.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(
            "secret value must be non-empty and must not contain control characters".into(),
        );
    }
    write_file_checked(path, &format!("{value}\n"), force, 0o600)
}

#[cfg(feature = "acme-client")]
fn write_file_checked(
    path: &Path,
    contents: &str,
    force: bool,
    mode: u32,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    validate_acme_init_output_path("output file", path)?;
    if path.exists() && !force {
        return Err(format!("refusing to overwrite existing file: {}", path.display()).into());
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        let mut options = std::fs::OpenOptions::new();
        options.write(true).mode(mode);
        if force {
            options.create(true).truncate(true);
        } else {
            options.create_new(true);
        }
        let mut file = options.open(path)?;
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
    }

    #[cfg(not(unix))]
    {
        let mut options = std::fs::OpenOptions::new();
        options.write(true);
        if force {
            options.create(true).truncate(true);
        } else {
            options.create_new(true);
        }
        let mut file = options.open(path)?;
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
    }

    set_mode(path, mode)?;
    Ok(())
}

#[cfg(feature = "acme-client")]
fn existing_prefix_contains_symlink(
    path: &Path,
    allow_missing_leaf: bool,
) -> Result<bool, Box<dyn Error + Send + Sync>> {
    let mut current = PathBuf::new();
    let component_count = path.components().count();
    for (index, component) in path.components().enumerate() {
        current.push(component);
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => return Ok(true),
            Ok(_) => {}
            Err(error)
                if error.kind() == io::ErrorKind::NotFound
                    && (allow_missing_leaf || index + 1 == component_count) =>
            {
                return Ok(false);
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(false)
}

#[cfg(all(feature = "acme-client", unix))]
fn existing_parent_is_world_writable(path: &Path) -> Result<bool, Box<dyn Error + Send + Sync>> {
    use std::os::unix::fs::MetadataExt;

    let Some(parent) = path.parent() else {
        return Ok(true);
    };
    let mut current = PathBuf::new();
    for component in parent.components() {
        current.push(component);
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.mode() & 0o002 != 0 => return Ok(true),
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error.into()),
        }
    }
    Ok(false)
}

#[cfg(feature = "acme-client")]
#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

#[cfg(feature = "acme-client")]
#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> io::Result<()> {
    Ok(())
}

#[cfg(any(
    feature = "tls",
    feature = "tls-rustls",
    feature = "tls-openssl",
    feature = "tls-boringssl",
    feature = "tls-s2n"
))]
fn check_tls_storage(config: &Config) -> Result<(), Box<dyn Error + Send + Sync>> {
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
    feature = "tls-rustls",
    feature = "tls-openssl",
    feature = "tls-boringssl",
    feature = "tls-s2n"
)))]
fn check_tls_storage(_config: &Config) -> Result<(), Box<dyn Error + Send + Sync>> {
    Err("TLS storage checks require a TLS feature".into())
}

#[cfg(all(
    test,
    any(
        feature = "tls",
        feature = "tls-rustls",
        feature = "tls-openssl",
        feature = "tls-boringssl",
        feature = "tls-s2n"
    )
))]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};

    use super::run_from_args;
    use crate::test_support::{safe_child_path, unique_temp_path};

    #[test]
    fn check_tls_storage_accepts_secure_files() {
        let dir = TestDir::new("cli-tls-secure");
        let cert = dir.file("fullchain.pem", 0o644);
        let key = dir.file("key.pem", 0o600);
        let acme = dir.dir("acme", 0o700);
        let config = dir.config(&cert, &key, &acme);

        run_from_args([
            "fluxheim",
            "--config",
            config.to_str().unwrap(),
            "--check-tls-storage",
        ])
        .unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn check_tls_storage_rejects_insecure_private_key() {
        let dir = TestDir::new("cli-tls-insecure-key");
        let cert = dir.file("fullchain.pem", 0o644);
        let key = dir.file("key.pem", 0o644);
        let acme = dir.dir("acme", 0o700);
        let config = dir.config(&cert, &key, &acme);

        let error = run_from_args([
            "fluxheim",
            "--config",
            config.to_str().unwrap(),
            "--check-tls-storage",
        ])
        .unwrap_err();

        assert_eq!(
            error.to_string(),
            "TLS storage check failed with 1 issue(s)"
        );
    }

    #[test]
    fn reload_from_accepts_snapshot_safe_changes() {
        let dir = TestDir::new("cli-reload-snapshot");
        let old_config = dir.simple_config("old.toml", "one", "one.example");
        let new_config = dir.simple_config("new.toml", "two", "two.example");

        run_from_args([
            "fluxheim",
            "--reload-from",
            old_config.to_str().unwrap(),
            "--config",
            new_config.to_str().unwrap(),
        ])
        .unwrap();
    }

    #[test]
    fn reload_from_accepts_process_upgrade_changes() {
        let dir = TestDir::new("cli-reload-process-upgrade");
        let old_config = dir.minimal_config("old.toml", "127.0.0.1:8080");
        let new_config = dir.minimal_config("new.toml", "127.0.0.1:8081");

        run_from_args([
            "fluxheim",
            "--reload-from",
            old_config.to_str().unwrap(),
            "--config",
            new_config.to_str().unwrap(),
        ])
        .unwrap();
    }

    #[test]
    fn validate_config_accepts_valid_config() {
        let dir = TestDir::new("cli-validate-config");
        let config = dir.simple_config("fluxheim.toml", "example", "example.test");

        run_from_args([
            "fluxheim",
            "--config",
            config.to_str().unwrap(),
            "--validate-config",
        ])
        .unwrap();
    }

    #[cfg(feature = "web")]
    #[test]
    fn validate_config_rejects_missing_static_root() {
        let dir = TestDir::new("cli-validate-missing-root");
        let missing_root = safe_child_path(&dir.path, "missing-site");
        let config = dir.web_config("fluxheim.toml", "example", "example.test", &missing_root);

        let error = run_from_args([
            "fluxheim",
            "--config",
            config.to_str().unwrap(),
            "--validate-config",
        ])
        .unwrap_err();

        let error = error.to_string();
        assert!(error.contains("vhost \"example\" web"));
        assert!(error.contains("web root does not exist"));
    }

    #[cfg(feature = "web")]
    #[test]
    fn validate_config_rejects_missing_route_static_root_with_context() {
        let dir = TestDir::new("cli-validate-missing-route-root");
        let missing_root = safe_child_path(&dir.path, "missing-route-site");
        let config = dir.route_web_config(
            "fluxheim.toml",
            "example",
            "example.test",
            "assets",
            &missing_root,
        );

        let error = run_from_args([
            "fluxheim",
            "--config",
            config.to_str().unwrap(),
            "--validate-config",
        ])
        .unwrap_err();

        let error = error.to_string();
        assert!(error.contains("vhost \"example\" route \"assets\" web"));
        assert!(error.contains("web root does not exist"));
    }

    #[cfg(not(feature = "acme-client"))]
    #[test]
    fn acme_renew_requires_acme_client_feature() {
        let error = run_from_args(["fluxheim", "acme-renew"]).unwrap_err();

        assert!(error.to_string().contains("acme-client"));
    }

    #[cfg(not(feature = "acme-client"))]
    #[test]
    fn acme_init_requires_acme_client_feature() {
        let error = run_from_args(["fluxheim", "acme-init", "actalis"]).unwrap_err();

        assert!(error.to_string().contains("acme-client"));
    }

    #[cfg(feature = "acme-client")]
    #[test]
    fn acme_init_actalis_writes_config_and_credential_files() {
        let dir = TestDir::new("cli-acme-init-actalis");
        let kid_input = dir.file("kid-input", 0o600);
        let hmac_input = dir.file("hmac-input", 0o600);
        fs::write(&kid_input, "kid-123\n").unwrap();
        fs::write(&hmac_input, "hmac-456\n").unwrap();
        let conf_dir = dir.dir("conf.d", 0o755);
        let output = conf_dir.join("acme.toml");
        let secrets_dir = dir.path.join("secrets");
        let systemd_dir = dir.path.join("systemd");
        let storage = dir.path.join("acme-storage");

        run_from_args([
            "fluxheim",
            "acme-init",
            "actalis",
            "--email",
            "admin@example.test",
            "--kid-file",
            kid_input.to_str().unwrap(),
            "--hmac-key-file",
            hmac_input.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
            "--secrets-dir",
            secrets_dir.to_str().unwrap(),
            "--systemd-dropin-dir",
            systemd_dir.to_str().unwrap(),
            "--storage",
            storage.to_str().unwrap(),
            "--non-interactive",
        ])
        .unwrap();

        assert_eq!(
            fs::read_to_string(secrets_dir.join("actalis-eab-kid")).unwrap(),
            "kid-123\n"
        );
        assert_eq!(
            fs::read_to_string(secrets_dir.join("actalis-eab-hmac-key")).unwrap(),
            "hmac-456\n"
        );
        assert!(systemd_dir.join("actalis-eab.conf").exists());
        let config = fs::read_to_string(output).unwrap();
        assert!(config.contains("default_issuer = \"actalis\""));
        assert!(config.contains("automation = \"external\""));
        assert!(config.contains("key_id_credential = \"actalis-eab-kid\""));
        assert!(config.contains("hmac_key_credential = \"actalis-eab-hmac-key\""));
    }

    #[test]
    fn snapshot_command_creates_store_snapshot() {
        let dir = TestDir::new("cli-snapshot-command");
        let config = dir.simple_config("fluxheim.toml", "example", "example.test");

        run_from_args([
            "fluxheim",
            "--config",
            config.to_str().unwrap(),
            "snapshot",
            "--store",
            dir.path.join("store").to_str().unwrap(),
            "--message",
            "known good",
        ])
        .unwrap();

        let store = crate::snapshot::SnapshotStore::new(dir.path.join("store"));
        assert_eq!(store.list().unwrap().len(), 1);
        assert!(store.current_id().unwrap().is_some());
    }

    #[test]
    fn rollback_command_selects_previous_snapshot() {
        let dir = TestDir::new("cli-rollback-command");
        let store_path = dir.path.join("store");
        let store = crate::snapshot::SnapshotStore::new(&store_path);
        let first = store
            .snapshot_config(&crate::config::Config::default(), Some("first"))
            .unwrap();
        let config = crate::config::Config {
            proxy: crate::config::ProxyConfig {
                upstream: Some("127.0.0.1:4000".to_owned()),
                ..crate::config::ProxyConfig::default()
            },
            ..crate::config::Config::default()
        };
        store.snapshot_config(&config, Some("second")).unwrap();

        run_from_args([
            "fluxheim",
            "rollback",
            "--store",
            store_path.to_str().unwrap(),
        ])
        .unwrap();

        assert_eq!(store.current_id().unwrap(), Some(first.id));
    }

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
            super::cache_warm_targets(Some("example.test"), &["/".to_owned()], Some(&input), 8)
                .unwrap();

        assert_eq!(
            targets,
            vec![
                super::CacheWarmTarget {
                    host: "example.test".to_owned(),
                    path: "/".to_owned(),
                },
                super::CacheWarmTarget {
                    host: "example.test".to_owned(),
                    path: "/assets/app.css".to_owned(),
                },
                super::CacheWarmTarget {
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
        fs::write(&input, vec![b'#'; super::CACHE_WARM_INPUT_MAX_BYTES + 1]).unwrap();

        let error = super::cache_warm_targets(Some("example.test"), &[], Some(&input), 8)
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
        let error = super::cache_warm_target("example.test", "/ok\r\nx-bad: 1").unwrap_err();
        assert!(error.to_string().contains("path contains control"));

        let error = super::cache_warm_target("bad host", "/ok").unwrap_err();
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
            super::cache_warm_listen_addr(&config, None).unwrap(),
            "127.0.0.1:8080".parse().unwrap()
        );
    }

    #[cfg(feature = "cache")]
    #[test]
    fn cache_warm_status_parser_reads_status_code() {
        assert_eq!(
            super::cache_warm_status_from_prefix(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n")
                .unwrap(),
            200
        );
        assert!(super::cache_warm_status_from_prefix(b"bad\r\n").is_err());
        assert_eq!(
            super::cache_warm_header_value_from_prefix(
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
        assert!(super::cache_warm_status_is_success(200, &[]));
        assert!(super::cache_warm_status_is_success(302, &[]));
        assert!(!super::cache_warm_status_is_success(404, &[]));
        assert!(super::cache_warm_status_is_success(404, &[404]));
        assert!(super::validate_cache_warm_allow_statuses(&[200, 404]).is_ok());
        assert!(super::validate_cache_warm_allow_statuses(&[99]).is_err());
        assert!(super::validate_cache_warm_header_name("x-cache-status").is_ok());
        assert!(super::validate_cache_warm_header_name("bad header").is_err());
        assert!(
            super::validate_cache_warm_expected_statuses(&["HIT".to_owned(), "MISS".to_owned()])
                .is_ok()
        );
        assert!(
            super::cache_warm_expected_status_matches(Some("hit"), &["HIT".to_owned()]).is_ok()
        );
        assert!(
            super::cache_warm_expected_status_matches(Some("BYPASS"), &["HIT".to_owned()]).is_err()
        );
        assert!(super::cache_warm_expected_status_matches(None, &["HIT".to_owned()]).is_err());
        assert!(
            super::validate_cache_warm_expected_sequence(
                &[],
                &["MISS".to_owned(), "HIT".to_owned()],
                2
            )
            .is_ok()
        );
        assert!(
            super::validate_cache_warm_expected_sequence(&[], &["MISS".to_owned()], 2).is_err()
        );
        assert!(
            super::validate_cache_warm_expected_sequence(
                &["HIT".to_owned()],
                &["MISS".to_owned()],
                1
            )
            .is_err()
        );
        assert_eq!(
            super::cache_warm_expected_statuses_for_attempt(
                &[],
                &["MISS".to_owned(), "HIT".to_owned()],
                2
            ),
            &["HIT".to_owned()]
        );
        assert_eq!(super::cache_warm_safe_label(Some("HIT")), "HIT");
        assert_eq!(super::cache_warm_safe_label(None), "-");
        assert_eq!(super::cache_warm_safe_label(Some("bad value")), "other");
    }

    #[cfg(feature = "cache")]
    #[test]
    fn cache_warm_count_summary_is_stable_and_bounded() {
        let empty = std::collections::BTreeMap::<String, usize>::new();
        assert_eq!(super::cache_warm_counts_summary(&empty), None);

        let mut counts = std::collections::BTreeMap::new();
        counts.insert("unexpected_status".to_owned(), 2);
        counts.insert("request_error".to_owned(), 1);
        counts.insert("unexpected_cache_status".to_owned(), 3);

        assert_eq!(
            super::cache_warm_counts_summary(&counts).as_deref(),
            Some("request_error=1 unexpected_cache_status=3 unexpected_status=2")
        );
    }

    #[cfg(all(feature = "cache", feature = "proxy"))]
    #[test]
    fn cache_lookup_expectations_validate_object_and_freshness_state() {
        let lookup = cache_lookup_with_state(crate::cache::CacheObjectFreshnessState::Stale);
        let states = super::parse_cache_lookup_freshness_states(&[" Stale ".to_owned()]).unwrap();
        let tiers = super::parse_cache_lookup_tiers(&[" Memory ".to_owned()]).unwrap();

        assert!(
            super::validate_cache_lookup_expectations(
                &lookup,
                true,
                &states,
                &[200],
                &tiers,
                &["etag".to_owned()],
                true
            )
            .is_ok()
        );
        assert!(
            super::validate_cache_lookup_expectations(
                &lookup,
                false,
                &[crate::cache::CacheObjectFreshnessState::Fresh],
                &[],
                &[],
                &[],
                false
            )
            .unwrap_err()
            .to_string()
            .contains("expected freshness state fresh, found stale")
        );
        assert!(
            super::validate_cache_lookup_expectations(&lookup, false, &[], &[404], &[], &[], false)
                .unwrap_err()
                .to_string()
                .contains("expected status 404, found 200")
        );
        assert!(
            super::validate_cache_lookup_expectations(
                &lookup,
                false,
                &[],
                &[],
                &[crate::cache::CacheObjectTier::Disk],
                &[],
                false
            )
            .unwrap_err()
            .to_string()
            .contains("expected tier disk, found memory")
        );
        assert_eq!(
            super::parse_cache_lookup_header_names(&[" ETag ".to_owned()]).unwrap(),
            vec!["etag"]
        );
        assert!(
            super::parse_cache_lookup_header_names(&["bad header".to_owned()])
                .unwrap_err()
                .to_string()
                .contains("valid HTTP header name")
        );
        assert!(
            super::validate_cache_lookup_expectations(
                &lookup,
                false,
                &[],
                &[],
                &[],
                &["last-modified".to_owned()],
                false
            )
            .unwrap_err()
            .to_string()
            .contains("expected stored header name last-modified, found cache-control,etag,vary")
        );
        assert!(
            super::parse_cache_lookup_freshness_states(&["invalid".to_owned()])
                .unwrap_err()
                .to_string()
                .contains("fresh, stale, or expired")
        );
        assert!(
            super::parse_cache_lookup_tiers(&["invalid".to_owned()])
                .unwrap_err()
                .to_string()
                .contains("memory or disk")
        );
        assert!(super::validate_cache_lookup_expected_statuses(&[99]).is_err());
        assert!(
            super::validate_cache_lookup_expectations(
                &cache_lookup_without_objects(),
                true,
                &[],
                &[],
                &[],
                &[],
                false
            )
            .unwrap_err()
            .to_string()
            .contains("expected at least one cached object")
        );
        assert!(
            super::validate_cache_lookup_expectations(
                &cache_lookup_without_objects(),
                false,
                &[],
                &[],
                &[],
                &[],
                true
            )
            .unwrap_err()
            .to_string()
            .contains("expected at least one purge-indexed object")
        );
    }

    #[cfg(all(feature = "cache", feature = "proxy"))]
    #[test]
    fn cache_key_uri_accepts_separate_query() {
        assert_eq!(
            super::cache_key_uri("/assets/app.js", Some("v=1")).unwrap(),
            "/assets/app.js?v=1"
        );
        assert!(super::cache_key_uri("/assets/app.js?v=1", Some("x=2")).is_err());
        assert!(super::cache_key_uri("/assets/app.js", Some("?v=1")).is_err());
    }

    #[cfg(all(feature = "cache", feature = "proxy"))]
    #[test]
    fn cache_key_headers_accept_safe_variance_inputs() {
        assert_eq!(
            super::parse_cache_cli_header("cache-key", "Accept-Language: de, en;q=0.8").unwrap(),
            ("accept-language".to_owned(), "de, en;q=0.8".to_owned())
        );
        assert!(super::parse_cache_cli_header("cache-key", "Host: example.test").is_err());
        assert!(super::parse_cache_cli_header("cache-key", "Connection: close").is_err());
        assert!(super::parse_cache_cli_header("cache-key", "Bad Header: value").is_err());
        assert!(super::parse_cache_cli_header("cache-key", "X-Test: bad\r\nvalue").is_err());
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

    struct TestDir {
        path: PathBuf,
    }

    impl TestDir {
        fn new(name: &str) -> Self {
            let path = unique_temp_path(name);
            fs::create_dir(&path).expect("create test directory");
            Self { path }
        }

        fn file(&self, name: &str, mode: u32) -> PathBuf {
            let path = safe_child_path(&self.path, name);
            fs::write(&path, "test").expect("write test file");
            set_mode(&path, mode);
            path
        }

        fn dir(&self, name: &str, mode: u32) -> PathBuf {
            let path = safe_child_path(&self.path, name);
            fs::create_dir(&path).expect("create child directory");
            set_mode(&path, mode);
            path
        }

        fn config(&self, cert: &Path, key: &Path, acme: &Path) -> PathBuf {
            let path = self.path.join("fluxheim.toml");
            fs::write(
                &path,
                format!(
                    r#"
                    [tls]
                    enabled = true

                    [[tls.certificates]]
                    cert_path = "{}"
                    key_path = "{}"

                    [tls.acme]
                    enabled = true
                    storage = "{}"
                    contact_email = "admin@example.test"
                    "#,
                    cert.display(),
                    key.display(),
                    acme.display()
                ),
            )
            .expect("write config");
            path
        }

        fn simple_config(&self, name: &str, vhost_name: &str, host: &str) -> PathBuf {
            let path = safe_child_path(&self.path, name);
            fs::write(
                &path,
                format!(
                    r#"
                    [[vhosts]]
                    name = "{vhost_name}"
                    hosts = ["{host}"]
                    "#
                ),
            )
            .expect("write config");
            path
        }

        #[cfg(feature = "web")]
        fn web_config(&self, name: &str, vhost_name: &str, host: &str, root: &Path) -> PathBuf {
            let path = safe_child_path(&self.path, name);
            fs::write(
                &path,
                format!(
                    r#"
                    [[vhosts]]
                    name = "{vhost_name}"
                    hosts = ["{host}"]

                    [vhosts.web]
                    root = "{}"
                    "#,
                    root.display()
                ),
            )
            .expect("write config");
            path
        }

        #[cfg(feature = "web")]
        fn route_web_config(
            &self,
            name: &str,
            vhost_name: &str,
            host: &str,
            route_name: &str,
            root: &Path,
        ) -> PathBuf {
            let path = safe_child_path(&self.path, name);
            fs::write(
                &path,
                format!(
                    r#"
                    [[vhosts]]
                    name = "{vhost_name}"
                    hosts = ["{host}"]

                    [[vhosts.routes]]
                    name = "{route_name}"
                    path_prefix = "/assets/"

                    [vhosts.routes.web]
                    root = "{}"
                    "#,
                    root.display()
                ),
            )
            .expect("write config");
            path
        }

        fn minimal_config(&self, name: &str, listen: &str) -> PathBuf {
            let path = safe_child_path(&self.path, name);
            fs::write(
                &path,
                format!(
                    r#"
                    [server]
                    listen = ["{listen}"]
                    "#
                ),
            )
            .expect("write config");
            path
        }
    }

    #[cfg(all(feature = "cache", feature = "proxy"))]
    fn cache_lookup_with_state(
        state: crate::cache::CacheObjectFreshnessState,
    ) -> crate::proxy::CacheObjectLookup {
        let mut lookup = cache_lookup_without_objects();
        lookup.objects.push(crate::cache::CacheObjectMetadata {
            tier: crate::cache::CacheObjectTier::Memory,
            purge_indexed: true,
            status: 200,
            fresh: state == crate::cache::CacheObjectFreshnessState::Fresh,
            freshness_state: state,
            serve_stale_while_revalidate: state == crate::cache::CacheObjectFreshnessState::Stale,
            serve_stale_if_error: false,
            body_bytes: 4,
            weight_bytes: 4,
            created_unix_secs: Some(1),
            updated_unix_secs: Some(1),
            fresh_until_unix_secs: Some(2),
            age_secs: 1,
            fresh_ttl_secs: 0,
            stale_while_revalidate_secs: 30,
            stale_if_error_secs: 0,
            cache_tags: Vec::new(),
            header_names: vec![
                "cache-control".to_owned(),
                "etag".to_owned(),
                "vary".to_owned(),
            ],
        });
        lookup
    }

    #[cfg(all(feature = "cache", feature = "proxy"))]
    fn cache_lookup_without_objects() -> crate::proxy::CacheObjectLookup {
        crate::proxy::CacheObjectLookup {
            preview: crate::proxy::CacheKeyPreview {
                vhost: "cached".to_owned(),
                route: Some("assets".to_owned()),
                scope: crate::proxy::CacheKeyPreviewScope::Route,
                eligible: true,
                cache_lock_enabled: true,
                cache_lock_wait_timeout_secs: 30,
                memory_tier_enabled: true,
                disk_tier_enabled: false,
                storage_tiers: 1,
                reason: None,
                namespace: Some("fluxheim-image-v1".to_owned()),
                primary_key: None,
                primary_hash: Some("primary".to_owned()),
                variance_hash: None,
                combined_hash: Some("primary".to_owned()),
                user_tag: Some("cached:route:assets".to_owned()),
            },
            objects: Vec::new(),
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[cfg(unix)]
    fn set_mode(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("set mode");
    }

    #[cfg(not(unix))]
    fn set_mode(_path: &Path, _mode: u32) {}
}
