use std::error::Error;
use std::net::ToSocketAddrs;
use std::path::PathBuf;

use clap::{Parser, ValueEnum};

use crate::config::{CacheConfig, Config, PhpConfig, ProxyConfig, TlsBackend, WebConfig};

#[derive(Debug, Parser)]
#[command(
    version = env!("FLUXHEIM_VERSION"),
    about = "Validate Fluxheim configs without starting the gateway"
)]
pub struct ConfigTesterCli {
    /// Path to the Fluxheim TOML configuration file or config directory.
    #[arg(short, long, env = "FLUXHEIM_CONFIG")]
    pub config: PathBuf,

    /// Target release profile to validate against.
    #[arg(long, default_value = "full")]
    pub profile: ConfigTesterProfile,

    /// Skip runtime path validation and only validate config syntax/semantics.
    #[arg(long)]
    pub no_runtime_paths: bool,

    /// Validate TLS certificate/key files and ACME storage permissions.
    #[arg(long)]
    pub check_tls_storage: bool,

    /// Print configured ACME targets without issuing certificates.
    #[arg(long)]
    pub acme_targets: bool,

    /// Resolve configured upstream hostnames without opening connections.
    #[arg(long)]
    pub resolve_upstreams: bool,

    /// Print vhost/route/module context for checks as they run.
    #[arg(long)]
    pub explain: bool,

    /// Print compiled crypto/TLS diagnostics for this tester build.
    #[arg(long)]
    pub crypto: bool,

    /// Print the native runtime cutover blocker report for this config.
    #[arg(long)]
    pub runtime_cutover: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum ConfigTesterProfile {
    Full,
    Cache,
    Proxy,
    FipsOpenssl,
    Iso19790Openssl,
    FipsRustls,
    Iso19790Rustls,
    WebPhp,
    Development,
    LoadBalancer,
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

    let cli = ConfigTesterCli::parse_from(args);
    run(cli)
}

fn run(cli: ConfigTesterCli) -> Result<(), Box<dyn Error + Send + Sync>> {
    let config = if cli.no_runtime_paths {
        Config::load_without_runtime_paths(Some(&cli.config))?
    } else {
        Config::load(Some(&cli.config))?
    };
    validate_profile_config(&config, cli.profile)?;

    if cli.crypto {
        crate::cli::print_crypto_diagnostics(Some(&config), Some(&cli.config));
    }

    if cli.runtime_cutover {
        print_runtime_cutover_report(&config)?;
    }

    if cli.explain {
        println!(
            "config: {} profile={} vhosts={}",
            cli.config.display(),
            cli.profile.as_str(),
            config.vhosts.len()
        );
    }

    if !cli.no_runtime_paths {
        crate::cli::validate_compiled_module_config(&config)?;
        crate::cli::validate_runtime_config(&config)?;
        if cli.explain {
            println!("runtime-paths: ok");
        }
    }

    if cli.check_tls_storage {
        crate::cli::check_tls_storage(&config)?;
        if cli.explain {
            println!("tls-storage: ok");
        }
    }

    if cli.acme_targets {
        print_acme_targets(&config)?;
    }

    if cli.resolve_upstreams {
        resolve_upstreams(&config)?;
    }

    println!("config tester: ok");
    Ok(())
}

fn print_runtime_cutover_report(config: &Config) -> Result<(), Box<dyn Error + Send + Sync>> {
    let plan = fluxheim_server::ServerPlan::from_config(config)?;
    let summary = plan.native_runtime_cutover_summary();
    println!("native-runtime-adapter: {:?}", plan.runtime_adapter());
    print!("{}", summary.to_tsv());
    Ok(())
}

fn validate_profile_config(
    config: &Config,
    profile: ConfigTesterProfile,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let policy = ProfilePolicy::for_profile(profile);
    if !policy.web {
        reject_web_config(config)?;
    }
    if !policy.cache {
        reject_cache_config(config)?;
    }
    if !policy.php {
        reject_php_config(config)?;
    }
    if !policy.proxy {
        reject_proxy_config(config)?;
    }
    if matches!(
        profile,
        ConfigTesterProfile::FipsOpenssl | ConfigTesterProfile::Iso19790Openssl
    ) {
        validate_fips_openssl_profile_config(config, profile)?;
    }
    if matches!(
        profile,
        ConfigTesterProfile::FipsRustls | ConfigTesterProfile::Iso19790Rustls
    ) {
        validate_fips_rustls_profile_config(config, profile)?;
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct ProfilePolicy {
    proxy: bool,
    web: bool,
    cache: bool,
    php: bool,
}

impl ProfilePolicy {
    fn for_profile(profile: ConfigTesterProfile) -> Self {
        match profile {
            ConfigTesterProfile::Full | ConfigTesterProfile::Development => Self {
                proxy: true,
                web: true,
                cache: true,
                php: matches!(profile, ConfigTesterProfile::Development),
            },
            ConfigTesterProfile::Cache => Self {
                proxy: true,
                web: false,
                cache: true,
                php: false,
            },
            ConfigTesterProfile::Proxy
            | ConfigTesterProfile::FipsOpenssl
            | ConfigTesterProfile::Iso19790Openssl
            | ConfigTesterProfile::FipsRustls
            | ConfigTesterProfile::Iso19790Rustls
            | ConfigTesterProfile::LoadBalancer => Self {
                proxy: true,
                web: false,
                cache: false,
                php: false,
            },
            ConfigTesterProfile::WebPhp => Self {
                proxy: false,
                web: true,
                cache: false,
                php: true,
            },
        }
    }
}

impl ConfigTesterProfile {
    fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Cache => "cache",
            Self::Proxy => "proxy",
            Self::FipsOpenssl => "fips-openssl",
            Self::Iso19790Openssl => "iso19790-openssl",
            Self::FipsRustls => "fips-rustls",
            Self::Iso19790Rustls => "iso19790-rustls",
            Self::WebPhp => "web-php",
            Self::Development => "development",
            Self::LoadBalancer => "load-balancer",
        }
    }
}

fn reject_web_config(config: &Config) -> Result<(), Box<dyn Error + Send + Sync>> {
    if config.web.enabled() {
        return Err("target profile does not include web; remove enabled [web] config".into());
    }
    for vhost in &config.vhosts {
        if vhost.web.enabled() {
            return Err(format!(
                "target profile does not include web; remove enabled [vhosts.web] from vhost {:?}",
                vhost.name
            )
            .into());
        }
        for route in &vhost.routes {
            if route.web.as_ref().is_some_and(WebConfig::enabled) {
                return Err(format!(
                    "target profile does not include web; remove enabled [vhosts.routes.web] from vhost {:?} route {:?}",
                    vhost.name, route.name
                )
                .into());
            }
        }
    }
    Ok(())
}

fn validate_fips_openssl_profile_config(
    config: &Config,
    profile: ConfigTesterProfile,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    if config.tls.backend != TlsBackend::Openssl {
        return Err(format!(
            "target profile {} requires [tls] backend = \"openssl\"",
            profile.as_str()
        )
        .into());
    }
    if !config.tls.compliance_mode().required() {
        return Err(format!(
            "target profile {} requires [tls.fips] required = true or [tls.iso19790] required = true",
            profile.as_str()
        )
        .into());
    }
    Ok(())
}

fn validate_fips_rustls_profile_config(
    config: &Config,
    profile: ConfigTesterProfile,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    if config.tls.backend != TlsBackend::Rustls {
        return Err(format!(
            "target profile {} requires [tls] backend = \"rustls\"",
            profile.as_str()
        )
        .into());
    }
    if !config.tls.compliance_mode().required() {
        return Err(format!(
            "target profile {} requires [tls.fips] required = true or [tls.iso19790] required = true",
            profile.as_str()
        )
        .into());
    }
    Ok(())
}

fn reject_cache_config(config: &Config) -> Result<(), Box<dyn Error + Send + Sync>> {
    if cache_policy_requires_module(&config.cache) {
        return Err("target profile does not include cache; remove enabled [cache] config".into());
    }
    for vhost in &config.vhosts {
        if cache_policy_requires_module(&vhost.cache) {
            return Err(format!(
                "target profile does not include cache; remove enabled [vhosts.cache] from vhost {:?}",
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
                    "target profile does not include cache; remove enabled [vhosts.routes.cache] from vhost {:?} route {:?}",
                    vhost.name, route.name
                )
                .into());
            }
        }
    }
    Ok(())
}

fn cache_policy_requires_module(config: &CacheConfig) -> bool {
    config.enabled
        || config.local_static
        || config.memory.enabled
        || config.disk.enabled
        || config.peer_fill.enabled
}

fn reject_php_config(config: &Config) -> Result<(), Box<dyn Error + Send + Sync>> {
    for vhost in &config.vhosts {
        if vhost.php.enabled() {
            return Err(format!(
                "target profile does not include php-fpm; remove enabled [vhosts.php] from vhost {:?}",
                vhost.name
            )
            .into());
        }
        for route in &vhost.routes {
            if route.php.as_ref().is_some_and(PhpConfig::enabled) {
                return Err(format!(
                    "target profile does not include php-fpm; remove enabled [vhosts.routes.php] from vhost {:?} route {:?}",
                    vhost.name, route.name
                )
                .into());
            }
        }
    }
    Ok(())
}

fn reject_proxy_config(config: &Config) -> Result<(), Box<dyn Error + Send + Sync>> {
    for vhost in &config.vhosts {
        if vhost.proxy.has_configured_upstream() {
            return Err(format!(
                "target profile does not include reverse proxying; remove [vhosts.proxy] from vhost {:?}",
                vhost.name
            )
            .into());
        }
        for route in &vhost.routes {
            if route.proxy.is_some() {
                return Err(format!(
                    "target profile does not include reverse proxying; remove [vhosts.routes.proxy] from vhost {:?} route {:?}",
                    vhost.name, route.name
                )
                .into());
            }
        }
    }
    Ok(())
}

#[cfg(feature = "acme")]
fn print_acme_targets(config: &Config) -> Result<(), Box<dyn Error + Send + Sync>> {
    let targets = crate::acme::renewal_targets(config);
    println!("acme targets: {}", targets.len());
    for target in targets {
        println!(
            "target: {} issuer={} challenge={:?} domains={} cert={} key={}",
            target.vhost_name,
            target.issuer,
            target.challenge,
            target.domains.join(","),
            target.certificate.cert_path.display(),
            target.certificate.key_path.display()
        );
    }
    Ok(())
}

#[cfg(not(feature = "acme"))]
fn print_acme_targets(_config: &Config) -> Result<(), Box<dyn Error + Send + Sync>> {
    Err("ACME target preview requires the `acme` or `acme-client` feature".into())
}

fn resolve_upstreams(config: &Config) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut failed = 0usize;
    for upstream in configured_upstreams(config) {
        match upstream.authority.to_socket_addrs() {
            Ok(addresses) => {
                let addresses = addresses
                    .map(|address| address.to_string())
                    .collect::<Vec<_>>()
                    .join(",");
                println!(
                    "upstream: {} {} -> {}",
                    upstream.scope, upstream.authority, addresses
                );
            }
            Err(error) => {
                failed = failed.saturating_add(1);
                println!(
                    "upstream: {} {} -> error: {}",
                    upstream.scope, upstream.authority, error
                );
            }
        }
    }
    if failed > 0 {
        return Err(format!("failed to resolve {failed} upstream target(s)").into());
    }
    Ok(())
}

#[derive(Debug)]
struct UpstreamTarget {
    scope: String,
    authority: String,
}

fn configured_upstreams(config: &Config) -> Vec<UpstreamTarget> {
    let mut targets = Vec::new();
    if config.vhosts.is_empty() && config.proxy.has_configured_upstream() {
        push_proxy_upstreams("proxy", &config.proxy, &mut targets);
    }
    for vhost in &config.vhosts {
        push_proxy_upstreams(
            &format!("vhost {:?}", vhost.name),
            &vhost.proxy,
            &mut targets,
        );
        if vhost.acme_challenge.enabled {
            if let Some(upstream) = &vhost.acme_challenge.upstream {
                targets.push(UpstreamTarget {
                    scope: format!("vhost {:?} acme_challenge", vhost.name),
                    authority: upstream.clone(),
                });
            }
            for upstream in &vhost.acme_challenge.upstreams {
                targets.push(UpstreamTarget {
                    scope: format!("vhost {:?} acme_challenge", vhost.name),
                    authority: upstream.clone(),
                });
            }
        }
        for route in &vhost.routes {
            if let Some(proxy) = &route.proxy {
                push_proxy_upstreams(
                    &format!("vhost {:?} route {:?}", vhost.name, route.name),
                    proxy,
                    &mut targets,
                );
            }
        }
    }
    targets
}

fn push_proxy_upstreams(scope: &str, proxy: &ProxyConfig, targets: &mut Vec<UpstreamTarget>) {
    if let Some(upstream) = &proxy.upstream {
        targets.push(UpstreamTarget {
            scope: scope.to_owned(),
            authority: upstream.clone(),
        });
    }
    for upstream in &proxy.upstreams {
        targets.push(UpstreamTarget {
            scope: scope.to_owned(),
            authority: upstream.clone(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::{ConfigTesterProfile, configured_upstreams, validate_profile_config};
    use crate::config::Config;
    use crate::test_support::unique_temp_path;
    use std::fs;

    fn config_from_toml(input: &str) -> Config {
        toml::from_str(input).expect("config should parse")
    }

    #[test]
    fn cache_profile_rejects_web_vhost() {
        let config = config_from_toml(
            r#"
            [[vhosts]]
            name = "site"
            hosts = ["site.example"]

            [vhosts.web]
            root = "/srv/site"
            "#,
        );

        let error = validate_profile_config(&config, ConfigTesterProfile::Cache).unwrap_err();

        assert!(error.to_string().contains("does not include web"));
    }

    #[test]
    fn full_profile_rejects_php_vhost() {
        let config = config_from_toml(
            r#"
            [[vhosts]]
            name = "site"
            hosts = ["site.example"]

            [vhosts.php]
            enabled = true
            runtime = "php-fpm"
            root = "/srv/site"

            [vhosts.php.fpm]
            tcp = "127.0.0.1:9000"
            allow_private_tcp_upstreams = true
            "#,
        );

        let error = validate_profile_config(&config, ConfigTesterProfile::Full).unwrap_err();

        assert!(error.to_string().contains("does not include php-fpm"));
    }

    #[test]
    fn fips_openssl_profile_requires_openssl_backend() {
        let config = config_from_toml(
            r#"
            [tls]
            backend = "rustls"

            [tls.fips]
            required = true
            "#,
        );

        let error = validate_profile_config(&config, ConfigTesterProfile::FipsOpenssl).unwrap_err();

        assert!(error.to_string().contains("backend = \"openssl\""));
    }

    #[test]
    fn fips_openssl_profile_requires_fips_guard() {
        let config = config_from_toml(
            r#"
            [tls]
            backend = "openssl"
            "#,
        );

        let error = validate_profile_config(&config, ConfigTesterProfile::FipsOpenssl).unwrap_err();

        assert!(error.to_string().contains("required = true"));
    }

    #[test]
    fn fips_openssl_profile_accepts_fips_required_openssl() {
        let config = config_from_toml(
            r#"
            [tls]
            backend = "openssl"

            [tls.fips]
            required = true
            "#,
        );

        validate_profile_config(&config, ConfigTesterProfile::FipsOpenssl).unwrap();
    }

    #[test]
    fn iso19790_openssl_profile_accepts_iso19790_required_openssl() {
        let config = config_from_toml(
            r#"
            [tls]
            backend = "openssl"

            [tls.iso19790]
            required = true
            "#,
        );

        validate_profile_config(&config, ConfigTesterProfile::Iso19790Openssl).unwrap();
    }

    #[test]
    fn fips_rustls_profile_requires_rustls_backend() {
        let config = config_from_toml(
            r#"
            [tls]
            backend = "openssl"

            [tls.fips]
            required = true
            "#,
        );

        let error = validate_profile_config(&config, ConfigTesterProfile::FipsRustls).unwrap_err();

        assert!(error.to_string().contains("backend = \"rustls\""));
    }

    #[test]
    fn fips_rustls_profile_requires_fips_guard() {
        let config = config_from_toml(
            r#"
            [tls]
            backend = "rustls"
            "#,
        );

        let error = validate_profile_config(&config, ConfigTesterProfile::FipsRustls).unwrap_err();

        assert!(error.to_string().contains("required = true"));
    }

    #[test]
    fn fips_rustls_profile_accepts_fips_required_rustls() {
        let config = config_from_toml(
            r#"
            [tls]
            backend = "rustls"

            [tls.fips]
            required = true
            "#,
        );

        validate_profile_config(&config, ConfigTesterProfile::FipsRustls).unwrap();
    }

    #[test]
    fn iso19790_rustls_profile_accepts_iso19790_required_rustls() {
        let config = config_from_toml(
            r#"
            [tls]
            backend = "rustls"

            [tls.iso19790]
            required = true
            "#,
        );

        validate_profile_config(&config, ConfigTesterProfile::Iso19790Rustls).unwrap();
    }

    fn write_test_config(label: &str, contents: &str) -> std::path::PathBuf {
        let dir = unique_temp_path(label);
        fs::create_dir_all(&dir).expect("create config tester fixture dir");
        let path = dir.join("config.toml");
        fs::write(&path, contents).expect("write config tester fixture");
        path
    }

    #[test]
    fn no_runtime_paths_skips_process_path_inspection() {
        let path = write_test_config("config-tester-no-runtime", "");

        let config = Config::load_without_runtime_paths(Some(&path))
            .expect("default runtime paths should be skipped");

        assert!(config.server.process.pid_file.ends_with("fluxheim.pid"));
    }

    #[test]
    fn no_runtime_paths_still_validates_process_settings() {
        let path = write_test_config(
            "config-tester-invalid-process",
            r#"
            [server.process]
            threads = 0
            "#,
        );

        let error = Config::load_without_runtime_paths(Some(&path)).unwrap_err();

        assert!(
            error.to_string().contains("server.process.threads"),
            "{error}"
        );
    }

    #[test]
    fn upstream_collection_includes_vhost_and_route_targets() {
        let config = config_from_toml(
            r#"
            [[vhosts]]
            name = "site"
            hosts = ["site.example"]

            [vhosts.proxy]
            upstreams = ["app-a:80", "app-b:80"]

            [[vhosts.routes]]
            name = "api"
            path_prefix = "/api/"

            [vhosts.routes.proxy]
            upstream = "api:8080"
            "#,
        );

        let targets = configured_upstreams(&config)
            .into_iter()
            .map(|target| target.authority)
            .collect::<Vec<_>>();

        assert_eq!(targets, ["app-a:80", "app-b:80", "api:8080"]);
    }
}
