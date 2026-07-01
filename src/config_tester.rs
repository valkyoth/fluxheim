use std::error::Error;
use std::path::PathBuf;

use clap::Parser;

use crate::config::Config;
pub use crate::config_tester_profiles::ConfigTesterProfile;
use crate::config_tester_profiles::validate_profile_config;
use crate::config_tester_runtime::print_runtime_cutover_report;
use crate::config_tester_upstreams::resolve_upstreams;

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

#[cfg(test)]
mod tests {
    use super::{ConfigTesterCli, ConfigTesterProfile, validate_profile_config};
    use crate::config::Config;
    use crate::config_tester_runtime::runtime_cutover_report;
    use crate::config_tester_upstreams::configured_upstreams;
    use clap::Parser;
    use fluxheim_common::test_support::unique_temp_path;
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
    fn runtime_cutover_flag_parses() {
        let cli = ConfigTesterCli::parse_from([
            "fluxheim-config-tester",
            "--config",
            "fluxheim.toml",
            "--runtime-cutover",
        ]);

        assert!(cli.runtime_cutover);
    }

    #[test]
    fn runtime_cutover_report_lists_config_blockers() {
        let config = config_from_toml(
            r#"
            [server]
            listen = ["127.0.0.1:8080"]

            [admin]
            enabled = true
            listen = "127.0.0.1:9090"
            token_env = "FLUXHEIM_ADMIN_TOKEN"
            snapshot_store = "/tmp/fluxheim-test-snapshots"

            [metrics]
            enabled = true
            listen = "127.0.0.1:9091"

            [proxy]
            upstreams = ["127.0.0.1:3000"]
            upstream_tls = false
            "#,
        );

        let report = runtime_cutover_report(&config).unwrap();

        assert!(report.contains("native-runtime-plan-adapter: NativeRuntimeBlocked\n"));
        assert!(report.contains("native-runtime-target-adapter: NativeRuntime\n"));
        assert!(report.contains("native-runtime-launch-plan\tready\t3\t3\t0\toff\n"));
        assert!(report.contains(
            "native-runtime-launch-listener\tProxyHttp\tFluxheim HTTP Proxy\tHttp\t127.0.0.1:8080\tfalse\n"
        ));
        assert!(!report.contains("native-http2\tnative HTTP/2 downstream parity\t1.6.33\n"));
        assert!(!report.contains("admin-control-plane\tnative admin control plane\t1.6.22\n"));
        assert!(!report.contains("metrics-http\tnative metrics HTTP service\t1.6.22\n"));
        assert!(report.contains("native-http1-proxy-candidate\tscope\tstatus\treason\n"));
        assert!(report.contains("native-http1-proxy-candidate\tproxy\tnative-ready\t-\n"));
    }

    #[test]
    fn runtime_cutover_report_lists_launch_plan_errors() {
        let config = config_from_toml(
            r#"
            [server]
            listen = ["127.0.0.1:8080"]

            [admin]
            enabled = true
            listen = "127.0.0.1:8080"
            token_env = "FLUXHEIM_ADMIN_TOKEN"
            snapshot_store = "/tmp/fluxheim-test-snapshots"

            [proxy]
            upstreams = ["127.0.0.1:3000"]
            upstream_tls = false
            "#,
        );

        let report = runtime_cutover_report(&config).unwrap();

        assert!(report.contains("native-runtime-target-adapter: NativeRuntimeBlocked\n"));
        assert!(report.contains(
            "native-runtime-launch-plan-error\tduplicate-listener\tnative runtime launch plan has duplicate TCP listener 127.0.0.1:8080 for ProxyHttp and AdminControlPlane\n"
        ));
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
