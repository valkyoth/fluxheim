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
    let targets = fluxheim_acme::renewal_targets(config);
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
mod tests;
