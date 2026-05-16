use std::error::Error;
use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::config::Config;

#[derive(Debug, Parser)]
#[command(
    version = env!("FLUXHEIM_VERSION"),
    about = "Fluxheim ACME companion for certificate lifecycle operations"
)]
pub struct AcmeCompanionCli {
    /// Path to a Fluxheim TOML configuration file.
    #[arg(short, long, env = "FLUXHEIM_CONFIG")]
    pub config: Option<PathBuf>,

    #[command(subcommand)]
    pub command: AcmeCompanionCommand,
}

#[derive(Debug, Subcommand)]
pub enum AcmeCompanionCommand {
    /// Run ACME issuance/renewal once for all configured ACME vhosts.
    Renew {
        /// Force renewal for every configured ACME vhost, even when certificates are not due.
        #[arg(long)]
        force_renew: bool,
    },

    /// Print configured ACME renewal targets without contacting an issuer.
    Targets,
}

pub fn run_from_env() -> Result<(), Box<dyn Error + Send + Sync>> {
    run_from_args(std::env::args_os())
}

pub fn run_from_args<I, T>(args: I) -> Result<(), Box<dyn Error + Send + Sync>>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    #[cfg(all(
        feature = "tls-rustls",
        not(any(feature = "tls-openssl", feature = "tls-boringssl"))
    ))]
    crate::tls::install_rustls_crypto_provider();

    let cli = AcmeCompanionCli::parse_from(args);
    match cli.command {
        AcmeCompanionCommand::Renew { force_renew } => {
            crate::cli::run_acme_renew_command(cli.config.as_deref(), force_renew)
        }
        AcmeCompanionCommand::Targets => print_targets(cli.config.as_deref()),
    }
}

#[cfg(feature = "acme")]
fn print_targets(
    config_path: Option<&std::path::Path>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let config = Config::load(config_path)?;
    config.validate()?;
    crate::cli::validate_compiled_module_config(&config)?;
    let targets = crate::acme::renewal_targets(&config);
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
fn print_targets(
    _config_path: Option<&std::path::Path>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    Err("fluxheim-acme requires the `acme` or `acme-client` feature".into())
}

#[cfg(test)]
mod tests {
    use super::run_from_args;

    #[test]
    fn targets_requires_valid_config_path() {
        let error =
            run_from_args(["fluxheim-acme", "--config", "/no/such/file", "targets"]).unwrap_err();

        assert!(
            error.to_string().contains("No such file")
                || error.to_string().contains("not found")
                || error.to_string().contains("does not exist")
        );
    }
}
