use std::error::Error;

use clap::Parser;

use crate::config::Config;

use super::{Cli, check_tls_storage, command_dispatch::run_command, validate_runtime_config};

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
