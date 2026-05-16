use std::error::Error;
#[cfg(all(feature = "acme-client", unix))]
use std::io::{Read, Write};
use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[cfg(feature = "acme")]
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

        /// Do not request a certificate reload from the running gateway after renewal.
        #[arg(long)]
        no_reload: bool,
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
        AcmeCompanionCommand::Renew {
            force_renew,
            no_reload,
        } => run_renew(cli.config.as_deref(), force_renew, !no_reload),
        AcmeCompanionCommand::Targets => print_targets(cli.config.as_deref()),
    }
}

#[cfg(feature = "acme-client")]
fn run_renew(
    config_path: Option<&std::path::Path>,
    force_renew: bool,
    reload_after_renewal: bool,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    crate::tls::install_rustls_crypto_provider();

    let config = Config::load(config_path)?;
    config.validate()?;
    crate::cli::validate_compiled_module_config(&config)?;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let now = std::time::SystemTime::now();
    let run = if force_renew {
        runtime.block_on(crate::acme::renew_all_instant_acme_targets(&config, now))?
    } else {
        runtime.block_on(crate::acme::renew_due_instant_acme_targets(&config, now))?
    };

    println!("acme attempted: {}", run.attempted);
    if !force_renew && run.attempted == 0 {
        println!("acme status: no certificates are missing or due for renewal");
    }

    let renewed_count = run.renewed.len();
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

    if renewed_count > 0 && reload_after_renewal && config.tls.acme.renewal.reload_after_renewal {
        request_certificate_reload(&config)?;
    }

    if !run.failed.is_empty() {
        return Err(format!("ACME renewal failed for {} target(s)", run.failed.len()).into());
    }
    Ok(())
}

#[cfg(not(feature = "acme-client"))]
fn run_renew(
    _config_path: Option<&std::path::Path>,
    _force_renew: bool,
    _reload_after_renewal: bool,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    Err("fluxheim-acme renew requires the `acme-client` feature".into())
}

#[cfg(all(feature = "acme-client", unix))]
fn request_certificate_reload(config: &Config) -> Result<(), Box<dyn Error + Send + Sync>> {
    let path = &config.server.process.certificate_reload_sock;
    let mut stream = std::os::unix::net::UnixStream::connect(path)?;
    stream.write_all(b"reload-certificates\n")?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    let response = response.trim();
    if response == "ok" {
        println!("certificate reload: ok");
        return Ok(());
    }
    Err(format!(
        "certificate reload request through {} failed: {response}",
        path.display()
    )
    .into())
}

#[cfg(all(feature = "acme-client", not(unix)))]
fn request_certificate_reload(_config: &Config) -> Result<(), Box<dyn Error + Send + Sync>> {
    Err("certificate reload control socket requires Unix domain sockets".into())
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
    #[cfg(all(feature = "acme-client", unix))]
    use super::request_certificate_reload;
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

    #[cfg(all(feature = "acme-client", unix))]
    #[test]
    fn certificate_reload_request_sends_control_command() {
        use std::io::{Read, Write};

        let root = std::env::temp_dir().join(format!("fh-acme-reload-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        let socket = root.join("reload.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0_u8; 64];
            let bytes = stream.read(&mut buffer).unwrap();
            assert_eq!(&buffer[..bytes], b"reload-certificates\n");
            stream.write_all(b"ok\n").unwrap();
        });

        let mut config = crate::config::Config::default();
        config.server.process.certificate_reload_sock = socket;

        request_certificate_reload(&config).unwrap();
        handle.join().unwrap();
    }
}
