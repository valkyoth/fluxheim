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

        /// Renew only the named ACME vhost target.
        #[arg(long)]
        vhost: Option<String>,

        /// Do not request a certificate reload from the running gateway after renewal.
        #[arg(long)]
        no_reload: bool,
    },

    /// Print configured ACME renewal targets without contacting an issuer.
    Targets,

    /// Print configured ACME renewal status without contacting an issuer.
    Status {
        /// Show status for only the named ACME vhost target.
        #[arg(long)]
        vhost: Option<String>,
    },

    /// Request certificate-handle reload from the running gateway.
    Reload,
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
            vhost,
            no_reload,
        } => run_renew(
            cli.config.as_deref(),
            force_renew,
            vhost.as_deref(),
            !no_reload,
        ),
        AcmeCompanionCommand::Targets => print_targets(cli.config.as_deref()),
        AcmeCompanionCommand::Status { vhost } => {
            print_status(cli.config.as_deref(), vhost.as_deref())
        }
        AcmeCompanionCommand::Reload => {
            request_certificate_reload_for_config(cli.config.as_deref())
        }
    }
}

#[cfg(feature = "acme-client")]
fn run_renew(
    config_path: Option<&std::path::Path>,
    force_renew: bool,
    vhost: Option<&str>,
    reload_after_renewal: bool,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    crate::tls::install_rustls_crypto_provider();

    let config = load_validated_config(config_path)?;
    if let Some(vhost) = vhost {
        ensure_acme_target_exists(&config, vhost)?;
    }

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let now = std::time::SystemTime::now();
    let run = if let Some(vhost) = vhost {
        runtime.block_on(crate::acme::renew_selected_instant_acme_targets(
            &config,
            now,
            vhost,
            force_renew,
        ))?
    } else if force_renew {
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
    _vhost: Option<&str>,
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

#[cfg(all(feature = "acme-client", unix))]
fn request_certificate_reload_for_config(
    config_path: Option<&std::path::Path>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let config = load_validated_config(config_path)?;
    request_certificate_reload(&config)
}

#[cfg(all(feature = "acme-client", not(unix)))]
fn request_certificate_reload(_config: &Config) -> Result<(), Box<dyn Error + Send + Sync>> {
    Err("certificate reload control socket requires Unix domain sockets".into())
}

#[cfg(any(not(feature = "acme-client"), all(feature = "acme-client", not(unix))))]
fn request_certificate_reload_for_config(
    _config_path: Option<&std::path::Path>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    Err(
        "certificate reload control socket requires Unix domain sockets and the `acme-client` feature"
            .into(),
    )
}

#[cfg(feature = "acme")]
fn print_targets(
    config_path: Option<&std::path::Path>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let config = load_validated_config(config_path)?;
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

#[cfg(feature = "acme")]
fn print_status(
    config_path: Option<&std::path::Path>,
    vhost: Option<&str>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let config = load_validated_config(config_path)?;
    if let Some(vhost) = vhost {
        ensure_acme_target_exists(&config, vhost)?;
    }

    let now = std::time::SystemTime::now();
    let observations = crate::acme::observe_configured_certificates(&config);
    let queue = crate::acme::plan_renewal_queue(&config, &observations, now);
    let items: Vec<_> = queue
        .into_iter()
        .filter(|item| vhost.is_none_or(|name| item.target.vhost_name == name))
        .collect();
    println!("acme status targets: {}", items.len());
    for item in items {
        let status = if item.not_after.is_none() {
            "missing"
        } else if item.due_now {
            "due"
        } else {
            "valid"
        };
        let not_after = item
            .not_after
            .map(system_time_epoch_secs)
            .unwrap_or_else(|| "missing".to_owned());
        println!(
            "target: {} status={} due_now={} due_at={} not_after={} issuer={} domains={} cert={} key={}",
            item.target.vhost_name,
            status,
            item.due_now,
            system_time_epoch_secs(item.due_at),
            not_after,
            item.target.issuer,
            item.target.domains.join(","),
            item.target.certificate.cert_path.display(),
            item.target.certificate.key_path.display()
        );
    }
    Ok(())
}

#[cfg(feature = "acme")]
fn load_validated_config(
    config_path: Option<&std::path::Path>,
) -> Result<Config, Box<dyn Error + Send + Sync>> {
    let config = Config::load(config_path)?;
    config.validate()?;
    crate::cli::validate_compiled_module_config(&config)?;
    Ok(config)
}

#[cfg(feature = "acme")]
fn ensure_acme_target_exists(
    config: &Config,
    vhost: &str,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    if crate::acme::renewal_targets(config)
        .into_iter()
        .any(|target| target.vhost_name == vhost)
    {
        return Ok(());
    }
    Err(format!("unknown ACME vhost target {vhost:?}").into())
}

#[cfg(feature = "acme")]
fn system_time_epoch_secs(time: std::time::SystemTime) -> String {
    match time.duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => duration.as_secs().to_string(),
        Err(_) => "before-unix-epoch".to_owned(),
    }
}

#[cfg(not(feature = "acme"))]
fn print_targets(
    _config_path: Option<&std::path::Path>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    Err("fluxheim-acme requires the `acme` or `acme-client` feature".into())
}

#[cfg(not(feature = "acme"))]
fn print_status(
    _config_path: Option<&std::path::Path>,
    _vhost: Option<&str>,
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

    #[cfg(all(feature = "acme-client", unix))]
    #[test]
    fn reload_command_sends_control_command() {
        use std::ffi::OsString;
        use std::io::{Read, Write};

        let root = std::env::temp_dir().join(format!("fh-acme-reload-cli-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        let socket = root.join("reload.sock");
        let config = root.join("fluxheim.toml");
        std::fs::write(
            &config,
            format!(
                r#"
                [server.process]
                certificate_reload_sock = "{}"
                "#,
                socket.display()
            ),
        )
        .unwrap();

        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0_u8; 64];
            let bytes = stream.read(&mut buffer).unwrap();
            assert_eq!(&buffer[..bytes], b"reload-certificates\n");
            stream.write_all(b"ok\n").unwrap();
        });

        run_from_args([
            OsString::from("fluxheim-acme"),
            OsString::from("--config"),
            config.into_os_string(),
            OsString::from("reload"),
        ])
        .unwrap();
        handle.join().unwrap();
    }
}
