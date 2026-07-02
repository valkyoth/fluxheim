use std::error::Error;
use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[path = "acme_companion_commands.rs"]
mod commands;
#[path = "acme_companion_config.rs"]
mod config_loader;
#[path = "acme_companion_reload.rs"]
mod reload;

use commands::{print_status, print_targets, run_renew};
use reload::request_certificate_reload_for_config;
#[cfg(all(feature = "acme-client", unix, test))]
use reload::{MAX_CERTIFICATE_RELOAD_RESPONSE_BYTES, request_certificate_reload};

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
    #[cfg(all(feature = "tls-rustls-backend", not(feature = "tls-openssl")))]
    crate::tls::install_rustls_crypto_provider()?;

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

#[cfg(test)]
mod tests {
    #[cfg(all(feature = "acme-client", unix))]
    use super::request_certificate_reload;
    #[cfg(any(feature = "acme", feature = "acme-client"))]
    use super::run_from_args;

    #[cfg(any(feature = "acme", feature = "acme-client"))]
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
    fn certificate_reload_response_is_bounded() {
        use std::io::{Read, Write};

        let root =
            std::env::temp_dir().join(format!("fh-acme-reload-bounded-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        let socket = root.join("reload.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0_u8; 64];
            let bytes = stream.read(&mut buffer).unwrap();
            assert_eq!(&buffer[..bytes], b"reload-certificates\n");
            stream.write_all(b"not-ok").unwrap();
            stream
                .write_all(&vec![
                    b'x';
                    (super::MAX_CERTIFICATE_RELOAD_RESPONSE_BYTES as usize)
                        * 2
                ])
                .unwrap();
        });

        let mut config = crate::config::Config::default();
        config.server.process.certificate_reload_sock = socket;
        let error = request_certificate_reload(&config).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("certificate reload request through"),
            "{error}"
        );
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
