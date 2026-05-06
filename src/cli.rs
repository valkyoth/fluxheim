use std::error::Error;
use std::path::PathBuf;

use clap::{Parser, Subcommand};

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

    /// Validate TLS certificate/key files and ACME storage permissions.
    #[arg(long)]
    pub check_tls_storage: bool,

    /// Classify whether OLD_CONFIG can be hot-reloaded into --config.
    #[arg(long, value_name = "OLD_CONFIG", conflicts_with_all = ["check_config", "check_tls_storage"])]
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

    if cli.check_tls_storage {
        return check_tls_storage(&config);
    }

    crate::runtime::run(config)
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
    }
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
