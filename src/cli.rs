use std::error::Error;
#[cfg(feature = "acme-client")]
use std::io::{self, Write};
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
        /// Confirm that all configured ACME vhosts should be attempted.
        #[arg(long)]
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
    validate_web_runtime_config(&config.web)?;
    for vhost in &config.vhosts {
        validate_web_runtime_config(&vhost.web)?;
        for route in &vhost.routes {
            if let Some(web) = &route.web {
                validate_web_runtime_config(web)?;
            }
        }
    }
    Ok(())
}

#[cfg(all(feature = "web", not(feature = "proxy")))]
fn validate_web_runtime_config(
    config: &crate::config::WebConfig,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    crate::web::StaticFileServer::from_config(config)?;
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
        CliCommand::AcmeRenew { all } => run_acme_renew_command(config_path, *all),
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
    }
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
    all: bool,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    crate::tls::install_rustls_crypto_provider();

    let config = Config::load(config_path)?;
    config.validate()?;
    validate_runtime_config(&config)?;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let now = std::time::SystemTime::now();
    let targets = crate::acme::renewal_targets(&config);
    println!("acme targets: {}", targets.len());
    for target in &targets {
        println!(
            "target: {} issuer={} domains={} cert={} key={}",
            target.vhost_name,
            target.issuer,
            target.domains.join(","),
            target.certificate.cert_path.display(),
            target.certificate.key_path.display()
        );
    }
    if targets.is_empty() {
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

    let run = if all {
        runtime.block_on(crate::acme::renew_all_instant_acme_targets(&config, now))?
    } else {
        runtime.block_on(crate::acme::renew_due_instant_acme_targets(&config, now))?
    };

    println!("acme attempted: {}", run.attempted);
    if all && !targets.is_empty() && run.attempted == 0 {
        return Err("ACME renewal planner produced targets, but --all attempted none".into());
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
    println!("next: run `fluxheim --config /etc/fluxheim/fluxheim.toml acme-renew --all`");
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
    key_id_file: String,
    hmac_key_file: String,
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
        let (key_id_file, hmac_key_file) = if use_systemd_credentials {
            (
                "/run/credentials/fluxheim.service/actalis-eab-kid".to_owned(),
                "/run/credentials/fluxheim.service/actalis-eab-hmac-key".to_owned(),
            )
        } else {
            (
                secrets_dir.join("actalis-eab-kid").display().to_string(),
                secrets_dir
                    .join("actalis-eab-hmac-key")
                    .display()
                    .to_string(),
            )
        };
        vec![AcmeInitIssuerToml {
            name: issuer.name().to_owned(),
            directory_url: issuer.directory_url().to_owned(),
            eab: AcmeInitEabToml {
                key_id_file,
                hmac_key_file,
            },
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

        assert!(error.to_string().contains("web root does not exist"));
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
        assert!(
            config.contains("key_id_file = \"/run/credentials/fluxheim.service/actalis-eab-kid\"")
        );
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
