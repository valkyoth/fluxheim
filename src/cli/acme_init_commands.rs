use std::error::Error;
#[cfg(feature = "acme-client")]
use std::io::{self, Read, Write};
#[cfg(feature = "acme-client")]
use std::path::{Path, PathBuf};

#[cfg(feature = "acme-client")]
use zeroize::Zeroizing;

#[cfg(feature = "acme-client")]
use super::AcmeInitIssuer;
use super::AcmeInitOptions;

#[cfg(feature = "acme-client")]
pub(super) fn run_acme_init_command(
    options: AcmeInitOptions,
) -> Result<(), Box<dyn Error + Send + Sync>> {
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
                include_str!("../../packaging/systemd/actalis-eab.conf"),
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
    println!("next: run `fluxheim --config /etc/fluxheim/fluxheim.toml acme-renew`");
    Ok(())
}

#[cfg(not(feature = "acme-client"))]
pub(super) fn run_acme_init_command(
    options: AcmeInitOptions,
) -> Result<(), Box<dyn Error + Send + Sync>> {
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
    automation: String,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    key_id_file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_id_credential: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hmac_key_file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hmac_key_credential: Option<String>,
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
        let eab = if use_systemd_credentials {
            AcmeInitEabToml {
                key_id_file: None,
                key_id_credential: Some("actalis-eab-kid".to_owned()),
                hmac_key_file: None,
                hmac_key_credential: Some("actalis-eab-hmac-key".to_owned()),
            }
        } else {
            AcmeInitEabToml {
                key_id_file: Some(secrets_dir.join("actalis-eab-kid").display().to_string()),
                key_id_credential: None,
                hmac_key_file: Some(
                    secrets_dir
                        .join("actalis-eab-hmac-key")
                        .display()
                        .to_string(),
                ),
                hmac_key_credential: None,
            }
        };
        vec![AcmeInitIssuerToml {
            name: issuer.name().to_owned(),
            directory_url: issuer.directory_url().to_owned(),
            eab,
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
                automation: if use_systemd_credentials {
                    "external".to_owned()
                } else {
                    "background".to_owned()
                },
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
) -> Result<Zeroizing<String>, Box<dyn Error + Send + Sync>> {
    if let Some(path) = path {
        validate_acme_init_output_path("secret input", path)?;
        let mut secret = Zeroizing::new(String::new());
        let file = std::fs::File::open(path)?;
        file.take(4097).read_to_string(&mut secret)?;
        if secret.len() > 4096 {
            return Err("ACME secret input file cannot exceed 4096 bytes".into());
        }
        return Ok(Zeroizing::new(secret.trim().to_owned()));
    }
    if non_interactive {
        return Err("EAB secret files are required with --non-interactive".into());
    }
    let secret = Zeroizing::new(rpassword::prompt_password(prompt)?);
    Ok(Zeroizing::new(secret.trim().to_owned()))
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
    if existing_parent_has_insecure_write_permissions(path)? {
        return Err(format!(
            "{field} must not be below a group- or world-writable parent: {}",
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
fn existing_parent_has_insecure_write_permissions(
    path: &Path,
) -> Result<bool, Box<dyn Error + Send + Sync>> {
    fluxheim_config::fs_trust::existing_parent_has_insecure_write_permissions(path)
        .map_err(|error| error.into())
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
