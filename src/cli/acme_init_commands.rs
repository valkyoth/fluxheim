use std::error::Error;
#[cfg(feature = "acme-client")]
use std::io::{self, Read, Write};
#[cfg(feature = "acme-client")]
use std::path::{Path, PathBuf};

#[cfg(feature = "acme-client")]
use sanitization::{SecretString, SecretVec};

#[cfg(feature = "acme-client")]
use super::acme_init_toml::build_acme_init_toml;
use super::command_options::AcmeInitOptions;

#[cfg(feature = "acme-client")]
pub(super) fn run_acme_init_command(
    options: AcmeInitOptions,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let issuer_name = options.issuer.name();
    if !options.accept_terms_of_service {
        return Err("acme-init requires --accept-terms-of-service".into());
    }
    let terms_of_service_url = options
        .terms_of_service_url
        .as_deref()
        .ok_or("acme-init requires --terms-of-service-url")?;
    if !terms_of_service_url.starts_with("https://")
        || terms_of_service_url.chars().any(char::is_whitespace)
    {
        return Err("--terms-of-service-url must be an HTTPS URL".into());
    }
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
        kid.try_with_secret(|secret| write_secret_file(&kid_path, secret, options.force))??;
        hmac_key
            .try_with_secret(|secret| write_secret_file(&hmac_key_path, secret, options.force))??;
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
        terms_of_service_url,
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
        terms_of_service_url,
        accept_terms_of_service,
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
        terms_of_service_url,
        accept_terms_of_service,
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
) -> Result<SecretString, Box<dyn Error + Send + Sync>> {
    if let Some(path) = path {
        validate_acme_init_output_path("secret input", path)?;
        #[cfg(windows)]
        let file = fluxheim_config::fs_trust::open_confidential_file(path)?;
        #[cfg(not(windows))]
        let file = std::fs::File::open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() > 4096 {
            return Err("ACME secret input file cannot exceed 4096 bytes".into());
        }
        let mut secret = SecretVec::from_fn(metadata.len() as usize, |_| 0);
        let mut limited = file.take(4097);
        secret.with_secret_mut(|bytes| limited.read_exact(bytes))?;
        let mut probe = [0_u8; 1];
        let grew = limited.read(&mut probe)? != 0;
        sanitization::SecureSanitize::secure_sanitize(&mut probe);
        if grew {
            return Err("ACME secret input file cannot exceed 4096 bytes".into());
        }
        return secret
            .with_secret(|bytes| {
                std::str::from_utf8(bytes)
                    .map(|secret| SecretString::from_secret_str(secret.trim()))
            })
            .map_err(Into::into);
    }
    if non_interactive {
        return Err("EAB secret files are required with --non-interactive".into());
    }
    let secret = SecretString::from_string(rpassword::prompt_password(prompt)?);
    Ok(secret.try_with_secret(|secret| SecretString::from_secret_str(secret.trim()))?)
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
    if existing_parent_has_insecure_write_permissions(path)? {
        return Err(format!(
            "{field} must not be below an untrusted writable parent: {}",
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
        #[cfg(windows)]
        use std::os::windows::fs::OpenOptionsExt as _;

        let mut options = std::fs::OpenOptions::new();
        options.write(true);
        if force {
            options.create(true);
        } else {
            options.create_new(true);
        }
        #[cfg(windows)]
        options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
        let mut file = options.open(path)?;
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt as _;

            let metadata = file.metadata()?;
            if !metadata.is_file()
                || metadata.file_attributes()
                    & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
                    != 0
                || same_file::Handle::from_path(path)?
                    != same_file::Handle::from_file(file.try_clone()?)?
            {
                return Err(format!(
                    "output file changed during secure open or is a reparse point: {}",
                    path.display()
                )
                .into());
            }
            fluxheim_config::fs_trust::harden_confidential_file(&mut file)?;
        }
        if force {
            file.set_len(0)?;
        }
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
    }

    #[cfg(unix)]
    set_mode(path, mode)?;
    Ok(())
}

#[cfg(feature = "acme-client")]
fn existing_prefix_contains_symlink(
    path: &Path,
    allow_missing_leaf: bool,
) -> Result<bool, Box<dyn Error + Send + Sync>> {
    #[cfg(windows)]
    {
        use std::path::Component;

        let mut components = path.components();
        if matches!(components.next(), Some(Component::Prefix(_)))
            && !matches!(components.next(), Some(Component::RootDir))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "drive-relative Windows paths are not allowed",
            )
            .into());
        }
    }

    let mut current = PathBuf::new();
    let component_count = path.components().count();
    for (index, component) in path.components().enumerate() {
        current.push(component);
        #[cfg(windows)]
        if matches!(
            component,
            std::path::Component::Prefix(_) | std::path::Component::RootDir
        ) {
            continue;
        }
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if acme_init_metadata_is_link(&metadata) => return Ok(true),
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

#[cfg(feature = "acme-client")]
fn existing_parent_has_insecure_write_permissions(
    path: &Path,
) -> Result<bool, Box<dyn Error + Send + Sync>> {
    fluxheim_config::fs_trust::existing_path_or_parent_has_insecure_write_permissions(path)
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
fn set_mode(path: &Path, _mode: u32) -> io::Result<()> {
    #[cfg(windows)]
    {
        let metadata = std::fs::symlink_metadata(path)?;
        if metadata.is_dir() {
            return fluxheim_config::fs_trust::harden_private_directory(path);
        }
        return Ok(());
    }
    #[cfg(not(windows))]
    let _ = path;
    Ok(())
}

#[cfg(all(feature = "acme-client", windows))]
fn acme_init_metadata_is_link(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;

    metadata.file_attributes()
        & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
        != 0
}

#[cfg(all(feature = "acme-client", not(windows)))]
fn acme_init_metadata_is_link(metadata: &std::fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}
