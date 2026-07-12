use super::*;
use fluxheim_config::normalize_host;

#[cfg(target_os = "linux")]
fn open_regular_http_01_challenge_file(path: &Path) -> io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(UNIX_O_NOFOLLOW)
        .open(path)
}

#[cfg(not(target_os = "linux"))]
fn open_regular_http_01_challenge_file(path: &Path) -> io::Result<std::fs::File> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ACME HTTP-01 challenge file is not a regular file",
        ));
    }

    std::fs::File::open(path)
}

pub struct AcmeHttp01ChallengeStore {
    pub(super) root: PathBuf,
}

impl AcmeHttp01ChallengeStore {
    pub fn new(storage: &Path, vhost_name: &str) -> Self {
        Self {
            root: storage
                .join(HTTP_01_CHALLENGE_DIR)
                .join(managed_certificate_segment(vhost_name)),
        }
    }

    pub fn install_key_authorization(&self, token: &str, value: &str) -> io::Result<()> {
        if !valid_http_01_token(token) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid ACME HTTP-01 token",
            ));
        }
        if !valid_http_01_key_authorization(value) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid ACME HTTP-01 key authorization",
            ));
        }

        self.ensure_root_directory()?;
        let _mutation_lock = AcmeMutationLock::acquire(&self.root)?;
        let token_path = self.token_path(token)?;
        let tmp_path = self.root.join(format!(
            ".challenge-{}-{}.tmp",
            short_sha256_hex(token.as_bytes()),
            unique_transaction_id()?
        ));
        let value = value.trim_end_matches(['\r', '\n']);

        let result = (|| {
            write_challenge_file(&tmp_path, value.as_bytes())?;
            self.ensure_regular_or_missing(&token_path)?;
            fs::rename(&tmp_path, &token_path)?;
            sync_directory_io(&self.root)
        })();

        if result.is_err() {
            let _ = fs::remove_file(&tmp_path);
        }

        result
    }

    pub fn load_key_authorization(&self, token: &str) -> io::Result<Option<String>> {
        if !valid_http_01_token(token) {
            return Ok(None);
        }
        let mut path = self.root.clone();
        let mut components = Path::new(token).components();
        match (components.next(), components.next()) {
            (Some(Component::Normal(component)), None) => path.push(component),
            _ => return Ok(None),
        }

        let file = match open_regular_http_01_challenge_file(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let metadata = file.metadata()?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Ok(None);
        }
        if metadata.len() > MAX_HTTP_01_KEY_AUTHORIZATION_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ACME HTTP-01 key authorization is too large",
            ));
        }

        let mut value = String::new();
        file.take(MAX_HTTP_01_KEY_AUTHORIZATION_BYTES.saturating_add(1))
            .read_to_string(&mut value)?;
        if value.len() as u64 > MAX_HTTP_01_KEY_AUTHORIZATION_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ACME HTTP-01 key authorization is too large",
            ));
        }
        if !valid_http_01_key_authorization(&value) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ACME HTTP-01 key authorization contains invalid bytes",
            ));
        }

        Ok(Some(value.trim_end_matches(['\r', '\n']).to_owned()))
    }

    pub fn remove_key_authorization(&self, token: &str) -> io::Result<bool> {
        if !valid_http_01_token(token) {
            return Ok(false);
        }
        self.ensure_root_directory()?;
        let _mutation_lock = AcmeMutationLock::acquire(&self.root)?;
        let mut path = self.root.clone();
        let mut components = Path::new(token).components();
        match (components.next(), components.next()) {
            (Some(Component::Normal(component)), None) => path.push(component),
            _ => return Ok(false),
        }

        let file = match open_regular_http_01_challenge_file(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        };
        let metadata = file.metadata()?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Ok(false);
        }
        drop(file);

        let tombstone = self.root.join(format!(
            ".removed-challenge-{}-{}.tmp",
            short_sha256_hex(token.as_bytes()),
            unique_transaction_id()?
        ));
        fs::rename(&path, &tombstone)?;
        std::fs::remove_file(&tombstone)?;
        sync_directory_io(&self.root)?;
        Ok(true)
    }

    fn ensure_root_directory(&self) -> io::Result<()> {
        #[cfg(unix)]
        {
            crate::acme_directory::create_private_directory_all(&self.root)?;
            Ok(())
        }

        #[cfg(not(unix))]
        {
            reject_existing_symlink_in_path(&self.root)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
            fs::create_dir_all(&self.root)?;
            reject_existing_symlink_in_path(&self.root)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
            let metadata = fs::symlink_metadata(&self.root)?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "ACME HTTP-01 challenge root is not a real directory",
                ));
            }
            Ok(())
        }
    }

    fn token_path(&self, token: &str) -> io::Result<PathBuf> {
        if !valid_http_01_token(token) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid ACME HTTP-01 token",
            ));
        }
        let mut components = Path::new(token).components();
        let Some(Component::Normal(component)) = components.next() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid ACME HTTP-01 token",
            ));
        };
        if components.next().is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid ACME HTTP-01 token",
            ));
        }

        let mut path = self.root.clone();
        path.push(component);
        Ok(path)
    }

    fn ensure_regular_or_missing(&self, path: &Path) -> io::Result<()> {
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "ACME HTTP-01 challenge destination is not a regular file",
                ))
            }
            Ok(_) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AcmeTlsAlpn01ChallengeStore {
    root: PathBuf,
}

impl AcmeTlsAlpn01ChallengeStore {
    pub fn new(storage: &Path) -> Self {
        Self {
            root: storage.join(TLS_ALPN_01_CHALLENGE_DIR),
        }
    }

    pub fn install_challenge_certificate(
        &self,
        domain: &str,
        fullchain_pem: &[u8],
        private_key_pem: &[u8],
    ) -> Result<AcmeCertificatePaths, AcmeCertificateInstallError> {
        let paths = self.certificate_paths_for_domain(domain).ok_or_else(|| {
            AcmeCertificateInstallError::UnsafePath {
                path: self.root.clone(),
                message: "invalid ACME TLS-ALPN-01 domain".to_owned(),
            }
        })?;
        validate_issued_material(
            fullchain_pem,
            private_key_pem,
            std::slice::from_ref(&normalize_host(domain).ok_or({
                AcmeCertificateInstallError::InvalidCertificatePem(
                    "TLS-ALPN certificate domain is invalid",
                )
            })?),
        )?;
        let owner = managed_certificate_owner(&self.root)?;
        install_certificate_files(&paths, fullchain_pem, private_key_pem, owner)?;
        Ok(paths)
    }

    pub fn remove_challenge_certificate(&self, domain: &str) -> io::Result<bool> {
        let Some(paths) = self.certificate_paths_for_domain(domain) else {
            return Ok(false);
        };
        let directory = paths.cert_path.parent().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "ACME TLS-ALPN-01 challenge path has no parent directory",
            )
        })?;
        match fs::symlink_metadata(directory) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "ACME TLS-ALPN-01 challenge directory is not a real directory",
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        }
        let _mutation_lock = AcmeMutationLock::acquire(directory)?;

        let mut removed = false;
        for path in [&paths.cert_path, &paths.key_path] {
            let metadata = match fs::symlink_metadata(path) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            };
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "ACME TLS-ALPN-01 challenge destination is not a regular file",
                ));
            }
            fs::remove_file(path)?;
            removed = true;
        }

        sync_directory_io(directory)?;

        Ok(removed)
    }

    pub fn certificate_paths_for_sni(&self, sni: &str) -> Option<AcmeCertificatePaths> {
        self.certificate_paths_for_domain(sni)
    }

    fn certificate_paths_for_domain(&self, domain: &str) -> Option<AcmeCertificatePaths> {
        let normalized = normalize_host(domain)?;
        let directory = self.root.join(managed_certificate_segment(&normalized));
        Some(AcmeCertificatePaths {
            cert_path: directory.join(MANAGED_FULLCHAIN_FILE),
            key_path: directory.join(MANAGED_PRIVATE_KEY_FILE),
        })
    }
}

pub(super) fn cleanup_http_01_challenges(
    store: &AcmeHttp01ChallengeStore,
    tokens: &[String],
) -> Result<(), AcmeRenewalError> {
    for token in tokens {
        store
            .remove_key_authorization(token)
            .map_err(|error| AcmeRenewalError::Challenge {
                token: token.clone(),
                error,
            })?;
    }
    Ok(())
}

pub(super) fn acme_client_error_message_with_http_01_context(
    error: impl std::fmt::Display,
    domains: &[String],
    tokens: &[String],
) -> String {
    let message = error.to_string();
    let urls = http_01_challenge_urls(domains, tokens);
    if urls.is_empty() {
        return message;
    }
    format!("{message}; published_http_01={}", urls.join(","))
}

fn http_01_challenge_urls(domains: &[String], tokens: &[String]) -> Vec<String> {
    let mut urls = Vec::new();
    for domain in domains {
        for token in tokens {
            let token = redacted_http_01_token(token);
            urls.push(format!(
                "http://{domain}/.well-known/acme-challenge/{token}"
            ));
        }
    }
    urls
}

fn redacted_http_01_token(token: &str) -> String {
    if token.is_empty() {
        return "<empty-token>".to_owned();
    }
    format!("<redacted:{}b>", token.len())
}

pub fn http_01_token_from_path(path: &str) -> Option<&str> {
    let token = path.strip_prefix("/.well-known/acme-challenge/")?;
    if token.is_empty() || token.contains('/') {
        return None;
    }
    valid_http_01_token(token).then_some(token)
}
