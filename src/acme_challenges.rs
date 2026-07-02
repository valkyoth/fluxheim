use super::*;
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
        let token_path = self.token_path(token)?;
        let tmp_path = self.root.join(format!(
            ".challenge-{}.tmp",
            short_sha256_hex(token.as_bytes())
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
            std::process::id()
        ));
        let _ = std::fs::remove_file(&tombstone);
        fs::rename(&path, &tombstone)?;
        std::fs::remove_file(&tombstone)?;
        sync_directory_io(&self.root)?;
        Ok(true)
    }

    fn ensure_root_directory(&self) -> io::Result<()> {
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
        validate_certificate_pem(fullchain_pem)?;
        validate_private_key_pem(private_key_pem)?;
        let owner = managed_certificate_owner(&self.root)?;
        install_certificate_files(&paths, fullchain_pem, private_key_pem, owner)?;
        Ok(paths)
    }

    pub fn remove_challenge_certificate(&self, domain: &str) -> io::Result<bool> {
        let Some(paths) = self.certificate_paths_for_domain(domain) else {
            return Ok(false);
        };

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

        if let Some(directory) = paths.cert_path.parent() {
            let _ = fs::remove_dir(directory);
        }
        let _ = fs::remove_dir(&self.root);

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

pub fn http_01_token_from_path(path: &str) -> Option<&str> {
    let token = path.strip_prefix("/.well-known/acme-challenge/")?;
    if token.is_empty() || token.contains('/') {
        return None;
    }
    valid_http_01_token(token).then_some(token)
}
