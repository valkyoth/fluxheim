use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};

use sha2::{Digest, Sha256};

const HTTP_01_CHALLENGE_DIR: &str = "http-01";
const MANAGED_CERTIFICATE_DIR: &str = "certificates";
const MANAGED_FULLCHAIN_FILE: &str = "fullchain.pem";
const MANAGED_PRIVATE_KEY_FILE: &str = "privkey.pem";
const MAX_HTTP_01_TOKEN_BYTES: usize = 256;
const MAX_HTTP_01_KEY_AUTHORIZATION_BYTES: u64 = 4096;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeHttp1AcmeHttp01Store {
    root: PathBuf,
}

impl NativeHttp1AcmeHttp01Store {
    pub fn new(storage: &Path, vhost_name: &str) -> Self {
        Self {
            root: storage
                .join(HTTP_01_CHALLENGE_DIR)
                .join(managed_certificate_segment(vhost_name)),
        }
    }

    #[cfg(test)]
    pub(crate) fn root_for_tests(&self) -> &Path {
        &self.root
    }

    pub fn load_key_authorization(&self, token: &str) -> io::Result<Option<String>> {
        if !valid_http_01_token(token) {
            return Ok(None);
        }
        let mut components = Path::new(token).components();
        let path = match (components.next(), components.next()) {
            (Some(Component::Normal(component)), None) => self.root.join(component),
            _ => return Ok(None),
        };

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
}

pub(crate) fn native_managed_certificate_config(
    storage: &Path,
    vhost_name: &str,
) -> fluxheim_config::StaticCertificateConfig {
    let directory = storage
        .join(MANAGED_CERTIFICATE_DIR)
        .join(managed_certificate_segment(vhost_name));
    fluxheim_config::StaticCertificateConfig {
        cert_path: directory.join(MANAGED_FULLCHAIN_FILE),
        key_path: directory.join(MANAGED_PRIVATE_KEY_FILE),
    }
}

pub fn http_01_token_from_path(path: &str) -> Option<&str> {
    let token = path.strip_prefix("/.well-known/acme-challenge/")?;
    if token.is_empty() || token.contains('/') {
        return None;
    }
    valid_http_01_token(token).then_some(token)
}

#[cfg(target_os = "linux")]
fn open_regular_http_01_challenge_file(path: &Path) -> io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(0o400000)
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

fn valid_http_01_token(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= MAX_HTTP_01_TOKEN_BYTES
        && token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn valid_http_01_key_authorization(value: &str) -> bool {
    let value = value.trim_end_matches(['\r', '\n']);
    !value.is_empty()
        && value.len() as u64 <= MAX_HTTP_01_KEY_AUTHORIZATION_BYTES
        && !value.bytes().any(|byte| {
            byte == b'\0' || byte == b'\r' || byte == b'\n' || byte < 0x20 || byte == 0x7f
        })
}

fn managed_certificate_segment(vhost_name: &str) -> String {
    let normalized = vhost_name.trim().to_ascii_lowercase();
    let mut slug = String::with_capacity(normalized.len().min(48));
    let mut last_was_separator = false;

    for character in normalized.chars() {
        let safe = character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-');
        let next = if safe { character } else { '-' };
        if next == '-' && last_was_separator {
            continue;
        }
        last_was_separator = next == '-';
        slug.push(next);
        if slug.len() >= 48 {
            break;
        }
    }

    let slug = slug.trim_matches(['.', '_', '-']);
    let slug = if slug.is_empty() { "vhost" } else { slug };
    format!("{slug}-{}", short_sha256_hex(vhost_name.as_bytes()))
}

fn short_sha256_hex(input: &[u8]) -> String {
    let digest = Sha256::digest(input);
    let mut value = String::with_capacity(16);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in &digest[..8] {
        value.push(HEX[(byte >> 4) as usize] as char);
        value.push(HEX[(byte & 0x0f) as usize] as char);
    }
    value
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::{NativeHttp1AcmeHttp01Store, http_01_token_from_path};

    #[test]
    fn native_acme_http_01_store_loads_safe_token_file() {
        let root = tempfile::tempdir().unwrap();
        let store = NativeHttp1AcmeHttp01Store::new(root.path(), "Example Site");
        std::fs::create_dir_all(&store.root).unwrap();
        let path = store.root.join("token_123");
        let mut file = std::fs::File::create(path).unwrap();
        file.write_all(b"token.key.authorization\n").unwrap();

        assert_eq!(
            store.load_key_authorization("token_123").unwrap(),
            Some("token.key.authorization".to_owned())
        );
    }

    #[test]
    fn native_acme_http_01_rejects_unsafe_token_paths() {
        assert_eq!(
            http_01_token_from_path("/.well-known/acme-challenge/token_123"),
            Some("token_123")
        );
        assert_eq!(
            http_01_token_from_path("/.well-known/acme-challenge/../token"),
            None
        );
        assert_eq!(
            http_01_token_from_path("/.well-known/acme-challenge/token/extra"),
            None
        );
    }
}
