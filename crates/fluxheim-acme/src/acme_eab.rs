use std::io;
use std::io::Read;
use std::path::{Path, PathBuf};

use sanitization::{SecretString, SecretVec};

use fluxheim_config::AcmeExternalAccountBindingConfig;

#[cfg(target_os = "linux")]
use super::UNIX_O_NOFOLLOW;
use super::{AcmeExternalAccountBindingSecrets, AcmeSecretLoadError, MAX_EAB_SECRET_BYTES};

#[cfg(feature = "acme-client")]
use super::AcmeInstantClientError;

pub(super) fn load_external_account_binding_from_config(
    issuer: &str,
    eab: &AcmeExternalAccountBindingConfig,
) -> Result<AcmeExternalAccountBindingSecrets, AcmeSecretLoadError> {
    Ok(AcmeExternalAccountBindingSecrets {
        key_id: load_eab_secret(
            issuer,
            "key_id",
            eab.key_id_env.as_deref(),
            eab.key_id_file.as_deref(),
            eab.key_id_credential.as_deref(),
        )?,
        hmac_key: load_eab_secret(
            issuer,
            "hmac_key",
            eab.hmac_key_env.as_deref(),
            eab.hmac_key_file.as_deref(),
            eab.hmac_key_credential.as_deref(),
        )?,
    })
}

#[cfg(feature = "acme-client")]
pub(super) fn external_account_key_from_secrets(
    issuer: &str,
    secrets: &AcmeExternalAccountBindingSecrets,
) -> Result<instant_acme::ExternalAccountKey, AcmeInstantClientError> {
    let key_bytes = secrets
        .hmac_key
        .try_with_secret(|value| decode_eab_hmac_key(issuer, value))
        .map_err(
            |_| AcmeInstantClientError::InvalidExternalAccountBindingHmacKey {
                issuer: issuer.to_owned(),
                message: "EAB HMAC key is not valid UTF-8".to_owned(),
            },
        )??;
    let key_id = secrets.key_id.try_with_secret(str::to_owned).map_err(|_| {
        AcmeInstantClientError::InvalidExternalAccountBindingHmacKey {
            issuer: issuer.to_owned(),
            message: "EAB key ID is not valid UTF-8".to_owned(),
        }
    })?;
    Ok(key_bytes.with_secret(|key| instant_acme::ExternalAccountKey::new(key_id, key)))
}

#[cfg(feature = "acme-client")]
pub(crate) fn decode_eab_hmac_key(
    issuer: &str,
    value: &str,
) -> Result<SecretVec, AcmeInstantClientError> {
    if let Some(decoded) =
        decoded_eab_hmac_key(base64_ng::URL_SAFE_NO_PAD.decode_vec(value.as_bytes()))
    {
        return Ok(decoded);
    }
    if let Some(decoded) = decoded_eab_hmac_key(base64_ng::URL_SAFE.decode_vec(value.as_bytes())) {
        return Ok(decoded);
    }
    if let Some(decoded) =
        decoded_eab_hmac_key(base64_ng::STANDARD_NO_PAD.decode_vec(value.as_bytes()))
    {
        return Ok(decoded);
    }
    if let Some(decoded) = decoded_eab_hmac_key(base64_ng::STANDARD.decode_vec(value.as_bytes())) {
        return Ok(decoded);
    }

    Err(
        AcmeInstantClientError::InvalidExternalAccountBindingHmacKey {
            issuer: issuer.to_owned(),
            message: "expected non-empty base64 or base64url encoded key".to_owned(),
        },
    )
}

#[cfg(feature = "acme-client")]
fn decoded_eab_hmac_key(decoded: Result<Vec<u8>, base64_ng::DecodeError>) -> Option<SecretVec> {
    match decoded {
        Ok(decoded) if !decoded.is_empty() && decoded.len() as u64 <= MAX_EAB_SECRET_BYTES => {
            Some(SecretVec::from_vec(decoded))
        }
        _ => None,
    }
}

fn load_eab_secret(
    issuer: &str,
    field: &'static str,
    env_name: Option<&str>,
    file_path: Option<&Path>,
    credential_name: Option<&str>,
) -> Result<SecretString, AcmeSecretLoadError> {
    let value = match (env_name, file_path, credential_name) {
        (Some(env_name), None, None) => {
            SecretString::from_string(std::env::var(env_name).map_err(|error| {
                AcmeSecretLoadError::EnvRead {
                    issuer: issuer.to_owned(),
                    field,
                    env: env_name.to_owned(),
                    message: error.to_string(),
                }
            })?)
        }
        (None, Some(path), None) => read_eab_secret_file(issuer, field, path)?,
        (None, None, Some(credential_name)) => {
            let path = resolve_eab_credential_path(credential_name);
            read_eab_secret_file(issuer, field, &path)?
        }
        _ => {
            return Err(AcmeSecretLoadError::InvalidSecretSource {
                issuer: issuer.to_owned(),
                field,
            });
        }
    };

    normalize_eab_secret(issuer, field, value)
}

fn resolve_eab_credential_path(credential_name: &str) -> PathBuf {
    std::env::var_os("CREDENTIALS_DIRECTORY")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/run/secrets"))
        .join(credential_name)
}

fn read_eab_secret_file(
    issuer: &str,
    field: &'static str,
    path: &Path,
) -> Result<SecretString, AcmeSecretLoadError> {
    let file = open_regular_eab_secret_file(issuer, field, path)?;
    let metadata = file
        .metadata()
        .map_err(|error| eab_file_error(issuer, field, path, error))?;
    if !metadata.file_type().is_file() {
        return Err(AcmeSecretLoadError::FileRead {
            issuer: issuer.to_owned(),
            field,
            path: path.to_path_buf(),
            message: "not a regular file".to_owned(),
        });
    }
    if metadata.len() > MAX_EAB_SECRET_BYTES {
        return Err(AcmeSecretLoadError::OversizedSecret {
            issuer: issuer.to_owned(),
            field,
            max_bytes: MAX_EAB_SECRET_BYTES,
        });
    }

    let admitted =
        usize::try_from(metadata.len()).map_err(|_| AcmeSecretLoadError::OversizedSecret {
            issuer: issuer.to_owned(),
            field,
            max_bytes: MAX_EAB_SECRET_BYTES,
        })?;
    let mut secret = SecretVec::from_fn(admitted, |_| 0);
    let mut limited = file.take(MAX_EAB_SECRET_BYTES.saturating_add(1));
    secret
        .with_secret_mut(|bytes| limited.read_exact(bytes))
        .map_err(|error| eab_file_error(issuer, field, path, error))?;
    let mut probe = [0_u8; 1];
    let grew = limited
        .read(&mut probe)
        .map_err(|error| eab_file_error(issuer, field, path, error))?
        != 0;
    sanitization::SecureSanitize::secure_sanitize(&mut probe);
    if grew {
        return Err(AcmeSecretLoadError::OversizedSecret {
            issuer: issuer.to_owned(),
            field,
            max_bytes: MAX_EAB_SECRET_BYTES,
        });
    }

    secret
        .with_secret(|bytes| std::str::from_utf8(bytes).map(SecretString::from_secret_str))
        .map_err(|error| AcmeSecretLoadError::FileRead {
            issuer: issuer.to_owned(),
            field,
            path: path.to_path_buf(),
            message: error.to_string(),
        })
}

#[cfg(target_os = "linux")]
fn open_regular_eab_secret_file(
    issuer: &str,
    field: &'static str,
    path: &Path,
) -> Result<std::fs::File, AcmeSecretLoadError> {
    use std::os::unix::fs::OpenOptionsExt;

    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(UNIX_O_NOFOLLOW)
        .open(path)
        .map_err(|error| eab_file_error(issuer, field, path, error))
}

#[cfg(windows)]
fn open_regular_eab_secret_file(
    issuer: &str,
    field: &'static str,
    path: &Path,
) -> Result<std::fs::File, AcmeSecretLoadError> {
    fluxheim_config::fs_trust::open_confidential_file(path)
        .map_err(|error| eab_file_error(issuer, field, path, error))
}

#[cfg(all(not(target_os = "linux"), not(windows)))]
fn open_regular_eab_secret_file(
    issuer: &str,
    field: &'static str,
    path: &Path,
) -> Result<std::fs::File, AcmeSecretLoadError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| eab_file_error(issuer, field, path, error))?;
    if !metadata.file_type().is_file() {
        return Err(AcmeSecretLoadError::FileRead {
            issuer: issuer.to_owned(),
            field,
            path: path.to_path_buf(),
            message: "not a regular file".to_owned(),
        });
    }

    std::fs::File::open(path).map_err(|error| eab_file_error(issuer, field, path, error))
}

fn eab_file_error(
    issuer: &str,
    field: &'static str,
    path: &Path,
    error: io::Error,
) -> AcmeSecretLoadError {
    AcmeSecretLoadError::FileRead {
        issuer: issuer.to_owned(),
        field,
        path: path.to_path_buf(),
        message: error.to_string(),
    }
}

fn normalize_eab_secret(
    issuer: &str,
    field: &'static str,
    value: SecretString,
) -> Result<SecretString, AcmeSecretLoadError> {
    let value = value
        .try_with_secret(|value| SecretString::from_secret_str(value.trim()))
        .map_err(|_| AcmeSecretLoadError::EmptySecret {
            issuer: issuer.to_owned(),
            field,
        })?;
    if value.is_empty() {
        return Err(AcmeSecretLoadError::EmptySecret {
            issuer: issuer.to_owned(),
            field,
        });
    }
    if value.len() as u64 > MAX_EAB_SECRET_BYTES {
        return Err(AcmeSecretLoadError::OversizedSecret {
            issuer: issuer.to_owned(),
            field,
            max_bytes: MAX_EAB_SECRET_BYTES,
        });
    }
    Ok(value)
}
