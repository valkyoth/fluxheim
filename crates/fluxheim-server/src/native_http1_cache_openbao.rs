use std::fmt::Write as _;
use std::sync::Arc;

use fluxheim_config::CacheDiskEncryptionConfig;
use sanitization::SecretString;
use zeroize::Zeroizing;

use super::{
    NativeDiskCacheEncryptionProvider, native_cache_encryption_credential_path,
    read_native_cache_encryption_secret_file,
};

const OPENBAO_TRANSIT_RESPONSE_OVERHEAD_BYTES: u64 = 4096;
const OPENBAO_TRANSIT_MAX_RESPONSE_BYTES: u64 = 512 * 1024 * 1024;

pub(super) fn native_openbao_transit_provider(
    config: &CacheDiskEncryptionConfig,
) -> std::io::Result<NativeDiskCacheEncryptionProvider> {
    let token = match (
        &config.openbao.token_file,
        config.openbao.token_credential.as_deref(),
    ) {
        (Some(path), None) => read_native_cache_encryption_secret_file(path)?,
        (None, Some(credential)) => {
            let path = native_cache_encryption_credential_path(credential);
            read_native_cache_encryption_secret_file(&path)?
        }
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "native disk cache encryption requires exactly one OpenBao token source",
            ));
        }
    };
    if token.trim().is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "native disk cache OpenBao token must not be empty",
        ));
    }
    let token = SecretString::from_secret_str(token.trim());
    Ok(NativeDiskCacheEncryptionProvider::OpenBaoTransit {
        address: Arc::from(
            config
                .openbao
                .address
                .as_deref()
                .unwrap_or_default()
                .trim()
                .trim_end_matches('/'),
        ),
        mount: Arc::from(
            config
                .openbao
                .mount
                .as_deref()
                .unwrap_or_default()
                .trim_matches('/'),
        ),
        key_name: Arc::from(
            config
                .openbao
                .key_name
                .as_deref()
                .unwrap_or_default()
                .trim_matches('/'),
        ),
        token,
    })
}

pub(super) fn openbao_transit_encrypt(
    address: &str,
    mount: &str,
    key_name: &str,
    token: &str,
    plaintext: &[u8],
    aad: &[u8],
) -> std::io::Result<String> {
    let plaintext = base64_standard_encode(plaintext)?;
    let associated_data = base64_standard_encode(aad)?;
    let request = serde_json::json!({
        "plaintext": plaintext,
        "associated_data": associated_data,
    });
    let mut response = openbao_transit_agent()
        .post(openbao_transit_url(address, mount, "encrypt", key_name))
        .header("X-Vault-Token", token)
        .header("Accept", "application/json")
        .send_json(request)
        .map_err(|error| openbao_io_error("encrypt", error))?;
    let value = openbao_transit_read_json(
        &mut response,
        "encrypt response",
        openbao_transit_response_limit(plaintext.len().max(associated_data.len()) as u64),
    )?;
    value
        .pointer("/data/ciphertext")
        .and_then(serde_json::Value::as_str)
        .filter(|value| value.starts_with("vault:v"))
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "OpenBao Transit encrypt response did not include a ciphertext",
            )
        })
}

pub(super) fn openbao_transit_decrypt(
    address: &str,
    mount: &str,
    key_name: &str,
    token: &str,
    ciphertext: &str,
    aad: &[u8],
) -> std::io::Result<Zeroizing<Vec<u8>>> {
    let associated_data = base64_standard_encode(aad)?;
    let request = serde_json::json!({
        "ciphertext": ciphertext,
        "associated_data": associated_data,
    });
    let mut response = openbao_transit_agent()
        .post(openbao_transit_url(address, mount, "decrypt", key_name))
        .header("X-Vault-Token", token)
        .header("Accept", "application/json")
        .send_json(request)
        .map_err(|error| openbao_io_error("decrypt", error))?;
    let value = openbao_transit_read_json(
        &mut response,
        "decrypt response",
        openbao_transit_response_limit(ciphertext.len().max(associated_data.len()) as u64),
    )?;
    let plaintext = value
        .pointer("/data/plaintext")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "OpenBao Transit decrypt response did not include plaintext",
            )
        })?;
    let decoded = base64_ng::STANDARD
        .decode_vec(plaintext.as_bytes())
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "OpenBao Transit decrypt response plaintext is not valid base64",
            )
        })?;
    Ok(Zeroizing::new(decoded))
}

fn openbao_transit_agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .max_redirects(0)
        .http_status_as_error(false)
        .build()
        .into()
}

fn openbao_transit_response_limit(input_bytes: u64) -> u64 {
    input_bytes
        .saturating_mul(2)
        .saturating_add(OPENBAO_TRANSIT_RESPONSE_OVERHEAD_BYTES)
        .min(OPENBAO_TRANSIT_MAX_RESPONSE_BYTES)
}

fn openbao_transit_read_json(
    response: &mut ureq::http::Response<ureq::Body>,
    operation: &str,
    max_response_bytes: u64,
) -> std::io::Result<serde_json::Value> {
    let body = Zeroizing::new(
        response
            .body_mut()
            .with_config()
            .limit(max_response_bytes.saturating_add(1))
            .read_to_vec()
            .map_err(|error| openbao_io_error(operation, error))?,
    );
    if body.len() as u64 > max_response_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("OpenBao Transit {operation} exceeded response size limit"),
        ));
    }
    serde_json::from_slice(&body).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("OpenBao Transit {operation} returned invalid JSON: {error}"),
        )
    })
}

fn base64_standard_encode(input: &[u8]) -> std::io::Result<String> {
    base64_ng::STANDARD.encode_string(input).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("base64 encode failed: {error}"),
        )
    })
}

fn openbao_io_error(operation: &str, error: ureq::Error) -> std::io::Error {
    std::io::Error::other(format!("OpenBao Transit {operation} failed: {error}"))
}

fn openbao_transit_url(address: &str, mount: &str, operation: &str, key_name: &str) -> String {
    format!(
        "{}/v1/{}/{}/{}",
        address.trim_end_matches('/'),
        openbao_path_encode(mount.trim_matches('/')),
        operation,
        openbao_path_encode(key_name.trim_matches('/'))
    )
}

fn openbao_path_encode(value: &str) -> String {
    value
        .split('/')
        .map(percent_encode_openbao_path_segment)
        .collect::<Vec<_>>()
        .join("/")
}

fn percent_encode_openbao_path_segment(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(byte as char);
        } else {
            let _ = write!(encoded, "%{byte:02X}");
        }
    }
    encoded
}
