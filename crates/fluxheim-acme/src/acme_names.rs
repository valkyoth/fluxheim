use sha2::{Digest, Sha256};

use super::{MAX_HTTP_01_KEY_AUTHORIZATION_BYTES, MAX_HTTP_01_TOKEN_BYTES};

pub(super) fn normalized_domain(domain: &str) -> String {
    domain.trim().trim_end_matches('.').to_ascii_lowercase()
}

pub(super) fn managed_certificate_segment(vhost_name: &str) -> String {
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

pub(super) fn short_sha256_hex(input: &[u8]) -> String {
    let digest = Sha256::digest(input);
    let mut value = String::with_capacity(16);
    for byte in &digest[..8] {
        use std::fmt::Write as _;
        let _ = write!(value, "{byte:02x}");
    }
    value
}

pub(super) fn valid_http_01_token(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= MAX_HTTP_01_TOKEN_BYTES
        && token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

pub(super) fn valid_http_01_key_authorization(value: &str) -> bool {
    let value = value.trim_end_matches(['\r', '\n']);
    !value.is_empty()
        && value.len() as u64 <= MAX_HTTP_01_KEY_AUTHORIZATION_BYTES
        && !value.bytes().any(|byte| {
            byte == b'\0' || byte == b'\r' || byte == b'\n' || byte < 0x20 || byte == 0x7f
        })
}
