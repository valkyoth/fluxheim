use std::sync::OnceLock;

type AdminHmacSha256 = fn(&'static str, &[u8], &[u8]) -> [u8; 32];

static ADMIN_HMAC_SHA256: OnceLock<AdminHmacSha256> = OnceLock::new();

pub fn set_admin_hmac_sha256(function: AdminHmacSha256) {
    let _ = ADMIN_HMAC_SHA256.set(function);
}

pub(crate) fn admin_hmac_sha256_or_abort(
    context: &'static str,
    key: &[u8],
    message: &[u8],
) -> [u8; 32] {
    ADMIN_HMAC_SHA256
        .get()
        .copied()
        .unwrap_or(ring_admin_hmac_sha256)(context, key, message)
}

fn ring_admin_hmac_sha256(_context: &'static str, key: &[u8], message: &[u8]) -> [u8; 32] {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key);
    let tag = ring::hmac::sign(&key, message);
    let mut digest = [0_u8; 32];
    digest.copy_from_slice(tag.as_ref());
    digest
}
