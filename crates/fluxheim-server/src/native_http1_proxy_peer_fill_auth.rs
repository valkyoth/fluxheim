use std::io::Read as _;
use std::path::Path;
use std::sync::Arc;

use sanitization::SecretVec;
use sanitization::ct::ConstantTimeEq;

use crate::{NativeHttp1Request, NativeHttp1Response};
use fluxheim_config::CacheConfig;

pub(crate) const NATIVE_PEER_FILL_NONCE_HEADER: &str = "x-fluxheim-peer-fill-nonce";
pub(crate) const NATIVE_PEER_FILL_REQUEST_SIGNATURE_HEADER: &str =
    "x-fluxheim-peer-fill-request-signature";
pub(crate) const NATIVE_PEER_FILL_RESPONSE_SIGNATURE_HEADER: &str =
    "x-fluxheim-peer-fill-response-signature";
const NATIVE_PEER_FILL_AUTH_MIN_BYTES: usize = 32;
const NATIVE_PEER_FILL_AUTH_MAX_BYTES: usize = 4096;

#[derive(Clone)]
pub(crate) struct NativePeerFillAuth {
    pub(crate) secret: Arc<SecretVec>,
}

impl std::fmt::Debug for NativePeerFillAuth {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativePeerFillAuth")
            .field("secret", &"<redacted>")
            .finish()
    }
}

pub(crate) fn native_peer_fill_auth_from_config(
    cache: &CacheConfig,
) -> std::io::Result<Option<Arc<NativePeerFillAuth>>> {
    let Some(path) = cache.peer_fill.shared_secret_file.as_deref() else {
        return Ok(None);
    };
    let secret = read_native_peer_fill_shared_secret_file(path)?;
    Ok(Some(Arc::new(NativePeerFillAuth { secret })))
}

fn read_native_peer_fill_shared_secret_file(path: &Path) -> std::io::Result<Arc<SecretVec>> {
    let mut file = open_regular_native_peer_fill_shared_secret_file(path)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "peer-fill shared secret file must be a regular file",
        ));
    }
    if metadata.len() > NATIVE_PEER_FILL_AUTH_MAX_BYTES as u64 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "peer-fill shared secret file exceeds 4096 bytes",
        ));
    }
    let mut secret = Vec::with_capacity(NATIVE_PEER_FILL_AUTH_MIN_BYTES);
    file.by_ref()
        .take((NATIVE_PEER_FILL_AUTH_MAX_BYTES + 1) as u64)
        .read_to_end(&mut secret)?;
    while matches!(secret.last(), Some(b'\n' | b'\r')) {
        secret.pop();
    }
    if secret.len() < NATIVE_PEER_FILL_AUTH_MIN_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "peer-fill shared secret must be at least 32 bytes",
        ));
    }
    if secret.len() > NATIVE_PEER_FILL_AUTH_MAX_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "peer-fill shared secret exceeds 4096 bytes",
        ));
    }
    Ok(Arc::new(SecretVec::from_vec(secret)))
}

#[cfg(unix)]
fn open_regular_native_peer_fill_shared_secret_file(path: &Path) -> std::io::Result<std::fs::File> {
    let fd = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| std::io::Error::from_raw_os_error(error.raw_os_error()))?;
    Ok(fd.into())
}

#[cfg(not(unix))]
fn open_regular_native_peer_fill_shared_secret_file(path: &Path) -> std::io::Result<std::fs::File> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "peer-fill shared secret file must not be a symlink",
        ));
    }
    std::fs::File::open(path)
}

pub(crate) fn native_peer_fill_nonce() -> String {
    let mut nonce = [0_u8; 16];
    if let Err(error) = getrandom::fill(&mut nonce) {
        log::error!(
            target: "fluxheim::security",
            "native peer-fill nonce generation failed: {error}; aborting"
        );
        std::process::abort();
    }
    base64_ng::URL_SAFE_NO_PAD.encode_string_infallible(&nonce)
}

pub(crate) fn native_peer_fill_request_signature(
    auth: &NativePeerFillAuth,
    target: &str,
    headers: &[(String, String)],
    nonce: &str,
) -> String {
    let host = headers
        .iter()
        .find_map(|(name, value)| name.eq_ignore_ascii_case("host").then_some(value.as_str()))
        .unwrap_or_default();
    let mut context = native_peer_fill_hmac_context(auth, b"fluxheim-peer-fill-request-v1");
    native_peer_fill_hmac_field(&mut context, b"GET");
    native_peer_fill_hmac_field(&mut context, target.as_bytes());
    native_peer_fill_hmac_field(&mut context, host.as_bytes());
    native_peer_fill_hmac_field(&mut context, nonce.as_bytes());
    native_peer_fill_hmac_hex(context.sign().as_ref())
}

pub(crate) fn native_peer_fill_request_signature_matches(
    auth: &NativePeerFillAuth,
    request: &NativeHttp1Request,
) -> bool {
    let Some(nonce) = native_request_single_header_value(request, NATIVE_PEER_FILL_NONCE_HEADER)
    else {
        return false;
    };
    let Some(candidate) =
        native_request_single_header_value(request, NATIVE_PEER_FILL_REQUEST_SIGNATURE_HEADER)
    else {
        return false;
    };
    let mut context = native_peer_fill_hmac_context(auth, b"fluxheim-peer-fill-request-v1");
    native_peer_fill_hmac_field(&mut context, request.method.as_bytes());
    native_peer_fill_hmac_field(&mut context, request.target.as_bytes());
    native_peer_fill_hmac_field(
        &mut context,
        native_request_header(request, "host")
            .unwrap_or_default()
            .as_bytes(),
    );
    native_peer_fill_hmac_field(&mut context, nonce.as_bytes());
    native_peer_fill_signature_matches(
        candidate,
        &native_peer_fill_hmac_hex(context.sign().as_ref()),
    )
}

pub(crate) fn native_peer_fill_sign_response(
    auth: &NativePeerFillAuth,
    request: &NativeHttp1Request,
    response: &mut NativeHttp1Response,
) {
    if !native_peer_fill_request_signature_matches(auth, request) {
        return;
    }
    let Some(nonce) = native_request_single_header_value(request, NATIVE_PEER_FILL_NONCE_HEADER)
    else {
        return;
    };
    response.remove_header(NATIVE_PEER_FILL_NONCE_HEADER);
    response.remove_header(NATIVE_PEER_FILL_RESPONSE_SIGNATURE_HEADER);
    let signature = native_peer_fill_response_signature(auth, request, response, nonce);
    response.push_header(NATIVE_PEER_FILL_NONCE_HEADER, nonce.to_owned());
    response.push_header(NATIVE_PEER_FILL_RESPONSE_SIGNATURE_HEADER, signature);
}

pub(crate) fn native_peer_fill_response_signature_matches(
    auth: &NativePeerFillAuth,
    request: &NativeHttp1Request,
    response: &NativeHttp1Response,
) -> bool {
    let Some(request_nonce) =
        native_request_single_header_value(request, NATIVE_PEER_FILL_NONCE_HEADER)
    else {
        return false;
    };
    let Some(response_nonce) =
        native_response_single_header_value(response, NATIVE_PEER_FILL_NONCE_HEADER)
    else {
        return false;
    };
    if request_nonce != response_nonce {
        return false;
    }
    let Some(candidate) =
        native_response_single_header_value(response, NATIVE_PEER_FILL_RESPONSE_SIGNATURE_HEADER)
    else {
        return false;
    };
    native_peer_fill_signature_matches(
        candidate,
        &native_peer_fill_response_signature(auth, request, response, request_nonce),
    )
}

fn native_peer_fill_response_signature(
    auth: &NativePeerFillAuth,
    request: &NativeHttp1Request,
    response: &NativeHttp1Response,
    nonce: &str,
) -> String {
    use sha2::{Digest, Sha256};

    let mut body_hash = Sha256::new();
    body_hash.update(response.body());
    let body_digest = body_hash.finalize();

    let mut context = native_peer_fill_hmac_context(auth, b"fluxheim-peer-fill-response-v1");
    native_peer_fill_hmac_field(&mut context, request.method.as_bytes());
    native_peer_fill_hmac_field(&mut context, request.target.as_bytes());
    native_peer_fill_hmac_field(
        &mut context,
        native_request_header(request, "host")
            .unwrap_or_default()
            .as_bytes(),
    );
    native_peer_fill_hmac_field(&mut context, nonce.as_bytes());
    native_peer_fill_hmac_field(&mut context, response.status().to_string().as_bytes());
    for (name, value) in native_peer_fill_canonical_response_headers(response) {
        native_peer_fill_hmac_field(&mut context, name.as_bytes());
        native_peer_fill_hmac_field(&mut context, value.as_bytes());
    }
    native_peer_fill_hmac_field(&mut context, &body_digest);
    native_peer_fill_hmac_hex(context.sign().as_ref())
}

fn native_peer_fill_canonical_response_headers(
    response: &NativeHttp1Response,
) -> Vec<(String, String)> {
    let mut headers = response
        .headers()
        .iter()
        .filter(|(name, _)| {
            !name.eq_ignore_ascii_case(NATIVE_PEER_FILL_NONCE_HEADER)
                && !name.eq_ignore_ascii_case(NATIVE_PEER_FILL_RESPONSE_SIGNATURE_HEADER)
        })
        .map(|(name, value)| (name.to_ascii_lowercase(), value.clone()))
        .collect::<Vec<_>>();
    headers.sort();
    headers
}

fn native_peer_fill_hmac_context(
    auth: &NativePeerFillAuth,
    label: &'static [u8],
) -> ring::hmac::Context {
    auth.secret.with_secret(|secret| {
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret);
        let mut context = ring::hmac::Context::with_key(&key);
        native_peer_fill_hmac_field(&mut context, label);
        context
    })
}

fn native_peer_fill_hmac_field(context: &mut ring::hmac::Context, bytes: &[u8]) {
    context.update(&(bytes.len() as u64).to_be_bytes());
    context.update(bytes);
}

fn native_peer_fill_hmac_hex(bytes: &[u8]) -> String {
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut value, "{byte:02x}");
    }
    value
}

fn native_peer_fill_signature_matches(candidate: &str, expected: &str) -> bool {
    candidate
        .trim()
        .as_bytes()
        .ct_eq(expected.as_bytes())
        .declassify("native peer-fill HMAC match result is public")
}

fn native_request_header<'a>(request: &'a NativeHttp1Request, name: &str) -> Option<&'a str> {
    request
        .headers
        .iter()
        .find_map(|(header_name, value)| header_name.eq_ignore_ascii_case(name).then_some(value))
        .map(String::as_str)
}

fn native_request_single_header_value<'a>(
    request: &'a NativeHttp1Request,
    name: &str,
) -> Option<&'a str> {
    let mut values = request
        .headers
        .iter()
        .filter_map(|(header_name, value)| header_name.eq_ignore_ascii_case(name).then_some(value));
    let first = values.next()?;
    values.next().is_none().then_some(first.trim())
}

pub(crate) fn native_response_single_header_value<'a>(
    response: &'a NativeHttp1Response,
    name: &str,
) -> Option<&'a str> {
    let mut values = response
        .headers()
        .iter()
        .filter_map(|(header_name, value)| header_name.eq_ignore_ascii_case(name).then_some(value));
    let first = values.next()?;
    values.next().is_none().then_some(first.trim())
}

pub(crate) fn native_peer_fill_response_without_cache_status(
    mut response: NativeHttp1Response,
    cache: &CacheConfig,
) -> NativeHttp1Response {
    response.remove_header(NATIVE_PEER_FILL_NONCE_HEADER);
    response.remove_header(NATIVE_PEER_FILL_RESPONSE_SIGNATURE_HEADER);
    if let Some(header) = cache.status_header.as_deref() {
        response.remove_header(header);
    }
    if let Some(header) = cache.status_reason_header.as_deref() {
        response.remove_header(header);
    }
    response
}
