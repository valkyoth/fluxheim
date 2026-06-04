use pingora::lb::Backend;

use super::selection::fnv1a64;

pub(crate) fn backend_authority_key(authority: &str) -> u64 {
    fnv1a64(authority.as_bytes())
}

pub(crate) fn backend_key(backend: &Backend) -> u64 {
    backend_authority_key(&backend.addr.to_string())
}
