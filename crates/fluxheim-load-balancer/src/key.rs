use super::backend::BackendIdentity;
use super::selection::fnv1a64;

pub(crate) fn backend_authority_key(authority: &str) -> u64 {
    fnv1a64(authority.as_bytes())
}

pub(crate) fn backend_key(backend: &impl BackendIdentity) -> u64 {
    backend.key()
}
