use pingora::lb::Backend;

use super::selection::fnv1a64;

pub(super) fn backend_key(backend: &Backend) -> u64 {
    fnv1a64(backend.addr.to_string().as_bytes())
}
