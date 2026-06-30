use std::collections::HashSet;
use std::net::SocketAddr;

use crc32fast::Hasher as Crc32Hasher;
use fluxheim_common::{FluxError, FluxResult};

use super::backend::BackendIdentity;

const NGINX_KETAMA_POINT_MULTIPLE: usize = 160;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct NginxKetamaPoint {
    pub(super) hash: u32,
    pub(super) backend_key: u64,
}

#[derive(Clone, Debug)]
pub(super) struct NginxKetamaTable {
    pub(super) points: Vec<NginxKetamaPoint>,
}

impl NginxKetamaTable {
    pub(super) fn from_backend_identities<'a, I, B>(backends: I) -> FluxResult<Self>
    where
        I: IntoIterator<Item = &'a B>,
        B: BackendIdentity + 'a,
    {
        let mut points = Vec::new();
        for backend in backends {
            let authority = backend.authority();
            let address = authority.parse::<SocketAddr>().map_err(|error| {
                FluxError::io(
                    "nginx-compatible consistent hash backend is not a socket address",
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, error),
                )
            })?;
            push_nginx_ketama_points(&mut points, address, backend.key(), backend.weight());
        }
        if points.is_empty() {
            return Err(FluxError::InvalidInput(
                "nginx-compatible consistent hash requires at least one backend",
            ));
        }
        let point_count = points.len();
        points.sort_unstable_by_key(|point| point.hash);
        points.dedup_by(|left, right| left.hash == right.hash);
        let deduped_count = points.len();
        if deduped_count < point_count {
            log::warn!(
                target: "fluxheim::load_balancer",
                "nginx-compatible Ketama ring dropped {} duplicate continuum point(s); backend coverage is slightly reduced",
                point_count - deduped_count
            );
        }
        Ok(Self { points })
    }

    pub(super) fn backend_keys(&self, key: &[u8], max_iterations: usize) -> Vec<u64> {
        if self.points.is_empty() {
            return Vec::new();
        }
        let hash = crc32fast::hash(key);
        let start = match self.points.binary_search_by(|point| point.hash.cmp(&hash)) {
            Ok(index) => index,
            Err(index) if index == self.points.len() => 0,
            Err(index) => index,
        };
        let limit = max_iterations.max(1).min(self.points.len());
        let mut keys = Vec::new();
        let mut seen = HashSet::with_capacity(limit);
        for offset in 0..self.points.len() {
            if keys.len() >= limit {
                break;
            }
            let key = self.points[(start + offset) % self.points.len()].backend_key;
            if seen.insert(key) {
                keys.push(key);
            }
        }
        keys
    }
}

fn push_nginx_ketama_points(
    points: &mut Vec<NginxKetamaPoint>,
    address: SocketAddr,
    backend_key: u64,
    weight: usize,
) {
    let mut base = Vec::new();
    base.extend_from_slice(address.ip().to_string().as_bytes());
    base.push(0);
    base.extend_from_slice(address.port().to_string().as_bytes());

    let mut previous_hash = 0u32;
    let point_count = weight.max(1).saturating_mul(NGINX_KETAMA_POINT_MULTIPLE);
    for _ in 0..point_count {
        let mut hasher = Crc32Hasher::new();
        hasher.update(&base);
        hasher.update(&previous_hash.to_le_bytes());
        let hash = hasher.finalize();
        points.push(NginxKetamaPoint { hash, backend_key });
        previous_hash = hash;
    }
}
