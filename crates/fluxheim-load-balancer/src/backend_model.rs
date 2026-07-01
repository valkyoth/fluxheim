use std::collections::{BTreeSet, HashMap};
use std::io;
use std::net::SocketAddr;

use fluxheim_common::{FluxError, FluxResult};

use super::backend::RuntimeBackend;
use super::key::backend_authority_key;

pub(crate) trait BackendIdentity {
    fn authority(&self) -> String;

    fn weight(&self) -> usize;

    fn key(&self) -> u64 {
        backend_authority_key(&self.authority())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct FluxBackend {
    pub addr: SocketAddr,
    pub weight: usize,
}

impl FluxBackend {
    pub(super) fn new(authority: &str) -> FluxResult<Self> {
        Self::new_with_weight(authority, 1)
    }

    pub(super) fn new_with_weight(authority: &str, weight: usize) -> FluxResult<Self> {
        let address = authority.parse::<SocketAddr>().map_err(|error| {
            FluxError::io(
                "load-balancer backend authority is not a socket address",
                io::Error::new(io::ErrorKind::InvalidInput, error),
            )
        })?;
        Ok(Self {
            addr: address,
            weight,
        })
    }
}

impl BackendIdentity for FluxBackend {
    fn authority(&self) -> String {
        self.addr.to_string()
    }

    fn weight(&self) -> usize {
        self.weight
    }
}

impl<T> BackendIdentity for &T
where
    T: BackendIdentity + ?Sized,
{
    fn authority(&self) -> String {
        (*self).authority()
    }

    fn weight(&self) -> usize {
        (*self).weight()
    }
}

#[derive(Clone, Debug, Default)]
pub(super) struct FluxBackendSet {
    backends: BTreeSet<FluxBackend>,
    ready: HashMap<u64, bool>,
}

impl FluxBackendSet {
    pub(super) fn insert(&mut self, backend: FluxBackend) {
        self.backends.insert(backend);
    }

    pub(super) fn is_empty(&self) -> bool {
        self.backends.is_empty()
    }

    pub(super) fn iter(&self) -> impl Iterator<Item = &FluxBackend> {
        self.backends.iter()
    }

    #[cfg(test)]
    pub(super) fn set_ready(&mut self, backend: &FluxBackend, ready: bool) {
        self.ready.insert(backend.key(), ready);
    }

    pub(super) fn into_parts(self) -> (BTreeSet<RuntimeBackend>, HashMap<u64, bool>) {
        (self.backends, self.ready)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flux_backend_preserves_authority_weight_and_key() {
        let backend = FluxBackend::new_with_weight("127.0.0.1:3000", 7).unwrap();

        assert_eq!(backend.authority(), "127.0.0.1:3000");
        assert_eq!(backend.weight(), 7);
        assert_eq!(backend.key(), backend_authority_key("127.0.0.1:3000"));
    }

    #[test]
    fn flux_backend_set_preserves_native_parts() {
        let backend = FluxBackend::new("127.0.0.1:3000").unwrap();
        let mut set = FluxBackendSet::default();
        set.insert(backend.clone());
        set.set_ready(&backend, false);

        let (backends, ready) = set.into_parts();
        assert_eq!(backends.len(), 1);
        assert_eq!(ready.get(&backend.key()), Some(&false));
        assert_eq!(
            backends.iter().next().unwrap().addr.to_string(),
            "127.0.0.1:3000"
        );
    }
}
