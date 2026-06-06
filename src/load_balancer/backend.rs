use std::collections::{BTreeSet, HashMap};
use std::io;
use std::net::SocketAddr;

use pingora::lb::Backend;

#[cfg(test)]
use super::key::backend_authority_key;
use crate::flux_error::{FluxError, FluxResult};

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(super) struct FluxBackend {
    address: SocketAddr,
    weight: usize,
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
        Ok(Self { address, weight })
    }

    pub(super) fn authority(&self) -> String {
        self.address.to_string()
    }

    #[cfg(test)]
    pub(super) fn key(&self) -> u64 {
        backend_authority_key(&self.authority())
    }

    #[cfg(test)]
    pub(super) fn weight(&self) -> usize {
        self.weight
    }

    pub(super) fn to_pingora_backend(&self) -> FluxResult<Backend> {
        Backend::new_with_weight(&self.authority(), self.weight).map_err(|error| {
            FluxError::io(
                "load-balancer backend cannot be adapted to Pingora",
                io::Error::other(error.to_string()),
            )
        })
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

    #[cfg(test)]
    pub(super) fn set_ready(&mut self, backend: &FluxBackend, ready: bool) {
        self.ready.insert(backend.key(), ready);
    }

    pub(super) fn into_pingora_parts(self) -> FluxResult<(BTreeSet<Backend>, HashMap<u64, bool>)> {
        let mut backends = BTreeSet::new();
        for backend in self.backends {
            backends.insert(backend.to_pingora_backend()?);
        }
        Ok((backends, self.ready))
    }

    pub(super) fn into_pingora_backends(self) -> FluxResult<BTreeSet<Backend>> {
        self.into_pingora_parts().map(|(backends, _ready)| backends)
    }
}

#[cfg(test)]
mod tests {
    use super::{FluxBackend, FluxBackendSet};

    #[test]
    fn flux_backend_preserves_authority_weight_and_key() {
        let backend = FluxBackend::new_with_weight("127.0.0.1:3000", 7).unwrap();

        assert_eq!(backend.authority(), "127.0.0.1:3000");
        assert_eq!(backend.weight(), 7);
        assert_eq!(
            backend.key(),
            crate::load_balancer::backend_authority_key("127.0.0.1:3000")
        );
    }

    #[test]
    fn flux_backend_set_adapts_to_pingora_parts() {
        let backend = FluxBackend::new("127.0.0.1:3000").unwrap();
        let mut set = FluxBackendSet::default();
        set.insert(backend.clone());
        set.set_ready(&backend, false);

        let (backends, ready) = set.into_pingora_parts().unwrap();
        assert_eq!(backends.len(), 1);
        assert_eq!(ready.get(&backend.key()), Some(&false));
        assert_eq!(
            backends.iter().next().unwrap().addr.to_string(),
            "127.0.0.1:3000"
        );
    }
}
