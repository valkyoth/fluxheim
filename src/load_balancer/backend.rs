use std::collections::{BTreeSet, HashMap};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use super::key::backend_authority_key;
use crate::flux_error::{FluxError, FluxResult};
use pingora::lb::Backend;
use pingora::lb::prelude::LoadBalancer;
use pingora::lb::selection::RoundRobin;

pub(crate) trait BackendIdentity {
    fn authority(&self) -> String;

    fn weight(&self) -> usize;

    fn key(&self) -> u64 {
        backend_authority_key(&self.authority())
    }
}

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

    pub(super) fn to_pingora_backend(&self) -> FluxResult<Backend> {
        Backend::new_with_weight(&self.authority(), self.weight).map_err(|error| {
            FluxError::io(
                "load-balancer backend cannot be adapted to Pingora",
                io::Error::other(error.to_string()),
            )
        })
    }
}

impl BackendIdentity for FluxBackend {
    fn authority(&self) -> String {
        self.address.to_string()
    }

    fn weight(&self) -> usize {
        self.weight
    }
}

impl BackendIdentity for Backend {
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

    pub(super) fn into_pingora_parts(self) -> FluxResult<(BTreeSet<Backend>, HashMap<u64, bool>)> {
        let mut backends = BTreeSet::new();
        for backend in self.backends {
            backends.insert(backend.to_pingora_backend()?);
        }
        Ok((backends, self.ready))
    }
}

pub(super) fn pingora_backend_set(inner: &LoadBalancer<RoundRobin>) -> Arc<BTreeSet<Backend>> {
    inner.backends().get_backend()
}

pub(super) fn pingora_backend_ready(inner: &LoadBalancer<RoundRobin>, backend: &Backend) -> bool {
    inner.backends().ready(backend)
}

pub(super) trait BackendContainer {
    fn backend_set(&self) -> Arc<BTreeSet<Backend>>;

    fn backend_ready(&self, backend: &Backend) -> bool;
}

impl BackendContainer for LoadBalancer<RoundRobin> {
    fn backend_set(&self) -> Arc<BTreeSet<Backend>> {
        pingora_backend_set(self)
    }

    fn backend_ready(&self, backend: &Backend) -> bool {
        pingora_backend_ready(self, backend)
    }
}

impl<T> BackendContainer for Arc<T>
where
    T: BackendContainer + ?Sized,
{
    fn backend_set(&self) -> Arc<BTreeSet<Backend>> {
        (**self).backend_set()
    }

    fn backend_ready(&self, backend: &Backend) -> bool {
        (**self).backend_ready(backend)
    }
}

pub(super) fn backend_container_set(container: &impl BackendContainer) -> Arc<BTreeSet<Backend>> {
    container.backend_set()
}

pub(super) fn backend_container_ready(
    container: &impl BackendContainer,
    backend: &Backend,
) -> bool {
    container.backend_ready(backend)
}

pub(super) fn pingora_health_check_frequency(inner: &LoadBalancer<RoundRobin>) -> Option<Duration> {
    inner.health_check_frequency
}

pub(super) fn pingora_parallel_health_check(inner: &LoadBalancer<RoundRobin>) -> bool {
    inner.parallel_health_check
}

#[cfg(test)]
pub(super) async fn pingora_run_health_check(inner: &LoadBalancer<RoundRobin>, parallel: bool) {
    inner.backends().run_health_check(parallel).await;
}

#[cfg(test)]
mod tests {
    use super::{BackendIdentity, FluxBackend, FluxBackendSet};

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
