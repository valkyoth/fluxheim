use super::LoadBalancerRequestView;
use super::backend::BackendIdentity;
use super::backend_key;
use super::selection_hash::fnv1a64_with_seed;

pub(super) fn install_test_crypto_provider() {
    #[cfg(feature = "tls-rustls-backend")]
    let _ = rustls::crypto::ring::default_provider().install_default();
}

#[derive(Clone, Debug)]
pub(super) struct TestRequest {
    uri: String,
    headers: Vec<(String, String)>,
}

impl TestRequest {
    pub(super) fn insert_header(
        &mut self,
        name: impl Into<String>,
        value: impl ToString,
    ) -> Result<(), &'static str> {
        self.headers.push((name.into(), value.to_string()));
        Ok(())
    }
}

impl LoadBalancerRequestView for TestRequest {
    fn uri_key(&self) -> Vec<u8> {
        self.uri.as_bytes().to_vec()
    }

    fn header_values<'a>(&'a self, name: &str) -> Box<dyn Iterator<Item = &'a [u8]> + 'a> {
        let name = name.to_owned();
        Box::new(
            self.headers
                .iter()
                .filter(move |(candidate, _)| candidate.eq_ignore_ascii_case(&name))
                .map(|(_, value)| value.as_bytes()),
        )
    }

    fn cookie_headers<'a>(&'a self) -> Box<dyn Iterator<Item = &'a str> + 'a> {
        Box::new(
            self.headers
                .iter()
                .filter(|(candidate, _)| candidate.eq_ignore_ascii_case("cookie"))
                .map(|(_, value)| value.as_str()),
        )
    }
}

pub(super) fn request() -> TestRequest {
    TestRequest {
        uri: "/app?id=42".to_owned(),
        headers: Vec::new(),
    }
}

pub(super) fn slow_start_blocking_sample(backend: &impl BackendIdentity) -> u64 {
    let key = backend_key(backend);
    (0_u64..10_000)
        .find(|sample| fnv1a64_with_seed(&sample.to_le_bytes(), key) % 1000 >= 1)
        .expect("blocking slow-start sample")
}
