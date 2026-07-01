use std::net::SocketAddr;

use fluxheim_protocol::{Http1RequestTarget, Http1Version, http1_request_target};
use zeroize::Zeroizing;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeHttp1Request {
    pub method: String,
    pub peer_addr: Option<SocketAddr>,
    pub local_addr: Option<SocketAddr>,
    pub effective_client_addr: Option<SocketAddr>,
    pub downstream_tls: bool,
    pub tls_identity: Option<NativeHttp1TlsClientIdentity>,
    pub geo_context: Option<NativeHttp1GeoContext>,
    pub target: String,
    pub version: Http1Version,
    pub headers: Vec<(String, String)>,
    pub body: Zeroizing<Vec<u8>>,
    pub trailers: Vec<(String, String)>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NativeHttp1TlsClientIdentity {
    pub cipher: Option<String>,
    pub version: Option<String>,
    pub organization: Option<String>,
    pub serial_number: Option<String>,
    pub cert_sha256: Option<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NativeHttp1GeoContext {
    pub country_iso: Option<String>,
    pub asn: Option<u32>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NativeHttp1RequestContext {
    pub local_addr: Option<SocketAddr>,
    pub effective_client_addr: Option<SocketAddr>,
    pub downstream_tls: bool,
    pub tls_identity: Option<NativeHttp1TlsClientIdentity>,
    pub geo_context: Option<NativeHttp1GeoContext>,
}

#[cfg(feature = "load-balancer")]
impl fluxheim_load_balancer::LoadBalancerRequestView for NativeHttp1Request {
    fn uri_key(&self) -> Vec<u8> {
        self.target.as_bytes().to_vec()
    }

    fn header_values<'a>(&'a self, name: &str) -> Box<dyn Iterator<Item = &'a [u8]> + 'a> {
        let name = name.to_owned();
        Box::new(
            self.headers
                .iter()
                .filter(move |(header_name, _)| header_name.eq_ignore_ascii_case(&name))
                .map(|(_, value)| value.as_bytes()),
        )
    }

    fn cookie_headers<'a>(&'a self) -> Box<dyn Iterator<Item = &'a str> + 'a> {
        Box::new(
            self.headers
                .iter()
                .filter(|(header_name, _)| header_name.eq_ignore_ascii_case("cookie"))
                .map(|(_, value)| value.as_str()),
        )
    }
}

impl fluxheim_cache::CacheRequestView for NativeHttp1Request {
    fn method(&self) -> &str {
        &self.method
    }

    fn path(&self) -> &str {
        native_http1_cache_request_path(&self.method, &self.target)
    }

    fn query(&self) -> Option<&str> {
        native_http1_cache_request_query(&self.method, &self.target)
    }

    fn contains_header(&self, name: &str) -> bool {
        self.headers
            .iter()
            .any(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
    }

    fn visit_header_values(&self, name: &str, visitor: &mut dyn FnMut(&str)) {
        for (_, value) in self
            .headers
            .iter()
            .filter(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
        {
            visitor(value);
        }
    }
}

fn native_http1_cache_request_path<'a>(method: &str, target: &'a str) -> &'a str {
    match http1_request_target(method, target) {
        Ok(Http1RequestTarget::Origin { path, .. }) => path,
        Ok(Http1RequestTarget::AbsoluteUri { path, .. }) => path.unwrap_or("/"),
        Ok(Http1RequestTarget::Authority { .. } | Http1RequestTarget::Asterisk) | Err(_) => "/",
    }
}

fn native_http1_cache_request_query<'a>(method: &str, target: &'a str) -> Option<&'a str> {
    match http1_request_target(method, target) {
        Ok(Http1RequestTarget::Origin { query, .. })
        | Ok(Http1RequestTarget::AbsoluteUri { query, .. }) => query,
        Ok(Http1RequestTarget::Authority { .. } | Http1RequestTarget::Asterisk) | Err(_) => None,
    }
}
