use std::net::SocketAddr;
use std::ops::Deref;

use fluxheim_protocol::{Http1RequestTarget, Http1Version, http1_request_target};

use crate::request_body_budget::NativeRequestBodyReservation;

#[derive(Debug, Eq, PartialEq)]
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
    pub body: NativeHttp1RequestBody,
    pub trailers: Vec<(String, String)>,
}

#[derive(Default)]
pub struct NativeHttp1RequestBody {
    bytes: Vec<u8>,
    admission: Option<NativeRequestBodyReservation>,
    #[cfg(test)]
    capacity_replacements: usize,
}

impl NativeHttp1RequestBody {
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            bytes: Vec::new(),
            admission: None,
            #[cfg(test)]
            capacity_replacements: 0,
        }
    }

    #[must_use]
    pub const fn from_vec(body: Vec<u8>) -> Self {
        Self {
            bytes: body,
            admission: None,
            #[cfg(test)]
            capacity_replacements: 0,
        }
    }

    pub(crate) fn attach_admission(&mut self, admission: NativeRequestBodyReservation) {
        if self.admission.is_some() {
            log::error!(
                target: "fluxheim::security",
                "request body admission was attached more than once"
            );
            std::process::abort();
        }
        self.admission = Some(admission);
    }

    pub(crate) fn extend_from_slice(
        &mut self,
        bytes: &[u8],
    ) -> Result<(), fluxheim_protocol::Http1ParseError> {
        let required = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .ok_or(fluxheim_protocol::Http1ParseError::BodyTooLarge)?;
        self.reserve_capacity(required)?;
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    pub(crate) fn reserve_capacity(
        &mut self,
        required: usize,
    ) -> Result<(), fluxheim_protocol::Http1ParseError> {
        if required <= self.bytes.capacity() {
            return Ok(());
        }
        let mut replacement = Vec::new();
        replacement
            .try_reserve_exact(required)
            .map_err(|_| fluxheim_protocol::Http1ParseError::BodyTooLarge)?;
        replacement.extend_from_slice(&self.bytes);
        sanitization::wipe::vec(&mut self.bytes);
        self.bytes = replacement;
        #[cfg(test)]
        {
            self.capacity_replacements += 1;
        }
        Ok(())
    }

    pub(crate) fn replace_capacity(
        &mut self,
        required: usize,
    ) -> Result<(), fluxheim_protocol::Http1ParseError> {
        let mut replacement = Vec::new();
        replacement
            .try_reserve_exact(required)
            .map_err(|_| fluxheim_protocol::Http1ParseError::BodyTooLarge)?;
        replacement.extend_from_slice(&self.bytes);
        sanitization::wipe::vec(&mut self.bytes);
        self.bytes = replacement;
        #[cfg(test)]
        {
            self.capacity_replacements += 1;
        }
        Ok(())
    }

    pub(crate) fn capacity(&self) -> usize {
        self.bytes.capacity()
    }

    #[cfg(test)]
    pub(crate) fn capacity_replacements(&self) -> usize {
        self.capacity_replacements
    }
}

impl PartialEq for NativeHttp1RequestBody {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl Eq for NativeHttp1RequestBody {}

impl std::fmt::Debug for NativeHttp1RequestBody {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeHttp1RequestBody")
            .field("len", &self.bytes.len())
            .field("contents", &"<redacted>")
            .finish()
    }
}

impl Deref for NativeHttp1RequestBody {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

impl AsRef<[u8]> for NativeHttp1RequestBody {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl fluxheim_protocol::Http1ChunkSink for NativeHttp1RequestBody {
    fn len(&self) -> usize {
        self.bytes.len()
    }

    fn append(&mut self, bytes: &[u8]) -> Result<(), fluxheim_protocol::Http1ParseError> {
        self.extend_from_slice(bytes)
    }
}

impl Drop for NativeHttp1RequestBody {
    fn drop(&mut self) {
        sanitization::wipe::vec(&mut self.bytes);
    }
}

impl NativeHttp1Request {
    #[must_use]
    pub(crate) fn take_body(&mut self) -> NativeHttp1RequestBody {
        std::mem::take(&mut self.body)
    }

    #[must_use]
    pub(crate) fn metadata_snapshot(&self) -> Self {
        Self {
            method: self.method.clone(),
            peer_addr: self.peer_addr,
            local_addr: self.local_addr,
            effective_client_addr: self.effective_client_addr,
            downstream_tls: self.downstream_tls,
            tls_identity: self.tls_identity.clone(),
            geo_context: self.geo_context.clone(),
            target: self.target.clone(),
            version: self.version,
            headers: self.headers.clone(),
            body: NativeHttp1RequestBody::empty(),
            trailers: self.trailers.clone(),
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_snapshot_never_copies_request_body() {
        let request = NativeHttp1Request {
            method: "POST".to_owned(),
            peer_addr: "127.0.0.1:1234".parse().ok(),
            local_addr: None,
            effective_client_addr: None,
            downstream_tls: true,
            tls_identity: None,
            geo_context: None,
            target: "/upload".to_owned(),
            version: Http1Version::Http11,
            headers: vec![(
                "content-type".to_owned(),
                "application/octet-stream".to_owned(),
            )],
            body: NativeHttp1RequestBody::from_vec(b"sensitive-body".to_vec()),
            trailers: vec![("x-checksum".to_owned(), "value".to_owned())],
        };

        let snapshot = request.metadata_snapshot();

        assert!(snapshot.body.is_empty());
        assert_eq!(snapshot.method, request.method);
        assert_eq!(snapshot.target, request.target);
        assert_eq!(snapshot.headers, request.headers);
        assert_eq!(snapshot.trailers, request.trailers);
        assert!(!format!("{request:?}").contains("sensitive-body"));
    }
}
