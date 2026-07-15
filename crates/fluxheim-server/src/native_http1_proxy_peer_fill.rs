use std::time::Duration;

use http::Uri;

#[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend"))]
use crate::NativeHttp1UpstreamTls;
use crate::native_http1_proxy_peer_fill_auth::{
    NATIVE_PEER_FILL_NONCE_HEADER, NATIVE_PEER_FILL_REQUEST_SIGNATURE_HEADER, NativePeerFillAuth,
    native_peer_fill_nonce, native_peer_fill_request_signature,
    native_peer_fill_response_signature_matches, native_peer_fill_response_without_cache_status,
};
use crate::{NativeHttp1Request, NativeHttp1Response, NativeHttp1Upstream};
use fluxheim_config::CacheConfig;

pub(crate) const NATIVE_PEER_FILL_MARKER_HEADER: &str = "x-fluxheim-peer-fill";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NativePeerFillPeer {
    pub(crate) name: String,
    pub(crate) base_path: String,
    pub(crate) upstream: NativeHttp1Upstream,
}

pub(crate) fn native_peer_fill_supported(cache: &CacheConfig) -> bool {
    !cache.peer_fill.enabled
        || (!cache.peer_fill.peers.is_empty()
            && cache
                .peer_fill
                .peers
                .iter()
                .all(|peer| native_peer_fill_peer_from_config(peer, &cache.peer_fill).is_some()))
}

pub(crate) fn native_peer_fill_peers(cache: &CacheConfig) -> Vec<NativePeerFillPeer> {
    if !cache.peer_fill.enabled {
        return Vec::new();
    }
    cache
        .peer_fill
        .peers
        .iter()
        .filter_map(|peer| native_peer_fill_peer_from_config(peer, &cache.peer_fill))
        .collect()
}

fn native_peer_fill_peer_from_config(
    peer: &fluxheim_config::CachePeerConfig,
    peer_fill: &fluxheim_config::CachePeerFillConfig,
) -> Option<NativePeerFillPeer> {
    let uri = peer.base_url.parse::<Uri>().ok()?;
    if uri.query().is_some() {
        return None;
    }
    let upstream = native_peer_fill_upstream_from_uri(&uri, peer_fill)?;
    let base_path = uri
        .path_and_query()
        .map(|path| path.as_str())
        .unwrap_or("/")
        .trim_end_matches('/')
        .to_owned();
    Some(NativePeerFillPeer {
        name: peer.name.clone(),
        base_path,
        upstream,
    })
}

fn native_peer_fill_upstream_from_uri(
    uri: &Uri,
    peer_fill: &fluxheim_config::CachePeerFillConfig,
) -> Option<NativeHttp1Upstream> {
    let authority = uri.authority()?;
    match uri.scheme_str()? {
        "http" => {
            if !peer_fill.allow_insecure_http && !native_peer_fill_authority_is_loopback(authority)
            {
                return None;
            }
            Some(native_peer_fill_plain_upstream(authority, peer_fill))
        }
        "https" => native_peer_fill_tls_upstream(authority, peer_fill),
        _ => None,
    }
}

fn native_peer_fill_plain_upstream(
    authority: &http::uri::Authority,
    peer_fill: &fluxheim_config::CachePeerFillConfig,
) -> NativeHttp1Upstream {
    NativeHttp1Upstream::new(authority.as_str().to_owned())
        .with_connect_timeout(Duration::from_secs(peer_fill.connect_timeout_secs))
        .with_read_timeout(Duration::from_secs(peer_fill.read_timeout_secs))
}

fn native_peer_fill_authority_is_loopback(authority: &http::uri::Authority) -> bool {
    let host = native_peer_fill_authority_host(authority);
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn native_peer_fill_authority_host(authority: &http::uri::Authority) -> &str {
    let authority = authority.as_str();
    if let Some(rest) = authority.strip_prefix('[') {
        return rest.split_once(']').map_or(authority, |(host, _)| host);
    }
    authority
        .rsplit_once(':')
        .map_or(authority, |(host, _)| host)
}

#[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend"))]
fn native_peer_fill_tls_upstream(
    authority: &http::uri::Authority,
    peer_fill: &fluxheim_config::CachePeerFillConfig,
) -> Option<NativeHttp1Upstream> {
    let host = native_peer_fill_authority_host(authority);
    if host.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }

    let authority = authority.as_str().to_owned();
    let mut proxy = fluxheim_config::ProxyConfig {
        upstream: None,
        upstreams: vec![authority.clone()],
        upstream_tls: true,
        upstream_sni: Some(host.to_owned()),
        connect_timeout_secs: Some(peer_fill.connect_timeout_secs),
        read_timeout_secs: Some(peer_fill.read_timeout_secs),
        ..Default::default()
    };
    proxy.upstream_http_version = fluxheim_config::UpstreamHttpVersion::Http1;

    let tls = NativeHttp1UpstreamTls::from_proxy_config(&proxy)
        .ok()
        .flatten()?;
    Some(
        NativeHttp1Upstream::new(authority)
            .with_tls(tls)
            .with_connect_timeout(Duration::from_secs(peer_fill.connect_timeout_secs))
            .with_read_timeout(Duration::from_secs(peer_fill.read_timeout_secs)),
    )
}

#[cfg(not(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend")))]
fn native_peer_fill_tls_upstream(
    _authority: &http::uri::Authority,
    _peer_fill: &fluxheim_config::CachePeerFillConfig,
) -> Option<NativeHttp1Upstream> {
    None
}

pub(crate) async fn native_peer_fill_fetch(
    peer: &NativePeerFillPeer,
    cache: &CacheConfig,
    auth: Option<&NativePeerFillAuth>,
    request: &NativeHttp1Request,
    max_body_bytes: u64,
) -> Result<Option<NativeHttp1Response>, crate::NativeHttp1Error> {
    let Some(peer_request) = native_peer_fill_request(peer, request, auth) else {
        return Ok(None);
    };
    let max_body_bytes = usize::try_from(max_body_bytes.saturating_add(1)).unwrap_or(usize::MAX);
    let response = peer
        .upstream
        .clone()
        .with_max_body_bytes(max_body_bytes)
        .send(&peer_request)
        .await?;
    if response.status() == 504 {
        return Ok(None);
    }
    if response.body().len() >= max_body_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "native peer fill response exceeds configured object limit",
        )
        .into());
    }
    if let Some(auth) = auth
        && !native_peer_fill_response_signature_matches(auth, &peer_request, &response)
    {
        log::warn!(
            target: "fluxheim::security",
            "native peer-fill response from {} failed authenticity verification; discarding peer response",
            peer.name
        );
        return Ok(None);
    }
    Ok(Some(native_peer_fill_response_without_cache_status(
        response, cache,
    )))
}

fn native_peer_fill_request(
    peer: &NativePeerFillPeer,
    request: &NativeHttp1Request,
    auth: Option<&NativePeerFillAuth>,
) -> Option<NativeHttp1Request> {
    if !fluxheim_common::path_safety::safe_forward_path_and_query(&request.target) {
        return None;
    }
    let target = if peer.base_path.is_empty() {
        request.target.clone()
    } else {
        format!("{}{}", peer.base_path, request.target)
    };
    if !fluxheim_common::path_safety::safe_forward_path_and_query(&target) {
        return None;
    }
    let mut headers = Vec::new();
    if let Some(host) = native_request_header(request, "host") {
        headers.push(("host".to_owned(), host.to_owned()));
    }
    for name in ["accept", "accept-encoding", "accept-language"] {
        for value in native_request_header_values(request, name) {
            headers.push((name.to_owned(), value.to_owned()));
        }
    }
    headers.push(("cache-control".to_owned(), "only-if-cached".to_owned()));
    headers.push((NATIVE_PEER_FILL_MARKER_HEADER.to_owned(), "1".to_owned()));
    if let Some(auth) = auth {
        let nonce = native_peer_fill_nonce();
        let signature = native_peer_fill_request_signature(auth, &target, &headers, &nonce);
        headers.push((NATIVE_PEER_FILL_NONCE_HEADER.to_owned(), nonce));
        headers.push((
            NATIVE_PEER_FILL_REQUEST_SIGNATURE_HEADER.to_owned(),
            signature,
        ));
    }
    Some(NativeHttp1Request {
        method: "GET".to_owned(),
        peer_addr: request.peer_addr,
        local_addr: request.local_addr,
        effective_client_addr: request.effective_client_addr,
        downstream_tls: request.downstream_tls,
        tls_identity: request.tls_identity.clone(),
        geo_context: request.geo_context.clone(),
        target,
        version: request.version,
        headers,
        body: crate::NativeHttp1RequestBody::empty(),
        trailers: Vec::new(),
    })
}

fn native_request_header_values<'a>(
    request: &'a NativeHttp1Request,
    name: &'a str,
) -> impl Iterator<Item = &'a str> {
    request
        .headers
        .iter()
        .filter(move |(header_name, _)| header_name.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn native_request_header<'a>(request: &'a NativeHttp1Request, name: &str) -> Option<&'a str> {
    request
        .headers
        .iter()
        .find_map(|(header_name, value)| header_name.eq_ignore_ascii_case(name).then_some(value))
        .map(String::as_str)
}

pub(crate) fn native_request_is_peer_fill(request: &NativeHttp1Request) -> bool {
    native_request_header_values(request, NATIVE_PEER_FILL_MARKER_HEADER)
        .any(|value| value.trim() == "1")
}

pub(crate) fn strip_native_peer_fill_header(request: &mut NativeHttp1Request) {
    request
        .headers
        .retain(|(name, _)| !name.eq_ignore_ascii_case(NATIVE_PEER_FILL_MARKER_HEADER));
}
