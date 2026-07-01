use std::collections::BTreeMap;
#[cfg(feature = "compression-gzip")]
use std::io::Read as _;

#[cfg(feature = "compression-gzip")]
use flate2::read::GzDecoder;
use fluxheim_config::ResponseHeaderPolicyOverlayConfig;

use crate::{NativeHttp1RouteProxy, NativeHttp1RouteProxyRoute};

use super::{downstream_get, response_header, route_proxy_listener};
#[cfg(feature = "compression-gzip")]
use super::{downstream_request_bytes, proxy_for, upstream_response};

#[cfg(feature = "compression-gzip")]
#[tokio::test]
async fn native_route_proxy_applies_gzip_route_compression() {
    let upstream = upstream_response(
        "HTTP/1.1 200 OK\r\n\
         content-type: text/plain\r\n\
         etag: \"origin-tag\"\r\n\r\n\
         hello native compression hello native compression hello native compression \
         hello native compression hello native compression hello native compression \
         hello native compression hello native compression hello native compression \
         hello native compression hello native compression hello native compression \
         hello native compression hello native compression hello native compression \
         hello native compression hello native compression hello native compression \
         hello native compression hello native compression hello native compression \
         hello native compression hello native compression hello native compression",
    )
    .await;
    let route = NativeHttp1RouteProxyRoute::prefix("/asset/", Vec::new(), proxy_for(upstream))
        .with_compression_config(fluxheim_config::CompressionConfig {
            enabled: true,
            gzip: true,
            min_bytes: fluxheim_config::ByteSize::from_bytes(1),
            max_input_bytes: fluxheim_config::ByteSize::from_bytes(4096),
            max_output_bytes: fluxheim_config::ByteSize::from_bytes(4096),
            ..Default::default()
        });
    let proxy = route_proxy_listener(NativeHttp1RouteProxy::new(vec![route], None)).await;

    let response = downstream_request_bytes(
        proxy,
        "GET /asset/text HTTP/1.1\r\nHost: route.test\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n",
    )
    .await;
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap();
    let head = String::from_utf8(response[..split].to_vec()).unwrap();
    let body = &response[split + 4..];

    assert!(head.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(head.contains("\r\ncontent-encoding: gzip"));
    assert!(head.contains("\r\nvary: accept-encoding"));
    assert!(!head.contains("\r\netag:"));
    let mut decoded = String::new();
    GzDecoder::new(body).read_to_string(&mut decoded).unwrap();
    assert!(decoded.contains("hello native compression"));
}

#[cfg(feature = "compression-gzip")]
#[tokio::test]
async fn native_route_proxy_inherits_gzip_compression_config() {
    let upstream = upstream_response(
        "HTTP/1.1 200 OK\r\n\
         content-type: text/plain\r\n\r\n\
         inherited native compression inherited native compression \
         inherited native compression inherited native compression \
         inherited native compression inherited native compression",
    )
    .await;
    let route_config = fluxheim_config::RouteConfig {
        name: "asset".to_owned(),
        path_exact: None,
        path_prefix: Some("/asset/".to_owned()),
        path_regex: None,
        methods: Vec::new(),
        fallback: false,
        https_redirect_exempt: false,
        strip_prefix: None,
        rewrite_prefix: None,
        rewrite_template: None,
        max_request_body_bytes: None,
        access: Default::default(),
        rate_limit: Default::default(),
        concurrency: Default::default(),
        grpc: Default::default(),
        redirect: None,
        proxy: Some(fluxheim_config::ProxyConfig {
            upstreams: vec![upstream.to_string()],
            ..Default::default()
        }),
        web: None,
        php: None,
        cache: None,
        compression: None,
        headers: Default::default(),
    };
    let inherited = fluxheim_config::CompressionConfig {
        enabled: true,
        gzip: true,
        min_bytes: fluxheim_config::ByteSize::from_bytes(1),
        max_input_bytes: fluxheim_config::ByteSize::from_bytes(4096),
        max_output_bytes: fluxheim_config::ByteSize::from_bytes(4096),
        ..Default::default()
    };
    let route = NativeHttp1RouteProxyRoute::from_config_with_inherited(
        &route_config,
        Some(proxy_for(upstream)),
        &fluxheim_config::HeaderPolicyConfig::default(),
        Some(&inherited),
        "route.test",
    )
    .unwrap();
    let proxy = route_proxy_listener(NativeHttp1RouteProxy::new(vec![route], None)).await;

    let response = downstream_request_bytes(
        proxy,
        "GET /asset/text HTTP/1.1\r\nHost: route.test\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n",
    )
    .await;
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap();
    let head = String::from_utf8(response[..split].to_vec()).unwrap();
    let body = &response[split + 4..];

    assert!(head.starts_with("HTTP/1.1 200 OK\r\n"));
    assert_eq!(
        response_header(&head, "content-encoding").as_deref(),
        Some("gzip")
    );
    let mut decoded = String::new();
    GzDecoder::new(body).read_to_string(&mut decoded).unwrap();
    assert!(decoded.contains("inherited native compression"));
}

#[cfg(all(feature = "compression-gzip", feature = "compression-zstd"))]
#[tokio::test]
async fn native_route_proxy_prefers_higher_accept_encoding_quality() {
    let upstream = upstream_response(
        "HTTP/1.1 200 OK\r\n\
         content-type: text/plain\r\n\r\n\
         hello native compression quality hello native compression quality \
         hello native compression quality hello native compression quality",
    )
    .await;
    let route = NativeHttp1RouteProxyRoute::prefix("/asset/", Vec::new(), proxy_for(upstream))
        .with_compression_config(fluxheim_config::CompressionConfig {
            enabled: true,
            gzip: true,
            zstd: true,
            min_bytes: fluxheim_config::ByteSize::from_bytes(1),
            max_input_bytes: fluxheim_config::ByteSize::from_bytes(4096),
            max_output_bytes: fluxheim_config::ByteSize::from_bytes(4096),
            ..Default::default()
        });
    let proxy = route_proxy_listener(NativeHttp1RouteProxy::new(vec![route], None)).await;

    let response = downstream_request_bytes(
        proxy,
        "GET /asset/text HTTP/1.1\r\nHost: route.test\r\nAccept-Encoding: zstd;q=0.1, gzip;q=1.0\r\nConnection: close\r\n\r\n",
    )
    .await;
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap();
    let head = String::from_utf8(response[..split].to_vec()).unwrap();

    assert!(head.starts_with("HTTP/1.1 200 OK\r\n"));
    assert_eq!(
        response_header(&head, "content-encoding").as_deref(),
        Some("gzip")
    );
}

#[tokio::test]
async fn native_route_proxy_skips_disabled_route_response_headers() {
    let mut set = BTreeMap::new();
    set.insert("x-route".to_owned(), "native".to_owned());
    let policy = ResponseHeaderPolicyOverlayConfig {
        enabled: Some(false),
        set,
        ..Default::default()
    };
    let route = NativeHttp1RouteProxyRoute::exact_redirect(
        "/old",
        Vec::new(),
        "https://new.example{uri}",
        302,
    )
    .with_response_header_policy(&policy);
    let proxy = route_proxy_listener(NativeHttp1RouteProxy::new(vec![route], None)).await;

    let response = downstream_get(proxy, "/old").await;

    assert!(response.starts_with("HTTP/1.1 302 Found\r\n"));
    assert_eq!(response_header(&response, "x-route"), None);
    assert_eq!(
        response_header(&response, "location").as_deref(),
        Some("https://new.example/old")
    );
}
