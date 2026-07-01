use fluxheim_cache::{CacheRequestView, request_cache_bypass_reason, selected_cache_range_request};
use fluxheim_config::CacheConfig;
use fluxheim_protocol::Http1Version;

use crate::NativeHttp1Request;

fn native_http1_cache_view_request(
    method: &str,
    target: &str,
    headers: Vec<(String, String)>,
) -> NativeHttp1Request {
    NativeHttp1Request {
        method: method.to_owned(),
        peer_addr: None,
        local_addr: None,
        effective_client_addr: None,
        downstream_tls: false,
        tls_identity: None,
        geo_context: None,
        target: target.to_owned(),
        version: Http1Version::Http11,
        headers,
        body: zeroize::Zeroizing::new(Vec::new()),
        trailers: Vec::new(),
    }
}

#[test]
fn native_http1_request_implements_cache_request_view_for_origin_targets() {
    let request = native_http1_cache_view_request(
        "GET",
        "/assets/logo.png?v=1",
        vec![
            ("cache-control".to_owned(), "no-store".to_owned()),
            ("x-cache-bypass".to_owned(), "1".to_owned()),
        ],
    );
    let cache = CacheConfig {
        bypass_request_headers: vec!["x-cache-bypass".to_owned()],
        ..Default::default()
    };

    assert_eq!(CacheRequestView::method(&request), "GET");
    assert_eq!(CacheRequestView::path(&request), "/assets/logo.png");
    assert_eq!(CacheRequestView::query(&request), Some("v=1"));
    assert!(CacheRequestView::contains_header(&request, "Cache-Control"));
    assert_eq!(
        request_cache_bypass_reason(&request, &cache),
        Some("request-header")
    );
}

#[cfg(feature = "load-balancer")]
#[test]
fn native_http1_request_implements_load_balancer_request_view() {
    let request = native_http1_cache_view_request(
        "GET",
        "/api/items?page=2",
        vec![
            ("X-Hash".to_owned(), "one".to_owned()),
            ("x-hash".to_owned(), "two".to_owned()),
            ("Cookie".to_owned(), "session=abc; shard=blue".to_owned()),
            ("cookie".to_owned(), "other=ignored".to_owned()),
        ],
    );

    assert_eq!(
        fluxheim_load_balancer::LoadBalancerRequestView::uri_key(&request),
        b"/api/items?page=2".to_vec()
    );
    assert_eq!(
        fluxheim_load_balancer::LoadBalancerRequestView::header_values(&request, "x-hash")
            .map(|value| std::str::from_utf8(value)
                .expect("valid header value")
                .to_owned())
            .collect::<Vec<_>>(),
        vec!["one".to_owned(), "two".to_owned()]
    );
    assert_eq!(
        fluxheim_load_balancer::LoadBalancerRequestView::cookie_headers(&request)
            .collect::<Vec<_>>(),
        vec!["session=abc; shard=blue", "other=ignored"]
    );
}

#[cfg(feature = "load-balancer")]
#[test]
fn native_http1_request_drives_load_balancer_header_hash_selection() {
    let balancer = fluxheim_load_balancer::UpstreamLoadBalancer::from_proxy_config(
        &fluxheim_config::ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            load_balance: fluxheim_config::LoadBalanceConfig {
                selection: fluxheim_config::LoadBalanceSelection::HeaderHash,
                hash_header: Some("x-shard".to_owned()),
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .expect("load balancer config")
    .expect("load balancer");
    let first_request = native_http1_cache_view_request(
        "GET",
        "/api/items",
        vec![("x-shard".to_owned(), "tenant-a".to_owned())],
    );
    let second_request = native_http1_cache_view_request(
        "GET",
        "/api/items",
        vec![("X-Shard".to_owned(), "tenant-a".to_owned())],
    );

    let first = balancer
        .select(&first_request, None)
        .expect("first selection");
    let second = balancer
        .select(&second_request, None)
        .expect("second selection");

    assert_eq!(first.address(), second.address());
    assert!(first.authority() == "127.0.0.1:3000" || first.authority() == "127.0.0.1:3001");
}

#[test]
fn native_http1_request_cache_view_handles_absolute_targets_and_duplicate_headers() {
    let request = native_http1_cache_view_request(
        "GET",
        "http://example.test/images/a.webp?size=1",
        vec![
            ("range".to_owned(), "bytes=0-9".to_owned()),
            ("Range".to_owned(), "bytes=10-19".to_owned()),
        ],
    );
    let cache = CacheConfig {
        range: fluxheim_config::CacheRangeConfig {
            enabled: true,
            ..Default::default()
        },
        ..Default::default()
    };
    let mut ranges = Vec::new();
    CacheRequestView::visit_header_values(&request, "range", &mut |value| {
        ranges.push(value.to_owned());
    });

    assert_eq!(CacheRequestView::path(&request), "/images/a.webp");
    assert_eq!(CacheRequestView::query(&request), Some("size=1"));
    assert_eq!(ranges, ["bytes=0-9", "bytes=10-19"]);
    assert_eq!(selected_cache_range_request(&request, &cache), None);
}
