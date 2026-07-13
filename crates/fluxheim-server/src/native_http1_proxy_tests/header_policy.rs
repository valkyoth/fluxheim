use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::{DownstreamHttp1Policy, NativeHttp1Proxy, NativeHttp1Upstream};

use super::{counting_upstream, proxy_listener_for, upstream};

#[tokio::test]
async fn native_proxy_applies_header_policy() {
    let upstream = upstream(|request, mut stream| async move {
        let request = String::from_utf8(request).unwrap();
        assert!(request.starts_with("GET /headers HTTP/1.1\r\n"));
        assert!(request.contains("x-root-request: native\r\n"));
        assert!(!request.contains("x-remove:"));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nx-remove-response: old\r\n\r\nok")
            .await
            .unwrap();
    })
    .await;
    let mut headers = fluxheim_config::HeaderPolicyConfig::default();
    headers.request.unset.push("x-remove".to_owned());
    headers
        .request
        .set
        .insert("x-root-request".to_owned(), "native".to_owned());
    headers.response.unset.push("x-remove-response".to_owned());
    headers
        .response
        .set
        .insert("x-root-response".to_owned(), "native".to_owned());
    let proxy = NativeHttp1Proxy::new(NativeHttp1Upstream::new(upstream.to_string()))
        .with_header_policy(&headers);
    let proxy = proxy_listener_for(proxy).await;

    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(b"GET /headers HTTP/1.1\r\nHost: proxy.test\r\nX-Remove: secret\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    let response = String::from_utf8(response).unwrap();

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("x-root-response: native\r\n"));
    assert!(response.contains("x-content-type-options: nosniff\r\n"));
    assert!(!response.contains("x-remove-response:"));
    assert!(response.ends_with("ok"));
}

#[tokio::test]
async fn native_proxy_root_config_applies_response_header_policy() {
    let upstream = upstream(|request, mut stream| async move {
        let request = String::from_utf8(request).unwrap();
        assert!(request.starts_with("GET /root-policy HTTP/1.1\r\n"));
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\n\
                  content-length: 4\r\n\
                  server: origin-edge\r\n\
                  x-powered-by: php\r\n\
                  x-root-remove: old\r\n\r\nroot",
            )
            .await
            .unwrap();
    })
    .await;

    let mut config = fluxheim_config::Config::default();
    config.proxy.upstreams = vec![upstream.to_string()];
    config
        .headers
        .response
        .unset
        .push("x-root-remove".to_owned());
    config
        .headers
        .response
        .set
        .insert("x-root-response".to_owned(), "native".to_owned());
    config.headers.response.append.insert(
        "x-root-append".to_owned(),
        fluxheim_config::HeaderValues::Many(vec!["one".to_owned()]),
    );

    let proxy = NativeHttp1Proxy::from_root_config(&config, DownstreamHttp1Policy::default(), 0)
        .unwrap()
        .unwrap();
    let proxy = proxy_listener_for(proxy).await;

    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(b"GET /root-policy HTTP/1.1\r\nHost: proxy.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    let response = String::from_utf8(response).unwrap();

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("x-root-response: native\r\n"));
    assert!(response.contains("x-root-append: one\r\n"));
    assert!(response.contains("x-content-type-options: nosniff\r\n"));
    assert!(response.contains("server: origin-edge\r\n"));
    assert!(!response.to_ascii_lowercase().contains("x-powered-by:"));
    assert!(!response.to_ascii_lowercase().contains("x-root-remove:"));
    assert!(response.ends_with("root"));
}

#[tokio::test]
async fn native_proxy_applies_opt_in_hardening_profile_with_explicit_overrides() {
    let upstream = upstream(|_, mut stream| async move {
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nserver: origin\r\n\r\nok")
            .await
            .unwrap();
    })
    .await;
    let mut headers = fluxheim_config::HeaderPolicyConfig::default();
    headers.response.hardening.profile =
        fluxheim_config::ResponseHardeningProfile::CrossOriginIsolated;
    headers.response.cross_origin_opener_policy =
        Some(fluxheim_config::CrossOriginOpenerPolicy::UnsafeNone);
    headers.response.content_security_policy_report_only =
        Some("default-src 'self'; report-to csp".to_owned());
    headers.response.reporting_endpoints.insert(
        "csp".to_owned(),
        "https://reports.example.test/csp".to_owned(),
    );
    headers
        .response
        .set
        .insert("server".to_owned(), "custom-edge".to_owned());
    let proxy = NativeHttp1Proxy::new(NativeHttp1Upstream::new(upstream.to_string()))
        .with_header_policy(&headers);
    let proxy = proxy_listener_for(proxy).await;

    let response = downstream_request(
        proxy,
        "GET / HTTP/1.1\r\nHost: proxy.test\r\nConnection: close\r\n\r\n",
    )
    .await;

    assert!(response.contains("server: custom-edge\r\n"));
    assert!(response.contains(
        "permissions-policy: camera=(), geolocation=(), microphone=(), payment=(), usb=()\r\n"
    ));
    assert!(response.contains("x-permitted-cross-domain-policies: none\r\n"));
    assert!(response.contains("cross-origin-opener-policy: unsafe-none\r\n"));
    assert!(response.contains("cross-origin-resource-policy: same-origin\r\n"));
    assert!(response.contains("cross-origin-embedder-policy: require-corp\r\n"));
    assert!(
        response
            .contains("content-security-policy-report-only: default-src 'self'; report-to csp\r\n")
    );
    assert!(response.contains("reporting-endpoints: csp=\"https://reports.example.test/csp\"\r\n"));
}

#[tokio::test]
async fn native_proxy_baseline_hardening_removes_origin_server_banner() {
    let upstream = upstream(|_, mut stream| async move {
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nserver: origin-edge\r\n\r\nok")
            .await
            .unwrap();
    })
    .await;
    let mut headers = fluxheim_config::HeaderPolicyConfig::default();
    headers.response.hardening.profile = fluxheim_config::ResponseHardeningProfile::Baseline;
    let proxy = NativeHttp1Proxy::new(NativeHttp1Upstream::new(upstream.to_string()))
        .with_header_policy(&headers);
    let proxy = proxy_listener_for(proxy).await;

    let response = downstream_request(
        proxy,
        "GET / HTTP/1.1\r\nHost: proxy.test\r\nConnection: close\r\n\r\n",
    )
    .await;

    assert!(!response.to_ascii_lowercase().contains("server:"));
    assert!(response.contains(
        "permissions-policy: camera=(), geolocation=(), microphone=(), payment=(), usb=()\r\n"
    ));
}

#[tokio::test]
async fn native_route_proxy_handles_validated_cors_preflight_and_actual_request() {
    let upstream = upstream(|request, mut stream| async move {
        let request = String::from_utf8(request).unwrap();
        assert!(request.starts_with("GET /resource HTTP/1.1\r\n"));
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nvary: Accept-Encoding\r\naccess-control-allow-origin: *\r\naccess-control-allow-methods: DELETE\r\naccess-control-max-age: 86400\r\n\r\nok",
            )
            .await
            .unwrap();
    })
    .await;
    let mut config = fluxheim_config::Config::default();
    config.proxy.upstreams = vec![upstream.to_string()];
    config.headers.cors = fluxheim_config::CorsPolicyConfig {
        enabled: true,
        allow_origins: vec!["https://app.example.test".to_owned()],
        allow_methods: vec!["GET".to_owned(), "POST".to_owned()],
        allow_headers: vec!["authorization".to_owned(), "content-type".to_owned()],
        expose_headers: vec!["x-request-id".to_owned()],
        allow_credentials: true,
        max_age_secs: Some(600),
    };
    config.headers.response.set.insert(
        "access-control-allow-methods".to_owned(),
        "DELETE".to_owned(),
    );
    config.headers.validate().unwrap();
    let proxy = crate::NativeHttp1RouteProxy::from_root_config(
        &config,
        DownstreamHttp1Policy::default(),
        0,
    )
    .unwrap();
    let proxy = route_proxy_listener(proxy).await;

    let denied = downstream_request(
        proxy,
        "OPTIONS /resource HTTP/1.1\r\nHost: proxy.test\r\nOrigin: https://evil.example\r\nAccess-Control-Request-Method: POST\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(denied.starts_with("HTTP/1.1 403 Forbidden\r\n"));

    let preflight = downstream_request(
        proxy,
        "OPTIONS /resource HTTP/1.1\r\nHost: proxy.test\r\nOrigin: https://app.example.test\r\nAccess-Control-Request-Method: POST\r\nAccess-Control-Request-Headers: Authorization, Content-Type\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(preflight.starts_with("HTTP/1.1 204 No Content\r\n"));
    assert!(preflight.contains("access-control-allow-origin: https://app.example.test\r\n"));
    assert!(preflight.contains("access-control-allow-credentials: true\r\n"));
    assert!(preflight.contains("access-control-allow-methods: GET, POST\r\n"));
    assert!(!preflight.contains("access-control-allow-methods: DELETE\r\n"));
    assert!(preflight.contains("access-control-allow-headers: authorization, content-type\r\n"));
    assert!(preflight.contains("access-control-max-age: 600\r\n"));
    assert!(preflight.contains(
        "vary: Origin, Access-Control-Request-Method, Access-Control-Request-Headers\r\n"
    ));

    let response = downstream_request(
        proxy,
        "GET /resource HTTP/1.1\r\nHost: proxy.test\r\nOrigin: https://app.example.test\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("access-control-allow-origin: https://app.example.test\r\n"));
    assert!(response.contains("access-control-allow-credentials: true\r\n"));
    assert!(response.contains("access-control-expose-headers: x-request-id\r\n"));
    assert!(response.contains("vary: Accept-Encoding, Origin\r\n"));
    assert!(!response.contains("access-control-allow-methods: DELETE\r\n"));
    assert!(!response.contains("access-control-max-age: 86400\r\n"));
}

#[tokio::test]
async fn native_route_proxy_enforces_cors_methods_on_actual_responses() {
    let (upstream, requests) = counting_upstream("ok", 2).await;
    let mut config = fluxheim_config::Config::default();
    config.proxy.upstreams = vec![upstream.to_string()];
    config.headers.cors = fluxheim_config::CorsPolicyConfig {
        enabled: true,
        allow_origins: vec!["https://app.example.test".to_owned()],
        allow_methods: vec!["POST".to_owned()],
        allow_headers: Vec::new(),
        expose_headers: Vec::new(),
        allow_credentials: true,
        max_age_secs: None,
    };
    config.headers.validate().unwrap();
    let proxy = crate::NativeHttp1RouteProxy::from_root_config(
        &config,
        DownstreamHttp1Policy::default(),
        0,
    )
    .unwrap();
    let proxy = route_proxy_listener(proxy).await;

    let get = downstream_request(
        proxy,
        "GET /resource HTTP/1.1\r\nHost: proxy.test\r\nOrigin: https://app.example.test\r\nConnection: close\r\n\r\n",
    )
    .await;
    let post = downstream_request(
        proxy,
        "POST /resource HTTP/1.1\r\nHost: proxy.test\r\nOrigin: https://app.example.test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    )
    .await;

    assert!(get.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(!get.contains("access-control-allow-origin:"));
    assert!(!get.contains("access-control-allow-credentials:"));
    assert!(post.contains("access-control-allow-origin: https://app.example.test\r\n"));
    assert!(post.contains("access-control-allow-credentials: true\r\n"));
    assert_eq!(requests.load(std::sync::atomic::Ordering::Acquire), 2);
}

async fn downstream_request(proxy: std::net::SocketAddr, request: &str) -> String {
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    String::from_utf8(response).unwrap()
}

async fn route_proxy_listener(route_proxy: crate::NativeHttp1RouteProxy) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        crate::serve_native_http1_listener(
            listener,
            DownstreamHttp1Policy::default(),
            Arc::new(route_proxy),
            std::future::pending(),
        )
        .await
        .unwrap();
    });
    addr
}

#[cfg(not(feature = "privacy-mode"))]
#[tokio::test]
async fn native_proxy_applies_default_forwarded_header_policy() {
    let upstream = upstream(|request, mut stream| async move {
        let request = String::from_utf8(request).unwrap();
        assert!(request.contains("x-forwarded-for: 127.0.0.1\r\n"));
        assert!(request.contains("x-real-ip: 127.0.0.1\r\n"));
        assert!(request.contains("x-forwarded-host: proxy.test\r\n"));
        assert!(request.contains("x-forwarded-proto: http\r\n"));
        assert!(!request.contains("x-forwarded-for: 192.0.2.9\r\n"));
        assert!(!request.contains("forwarded: for=192.0.2.9\r\n"));
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\ncontent-length: 0\r\n\r\n")
            .await
            .unwrap();
    })
    .await;
    let proxy = NativeHttp1Proxy::new(NativeHttp1Upstream::new(upstream.to_string()))
        .with_header_policy(&fluxheim_config::HeaderPolicyConfig::default());
    let proxy = proxy_listener_for(proxy).await;

    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(
            b"GET /forwarded HTTP/1.1\r\n\
              Host: proxy.test\r\n\
              X-Forwarded-For: 192.0.2.9\r\n\
              Forwarded: for=192.0.2.9\r\n\
              Connection: close\r\n\r\n",
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    let response = String::from_utf8(response).unwrap();

    assert!(response.starts_with("HTTP/1.1 204 No Content\r\n"));
}

#[cfg(not(feature = "privacy-mode"))]
#[tokio::test]
async fn native_proxy_honors_forwarded_for_off_policy() {
    let upstream = upstream(|request, mut stream| async move {
        let request = String::from_utf8(request).unwrap();
        assert!(!request.to_ascii_lowercase().contains("x-forwarded-for:"));
        assert!(request.contains("x-forwarded-host: proxy.test\r\n"));
        assert!(request.contains("x-forwarded-proto: http\r\n"));
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\ncontent-length: 0\r\n\r\n")
            .await
            .unwrap();
    })
    .await;
    let mut headers = fluxheim_config::HeaderPolicyConfig::default();
    headers.request.x_forwarded_for = fluxheim_config::ForwardedClientIpHeaderMode::Off;
    let proxy = NativeHttp1Proxy::new(NativeHttp1Upstream::new(upstream.to_string()))
        .with_header_policy(&headers);
    let proxy = proxy_listener_for(proxy).await;

    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(b"GET /forwarded HTTP/1.1\r\nHost: proxy.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    let response = String::from_utf8(response).unwrap();

    assert!(response.starts_with("HTTP/1.1 204 No Content\r\n"));
}
