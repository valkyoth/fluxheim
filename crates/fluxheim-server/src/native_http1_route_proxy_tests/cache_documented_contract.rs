use std::time::Duration;

use crate::NativeHttp1RouteProxy;

use super::{
    downstream_get, downstream_request, native_proxy_memory_cache_config,
    native_proxy_tiered_cache_config, proxy_for, response_header, route_proxy_listener,
    route_proxy_listener_with_shutdown, upstream_raw_response_sequence,
    upstream_slice_response_sequence,
};

#[test]
fn peer_signature_rejects_negotiation_substitution() {
    use crate::native_http1_proxy_peer_fill_auth::*;
    use sanitization::SecretVec;
    use std::sync::Arc;

    let auth = NativePeerFillAuth {
        secret: Arc::new(SecretVec::from_vec(vec![42; 32])),
    };
    let mut request = super::route_test_request("/asset.png");
    request
        .headers
        .push(("cache-control".to_owned(), "only-if-cached".to_owned()));
    request.headers.push((
        crate::native_http1_proxy_peer_context::VERSION.to_owned(),
        "2".to_owned(),
    ));
    request.headers.push((
        crate::native_http1_proxy_peer_context::CONTEXT.to_owned(),
        "accept,accept-encoding,accept-language".to_owned(),
    ));
    request
        .headers
        .push(("accept-language".to_owned(), "en".to_owned()));
    let nonce = native_peer_fill_nonce();
    let signature =
        native_peer_fill_request_signature(&auth, &request.target, &request.headers, &nonce);
    request
        .headers
        .push((NATIVE_PEER_FILL_NONCE_HEADER.to_owned(), nonce));
    request.headers.push((
        NATIVE_PEER_FILL_REQUEST_SIGNATURE_HEADER.to_owned(),
        signature,
    ));
    let original = request.metadata_snapshot();
    for (name, value) in &mut request.headers {
        if name == "accept-language" {
            *value = "sv".to_owned();
        }
    }
    assert!(!native_peer_fill_request_signature_matches(&auth, &request));
    let mut response = crate::NativeHttp1Response::new(200, "OK", b"swedish-variant".to_vec())
        .with_header("vary", "Accept-Language")
        .with_header("content-type", "image/png");
    native_peer_fill_sign_response(&auth, &request, &mut response);
    assert!(!native_peer_fill_response_signature_matches(
        &auth, &original, &response
    ));
}

#[tokio::test]
async fn peer_fill_does_not_store_missing_custom_variant() {
    let origin = upstream_raw_response_sequence(&[(
        "/asset.png",
        "HTTP/1.1 200 OK\r\ncontent-type: image/png\r\ncache-control: max-age=60\r\nvary: X-Edition\r\ncontent-length: 7\r\n\r\ndefault",
    )])
    .await;
    let mut cache = native_proxy_memory_cache_config();
    cache.vary_request_headers = vec!["x-edition".to_owned()];
    let peer = route_proxy_listener(NativeHttp1RouteProxy::new(
        Vec::new(),
        Some(proxy_for(origin).with_proxy_cache_config(&cache)),
    ))
    .await;
    assert!(
        downstream_get(peer, "/asset.png")
            .await
            .ends_with("default")
    );
    cache.peer_fill.enabled = true;
    cache.peer_fill.fail_open = false;
    cache.peer_fill.peers = vec![fluxheim_config::CachePeerConfig {
        name: "fixture".to_owned(),
        base_url: format!("http://{peer}"),
    }];
    let front = route_proxy_listener(NativeHttp1RouteProxy::new(
        Vec::new(),
        Some(proxy_for(origin).with_proxy_cache_config(&cache)),
    ))
    .await;
    let request = "GET /asset.png HTTP/1.1\r\nHost: route.test\r\nX-Edition: special\r\nConnection: close\r\n\r\n";
    for _ in 0..2 {
        let response =
            tokio::time::timeout(Duration::from_secs(5), downstream_request(front, request))
                .await
                .unwrap();
        assert!(response.starts_with("HTTP/1.1 504"), "{response}");
        assert!(!response.ends_with("default"), "{response}");
    }
}

#[tokio::test]
async fn tiered_slices_survive_cache_restart() {
    for backend in [
        fluxheim_config::CacheDiskBackend::Filesystem,
        fluxheim_config::CacheDiskBackend::StorageBin,
    ] {
        let root = tempfile::tempdir().unwrap();
        let origin = upstream_slice_response_sequence(&[
            ("/asset.png", "bytes=0-3", "HTTP/1.1 206 Partial Content\r\ncontent-type: image/png\r\ncache-control: max-age=60\r\ncontent-range: bytes 0-3/8\r\netag: \"one\"\r\ncontent-length: 4\r\n\r\n0123"),
        ])
        .await;
        let mut cache = native_proxy_tiered_cache_config(root.path().to_path_buf());
        cache.disk.backend = backend;
        cache.disk.storage_bin.bin_size_bytes = fluxheim_config::ByteSize::from_bytes(65536);
        cache.range.enabled = true;
        cache.range.slice.enabled = true;
        cache.range.slice.size_bytes = fluxheim_config::ByteSize::from_bytes(4);
        let request = "GET /asset.png HTTP/1.1\r\nHost: route.test\r\nRange: bytes=0-3\r\nConnection: close\r\n\r\n";
        for restart in 0..2 {
            let (listener, shutdown, task) =
                route_proxy_listener_with_shutdown(NativeHttp1RouteProxy::new(
                    Vec::new(),
                    Some(proxy_for(origin).with_proxy_cache_config(&cache)),
                ))
                .await;
            for expected in [if restart == 0 { "MISS" } else { "HIT" }, "HIT"] {
                let response = tokio::time::timeout(
                    Duration::from_secs(5),
                    downstream_request(listener, request),
                )
                .await
                .unwrap();
                assert!(response.ends_with("0123"), "{response}");
                assert_eq!(
                    response_header(&response, "x-cache-status").as_deref(),
                    Some(expected)
                );
                assert_eq!(
                    response_header(&response, "x-cache-reason").as_deref(),
                    Some(if expected == "MISS" {
                        "slice-fill"
                    } else {
                        "slice"
                    })
                );
            }
            shutdown.send(()).unwrap();
            tokio::time::timeout(Duration::from_secs(5), task)
                .await
                .unwrap()
                .unwrap();
        }
    }
}
