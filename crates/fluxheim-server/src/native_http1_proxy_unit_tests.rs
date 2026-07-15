use crate::native_http1_cache::{
    NativeDiskCache, NativeDiskCacheStoreKey, NativeMemoryCacheEntry, native_cache_body_sha256,
    purge_native_disk_cache_primary, register_native_disk_cache_purge_handle,
};
use crate::native_http1_proxy_cache_policy::native_cache_expiry_times;
use crate::native_http1_proxy_peer_fill::{
    NATIVE_PEER_FILL_MARKER_HEADER, NativePeerFillPeer, native_peer_fill_fetch,
    native_request_is_peer_fill, strip_native_peer_fill_header,
};
use crate::native_http1_proxy_peer_fill_auth::{
    NATIVE_PEER_FILL_NONCE_HEADER, NATIVE_PEER_FILL_REQUEST_SIGNATURE_HEADER,
    NATIVE_PEER_FILL_RESPONSE_SIGNATURE_HEADER, NativePeerFillAuth, native_peer_fill_nonce,
    native_peer_fill_request_signature, native_peer_fill_request_signature_matches,
    native_peer_fill_response_signature_matches, native_peer_fill_response_without_cache_status,
    native_peer_fill_sign_response, native_response_single_header_value,
};
use crate::{NativeHttp1Request, NativeHttp1Response};
use fluxheim_protocol::Http1Version;
use sanitization::SecretVec;
use std::sync::Arc;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

#[test]
fn native_cache_expiry_times_rejects_unrepresentable_ttl() {
    assert!(native_cache_expiry_times(Instant::now(), Duration::MAX, None, None).is_none());
}

#[test]
fn native_cache_expiry_times_extends_stale_window_from_fresh_expiry() {
    let now = Instant::now();
    let (expires_at, stale_while_revalidate_until, stale_if_error_until) =
        native_cache_expiry_times(now, Duration::from_secs(1), Some(2), Some(3)).unwrap();

    assert!(expires_at > now);
    assert!(
        stale_while_revalidate_until
            .is_some_and(|stale_while_revalidate_until| stale_while_revalidate_until > expires_at)
    );
    assert!(
        stale_if_error_until.is_some_and(|stale_if_error_until| stale_if_error_until > expires_at)
    );
}

#[test]
fn strips_client_supplied_peer_fill_marker() {
    let mut request = NativeHttp1Request {
        method: "GET".to_owned(),
        peer_addr: None,
        local_addr: None,
        effective_client_addr: None,
        downstream_tls: false,
        tls_identity: None,
        geo_context: None,
        target: "/asset.png".to_owned(),
        version: Http1Version::Http11,
        headers: vec![
            (NATIVE_PEER_FILL_MARKER_HEADER.to_owned(), "1".to_owned()),
            ("host".to_owned(), "cache.test".to_owned()),
        ],
        body: Zeroizing::new(Vec::new()),
        trailers: Vec::new(),
    };

    assert!(native_request_is_peer_fill(&request));
    strip_native_peer_fill_header(&mut request);

    assert!(!native_request_is_peer_fill(&request));
    assert_eq!(
        request.headers,
        vec![("host".to_owned(), "cache.test".to_owned())]
    );
}

#[test]
fn native_peer_fill_auth_binds_response_body_and_headers() {
    let auth = NativePeerFillAuth {
        secret: Arc::new(SecretVec::from_vec(
            b"0123456789abcdef0123456789abcdef".to_vec(),
        )),
    };
    let nonce = native_peer_fill_nonce();
    let mut request = NativeHttp1Request {
        method: "GET".to_owned(),
        peer_addr: None,
        local_addr: None,
        effective_client_addr: None,
        downstream_tls: false,
        tls_identity: None,
        geo_context: None,
        target: "/asset.css?b=1".to_owned(),
        version: Http1Version::Http11,
        headers: vec![
            ("host".to_owned(), "cache.test".to_owned()),
            (NATIVE_PEER_FILL_MARKER_HEADER.to_owned(), "1".to_owned()),
            ("cache-control".to_owned(), "only-if-cached".to_owned()),
            (NATIVE_PEER_FILL_NONCE_HEADER.to_owned(), nonce.clone()),
        ],
        body: Zeroizing::new(Vec::new()),
        trailers: Vec::new(),
    };
    let signature =
        native_peer_fill_request_signature(&auth, &request.target, &request.headers, &nonce);
    request.headers.push((
        NATIVE_PEER_FILL_REQUEST_SIGNATURE_HEADER.to_owned(),
        signature,
    ));
    assert!(native_peer_fill_request_signature_matches(&auth, &request));

    let mut response = NativeHttp1Response::new(200, "OK", b"safe-body".to_vec())
        .with_header("cache-control", "max-age=60")
        .with_header("content-type", "text/css");
    native_peer_fill_sign_response(&auth, &request, &mut response);

    assert!(native_peer_fill_response_signature_matches(
        &auth, &request, &response
    ));

    let tampered_body = NativeHttp1Response::new(200, "OK", b"evil-body".to_vec())
        .with_header("cache-control", "max-age=60")
        .with_header("content-type", "text/css")
        .with_header(
            NATIVE_PEER_FILL_NONCE_HEADER,
            native_response_single_header_value(&response, NATIVE_PEER_FILL_NONCE_HEADER)
                .unwrap()
                .to_owned(),
        )
        .with_header(
            NATIVE_PEER_FILL_RESPONSE_SIGNATURE_HEADER,
            native_response_single_header_value(
                &response,
                NATIVE_PEER_FILL_RESPONSE_SIGNATURE_HEADER,
            )
            .unwrap()
            .to_owned(),
        );
    assert!(!native_peer_fill_response_signature_matches(
        &auth,
        &request,
        &tampered_body
    ));

    let unsigned = NativeHttp1Response::new(200, "OK", b"safe-body".to_vec())
        .with_header("cache-control", "max-age=60")
        .with_header("content-type", "text/css");
    assert!(!native_peer_fill_response_signature_matches(
        &auth, &request, &unsigned
    ));
}

#[tokio::test]
async fn native_peer_fill_fetch_discards_unsigned_authenticated_peer_response() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let authority = listener.local_addr().unwrap().to_string();
    let peer_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut buffer = [0_u8; 256];
        loop {
            let read = stream.read(&mut buffer).await.unwrap();
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        assert!(String::from_utf8_lossy(&request).contains("x-fluxheim-peer-fill-nonce: "));
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncache-control: max-age=60\r\ncontent-length: 12\r\n\r\npoison-body!",
            )
            .await
            .unwrap();
    });
    let auth = NativePeerFillAuth {
        secret: Arc::new(SecretVec::from_vec(
            b"0123456789abcdef0123456789abcdef".to_vec(),
        )),
    };
    let peer = NativePeerFillPeer {
        name: "forged-peer".to_owned(),
        base_path: String::new(),
        upstream: crate::NativeHttp1Upstream::new(authority),
    };
    let request = NativeHttp1Request {
        method: "GET".to_owned(),
        peer_addr: None,
        local_addr: None,
        effective_client_addr: None,
        downstream_tls: false,
        tls_identity: None,
        geo_context: None,
        target: "/poison.txt".to_owned(),
        version: Http1Version::Http11,
        headers: vec![("host".to_owned(), "cache.test".to_owned())],
        body: Zeroizing::new(Vec::new()),
        trailers: Vec::new(),
    };
    let cache = fluxheim_config::CacheConfig::default();

    let result = native_peer_fill_fetch(&peer, &cache, Some(&auth), &request, 1024)
        .await
        .unwrap();

    assert!(result.is_none());
    peer_task.await.unwrap();
}

#[test]
fn native_peer_fill_response_without_cache_status_strips_internal_auth_headers() {
    let cache = fluxheim_config::CacheConfig::default();
    let response = NativeHttp1Response::new(200, "OK", b"safe-body".to_vec())
        .with_header(NATIVE_PEER_FILL_NONCE_HEADER, "nonce")
        .with_header(NATIVE_PEER_FILL_RESPONSE_SIGNATURE_HEADER, "signature")
        .with_header("content-type", "text/plain");

    let response = native_peer_fill_response_without_cache_status(response, &cache);

    assert!(
        native_response_single_header_value(&response, NATIVE_PEER_FILL_NONCE_HEADER).is_none()
    );
    assert!(
        native_response_single_header_value(&response, NATIVE_PEER_FILL_RESPONSE_SIGNATURE_HEADER)
            .is_none()
    );
    assert_eq!(
        native_response_single_header_value(&response, "content-type"),
        Some("text/plain")
    );
}

#[test]
fn native_storage_bin_disk_purge_uses_live_cache_instance() {
    let root = tempfile::tempdir().unwrap();
    let mut config = fluxheim_config::CacheConfig {
        enabled: true,
        memory: fluxheim_config::CacheMemoryConfig {
            enabled: false,
            ..Default::default()
        },
        disk: fluxheim_config::CacheDiskConfig {
            enabled: true,
            path: Some(root.path().to_path_buf()),
            backend: fluxheim_config::CacheDiskBackend::StorageBin,
            max_size_bytes: fluxheim_config::ByteSize::from_bytes(1024 * 1024),
            ..Default::default()
        },
        ..Default::default()
    };
    config.disk.storage_bin.bin_size_bytes = fluxheim_config::ByteSize::from_bytes(64 * 1024);
    let cache = Arc::new(NativeDiskCache::from_config(&config).unwrap());
    let vhost = Arc::<str>::from("purge.test");
    register_native_disk_cache_purge_handle(vhost.clone(), None, &cache);

    let now = Instant::now();
    let entry = NativeMemoryCacheEntry {
        status: 200,
        reason: "OK".to_owned(),
        headers: vec![
            ("content-type".to_owned(), "image/png".to_owned()),
            ("cache-control".to_owned(), "max-age=60".to_owned()),
            ("content-length".to_owned(), "11".to_owned()),
            ("surrogate-key".to_owned(), "purge-live".to_owned()),
        ],
        content_length: Some(11),
        body: Arc::from(&b"hello-cache"[..]),
        body_sha256: Arc::new(native_cache_body_sha256(b"hello-cache")),
        expires_at: now + Duration::from_secs(60),
        stale_while_revalidate_until: None,
        stale_if_error_until: None,
        stored_at: now,
        weight: 128,
    };
    let key = NativeDiskCacheStoreKey {
        combined: "combined-live".to_owned(),
        primary: "primary-live".to_owned(),
        user_tag: vhost.to_string(),
        index_path: Some("/asset.png".to_owned()),
        cache_tags: vec!["purge-live".to_owned()],
        vary_fields: Vec::new(),
    };
    cache.store(key, &entry).unwrap();
    assert!(cache.get("combined-live", |_| None).is_some());
    assert_eq!(cache.stats().purge_index_entries, 1);

    assert!(purge_native_disk_cache_primary(
        "purge.test",
        None,
        "primary-live",
        "combined-live"
    ));
    assert!(cache.get("combined-live", |_| None).is_none());
    assert_eq!(cache.stats().purge_index_entries, 0);
}
