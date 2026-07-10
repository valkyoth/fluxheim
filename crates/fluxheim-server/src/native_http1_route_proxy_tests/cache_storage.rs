use tokio::net::TcpListener;

use crate::NativeHttp1RouteProxy;

#[cfg(feature = "openbao-cache-encryption")]
use super::native_proxy_openbao_storage_bin_cache_config;
use super::{
    downstream_get, native_proxy_disk_cache_config, native_proxy_encrypted_disk_cache_config,
    native_proxy_encrypted_storage_bin_cache_config, native_proxy_memory_cache_config,
    native_proxy_storage_bin_cache_config, native_proxy_tiered_cache_config, proxy_for,
    response_header, route_proxy_listener, upstream_cacheable_once,
};

#[tokio::test]
async fn native_route_proxy_caches_proxy_response_in_memory() {
    let upstream = upstream_cacheable_once("origin-one").await;
    let cache = native_proxy_memory_cache_config();
    let proxy = proxy_for(upstream).with_proxy_cache_config(&cache);
    let listener = route_proxy_listener(NativeHttp1RouteProxy::new(Vec::new(), Some(proxy))).await;

    let first = downstream_get(listener, "/asset.png").await;
    let second = downstream_get(listener, "/asset.png").await;

    assert!(first.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(first.ends_with("origin-one"));
    assert_eq!(
        response_header(&first, "x-cache-status").as_deref(),
        Some("MISS")
    );
    assert!(
        second.starts_with("HTTP/1.1 200 OK\r\n"),
        "unexpected second response: {second:?}"
    );
    assert!(second.ends_with("origin-one"));
    assert_eq!(
        response_header(&second, "x-cache-status").as_deref(),
        Some("HIT")
    );
}

#[tokio::test]
async fn native_route_proxy_caches_proxy_response_on_disk() {
    let root = tempfile::tempdir().unwrap();
    let upstream = upstream_cacheable_once("disk-origin").await;
    let cache = native_proxy_disk_cache_config(root.path().to_path_buf());
    let first_proxy = proxy_for(upstream).with_proxy_cache_config(&cache);
    let first_listener =
        route_proxy_listener(NativeHttp1RouteProxy::new(Vec::new(), Some(first_proxy))).await;

    let first = downstream_get(first_listener, "/asset.png").await;
    assert!(first.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(first.ends_with("disk-origin"));
    assert_eq!(
        response_header(&first, "x-cache-status").as_deref(),
        Some("MISS")
    );

    let unused_origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let unavailable_origin = unused_origin_listener.local_addr().unwrap();
    drop(unused_origin_listener);
    let second_proxy = proxy_for(unavailable_origin).with_proxy_cache_config(&cache);
    let second_listener =
        route_proxy_listener(NativeHttp1RouteProxy::new(Vec::new(), Some(second_proxy))).await;

    let second = downstream_get(second_listener, "/asset.png").await;
    assert!(
        second.starts_with("HTTP/1.1 200 OK\r\n"),
        "unexpected second response: {second:?}"
    );
    assert!(second.ends_with("disk-origin"));
    assert_eq!(
        response_header(&second, "x-cache-status").as_deref(),
        Some("HIT")
    );
}

#[tokio::test]
async fn native_route_proxy_caches_proxy_response_on_encrypted_disk() {
    let root = tempfile::tempdir().unwrap();
    let key_file = root.path().join("cache.key");
    std::fs::write(
        &key_file,
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n",
    )
    .unwrap();
    let cache_root = root.path().join("objects");
    let upstream = upstream_cacheable_once("encrypted-disk-origin").await;
    let cache = native_proxy_encrypted_disk_cache_config(cache_root.clone(), key_file);
    let first_proxy = proxy_for(upstream).with_proxy_cache_config(&cache);
    let first_listener =
        route_proxy_listener(NativeHttp1RouteProxy::new(Vec::new(), Some(first_proxy))).await;

    let first = downstream_get(first_listener, "/asset.png").await;
    assert!(first.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(first.ends_with("encrypted-disk-origin"));
    assert_eq!(
        response_header(&first, "x-cache-status").as_deref(),
        Some("MISS")
    );

    let encrypted_objects = native_disk_cache_object_bytes(&cache_root);
    assert!(!encrypted_objects.is_empty());
    assert!(
        encrypted_objects
            .iter()
            .any(|bytes| bytes.starts_with(b"FLUXHEIM-CACHE-ENC-v1\n"))
    );
    assert!(encrypted_objects.iter().all(|bytes| {
        !bytes
            .windows("encrypted-disk-origin".len())
            .any(|window| window == "encrypted-disk-origin".as_bytes())
    }));

    let unused_origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let unavailable_origin = unused_origin_listener.local_addr().unwrap();
    drop(unused_origin_listener);
    let second_proxy = proxy_for(unavailable_origin).with_proxy_cache_config(&cache);
    let second_listener =
        route_proxy_listener(NativeHttp1RouteProxy::new(Vec::new(), Some(second_proxy))).await;

    let second = downstream_get(second_listener, "/asset.png").await;
    assert!(second.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(second.ends_with("encrypted-disk-origin"));
    assert_eq!(
        response_header(&second, "x-cache-status").as_deref(),
        Some("HIT")
    );
}

#[tokio::test]
async fn native_route_proxy_caches_proxy_response_on_storage_bin_disk() {
    let root = tempfile::tempdir().unwrap();
    let upstream = upstream_cacheable_once("storage-bin-origin").await;
    let cache = native_proxy_storage_bin_cache_config(root.path().to_path_buf());
    let first_proxy = proxy_for(upstream).with_proxy_cache_config(&cache);
    let first_listener =
        route_proxy_listener(NativeHttp1RouteProxy::new(Vec::new(), Some(first_proxy))).await;

    let first = downstream_get(first_listener, "/asset.png").await;
    assert!(first.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(first.ends_with("storage-bin-origin"));
    assert_eq!(
        response_header(&first, "x-cache-status").as_deref(),
        Some("MISS")
    );
    wait_for_storage_bin_index(root.path()).await;
    assert!(root.path().join(".fluxheim-storage-bin-v1").is_file());
    assert!(root.path().join(".fluxheim-storage-bin-index-v1").is_file());
    assert!(root.path().join("bins").is_dir());

    let unused_origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let unavailable_origin = unused_origin_listener.local_addr().unwrap();
    drop(unused_origin_listener);
    let second_proxy = proxy_for(unavailable_origin).with_proxy_cache_config(&cache);
    let second_listener =
        route_proxy_listener(NativeHttp1RouteProxy::new(Vec::new(), Some(second_proxy))).await;

    let second = downstream_get(second_listener, "/asset.png").await;
    assert!(second.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(second.ends_with("storage-bin-origin"));
    assert_eq!(
        response_header(&second, "x-cache-status").as_deref(),
        Some("HIT")
    );
}

#[tokio::test]
async fn native_route_proxy_caches_proxy_response_on_encrypted_storage_bin_disk() {
    let root = tempfile::tempdir().unwrap();
    let key_file = root.path().join("cache.key");
    std::fs::write(
        &key_file,
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n",
    )
    .unwrap();
    let cache_root = root.path().join("objects");
    let upstream = upstream_cacheable_once("encrypted-storage-bin-origin").await;
    let cache = native_proxy_encrypted_storage_bin_cache_config(cache_root.clone(), key_file);
    let first_proxy = proxy_for(upstream).with_proxy_cache_config(&cache);
    let first_listener =
        route_proxy_listener(NativeHttp1RouteProxy::new(Vec::new(), Some(first_proxy))).await;

    let first = downstream_get(first_listener, "/asset.png").await;
    assert!(first.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(first.ends_with("encrypted-storage-bin-origin"));
    assert_eq!(
        response_header(&first, "x-cache-status").as_deref(),
        Some("MISS")
    );
    wait_for_storage_bin_index(&cache_root).await;
    let bin_bytes = native_storage_bin_bytes(&cache_root);
    assert!(!bin_bytes.is_empty());
    assert!(bin_bytes.iter().all(|bytes| {
        !bytes
            .windows("encrypted-storage-bin-origin".len())
            .any(|window| window == "encrypted-storage-bin-origin".as_bytes())
    }));

    let unused_origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let unavailable_origin = unused_origin_listener.local_addr().unwrap();
    drop(unused_origin_listener);
    let second_proxy = proxy_for(unavailable_origin).with_proxy_cache_config(&cache);
    let second_listener =
        route_proxy_listener(NativeHttp1RouteProxy::new(Vec::new(), Some(second_proxy))).await;

    let second = downstream_get(second_listener, "/asset.png").await;
    assert!(second.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(second.ends_with("encrypted-storage-bin-origin"));
    assert_eq!(
        response_header(&second, "x-cache-status").as_deref(),
        Some("HIT")
    );
}

#[cfg(feature = "openbao-cache-encryption")]
#[tokio::test]
async fn native_route_proxy_caches_proxy_response_on_openbao_storage_bin_disk() {
    let root = tempfile::tempdir().unwrap();
    let token_file = root.path().join("openbao.token");
    std::fs::write(&token_file, "test-token\n").unwrap();
    let openbao = native_openbao_transit_mock();
    let cache_root = root.path().join("objects");
    let upstream = upstream_cacheable_once("openbao-storage-bin-origin").await;
    let cache = native_proxy_openbao_storage_bin_cache_config(
        cache_root.clone(),
        openbao.address.clone(),
        token_file,
    );
    let first_proxy = proxy_for(upstream).with_proxy_cache_config(&cache);
    let first_listener =
        route_proxy_listener(NativeHttp1RouteProxy::new(Vec::new(), Some(first_proxy))).await;

    let first = downstream_get(first_listener, "/asset.png").await;
    assert!(first.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(first.ends_with("openbao-storage-bin-origin"));
    assert_eq!(
        response_header(&first, "x-cache-status").as_deref(),
        Some("MISS")
    );
    wait_for_storage_bin_index(&cache_root).await;
    let bin_bytes = native_storage_bin_bytes(&cache_root);
    assert!(!bin_bytes.is_empty());
    assert!(
        bin_bytes
            .iter()
            .any(|bytes| bytes.windows(8).any(|window| window == b"vault:v1"))
    );
    assert!(bin_bytes.iter().all(|bytes| {
        !bytes
            .windows("openbao-storage-bin-origin".len())
            .any(|window| window == "openbao-storage-bin-origin".as_bytes())
    }));

    let unused_origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let unavailable_origin = unused_origin_listener.local_addr().unwrap();
    drop(unused_origin_listener);
    let second_proxy = proxy_for(unavailable_origin).with_proxy_cache_config(&cache);
    let second_listener =
        route_proxy_listener(NativeHttp1RouteProxy::new(Vec::new(), Some(second_proxy))).await;

    let second = downstream_get(second_listener, "/asset.png").await;
    let requests = openbao.join();
    assert_eq!(requests.len(), 3);
    assert!(requests[0].contains("POST /v1/transit/cache/encrypt/native-key HTTP/1.1"));
    assert!(
        requests[0]
            .to_ascii_lowercase()
            .contains("x-vault-token: test-token")
    );
    assert!(requests[0].contains("\"associated_data\""));
    assert!(requests[1].contains("POST /v1/transit/cache/decrypt/native-key HTTP/1.1"));
    assert!(requests[1].contains("\"ciphertext\""));
    assert!(requests[1].contains("vault:v1:native-test"));
    assert!(requests[2].contains("POST /v1/transit/cache/decrypt/native-key HTTP/1.1"));
    assert!(requests[2].contains("\"ciphertext\""));
    assert!(requests[2].contains("vault:v1:native-test"));
    assert!(
        second.starts_with("HTTP/1.1 200 OK\r\n"),
        "unexpected second response: {second:?}"
    );
    assert!(second.ends_with("openbao-storage-bin-origin"));
    assert_eq!(
        response_header(&second, "x-cache-status").as_deref(),
        Some("HIT")
    );
}

#[tokio::test]
async fn native_route_proxy_tiered_cache_refills_memory_from_disk() {
    let root = tempfile::tempdir().unwrap();
    let upstream = upstream_cacheable_once("tiered-origin").await;
    let cache = native_proxy_tiered_cache_config(root.path().to_path_buf());
    let first_proxy = proxy_for(upstream).with_proxy_cache_config(&cache);
    let first_listener =
        route_proxy_listener(NativeHttp1RouteProxy::new(Vec::new(), Some(first_proxy))).await;

    let first = downstream_get(first_listener, "/asset.png").await;
    assert!(first.ends_with("tiered-origin"));
    assert_eq!(
        response_header(&first, "x-cache-status").as_deref(),
        Some("MISS")
    );

    let unused_origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let unavailable_origin = unused_origin_listener.local_addr().unwrap();
    drop(unused_origin_listener);
    let second_proxy = proxy_for(unavailable_origin).with_proxy_cache_config(&cache);
    let second_listener =
        route_proxy_listener(NativeHttp1RouteProxy::new(Vec::new(), Some(second_proxy))).await;

    let second = downstream_get(second_listener, "/asset.png").await;
    let third = downstream_get(second_listener, "/asset.png").await;
    assert!(second.ends_with("tiered-origin"));
    assert!(third.ends_with("tiered-origin"));
    assert_eq!(
        response_header(&second, "x-cache-status").as_deref(),
        Some("HIT")
    );
    assert_eq!(
        response_header(&third, "x-cache-status").as_deref(),
        Some("HIT")
    );
}

fn native_disk_cache_object_bytes(root: &std::path::Path) -> Vec<Vec<u8>> {
    let mut objects = Vec::new();
    native_collect_disk_cache_object_bytes(root, &mut objects);
    objects
}

fn native_collect_disk_cache_object_bytes(root: &std::path::Path, objects: &mut Vec<Vec<u8>>) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            native_collect_disk_cache_object_bytes(&path, objects);
        } else if path.extension().and_then(|value| value.to_str()) == Some("fhc")
            && let Ok(bytes) = std::fs::read(&path)
        {
            objects.push(bytes);
        }
    }
}

fn native_storage_bin_bytes(root: &std::path::Path) -> Vec<Vec<u8>> {
    let Ok(entries) = std::fs::read_dir(root.join("bins")) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|entry| std::fs::read(entry.path()).ok())
        .collect()
}

async fn wait_for_storage_bin_index(root: &std::path::Path) {
    let index = root.join(".fluxheim-storage-bin-index-v1");
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        while !index.is_file() {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}

#[cfg(feature = "openbao-cache-encryption")]
struct NativeOpenBaoTransitMock {
    address: String,
    handle: std::thread::JoinHandle<Vec<String>>,
}

#[cfg(feature = "openbao-cache-encryption")]
impl NativeOpenBaoTransitMock {
    fn join(self) -> Vec<String> {
        self.handle.join().unwrap()
    }
}

#[cfg(feature = "openbao-cache-encryption")]
fn native_openbao_transit_mock() -> NativeOpenBaoTransitMock {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = format!("http://{}", listener.local_addr().unwrap());
    let handle = std::thread::spawn(move || {
        let mut requests = Vec::new();
        let (mut encrypt_stream, _) = listener.accept().unwrap();
        let encrypt_request = native_openbao_read_request(&mut encrypt_stream);
        let encrypt_body = native_openbao_request_body(&encrypt_request);
        let encrypt_json: serde_json::Value = serde_json::from_str(encrypt_body).unwrap();
        let plaintext = encrypt_json
            .pointer("/plaintext")
            .and_then(serde_json::Value::as_str)
            .unwrap()
            .to_owned();
        let decoded_plaintext = base64_ng::STANDARD
            .decode_vec(plaintext.as_bytes())
            .unwrap();
        assert!(decoded_plaintext.starts_with(b"FLUXHEIM-CACHE-v5\n"));
        assert!(
            decoded_plaintext
                .windows("openbao-storage-bin-origin".len())
                .any(|window| window == "openbao-storage-bin-origin".as_bytes())
        );
        native_openbao_write_response(
            &mut encrypt_stream,
            r#"{"data":{"ciphertext":"vault:v1:native-test"}}"#,
        );
        requests.push(encrypt_request);

        for _ in 0..2 {
            let (mut decrypt_stream, _) = listener.accept().unwrap();
            let decrypt_request = native_openbao_read_request(&mut decrypt_stream);
            native_openbao_write_response(
                &mut decrypt_stream,
                &format!(r#"{{"data":{{"plaintext":"{plaintext}"}}}}"#),
            );
            requests.push(decrypt_request);
        }
        requests
    });
    NativeOpenBaoTransitMock { address, handle }
}

#[cfg(feature = "openbao-cache-encryption")]
fn native_openbao_read_request(stream: &mut std::net::TcpStream) -> String {
    use std::io::Read as _;

    let mut request = Vec::new();
    let mut chunk = [0_u8; 1024];
    let mut header_end = None;
    while header_end.is_none() {
        let read = stream.read(&mut chunk).unwrap();
        assert!(read > 0, "mock OpenBao connection closed before headers");
        request.extend_from_slice(&chunk[..read]);
        header_end = request.windows(4).position(|window| window == b"\r\n\r\n");
    }
    let header_end = header_end.unwrap() + 4;
    let headers = std::str::from_utf8(&request[..header_end]).unwrap();
    let content_length = headers
        .lines()
        .find_map(|line| {
            line.strip_prefix("Content-Length:")
                .or_else(|| line.strip_prefix("content-length:"))
                .and_then(|value| value.trim().parse::<usize>().ok())
        })
        .unwrap_or(0);
    while request.len() < header_end + content_length {
        let read = stream.read(&mut chunk).unwrap();
        assert!(read > 0, "mock OpenBao connection closed before body");
        request.extend_from_slice(&chunk[..read]);
    }
    String::from_utf8(request).unwrap()
}

#[cfg(feature = "openbao-cache-encryption")]
fn native_openbao_request_body(request: &str) -> &str {
    request
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap()
}

#[cfg(feature = "openbao-cache-encryption")]
fn native_openbao_write_response(stream: &mut std::net::TcpStream, body: &str) {
    use std::io::Write as _;

    stream
        .write_all(
            format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
                body.len(),
                body
            )
            .as_bytes(),
        )
        .unwrap();
}
