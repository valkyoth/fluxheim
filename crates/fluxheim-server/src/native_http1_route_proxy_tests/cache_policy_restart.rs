use std::time::Duration;

use crate::{
    DownstreamHttp1Policy, NativeHttp1Handler, NativeHttp1HostRouter, NativeHttp1Response,
};
use fluxheim_config::{CacheDiskBackend, CachePeerConfig, Config};

use super::{
    native_proxy_storage_bin_cache_config, route_test_request, upstream_raw_response_sequence,
};

const OLD: &str = "HTTP/1.1 200 OK\r\ncontent-type: image/png\r\ncache-control: max-age=120\r\nx-internal-token: old-fixture\r\ncontent-length: 3\r\n\r\nold";
const NEW: &str = "HTTP/1.1 200 OK\r\ncontent-type: image/png\r\ncache-control: max-age=120\r\nx-internal-token: new-fixture\r\ncontent-length: 3\r\n\r\nnew";

async fn get(router: &NativeHttp1HostRouter) -> NativeHttp1Response {
    let response = tokio::time::timeout(
        Duration::from_secs(5),
        router.handle(route_test_request("/asset.png")),
    )
    .await
    .unwrap();
    assert_eq!(response.status(), 200);
    response
}

fn header<'a>(response: &'a NativeHttp1Response, name: &str) -> Option<&'a str> {
    response
        .headers()
        .iter()
        .find_map(|(key, value)| key.eq_ignore_ascii_case(name).then_some(value.as_str()))
}

#[tokio::test]
async fn changed_security_policy_cannot_recover_an_old_disk_hit() {
    for backend in [CacheDiskBackend::Filesystem, CacheDiskBackend::StorageBin] {
        for memory in [false, true] {
            for policy in [
                "hide", "bypass", "ttl", "no-store", "stale", "peer", "epoch",
            ] {
                let directory = tempfile::tempdir().unwrap();
                let origin = upstream_raw_response_sequence(&[
                    ("/asset.png", OLD),
                    ("/asset.png", NEW),
                    ("/asset.png", NEW),
                ])
                .await;
                let mut config = Config::default();
                config.proxy.upstream = Some(origin.to_string());
                config.proxy.upstream_tls = false;
                config.cache =
                    native_proxy_storage_bin_cache_config(directory.path().canonicalize().unwrap());
                config.cache.disk.backend = backend;
                config.cache.memory.enabled = memory;
                let initial = NativeHttp1HostRouter::from_config(
                    &config,
                    DownstreamHttp1Policy::default(),
                    0,
                )
                .unwrap();
                assert_eq!(header(&get(&initial).await, "x-cache-status"), Some("MISS"));
                let warm = get(&initial).await;
                assert_eq!(header(&warm, "x-cache-status"), Some("HIT"));
                assert_eq!(header(&warm, "x-internal-token"), Some("old-fixture"));
                assert_eq!(warm.body(), b"old");
                drop(initial);

                match policy {
                    "hide" => config
                        .cache
                        .hide_response_headers
                        .push("x-internal-token".into()),
                    "bypass" => config
                        .cache
                        .bypass_cookie_names
                        .push("private-session".into()),
                    "ttl" => {
                        config.cache.status_ttls.insert(200, 30);
                    }
                    "no-store" => config
                        .cache
                        .no_store_response_headers
                        .push("x-internal-token".into()),
                    "stale" => config.cache.stale_if_error_secs = Some(1),
                    "peer" => {
                        let peer = upstream_raw_response_sequence(&[(
                            "/asset.png",
                            "HTTP/1.1 504 Gateway Timeout\r\ncontent-length: 0\r\n\r\n",
                        )])
                        .await;
                        config.cache.peer_fill.enabled = true;
                        config.cache.peer_fill.peers.push(CachePeerConfig {
                            name: "replacement-peer".into(),
                            base_url: format!("http://{peer}"),
                        });
                    }
                    "epoch" => config.cache.key_namespace = Some("external-policy-epoch-2".into()),
                    _ => unreachable!(),
                }
                let restarted = NativeHttp1HostRouter::from_config(
                    &config,
                    DownstreamHttp1Policy::default(),
                    0,
                )
                .unwrap();
                let fresh = get(&restarted).await;
                assert_eq!(
                    fresh.body(),
                    b"new",
                    "{backend:?}, memory={memory}, policy={policy}"
                );
                assert_ne!(header(&fresh, "x-cache-status"), Some("HIT"));
                let second = get(&restarted).await;
                assert_eq!(second.body(), b"new");
                if policy == "no-store" {
                    assert_ne!(header(&second, "x-cache-status"), Some("HIT"));
                } else {
                    assert_eq!(header(&second, "x-cache-status"), Some("HIT"));
                }
                if policy == "hide" {
                    assert_eq!(header(&second, "x-internal-token"), None);
                }
            }
        }
    }
}
