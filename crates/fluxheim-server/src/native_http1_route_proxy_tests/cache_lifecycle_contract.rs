use std::time::Duration;

use crate::{
    DownstreamHttp1Policy, NativeHttp1Handler, NativeHttp1HostRouter, NativeHttp1ReloadableRouter,
    NativeHttp1Response, NativeRequestBodyBudget,
};

use super::{
    native_proxy_storage_bin_cache_config, route_test_request, upstream_raw_response_sequence,
};

const ORIGIN_RESPONSE: &str = "HTTP/1.1 200 OK\r\ncontent-type: image/png\r\ncache-control: max-age=120\r\ncontent-length: 4\r\n\r\nbody";

fn config(root: &std::path::Path, upstream: std::net::SocketAddr) -> fluxheim_config::Config {
    let mut config = fluxheim_config::Config::default();
    config.proxy.upstream = Some(upstream.to_string());
    config.proxy.upstream_tls = false;
    config.cache = native_proxy_storage_bin_cache_config(root.to_path_buf());
    config
}

async fn get(handler: &impl NativeHttp1Handler) -> NativeHttp1Response {
    let response = tokio::time::timeout(
        Duration::from_secs(5),
        handler.handle(route_test_request("/asset.png")),
    )
    .await
    .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), b"body");
    response
}

fn cache_status(response: &NativeHttp1Response) -> Option<&str> {
    response.headers().iter().find_map(|(name, value)| {
        name.eq_ignore_ascii_case("x-cache-status")
            .then_some(value.as_str())
    })
}

// Current failures, not desired contracts. Replace these expectations with
// explicit initialization failure and qualified lease handoff in documented contract.
#[tokio::test]
async fn documented_storage_bin_reload_currently_loses_disk_cache() {
    let root = tempfile::tempdir().unwrap();
    let upstream = upstream_raw_response_sequence(&[
        ("/asset.png", ORIGIN_RESPONSE),
        ("/asset.png", ORIGIN_RESPONSE),
    ])
    .await;
    let baseline = config(&root.path().canonicalize().unwrap(), upstream);
    let handler =
        NativeHttp1HostRouter::from_config(&baseline, DownstreamHttp1Policy::default(), 0).unwrap();
    let (router, reloader) = NativeHttp1ReloadableRouter::new(
        handler,
        DownstreamHttp1Policy::default(),
        0,
        false,
        NativeRequestBodyBudget::new(1024 * 1024),
    );
    assert_eq!(cache_status(&get(&router).await), Some("MISS"));
    assert_eq!(cache_status(&get(&router).await), Some("HIT"));
    let mut candidate = baseline.clone();
    candidate.cache.status_reason_header = Some("x-new-cache-reason".to_owned());
    assert_eq!(
        fluxheim_config::reload::classify_reload(&baseline, &candidate),
        fluxheim_config::reload::ReloadImpact::Snapshot
    );
    reloader.reload_from_config(&candidate).unwrap();
    assert_eq!(cache_status(&get(&router).await), None);
    drop(reloader);
    drop(router);
    let restarted =
        NativeHttp1HostRouter::from_config(&candidate, DownstreamHttp1Policy::default(), 0)
            .unwrap();
    assert_eq!(cache_status(&get(&restarted).await), Some("HIT"));
}

#[tokio::test]
async fn documented_manifest_mismatch_currently_allows_uncached_router() {
    let root = tempfile::tempdir().unwrap();
    let upstream = upstream_raw_response_sequence(&[("/asset.png", ORIGIN_RESPONSE)]).await;
    let baseline = config(&root.path().canonicalize().unwrap(), upstream);
    let handler =
        NativeHttp1HostRouter::from_config(&baseline, DownstreamHttp1Policy::default(), 0).unwrap();
    drop(handler);
    let manifest_path = root.path().join(".fluxheim-storage-bin-v1");
    let manifest = std::fs::read(&manifest_path).unwrap();
    let mut candidate = baseline;
    candidate.cache.disk.storage_bin.max_open_bins += 1;
    let handler =
        NativeHttp1HostRouter::from_config(&candidate, DownstreamHttp1Policy::default(), 0)
            .unwrap();
    assert_eq!(cache_status(&get(&handler).await), None);
    assert_eq!(std::fs::read(manifest_path).unwrap(), manifest);
}
