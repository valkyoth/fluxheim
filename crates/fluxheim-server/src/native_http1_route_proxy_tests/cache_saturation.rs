use tokio::net::TcpListener;

use crate::NativeHttp1RouteProxy;

use super::{
    downstream_get, native_proxy_disk_cache_config, native_proxy_tiered_cache_config, proxy_for,
    response_header, route_proxy_listener, upstream_cacheable_once_with_max_age,
};

const DISK_CACHE_SATURATION_CHILD: &str = "FLUXHEIM_DISK_CACHE_SATURATION_CHILD";

#[tokio::test]
async fn disk_cache_saturation_child_process() {
    if std::env::var_os(DISK_CACHE_SATURATION_CHILD).is_none() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let cache = native_proxy_disk_cache_config(root.path().to_path_buf());
    let unavailable_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let unavailable_origin = unavailable_listener.local_addr().unwrap();
    drop(unavailable_listener);
    let proxy = proxy_for(unavailable_origin).with_proxy_cache_config(&cache);
    let listener = route_proxy_listener(NativeHttp1RouteProxy::new(Vec::new(), Some(proxy))).await;
    let permits = crate::blocking_work::exhaust_disk_cache_blocking_work_for_test();

    let response = downstream_get(listener, "/asset.png").await;

    assert!(response.starts_with("HTTP/1.1 503 Service Unavailable\r\n"));
    assert!(response.ends_with("cache temporarily unavailable\n"));
    assert_eq!(
        response_header(&response, "x-cache-status").as_deref(),
        Some("BYPASS")
    );
    drop(permits);

    let stale_root = tempfile::tempdir().unwrap();
    let upstream = upstream_cacheable_once_with_max_age("stale-memory", 1).await;
    let mut stale_cache = native_proxy_tiered_cache_config(stale_root.path().to_path_buf());
    stale_cache.stale_while_revalidate_secs = Some(60);
    let stale_proxy = proxy_for(upstream).with_proxy_cache_config(&stale_cache);
    let stale_listener =
        route_proxy_listener(NativeHttp1RouteProxy::new(Vec::new(), Some(stale_proxy))).await;
    let first = downstream_get(stale_listener, "/asset.png").await;
    assert!(first.ends_with("stale-memory"));
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let _permits = crate::blocking_work::exhaust_disk_cache_blocking_work_for_test();

    let stale = downstream_get(stale_listener, "/asset.png").await;

    assert!(stale.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(stale.ends_with("stale-memory"));
    assert_eq!(
        response_header(&stale, "x-cache-status").as_deref(),
        Some("STALE-UPDATING")
    );
}

#[test]
fn disk_cache_saturation_fails_closed_without_origin_contact() {
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg(
            "native_http1_route_proxy_tests::cache_saturation_tests::disk_cache_saturation_child_process",
        )
        .arg("--nocapture")
        .env(DISK_CACHE_SATURATION_CHILD, "1")
        .status()
        .unwrap();

    assert!(status.success());
}
