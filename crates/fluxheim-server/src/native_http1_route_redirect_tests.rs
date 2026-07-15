use crate::native_http1_route_static_web_tests::{
    downstream_get, response_header, route_proxy_listener,
};
use crate::{NativeHttp1RouteProxy, NativeHttp1RouteProxyRoute};

#[tokio::test]
async fn native_route_proxy_redirect_expands_uri_template() {
    let route = NativeHttp1RouteProxyRoute::prefix_redirect(
        "/old/",
        Vec::new(),
        "https://new.example{uri}",
        301,
    );
    let proxy = route_proxy_listener(NativeHttp1RouteProxy::new(vec![route], None)).await;

    let response = downstream_get(proxy, "/old/path?x=1").await;

    assert!(response.starts_with("HTTP/1.1 301 Moved Permanently\r\n"));
    assert_eq!(
        response_header(&response, "location").as_deref(),
        Some("https://new.example/old/path?x=1")
    );
    assert!(response.contains("Content-Length: 0\r\n"));
}

#[tokio::test]
async fn native_route_proxy_redirect_rejects_unsafe_uri_expansion() {
    let route = NativeHttp1RouteProxyRoute::prefix_redirect(
        "/old",
        Vec::new(),
        "https://new.example{uri}",
        308,
    );
    let proxy = route_proxy_listener(NativeHttp1RouteProxy::new(vec![route], None)).await;

    let response = downstream_get(proxy, "/old//admin").await;

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.ends_with("invalid redirect target\n"));
}

#[tokio::test]
async fn native_route_proxy_redirect_rejects_ambiguous_encoded_path() {
    let route = NativeHttp1RouteProxyRoute::prefix_redirect(
        "/old",
        Vec::new(),
        "https://new.example{uri}",
        308,
    );
    let proxy = route_proxy_listener(NativeHttp1RouteProxy::new(vec![route], None)).await;

    for target in ["/old/%c0%afadmin", "/old/%ff", "/old/%c2%85admin"] {
        let response = downstream_get(proxy, target).await;
        assert!(
            response.starts_with("HTTP/1.1 400 Bad Request\r\n"),
            "target: {target}"
        );
        assert!(response.ends_with("invalid redirect target\n"));
    }
}

#[tokio::test]
async fn native_route_proxy_redirect_rejects_query_path_traversal_expansion() {
    let route = NativeHttp1RouteProxyRoute::exact_redirect(
        "/file",
        Vec::new(),
        "https://cdn.example/files/{query}",
        302,
    );
    let proxy = route_proxy_listener(NativeHttp1RouteProxy::new(vec![route], None)).await;

    let response = downstream_get(proxy, "/file?../../admin/secrets").await;

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.ends_with("invalid redirect target\n"));
}

#[tokio::test]
async fn native_route_proxy_redirect_rejects_percent_encoded_query_path_traversal_expansion() {
    let route = NativeHttp1RouteProxyRoute::exact_redirect(
        "/file",
        Vec::new(),
        "https://cdn.example/files/{query}",
        302,
    );
    let proxy = route_proxy_listener(NativeHttp1RouteProxy::new(vec![route], None)).await;

    let response = downstream_get(proxy, "/file?%2e%2e/%2e%2e/admin/secrets").await;

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.ends_with("invalid redirect target\n"));
}

#[tokio::test]
async fn native_route_proxy_redirect_rejects_double_encoded_query_path_traversal_expansion() {
    let route = NativeHttp1RouteProxyRoute::exact_redirect(
        "/file",
        Vec::new(),
        "https://cdn.example/files/{query}",
        302,
    );
    let proxy = route_proxy_listener(NativeHttp1RouteProxy::new(vec![route], None)).await;

    let response = downstream_get(proxy, "/file?%252e%252e/secret").await;

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.ends_with("invalid redirect target\n"));
}

#[tokio::test]
async fn native_route_proxy_redirect_rejects_double_slash_location_path() {
    let route = NativeHttp1RouteProxyRoute::exact_redirect(
        "/file",
        Vec::new(),
        "https://cdn.example/{path}",
        302,
    );
    let proxy = route_proxy_listener(NativeHttp1RouteProxy::new(vec![route], None)).await;

    let response = downstream_get(proxy, "/file").await;

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.ends_with("invalid redirect target\n"));
}

#[tokio::test]
async fn native_route_proxy_redirect_rejects_percent_encoded_double_slash_location_path() {
    let route = NativeHttp1RouteProxyRoute::exact_redirect(
        "/file",
        Vec::new(),
        "https://cdn.example/files/{query}",
        302,
    );
    let proxy = route_proxy_listener(NativeHttp1RouteProxy::new(vec![route], None)).await;

    let response = downstream_get(proxy, "/file?%2f%2fadmin").await;

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.ends_with("invalid redirect target\n"));
}
