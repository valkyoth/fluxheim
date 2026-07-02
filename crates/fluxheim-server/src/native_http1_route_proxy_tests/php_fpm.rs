#[cfg(feature = "php-fpm")]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(feature = "php-fpm")]
use tokio::net::{TcpListener, TcpStream};

#[cfg(feature = "php-fpm")]
use crate::{DownstreamHttp1Policy, NativeHttp1RouteProxy};
use crate::{
    NativeHttp1ProxyConfigError, NativeHttp1RouteProxyConfigError, NativeHttp1RouteProxyRoute,
};

use super::native_route_proxy_test_route;
#[cfg(feature = "php-fpm")]
use super::{downstream_get, native_route_proxy_test_vhost, response_header, route_proxy_listener};

#[cfg(feature = "php-fpm")]
async fn fastcgi_responder(stdout: &'static [u8]) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request_id = 1_u16;
        let mut params_done = false;
        let mut stdin_done = false;
        while !(params_done && stdin_done) {
            let (record_type, id, content) = read_fastcgi_record(&mut stream).await;
            request_id = id;
            match record_type {
                4 if content.is_empty() => params_done = true,
                5 if content.is_empty() => stdin_done = true,
                _ => {}
            }
        }
        write_fastcgi_record(&mut stream, 6, request_id, stdout)
            .await
            .unwrap();
        write_fastcgi_record(&mut stream, 6, request_id, b"")
            .await
            .unwrap();
        write_fastcgi_record(&mut stream, 3, request_id, &[0, 0, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        stream.shutdown().await.unwrap();
    });
    addr
}

#[cfg(feature = "php-fpm")]
async fn read_fastcgi_record(stream: &mut TcpStream) -> (u8, u16, Vec<u8>) {
    let mut header = [0_u8; 8];
    stream.read_exact(&mut header).await.unwrap();
    assert_eq!(header[0], 1, "unexpected FastCGI version");
    let record_type = header[1];
    let request_id = u16::from_be_bytes([header[2], header[3]]);
    let content_len = u16::from_be_bytes([header[4], header[5]]) as usize;
    let padding_len = header[6] as usize;
    let mut content = vec![0_u8; content_len];
    if content_len > 0 {
        stream.read_exact(&mut content).await.unwrap();
    }
    if padding_len > 0 {
        let mut padding = vec![0_u8; padding_len];
        stream.read_exact(&mut padding).await.unwrap();
    }
    (record_type, request_id, content)
}

#[cfg(feature = "php-fpm")]
async fn write_fastcgi_record(
    stream: &mut TcpStream,
    record_type: u8,
    request_id: u16,
    content: &[u8],
) -> std::io::Result<()> {
    let len = u16::try_from(content.len()).unwrap();
    let mut header = [0_u8; 8];
    header[0] = 1;
    header[1] = record_type;
    header[2..4].copy_from_slice(&request_id.to_be_bytes());
    header[4..6].copy_from_slice(&len.to_be_bytes());
    stream.write_all(&header).await?;
    stream.write_all(content).await
}

#[test]
fn native_route_proxy_rejects_route_php_without_root() {
    let mut route = native_route_proxy_test_route();
    route.redirect = None;
    route.php = Some(fluxheim_config::PhpConfig {
        enabled: true,
        ..Default::default()
    });

    let error = NativeHttp1RouteProxyRoute::from_config(&route, None).unwrap_err();

    assert_eq!(
        error,
        NativeHttp1RouteProxyConfigError::Proxy(NativeHttp1ProxyConfigError::PhpFpm)
    );
}

#[cfg(feature = "php-fpm")]
#[tokio::test]
async fn native_route_proxy_php_route_fails_closed_when_fpm_unavailable() {
    let root = tempfile::TempDir::new().unwrap();
    std::fs::write(root.path().join("index.php"), b"<?php echo 'ok';").unwrap();
    let mut route = native_route_proxy_test_route();
    route.path_exact = Some("/index.php".to_owned());
    route.redirect = None;
    route.php = Some(fluxheim_config::PhpConfig {
        enabled: true,
        root: Some(root.path().to_path_buf()),
        fpm: fluxheim_config::PhpFpmConfig {
            tcp: Some("127.0.0.1:9".to_owned()),
            ..Default::default()
        },
        ..Default::default()
    });

    let route = NativeHttp1RouteProxyRoute::from_config(&route, None).unwrap();
    let proxy = route_proxy_listener(NativeHttp1RouteProxy::new(vec![route], None)).await;

    let response = downstream_get(proxy, "/index.php").await;

    assert!(response.starts_with("HTTP/1.1 502 Bad Gateway\r\n"));
    assert!(response.ends_with("php-fpm failed\n"));
}

#[cfg(feature = "php-fpm")]
#[tokio::test]
async fn native_route_proxy_php_route_executes_fastcgi_responder() {
    let fpm = fastcgi_responder(
        b"Status: 201 Created\r\nContent-Type: text/plain\r\nX-Powered-By: php\r\n\r\nphp-ok",
    )
    .await;
    let root = tempfile::TempDir::new().unwrap();
    std::fs::write(root.path().join("index.php"), b"<?php echo 'ok';").unwrap();
    let mut route = native_route_proxy_test_route();
    route.path_exact = Some("/index.php".to_owned());
    route.redirect = None;
    route.php = Some(fluxheim_config::PhpConfig {
        enabled: true,
        root: Some(root.path().to_path_buf()),
        hide_response_headers: vec!["x-powered-by".to_owned()],
        fpm: fluxheim_config::PhpFpmConfig {
            tcp: Some(fpm.to_string()),
            ..Default::default()
        },
        ..Default::default()
    });

    let route = NativeHttp1RouteProxyRoute::from_config(&route, None).unwrap();
    let proxy = route_proxy_listener(NativeHttp1RouteProxy::new(vec![route], None)).await;

    let response = downstream_get(proxy, "/index.php").await;

    assert!(
        response.starts_with("HTTP/1.1 201 Created\r\n"),
        "unexpected response: {response:?}"
    );
    assert_eq!(
        response_header(&response, "content-type").as_deref(),
        Some("text/plain")
    );
    assert_eq!(response_header(&response, "x-powered-by"), None);
    assert!(response.ends_with("php-ok"));
}

#[cfg(feature = "php-fpm")]
#[tokio::test]
async fn native_route_proxy_vhost_php_takes_precedence_over_static_web_for_php_paths() {
    let fpm = fastcgi_responder(b"Status: 200 OK\r\nContent-Type: text/plain\r\n\r\nphp-ok").await;
    let root = tempfile::TempDir::new().unwrap();
    std::fs::write(
        root.path().join("wp-login.php"),
        b"<?php echo 'do not leak';",
    )
    .unwrap();
    std::fs::write(root.path().join("style.css"), b"body{}").unwrap();
    let mut vhost = native_route_proxy_test_vhost();
    vhost.web = fluxheim_config::WebConfig {
        root: Some(root.path().to_path_buf()),
        ..Default::default()
    };
    vhost.php = fluxheim_config::PhpConfig {
        enabled: true,
        root: Some(root.path().to_path_buf()),
        fpm: fluxheim_config::PhpFpmConfig {
            tcp: Some(fpm.to_string()),
            allow_private_tcp_upstreams: true,
            ..Default::default()
        },
        ..Default::default()
    };

    let route_proxy = NativeHttp1RouteProxy::from_vhost_config(
        &vhost,
        &fluxheim_config::HeaderPolicyConfig::default(),
        None,
        DownstreamHttp1Policy::default(),
        0,
    )
    .unwrap();
    let proxy = route_proxy_listener(route_proxy).await;

    let php_response = downstream_get(proxy, "/wp-login.php").await;
    let static_response = downstream_get(proxy, "/style.css").await;

    assert!(
        php_response.starts_with("HTTP/1.1 200 OK\r\n"),
        "unexpected php response: {php_response:?}"
    );
    assert!(php_response.ends_with("php-ok"));
    assert!(!php_response.contains("<?php"));
    assert!(
        static_response.starts_with("HTTP/1.1 200 OK\r\n"),
        "unexpected static response: {static_response:?}"
    );
    assert!(static_response.ends_with("body{}"));
}

#[cfg(feature = "php-fpm")]
#[tokio::test]
async fn native_route_proxy_vhost_php_denied_paths_do_not_fall_through_to_static_web() {
    let fpm = fastcgi_responder(b"Status: 200 OK\r\nContent-Type: text/plain\r\n\r\nphp-ok").await;
    let root = tempfile::TempDir::new().unwrap();
    std::fs::create_dir(root.path().join("admin")).unwrap();
    std::fs::write(
        root.path().join("admin").join("index.php"),
        b"<?php echo 'do not leak';",
    )
    .unwrap();
    std::fs::write(root.path().join("style.css"), b"body{}").unwrap();
    let mut vhost = native_route_proxy_test_vhost();
    vhost.web = fluxheim_config::WebConfig {
        root: Some(root.path().to_path_buf()),
        ..Default::default()
    };
    vhost.php = fluxheim_config::PhpConfig {
        enabled: true,
        root: Some(root.path().to_path_buf()),
        deny_path_prefixes: vec!["/admin".to_owned()],
        fpm: fluxheim_config::PhpFpmConfig {
            tcp: Some(fpm.to_string()),
            allow_private_tcp_upstreams: true,
            ..Default::default()
        },
        ..Default::default()
    };

    let route_proxy = NativeHttp1RouteProxy::from_vhost_config(
        &vhost,
        &fluxheim_config::HeaderPolicyConfig::default(),
        None,
        DownstreamHttp1Policy::default(),
        0,
    )
    .unwrap();
    let proxy = route_proxy_listener(route_proxy).await;

    let denied_response = downstream_get(proxy, "/admin/index.php").await;
    let static_response = downstream_get(proxy, "/style.css").await;

    assert!(
        denied_response.starts_with("HTTP/1.1 403 Forbidden\r\n"),
        "unexpected denied response: {denied_response:?}"
    );
    assert!(!denied_response.contains("<?php"));
    assert!(
        static_response.starts_with("HTTP/1.1 200 OK\r\n"),
        "unexpected static response: {static_response:?}"
    );
    assert!(static_response.ends_with("body{}"));
}
