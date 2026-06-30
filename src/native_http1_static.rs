#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "native HTTP/1 static adapter is staged before the production runtime cutover"
    )
)]

use fluxheim_protocol::{Http1RequestTarget, http1_request_target};
use fluxheim_server::{NativeHttp1Request, NativeHttp1Response};

use crate::web::{
    ResolveResult, StaticFile, StaticFileServer, StaticRequestConditions, StaticResponseBody,
    plan_static_response, read_static_response_body, render_directory_listing,
};

pub(crate) fn native_static_response(
    server: &StaticFileServer,
    request: &NativeHttp1Request,
) -> NativeHttp1Response {
    if !request.method.eq_ignore_ascii_case("GET") && !request.method.eq_ignore_ascii_case("HEAD") {
        return NativeHttp1Response::new(405, "Method Not Allowed", b"method not allowed\n")
            .with_header("Allow", "GET, HEAD");
    }

    let Some(path) = request_path(request) else {
        return NativeHttp1Response::new(400, "Bad Request", b"bad request\n").close_connection();
    };

    match server.resolve(path) {
        Ok(ResolveResult::Found(file)) => native_static_file_response(server, &file, request),
        Ok(ResolveResult::DirectoryListing(listing)) => {
            let body = render_directory_listing(&listing);
            let content_length = body.len() as u64;
            let response_body = if request.method.eq_ignore_ascii_case("HEAD") {
                Vec::new()
            } else {
                body.into_bytes()
            };
            NativeHttp1Response::new(200, "OK", response_body)
                .with_content_length(content_length)
                .with_header("content-type", "text/html; charset=utf-8")
                .with_header("cache-control", "private, no-store")
        }
        Ok(ResolveResult::Forbidden) => {
            NativeHttp1Response::new(403, "Forbidden", b"forbidden\n").close_connection()
        }
        Ok(ResolveResult::NotFound) => NativeHttp1Response::new(404, "Not Found", b"not found\n"),
        Err(error) => {
            log::error!(
                target: "fluxheim::native_http1",
                "static file resolution failed: {error}"
            );
            NativeHttp1Response::new(500, "Internal Server Error", b"internal server error\n")
                .close_connection()
        }
    }
}

fn native_static_file_response(
    server: &StaticFileServer,
    file: &StaticFile,
    request: &NativeHttp1Request,
) -> NativeHttp1Response {
    let plan = plan_static_response(file, &request.method, request_conditions(request));
    let body = match plan.body {
        StaticResponseBody::None => Vec::new(),
        body => match read_static_response_body(file, body) {
            Ok(body) => body.to_vec(),
            Err(error) => {
                log::error!(
                    target: "fluxheim::native_http1",
                    "static file body read failed for {}: {error}",
                    file.path.display()
                );
                return NativeHttp1Response::new(
                    500,
                    "Internal Server Error",
                    b"internal server error\n",
                )
                .close_connection();
            }
        },
    };
    let mut response = NativeHttp1Response::new(plan.status, status_reason(plan.status), body)
        .with_header("content-type", file.mime.as_str())
        .with_header("cache-control", server.cache_control())
        .with_header("etag", plan.etag.as_str())
        .with_header("accept-ranges", "bytes");
    if let Some(content_length) = plan.content_length {
        response = response.with_content_length(content_length);
    }
    if let Some(expires) = server.expires() {
        response = response.with_header("expires", expires);
    }
    if let Some(modified) = file.modified {
        response = response.with_header("last-modified", httpdate::fmt_http_date(modified));
    }
    if let Some(content_range) = plan.content_range.as_deref() {
        response = response.with_header("content-range", content_range);
    }
    response
}

fn request_path(request: &NativeHttp1Request) -> Option<&str> {
    match http1_request_target(&request.method, &request.target).ok()? {
        Http1RequestTarget::Origin { path, .. } => Some(path),
        Http1RequestTarget::AbsoluteUri { path, .. } => path,
        Http1RequestTarget::Authority { .. } | Http1RequestTarget::Asterisk => None,
    }
}

fn request_conditions(request: &NativeHttp1Request) -> StaticRequestConditions<'_> {
    StaticRequestConditions {
        if_match: header(request, "if-match"),
        if_unmodified_since: header(request, "if-unmodified-since"),
        if_none_match: header(request, "if-none-match"),
        if_modified_since: header(request, "if-modified-since"),
        cache_control: header(request, "cache-control"),
        pragma: header(request, "pragma"),
        range: header(request, "range"),
        if_range: header(request, "if-range"),
    }
}

fn header<'a>(request: &'a NativeHttp1Request, name: &str) -> Option<&'a str> {
    request
        .headers
        .iter()
        .find(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn status_reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        206 => "Partial Content",
        304 => "Not Modified",
        412 => "Precondition Failed",
        416 => "Range Not Satisfiable",
        _ => {
            debug_assert!(false, "unhandled static response status {status}");
            "Internal Server Error"
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    use fluxheim_server::{
        DownstreamHttp1Policy, NativeHttp1Request, serve_native_http1_connection,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    use crate::config::{DirectoryListingConfig, WebConfig};
    use crate::web::StaticFileServer;
    use fluxheim_common::test_support::{safe_relative_path, unique_temp_path};

    use super::native_static_response;

    async fn spawn_static_server(server: StaticFileServer) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = Arc::new(server);
        let handler = Arc::new(move |request: NativeHttp1Request| {
            let server = server.clone();
            async move { native_static_response(&server, &request) }
        });
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            serve_native_http1_connection(stream, None, DownstreamHttp1Policy::default(), handler)
                .await
                .unwrap();
        });
        addr
    }

    async fn request(addr: std::net::SocketAddr, request: &[u8]) -> String {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(request).await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        String::from_utf8(response).unwrap()
    }

    #[tokio::test]
    async fn native_static_serves_file_over_http1_socket() {
        let root = TestDir::new("native-static-file");
        fs::write(root.child("index.txt"), "hello native static").unwrap();
        let addr = spawn_static_server(server(root.path())).await;

        let response = request(
            addr,
            b"GET /index.txt HTTP/1.1\r\nHost: local.test\r\nConnection: close\r\n\r\n",
        )
        .await;

        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.contains("content-type: text/plain\r\n"));
        assert!(response.contains("cache-control: public, max-age=60\r\n"));
        assert!(response.ends_with("hello native static"));
    }

    #[tokio::test]
    async fn native_static_preserves_head_content_length() {
        let root = TestDir::new("native-static-head");
        fs::write(root.child("index.txt"), "hello native static").unwrap();
        let addr = spawn_static_server(server(root.path())).await;

        let response = request(
            addr,
            b"HEAD /index.txt HTTP/1.1\r\nHost: local.test\r\nConnection: close\r\n\r\n",
        )
        .await;

        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.contains("Content-Length: 19\r\n"));
        assert!(response.ends_with("\r\n\r\n"));
    }

    #[tokio::test]
    async fn native_static_serves_directory_listing_over_http1_socket() {
        let root = TestDir::new("native-static-listing");
        fs::write(root.child("alpha.txt"), "alpha").unwrap();
        let mut config = web_config(root.path());
        config.directory_listing = DirectoryListingConfig {
            enabled: true,
            exact_size: true,
            local_time: false,
        };
        let addr =
            spawn_static_server(StaticFileServer::from_config(&config).unwrap().unwrap()).await;

        let response = request(
            addr,
            b"GET / HTTP/1.1\r\nHost: local.test\r\nConnection: close\r\n\r\n",
        )
        .await;

        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.contains("content-type: text/html; charset=utf-8\r\n"));
        assert!(response.contains("alpha.txt"));
    }

    struct TestDir {
        path: PathBuf,
    }

    impl TestDir {
        fn new(label: &str) -> Self {
            let path = unique_temp_path(label);
            fs::create_dir_all(&path).unwrap();
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }

        fn child(&self, name: &str) -> PathBuf {
            safe_relative_path(&self.path, name)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn server(root: &Path) -> StaticFileServer {
        StaticFileServer::from_config(&web_config(root))
            .unwrap()
            .unwrap()
    }

    fn web_config(root: &Path) -> WebConfig {
        WebConfig {
            root: Some(root.to_owned()),
            index_files: vec!["index.html".to_owned()],
            cache_control: "public, max-age=60".to_owned(),
            deny_dotfiles: true,
            ..WebConfig::default()
        }
    }
}
