use std::io::{Read, Write};
use std::sync::{Arc, mpsc};

use fluxheim_common::test_support::{safe_child_path, unique_temp_path};

use super::backend::FluxBackendDiscovery;
use super::discovery_dns::DnsUpstreamDiscovery;
use super::discovery_http::{
    fetch_proxy_upstreams_http, parse_proxy_upstreams_http_body,
    validate_http_discovery_bearer_token, validate_http_discovery_content_type,
};

#[test]
fn parses_http_discovery_list_payload() {
    let upstreams =
        parse_proxy_upstreams_http_body(br#"["8.8.8.8:3001","backend.example.test:443"]"#, false)
            .unwrap();

    assert_eq!(upstreams, ["8.8.8.8:3001", "backend.example.test:443"]);
}

#[test]
fn parses_http_discovery_object_payload() {
    let upstreams =
        parse_proxy_upstreams_http_body(br#"{"upstreams":["8.8.8.8:3001","1.1.1.1:3002"]}"#, false)
            .unwrap();

    assert_eq!(upstreams, ["8.8.8.8:3001", "1.1.1.1:3002"]);
}

#[test]
fn rejects_http_discovery_duplicate_and_short_payloads() {
    assert!(
        parse_proxy_upstreams_http_body(br#"["8.8.8.8:3001","8.8.8.8:3001"]"#, false)
            .unwrap_err()
            .to_string()
            .contains("repeats")
    );
    assert!(
        parse_proxy_upstreams_http_body(br#"["8.8.8.8:3001"]"#, false)
            .unwrap_err()
            .to_string()
            .contains("at least two")
    );
}

#[test]
fn rejects_http_discovery_invalid_authority() {
    assert!(
        parse_proxy_upstreams_http_body(br#"["http://127.0.0.1:3001","1.1.1.1:3002"]"#, false)
            .unwrap_err()
            .to_string()
            .contains("authority")
    );
}

#[test]
fn rejects_http_discovery_private_backends_without_opt_in() {
    assert!(
        parse_proxy_upstreams_http_body(br#"["169.254.169.254:80","8.8.8.8:3002"]"#, false)
            .unwrap_err()
            .to_string()
            .contains("private")
    );
    assert!(
        parse_proxy_upstreams_http_body(br#"["127.0.0.1:3001","8.8.8.8:3002"]"#, false)
            .unwrap_err()
            .to_string()
            .contains("private")
    );
    assert!(
        parse_proxy_upstreams_http_body(br#"["[::1]:3001","8.8.8.8:3002"]"#, false)
            .unwrap_err()
            .to_string()
            .contains("private")
    );

    let upstreams =
        parse_proxy_upstreams_http_body(br#"["169.254.169.254:80","127.0.0.1:3001"]"#, true)
            .unwrap();
    assert_eq!(upstreams, ["169.254.169.254:80", "127.0.0.1:3001"]);
}

#[test]
fn rejects_http_discovery_ipv4_encoded_ipv6_literals_without_opt_in() {
    for upstream in [
        "[::ffff:169.254.169.254]:80",
        "[::ffff:127.0.0.1]:3001",
        "[::ffff:10.0.0.1]:3001",
        "[::169.254.169.254]:80",
        "[2002:7f00:1::1]:3001",
        "[2002:a00:1::1]:3001",
        "[2001:0000::ffff:80ff:fffe]:3001",
    ] {
        let body = format!(r#"["{upstream}","8.8.8.8:3002"]"#);
        assert!(
            parse_proxy_upstreams_http_body(body.as_bytes(), false)
                .unwrap_err()
                .to_string()
                .contains("private"),
            "{upstream}"
        );
    }

    let upstreams = parse_proxy_upstreams_http_body(
        br#"["[::ffff:169.254.169.254]:80","[::ffff:127.0.0.1]:3001"]"#,
        true,
    )
    .unwrap();
    assert_eq!(
        upstreams,
        ["[::ffff:169.254.169.254]:80", "[::ffff:127.0.0.1]:3001"]
    );
}

#[tokio::test]
async fn rejects_dns_discovery_private_backends_without_opt_in() {
    let discovery = DnsUpstreamDiscovery {
        upstreams: Arc::from(["127.0.0.1:3001".to_owned()]),
        allow_private_backends: false,
    };

    let error = discovery
        .discover_flux_backends()
        .await
        .expect_err("restricted DNS backend");
    assert!(error.to_string().contains("private"));

    let discovery = DnsUpstreamDiscovery {
        upstreams: Arc::from(["127.0.0.1:3001".to_owned()]),
        allow_private_backends: true,
    };
    assert!(discovery.discover_flux_backends().await.is_ok());
}

#[test]
fn rejects_http_discovery_payload_over_upstream_cap() {
    let upstreams = (0..=fluxheim_config::config_proxy::MAX_PROXY_UPSTREAMS)
        .map(|index| format!("\"8.8.8.8:{}\"", 3000 + index))
        .collect::<Vec<_>>()
        .join(",");
    let body = format!("[{upstreams}]");

    assert!(
        parse_proxy_upstreams_http_body(body.as_bytes(), false)
            .unwrap_err()
            .to_string()
            .contains("too many")
    );
}

#[test]
fn validates_http_discovery_json_content_types() {
    validate_http_discovery_content_type(None).unwrap();
    validate_http_discovery_content_type(Some("application/json")).unwrap();
    validate_http_discovery_content_type(Some("application/json; charset=utf-8")).unwrap();
    validate_http_discovery_content_type(Some("application/vnd.fluxheim.upstreams+json")).unwrap();

    assert!(
        validate_http_discovery_content_type(Some("text/plain"))
            .unwrap_err()
            .to_string()
            .contains("content-type")
    );
}

#[test]
fn rejects_empty_or_control_character_http_discovery_bearer_token() {
    validate_http_discovery_bearer_token("secret-token\n").unwrap();
    assert!(
        validate_http_discovery_bearer_token(" \n\t ")
            .unwrap_err()
            .to_string()
            .contains("empty")
    );
    assert!(
        validate_http_discovery_bearer_token("secret\r\nother")
            .unwrap_err()
            .to_string()
            .contains("whitespace")
    );
    assert!(
        validate_http_discovery_bearer_token("secret other")
            .unwrap_err()
            .to_string()
            .contains("whitespace")
    );
}

#[test]
fn fetches_http_discovery_with_json_accept_and_bearer_token() {
    let root = unique_temp_path("lb-http-discovery-token");
    std::fs::create_dir_all(&root).unwrap();
    let token_path = safe_child_path(&root, "token.txt");
    #[cfg(windows)]
    {
        let mut token = fluxheim_config::fs_trust::create_confidential_file(&token_path).unwrap();
        token.write_all(b"secret-token\n").unwrap();
    }
    #[cfg(not(windows))]
    std::fs::write(&token_path, "secret-token\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let (sender, receiver) = mpsc::channel();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = Vec::new();
        let mut buffer = [0_u8; 512];
        loop {
            let read = stream.read(&mut buffer).unwrap();
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        let request = String::from_utf8(request).unwrap();
        sender.send(request).unwrap();
        let body = br#"["127.0.0.1:3001","127.0.0.1:3002"]"#;
        write!(
            stream,
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            body.len()
        )
        .unwrap();
        stream.write_all(body).unwrap();
    });

    let upstreams = fetch_proxy_upstreams_http(
        &format!("http://{address}/v1/upstreams"),
        Some(token_path),
        true,
    )
    .unwrap();
    handle.join().unwrap();
    let request = receiver.recv().unwrap();

    assert_eq!(upstreams, ["127.0.0.1:3001", "127.0.0.1:3002"]);
    let lower_request = request.to_ascii_lowercase();
    assert!(request.contains("GET /v1/upstreams HTTP/1.1"));
    assert!(lower_request.contains("accept: application/json"));
    assert!(lower_request.contains("cache-control: no-store"));
    assert!(lower_request.contains("authorization: bearer secret-token"));
}
