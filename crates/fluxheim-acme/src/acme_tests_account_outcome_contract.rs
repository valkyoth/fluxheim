use super::*;
use std::io::{BufRead as _, Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Instant;

#[derive(Clone, Copy)]
enum Outcome {
    Accepted,
    Rejected,
    AcceptedWithTruncatedReply,
}

// This is a bounded HTTP/TLS outcome fixture, not an ACME authority: it checks
// the signed envelope's payload, but does not validate its signature or issue.
fn serve_outcome(listener: TcpListener, tls: Arc<rustls::ServerConfig>, outcome: Outcome) -> bool {
    listener.set_nonblocking(true).unwrap();
    let base = format!(
        "https://127.0.0.1:{}",
        listener.local_addr().unwrap().port()
    );
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        assert!(
            Instant::now() < deadline,
            "fixture request deadline elapsed"
        );
        let socket = match listener.accept() {
            Ok((socket, _)) => socket,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            Err(error) => panic!("fixture accept: {error}"),
        };
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut stream =
            rustls::StreamOwned::new(rustls::ServerConnection::new(tls.clone()).unwrap(), socket);
        let (request, body) = read_request(&mut stream);
        if request.starts_with("GET /directory ") {
            let directory = serde_json::json!({
                "newNonce": format!("{base}/nonce"),
                "newAccount": format!("{base}/new-account"),
                "newOrder": format!("{base}/new-order"),
            });
            reply(&mut stream, "200 OK", &directory.to_string());
        } else if request.starts_with("HEAD /nonce ") {
            reply(&mut stream, "200 OK", "");
        } else {
            assert!(
                request.starts_with("POST /account/1 "),
                "unexpected request: {request}"
            );
            let envelope: serde_json::Value = serde_json::from_slice(&body).unwrap();
            let payload = base64_ng::URL_SAFE_NO_PAD
                .decode_vec(envelope["payload"].as_str().unwrap().as_bytes())
                .unwrap();
            let payload: serde_json::Value = serde_json::from_slice(&payload).unwrap();
            assert_eq!(payload["status"], "deactivated");
            match outcome {
                Outcome::Accepted => reply(&mut stream, "200 OK", r#"{"status":"deactivated"}"#),
                Outcome::Rejected => reply(
                    &mut stream,
                    "503 Service Unavailable",
                    r#"{"type":"urn:ietf:params:acme:error:serverInternal","detail":"not applied","status":503}"#,
                ),
                Outcome::AcceptedWithTruncatedReply => {
                    // The simulated remote mutation has happened, but the
                    // client cannot read the complete declared response.
                    stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 128\r\nConnection: close\r\n\r\n{",
                        )
                        .unwrap();
                    stream.flush().unwrap();
                }
            }
            stream.conn.send_close_notify();
            let _ = stream.flush();
            return !matches!(outcome, Outcome::Rejected);
        }
        stream.conn.send_close_notify();
        let _ = stream.flush();
    }
}

fn read_request(
    stream: &mut rustls::StreamOwned<rustls::ServerConnection, TcpStream>,
) -> (String, Vec<u8>) {
    let mut reader = std::io::BufReader::new(stream.take(64 * 1024));
    let mut request = String::new();
    reader.read_line(&mut request).unwrap();
    let mut length = 0;
    loop {
        let mut header = String::new();
        assert_ne!(
            reader.read_line(&mut header).unwrap(),
            0,
            "incomplete request"
        );
        if header == "\r\n" {
            break;
        }
        if let Some((name, value)) = header.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            length = value.trim().parse::<usize>().unwrap();
        }
    }
    assert!(length <= 16 * 1024);
    let mut body = vec![0; length];
    reader.read_exact(&mut body).unwrap();
    (request, body)
}

fn reply(stream: &mut impl std::io::Write, status: &str, body: &str) {
    write!(stream, "HTTP/1.1 {status}\r\nContent-Length: {}\r\nContent-Type: application/json\r\nReplay-Nonce: fixture-nonce\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
    stream.flush().unwrap();
}

struct PrivateRoot(PathBuf);

impl Drop for PrivateRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn check_outcome(outcome: Outcome) {
    let root = PrivateRoot(fluxheim_common::test_support::unique_temp_path(
        "acme-account-outcome",
    ));
    std::fs::create_dir_all(&root.0).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&root.0, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let certificate = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_owned()]).unwrap();
    let trust = root.0.join("fixture-ca.pem");
    std::fs::write(&trust, certificate.cert.pem()).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![certificate.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(certificate.signing_key.serialize_der())
                .into(),
        )
        .unwrap();
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("https://{}", listener.local_addr().unwrap());
    let storage = root.0.join("state");
    let mut credentials: serde_json::Value =
        serde_json::from_str(test_account_credentials_json()).unwrap();
    credentials["id"] = format!("{base}/account/1").into();
    credentials["directory"] = format!("{base}/directory").into();
    let credentials = serde_json::from_value(credentials).unwrap();
    let active = store_account_credentials(&storage, "fixture", &credentials)
        .unwrap()
        .path;
    let pending = active
        .parent()
        .unwrap()
        .join(".credentials.deactivation.pending");
    let mut config = Config::default();
    config.tls.acme.storage = Some(storage.clone());
    config.tls.acme.issuers = vec![AcmeIssuerConfig {
        name: "fixture".to_owned(),
        directory_url: format!("{base}/directory"),
        ca_bundle_file: Some(trust),
        terms_of_service_agreed: false,
        terms_of_service_url: None,
        allow_unadvertised_terms_of_service: false,
        eab: None,
    }];
    let worker = std::thread::spawn(move || serve_outcome(listener, Arc::new(tls), outcome));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let result = runtime.block_on(async {
        tokio::time::timeout(
            Duration::from_secs(10),
            crate::deactivate_instant_acme_account(&config, "fixture"),
        )
        .await
    });
    let remotely_deactivated = worker.join().unwrap();
    let result = result.expect("bounded deactivation fixture timed out");
    match outcome {
        Outcome::Accepted => {
            assert!(remotely_deactivated);
            result.unwrap();
            assert!(!active.exists() && !pending.exists());
        }
        Outcome::Rejected => {
            assert!(!remotely_deactivated);
            // documented contract: an HTTP error currently looks like confirmed success.
            result.unwrap();
            assert!(!active.exists() && !pending.exists());
        }
        Outcome::AcceptedWithTruncatedReply => {
            assert!(remotely_deactivated);
            assert!(result.is_err());
            assert!(active.is_file() && !pending.exists());
            assert!(
                load_account_credentials(&storage, "fixture")
                    .unwrap()
                    .is_some()
            );
        }
    }
}

#[test]
fn accepted_deactivation_removes_local_credentials() {
    check_outcome(Outcome::Accepted);
}

#[test]
fn rejected_deactivation_currently_reports_success_and_removes_credentials() {
    check_outcome(Outcome::Rejected);
}

#[test]
fn accepted_deactivation_with_truncated_reply_currently_restores_credentials() {
    check_outcome(Outcome::AcceptedWithTruncatedReply);
}
