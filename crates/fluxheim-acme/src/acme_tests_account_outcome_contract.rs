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
    Malformed,
    UnexpectedStatus,
    Redirect,
    Cancelled,
    TimedOut,
}

// This is a bounded HTTP/TLS outcome fixture, not an ACME authority: it checks
// the signed envelope's payload, but does not validate its signature or issue.
fn serve_outcome(
    listener: TcpListener,
    tls: Arc<rustls::ServerConfig>,
    outcome: Outcome,
    applied: tokio::sync::oneshot::Sender<()>,
) -> bool {
    listener.set_nonblocking(true).unwrap();
    let base = format!(
        "https://127.0.0.1:{}",
        listener.local_addr().unwrap().port()
    );
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut applied = Some(applied);
    let mut changed = false;
    let mut stalled_response = None;
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
        prepare_socket(&socket);
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
            if applied.is_none() {
                drop(stalled_response.take());
                assert!(payload.is_empty(), "reconciliation must be POST-as-GET");
                match outcome {
                    Outcome::Malformed => reply(&mut stream, "403 Forbidden", "{}"),
                    Outcome::UnexpectedStatus => {
                        reply(&mut stream, "200 OK", r#"{"status":"unknown"}"#)
                    }
                    _ if changed => reply(&mut stream, "200 OK", r#"{"status":"deactivated"}"#),
                    _ => reply(&mut stream, "200 OK", r#"{"status":"valid"}"#),
                }
                stream.conn.send_close_notify();
                let _ = stream.flush();
                return changed;
            }
            let payload: serde_json::Value = serde_json::from_slice(&payload).unwrap();
            assert_eq!(payload["status"], "deactivated");
            changed = !matches!(outcome, Outcome::Rejected | Outcome::Redirect);
            let _ = applied.take().unwrap().send(());
            match outcome {
                Outcome::Cancelled | Outcome::TimedOut => {
                    stalled_response = Some(stream);
                    continue;
                }
                Outcome::Malformed => reply(&mut stream, "200 OK", "{"),
                Outcome::UnexpectedStatus => reply(&mut stream, "200 OK", r#"{"status":"valid"}"#),
                Outcome::Redirect => reply(&mut stream, "302 Found", r#"{"status":"deactivated"}"#),
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
            if matches!(outcome, Outcome::Accepted) {
                return changed;
            }
            continue;
        }
        stream.conn.send_close_notify();
        let _ = stream.flush();
    }
}

fn prepare_socket(socket: &TcpStream) {
    // Windows inherits the listener's nonblocking mode; the TLS fixture uses
    // blocking I/O with bounded deadlines on every platform.
    socket.set_nonblocking(false).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(3)))
        .unwrap();
}

#[test]
fn outcome_fixture_resets_nonblocking_mode_before_reading() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (mut socket, _) = listener.accept().unwrap();
    socket.set_nonblocking(true).unwrap();
    prepare_socket(&socket);
    let peer = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        client
            .set_write_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        client.write_all(b"x").unwrap();
    });
    let mut byte = [0];
    let result = socket.read_exact(&mut byte);
    peer.join().unwrap();
    result.unwrap();
    assert_eq!(byte, *b"x");
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
    check_outcome_with(outcome, false);
}

fn check_outcome_with(outcome: Outcome, cli: bool) {
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
        ca_bundle_file: Some(trust.clone()),
        terms_of_service_agreed: false,
        terms_of_service_url: None,
        allow_unadvertised_terms_of_service: false,
        eab: None,
    }];
    let invoke = |operation: &str| {
        let config_file = root.0.join("fixture.toml");
        std::fs::write(&config_file, format!(
            "[tls]\nenabled=true\n[tls.acme]\nenabled=true\ncontact_email=\"test@example.test\"\nstorage={}\ndefault_issuer=\"fixture\"\n[[tls.acme.issuers]]\nname=\"fixture\"\ndirectory_url=\"{base}/directory\"\nca_bundle_file={}\nterms_of_service_agreed=true\nterms_of_service_url=\"{base}/terms\"\n",
            serde_json::to_string(&storage).unwrap(), serde_json::to_string(&trust).unwrap()
        )).unwrap();
        let test_exe = std::env::current_exe().unwrap();
        let debug = test_exe
            .ancestors()
            .find(|p| p.file_name().is_some_and(|n| n == "debug"))
            .unwrap();
        let exe = debug.join(format!("fluxheim-acme{}", std::env::consts::EXE_SUFFIX));
        let output = std::process::Command::new(exe)
            .arg("--config")
            .arg(config_file)
            .args([operation, "--issuer", "fixture", "--confirm"])
            .output()
            .unwrap();
        if output.status.success() {
            Ok(String::from_utf8(output.stdout).unwrap())
        } else {
            Err(String::from_utf8(output.stderr).unwrap())
        }
    };
    let (notify, applied) = tokio::sync::oneshot::channel();
    let worker =
        std::thread::spawn(move || serve_outcome(listener, Arc::new(tls), outcome, notify));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let result = runtime.block_on(async {
        assert!(
            crate::reconcile_instant_acme_account(&config, "fixture")
                .await
                .is_err()
        );
        assert!(active.is_file() && !pending.exists());
        let mut wrong = config.clone();
        wrong.tls.acme.issuers[0].directory_url.push_str("-other");
        assert!(
            crate::deactivate_instant_acme_account(&wrong, "fixture")
                .await
                .unwrap_err()
                .to_string()
                .contains("no account request sent")
        );
        assert!(active.is_file() && !pending.exists());
        if cli {
            return Some(invoke("account-deactivate").map(|_| ()));
        }
        let timeout = if matches!(outcome, Outcome::TimedOut) {
            Duration::from_secs(2)
        } else {
            Duration::from_secs(10)
        };
        let deactivate =
            crate::acme_instant_account::account_outcome(&config, "fixture", false, timeout);
        if matches!(outcome, Outcome::Cancelled) {
            match futures::future::select(applied, Box::pin(deactivate)).await {
                futures::future::Either::Left((received, in_flight)) => {
                    received.unwrap();
                    assert!(matches!(
                        crate::try_load_account_credentials(&storage, "fixture").unwrap(),
                        crate::AccountStoreAttempt::Contended
                    ));
                    drop(in_flight);
                }
                futures::future::Either::Right((result, _)) => {
                    panic!("expected in-flight cancellation, got {result:?}")
                }
            }
            None
        } else {
            Some(
                tokio::time::timeout(Duration::from_secs(12), deactivate)
                    .await
                    .unwrap()
                    .map(|_| ())
                    .map_err(|e| e.to_string()),
            )
        }
    });
    match outcome {
        Outcome::Accepted => {
            result.unwrap().unwrap();
            assert!(!active.exists() && !pending.exists());
        }
        _ => {
            if let Some(result) = result {
                assert!(
                    result
                        .unwrap_err()
                        .to_string()
                        .contains("remote=unconfirmed")
                );
            }
            assert!(!active.exists() && pending.is_file());
            assert!(load_account_credentials(&storage, "fixture").is_err());
            // A new invocation can only inspect the same pending identity, never retry the mutation.
            let result = if cli {
                invoke("account-reconcile").map(|line| {
                    match line
                        .strip_suffix("\r\n")
                        .or_else(|| line.strip_suffix('\n'))
                    {
                        Some(
                            "acme account reconcile: issuer=fixture remote=deactivated status=ok",
                        ) => crate::ReconciledAccountStatus::Deactivated,
                        Some("acme account reconcile: issuer=fixture remote=valid status=ok") => {
                            crate::ReconciledAccountStatus::Valid
                        }
                        _ => panic!("unexpected reconciliation output"),
                    }
                })
            } else {
                runtime
                    .block_on(crate::reconcile_instant_acme_account(&config, "fixture"))
                    .map_err(|e| e.to_string())
            };
            match outcome {
                Outcome::Rejected | Outcome::Redirect => {
                    assert_eq!(result.unwrap(), crate::ReconciledAccountStatus::Valid);
                    assert!(active.is_file() && !pending.exists());
                }
                Outcome::Malformed | Outcome::UnexpectedStatus => {
                    assert!(result.is_err());
                    assert!(!active.exists() && pending.is_file());
                }
                _ => {
                    assert_eq!(result.unwrap(), crate::ReconciledAccountStatus::Deactivated);
                    assert!(!active.exists() && !pending.exists());
                }
            }
        }
    }
    assert_eq!(
        worker.join().unwrap(),
        !matches!(outcome, Outcome::Rejected | Outcome::Redirect)
    );
}

#[test]
fn accepted_deactivation_removes_local_credentials() {
    check_outcome(Outcome::Accepted);
}

#[test]
fn rejected_deactivation_retains_credentials_until_verified_valid() {
    check_outcome(Outcome::Rejected);
}

#[test]
fn truncated_reply_requires_reconciliation_before_cleanup() {
    check_outcome(Outcome::AcceptedWithTruncatedReply);
}

#[test]
fn unexpected_responses_and_denied_or_unknown_reconciliation_remain_pending() {
    for outcome in [
        Outcome::Malformed,
        Outcome::UnexpectedStatus,
        Outcome::Redirect,
        Outcome::Cancelled,
        Outcome::TimedOut,
    ] {
        check_outcome(outcome);
    }
}

#[test]
#[ignore = "requires a native debug fluxheim-acme companion built with profile-web-server,acme-client"]
fn native_companion_reconciles_account_outcomes_across_processes() {
    for outcome in [
        Outcome::Accepted,
        Outcome::Rejected,
        Outcome::AcceptedWithTruncatedReply,
        Outcome::Malformed,
    ] {
        check_outcome_with(outcome, true);
    }
}
