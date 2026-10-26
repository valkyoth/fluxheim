use super::*;
use std::io::Write;
use std::net::TcpListener;
use std::sync::Arc;

fn private_file(path: &Path, bytes: &[u8]) {
    #[cfg(windows)]
    let mut file = fluxheim_config::fs_trust::create_confidential_file(path).unwrap();
    #[cfg(unix)]
    let mut file = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap()
    };
    file.write_all(bytes).unwrap();
}

#[test]
fn tls_verification_authentication_and_redirect_policy_are_enforced() {
    let root = fluxheim_common::test_support::unique_temp_path("otlp-tls");
    #[cfg(windows)]
    fluxheim_config::fs_trust::create_private_directory_all(&root).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .unwrap();
    }
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let ca = root.join("ca.pem");
    let token = root.join("token");
    private_file(&ca, cert.cert.pem().as_bytes());
    private_file(&token, b"collector-secret-canary\n");
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![cert.cert.der().clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
    )
    .unwrap();
    for (trust, host, status, expected) in [
        (true, "localhost", 200, ExportOutcome::Success),
        (true, "localhost", 401, ExportOutcome::Rejected),
        (true, "localhost", 403, ExportOutcome::Rejected),
        (true, "localhost", 302, ExportOutcome::Rejected),
        (false, "localhost", 200, ExportOutcome::Rejected),
        (true, "127.0.0.1", 200, ExportOutcome::Rejected),
    ] {
        // Windows resolves localhost to ::1 first; bind that address so this
        // certificate test does not spend its deadline on IPv4 fallback.
        let listener = TcpListener::bind(if host == "localhost" {
            "[::1]:0"
        } else {
            "127.0.0.1:0"
        })
        .unwrap();
        let endpoint = format!(
            "https://{host}:{}/v1/traces",
            listener.local_addr().unwrap().port()
        );
        let config = Arc::new(config.clone());
        let (release, complete) = std::sync::mpsc::sync_channel(1);
        let server = std::thread::spawn(move || {
            listener.set_nonblocking(true).unwrap();
            let end = std::time::Instant::now() + Duration::from_secs(5);
            let socket = loop {
                if let Ok((socket, _)) = listener.accept() {
                    break socket;
                }
                assert!(std::time::Instant::now() < end);
                std::thread::sleep(Duration::from_millis(5));
            };
            socket.set_nonblocking(false).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let session = rustls::ServerConnection::new(config).unwrap();
            let mut stream = rustls::StreamOwned::new(session, socket);
            let mut received = Vec::new();
            let mut byte = [0];
            while !received.ends_with(b"\r\n\r\n") {
                if stream.read_exact(&mut byte).is_err() {
                    return false;
                }
                received.push(byte[0]);
                assert!(received.len() < 8192);
            }
            let headers = String::from_utf8(received).unwrap();
            let authorized = headers
                .to_ascii_lowercase()
                .contains("authorization: bearer collector-secret-canary\r\n");
            let mut body = [0; 2];
            stream.read_exact(&mut body).unwrap();
            assert_eq!(&body, b"{}");
            // Following this location would fail or leak credentials; redirects must stop here.
            write!(stream, "HTTP/1.1 {status} Test\r\nLocation: http://127.0.0.1:1/secret-canary\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}").unwrap();
            stream.flush().unwrap();
            // Keep the accepted socket alive until the client consumed the response;
            // dropping it immediately can reset the connection on Windows.
            complete.recv_timeout(Duration::from_secs(3)).unwrap();
            stream.conn.send_close_notify();
            let _ = stream.flush();
            authorized
        });
        let delivery = Delivery::new(
            &endpoint,
            trust.then_some(ca.as_path()),
            Some(&token),
            ExportSignal::Traces,
        )
        .unwrap();
        let outcome = delivery.post("{}", Duration::from_secs(2));
        let _ = release.try_send(());
        let authorized = server.join().unwrap();
        assert_eq!(outcome, expected);
        assert!(!format!("{outcome:?}").contains("secret-canary"));
        assert_eq!(authorized, trust && host == "localhost");
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn token_reader_is_bounded_and_rejects_header_injection() {
    for content in [
        vec![b'x'; 4097],
        b"secret\r\nInjected: header".to_vec(),
        Vec::new(),
    ] {
        let path = fluxheim_common::test_support::unique_temp_path("otlp-token");
        private_file(&path, &content);
        assert!(load_token(&path).is_err());
        std::fs::remove_file(path).unwrap();
    }
}
