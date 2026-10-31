use super::*;
use std::sync::Mutex;
use std::time::Duration;

#[derive(Debug, PartialEq)]
struct Sample {
    method: String,
    status: Option<u16>,
    outcome: &'static str,
}

#[derive(Default)]
struct Recorder(Mutex<Vec<Sample>>);

impl crate::NativePhpMetricsRecorder for Recorder {
    fn record_request(
        &self,
        vhost: &str,
        method: &str,
        status: Option<u16>,
        outcome: &'static str,
        _duration: Duration,
    ) {
        // Other parallel PHP tests share the process-global recorder.
        if vhost == "php-handler-metrics-test" {
            self.0.lock().unwrap().push(Sample {
                method: method.to_owned(),
                status,
                outcome,
            });
        }
    }
}

fn request(method: &str) -> NativeHttp1Request {
    NativeHttp1Request {
        method: method.to_owned(),
        peer_addr: None,
        local_addr: None,
        effective_client_addr: None,
        downstream_tls: false,
        tls_identity: None,
        geo_context: None,
        target: "/index.php".to_owned(),
        version: fluxheim_protocol::Http1Version::Http11,
        headers: vec![("host".to_owned(), "untrusted-host-canary".to_owned())],
        body: crate::NativeHttp1RequestBody::empty(),
        trailers: Vec::new(),
    }
}

#[tokio::test]
async fn php_handler_metrics_cover_direct_fallback_rejection_and_cancellation_once() {
    let recorder = Arc::new(Recorder::default());
    assert!(crate::install_native_php_metrics_recorder(recorder.clone()));
    let root = tempfile::TempDir::new().unwrap();
    // Match production's canonical root, including Windows verbatim prefixes.
    let canonical_root = std::fs::canonicalize(root.path()).unwrap();
    let mut php = super::tests::test_php_route(&canonical_root);
    php.vhost_name = "php-handler-metrics-test".to_owned();
    assert_eq!(php.handle(request("GET")).await.status(), 404);
    assert_eq!(php.handle(request("ATTACKER-METHOD")).await.status(), 405);
    assert_eq!(
        php.handle_resolved(
            request("POST"),
            "/index.php".into(),
            Ok(NativePhpScriptResolve::Forbidden)
        )
        .await
        .status(),
        403
    );

    // A real TCP endpoint accepts a connection but never completes FastCGI.
    std::fs::write(root.path().join("index.php"), b"<?php echo 'ok';").unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    php.config.fpm.tcp = Some(listener.local_addr().unwrap().to_string());
    php.config.fpm.allow_private_tcp_upstreams = true;
    let mut handler = Box::pin(php.handle(request("GET")));
    let accepted = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::select! {
            result = listener.accept() => result.unwrap(),
            response = &mut handler => panic!("handler returned before cancellation: {}", response.status()),
        }
    }).await.unwrap();
    drop(handler);
    drop(accepted);

    assert_eq!(
        *recorder.0.lock().unwrap(),
        vec![
            Sample {
                method: "GET".into(),
                status: Some(404),
                outcome: "response"
            },
            Sample {
                method: "OTHER".into(),
                status: Some(405),
                outcome: "response"
            },
            Sample {
                method: "POST".into(),
                status: Some(403),
                outcome: "response"
            },
            Sample {
                method: "GET".into(),
                status: None,
                outcome: "cancelled"
            },
        ]
    );
}
