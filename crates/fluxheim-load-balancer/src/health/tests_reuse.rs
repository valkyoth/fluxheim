use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use super::FluxHealthCheck;
use super::tests_reuse_fixture::{Fixture, OK};

#[tokio::test]
async fn reuse_isolates_backends_even_with_the_same_readiness_port() {
    let fixture = Fixture::start(false).await;
    let mut check = fixture.check(false, true);
    check.port_override = Some(fixture.backend.addr.port());
    let mut second = fixture.backend.clone();
    second
        .addr
        .set_port(if second.addr.port() == 1 { 2 } else { 1 });
    for _ in 0..3 {
        let (a, b) = tokio::join!(check.check(&fixture.backend), check.check(&second));
        a.unwrap();
        b.unwrap();
    }
    assert_eq!(fixture.count(), 2);
    check.update_backends(&BTreeSet::from([second.clone()]));
    assert!(check.check(&fixture.backend).await.is_err());
    check.check(&second).await.unwrap();
    assert_eq!(fixture.count(), 2);
}

#[tokio::test]
async fn reuse_head_has_no_response_body_and_semantic_failures_discard() {
    let fixture = Fixture::start(false).await;
    fixture.respond("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n");
    let mut check = fixture.check(false, true);
    check.req.method = http::Method::HEAD;
    for _ in 0..3 {
        check.check(&fixture.backend).await.unwrap();
    }
    assert_eq!(fixture.count(), 1);
    drop(check);
    fixture.respond(OK);
    let mut check = fixture.check(false, true);
    check.expected_body_contains = vec!["missing".to_owned()].into();
    assert!(check.check(&fixture.backend).await.is_err());
    assert!(check.check(&fixture.backend).await.is_err());
    assert_eq!(fixture.count(), 3);
}

#[test]
fn reuse_rejects_unsupported_protocols_even_without_configuration_validation() {
    use fluxheim_config::{LoadBalanceHealthCheckProtocol as Protocol, ProxyConfig};
    for protocol in [
        Protocol::Tcp,
        Protocol::Exec,
        Protocol::Redis,
        Protocol::Mysql,
        Protocol::Postgres,
    ] {
        let mut config = ProxyConfig::default();
        config.load_balance.health_check.protocol = protocol;
        config.load_balance.health_check.reuse_connection = true;
        assert!(
            super::configured_health_check(
                &config,
                Arc::new(super::HealthDerivedWeights::default())
            )
            .is_err()
        );
    }
}

#[tokio::test]
async fn reuse_connection_counts_http_and_grpc() {
    for grpc in [false, true] {
        for reuse in [false, true] {
            let fixture = Fixture::start(grpc).await;
            let check = fixture.check(grpc, reuse);
            for _ in 0..4 {
                check.check(&fixture.backend).await.unwrap();
            }
            assert_eq!(
                fixture.count(),
                if reuse { 1 } else { 4 },
                "grpc={grpc} reuse={reuse}"
            );
        }
    }
}

#[tokio::test]
async fn reuse_consumes_http_chunks_and_trailers() {
    let fixture = Fixture::start(false).await;
    fixture.respond("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\nx-health: ready\r\n\r\n");
    let check = fixture.check(false, true);
    for _ in 0..3 {
        check.check(&fixture.backend).await.unwrap();
    }
    assert_eq!(fixture.count(), 1);
}

#[tokio::test]
async fn reuse_bounds_headers_trailers_and_chunked_body() {
    let responses = [
        format!(
            "HTTP/1.1 200 OK\r\nx-large: {}\r\nContent-Length: 0\r\n\r\n",
            "a".repeat(8192)
        ),
        format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nx-large: {}\r\n\r\n",
            "a".repeat(8192)
        ),
        format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n10001\r\n{}\r\n0\r\n\r\n",
            "a".repeat(65537)
        ),
    ];
    for response in responses {
        let fixture = Fixture::start(false).await;
        fixture.respond(&response);
        let check = fixture.check(false, true);
        assert!(check.check(&fixture.backend).await.is_err());
        assert_eq!(fixture.count(), 1);
        fixture.respond(OK);
        check.check(&fixture.backend).await.unwrap();
        assert_eq!(fixture.count(), 2);
    }
}

#[tokio::test]
async fn reuse_rejects_invalid_http_and_recovers_without_retry() {
    for response in [
        "HTTP/1.1 200 OK\r\nContent-Length: 65537\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nok",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nZZ\r\n",
        "HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nx-health: incomplete",
    ] {
        let fixture = Fixture::start(false).await;
        fixture.respond(response);
        let check = fixture.check(false, true);
        assert!(check.check(&fixture.backend).await.is_err(), "{response:?}");
        assert_eq!(fixture.count(), 1);
        fixture.respond(OK);
        check.check(&fixture.backend).await.unwrap();
        check.check(&fixture.backend).await.unwrap();
        assert_eq!(fixture.count(), 2);
    }
}

#[tokio::test]
async fn reuse_honors_http_connection_close() {
    let fixture = Fixture::start(false).await;
    fixture.respond("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
    let check = fixture.check(false, true);
    for _ in 0..3 {
        check.check(&fixture.backend).await.unwrap();
    }
    assert_eq!(fixture.count(), 3);
}

#[tokio::test]
async fn reuse_grpc_status_goaway_and_timeout_discard_connection() {
    for status in ["7", "goaway", "hang"] {
        let fixture = Fixture::start(true).await;
        fixture.respond(status);
        let check = fixture.check(true, true);
        assert!(check.check(&fixture.backend).await.is_err());
        assert_eq!(fixture.count(), 1);
        fixture.respond("0");
        check.check(&fixture.backend).await.unwrap();
        check.check(&fixture.backend).await.unwrap();
        assert_eq!(fixture.count(), 2);
    }
}

#[tokio::test]
async fn reuse_bounds_concurrency_and_discards_cancelled_exchange() {
    for grpc in [false, true] {
        let fixture = Fixture::start(grpc).await;
        fixture.respond(if grpc { "hang" } else { "" });
        let check: Arc<super::http::FluxHttpHealthCheck> = Arc::from(fixture.check(grpc, true));
        let clone = Arc::clone(&check);
        let backend = fixture.backend.clone();
        let task = tokio::spawn(async move { clone.check(&backend).await });
        fixture.wait_requests(1).await;
        assert!(check.check(&fixture.backend).await.is_err());
        assert_eq!(fixture.count(), 1);
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        fixture.respond(if grpc { "0" } else { OK });
        check.check(&fixture.backend).await.unwrap();
        assert_eq!(fixture.count(), 2);
    }
}

#[tokio::test]
async fn reuse_membership_change_cancels_active_and_rejects_stale_snapshot() {
    for grpc in [false, true] {
        let fixture = Fixture::start(grpc).await;
        fixture.respond(if grpc { "hang" } else { "" });
        let check: Arc<super::http::FluxHttpHealthCheck> = Arc::from(fixture.check(grpc, true));
        check.update_backends(&BTreeSet::from([fixture.backend.clone()]));
        let clone = Arc::clone(&check);
        let backend = fixture.backend.clone();
        let task = tokio::spawn(async move { clone.check(&backend).await });
        fixture.wait_requests(1).await;
        check.update_backends(&BTreeSet::new());
        assert!(
            tokio::time::timeout(Duration::from_secs(1), task)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
        assert!(check.check(&fixture.backend).await.is_err());
        assert_eq!(fixture.count(), 1);
        fixture.respond(if grpc { "0" } else { OK });
        check.update_backends(&BTreeSet::from([fixture.backend.clone()]));
        check.check(&fixture.backend).await.unwrap();
        assert_eq!(fixture.count(), 2);
        check.close_connections();
        assert!(check.check(&fixture.backend).await.is_err());
    }
}
