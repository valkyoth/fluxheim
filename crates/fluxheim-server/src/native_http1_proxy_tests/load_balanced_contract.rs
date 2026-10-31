use super::*;

fn config(
    first: std::net::SocketAddr,
    second: std::net::SocketAddr,
) -> fluxheim_config::ProxyConfig {
    fluxheim_config::ProxyConfig {
        upstream: None,
        upstreams: vec![first.to_string(), second.to_string()],
        load_balance: fluxheim_config::LoadBalanceConfig {
            health_check: fluxheim_config::LoadBalanceHealthCheckConfig {
                enabled: false,
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    }
}

fn proxy(config: &fluxheim_config::ProxyConfig) -> NativeHttp1Proxy {
    NativeHttp1Proxy::from_proxy_config_with_native_load_balancer(
        "documented-contract",
        "proxy.test",
        None,
        config,
        DownstreamHttp1Policy::default(),
        0,
    )
    .unwrap()
    .unwrap()
    .0
}

async fn origin(status: u16, delay: Duration, count: Arc<AtomicUsize>) -> std::net::SocketAddr {
    upstream(move |_, mut stream| {
        let count = Arc::clone(&count);
        async move {
            count.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(delay).await;
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 {status} Test\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
        }
    })
    .await
}

#[tokio::test]
async fn native_load_balancer_retries_configured_status_once_per_distinct_member() {
    let count = Arc::new(AtomicUsize::new(0));
    let first = origin(503, Duration::ZERO, Arc::clone(&count)).await;
    let second = origin(503, Duration::ZERO, Arc::clone(&count)).await;
    let mut config = config(first, second);
    config.load_balance.retry.enabled = true;
    config.load_balance.retry.max_retries = 2;
    config.load_balance.retry.statuses = vec![503];
    let listener = proxy_listener_for(proxy(&config)).await;
    let response = tokio::time::timeout(Duration::from_secs(3), downstream_get(listener, "/"))
        .await
        .unwrap();
    assert!(response.starts_with("HTTP/1.1 503"), "{response}");
    assert_eq!(count.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn native_load_balancer_feeds_latency_policy_and_ejects_slow_member() {
    let count = Arc::new(AtomicUsize::new(0));
    let first = origin(200, Duration::from_millis(25), Arc::clone(&count)).await;
    let second = origin(200, Duration::from_millis(25), count).await;
    let mut config = config(first, second);
    config.load_balance.selection = fluxheim_config::LoadBalanceSelection::LeastTime;
    config.load_balance.passive_health.enabled = true;
    config.load_balance.passive_health.consecutive_failure = 1;
    config.load_balance.passive_health.min_healthy_backends = 0;
    config.load_balance.passive_health.max_latency_ms = 1;
    let proxy = proxy(&config);
    let pool = proxy.load_balancer.clone().unwrap();
    let listener = proxy_listener_for(proxy).await;
    let response = tokio::time::timeout(Duration::from_secs(3), downstream_get(listener, "/"))
        .await
        .unwrap();
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    let stats = pool.runtime_stats();
    assert!(
        stats
            .backends
            .iter()
            .any(|backend| backend.latency_micros.is_some_and(|sample| sample >= 1000))
    );
    assert_eq!(stats.passive_ejected_backend_count, 1);
}
