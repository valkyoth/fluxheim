use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use fluxheim_config::{LoadBalanceConfig, LoadBalanceHealthCheckConfig, ProxyConfig};
use tokio::net::TcpListener;

use super::{Backend, HealthDerivedWeights, configured_health_check};
use crate::UpstreamLoadBalancer;
use crate::tests_support::request;

fn config(application: SocketAddr, second: SocketAddr, port: Option<u16>) -> ProxyConfig {
    ProxyConfig {
        upstreams: vec![application.to_string(), second.to_string()],
        load_balance: LoadBalanceConfig {
            health_check: LoadBalanceHealthCheckConfig {
                enabled: true,
                port_override: port,
                consecutive_success: 1,
                consecutive_failure: 1,
                connect_timeout_secs: Some(1),
                ..LoadBalanceHealthCheckConfig::default()
            },
            ..LoadBalanceConfig::default()
        },
        ..ProxyConfig::default()
    }
}

async fn assert_probe_destination(ip: IpAddr) {
    let application = TcpListener::bind((ip, 0)).await.unwrap();
    let readiness = TcpListener::bind((ip, 0)).await.unwrap();
    let address = application.local_addr().unwrap();
    let port = readiness.local_addr().unwrap().port();
    let backend = Backend::new(&address.to_string()).unwrap();
    for override_port in [Some(port), None] {
        let check = configured_health_check(
            &config(address, readiness.local_addr().unwrap(), override_port),
            Arc::new(HealthDerivedWeights::default()),
        )
        .unwrap();
        check.check(&backend).await.unwrap();
        let (expected, untouched) = if override_port.is_some() {
            (&readiness, &application)
        } else {
            (&application, &readiness)
        };
        tokio::time::timeout(Duration::from_secs(2), expected.accept())
            .await
            .expect("probe reached the wrong listener")
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(30), untouched.accept())
                .await
                .is_err()
        );
        assert_eq!(
            backend.addr, address,
            "health checks must not mutate backend identity"
        );
    }
}

#[tokio::test]
async fn tcp_port_override_preserves_ipv4_destination_and_default() {
    assert_probe_destination(Ipv4Addr::LOCALHOST.into()).await;
}

#[tokio::test]
async fn tcp_port_override_preserves_ipv6_destination_and_default() {
    assert_probe_destination(Ipv6Addr::LOCALHOST.into()).await;
}

#[tokio::test]
async fn tcp_port_override_failure_recovery_preserves_application_selection() {
    let application = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let second = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let readiness = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ready_address = readiness.local_addr().unwrap();
    let addresses = [
        application.local_addr().unwrap(),
        second.local_addr().unwrap(),
    ];
    let pool = UpstreamLoadBalancer::from_proxy_config(&config(
        addresses[0],
        addresses[1],
        Some(ready_address.port()),
    ))
    .unwrap()
    .unwrap();
    pool.run_health_check(false).await;
    assert_eq!(pool.runtime_stats().ready_backend_count, 2);
    for _ in 0..4 {
        assert!(addresses.contains(&pool.select(&request(), None).unwrap().address()));
    }
    drop(readiness);
    let unavailable = tokio::net::TcpSocket::new_v4().unwrap();
    unavailable.bind(ready_address).unwrap();
    pool.run_health_check(false).await;
    assert_eq!(pool.runtime_stats().ready_backend_count, 0);
    assert!(pool.select(&request(), None).is_none());
    let _readiness = unavailable.listen(32).unwrap();
    pool.run_health_check(true).await;
    assert_eq!(pool.runtime_stats().ready_backend_count, 2);
    // Application failure does not change the explicitly separate readiness probe.
    drop(application);
    drop(second);
    pool.run_health_check(false).await;
    assert_eq!(pool.runtime_stats().ready_backend_count, 2);
    for _ in 0..4 {
        assert!(addresses.contains(&pool.select(&request(), None).unwrap().address()));
    }
}
