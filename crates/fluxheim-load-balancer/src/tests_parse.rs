#![allow(unused_imports)]

use std::io::{self, ErrorKind};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use fluxheim_config::{
    LoadBalanceConfig, LoadBalanceHealthCheckConfig, LoadBalanceHealthCheckExpectedStatusRange,
    LoadBalanceHealthCheckProtocol, LoadBalanceManagedCookieSameSite,
    LoadBalancePassiveHealthConfig, LoadBalancePersistenceConfig, LoadBalancePersistenceMode,
    LoadBalanceQueueConfig, LoadBalanceSelection, LoadBalanceSlowStartConfig, ProxyConfig,
};
use tokio::sync::watch;

#[cfg(not(feature = "privacy-mode"))]
use super::LoadBalancerCircuitState;
use super::backend::FluxBackend;
use super::persistence::{MAX_PERSISTENCE_KEY_BYTES, cookie_key, request_header_key};
use super::selection::least_connections_score_is_lower;
use super::state::PassiveBackendHealth;
use super::tests_support::{install_test_crypto_provider, request, slow_start_blocking_sample};
use super::{
    LoadBalancedUpstreamReporter, LoadBalancerDiscoveryMode, LoadBalancerPersistenceOutcome,
    LoadBalancerQueueOutcome, LoadBalancerRuntimeBackendSetOperation,
    LoadBalancerRuntimeBackendState, PassiveHealthState, SlowStartState, UpstreamLoadBalancer,
    backend_key,
};
use fluxheim_common::test_support::{safe_child_path, unique_temp_path};

#[test]
fn runtime_weight_parser_documents_reset_keywords_and_bounds() {
    assert_eq!(
        super::parse_load_balancer_runtime_weight("configured"),
        Ok(None)
    );
    assert_eq!(
        super::parse_load_balancer_runtime_weight("default"),
        Ok(None)
    );
    assert_eq!(super::parse_load_balancer_runtime_weight("reset"), Ok(None));
    assert_eq!(super::parse_load_balancer_runtime_weight("clear"), Ok(None));
    assert_eq!(
        super::parse_load_balancer_runtime_weight(" 7 "),
        Ok(Some(7))
    );
    assert_eq!(
        super::parse_load_balancer_runtime_weight("bogus"),
        Err("load balancer weight must be a number or one of default/reset/clear/configured")
    );
    assert_eq!(
        super::parse_load_balancer_runtime_weight("0"),
        Err("load balancer weight must be between 1 and 1000")
    );
    assert_eq!(
        super::parse_load_balancer_runtime_weight("1001"),
        Err("load balancer weight must be between 1 and 1000")
    );
}

#[test]
fn member_weight_parser_accepts_only_numeric_configured_weight() {
    assert_eq!(super::parse_load_balancer_member_weight(" 5 "), Ok(5));
    assert_eq!(
        super::parse_load_balancer_member_weight("reset"),
        Err("load balancer member weight must be a number")
    );
    assert_eq!(
        super::parse_load_balancer_member_weight("0"),
        Err("load balancer member weight must be between 1 and 1000")
    );
    assert_eq!(
        super::parse_load_balancer_member_weight("1001"),
        Err("load balancer member weight must be between 1 and 1000")
    );
}
