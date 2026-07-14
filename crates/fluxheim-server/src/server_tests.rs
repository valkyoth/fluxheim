use super::*;
use crate::http1::DEFAULT_HTTP1_MAX_CONNECTIONS;

use fluxheim_config::{Config, ServerLimitsConfig};
use fluxheim_runtime::{BackgroundTaskKind, BackgroundTaskSpec, ShutdownReason, ShutdownState};

struct StaticShutdown(ShutdownState);

impl ShutdownView for StaticShutdown {
    fn shutdown_state(&self) -> ShutdownState {
        self.0
    }
}

struct RecordingRunner;

impl ServerRunner for RecordingRunner {
    type Error = &'static str;

    fn run(&self, _plan: ServerPlan, shutdown: &dyn ShutdownView) -> Result<(), Self::Error> {
        if shutdown.is_shutdown_requested() {
            return Err("shutdown requested");
        }
        Ok(())
    }
}

#[test]
fn listener_spec_reports_loopback_and_proxy_protocol() {
    let spec = ListenerSpec::new("127.0.0.1:8080".parse().unwrap(), ListenerProtocol::Http)
        .with_proxy_protocol(true);

    assert!(spec.is_loopback());
    assert!(spec.proxy_protocol_enabled());
}

#[test]
fn server_plan_reports_public_listeners() {
    let public = ListenerSpec::new("0.0.0.0:443".parse().unwrap(), ListenerProtocol::Https);
    let local = ListenerSpec::new(
        "127.0.0.1:9090".parse().unwrap(),
        ListenerProtocol::MetricsHttp,
    );

    assert!(ServerPlan::new(vec![local, public], Vec::new()).has_public_listener());
    assert!(!ServerPlan::new(vec![local], Vec::new()).has_public_listener());
}

#[test]
fn downstream_http2_policy_uses_hardened_defaults() {
    let policy = DownstreamHttp2Policy::default();

    assert_eq!(policy.max_header_list_size(), 64 * 1024);
    assert_eq!(policy.max_header_count(), 100);
    assert_eq!(policy.max_uri_bytes(), 8 * 1024);
    assert_eq!(
        policy.response_write_lifetime(),
        std::time::Duration::from_secs(30)
    );
    assert_eq!(policy.handler_timeout(), std::time::Duration::from_secs(30));
    assert_eq!(policy.max_concurrent_streams(), 32);
    assert_eq!(policy.initial_window_size(), 64 * 1024);
    assert_eq!(policy.max_frame_size(), 16 * 1024);
    assert_eq!(policy.max_send_buffer_size(), 256 * 1024);
    assert_eq!(policy.max_pending_accept_reset_streams(), 8);
}

#[test]
fn downstream_http2_policy_maps_server_header_limits() {
    let policy = DownstreamHttp2Policy::from_server_limits(ServerLimitsConfig {
        max_request_header_bytes: fluxheim_config::ByteSize::from_bytes(4096),
        max_uri_bytes: fluxheim_config::ByteSize::from_bytes(1024),
        max_request_headers: 7,
        max_request_body_bytes: fluxheim_config::ByteSize::from_bytes(2048),
    });

    assert_eq!(policy.max_header_list_size(), 4096);
    assert_eq!(policy.max_header_count(), 7);
    assert_eq!(policy.max_uri_bytes(), 1024);
    assert_eq!(policy.max_concurrent_streams(), 32);
}

#[test]
fn server_plan_exposes_native_http2_preview_gate() {
    let plan = ServerPlan::from_config(&Config::default()).expect("valid server plan");
    let preview = plan.native_http2_preview();

    assert_eq!(preview.downstream_policy(), plan.downstream_http2());
    assert!(preview.is_cutover_ready());
    assert!(preview.reports().iter().any(|report| {
        report.hook() == NativeHttp2SafetyHook::DownstreamListenerDispatch
            && report.status() == NativeHttp2SafetyStatus::Satisfied
    }));
    assert!(preview.reports().iter().any(|report| {
        report.hook() == NativeHttp2SafetyHook::HeaderFieldCount
            && report.status() == NativeHttp2SafetyStatus::Satisfied
            && report.detail().contains("max_header_list_size")
    }));
}

#[test]
fn downstream_http1_policy_uses_bounded_native_defaults() {
    let policy = DownstreamHttp1Policy::default();

    assert_eq!(policy.max_body_bytes(), 64 * 1024 * 1024);
    assert_eq!(policy.max_head_bytes(), 64 * 1024);
    assert_eq!(policy.max_header_count(), 100);
    assert_eq!(policy.max_header_line_bytes(), 8 * 1024);
    assert_eq!(policy.max_start_line_bytes(), 8 * 1024);
    assert_eq!(policy.max_connections(), 1024);
    assert_eq!(
        policy.request_head_timeout(),
        std::time::Duration::from_secs(10)
    );
    assert_eq!(
        policy.tls_handshake_timeout(),
        std::time::Duration::from_secs(5)
    );
    assert_eq!(
        policy.request_body_timeout(),
        std::time::Duration::from_secs(30)
    );

    let plan = ServerPlan::new(Vec::new(), Vec::new());
    assert_eq!(plan.downstream_http1(), &policy);

    let limits = fluxheim_protocol::Http1HeadLimits::from(policy);
    assert_eq!(limits.max_head_bytes, policy.max_head_bytes());
    assert_eq!(limits.max_header_count, policy.max_header_count());
    assert_eq!(limits.max_header_line_bytes, policy.max_header_line_bytes());
    assert_eq!(limits.max_start_line_bytes, policy.max_start_line_bytes());
}

#[test]
fn downstream_http1_policy_preserves_tight_head_limit_invariant() {
    let policy = DownstreamHttp1Policy::from_server_limits(ServerLimitsConfig {
        max_request_header_bytes: fluxheim_config::ByteSize::from_bytes(16),
        max_uri_bytes: fluxheim_config::ByteSize::from_bytes(8),
        max_request_headers: 4,
        max_request_body_bytes: fluxheim_config::ByteSize::from_bytes(16),
    });

    assert_eq!(policy.max_head_bytes(), 16);
    assert_eq!(policy.max_start_line_bytes(), 16);
    assert!(policy.max_start_line_bytes() <= policy.max_head_bytes());
}

#[test]
fn downstream_http1_policy_treats_zero_connection_cap_as_default() {
    let policy = DownstreamHttp1Policy::default().with_max_connections(0);

    assert_eq!(policy.max_connections(), DEFAULT_HTTP1_MAX_CONNECTIONS);
}

#[test]
fn downstream_http1_policy_bounds_connection_cap_without_panicking() {
    let saturated = DownstreamHttp1Policy::default().with_max_connections(usize::MAX);
    let rejected = DownstreamHttp1Policy::default().try_with_max_connections(usize::MAX);

    assert_eq!(
        saturated.max_connections(),
        tokio::sync::Semaphore::MAX_PERMITS
    );
    assert_eq!(
        rejected,
        Err("HTTP/1 max_connections exceeds Tokio semaphore capacity")
    );
}

#[test]
fn server_plan_maps_configured_limits_to_downstream_http1_policy() {
    let mut config = Config::default();
    config.server.limits = ServerLimitsConfig {
        max_request_header_bytes: fluxheim_config::ByteSize::from_bytes(4096),
        max_uri_bytes: fluxheim_config::ByteSize::from_bytes(1024),
        max_request_headers: 32,
        max_request_body_bytes: fluxheim_config::ByteSize::from_bytes(2048),
    };

    let plan = ServerPlan::from_config(&config).expect("valid server plan");
    let policy = plan.downstream_http1();

    assert_eq!(policy.max_body_bytes(), 2048);
    assert_eq!(policy.max_head_bytes(), 4096);
    assert_eq!(policy.max_header_count(), 32);
    assert_eq!(policy.max_start_line_bytes(), 1056);
}

#[test]
fn server_plan_builds_certificate_reload_control_plan_when_enabled() {
    let mut config = Config::default();
    config.tls.acme.enabled = true;
    config.server.process.certificate_reload_sock =
        std::path::PathBuf::from("/run/fluxheim/test-cert-reload.sock");

    let plan = ServerPlan::from_config(&config).expect("valid server plan");
    let control = plan
        .certificate_reload_control()
        .expect("certificate reload control plan");

    assert_eq!(
        control.socket_path(),
        std::path::Path::new("/run/fluxheim/test-cert-reload.sock")
    );
    assert_eq!(control.max_concurrent_requests(), 4);
    assert_eq!(control.read_timeout(), std::time::Duration::from_secs(5));

    config.tls.acme.renewal.reload_after_renewal = false;
    let plan = ServerPlan::from_config(&config).expect("valid server plan");
    assert!(plan.certificate_reload_control().is_none());
}

#[test]
fn server_runner_boundary_accepts_shutdown_view() {
    let plan = ServerPlan::new(
        Vec::new(),
        vec![BackgroundTaskSpec::new(
            "metrics-export",
            BackgroundTaskKind::MetricsExport,
        )],
    );
    let runner = RecordingRunner;

    assert!(
        runner
            .run(plan.clone(), &StaticShutdown(ShutdownState::running()))
            .is_ok()
    );
    assert_eq!(
        runner.run(
            plan,
            &StaticShutdown(ShutdownState::requested(ShutdownReason::Signal))
        ),
        Err("shutdown requested")
    );
}
