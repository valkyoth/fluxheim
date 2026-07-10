use crate::config::{Config, DownstreamProxyProtocol, TlsClientAuthConfig, TlsClientAuthMode};
use crate::reload::{ReloadImpact, ReloadReason, classify_reload};

fn assert_process_upgrade(new: Config, expected: ReloadReason) {
    assert_eq!(
        classify_reload(&Config::default(), &new),
        ReloadImpact::ProcessUpgrade {
            reasons: vec![expected],
        }
    );
}

#[test]
fn client_auth_change_requires_process_upgrade() {
    let mut new = Config::default();
    new.tls.client_auth = TlsClientAuthConfig {
        mode: TlsClientAuthMode::Required,
        ca_path: Some("client-ca.pem".into()),
    };
    assert_process_upgrade(new, ReloadReason::TlsClientAuthChanged);
}

#[test]
fn compliance_mode_change_requires_process_upgrade() {
    let mut new = Config::default();
    new.tls.iso19790.required = true;
    assert_process_upgrade(new, ReloadReason::ComplianceModeChanged);
}

#[test]
fn proxy_protocol_change_requires_process_upgrade() {
    let mut new = Config::default();
    new.server.proxy_protocol = DownstreamProxyProtocol::V1;
    assert_process_upgrade(new, ReloadReason::ListenerSecurityChanged);
}

#[test]
fn server_limit_change_requires_process_upgrade() {
    let mut new = Config::default();
    new.server.limits.max_request_headers += 1;
    assert_process_upgrade(new, ReloadReason::ListenerSecurityChanged);
}

#[test]
fn stream_service_change_requires_process_upgrade() {
    let mut new = Config::default();
    new.stream.enabled = true;
    assert_process_upgrade(new, ReloadReason::StreamServiceChanged);
}

#[test]
fn udp_service_change_requires_process_upgrade() {
    let mut new = Config::default();
    new.udp.enabled = true;
    assert_process_upgrade(new, ReloadReason::UdpServiceChanged);
}

#[test]
fn acme_service_change_requires_process_upgrade() {
    let mut new = Config::default();
    new.tls.acme.enabled = true;
    assert_process_upgrade(new, ReloadReason::AcmeServiceChanged);
}

#[test]
fn cache_purger_service_change_requires_process_upgrade() {
    let mut new = Config::default();
    new.cache_purger.enabled = true;
    assert_process_upgrade(new, ReloadReason::CachePurgerServiceChanged);
}

#[test]
fn tracing_service_change_requires_process_upgrade() {
    let mut new = Config::default();
    new.tracing.enabled = true;
    assert_process_upgrade(new, ReloadReason::TracingServiceChanged);
}

#[test]
fn certificate_lookup_change_remains_snapshot_safe() {
    let mut new = Config::default();
    new.tls
        .certificates
        .push(crate::config::StaticCertificateConfig {
            cert_path: "certificate.pem".into(),
            key_path: "key.pem".into(),
        });
    assert_eq!(
        classify_reload(&Config::default(), &new),
        ReloadImpact::Snapshot
    );
}
