use std::io;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use pingora::connectors::http::Connector as HttpConnector;
use pingora::lb::Backend;
use pingora::lb::health_check::{HealthCheck, TcpHealthCheck};
use pingora::protocols::http::client::HttpSession;
use pingora::upstreams::peer::{HttpPeer, Peer};
use pingora::{Error, ErrorType};

use crate::config::{
    LoadBalanceHealthCheckExpectedHeader, LoadBalanceHealthCheckExpectedStatusRange,
    LoadBalanceHealthCheckProtocol, ProxyConfig,
};
use crate::http_types::{
    PingoraRequestHeader as RequestHeader, PingoraResponseHeader as ResponseHeader,
};

const HTTP_HEALTH_CHECK_MAX_BODY_BYTES: usize = 64 * 1024;

pub(super) fn configured_health_check(
    config: &ProxyConfig,
) -> io::Result<Box<dyn HealthCheck + Send + Sync + 'static>> {
    match config.load_balance.health_check.protocol {
        LoadBalanceHealthCheckProtocol::Tcp => {
            let mut health_check = if config.upstream_tls {
                TcpHealthCheck::new_tls(&config.upstream_sni())
            } else {
                TcpHealthCheck::new()
            };
            health_check.consecutive_success = config.load_balance.health_check.consecutive_success;
            health_check.consecutive_failure = config.load_balance.health_check.consecutive_failure;
            apply_health_check_peer_timeouts(
                &mut health_check.peer_template.options.connection_timeout,
                None,
                config,
            );
            Ok(health_check)
        }
        LoadBalanceHealthCheckProtocol::Http => configured_http_health_check(config)
            .map(|check| check as Box<dyn HealthCheck + Send + Sync + 'static>),
    }
}

struct FluxHttpHealthCheck {
    consecutive_success: usize,
    consecutive_failure: usize,
    peer_template: HttpPeer,
    reuse_connection: bool,
    req: RequestHeader,
    connector: HttpConnector,
    port_override: Option<u16>,
    expected_statuses: Arc<[u16]>,
    expected_status_ranges: Arc<[LoadBalanceHealthCheckExpectedStatusRange]>,
    expected_headers: Arc<[LoadBalanceHealthCheckExpectedHeader]>,
    expected_body_contains: Arc<[String]>,
}

#[async_trait]
impl HealthCheck for FluxHttpHealthCheck {
    fn health_threshold(&self, success: bool) -> usize {
        if success {
            self.consecutive_success
        } else {
            self.consecutive_failure
        }
    }

    async fn check(&self, target: &Backend) -> pingora::Result<()> {
        let mut peer = self.peer_template.clone();
        peer._address = target.addr.clone();
        if let Some(port) = self.port_override {
            peer._address.set_port(port);
        }

        let (mut session, _) = self.connector.get_http_session(&peer).await?;
        session
            .write_request_header(Box::new(self.req.clone()))
            .await?;
        session.finish_request_body().await?;

        if let Some(read_timeout) = peer.options.read_timeout {
            session.set_read_timeout(Some(read_timeout));
        }

        session.read_response_header().await?;
        let Some(response) = session.response_header() else {
            return Error::e_explain(
                ErrorType::ReadError,
                "missing HTTP health check response header",
            );
        };
        validate_http_health_response(
            response,
            &self.expected_statuses,
            &self.expected_status_ranges,
            &self.expected_headers,
        )?;

        if self.expected_body_contains.is_empty() {
            drain_http_health_response_body(&mut session).await?;
        } else {
            let body = read_http_health_response_body(&mut session).await?;
            validate_http_health_response_body(&body, &self.expected_body_contains)?;
        }

        if self.reuse_connection {
            let idle_timeout = peer.idle_timeout();
            self.connector
                .release_http_session(session, &peer, idle_timeout)
                .await;
        }

        Ok(())
    }
}

fn configured_http_health_check(config: &ProxyConfig) -> io::Result<Box<FluxHttpHealthCheck>> {
    let host = config
        .load_balance
        .health_check
        .host
        .clone()
        .unwrap_or_else(|| config.upstream_sni());
    let mut request = RequestHeader::build(
        config.load_balance.health_check.method.as_str(),
        config.load_balance.health_check.path.as_bytes(),
        None,
    )
    .map_err(|error| io::Error::other(error.to_string()))?;
    request
        .append_header("Host", &host)
        .map_err(|error| io::Error::other(error.to_string()))?;

    let sni = if config.upstream_tls {
        host.clone()
    } else {
        String::new()
    };
    let mut peer_template = HttpPeer::new("0.0.0.0:1", config.upstream_tls, sni);
    peer_template.options.connection_timeout = Some(Duration::from_secs(1));
    peer_template.options.read_timeout = Some(Duration::from_secs(1));
    apply_health_check_peer_timeouts(
        &mut peer_template.options.connection_timeout,
        Some(&mut peer_template.options.read_timeout),
        config,
    );

    Ok(Box::new(FluxHttpHealthCheck {
        consecutive_success: config.load_balance.health_check.consecutive_success,
        consecutive_failure: config.load_balance.health_check.consecutive_failure,
        peer_template,
        reuse_connection: config.load_balance.health_check.reuse_connection,
        req: request,
        connector: HttpConnector::new(None),
        port_override: config.load_balance.health_check.port_override,
        expected_statuses: config
            .load_balance
            .health_check
            .expected_statuses
            .clone()
            .into(),
        expected_status_ranges: config
            .load_balance
            .health_check
            .expected_status_ranges
            .clone()
            .into(),
        expected_headers: config
            .load_balance
            .health_check
            .expected_headers
            .clone()
            .into(),
        expected_body_contains: config
            .load_balance
            .health_check
            .expected_body_contains
            .clone()
            .into(),
    }))
}

fn apply_health_check_peer_timeouts(
    connection_timeout: &mut Option<Duration>,
    read_timeout: Option<&mut Option<Duration>>,
    config: &ProxyConfig,
) {
    if let Some(timeout) = config
        .load_balance
        .health_check
        .connect_timeout_secs
        .or(config.connect_timeout_secs)
    {
        *connection_timeout = Some(Duration::from_secs(timeout));
    }
    if let Some(read_timeout) = read_timeout
        && let Some(timeout) = config
            .load_balance
            .health_check
            .read_timeout_secs
            .or(config.read_timeout_secs)
    {
        *read_timeout = Some(Duration::from_secs(timeout));
    }
}

fn validate_http_health_response(
    response: &ResponseHeader,
    expected_statuses: &[u16],
    expected_status_ranges: &[LoadBalanceHealthCheckExpectedStatusRange],
    expected_headers: &[LoadBalanceHealthCheckExpectedHeader],
) -> pingora::Result<()> {
    let status = response.status.as_u16();
    if expected_statuses.is_empty() && expected_status_ranges.is_empty() {
        if status != 200 {
            return Error::e_explain(
                ErrorType::HTTPStatus(status),
                "unexpected HTTP health check status",
            );
        }
    } else if !expected_statuses.contains(&status)
        && !expected_status_ranges
            .iter()
            .any(|range| (range.start..=range.end).contains(&status))
    {
        return Error::e_explain(
            ErrorType::HTTPStatus(status),
            "unexpected HTTP health check status",
        );
    }

    for expected in expected_headers {
        let mut matched = false;
        for value in response.headers.get_all(expected.name.as_str()) {
            if value.as_bytes() == expected.value.as_bytes() {
                matched = true;
                break;
            }
        }
        if !matched {
            return Error::e_explain(
                ErrorType::InvalidHTTPHeader,
                "missing expected HTTP health check header",
            );
        }
    }
    Ok(())
}

async fn drain_http_health_response_body(session: &mut HttpSession) -> pingora::Result<()> {
    let mut drained = 0usize;
    while let Some(chunk) = session.read_response_body().await? {
        drained = drained.saturating_add(chunk.len());
        if drained > HTTP_HEALTH_CHECK_MAX_BODY_BYTES {
            return Error::e_explain(
                ErrorType::ReadError,
                "HTTP health check response body exceeded maximum size",
            );
        }
    }
    Ok(())
}

async fn read_http_health_response_body(session: &mut HttpSession) -> pingora::Result<Vec<u8>> {
    let mut body = Vec::new();
    while let Some(chunk) = session.read_response_body().await? {
        if body.len().saturating_add(chunk.len()) > HTTP_HEALTH_CHECK_MAX_BODY_BYTES {
            return Error::e_explain(
                ErrorType::ReadError,
                "HTTP health check response body exceeded maximum size",
            );
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn validate_http_health_response_body(
    body: &[u8],
    expected_body_contains: &[String],
) -> pingora::Result<()> {
    for expected in expected_body_contains {
        if !body
            .windows(expected.len())
            .any(|window| window == expected.as_bytes())
        {
            return Error::e_explain(
                ErrorType::ReadError,
                "missing expected HTTP health check response body substring",
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{
        configured_http_health_check, validate_http_health_response,
        validate_http_health_response_body,
    };
    use crate::config::{
        LoadBalanceConfig, LoadBalanceHealthCheckConfig, LoadBalanceHealthCheckExpectedHeader,
        LoadBalanceHealthCheckExpectedStatusRange, LoadBalanceHealthCheckProtocol, ProxyConfig,
    };
    use crate::http_types::PingoraResponseHeader as ResponseHeader;

    fn install_test_crypto_provider() {
        #[cfg(feature = "tls-rustls-backend")]
        let _ = crate::tls::install_rustls_crypto_provider();
    }

    #[test]
    fn configures_pingora_http_health_check() {
        install_test_crypto_provider();
        let health_check = configured_http_health_check(&ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            connect_timeout_secs: Some(2),
            read_timeout_secs: Some(4),
            load_balance: LoadBalanceConfig {
                health_check: LoadBalanceHealthCheckConfig {
                    enabled: true,
                    protocol: LoadBalanceHealthCheckProtocol::Http,
                    consecutive_success: 2,
                    consecutive_failure: 3,
                    method: "HEAD".to_owned(),
                    path: "/healthz".to_owned(),
                    host: Some("origin.example.test".to_owned()),
                    expected_statuses: vec![200, 204],
                    expected_status_ranges: vec![LoadBalanceHealthCheckExpectedStatusRange {
                        start: 300,
                        end: 399,
                    }],
                    expected_headers: vec![LoadBalanceHealthCheckExpectedHeader {
                        name: "x-fluxheim-health".to_owned(),
                        value: "ready".to_owned(),
                    }],
                    expected_body_contains: vec!["ready".to_owned()],
                    reuse_connection: true,
                    port_override: Some(8081),
                    connect_timeout_secs: Some(5),
                    read_timeout_secs: Some(6),
                    ..LoadBalanceHealthCheckConfig::default()
                },
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap();

        assert_eq!(health_check.consecutive_success, 2);
        assert_eq!(health_check.consecutive_failure, 3);
        assert_eq!(health_check.req.method.as_str(), "HEAD");
        assert!(health_check.reuse_connection);
        assert_eq!(health_check.port_override, Some(8081));
        assert_eq!(
            health_check.peer_template.options.connection_timeout,
            Some(Duration::from_secs(5))
        );
        assert_eq!(
            health_check.peer_template.options.read_timeout,
            Some(Duration::from_secs(6))
        );
        assert!(!health_check.expected_statuses.is_empty());
        assert!(!health_check.expected_headers.is_empty());
        assert_eq!(
            health_check.expected_body_contains.as_ref(),
            ["ready".to_owned()]
        );
    }

    #[test]
    fn validates_http_health_check_expected_headers() {
        let expected_statuses = [204];
        let expected_status_ranges = [LoadBalanceHealthCheckExpectedStatusRange {
            start: 300,
            end: 399,
        }];
        let expected_headers = [LoadBalanceHealthCheckExpectedHeader {
            name: "x-fluxheim-health".to_owned(),
            value: "ready".to_owned(),
        }];
        let mut response = ResponseHeader::build(204, None).unwrap();
        response
            .append_header("x-fluxheim-health", "ready")
            .unwrap();
        assert!(
            validate_http_health_response(
                &response,
                &expected_statuses,
                &expected_status_ranges,
                &expected_headers
            )
            .is_ok()
        );

        let missing = ResponseHeader::build(204, None).unwrap();
        assert!(
            validate_http_health_response(
                &missing,
                &expected_statuses,
                &expected_status_ranges,
                &expected_headers
            )
            .is_err()
        );

        let ranged = ResponseHeader::build(302, None).unwrap();
        assert!(validate_http_health_response(&ranged, &[], &expected_status_ranges, &[]).is_ok());
    }

    #[test]
    fn validates_http_health_check_expected_body_contains() {
        let expected = ["ready".to_owned(), "database=up".to_owned()];
        assert!(validate_http_health_response_body(b"ready database=up", &expected).is_ok());
        assert!(validate_http_health_response_body(b"ready database=down", &expected).is_err());
    }
}
