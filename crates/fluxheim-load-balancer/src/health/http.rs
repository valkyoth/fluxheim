use std::io;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header};
use serde_json::Value;

use fluxheim_common::{FluxError, FluxResult};
use fluxheim_config::{
    LoadBalanceHealthCheckExpectedHeader, LoadBalanceHealthCheckExpectedJson,
    LoadBalanceHealthCheckExpectedStatusRange, LoadBalanceHealthCheckProtocol, ProxyConfig,
};

use crate::backend::{FluxHealthCheck, RuntimeBackend as Backend};
use crate::key::backend_key;
use crate::policy::HealthDerivedWeights;

use super::grpc::{
    execute_grpc_health_check, grpc_health_request_body, validate_grpc_health_response_body,
    validate_grpc_health_response_header,
};
use super::http1::execute_http1_health_check;
use super::transport::{
    FluxTcpHealthCheckTls, HealthTlsAlpn, configured_tcp_health_check_tls, connect_health_stream,
};

pub(super) const HTTP_HEALTH_CHECK_MAX_BODY_BYTES: usize = 64 * 1024;
pub(super) const HTTP_HEALTH_CHECK_MAX_HEADER_BYTES: usize = 8 * 1024;
const GRPC_HEALTH_CHECK_PATH: &[u8] = b"/grpc.health.v1.Health/Check";
const HEALTH_WEIGHT_HEADER: &str = "x-health-weight";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct HealthHttpRequest {
    pub(super) method: Method,
    pub(super) path: String,
    pub(super) host: String,
    pub(super) headers: HeaderMap,
    pub(super) body: Option<Bytes>,
    pub(super) grpc: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct HealthHttpResponse {
    pub(super) status: StatusCode,
    pub(super) headers: HeaderMap,
}

pub(super) struct FluxHttpHealthCheck {
    pub(super) consecutive_success: usize,
    pub(super) consecutive_failure: usize,
    upstream_tls: bool,
    tls: Option<FluxTcpHealthCheckTls>,
    pub(super) connection_timeout: Duration,
    pub(super) read_timeout: Duration,
    pub(super) req: HealthHttpRequest,
    pub(super) port_override: Option<u16>,
    pub(super) expected_statuses: Arc<[u16]>,
    pub(super) expected_status_ranges: Arc<[LoadBalanceHealthCheckExpectedStatusRange]>,
    pub(super) expected_headers: Arc<[LoadBalanceHealthCheckExpectedHeader]>,
    pub(super) expected_body_contains: Arc<[String]>,
    pub(super) expected_body_json: Arc<[LoadBalanceHealthCheckExpectedJson]>,
    health_weight_min_percent: u8,
    health_weights: Arc<HealthDerivedWeights>,
}

#[async_trait]
impl FluxHealthCheck for FluxHttpHealthCheck {
    fn health_threshold(&self, success: bool) -> usize {
        if success {
            self.consecutive_success
        } else {
            self.consecutive_failure
        }
    }

    async fn check(&self, target: &Backend) -> FluxResult<()> {
        let mut address = target.addr;
        if let Some(port) = self.port_override {
            address.set_port(port);
        }
        let stream = connect_health_stream(
            address,
            self.upstream_tls,
            self.tls.as_ref(),
            self.connection_timeout,
        )
        .await?;

        let (response, body) = if self.req.grpc {
            execute_grpc_health_check(stream, &self.req, self.read_timeout).await?
        } else {
            execute_http1_health_check(stream, &self.req, self.read_timeout).await?
        };
        validate_http_health_response(
            &response,
            &self.expected_statuses,
            &self.expected_status_ranges,
            &self.expected_headers,
        )
        .map_err(HttpHealthCheckError::into_flux)?;
        record_health_weight(
            &response,
            backend_key(target),
            self.health_weight_min_percent,
            &self.health_weights,
        )
        .map_err(HttpHealthCheckError::into_flux)?;

        if self.req.grpc {
            validate_grpc_health_response_header(&response)
                .map_err(HttpHealthCheckError::into_flux)?;
            validate_grpc_health_response_body(&body).map_err(HttpHealthCheckError::into_flux)?;
        } else if self.expected_body_contains.is_empty() && self.expected_body_json.is_empty() {
            let _ = body;
        } else {
            validate_http_health_response_body(&body, &self.expected_body_contains)
                .map_err(HttpHealthCheckError::into_flux)?;
            validate_http_health_response_body_json(&body, &self.expected_body_json)
                .map_err(HttpHealthCheckError::into_flux)?;
        }

        Ok(())
    }
}

pub(super) fn configured_http_health_check(
    config: &ProxyConfig,
    health_weights: Arc<HealthDerivedWeights>,
) -> FluxResult<Box<FluxHttpHealthCheck>> {
    #[cfg(test)]
    crate::install_test_crypto_provider();

    let grpc = config.load_balance.health_check.protocol == LoadBalanceHealthCheckProtocol::Grpc;
    let host = config
        .load_balance
        .health_check
        .host
        .clone()
        .unwrap_or_else(|| config.upstream_sni());
    let method = if grpc {
        "POST"
    } else {
        config.load_balance.health_check.method.as_str()
    };
    let path = if grpc {
        std::str::from_utf8(GRPC_HEALTH_CHECK_PATH).unwrap_or("/grpc.health.v1.Health/Check")
    } else {
        config.load_balance.health_check.path.as_str()
    };
    reject_http1_health_request_crlf(path, "health check path must not contain CR or LF")?;
    reject_http1_health_request_crlf(&host, "health check host must not contain CR or LF")?;
    reject_http_health_host_userinfo(&host)?;
    let method = Method::from_bytes(method.as_bytes()).map_err(|error| {
        FluxError::io(
            "build HTTP health check request method",
            io::Error::other(error.to_string()),
        )
    })?;
    let mut headers = HeaderMap::new();
    for header in &config.load_balance.health_check.request_headers {
        let name = HeaderName::from_bytes(header.name.as_bytes()).map_err(|error| {
            FluxError::io(
                "append HTTP health check request header",
                io::Error::other(error.to_string()),
            )
        })?;
        let value = HeaderValue::from_str(&header.value).map_err(|error| {
            FluxError::io(
                "append HTTP health check request header",
                io::Error::other(error.to_string()),
            )
        })?;
        headers.append(name, value);
    }
    if grpc {
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/grpc"),
        );
        headers.insert("te", HeaderValue::from_static("trailers"));
    }
    if config.load_balance.health_check.reuse_connection {
        log::warn!(
            target: "fluxheim::load_balancer",
            "load-balancer health_check.reuse_connection is accepted for compatibility but not \
             implemented by the native health-check client yet; checks will open a fresh connection"
        );
    }

    let mut connection_timeout = Some(Duration::from_secs(1));
    let mut read_timeout = Some(Duration::from_secs(1));
    apply_health_check_peer_timeouts(&mut connection_timeout, Some(&mut read_timeout), config);
    let connection_timeout = connection_timeout.unwrap_or_else(|| Duration::from_secs(1));
    let read_timeout = read_timeout.unwrap_or_else(|| Duration::from_secs(1));
    let tls = configured_tcp_health_check_tls(
        config,
        if grpc {
            HealthTlsAlpn::Http2
        } else {
            HealthTlsAlpn::Http1
        },
    )?;

    Ok(Box::new(FluxHttpHealthCheck {
        consecutive_success: config.load_balance.health_check.consecutive_success,
        consecutive_failure: config.load_balance.health_check.consecutive_failure,
        upstream_tls: config.upstream_tls,
        tls,
        connection_timeout,
        read_timeout,
        req: HealthHttpRequest {
            method,
            path: path.to_owned(),
            host,
            headers,
            body: if grpc {
                Some(Bytes::from(grpc_health_request_body(
                    config.load_balance.health_check.grpc_service.as_deref(),
                )?))
            } else {
                None
            },
            grpc,
        },
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
        expected_body_json: config
            .load_balance
            .health_check
            .expected_body_json
            .clone()
            .into(),
        health_weight_min_percent: config.load_balance.health_check.health_weight_min_percent,
        health_weights,
    }))
}

fn reject_http1_health_request_crlf(value: &str, message: &'static str) -> FluxResult<()> {
    if value.bytes().any(|byte| matches!(byte, b'\r' | b'\n')) {
        return Err(FluxError::InvalidInput(message));
    }
    Ok(())
}

fn reject_http_health_host_userinfo(value: &str) -> FluxResult<()> {
    if value.as_bytes().contains(&b'@') {
        return Err(FluxError::InvalidInput(
            "health check host must not contain userinfo",
        ));
    }
    Ok(())
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

pub(super) fn validate_http_health_response(
    response: &HealthHttpResponse,
    expected_statuses: &[u16],
    expected_status_ranges: &[LoadBalanceHealthCheckExpectedStatusRange],
    expected_headers: &[LoadBalanceHealthCheckExpectedHeader],
) -> Result<(), HttpHealthCheckError> {
    let status = response.status.as_u16();
    if expected_statuses.is_empty() && expected_status_ranges.is_empty() {
        if status != 200 {
            return Err(HttpHealthCheckError::new(
                HealthErrorKind::HttpStatus(status),
                "unexpected HTTP health check status",
            ));
        }
    } else if !expected_statuses.contains(&status)
        && !expected_status_ranges
            .iter()
            .any(|range| (range.start..=range.end).contains(&status))
    {
        return Err(HttpHealthCheckError::new(
            HealthErrorKind::HttpStatus(status),
            "unexpected HTTP health check status",
        ));
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
            return Err(HttpHealthCheckError::new(
                HealthErrorKind::InvalidHttpHeader,
                "missing expected HTTP health check header",
            ));
        }
    }
    Ok(())
}

pub(super) fn validate_http_health_response_body(
    body: &[u8],
    expected_body_contains: &[String],
) -> Result<(), HttpHealthCheckError> {
    for expected in expected_body_contains {
        if !body
            .windows(expected.len())
            .any(|window| window == expected.as_bytes())
        {
            return Err(HttpHealthCheckError::new(
                HealthErrorKind::ReadError,
                "missing expected HTTP health check response body substring",
            ));
        }
    }
    Ok(())
}

pub(super) fn validate_http_health_response_body_json(
    body: &[u8],
    expected_body_json: &[LoadBalanceHealthCheckExpectedJson],
) -> Result<(), HttpHealthCheckError> {
    if expected_body_json.is_empty() {
        return Ok(());
    }
    let json: Value = serde_json::from_slice(body).map_err(|_| {
        HttpHealthCheckError::new(
            HealthErrorKind::ReadError,
            "invalid HTTP health check JSON response body",
        )
    })?;
    for expected in expected_body_json {
        let Some(value) = json_path_value(&json, &expected.path) else {
            return Err(HttpHealthCheckError::new(
                HealthErrorKind::ReadError,
                "missing expected HTTP health check JSON field",
            ));
        };
        if json_scalar_string(value).as_deref() != Some(expected.equals.as_str()) {
            return Err(HttpHealthCheckError::new(
                HealthErrorKind::ReadError,
                "unexpected HTTP health check JSON field value",
            ));
        }
    }
    Ok(())
}

fn json_path_value<'a>(json: &'a Value, path: &str) -> Option<&'a Value> {
    let mut value = json;
    for segment in path.split('.') {
        value = value.as_object()?.get(segment)?;
    }
    Some(value)
}

pub(super) fn record_health_weight(
    response: &HealthHttpResponse,
    key: u64,
    min_percent: u8,
    health_weights: &HealthDerivedWeights,
) -> Result<(), HttpHealthCheckError> {
    let Some(value) = response.headers.get(HEALTH_WEIGHT_HEADER) else {
        health_weights.set_percent(key, None);
        return Ok(());
    };
    let value = value.to_str().map_err(|_| {
        HttpHealthCheckError::new(
            HealthErrorKind::InvalidHttpHeader,
            "invalid HTTP health check degraded weight header",
        )
    })?;
    let percent = value.trim().parse::<u8>().map_err(|_| {
        HttpHealthCheckError::new(
            HealthErrorKind::InvalidHttpHeader,
            "invalid HTTP health check degraded weight header",
        )
    })?;
    if percent == 0 || percent > 100 {
        return Err(HttpHealthCheckError::new(
            HealthErrorKind::InvalidHttpHeader,
            "invalid HTTP health check degraded weight header",
        ));
    }
    let percent = percent.max(min_percent);
    health_weights.set_percent(key, (percent < 100).then_some(percent));
    Ok(())
}

fn json_scalar_string(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Null => Some("null".to_owned()),
        Value::Array(_) | Value::Object(_) => None,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum HealthErrorKind {
    ReadError,
    InvalidHttpHeader,
    HttpStatus(u16),
}

pub(super) struct HttpHealthCheckError {
    pub(super) kind: HealthErrorKind,
    error: FluxError,
}

impl HttpHealthCheckError {
    pub(super) fn new(kind: HealthErrorKind, detail: &'static str) -> Self {
        Self {
            kind,
            error: FluxError::InvalidInput(detail),
        }
    }

    pub(super) fn into_flux(self) -> FluxError {
        FluxError::io(
            "HTTP health check failed",
            io::Error::other(format!("{:?}: {}", self.kind, self.error)),
        )
    }
}
