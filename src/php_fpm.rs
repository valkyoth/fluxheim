use std::io;
use std::sync::Arc;
use std::time::Duration;

use crate::http_types::{PingoraResponseHeader as ResponseHeader, StatusCode};

use crate::config::{PhpConfig, PhpFpmConfig};
use crate::flux_error::{FluxError, FluxResult};
#[cfg(all(test, unix))]
pub(crate) use fluxheim_php_fpm::create_php_request_body_spool_dir_sync;
#[cfg(test)]
pub(crate) use fluxheim_php_fpm::php_fpm_retry_attempts;
#[cfg(test)]
pub(crate) use fluxheim_php_fpm::push_php_fpm_stream_chunk;
#[cfg(test)]
pub(crate) use fluxheim_php_fpm::safe_php_header_value;
pub(crate) use fluxheim_php_fpm::{
    ManagedPhpFpmProcess, PhpFpmEndpoint, PhpFpmPool, PhpFpmPoolMetrics, PhpFpmTimeoutKind,
    PhpRequestBody, collect_php_fpm_response_stream, create_php_request_body_spool_file,
    managed_php_fpm_from_config, php_fpm_effective_connect_timeout,
    php_fpm_effective_request_timeout, php_fpm_endpoints_from_config, php_fpm_error_outcome,
    php_fpm_retry_attempts_for_endpoint_count, php_fpm_retry_deadline,
    php_fpm_retry_deadline_allows, php_fpm_retryable_error, php_fpm_retryable_status,
    php_fpm_timeout_error,
};
#[cfg(all(test, unix))]
pub(crate) use fluxheim_php_fpm::{
    managed_php_fpm_config, managed_php_fpm_path_env_from, managed_php_fpm_restart_backoff_secs,
};

pub(crate) struct PhpFpmParsedResponse {
    pub(crate) response: ResponseHeader,
    pub(crate) body: Vec<u8>,
    pub(crate) stderr: Option<Vec<u8>>,
}

pub(crate) fn php_fpm_keepalive_pools_from_config(
    config: &PhpConfig,
    metric_vhost: &str,
    metric_pool: &str,
) -> Vec<Arc<PhpFpmPool>> {
    fluxheim_php_fpm::php_fpm_keepalive_pools_from_config(
        config,
        metric_vhost,
        metric_pool,
        php_fpm_pool_metrics(),
    )
}

fn php_fpm_pool_metrics() -> PhpFpmPoolMetrics {
    #[cfg(feature = "metrics")]
    {
        PhpFpmPoolMetrics::new(
            crate::metrics::record_php_fpm_pool_event,
            crate::metrics::record_php_fpm_pool_idle,
        )
    }
    #[cfg(not(feature = "metrics"))]
    {
        PhpFpmPoolMetrics::default()
    }
}

pub(crate) async fn execute_php_fpm_once(
    pool: Option<&PhpFpmPool>,
    endpoint: &PhpFpmEndpoint,
    params: fastcgi_client::Params<'_>,
    body: &PhpRequestBody,
    connect_timeout: Duration,
    timeout: Duration,
    max_response_bytes: u64,
) -> io::Result<fastcgi_client::Response> {
    if let Some(pool) = pool {
        return pool.execute(params, body, connect_timeout, timeout).await;
    }

    match endpoint {
        PhpFpmEndpoint::Tcp(address) => {
            let stream =
                tokio::time::timeout(connect_timeout, tokio::net::TcpStream::connect(address))
                    .await
                    .map_err(|_| php_fpm_timeout_error(PhpFpmTimeoutKind::Connect))??;
            execute_php_fpm_stream(stream, params, body, timeout, max_response_bytes).await
        }
        #[cfg(unix)]
        PhpFpmEndpoint::Unix(socket) => {
            let stream =
                tokio::time::timeout(connect_timeout, tokio::net::UnixStream::connect(socket))
                    .await
                    .map_err(|_| php_fpm_timeout_error(PhpFpmTimeoutKind::Connect))??;
            execute_php_fpm_stream(stream, params, body, timeout, max_response_bytes).await
        }
    }
}

pub(crate) fn php_fpm_retryable_response(fpm: &PhpFpmConfig, status: StatusCode) -> bool {
    php_fpm_retryable_status(fpm, status.as_u16())
}

async fn execute_php_fpm_stream<S>(
    stream: S,
    params: fastcgi_client::Params<'_>,
    body: &PhpRequestBody,
    timeout: Duration,
    max_response_bytes: u64,
) -> io::Result<fastcgi_client::Response>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let client = fastcgi_client::Client::new_tokio(stream);
    let request = fastcgi_client::Request::new(params, body.reader().await?);
    let stream = tokio::time::timeout(timeout, client.execute_once_stream(request))
        .await
        .map_err(|_| php_fpm_timeout_error(PhpFpmTimeoutKind::Request))?
        .map_err(|error| io::Error::other(error.to_string()))?;
    collect_php_fpm_response_stream(stream, max_response_bytes).await
}

pub(crate) fn parse_php_response(
    stdout: &[u8],
    max_response_bytes: u64,
    max_response_header_bytes: u64,
) -> io::Result<(ResponseHeader, Vec<u8>)> {
    let parsed = fluxheim_php_fpm::parse_php_response(
        stdout,
        max_response_bytes,
        max_response_header_bytes,
    )?;
    let mut response = php_response_header(parsed.status).map_err(FluxError::into_io)?;
    for (name, value) in parsed.headers {
        response
            .append_header(name, value)
            .map_err(|error| io::Error::other(error.to_string()))?;
    }

    Ok((response, parsed.body))
}

pub fn fuzz_parse_php_response(stdout: &[u8]) -> io::Result<()> {
    let _ = parse_php_response(stdout, 1024 * 1024, 64 * 1024)?;
    Ok(())
}

pub(crate) fn php_response_header(status: u16) -> FluxResult<ResponseHeader> {
    ResponseHeader::build(status, Some(8))
        .map_err(|error| FluxError::invalid_input(error.to_string()))
}
