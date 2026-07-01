use std::io;
use std::sync::Arc;
use std::time::Duration;

use fluxheim_common::FluxError;
use fluxheim_config::{LoadBalanceHealthCheckProtocol, ProxyConfig};

use super::backend::FluxHealthCheck;
#[cfg(test)]
use super::backend::RuntimeBackend as Backend;
#[cfg(test)]
use super::key::backend_key;
use super::policy::HealthDerivedWeights;

mod database;
mod exec;
mod grpc;
mod http;
mod http1;
mod transport;

#[cfg(test)]
use self::database::{
    POSTGRES_HEALTH_CHECK_SSL_REQUEST, REDIS_HEALTH_CHECK_REQUEST, validate_mysql_health_handshake,
    validate_postgres_health_response, validate_redis_health_response,
};
use self::database::{
    configured_mysql_health_check, configured_postgres_health_check, configured_redis_health_check,
};
use self::exec::configured_exec_health_check;
#[cfg(test)]
use self::grpc::execute_grpc_health_check;
#[cfg(test)]
use self::grpc::grpc_frame;
#[cfg(test)]
use self::grpc::{
    grpc_health_request_body, validate_grpc_health_response_body,
    validate_grpc_health_response_header,
};
use self::http::configured_http_health_check;
use self::http::{
    HTTP_HEALTH_CHECK_MAX_BODY_BYTES, HTTP_HEALTH_CHECK_MAX_HEADER_BYTES, HealthErrorKind,
    HealthHttpRequest, HealthHttpResponse, HttpHealthCheckError,
};
#[cfg(test)]
use self::http::{
    record_health_weight, validate_http_health_response, validate_http_health_response_body,
    validate_http_health_response_body_json,
};
use self::transport::BoxedHealthIo;
use self::transport::{FluxTcpHealthCheck, HealthTlsAlpn, configured_tcp_health_check_tls};

pub(super) fn configured_health_check(
    config: &ProxyConfig,
    health_weights: Arc<HealthDerivedWeights>,
) -> io::Result<Box<dyn FluxHealthCheck>> {
    #[cfg(test)]
    crate::install_test_crypto_provider();

    match config.load_balance.health_check.protocol {
        LoadBalanceHealthCheckProtocol::Tcp => {
            let consecutive_success = config.load_balance.health_check.consecutive_success;
            let consecutive_failure = config.load_balance.health_check.consecutive_failure;
            let connect_timeout = Duration::from_secs(
                config
                    .load_balance
                    .health_check
                    .connect_timeout_secs
                    .or(config.connect_timeout_secs)
                    .unwrap_or(1),
            );
            let tls = configured_tcp_health_check_tls(config, HealthTlsAlpn::None)
                .map_err(FluxError::into_io)?;
            Ok(Box::new(FluxTcpHealthCheck {
                consecutive_success,
                consecutive_failure,
                connect_timeout,
                tls,
            }))
        }
        LoadBalanceHealthCheckProtocol::Http | LoadBalanceHealthCheckProtocol::Grpc => {
            configured_http_health_check(config, health_weights)
                .map_err(FluxError::into_io)
                .map(|check| check as Box<dyn FluxHealthCheck>)
        }
        LoadBalanceHealthCheckProtocol::Exec => configured_exec_health_check(config)
            .map_err(FluxError::into_io)
            .map(|check| check as Box<dyn FluxHealthCheck>),
        LoadBalanceHealthCheckProtocol::Redis => configured_redis_health_check(config)
            .map_err(FluxError::into_io)
            .map(|check| check as Box<dyn FluxHealthCheck>),
        LoadBalanceHealthCheckProtocol::Mysql => configured_mysql_health_check(config)
            .map_err(FluxError::into_io)
            .map(|check| check as Box<dyn FluxHealthCheck>),
        LoadBalanceHealthCheckProtocol::Postgres => configured_postgres_health_check(config)
            .map_err(FluxError::into_io)
            .map(|check| check as Box<dyn FluxHealthCheck>),
    }
}

#[cfg(test)]
mod tests;
