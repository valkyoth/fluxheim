use async_trait::async_trait;
use fluxheim_common::FluxResult;

use crate::backend::{FluxHealthCheck, RuntimeBackend as Backend};
use crate::health::grpc::{
    execute_grpc_health_check, validate_grpc_health_response_body,
    validate_grpc_health_response_header,
};
use crate::health::http1::execute_http1_health_check;
use crate::health::reuse_connection::{Connection, failure};
use crate::health::transport::connect_health_stream;
use crate::key::backend_key;

use super::{
    FluxHttpHealthCheck, HttpHealthCheckError, record_health_weight, validate_http_health_response,
    validate_http_health_response_body, validate_http_health_response_body_json,
};

#[async_trait]
impl FluxHealthCheck for FluxHttpHealthCheck {
    fn update_backends(&self, backends: &std::collections::BTreeSet<Backend>) {
        if let Some(pool) = &self.pool {
            pool.members(backends);
        }
    }

    fn close_connections(&self) {
        if let Some(pool) = &self.pool {
            pool.clear();
        }
    }

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
        let mut lease = self
            .pool
            .as_ref()
            .map(|pool| pool.reserve(target.addr))
            .transpose()?;
        let (response, body) = if let Some(lease) = &mut lease {
            let mut cancellation = lease.cancellation();
            let exchange = async {
                if lease.connection.is_none() {
                    let stream = connect_health_stream(
                        address,
                        self.upstream_tls,
                        self.tls.as_ref(),
                        self.connection_timeout,
                    )
                    .await?;
                    lease.connection = Some(Connection::new(stream, self.req.grpc).await?);
                }
                let connection = lease
                    .connection
                    .as_mut()
                    .ok_or_else(|| failure("health connection unavailable"))?;
                tokio::time::timeout(
                    self.read_timeout,
                    connection.exchange(&self.req, self.upstream_tls, self.read_timeout),
                )
                .await
                .map_err(|_| failure("health response deadline exceeded"))?
            };
            let deadline = self
                .connection_timeout
                .saturating_mul(2)
                .saturating_add(self.read_timeout);
            tokio::select! {
                biased;
                _ = cancellation.wait_for(|cancelled| *cancelled) => return Err(failure("health connection invalidated")),
                result = tokio::time::timeout(deadline, exchange) => result.map_err(|_| failure("health probe deadline exceeded"))??,
            }
        } else {
            let stream = connect_health_stream(
                address,
                self.upstream_tls,
                self.tls.as_ref(),
                self.connection_timeout,
            )
            .await?;
            if self.req.grpc {
                execute_grpc_health_check(stream, &self.req, self.read_timeout).await?
            } else {
                execute_http1_health_check(stream, &self.req, self.read_timeout).await?
            }
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
        } else {
            validate_http_health_response_body(&body, &self.expected_body_contains)
                .map_err(HttpHealthCheckError::into_flux)?;
            validate_http_health_response_body_json(&body, &self.expected_body_json)
                .map_err(HttpHealthCheckError::into_flux)?;
        }
        if let Some(lease) = lease {
            lease.release();
        }
        Ok(())
    }
}
