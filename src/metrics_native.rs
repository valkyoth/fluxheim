use std::error::Error;
use std::fmt;
#[cfg(feature = "proxy")]
use std::process;
#[cfg(feature = "proxy")]
use std::sync::Arc;

#[cfg(feature = "proxy")]
use crate::background::{FluxBackgroundReady, FluxBackgroundTask, FluxShutdown};
use fluxheim_server::NativeHttp1Response;
use prometheus::Encoder;
use sanitization::{SecretString, SecretVec, ct::ConstantTimeEq};
use sha2::{Digest, Sha256};
#[cfg(feature = "proxy")]
use tokio::net::TcpListener;

use crate::metrics::prometheus_text;
use crate::metrics_secret::load_native_metrics_token;

pub fn native_prometheus_response() -> Result<NativeHttp1Response, prometheus::Error> {
    Ok(NativeHttp1Response::new(200, "OK", prometheus_text()?)
        .with_header("content-type", prometheus::TextEncoder::new().format_type()))
}

fn native_prometheus_head_response() -> Result<NativeHttp1Response, prometheus::Error> {
    let body = prometheus_text()?;
    Ok(NativeHttp1Response::new(200, "OK", Vec::new())
        .with_content_length(body.len() as u64)
        .with_header("content-type", prometheus::TextEncoder::new().format_type()))
}

fn native_metrics_target_allowed(target: &str) -> bool {
    let path = native_metrics_target_path(target);
    path.split_once('?').map_or(path, |(path, _)| path) == "/metrics"
}

fn native_metrics_target_path(target: &str) -> &str {
    if let Some(rest) = target
        .strip_prefix("http://")
        .or_else(|| target.strip_prefix("https://"))
    {
        return rest.find('/').map_or("/", |index| &rest[index..]);
    }
    target
}

#[derive(Default)]
pub struct NativeMetricsApp {
    bearer_token: Option<SecretString>,
}

impl fmt::Debug for NativeMetricsApp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeMetricsApp")
            .field("bearer_token_configured", &self.bearer_token.is_some())
            .finish()
    }
}

impl NativeMetricsApp {
    pub const fn new() -> Self {
        Self { bearer_token: None }
    }

    pub fn with_bearer_token(mut self, token: impl Into<String>) -> Self {
        self.bearer_token = Some(SecretString::from_string(token.into()));
        self
    }
}

pub(crate) fn native_metrics_app_from_config(
    config: &crate::config::MetricsConfig,
) -> Result<NativeMetricsApp, Box<dyn Error + Send + Sync>> {
    let Some(token) = load_native_metrics_token(config)? else {
        return Ok(NativeMetricsApp::new());
    };
    Ok(NativeMetricsApp {
        bearer_token: Some(token),
    })
}

#[cfg(feature = "proxy")]
pub(crate) fn metrics_background_service_from_config(
    config: &crate::config::MetricsConfig,
) -> Result<
    Option<crate::background::FluxBackgroundService<NativeMetricsTask>>,
    Box<dyn Error + Send + Sync>,
> {
    if !config.enabled {
        return Ok(None);
    }
    let app = native_metrics_app_from_config(config)?;
    Ok(Some(crate::background::FluxBackgroundService::new(
        "Fluxheim metrics HTTP",
        NativeMetricsTask {
            listen: config.listen.clone(),
            app: Arc::new(app),
        },
    )))
}

#[cfg(feature = "proxy")]
pub(crate) struct NativeMetricsTask {
    listen: String,
    app: Arc<NativeMetricsApp>,
}

#[cfg(feature = "proxy")]
#[async_trait::async_trait]
impl FluxBackgroundTask for NativeMetricsTask {
    async fn start(&self, mut shutdown: FluxShutdown, mut ready: FluxBackgroundReady) {
        let listener = match TcpListener::bind(&self.listen).await {
            Ok(listener) => listener,
            Err(error) => {
                log::error!(
                    target: "fluxheim::metrics",
                    "failed to bind native metrics listener {}: {error}",
                    self.listen
                );
                process::exit(1);
            }
        };
        ready.notify_ready();
        if let Err(error) = fluxheim_server::serve_native_http1_listener(
            listener,
            fluxheim_server::DownstreamHttp1Policy::default(),
            self.app.clone(),
            async move {
                let _ = shutdown.wait_for_shutdown().await;
            },
        )
        .await
        {
            log::error!(
                target: "fluxheim::metrics",
                "native metrics listener {} stopped unexpectedly: {error}",
                self.listen
            );
            process::exit(1);
        }
    }
}

fn native_metrics_authorized(
    request: &fluxheim_server::NativeHttp1Request,
    token: &SecretString,
) -> bool {
    request.headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("authorization")
            && native_metrics_bearer_token_matches(value, token)
    })
}

fn native_metrics_bearer_token_matches(value: &str, token: &SecretString) -> bool {
    let Some(candidate) = value.trim().strip_prefix("Bearer ") else {
        return false;
    };
    let candidate = SecretVec::from_slice(candidate.as_bytes());
    let candidate_digest = candidate.with_secret(metrics_bearer_token_digest);
    let token_digest = token.with_secret_bytes(metrics_bearer_token_digest);
    candidate_digest
        .ct_eq(&token_digest)
        .declassify("native metrics bearer-token comparison result is public")
}

fn metrics_bearer_token_digest(token: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update((token.len() as u64).to_le_bytes());
    hasher.update(token);
    hasher.finalize().into()
}

impl fluxheim_server::NativeHttp1Handler for NativeMetricsApp {
    fn handle<'a>(
        &'a self,
        request: fluxheim_server::NativeHttp1Request,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = fluxheim_server::NativeHttp1Response> + Send + 'a>,
    > {
        Box::pin(async move {
            if !native_metrics_target_allowed(&request.target) {
                return fluxheim_server::NativeHttp1Response::new(404, "Not Found", b"not found\n")
                    .close_connection();
            }
            if let Some(token) = &self.bearer_token
                && !native_metrics_authorized(&request, token)
            {
                return fluxheim_server::NativeHttp1Response::new(
                    401,
                    "Unauthorized",
                    b"unauthorized\n",
                )
                .with_header("www-authenticate", "Bearer realm=\"metrics\"")
                .close_connection();
            }
            let response = match request.method.as_str() {
                "GET" => native_prometheus_response(),
                "HEAD" => native_prometheus_head_response(),
                _ => {
                    return fluxheim_server::NativeHttp1Response::new(
                        405,
                        "Method Not Allowed",
                        b"method not allowed\n",
                    )
                    .with_header("allow", "GET, HEAD")
                    .close_connection();
                }
            };
            response.unwrap_or_else(|error| {
                log::debug!("native metrics response unavailable: {error}");
                fluxheim_server::NativeHttp1Response::new(
                    500,
                    "Internal Server Error",
                    b"metrics unavailable\n",
                )
                .close_connection()
            })
        })
    }
}
