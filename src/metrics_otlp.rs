use std::time::Duration;

use fluxheim_observability::{OtlpHttpEndpoint, build_metrics_payload};

use crate::config::MetricsOtlpExportConfig;

pub fn spawn_from_config(config: &MetricsOtlpExportConfig) -> std::io::Result<()> {
    if !config.enabled {
        return Ok(());
    }

    let endpoint = OtlpHttpEndpoint::parse(&config.endpoint).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid OTLP metrics endpoint",
        )
    })?;
    let service_name = config.service_name.clone();
    let interval = Duration::from_secs(config.interval_secs);
    let timeout = Duration::from_secs(config.timeout_secs);
    let agent = crate::otlp_http::agent(timeout, config.tls_ca_cert_path.as_deref())?;

    std::thread::Builder::new()
        .name("Fluxheim OTLP Metrics".to_owned())
        .spawn(move || {
            loop {
                std::thread::sleep(interval);
                let payload = build_metrics_payload(prometheus::gather(), &service_name);
                match post_otlp_metrics(&agent, &endpoint, payload) {
                    Ok(()) => crate::metrics::record_metrics_otlp_export("success"),
                    Err(error) => {
                        crate::metrics::record_metrics_otlp_export("failure");
                        log::debug!("OTLP metrics export failed: {error}");
                    }
                }
            }
        })
        .map(|_| ())
        .map_err(|error| {
            std::io::Error::new(
                error.kind(),
                format!("failed to spawn OTLP metrics exporter: {error}"),
            )
        })
}

fn post_otlp_metrics(
    agent: &ureq::Agent,
    endpoint: &OtlpHttpEndpoint,
    body: String,
) -> std::io::Result<()> {
    let response = agent
        .post(&endpoint.url)
        .header("content-type", "application/json")
        .send(body.as_str())
        .map_err(otlp_metrics_io_error)?;
    let status = response.status().as_u16();
    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err(std::io::Error::other(format!(
            "OTLP metrics endpoint returned HTTP {status}"
        )))
    }
}

fn otlp_metrics_io_error(error: ureq::Error) -> std::io::Error {
    std::io::Error::other(error.to_string())
}
