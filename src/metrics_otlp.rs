use std::time::Duration;

use fluxheim_observability::{OtlpHttpEndpoint, agent, build_metrics_payload};

use crate::config::MetricsOtlpExportConfig;

pub struct MetricsOtlpExporter {
    endpoint: OtlpHttpEndpoint,
    service_name: String,
    interval: Duration,
    agent: ureq::Agent,
}

impl MetricsOtlpExporter {
    pub fn from_config(config: &MetricsOtlpExportConfig) -> std::io::Result<Option<Self>> {
        if !config.enabled {
            return Ok(None);
        }

        let endpoint = parse_endpoint(config)?;
        let service_name = config.service_name.clone();
        let interval = Duration::from_secs(config.interval_secs);
        let timeout = Duration::from_secs(config.timeout_secs);
        let agent = agent(timeout, config.tls_ca_cert_path.as_deref())?;

        Ok(Some(Self {
            endpoint,
            service_name,
            interval,
            agent,
        }))
    }

    pub fn interval(&self) -> Duration {
        self.interval
    }

    pub fn export_once(&self) {
        let payload = build_metrics_payload(prometheus::gather(), &self.service_name);
        match post_otlp_metrics(&self.agent, &self.endpoint, payload) {
            Ok(()) => crate::metrics::record_metrics_otlp_export("success"),
            Err(error) => {
                crate::metrics::record_metrics_otlp_export("failure");
                log::debug!("OTLP metrics export failed: {error}");
            }
        }
    }
}

fn parse_endpoint(config: &MetricsOtlpExportConfig) -> std::io::Result<OtlpHttpEndpoint> {
    let endpoint = OtlpHttpEndpoint::parse(&config.endpoint).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid OTLP metrics endpoint",
        )
    })?;
    Ok(endpoint)
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

#[cfg(test)]
mod tests {
    use super::MetricsOtlpExporter;
    use crate::config::MetricsOtlpExportConfig;

    #[test]
    fn exporter_is_absent_when_disabled() {
        let config = MetricsOtlpExportConfig {
            enabled: false,
            ..MetricsOtlpExportConfig::default()
        };

        assert!(MetricsOtlpExporter::from_config(&config).unwrap().is_none());
    }

    #[test]
    fn exporter_rejects_invalid_endpoint() {
        let config = MetricsOtlpExportConfig {
            enabled: true,
            endpoint: "file:///tmp/metrics".to_owned(),
            ..MetricsOtlpExportConfig::default()
        };

        assert!(MetricsOtlpExporter::from_config(&config).is_err());
    }
}
