use std::time::Duration;

use fluxheim_observability::{
    ExportOptions, ExportOutcome, ExportSignal, ExportWorker, build_metrics_payload,
};

use crate::config::MetricsOtlpExportConfig;

pub struct MetricsOtlpExporter {
    worker: ExportWorker,
    service_name: String,
    interval: Duration,
}

impl MetricsOtlpExporter {
    pub fn from_config(config: &MetricsOtlpExportConfig) -> std::io::Result<Option<Self>> {
        if !config.enabled {
            return Ok(None);
        }

        if !(1..=3600).contains(&config.interval_secs)
            || config.service_name.is_empty()
            || config.service_name.len() > 128
            || !config
                .service_name
                .bytes()
                .all(|b| b.is_ascii_graphic() || b == b' ')
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid OTLP metrics policy",
            ));
        }
        let service_name = config.service_name.clone();
        let interval = Duration::from_secs(config.interval_secs);
        let timeout = Duration::from_secs(config.timeout_secs);
        let worker = ExportWorker::new(ExportOptions {
            endpoint: &config.endpoint,
            ca: config.tls_ca_cert_path.as_deref(),
            token: config.bearer_token_file.as_deref(),
            signal: ExportSignal::Metrics,
            queue_size: 1,
            timeout,
            on_complete: Some(record_outcome),
        })?;

        Ok(Some(Self {
            worker,
            service_name,
            interval,
        }))
    }

    pub fn interval(&self) -> Duration {
        self.interval
    }

    pub fn export_once(&self) {
        match build_metrics_payload(prometheus::gather(), &self.service_name) {
            Some(payload) => {
                self.worker.try_export(payload);
            }
            None => self.worker.record_drop(),
        }
    }
    pub fn shutdown(&self) {
        self.worker.shutdown();
    }
}

fn record_outcome(outcome: ExportOutcome) {
    crate::metrics::record_metrics_otlp_export(if outcome == ExportOutcome::Success {
        "success"
    } else {
        "failure"
    });
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
