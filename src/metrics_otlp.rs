use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use prometheus::proto::MetricType;
use serde_json::json;

use crate::config::MetricsOtlpExportConfig;

pub fn spawn_from_config(config: &MetricsOtlpExportConfig) -> std::io::Result<()> {
    if !config.enabled {
        return Ok(());
    }

    let endpoint = HttpEndpoint::parse(&config.endpoint).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid OTLP metrics endpoint",
        )
    })?;
    let service_name = config.service_name.clone();
    let interval = Duration::from_secs(config.interval_secs);
    let timeout = Duration::from_secs(config.timeout_secs);

    std::thread::Builder::new()
        .name("Fluxheim OTLP Metrics".to_owned())
        .spawn(move || {
            loop {
                std::thread::sleep(interval);
                let payload = build_metrics_payload(prometheus::gather(), &service_name);
                if let Err(error) = post_otlp_metrics(&endpoint, timeout, payload) {
                    log::debug!("OTLP metrics export failed: {error}");
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

#[derive(Debug, Clone, Eq, PartialEq)]
struct HttpEndpoint {
    host: String,
    port: u16,
    path: String,
    authority: String,
}

impl HttpEndpoint {
    fn parse(endpoint: &str) -> Option<Self> {
        let rest = endpoint.strip_prefix("http://")?;
        let (authority, path) = rest.split_once('/')?;
        if authority.is_empty() || path.is_empty() {
            return None;
        }
        let (host, port) = parse_authority(authority)?;
        Some(Self {
            host,
            port,
            path: format!("/{path}"),
            authority: authority.to_owned(),
        })
    }
}

fn parse_authority(authority: &str) -> Option<(String, u16)> {
    if let Some(stripped) = authority.strip_prefix('[') {
        let (host, tail) = stripped.split_once(']')?;
        if host.is_empty() {
            return None;
        }
        let port = if tail.is_empty() {
            80
        } else {
            tail.strip_prefix(':')?.parse::<u16>().ok()?
        };
        return (port != 0).then(|| (host.to_owned(), port));
    }

    let Some((host, port)) = authority.rsplit_once(':') else {
        return Some((authority.to_owned(), 80));
    };
    if host.is_empty() {
        return None;
    }
    let port = port.parse::<u16>().ok()?;
    (port != 0).then(|| (host.to_owned(), port))
}

fn build_metrics_payload(
    families: Vec<prometheus::proto::MetricFamily>,
    service_name: &str,
) -> String {
    let time_unix_nanos = unix_time_nanos().to_string();
    let mut metrics = Vec::new();

    for family in families {
        match family.get_field_type() {
            MetricType::COUNTER => {
                let mut data_points = Vec::new();
                for metric in family.get_metric() {
                    data_points.push(number_data_point(
                        metric,
                        metric.get_counter().get_value(),
                        &time_unix_nanos,
                    ));
                }
                metrics.push(json!({
                    "name": family.get_name(),
                    "description": family.get_help(),
                    "unit": "1",
                    "sum": {
                        "aggregationTemporality": "AGGREGATION_TEMPORALITY_CUMULATIVE",
                        "isMonotonic": true,
                        "dataPoints": data_points,
                    }
                }));
            }
            MetricType::GAUGE => {
                let mut data_points = Vec::new();
                for metric in family.get_metric() {
                    data_points.push(number_data_point(
                        metric,
                        metric.get_gauge().get_value(),
                        &time_unix_nanos,
                    ));
                }
                metrics.push(json!({
                    "name": family.get_name(),
                    "description": family.get_help(),
                    "unit": "1",
                    "gauge": {
                        "dataPoints": data_points,
                    }
                }));
            }
            _ => {}
        }
    }

    json!({
        "resourceMetrics": [{
            "resource": {
                "attributes": [
                    string_attr("service.name", service_name),
                    string_attr("service.version", env!("CARGO_PKG_VERSION")),
                ]
            },
            "scopeMetrics": [{
                "scope": {
                    "name": "fluxheim",
                    "version": env!("CARGO_PKG_VERSION")
                },
                "metrics": metrics
            }]
        }]
    })
    .to_string()
}

fn number_data_point(
    metric: &prometheus::proto::Metric,
    value: f64,
    time_unix_nanos: &str,
) -> serde_json::Value {
    json!({
        "attributes": metric
            .get_label()
            .iter()
            .map(|label| string_attr(label.get_name(), label.get_value()))
            .collect::<Vec<_>>(),
        "timeUnixNano": time_unix_nanos,
        "asDouble": value,
    })
}

fn string_attr(key: &str, value: impl Into<String>) -> serde_json::Value {
    json!({
        "key": key,
        "value": {
            "stringValue": value.into()
        }
    })
}

fn post_otlp_metrics(
    endpoint: &HttpEndpoint,
    timeout: Duration,
    body: String,
) -> std::io::Result<()> {
    let mut stream = TcpStream::connect((endpoint.host.as_str(), endpoint.port))?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    write!(
        stream,
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        endpoint.path,
        endpoint.authority,
        body.len(),
        body
    )?;
    stream.flush()?;

    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    let Some(status_line) = response.lines().next() else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "empty OTLP metrics response",
        ));
    };
    if status_line.contains(" 2") {
        Ok(())
    } else {
        Err(std::io::Error::other(format!(
            "OTLP metrics endpoint returned {status_line}"
        )))
    }
}

fn unix_time_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use prometheus::{CounterVec, Encoder, Gauge, Opts};

    use super::*;

    #[test]
    fn parses_prometheus_otlp_endpoint() {
        let endpoint = HttpEndpoint::parse("http://127.0.0.1:9090/api/v1/otlp/v1/metrics").unwrap();

        assert_eq!(endpoint.host, "127.0.0.1");
        assert_eq!(endpoint.port, 9090);
        assert_eq!(endpoint.path, "/api/v1/otlp/v1/metrics");
    }

    #[test]
    fn payload_contains_counter_and_gauge_metrics() {
        let registry = prometheus::Registry::new();
        let counter = CounterVec::new(
            Opts::new("fluxheim_test_counter_total", "test counter"),
            &["vhost"],
        )
        .unwrap();
        counter.with_label_values(&["example"]).inc();
        registry.register(Box::new(counter)).unwrap();

        let gauge = Gauge::new("fluxheim_test_gauge", "test gauge").unwrap();
        gauge.set(7.0);
        registry.register(Box::new(gauge)).unwrap();

        let payload = build_metrics_payload(registry.gather(), "fluxheim-test");

        assert!(payload.contains(r#""resourceMetrics""#));
        assert!(payload.contains(r#""service.name""#));
        assert!(payload.contains(r#""fluxheim-test""#));
        assert!(payload.contains(r#""name":"fluxheim_test_counter_total""#));
        assert!(payload.contains(r#""sum""#));
        assert!(payload.contains(r#""name":"fluxheim_test_gauge""#));
        assert!(payload.contains(r#""gauge""#));
        assert!(!payload.contains("query"));
        assert!(!payload.contains("path"));

        let mut text = Vec::new();
        prometheus::TextEncoder::new()
            .encode(&registry.gather(), &mut text)
            .unwrap();
        assert!(
            String::from_utf8(text)
                .unwrap()
                .contains("fluxheim_test_counter_total")
        );
    }
}
