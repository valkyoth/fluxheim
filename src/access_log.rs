#[cfg(not(feature = "privacy-mode"))]
use crate::http_types::PingoraRequestHeader as RequestHeader;
use bytes::Bytes;

#[cfg(not(feature = "privacy-mode"))]
use crate::config::AccessLoggingConfig;
use fluxheim_observability::count_access_log_response_body_bytes;
#[cfg(not(feature = "privacy-mode"))]
use fluxheim_observability::json_escape;
#[cfg(feature = "otel-otlp")]
pub(crate) use fluxheim_observability::unix_time_nanos;
#[cfg(not(feature = "privacy-mode"))]
use fluxheim_observability::{access_log_request_id_valid, generate_access_log_request_id};

#[cfg(not(feature = "privacy-mode"))]
pub(crate) struct AccessLogEvent<'a> {
    pub(crate) method: &'a str,
    pub(crate) host: Option<&'a str>,
    pub(crate) client_ip: Option<String>,
    #[cfg(feature = "geoip")]
    pub(crate) geo_country: Option<&'a str>,
    #[cfg(feature = "geoip")]
    pub(crate) geo_asn: Option<u32>,
    #[cfg(feature = "cache")]
    pub(crate) cache_phase: Option<&'static str>,
    #[cfg(any(
        feature = "compression-brotli",
        feature = "compression-gzip",
        feature = "compression-zstd"
    ))]
    pub(crate) compression_encoding: Option<&'static str>,
    pub(crate) tls_version: Option<&'a str>,
    pub(crate) tls_cipher: Option<&'a str>,
    pub(crate) tls_client_cert_sha256: Option<&'a str>,
    pub(crate) tls_client_cert_serial: Option<&'a str>,
    pub(crate) tls_client_cert_organization: Option<&'a str>,
    pub(crate) vhost: &'a str,
    pub(crate) route: &'a str,
    pub(crate) upstream: Option<&'a str>,
    pub(crate) upstream_alias: Option<&'a str>,
    pub(crate) upstream_retries: u8,
    pub(crate) path: Option<&'a str>,
    pub(crate) status: Option<u16>,
    pub(crate) status_class: Option<&'static str>,
    pub(crate) error: bool,
    pub(crate) request_id: Option<&'a str>,
    #[cfg(feature = "otel-tracing")]
    pub(crate) trace_id: Option<String>,
    pub(crate) request_body_bytes: u64,
    pub(crate) response_body_bytes: u64,
    pub(crate) latency_ms: u128,
}

#[cfg(not(feature = "privacy-mode"))]
pub(crate) fn access_log_json(event: AccessLogEvent<'_>) -> String {
    let status = event
        .status
        .map(|status| status.to_string())
        .unwrap_or_else(|| "null".to_owned());
    let status_class = event.status_class.unwrap_or("unknown");
    let host = event.host.unwrap_or("");
    let client_ip = event.client_ip.as_deref().unwrap_or("");
    #[cfg(feature = "geoip")]
    let geo_country = event.geo_country.unwrap_or("");
    #[cfg(feature = "geoip")]
    let geo_asn = event
        .geo_asn
        .map(|asn| asn.to_string())
        .unwrap_or_else(|| "null".to_owned());
    #[cfg(feature = "cache")]
    let cache_phase = event.cache_phase.unwrap_or("");
    #[cfg(not(feature = "cache"))]
    let cache_phase = "";
    #[cfg(any(
        feature = "compression-brotli",
        feature = "compression-gzip",
        feature = "compression-zstd"
    ))]
    let compression_encoding = event.compression_encoding.unwrap_or("");
    #[cfg(not(any(
        feature = "compression-brotli",
        feature = "compression-gzip",
        feature = "compression-zstd"
    )))]
    let compression_encoding = "";
    let tls_version = event.tls_version.unwrap_or("");
    let tls_cipher = event.tls_cipher.unwrap_or("");
    let tls_client_cert_sha256 = event.tls_client_cert_sha256.unwrap_or("");
    let tls_client_cert_serial = event.tls_client_cert_serial.unwrap_or("");
    let tls_client_cert_organization = event.tls_client_cert_organization.unwrap_or("");
    let upstream = event.upstream.unwrap_or("");
    let upstream_alias = event.upstream_alias.unwrap_or("");
    let path = event.path.unwrap_or("");
    let request_id = event.request_id.unwrap_or("");
    let body = format!(
        "{{\"event\":\"access\",\"method\":\"{}\",\"host\":\"{}\",\"client_ip\":\"{}\",\"cache_phase\":\"{}\",\"compression_encoding\":\"{}\",\"tls_version\":\"{}\",\"tls_cipher\":\"{}\",\"tls_client_cert_sha256\":\"{}\",\"tls_client_cert_serial\":\"{}\",\"tls_client_cert_organization\":\"{}\",\"vhost\":\"{}\",\"route\":\"{}\",\"upstream\":\"{}\",\"upstream_alias\":\"{}\",\"upstream_retries\":{},\"path\":\"{}\",\"status\":{},\"status_class\":\"{}\",\"error\":{},\"request_id\":\"{}\",\"request_body_bytes\":{},\"response_body_bytes\":{},\"latency_ms\":{}}}",
        json_escape(event.method),
        json_escape(host),
        json_escape(client_ip),
        json_escape(cache_phase),
        json_escape(compression_encoding),
        json_escape(tls_version),
        json_escape(tls_cipher),
        json_escape(tls_client_cert_sha256),
        json_escape(tls_client_cert_serial),
        json_escape(tls_client_cert_organization),
        json_escape(event.vhost),
        json_escape(event.route),
        json_escape(upstream),
        json_escape(upstream_alias),
        event.upstream_retries,
        json_escape(path),
        status,
        status_class,
        event.error,
        json_escape(request_id),
        event.request_body_bytes,
        event.response_body_bytes,
        event.latency_ms,
    );
    #[cfg(feature = "otel-tracing")]
    {
        let mut body = body;
        #[cfg(feature = "geoip")]
        {
            let insert_at = body.len().saturating_sub(1);
            body.insert_str(
                insert_at,
                &format!(
                    r#","geo_country":"{}","geo_asn":{}"#,
                    json_escape(geo_country),
                    geo_asn
                ),
            );
        }
        if let Some(trace_id) = event.trace_id.as_deref() {
            let insert_at = body.len().saturating_sub(1);
            body.insert_str(
                insert_at,
                &format!(r#","trace_id":"{}""#, json_escape(trace_id)),
            );
        }
        body
    }
    #[cfg(not(feature = "otel-tracing"))]
    {
        #[cfg(feature = "geoip")]
        {
            let mut body = body;
            let insert_at = body.len().saturating_sub(1);
            body.insert_str(
                insert_at,
                &format!(
                    r#","geo_country":"{}","geo_asn":{}"#,
                    json_escape(geo_country),
                    geo_asn
                ),
            );
            body
        }
        #[cfg(not(feature = "geoip"))]
        {
            body
        }
    }
}

#[cfg(not(feature = "privacy-mode"))]
pub(crate) fn status_class(status: u16) -> &'static str {
    fluxheim_observability::access_log_status_class(status)
}

#[cfg(not(feature = "privacy-mode"))]
pub(crate) fn access_log_request_id(
    config: &AccessLoggingConfig,
    request: &RequestHeader,
) -> Option<String> {
    if !config.enabled || !config.request_id {
        return None;
    }

    request
        .headers
        .get(config.request_id_header.as_str())
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| access_log_request_id_valid(value))
        .map(str::to_owned)
        .or_else(generate_access_log_request_id)
}

pub(crate) fn count_response_body_chunk(bytes_seen: &mut u64, body: Option<&Bytes>) {
    if let Some(body) = body {
        count_access_log_response_body_bytes(bytes_seen, body.len());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(feature = "privacy-mode"))]
    #[test]
    fn access_log_json_escapes_values_and_omits_query_when_given_path() {
        let log = access_log_json(AccessLogEvent {
            method: "GET",
            host: Some("example.test"),
            client_ip: Some("203.0.113.10".to_owned()),
            #[cfg(feature = "geoip")]
            geo_country: Some("SE"),
            #[cfg(feature = "geoip")]
            geo_asn: Some(12552),
            #[cfg(feature = "cache")]
            cache_phase: Some("hit"),
            #[cfg(any(
                feature = "compression-brotli",
                feature = "compression-gzip",
                feature = "compression-zstd"
            ))]
            compression_encoding: Some("gzip"),
            tls_version: Some("TLSv1.3"),
            tls_cipher: Some("TLS_AES_128_GCM_SHA256"),
            tls_client_cert_sha256: Some("aabbcc"),
            tls_client_cert_serial: Some("01AB"),
            tls_client_cert_organization: Some("Fluxheim Test"),
            vhost: "main\"site",
            route: "assets",
            upstream: Some("127.0.0.1:3000"),
            upstream_alias: Some("origin-a"),
            upstream_retries: 2,
            path: Some("/asset path/one.js"),
            status: Some(200),
            status_class: Some(status_class(200)),
            error: false,
            request_id: Some("req-123"),
            #[cfg(feature = "otel-tracing")]
            trace_id: None,
            request_body_bytes: 42,
            response_body_bytes: 2048,
            latency_ms: 7,
        });

        assert!(log.contains("\"event\":\"access\""));
        assert!(log.contains("\"host\":\"example.test\""));
        assert!(log.contains("\"client_ip\":\"203.0.113.10\""));
        #[cfg(feature = "geoip")]
        {
            assert!(log.contains("\"geo_country\":\"SE\""));
            assert!(log.contains("\"geo_asn\":12552"));
        }
        #[cfg(feature = "cache")]
        assert!(log.contains("\"cache_phase\":\"hit\""));
        #[cfg(any(
            feature = "compression-brotli",
            feature = "compression-gzip",
            feature = "compression-zstd"
        ))]
        assert!(log.contains("\"compression_encoding\":\"gzip\""));
        assert!(log.contains("\"tls_version\":\"TLSv1.3\""));
        assert!(log.contains("\"tls_cipher\":\"TLS_AES_128_GCM_SHA256\""));
        assert!(log.contains("\"tls_client_cert_sha256\":\"aabbcc\""));
        assert!(log.contains("\"tls_client_cert_serial\":\"01AB\""));
        assert!(log.contains("\"tls_client_cert_organization\":\"Fluxheim Test\""));
        assert!(log.contains("\"vhost\":\"main\\\"site\""));
        assert!(log.contains("\"route\":\"assets\""));
        assert!(log.contains("\"upstream\":\"127.0.0.1:3000\""));
        assert!(log.contains("\"upstream_alias\":\"origin-a\""));
        assert!(log.contains("\"upstream_retries\":2"));
        assert!(log.contains("\"path\":\"/asset path/one.js\""));
        assert!(log.contains("\"status_class\":\"2xx\""));
        assert!(log.contains("\"request_id\":\"req-123\""));
        assert!(log.contains("\"response_body_bytes\":2048"));
        assert!(!log.contains("secret="));
    }

    #[cfg(not(feature = "privacy-mode"))]
    #[test]
    fn access_log_json_can_omit_path() {
        let log = access_log_json(AccessLogEvent {
            method: "GET",
            host: Some("example.test"),
            client_ip: None,
            #[cfg(feature = "geoip")]
            geo_country: None,
            #[cfg(feature = "geoip")]
            geo_asn: None,
            #[cfg(feature = "cache")]
            cache_phase: None,
            #[cfg(any(
                feature = "compression-brotli",
                feature = "compression-gzip",
                feature = "compression-zstd"
            ))]
            compression_encoding: None,
            tls_version: None,
            tls_cipher: None,
            tls_client_cert_sha256: None,
            tls_client_cert_serial: None,
            tls_client_cert_organization: None,
            vhost: "main",
            route: "private",
            upstream: None,
            upstream_alias: None,
            upstream_retries: 0,
            path: None,
            status: Some(204),
            status_class: Some(status_class(204)),
            error: false,
            request_id: None,
            #[cfg(feature = "otel-tracing")]
            trace_id: None,
            request_body_bytes: 0,
            response_body_bytes: 0,
            latency_ms: 1,
        });

        assert!(log.contains("\"path\":\"\""));
        assert!(log.contains("\"upstream_alias\":\"\""));
        assert!(log.contains("\"upstream_retries\":0"));
        assert!(log.contains("\"cache_phase\":\"\""));
        assert!(log.contains("\"compression_encoding\":\"\""));
        assert!(log.contains("\"tls_client_cert_sha256\":\"\""));
        assert!(!log.contains("/private"));
    }

    #[cfg(not(feature = "privacy-mode"))]
    #[test]
    fn access_log_json_can_omit_host() {
        let log = access_log_json(AccessLogEvent {
            method: "GET",
            host: None,
            client_ip: None,
            #[cfg(feature = "geoip")]
            geo_country: None,
            #[cfg(feature = "geoip")]
            geo_asn: None,
            #[cfg(feature = "cache")]
            cache_phase: None,
            #[cfg(any(
                feature = "compression-brotli",
                feature = "compression-gzip",
                feature = "compression-zstd"
            ))]
            compression_encoding: None,
            tls_version: None,
            tls_cipher: None,
            tls_client_cert_sha256: None,
            tls_client_cert_serial: None,
            tls_client_cert_organization: None,
            vhost: "main",
            route: "root",
            upstream: None,
            upstream_alias: None,
            upstream_retries: 0,
            path: Some("/"),
            status: Some(204),
            status_class: Some(status_class(204)),
            error: false,
            request_id: None,
            #[cfg(feature = "otel-tracing")]
            trace_id: None,
            request_body_bytes: 0,
            response_body_bytes: 0,
            latency_ms: 1,
        });

        assert!(log.contains("\"host\":\"\""));
        assert!(!log.contains("tenant.example"));
    }

    #[cfg(all(not(feature = "privacy-mode"), feature = "otel-tracing"))]
    #[test]
    fn access_log_json_can_include_trace_id() {
        let log = access_log_json(AccessLogEvent {
            method: "GET",
            host: Some("example.test"),
            client_ip: None,
            #[cfg(feature = "geoip")]
            geo_country: None,
            #[cfg(feature = "geoip")]
            geo_asn: None,
            #[cfg(feature = "cache")]
            cache_phase: None,
            #[cfg(any(
                feature = "compression-brotli",
                feature = "compression-gzip",
                feature = "compression-zstd"
            ))]
            compression_encoding: None,
            tls_version: None,
            tls_cipher: None,
            tls_client_cert_sha256: None,
            tls_client_cert_serial: None,
            tls_client_cert_organization: None,
            vhost: "main",
            route: "root",
            upstream: None,
            upstream_alias: None,
            upstream_retries: 0,
            path: Some("/"),
            status: Some(200),
            status_class: Some(status_class(200)),
            error: false,
            request_id: None,
            trace_id: Some("4bf92f3577b34da6a3ce929d0e0e4736".to_owned()),
            request_body_bytes: 0,
            response_body_bytes: 0,
            latency_ms: 1,
        });

        assert!(log.contains(r#""trace_id":"4bf92f3577b34da6a3ce929d0e0e4736""#));
    }

    #[cfg(not(feature = "privacy-mode"))]
    #[test]
    fn access_log_status_class_is_low_cardinality() {
        assert_eq!(status_class(101), "1xx");
        assert_eq!(status_class(204), "2xx");
        assert_eq!(status_class(304), "3xx");
        assert_eq!(status_class(404), "4xx");
        assert_eq!(status_class(503), "5xx");
        assert_eq!(status_class(700), "other");
    }

    #[test]
    fn response_body_chunks_are_counted_for_access_logs() {
        let mut seen = 0;

        count_response_body_chunk(&mut seen, Some(&Bytes::from_static(b"hello")));
        count_response_body_chunk(&mut seen, None);
        count_response_body_chunk(&mut seen, Some(&Bytes::from_static(b" world")));

        assert_eq!(seen, 11);
    }

    #[test]
    fn response_body_byte_counter_saturates() {
        let mut seen = u64::MAX - 1;

        count_response_body_chunk(&mut seen, Some(&Bytes::from_static(b"abcd")));

        assert_eq!(seen, u64::MAX);
    }

    #[cfg(not(feature = "privacy-mode"))]
    #[test]
    fn access_log_request_id_reuses_valid_inbound_value() {
        let mut request = RequestHeader::build("GET", b"/", None).unwrap();
        request
            .insert_header("x-request-id", "edge-req-123")
            .unwrap();

        assert_eq!(
            access_log_request_id(&crate::config::AccessLoggingConfig::default(), &request)
                .as_deref(),
            Some("edge-req-123")
        );
    }

    #[cfg(not(feature = "privacy-mode"))]
    #[test]
    fn access_log_request_id_generates_for_missing_or_invalid_value() {
        let missing = RequestHeader::build("GET", b"/", None).unwrap();
        let generated =
            access_log_request_id(&crate::config::AccessLoggingConfig::default(), &missing)
                .unwrap();
        assert!(generated.starts_with("fh-"));

        let mut invalid = RequestHeader::build("GET", b"/", None).unwrap();
        invalid.insert_header("x-request-id", "bad value").unwrap();
        let regenerated =
            access_log_request_id(&crate::config::AccessLoggingConfig::default(), &invalid)
                .unwrap();
        assert!(regenerated.starts_with("fh-"));
        assert_ne!(regenerated, "bad value");

        let mut url_like = RequestHeader::build("GET", b"/", None).unwrap();
        url_like
            .insert_header("x-request-id", "https://evil.example/reset")
            .unwrap();
        let regenerated =
            access_log_request_id(&crate::config::AccessLoggingConfig::default(), &url_like)
                .unwrap();
        assert!(regenerated.starts_with("fh-"));

        let mut email_like = RequestHeader::build("GET", b"/", None).unwrap();
        email_like
            .insert_header("x-request-id", "admin@example.test")
            .unwrap();
        let regenerated =
            access_log_request_id(&crate::config::AccessLoggingConfig::default(), &email_like)
                .unwrap();
        assert!(regenerated.starts_with("fh-"));
    }
}
