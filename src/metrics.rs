use std::sync::OnceLock;

use prometheus::{IntCounterVec, Opts};

static PROXY_REQUESTS_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();

pub fn enabled() -> bool {
    true
}

pub fn init() -> Result<(), prometheus::Error> {
    proxy_requests_total().map(|_| ())
}

pub fn record_proxy_outcome(vhost: &str, method: &str, status: Option<u16>, error: bool) {
    match proxy_requests_total() {
        Ok(counter) => counter
            .with_label_values(&[
                vhost,
                method_bucket(method),
                outcome_class(status, error),
                status_class(status),
            ])
            .inc(),
        Err(error) => log::debug!("metrics counter unavailable: {error}"),
    }
}

fn proxy_requests_total() -> Result<&'static IntCounterVec, prometheus::Error> {
    if let Some(counter) = PROXY_REQUESTS_TOTAL.get() {
        return Ok(counter);
    }

    let counter = IntCounterVec::new(
        Opts::new(
            "fluxheim_proxy_requests_total",
            "Total Fluxheim proxy requests by virtual host, method bucket, outcome class, and status class.",
        ),
        &["vhost", "method", "class", "status_class"],
    )?;
    match prometheus::default_registry().register(Box::new(counter.clone())) {
        Ok(()) => {}
        Err(prometheus::Error::AlreadyReg) => {}
        Err(error) => return Err(error),
    }

    let _ = PROXY_REQUESTS_TOTAL.set(counter);
    PROXY_REQUESTS_TOTAL
        .get()
        .ok_or_else(|| prometheus::Error::Msg("metrics counter failed to initialize".to_owned()))
}

fn outcome_class(status: Option<u16>, error: bool) -> &'static str {
    if error {
        return "proxy_error";
    }

    match status {
        Some(100..=199) => "informational",
        Some(200..=299) => "success",
        Some(300..=399) => "redirect",
        Some(400..=499) => "client_error",
        Some(500..=599) => "server_error",
        Some(_) => "other",
        None => "unknown",
    }
}

fn method_bucket(method: &str) -> &'static str {
    match method {
        "GET" => "GET",
        "HEAD" => "HEAD",
        "POST" => "POST",
        "PUT" => "PUT",
        "PATCH" => "PATCH",
        "DELETE" => "DELETE",
        "OPTIONS" => "OPTIONS",
        "TRACE" => "TRACE",
        "CONNECT" => "CONNECT",
        _ => "OTHER",
    }
}

fn status_class(status: Option<u16>) -> &'static str {
    match status {
        Some(100..=199) => "1xx",
        Some(200..=299) => "2xx",
        Some(300..=399) => "3xx",
        Some(400..=499) => "4xx",
        Some(500..=599) => "5xx",
        Some(_) => "other",
        None => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use prometheus::Encoder;

    use super::{init, method_bucket, record_proxy_outcome, status_class};

    #[test]
    fn records_proxy_outcome_counter() {
        init().unwrap();

        record_proxy_outcome("metrics-test", "GET", Some(502), false);

        let metric_families = prometheus::gather();
        let mut output = Vec::new();
        prometheus::TextEncoder::new()
            .encode(&metric_families, &mut output)
            .unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("fluxheim_proxy_requests_total"));
        assert!(output.contains(r#"vhost="metrics-test""#));
        assert!(output.contains(r#"method="GET""#));
        assert!(output.contains(r#"class="server_error""#));
        assert!(output.contains(r#"status_class="5xx""#));
        assert!(!output.contains(r#"status="502""#));
    }

    #[test]
    fn status_class_is_bounded() {
        assert_eq!(status_class(Some(101)), "1xx");
        assert_eq!(status_class(Some(204)), "2xx");
        assert_eq!(status_class(Some(304)), "3xx");
        assert_eq!(status_class(Some(404)), "4xx");
        assert_eq!(status_class(Some(503)), "5xx");
        assert_eq!(status_class(Some(799)), "other");
        assert_eq!(status_class(None), "unknown");
    }

    #[test]
    fn method_bucket_is_bounded() {
        assert_eq!(method_bucket("GET"), "GET");
        assert_eq!(method_bucket("POST"), "POST");
        assert_eq!(method_bucket("PROPFIND"), "OTHER");
        assert_eq!(method_bucket("attacker-controlled-method"), "OTHER");
    }
}
