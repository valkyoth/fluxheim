use std::sync::OnceLock;

use prometheus::{IntCounterVec, Opts};

static PROXY_REQUESTS_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();

pub fn enabled() -> bool {
    true
}

pub fn init() -> Result<(), prometheus::Error> {
    proxy_requests_total().map(|_| ())
}

pub fn record_proxy_outcome(vhost: &str, status: Option<u16>, error: bool) {
    let status_label = status
        .map(|status| status.to_string())
        .unwrap_or_else(|| "none".to_owned());
    proxy_requests_total()
        .expect("Fluxheim metrics registry must initialize")
        .with_label_values(&[vhost, outcome_class(status, error), status_label.as_str()])
        .inc();
}

fn proxy_requests_total() -> Result<&'static IntCounterVec, prometheus::Error> {
    if let Some(counter) = PROXY_REQUESTS_TOTAL.get() {
        return Ok(counter);
    }

    let counter = IntCounterVec::new(
        Opts::new(
            "fluxheim_proxy_requests_total",
            "Total Fluxheim proxy requests by virtual host, outcome class, and status.",
        ),
        &["vhost", "class", "status"],
    )?;
    match prometheus::default_registry().register(Box::new(counter.clone())) {
        Ok(()) => {}
        Err(prometheus::Error::AlreadyReg) => {}
        Err(error) => return Err(error),
    }

    let _ = PROXY_REQUESTS_TOTAL.set(counter);
    Ok(PROXY_REQUESTS_TOTAL
        .get()
        .expect("metrics counter is initialized"))
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

#[cfg(test)]
mod tests {
    use prometheus::Encoder;

    use super::{init, record_proxy_outcome};

    #[test]
    fn records_proxy_outcome_counter() {
        init().unwrap();

        record_proxy_outcome("metrics-test", Some(502), false);

        let metric_families = prometheus::gather();
        let mut output = Vec::new();
        prometheus::TextEncoder::new()
            .encode(&metric_families, &mut output)
            .unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("fluxheim_proxy_requests_total"));
        assert!(output.contains(r#"vhost="metrics-test""#));
        assert!(output.contains(r#"class="server_error""#));
        assert!(output.contains(r#"status="502""#));
    }
}
