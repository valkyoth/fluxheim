use std::sync::OnceLock;

use prometheus::{HistogramOpts, HistogramVec, IntCounterVec, IntGaugeVec, Opts};

static PHP_REQUESTS_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();
static PHP_REQUEST_DURATION_SECONDS: OnceLock<HistogramVec> = OnceLock::new();
static PHP_STDERR_EVENTS_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();
static PHP_FPM_RETRIES_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();
static PHP_FPM_POOL_IDLE_CONNECTIONS: OnceLock<IntGaugeVec> = OnceLock::new();
static PHP_FPM_POOL_EVENTS_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();
static METRICS_OTLP_EXPORTS_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();
pub(in crate::metrics) fn php_requests_total() -> Result<&'static IntCounterVec, prometheus::Error>
{
    if let Some(counter) = PHP_REQUESTS_TOTAL.get() {
        return Ok(counter);
    }

    let counter = IntCounterVec::new(
        Opts::new(
            "fluxheim_php_requests_total",
            "Total Fluxheim PHP handler requests by virtual host, method bucket, bounded outcome, and status class.",
        ),
        &["vhost", "method", "outcome", "status_class"],
    )?;
    match prometheus::default_registry().register(Box::new(counter.clone())) {
        Ok(()) => {}
        Err(prometheus::Error::AlreadyReg) => {}
        Err(error) => return Err(error),
    }

    let _ = PHP_REQUESTS_TOTAL.set(counter);
    PHP_REQUESTS_TOTAL.get().ok_or_else(|| {
        prometheus::Error::Msg("PHP request counter failed to initialize".to_owned())
    })
}

pub(in crate::metrics) fn php_request_duration_seconds()
-> Result<&'static HistogramVec, prometheus::Error> {
    if let Some(histogram) = PHP_REQUEST_DURATION_SECONDS.get() {
        return Ok(histogram);
    }

    let histogram = HistogramVec::new(
        HistogramOpts::new(
            "fluxheim_php_request_duration_seconds",
            "Fluxheim PHP handler request duration by virtual host, method bucket, bounded outcome, and status class.",
        )
        .buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]),
        &["vhost", "method", "outcome", "status_class"],
    )?;
    match prometheus::default_registry().register(Box::new(histogram.clone())) {
        Ok(()) => {}
        Err(prometheus::Error::AlreadyReg) => {}
        Err(error) => return Err(error),
    }

    let _ = PHP_REQUEST_DURATION_SECONDS.set(histogram);
    PHP_REQUEST_DURATION_SECONDS.get().ok_or_else(|| {
        prometheus::Error::Msg("PHP request duration histogram failed to initialize".to_owned())
    })
}

pub(in crate::metrics) fn php_stderr_events_total()
-> Result<&'static IntCounterVec, prometheus::Error> {
    if let Some(counter) = PHP_STDERR_EVENTS_TOTAL.get() {
        return Ok(counter);
    }

    let counter = IntCounterVec::new(
        Opts::new(
            "fluxheim_php_stderr_events_total",
            "Total Fluxheim PHP FastCGI STDERR events by virtual host and bounded state.",
        ),
        &["vhost", "state"],
    )?;
    match prometheus::default_registry().register(Box::new(counter.clone())) {
        Ok(()) => {}
        Err(prometheus::Error::AlreadyReg) => {}
        Err(error) => return Err(error),
    }

    let _ = PHP_STDERR_EVENTS_TOTAL.set(counter);
    PHP_STDERR_EVENTS_TOTAL
        .get()
        .ok_or_else(|| prometheus::Error::Msg("PHP STDERR counter failed to initialize".to_owned()))
}
pub(in crate::metrics) fn php_fpm_retries_total()
-> Result<&'static IntCounterVec, prometheus::Error> {
    if let Some(counter) = PHP_FPM_RETRIES_TOTAL.get() {
        return Ok(counter);
    }

    let counter = IntCounterVec::new(
        Opts::new(
            "fluxheim_php_fpm_retries_total",
            "Total Fluxheim php-fpm retry attempts by virtual host and bounded reason.",
        ),
        &["vhost", "reason"],
    )?;
    match prometheus::default_registry().register(Box::new(counter.clone())) {
        Ok(()) => {}
        Err(prometheus::Error::AlreadyReg) => {}
        Err(error) => return Err(error),
    }

    let _ = PHP_FPM_RETRIES_TOTAL.set(counter);
    PHP_FPM_RETRIES_TOTAL.get().ok_or_else(|| {
        prometheus::Error::Msg("PHP FPM retry counter failed to initialize".to_owned())
    })
}

pub(in crate::metrics) fn php_fpm_pool_idle_connections()
-> Result<&'static IntGaugeVec, prometheus::Error> {
    if let Some(gauge) = PHP_FPM_POOL_IDLE_CONNECTIONS.get() {
        return Ok(gauge);
    }

    let gauge = IntGaugeVec::new(
        Opts::new(
            "fluxheim_php_fpm_pool_idle_connections",
            "Current idle php-fpm keepalive connections by virtual host and configured pool.",
        ),
        &["vhost", "pool"],
    )?;
    match prometheus::default_registry().register(Box::new(gauge.clone())) {
        Ok(()) => {}
        Err(prometheus::Error::AlreadyReg) => {}
        Err(error) => return Err(error),
    }

    let _ = PHP_FPM_POOL_IDLE_CONNECTIONS.set(gauge);
    PHP_FPM_POOL_IDLE_CONNECTIONS.get().ok_or_else(|| {
        prometheus::Error::Msg("PHP FPM pool idle gauge failed to initialize".to_owned())
    })
}

pub(in crate::metrics) fn php_fpm_pool_events_total()
-> Result<&'static IntCounterVec, prometheus::Error> {
    if let Some(counter) = PHP_FPM_POOL_EVENTS_TOTAL.get() {
        return Ok(counter);
    }

    let counter = IntCounterVec::new(
        Opts::new(
            "fluxheim_php_fpm_pool_events_total",
            "Total Fluxheim php-fpm keepalive pool events by virtual host, configured pool, and bounded event.",
        ),
        &["vhost", "pool", "event"],
    )?;
    match prometheus::default_registry().register(Box::new(counter.clone())) {
        Ok(()) => {}
        Err(prometheus::Error::AlreadyReg) => {}
        Err(error) => return Err(error),
    }

    let _ = PHP_FPM_POOL_EVENTS_TOTAL.set(counter);
    PHP_FPM_POOL_EVENTS_TOTAL.get().ok_or_else(|| {
        prometheus::Error::Msg("PHP FPM pool event counter failed to initialize".to_owned())
    })
}
pub(in crate::metrics) fn metrics_otlp_exports_total()
-> Result<&'static IntCounterVec, prometheus::Error> {
    if let Some(counter) = METRICS_OTLP_EXPORTS_TOTAL.get() {
        return Ok(counter);
    }

    let counter = IntCounterVec::new(
        Opts::new(
            "fluxheim_metrics_otlp_exports_total",
            "Fluxheim OTLP metrics exporter attempts by bounded outcome.",
        ),
        &["outcome"],
    )?;
    match prometheus::default_registry().register(Box::new(counter.clone())) {
        Ok(()) => {}
        Err(prometheus::Error::AlreadyReg) => {}
        Err(error) => return Err(error),
    }

    let _ = METRICS_OTLP_EXPORTS_TOTAL.set(counter);
    METRICS_OTLP_EXPORTS_TOTAL.get().ok_or_else(|| {
        prometheus::Error::Msg(
            "fluxheim_metrics_otlp_exports_total failed to initialize".to_owned(),
        )
    })
}
