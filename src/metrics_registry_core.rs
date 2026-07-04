use std::sync::OnceLock;

use prometheus::{HistogramOpts, HistogramVec, IntCounterVec, IntGaugeVec, Opts};

static PROXY_REQUESTS_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();
static HOST_ROUTING_REJECTIONS_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();
static EDGE_POLICY_EVENTS_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();
static LOAD_BALANCER_EVENTS_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();
static LOAD_BALANCER_QUEUE_WAIT_SECONDS: OnceLock<HistogramVec> = OnceLock::new();
static LOAD_BALANCER_POOLS: OnceLock<IntGaugeVec> = OnceLock::new();
static RESPONSE_COMPRESSIONS_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();
static STREAM_CONNECTIONS_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();
static STREAM_BYTES_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();
static UDP_DATAGRAMS_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();
static UDP_DROPS_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();
static UDP_ACTIVE_SESSIONS: OnceLock<IntGaugeVec> = OnceLock::new();
static ADMIN_AUTH_EVENTS_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();
static ACME_EVENTS_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();
static WASM_PLUGIN_EXECUTIONS_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();
static WASM_PLUGIN_EXECUTION_SECONDS: OnceLock<HistogramVec> = OnceLock::new();
static WASM_PLUGIN_ADMISSION_REJECTIONS_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();
pub(in crate::metrics) fn proxy_requests_total() -> Result<&'static IntCounterVec, prometheus::Error>
{
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

pub(in crate::metrics) fn host_routing_rejections_total()
-> Result<&'static IntCounterVec, prometheus::Error> {
    if let Some(counter) = HOST_ROUTING_REJECTIONS_TOTAL.get() {
        return Ok(counter);
    }

    let counter = IntCounterVec::new(
        Opts::new(
            "fluxheim_host_routing_rejections_total",
            "Total Fluxheim strict host-routing rejections by reason.",
        ),
        &["reason"],
    )?;
    match prometheus::default_registry().register(Box::new(counter.clone())) {
        Ok(()) => {}
        Err(prometheus::Error::AlreadyReg) => {}
        Err(error) => return Err(error),
    }

    let _ = HOST_ROUTING_REJECTIONS_TOTAL.set(counter);
    HOST_ROUTING_REJECTIONS_TOTAL.get().ok_or_else(|| {
        prometheus::Error::Msg("host routing counter failed to initialize".to_owned())
    })
}

pub(in crate::metrics) fn edge_policy_events_total()
-> Result<&'static IntCounterVec, prometheus::Error> {
    if let Some(counter) = EDGE_POLICY_EVENTS_TOTAL.get() {
        return Ok(counter);
    }

    let counter = IntCounterVec::new(
        Opts::new(
            "fluxheim_edge_policy_events_total",
            "Total Fluxheim edge policy enforcement events by configured vhost, optional route, bounded policy, and bounded outcome.",
        ),
        &["scope", "vhost", "route", "policy", "outcome"],
    )?;
    match prometheus::default_registry().register(Box::new(counter.clone())) {
        Ok(()) => {}
        Err(prometheus::Error::AlreadyReg) => {}
        Err(error) => return Err(error),
    }

    let _ = EDGE_POLICY_EVENTS_TOTAL.set(counter);
    EDGE_POLICY_EVENTS_TOTAL.get().ok_or_else(|| {
        prometheus::Error::Msg("fluxheim_edge_policy_events_total failed to initialize".to_owned())
    })
}

pub(in crate::metrics) fn load_balancer_events_total()
-> Result<&'static IntCounterVec, prometheus::Error> {
    if let Some(counter) = LOAD_BALANCER_EVENTS_TOTAL.get() {
        return Ok(counter);
    }

    let counter = IntCounterVec::new(
        Opts::new(
            "fluxheim_load_balancer_events_total",
            "Total Fluxheim load-balancer events by configured vhost, optional route, optional upstream alias, and bounded event.",
        ),
        &["scope", "vhost", "route", "upstream", "event"],
    )?;
    match prometheus::default_registry().register(Box::new(counter.clone())) {
        Ok(()) => {}
        Err(prometheus::Error::AlreadyReg) => {}
        Err(error) => return Err(error),
    }

    let _ = LOAD_BALANCER_EVENTS_TOTAL.set(counter);
    LOAD_BALANCER_EVENTS_TOTAL.get().ok_or_else(|| {
        prometheus::Error::Msg(
            "fluxheim_load_balancer_events_total failed to initialize".to_owned(),
        )
    })
}

pub(in crate::metrics) fn load_balancer_queue_wait_seconds()
-> Result<&'static HistogramVec, prometheus::Error> {
    if let Some(histogram) = LOAD_BALANCER_QUEUE_WAIT_SECONDS.get() {
        return Ok(histogram);
    }

    let histogram = HistogramVec::new(
        HistogramOpts::new(
            "fluxheim_load_balancer_queue_wait_seconds",
            "Fluxheim load-balancer queue wait duration by configured vhost, optional route, and bounded queue outcome.",
        )
        .buckets(vec![
            0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0,
            60.0,
        ]),
        &["scope", "vhost", "route", "outcome"],
    )?;
    match prometheus::default_registry().register(Box::new(histogram.clone())) {
        Ok(()) => {}
        Err(prometheus::Error::AlreadyReg) => {}
        Err(error) => return Err(error),
    }

    let _ = LOAD_BALANCER_QUEUE_WAIT_SECONDS.set(histogram);
    LOAD_BALANCER_QUEUE_WAIT_SECONDS.get().ok_or_else(|| {
        prometheus::Error::Msg(
            "fluxheim_load_balancer_queue_wait_seconds failed to initialize".to_owned(),
        )
    })
}

pub(in crate::metrics) fn load_balancer_pools() -> Result<&'static IntGaugeVec, prometheus::Error> {
    if let Some(gauge) = LOAD_BALANCER_POOLS.get() {
        return Ok(gauge);
    }

    let gauge = IntGaugeVec::new(
        Opts::new(
            "fluxheim_load_balancer_pools",
            "Configured Fluxheim load-balancer pools by scope and bounded selection algorithm.",
        ),
        &["scope", "selection"],
    )?;
    match prometheus::default_registry().register(Box::new(gauge.clone())) {
        Ok(()) => {}
        Err(prometheus::Error::AlreadyReg) => {}
        Err(error) => return Err(error),
    }

    let _ = LOAD_BALANCER_POOLS.set(gauge);
    LOAD_BALANCER_POOLS.get().ok_or_else(|| {
        prometheus::Error::Msg("fluxheim_load_balancer_pools failed to initialize".to_owned())
    })
}

pub(in crate::metrics) fn response_compressions_total()
-> Result<&'static IntCounterVec, prometheus::Error> {
    if let Some(counter) = RESPONSE_COMPRESSIONS_TOTAL.get() {
        return Ok(counter);
    }

    let counter = IntCounterVec::new(
        Opts::new(
            "fluxheim_response_compressions_total",
            "Total Fluxheim-applied response compressions by configured vhost, optional route, and bounded encoding.",
        ),
        &["scope", "vhost", "route", "encoding"],
    )?;
    match prometheus::default_registry().register(Box::new(counter.clone())) {
        Ok(()) => {}
        Err(prometheus::Error::AlreadyReg) => {}
        Err(error) => return Err(error),
    }

    let _ = RESPONSE_COMPRESSIONS_TOTAL.set(counter);
    RESPONSE_COMPRESSIONS_TOTAL.get().ok_or_else(|| {
        prometheus::Error::Msg(
            "fluxheim_response_compressions_total failed to initialize".to_owned(),
        )
    })
}

pub(in crate::metrics) fn stream_connections_total()
-> Result<&'static IntCounterVec, prometheus::Error> {
    if let Some(counter) = STREAM_CONNECTIONS_TOTAL.get() {
        return Ok(counter);
    }

    let counter = IntCounterVec::new(
        Opts::new(
            "fluxheim_stream_connections_total",
            "Total Fluxheim TCP stream proxy connections by configured stream route and bounded outcome.",
        ),
        &["route", "outcome"],
    )?;
    match prometheus::default_registry().register(Box::new(counter.clone())) {
        Ok(()) => {}
        Err(prometheus::Error::AlreadyReg) => {}
        Err(error) => return Err(error),
    }

    let _ = STREAM_CONNECTIONS_TOTAL.set(counter);
    STREAM_CONNECTIONS_TOTAL.get().ok_or_else(|| {
        prometheus::Error::Msg("fluxheim_stream_connections_total failed to initialize".to_owned())
    })
}

pub(in crate::metrics) fn stream_bytes_total() -> Result<&'static IntCounterVec, prometheus::Error>
{
    if let Some(counter) = STREAM_BYTES_TOTAL.get() {
        return Ok(counter);
    }

    let counter = IntCounterVec::new(
        Opts::new(
            "fluxheim_stream_bytes_total",
            "Total Fluxheim TCP stream proxy bytes by configured stream route and bounded direction.",
        ),
        &["route", "direction"],
    )?;
    match prometheus::default_registry().register(Box::new(counter.clone())) {
        Ok(()) => {}
        Err(prometheus::Error::AlreadyReg) => {}
        Err(error) => return Err(error),
    }

    let _ = STREAM_BYTES_TOTAL.set(counter);
    STREAM_BYTES_TOTAL.get().ok_or_else(|| {
        prometheus::Error::Msg("fluxheim_stream_bytes_total failed to initialize".to_owned())
    })
}

pub(in crate::metrics) fn udp_datagrams_total() -> Result<&'static IntCounterVec, prometheus::Error>
{
    if let Some(counter) = UDP_DATAGRAMS_TOTAL.get() {
        return Ok(counter);
    }

    let counter = IntCounterVec::new(
        Opts::new(
            "fluxheim_udp_datagrams_total",
            "Total Fluxheim UDP datagrams by configured route, bounded mode, direction, and bounded outcome.",
        ),
        &["route", "mode", "direction", "outcome"],
    )?;
    match prometheus::default_registry().register(Box::new(counter.clone())) {
        Ok(()) => {}
        Err(prometheus::Error::AlreadyReg) => {}
        Err(error) => return Err(error),
    }

    let _ = UDP_DATAGRAMS_TOTAL.set(counter);
    UDP_DATAGRAMS_TOTAL.get().ok_or_else(|| {
        prometheus::Error::Msg("fluxheim_udp_datagrams_total failed to initialize".to_owned())
    })
}

pub(in crate::metrics) fn udp_drops_total() -> Result<&'static IntCounterVec, prometheus::Error> {
    if let Some(counter) = UDP_DROPS_TOTAL.get() {
        return Ok(counter);
    }

    let counter = IntCounterVec::new(
        Opts::new(
            "fluxheim_udp_drops_total",
            "Total Fluxheim UDP datagram drops by configured route and bounded reason.",
        ),
        &["route", "reason"],
    )?;
    match prometheus::default_registry().register(Box::new(counter.clone())) {
        Ok(()) => {}
        Err(prometheus::Error::AlreadyReg) => {}
        Err(error) => return Err(error),
    }

    let _ = UDP_DROPS_TOTAL.set(counter);
    UDP_DROPS_TOTAL.get().ok_or_else(|| {
        prometheus::Error::Msg("fluxheim_udp_drops_total failed to initialize".to_owned())
    })
}

pub(in crate::metrics) fn udp_active_sessions() -> Result<&'static IntGaugeVec, prometheus::Error> {
    if let Some(gauge) = UDP_ACTIVE_SESSIONS.get() {
        return Ok(gauge);
    }

    let gauge = IntGaugeVec::new(
        Opts::new(
            "fluxheim_udp_active_sessions",
            "Current Fluxheim UDP active datagram sessions by configured route.",
        ),
        &["route"],
    )?;
    match prometheus::default_registry().register(Box::new(gauge.clone())) {
        Ok(()) => {}
        Err(prometheus::Error::AlreadyReg) => {}
        Err(error) => return Err(error),
    }

    let _ = UDP_ACTIVE_SESSIONS.set(gauge);
    UDP_ACTIVE_SESSIONS.get().ok_or_else(|| {
        prometheus::Error::Msg("fluxheim_udp_active_sessions failed to initialize".to_owned())
    })
}

pub(in crate::metrics) fn admin_auth_events_total()
-> Result<&'static IntCounterVec, prometheus::Error> {
    if let Some(counter) = ADMIN_AUTH_EVENTS_TOTAL.get() {
        return Ok(counter);
    }

    let counter = IntCounterVec::new(
        Opts::new(
            "fluxheim_admin_auth_events_total",
            "Total Fluxheim admin authentication security events by event and throttle scope.",
        ),
        &["event", "scope"],
    )?;
    match prometheus::default_registry().register(Box::new(counter.clone())) {
        Ok(()) => {}
        Err(prometheus::Error::AlreadyReg) => {}
        Err(error) => return Err(error),
    }

    let _ = ADMIN_AUTH_EVENTS_TOTAL.set(counter);
    ADMIN_AUTH_EVENTS_TOTAL.get().ok_or_else(|| {
        prometheus::Error::Msg("admin auth event counter failed to initialize".to_owned())
    })
}

pub(in crate::metrics) fn acme_events_total() -> Result<&'static IntCounterVec, prometheus::Error> {
    if let Some(counter) = ACME_EVENTS_TOTAL.get() {
        return Ok(counter);
    }

    let counter = IntCounterVec::new(
        Opts::new(
            "fluxheim_acme_events_total",
            "Total Fluxheim managed-ACME lifecycle events by bounded event.",
        ),
        &["event"],
    )?;
    match prometheus::default_registry().register(Box::new(counter.clone())) {
        Ok(()) => {}
        Err(prometheus::Error::AlreadyReg) => {}
        Err(error) => return Err(error),
    }

    let _ = ACME_EVENTS_TOTAL.set(counter);
    ACME_EVENTS_TOTAL
        .get()
        .ok_or_else(|| prometheus::Error::Msg("ACME event counter failed to initialize".to_owned()))
}

pub(in crate::metrics) fn wasm_plugin_executions_total()
-> Result<&'static IntCounterVec, prometheus::Error> {
    if let Some(counter) = WASM_PLUGIN_EXECUTIONS_TOTAL.get() {
        return Ok(counter);
    }

    let counter = IntCounterVec::new(
        Opts::new(
            "fluxheim_wasm_plugin_executions_total",
            "Total Fluxheim Wasm plugin executions by bounded plugin name, phase, and outcome.",
        ),
        &["plugin", "phase", "outcome"],
    )?;
    match prometheus::default_registry().register(Box::new(counter.clone())) {
        Ok(()) => {}
        Err(prometheus::Error::AlreadyReg) => {}
        Err(error) => return Err(error),
    }

    let _ = WASM_PLUGIN_EXECUTIONS_TOTAL.set(counter);
    WASM_PLUGIN_EXECUTIONS_TOTAL.get().ok_or_else(|| {
        prometheus::Error::Msg(
            "fluxheim_wasm_plugin_executions_total failed to initialize".to_owned(),
        )
    })
}

pub(in crate::metrics) fn wasm_plugin_execution_seconds()
-> Result<&'static HistogramVec, prometheus::Error> {
    if let Some(histogram) = WASM_PLUGIN_EXECUTION_SECONDS.get() {
        return Ok(histogram);
    }

    let histogram = HistogramVec::new(
        HistogramOpts::new(
            "fluxheim_wasm_plugin_execution_seconds",
            "Fluxheim Wasm plugin execution duration by bounded plugin name, phase, and outcome.",
        )
        .buckets(vec![
            0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0,
        ]),
        &["plugin", "phase", "outcome"],
    )?;
    match prometheus::default_registry().register(Box::new(histogram.clone())) {
        Ok(()) => {}
        Err(prometheus::Error::AlreadyReg) => {}
        Err(error) => return Err(error),
    }

    let _ = WASM_PLUGIN_EXECUTION_SECONDS.set(histogram);
    WASM_PLUGIN_EXECUTION_SECONDS.get().ok_or_else(|| {
        prometheus::Error::Msg(
            "fluxheim_wasm_plugin_execution_seconds failed to initialize".to_owned(),
        )
    })
}

pub(in crate::metrics) fn wasm_plugin_admission_rejections_total()
-> Result<&'static IntCounterVec, prometheus::Error> {
    if let Some(counter) = WASM_PLUGIN_ADMISSION_REJECTIONS_TOTAL.get() {
        return Ok(counter);
    }

    let counter = IntCounterVec::new(
        Opts::new(
            "fluxheim_wasm_plugin_admission_rejections_total",
            "Total Fluxheim Wasm plugin admission rejections by bounded plugin name, phase, and admission scope.",
        ),
        &["plugin", "phase", "scope"],
    )?;
    match prometheus::default_registry().register(Box::new(counter.clone())) {
        Ok(()) => {}
        Err(prometheus::Error::AlreadyReg) => {}
        Err(error) => return Err(error),
    }

    let _ = WASM_PLUGIN_ADMISSION_REJECTIONS_TOTAL.set(counter);
    WASM_PLUGIN_ADMISSION_REJECTIONS_TOTAL.get().ok_or_else(|| {
        prometheus::Error::Msg(
            "fluxheim_wasm_plugin_admission_rejections_total failed to initialize".to_owned(),
        )
    })
}
