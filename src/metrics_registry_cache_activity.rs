use std::sync::OnceLock;

use prometheus::{HistogramOpts, HistogramVec, IntCounterVec, Opts};

static CACHE_ACTIVITY_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();
static CACHE_ACTIVITY_SCOPE_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();
static CACHE_OPERATION_DURATION_SECONDS: OnceLock<HistogramVec> = OnceLock::new();
static CACHE_PURGES_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();
static CACHE_PURGER_RUNS_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();
static CACHE_PURGER_ENTRIES_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();
static CACHE_PURGER_DURATION_SECONDS: OnceLock<HistogramVec> = OnceLock::new();
pub(in crate::metrics) fn cache_activity_total() -> Result<&'static IntCounterVec, prometheus::Error>
{
    if let Some(counter) = CACHE_ACTIVITY_TOTAL.get() {
        return Ok(counter);
    }

    let counter = IntCounterVec::new(
        Opts::new(
            "fluxheim_cache_activity_total",
            "Fluxheim cache activity events by storage tier and bounded event name.",
        ),
        &["tier", "event"],
    )?;
    match prometheus::default_registry().register(Box::new(counter.clone())) {
        Ok(()) => {}
        Err(prometheus::Error::AlreadyReg) => {}
        Err(error) => return Err(error),
    }

    let _ = CACHE_ACTIVITY_TOTAL.set(counter);
    CACHE_ACTIVITY_TOTAL.get().ok_or_else(|| {
        prometheus::Error::Msg("fluxheim_cache_activity_total failed to initialize".to_owned())
    })
}

pub(in crate::metrics) fn cache_activity_scope_total()
-> Result<&'static IntCounterVec, prometheus::Error> {
    if let Some(counter) = CACHE_ACTIVITY_SCOPE_TOTAL.get() {
        return Ok(counter);
    }

    let counter = IntCounterVec::new(
        Opts::new(
            "fluxheim_cache_activity_scope_total",
            "Fluxheim cache activity events by configured vhost, optional route, storage tier, and bounded event name.",
        ),
        &["scope", "vhost", "route", "tier", "event"],
    )?;
    match prometheus::default_registry().register(Box::new(counter.clone())) {
        Ok(()) => {}
        Err(prometheus::Error::AlreadyReg) => {}
        Err(error) => return Err(error),
    }

    let _ = CACHE_ACTIVITY_SCOPE_TOTAL.set(counter);
    CACHE_ACTIVITY_SCOPE_TOTAL.get().ok_or_else(|| {
        prometheus::Error::Msg(
            "fluxheim_cache_activity_scope_total failed to initialize".to_owned(),
        )
    })
}

pub(in crate::metrics) fn cache_operation_duration_seconds()
-> Result<&'static HistogramVec, prometheus::Error> {
    if let Some(histogram) = CACHE_OPERATION_DURATION_SECONDS.get() {
        return Ok(histogram);
    }

    let histogram = HistogramVec::new(
        HistogramOpts::new(
            "fluxheim_cache_operation_duration_seconds",
            "Fluxheim cache lookup and request-collapsing wait durations with bounded labels.",
        )
        .buckets(vec![
            0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
        ]),
        &["scope", "vhost", "route", "phase", "operation"],
    )?;
    match prometheus::default_registry().register(Box::new(histogram.clone())) {
        Ok(()) => {}
        Err(prometheus::Error::AlreadyReg) => {}
        Err(error) => return Err(error),
    }

    let _ = CACHE_OPERATION_DURATION_SECONDS.set(histogram);
    CACHE_OPERATION_DURATION_SECONDS.get().ok_or_else(|| {
        prometheus::Error::Msg(
            "fluxheim_cache_operation_duration_seconds failed to initialize".to_owned(),
        )
    })
}

pub(in crate::metrics) fn cache_purges_total() -> Result<&'static IntCounterVec, prometheus::Error>
{
    if let Some(counter) = CACHE_PURGES_TOTAL.get() {
        return Ok(counter);
    }

    let counter = IntCounterVec::new(
        Opts::new(
            "fluxheim_cache_purges_total",
            "Fluxheim cache purge admin commands by bounded operation, configured cache scope, and purge mode.",
        ),
        &["operation", "scope", "vhost", "route", "mode"],
    )?;
    match prometheus::default_registry().register(Box::new(counter.clone())) {
        Ok(()) => {}
        Err(prometheus::Error::AlreadyReg) => {}
        Err(error) => return Err(error),
    }

    let _ = CACHE_PURGES_TOTAL.set(counter);
    CACHE_PURGES_TOTAL.get().ok_or_else(|| {
        prometheus::Error::Msg("fluxheim_cache_purges_total failed to initialize".to_owned())
    })
}

pub(in crate::metrics) fn cache_purger_runs_total()
-> Result<&'static IntCounterVec, prometheus::Error> {
    if let Some(counter) = CACHE_PURGER_RUNS_TOTAL.get() {
        return Ok(counter);
    }

    let counter = IntCounterVec::new(
        Opts::new(
            "fluxheim_cache_purger_runs_total",
            "Fluxheim background stale disk cache purger runs by bounded outcome.",
        ),
        &["outcome"],
    )?;
    match prometheus::default_registry().register(Box::new(counter.clone())) {
        Ok(()) => {}
        Err(prometheus::Error::AlreadyReg) => {}
        Err(error) => return Err(error),
    }

    let _ = CACHE_PURGER_RUNS_TOTAL.set(counter);
    CACHE_PURGER_RUNS_TOTAL.get().ok_or_else(|| {
        prometheus::Error::Msg("fluxheim_cache_purger_runs_total failed to initialize".to_owned())
    })
}

pub(in crate::metrics) fn cache_purger_entries_total()
-> Result<&'static IntCounterVec, prometheus::Error> {
    if let Some(counter) = CACHE_PURGER_ENTRIES_TOTAL.get() {
        return Ok(counter);
    }

    let counter = IntCounterVec::new(
        Opts::new(
            "fluxheim_cache_purger_entries_total",
            "Fluxheim background stale disk cache purger entry counts by bounded result.",
        ),
        &["result"],
    )?;
    match prometheus::default_registry().register(Box::new(counter.clone())) {
        Ok(()) => {}
        Err(prometheus::Error::AlreadyReg) => {}
        Err(error) => return Err(error),
    }

    let _ = CACHE_PURGER_ENTRIES_TOTAL.set(counter);
    CACHE_PURGER_ENTRIES_TOTAL.get().ok_or_else(|| {
        prometheus::Error::Msg(
            "fluxheim_cache_purger_entries_total failed to initialize".to_owned(),
        )
    })
}

pub(in crate::metrics) fn cache_purger_duration_seconds()
-> Result<&'static HistogramVec, prometheus::Error> {
    if let Some(histogram) = CACHE_PURGER_DURATION_SECONDS.get() {
        return Ok(histogram);
    }

    let histogram = HistogramVec::new(
        HistogramOpts::new(
            "fluxheim_cache_purger_duration_seconds",
            "Fluxheim background stale disk cache purger run duration by bounded outcome.",
        )
        .buckets(vec![
            0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
            30.0,
        ]),
        &["outcome"],
    )?;
    match prometheus::default_registry().register(Box::new(histogram.clone())) {
        Ok(()) => {}
        Err(prometheus::Error::AlreadyReg) => {}
        Err(error) => return Err(error),
    }

    let _ = CACHE_PURGER_DURATION_SECONDS.set(histogram);
    CACHE_PURGER_DURATION_SECONDS.get().ok_or_else(|| {
        prometheus::Error::Msg(
            "fluxheim_cache_purger_duration_seconds failed to initialize".to_owned(),
        )
    })
}
