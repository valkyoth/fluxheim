//! Collect snapshots directly: no delta cache, reset race or exporter-specific state.
use prometheus::core::{Collector, Desc};
use prometheus::proto::MetricFamily;
use prometheus::{Error, IntCounterVec, IntGaugeVec, Opts};

pub(super) struct Health {
    counters: IntCounterVec,
    gauges: IntGaugeVec,
    budget: IntGaugeVec,
    overflow: prometheus::IntCounter,
}

impl Health {
    pub(super) fn new() -> Result<Self, Error> {
        Ok(Self {
            counters: IntCounterVec::new(
                Opts::new(
                    "fluxheim_log_dispatch_events_total",
                    "Process-lifetime dispatcher outcomes; some stages overlap, do not sum all outcomes.",
                ),
                &["lane", "outcome"],
            )?,
            gauges: IntGaugeVec::new(
                Opts::new(
                    "fluxheim_log_dispatch_state",
                    "Current dispatcher pending, reserved, capacity, alive, and available state.",
                ),
                &["lane", "state"],
            )?,
            budget: IntGaugeVec::new(
                Opts::new(
                    "fluxheim_metric_series_budget",
                    "Process-lifetime variable-series admission budget including histogram bucket costs; fixed reserve is separate.",
                ),
                &["state"],
            )?,
            overflow: prometheus::IntCounter::new(
                "fluxheim_metric_series_overflow_total",
                "Metric updates coalesced or gauge updates discarded due to identity or series limits.",
            )?,
        })
    }

    fn gauge(&self, lane: &str, state: &str, value: u64) {
        self.gauges
            .with_label_values(&[lane, state])
            .set(super::u64_to_i64_saturating(value));
    }

    fn lane(
        &self,
        name: &str,
        lane: &fluxheim_observability::operational::LaneStatus,
        capacity: usize,
    ) {
        self.gauge(name, "available", 1);
        self.gauge(name, "alive", u64::from(lane.worker_alive));
        self.gauge(name, "pending", lane.pending);
        self.gauge(name, "reserved", lane.reserved);
        self.gauge(name, "capacity", capacity as u64);
        for (outcome, value) in [
            ("accepted", lane.accepted),
            ("filtered", lane.filtered),
            ("rate_limited", lane.rate_limited),
            ("queue_full", lane.queue_full),
            ("unavailable", lane.unavailable),
            ("encoded", lane.encoded),
            ("written", lane.written),
            ("sink_errors", lane.sink_errors),
            ("discarded", lane.discarded),
        ] {
            self.counters
                .with_label_values(&[name, outcome])
                .inc_by(value);
        }
    }

    fn refresh(&self) {
        let (used, overflow) = super::bounded::usage();
        for (state, value) in [
            ("used", used),
            ("limit", super::bounded::SERIES_LIMIT),
            ("fixed_reserve", 1000),
        ] {
            self.budget
                .with_label_values(&[state])
                .set(super::usize_to_i64_saturating(value));
        }
        self.overflow.inc_by(overflow);
        if let Some(status) = fluxheim_observability::operational::status() {
            for (name, lane) in [
                ("ordinary", &status.ordinary),
                ("security", &status.security),
                ("audit", &status.audit),
            ] {
                self.lane(name, lane, status.queue_capacity_per_lane);
            }
        } else {
            for name in ["ordinary", "security", "audit"] {
                self.gauge(name, "available", 0);
            }
        }
        #[cfg(feature = "proxy")]
        if let Some(status) = crate::runtime::logging_status() {
            self.gauge("legacy", "available", 1);
            for (state, value) in status.metric_gauges() {
                self.gauge("legacy", state, value);
            }
            for (outcome, value) in status.metric_counters() {
                self.counters
                    .with_label_values(&["legacy", outcome])
                    .inc_by(value);
            }
        } else {
            self.gauge("legacy", "available", 0);
        }
    }
}

impl Collector for Health {
    fn desc(&self) -> Vec<&Desc> {
        [
            &self.counters as &dyn Collector,
            &self.gauges,
            &self.budget,
            &self.overflow,
        ]
        .iter()
        .flat_map(|c| c.desc())
        .collect()
    }
    fn collect(&self) -> Vec<MetricFamily> {
        let Ok(snapshot) = Self::new() else {
            return Vec::new();
        };
        snapshot.refresh();
        [
            &snapshot.counters as &dyn Collector,
            &snapshot.gauges,
            &snapshot.budget,
            &snapshot.overflow,
        ]
        .iter()
        .flat_map(|c| c.collect())
        .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fluxheim_observability::event::{EventData, EventFormat, FailureReason};
    use fluxheim_observability::operational::Dispatcher;
    use std::io::{self, Write};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    struct Broken;
    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("injected sink failure"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn real_sink_failure_remains_visible_without_successful_log_delivery() {
        let dispatcher = Dispatcher::new(
            EventFormat::Json,
            Arc::new(|_| true),
            [Box::new(Broken), Box::new(io::sink()), Box::new(io::sink())],
        )
        .unwrap();
        dispatcher.try_emit(EventData::Error {
            reason: FailureReason::ConnectionRefused,
            attempt: None,
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        while dispatcher.status().ordinary.worker_alive {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(1));
        }
        let status = dispatcher.status();
        for _ in 0..2 {
            let snapshot = Health::new().unwrap();
            snapshot.lane("ordinary", &status.ordinary, status.queue_capacity_per_lane);
            assert_eq!(
                snapshot
                    .counters
                    .with_label_values(&["ordinary", "sink_errors"])
                    .get(),
                1
            );
            assert_eq!(
                snapshot
                    .counters
                    .with_label_values(&["ordinary", "written"])
                    .get(),
                0
            );
            assert_eq!(
                snapshot
                    .gauges
                    .with_label_values(&["ordinary", "alive"])
                    .get(),
                0
            );
            assert_eq!(
                snapshot
                    .gauges
                    .with_label_values(&["ordinary", "available"])
                    .get(),
                1
            );
        }
        dispatcher.shutdown(Duration::from_millis(100));
    }
}
