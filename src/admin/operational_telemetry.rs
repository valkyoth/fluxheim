use super::operational_inventory::Inventory;
use serde_json::{Value, json};

fn logging(alive: bool, failures: u64, pending: u64) -> Value {
    json!({"state": if alive { "observed" } else { "degraded" },
        "failed_total": failures, "pending": pending})
}

pub(super) fn snapshot(inventory: &Inventory) -> Value {
    let legacy = crate::runtime::logging_status()
        .map(|status| {
            let (alive, failures, pending) = status.operational_health();
            logging(alive, failures, pending)
        })
        .unwrap_or_else(|| json!({"state": "unavailable", "failed_total": null, "pending": null}));
    let events = fluxheim_observability::operational::status()
        .map(|s| {
            let lanes = [&s.ordinary, &s.security, &s.audit];
            let failures = lanes
                .iter()
                .fold(0u64, |n, lane| n.saturating_add(lane.sink_errors));
            let pending = lanes
                .iter()
                .fold(0u64, |n, lane| n.saturating_add(lane.pending));
            logging(
                lanes.iter().all(|lane| lane.worker_alive),
                failures,
                pending,
            )
        })
        .unwrap_or_else(|| json!({"state": "unavailable", "failed_total": null, "pending": null}));
    json!({"logging": legacy, "events": events,
        "metrics": exporter(cfg!(feature = "metrics-otlp"), inventory.metrics_otlp, false),
        "traces": exporter(cfg!(feature = "otel-otlp"), inventory.traces_otlp, true)})
}

fn exporter(compiled: bool, enabled: bool, traces: bool) -> Value {
    let state = if !compiled {
        "not_compiled"
    } else if !enabled {
        "disabled"
    } else {
        "unavailable"
    };
    #[cfg(any(feature = "metrics-otlp", feature = "otel-otlp"))]
    if compiled && enabled {
        use fluxheim_observability::{ExportSignal, export_health};
        let health = export_health(if traces {
            ExportSignal::Traces
        } else {
            ExportSignal::Metrics
        });
        return json!({
            "state": match health.last_outcome {
                "success" => "observed", "partial" | "failed" => "degraded", _ => "unavailable",
            },
            "last_outcome": health.last_outcome, "failed_total": health.failed,
            "dropped_total": health.dropped, "queued_bytes": health.queued_bytes,
            "active_requests": health.active_requests,
        });
    }
    #[cfg(not(any(feature = "metrics-otlp", feature = "otel-otlp")))]
    let _ = traces;
    json!({"state": state, "last_outcome": "unknown", "failed_total": null,
        "dropped_total": null, "queued_bytes": null, "active_requests": null})
}
