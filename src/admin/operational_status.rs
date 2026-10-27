//! Fixed-shape observer. No filesystem access, probes, recovery or inventory walks.
use super::operational_inventory::Inventory;
use super::{AdminApp, AdminResponse, Config, StatusCode, json_response, unix_secs};
use serde::Serialize;
use serde_json::json;
use std::io::{self, Write};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

pub(super) const MAX_RESPONSE: usize = 16 * 1024;
const DEADLINE: Duration = Duration::from_millis(50);
const MAX_READERS: usize = 4;

#[derive(Clone, Copy, Serialize)]
struct Change {
    operation: &'static str,
    outcome: &'static str,
    completed_unix_secs: u64,
}

#[derive(Clone, Copy, Serialize)]
struct Published {
    generation: u64,
    updated_unix_secs: u64,
    inventory: Inventory,
    last_change: Option<Change>,
}

pub(super) struct Operational {
    instance: String,
    started: Instant,
    published: Mutex<Published>,
    readers: AtomicUsize,
}

impl Operational {
    pub fn new(config: &Config) -> io::Result<Self> {
        let mut nonce = [0u8; 16];
        getrandom::fill(&mut nonce).map_err(io::Error::other)?;
        let instance = nonce.iter().map(|byte| format!("{byte:02x}")).collect();
        Ok(Self {
            instance,
            started: Instant::now(),
            published: Mutex::new(Published {
                generation: 1,
                updated_unix_secs: unix_secs(),
                inventory: Inventory::new(config),
                last_change: None,
            }),
            readers: AtomicUsize::new(0),
        })
    }

    pub fn publish(&self, config: &Config) {
        let inventory = Inventory::new(config);
        if let Ok(mut state) = self.published.lock() {
            state.inventory = inventory;
            state.generation = state.generation.saturating_add(1);
            state.updated_unix_secs = unix_secs();
        }
    }

    pub fn record_attempt(&self, operation: &'static str, success: bool) {
        if let Ok(mut state) = self.published.lock() {
            state.last_change = Some(Change {
                operation,
                outcome: if success { "succeeded" } else { "failed" },
                completed_unix_secs: unix_secs(),
            });
        }
    }

    fn enter(&self) -> Option<Reader<'_>> {
        self.readers
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < MAX_READERS).then(|| n + 1)
            })
            .ok()
            .map(|_| Reader(&self.readers))
    }
}

struct Reader<'a>(&'a AtomicUsize);
impl Drop for Reader<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Release);
    }
}

pub(super) fn unavailable() -> AdminResponse {
    json_response(
        StatusCode::SERVICE_UNAVAILABLE,
        br#"{"error":"operational_status_unavailable"}"#,
    )
}

impl AdminApp {
    pub(super) fn operational_response(&self, method: &str, query: Option<&str>) -> AdminResponse {
        if method != "GET" {
            return json_response(
                StatusCode::METHOD_NOT_ALLOWED,
                br#"{"error":"method_not_allowed"}"#,
            );
        }
        if query.is_some_and(|q| !q.is_empty()) {
            return json_response(
                StatusCode::BAD_REQUEST,
                br#"{"error":"query_not_supported"}"#,
            );
        }
        let start = Instant::now();
        let Some(_reader) = self.operational.enter() else {
            return unavailable();
        };
        let Ok(published) = self.operational.published.try_lock().map(|value| *value) else {
            return unavailable();
        };
        let recovery = match self.recovery_status() {
            Some(value) => value,
            None => return unavailable(),
        };
        let body = json!({
            "schema_version": 1,
            "version": env!("CARGO_PKG_VERSION"),
            "instance_id": self.operational.instance,
            "sampled_unix_secs": unix_secs(),
            "uptime_secs": self.operational.started.elapsed().as_secs(),
            "consistency": "best_effort",
            "stale": !published.inventory.complete,
            "health": "responding",
            "readiness": recovery,
            "configuration": published,
            "capabilities": {
                "proxy": cfg!(feature = "proxy"), "web": cfg!(feature = "web"),
                "cache": cfg!(feature = "cache"), "load_balancer": cfg!(feature = "load-balancer"),
                "php": cfg!(feature = "php-fpm"), "acme": cfg!(feature = "acme"),
                "wasm": cfg!(feature = "wasm"), "metrics": cfg!(feature = "metrics"),
                "metrics_otlp": cfg!(feature = "metrics-otlp"), "traces_otlp": cfg!(feature = "otel-otlp"),
                "privacy_mode": cfg!(feature = "privacy-mode"),
                "tls_rustls": cfg!(feature = "tls-rustls-backend"), "tls_openssl": cfg!(feature = "tls-openssl"),
                "stream": cfg!(feature = "stream-proxy"), "udp": cfg!(feature = "udp-proxy")
            },
            "platform": {
                "os": std::env::consts::OS, "arch": std::env::consts::ARCH,
                "managed_php": cfg!(all(unix, feature = "php-fpm")),
                "ops_socket": cfg!(unix)
            },
            "telemetry": super::operational_telemetry::snapshot(&published.inventory)
        });
        encode(&body, start)
    }

    fn recovery_status(&self) -> Option<&'static str> {
        // Nonblocking, fixed-size reads. Never clone snapshot IDs or pending errors.
        let deadline = *self.validation_deadline.try_lock().ok()?;
        let state = self.state.try_lock().ok()?;
        let Some(pending) = &state.pending_validation else {
            return Some("ready");
        };
        if pending.rollback_attempts > 0 || pending.last_rollback_failure.is_some() {
            return Some("recovery_required");
        }
        let expired = deadline.map_or_else(
            || pending.expires_unix_secs <= unix_secs(),
            |d| Instant::now() >= d,
        );
        let failed = pending.failed_checks > 0
            && pending.metrics().error_rate_per_mille() > u64::from(self.max_error_rate_per_mille);
        Some(if expired || failed {
            "recovery_required"
        } else {
            "validating"
        })
    }
}

struct Bounded(Vec<u8>);
impl Write for Bounded {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_RESPONSE.saturating_sub(self.0.len()) {
            return Err(io::Error::other("status size limit"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn encode(value: &impl Serialize, started: Instant) -> AdminResponse {
    let mut writer = Bounded(Vec::with_capacity(MAX_RESPONSE));
    if serde_json::to_writer(&mut writer, value).is_err() || started.elapsed() > DEADLINE {
        return unavailable();
    }
    AdminResponse {
        status: StatusCode::OK,
        content_type: "application/json",
        body: writer.0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn response_size_and_admission_are_bounded() {
        assert_eq!(
            encode(&"x".repeat(MAX_RESPONSE), Instant::now()).status,
            StatusCode::SERVICE_UNAVAILABLE
        );
        let operational = Operational::new(&Config::default()).unwrap();
        let permits: Vec<_> = (0..MAX_READERS)
            .map(|_| operational.enter().unwrap())
            .collect();
        assert!(operational.enter().is_none());
        drop(permits);
        assert!(operational.enter().is_some());
    }

    #[test]
    fn elapsed_collection_budget_returns_no_partial_sample() {
        let response = encode(
            &json!({"schema_version": 1}),
            Instant::now() - Duration::from_secs(1),
        );
        assert_eq!(response.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response.body,
            br#"{"error":"operational_status_unavailable"}"#
        );
    }
}
