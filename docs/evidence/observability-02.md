# Observability Commit 02 Evidence

Base: `2948422930bb45d3e6fad1119978b4a8eaee8ca8`. Local verification on
2026-10-23, Linux x86_64, Rust 1.99.1. Implementation is ready for incremental
review, not accepted until pentest/retest, exact-SHA GitHub and user approval.
The final commit SHA is recorded by Git/acceptance ledger, not self-embedded.

## Scope And Limits

The [event contract](../architecture/structured-events.md) specifies closed
access/error/security/audit envelopes, schema and service version, fixed
messages, finite codes, numeric resources, filtered opt-in correlation, privacy
suppression and bounded serialization. Existing runtime and collector outputs
are unchanged; runtime owners/dispatcher wiring belongs to later checkpoints.
No filesystem, listener, authentication, ACME or Windows runtime implementation
changed. No unsafe code or error-chain formatting was added.

Hard event bounds are 8 KiB encoded, fewer than 32 nested fields and at most
128/32/16 bytes for retained request/trace/span IDs. Encoders share the same
captured fields, include framing/newline in their cap, and return no partial
output on failure. Long candidates are length-rejected before copy/scan;
malformed Unicode is never byte-sliced. Returned bytes have no capacity slack.

No existing operator configuration is clamped. Library optional capture defaults
off; runtime policy mapping is future owner work. Valid opted-in IDs are not
automatically secret-free. Generic existing `log!` calls remain caller-owned.
Protected reservation/rate limits are documented for Commit 04, not implemented
or claimed as active controls here.

## Local Verification

All listed commands exited 0:

| Command | Result |
| --- | --- |
| `cargo test --locked --workspace` | 1782 passed; one existing privileged ACME mount-namespace test ignored |
| `cargo test --locked -p fluxheim --lib --no-default-features --features profile-observability` | 243 passed |
| `cargo test --locked -p fluxheim --lib --no-default-features --features profile-privacy structured_event_` | 2 passed; verifies application-to-library privacy feature forwarding |
| `cargo test --locked -p fluxheim-observability --no-default-features` | 14 passed; production dependency tree still only getrandom/log and their dependencies |
| `cargo test --locked -p fluxheim-observability --no-default-features --features structured-events` | 28 passed plus one compile-fail doc test |
| `cargo test --locked -p fluxheim-observability --all-features` | 34 passed plus one compile-fail doc test; includes compile-time privacy mode |
| `cargo test --locked -p fluxheim-config --no-default-features --features privacy-mode observability` | 7 passed |
| `cargo test --locked -p fluxheim-config --no-default-features --features metrics-otlp,otel-tracing,otel-otlp observability` | 10 passed |
| `cargo clippy --locked -p fluxheim-observability --all-targets --all-features -- -D warnings` | Passed |
| `cargo clippy --locked -p fluxheim --no-default-features --features profile-observability --all-targets -- -D warnings` | Passed |
| `cargo check --locked -p fluxheim-observability --target x86_64-pc-windows-msvc --no-default-features --features structured-events --tests` | Passed; compile-only, not Windows execution |
| `cargo audit` / `cargo deny check` | No advisories; dependency policies passed; no third-party version changes |

Permanent regressions include 512 generated Unicode/correlation input cases per
property run; secret canaries; disabled/trusted/privacy combinations; max values
and recursive field counts; encoded byte boundaries/escape expansion; schema
fixtures for all families; refusal to accept raw errors; and actual env_logger
module/level/message-regex behavior without mutating the test process environment.

Formatting, Markdown links, documentation layout (4), development scope (7),
release metadata tests (3), release metadata validation and modularity checks
also pass. CI explicitly covers feature-off, normal and all-feature event tests.

## Live Linux Diagnostic

Commands:

```sh
cargo build --locked --release --no-default-features --features profile-observability --bin fluxheim
python3 scripts/observability_baseline.py --binary target/release/fluxheim
```

[Raw measurements](observability-02-linux.json) include exact binary identity,
toolchain, dirty development-build status and every sample. Binary SHA-256:
`d647c2a77726e5a37887b50061e26298b1c834723d9fbe4c04291c2fa2ce2ff0`.

Three alternating on/off pairs, 500 HTTP/1.1 requests each, eight client workers,
20 warmups and two server threads; local proxy, Python origin and fixture
collector. Every request matched expected status/body. Each on run scraped real
proxy metrics, delivered four metric exports and eight runtime records; off
runs delivered none. Secret canaries were absent. All runs still had zero native
access events/exported spans, the known future wiring gap, not an APM pass.

This is a short shared-host compatibility diagnostic, not an isolated before/
after performance qualification. It does not exercise the new event API through
runtime owners, prove saturation guarantees, or qualify Grafana/SigNoz. The
raw timings are retained without treating noisy differences as improvements.

Pending: user pentest, exact-final-SHA GitHub/CodeQL including native Windows and
macOS, and explicit acceptance. Do not advance to Commit 03 automatically.
