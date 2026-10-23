# WAF Architecture

Fluxheim WAF support is future optional security functionality. It must not be
compiled into default builds. The normal secure default remains a small edge
proxy/static server focused on strict protocol handling, TLS, cache, logging,
and metrics.

The WAF goal is to provide a per-vhost request inspection layer that can block,
score, or audit suspicious traffic without turning request workers into a slow
or unbounded parsing path.

Long-term scope should cover the web-application security jobs operators expect
from F5 BIG-IP ASM/Advanced WAF-class deployments, but through Fluxheim's
optional modules and release gates. That includes signature/anomaly scoring,
OWASP CRS-compatible rule paths where practical, positive-security policy over
time, bot/reputation inputs, per-vhost dry-run/blocking modes, audit evidence,
and integration points for load-balancer routing decisions. It is not part of
the `1.5` load-balancer release.

## Goals

- Keep WAF support compile-time optional and disabled by default.
- Support per-vhost WAF policy.
- Inspect headers and small request bodies before proxying dynamic traffic.
- Provide dry-run mode for tuning before enforcement.
- Keep logs and metrics privacy-safe and cardinality-safe.
- Fail predictably when the WAF engine or rule set cannot load.

## Non-Goals

- No default OWASP CRS enforcement in normal Fluxheim builds.
- No unbounded body buffering.
- No raw request-body storage in logs.
- No automatic trust in community rule packs without license and security
  review.
- No C/FFI engine in the default binary.

## Feature Flags

Planned feature split:

```toml
waf = []
waf-native = ["waf", "dep:aho-corasick"]
waf-hyperscan = ["waf-native", "dep:hyperscan"]
waf-proxy-wasm = ["waf"]
```

Reviewed crate/source candidates as of 2026-05-05:

- `aho-corasick 1.1.4`, Unlicense/MIT: native multi-pattern matching.
- `hyperscan 0.3.2`, MIT/Apache-2.0: optional high-performance regex scanning
  through FFI bindings. This needs platform/package checks and must stay out of
  defaults.
- `proxy-wasm 0.2.4`, Apache-2.0: Rust SDK for writing Proxy-Wasm extensions,
  not a complete Pingora host runtime by itself.
- Coraza is a Go WAF engine with OWASP CRS compatibility. The practical
  Fluxheim path is a future `waf-proxy-wasm` engine if a reviewed WASM host
  integration is built.
- OWASP Core Rule Set is Apache-2.0 and should be treated as an external rule
  dependency with explicit version pinning.

## Recommended Engine Path

### Stage 1: Native MVP

Start with `waf-native` because it is auditable and fits Rust/Pingora without
embedding a second runtime.

Capabilities:

- URI and normalized-header inspection.
- Cookie-name and cookie-value inspection with redaction-aware handling.
- Fixed signature rules using `aho-corasick`.
- Simple regex rules only after a safe regex engine review.
- Anomaly scoring.
- Dry-run mode.
- Per-vhost allow/deny/audit policy.
- JSON audit events through the structured logging pipeline.

This stage should not claim CRS compatibility.

### Stage 2: Optional Hyperscan

`waf-hyperscan` can accelerate larger rule sets. It is FFI-backed and commonly
Linux-oriented, so it should be:

- disabled by default;
- excluded from minimal/rootless builds unless explicitly selected;
- checked in CI for supported target platforms;
- documented as requiring system/library compatibility where needed.

### Stage 3: Coraza/Proxy-Wasm Compatibility

Coraza plus OWASP CRS is the better compatibility target for users who want
industry-standard CRS behavior. It should be a separate experimental engine
until Fluxheim has:

- a reviewed WASM host/runtime design;
- bounded memory and CPU execution;
- deterministic timeout behavior;
- rule-pack pinning and integrity checks;
- clear CRS tuning workflow;
- integration tests proving request phase mapping is correct.

Coraza/CRS should not be represented as plug-and-play. Production CRS use needs
tuning, exclusions, and monitoring.

## Pingora Hook Placement

WAF decisions should happen before expensive upstream work.

Header phase:

- request method
- normalized path and query metadata
- HTTP version
- Host after vhost resolution
- selected headers after canonicalization
- cookies after size and count limits
- client metadata already trusted by Fluxheim

Body phase:

- inspect only configured content types, initially:
  `application/x-www-form-urlencoded`, `application/json`, and optionally
  selected text media types;
- scan only up to `max_scan_bytes`;
- do not inspect binary uploads by default;
- do not buffer bodies beyond the configured cap;
- pass streaming bodies through once the scan budget is exhausted according to
  the per-vhost overflow policy.

## Decision Model

Actions:

- `allow`: continue request handling.
- `deny`: return a configured status, normally `403`.
- `audit`: log the rule hit and continue.
- `score`: add anomaly points and decide after all applicable rules run.

Per-vhost modes:

- `off`: WAF disabled.
- `dry_run`: record decisions but never block.
- `block`: enforce deny/score thresholds.

Fail modes:

- `fail_closed`: deny requests when the enabled WAF cannot evaluate. This is
  safest for protected applications.
- `fail_open`: continue when WAF evaluation fails. This is availability-first
  and should trigger config validation warnings.

## Rule Format

Fluxheim should start with a small typed TOML/YAML model, not full SecLang.

Example target:

```toml
[[waf.rules]]
id = "native-sqli-001"
phase = "headers"
target = "uri_query"
match = "contains_any"
patterns = ["union select", "' or 1=1", "\" or \"1\"=\"1"]
score = 5
action = "score"

[[waf.rules]]
id = "native-xss-001"
phase = "body"
target = "form_values"
match = "contains_any"
patterns = ["<script", "javascript:"]
score = 5
action = "score"
```

Rules should be validated before snapshot activation. Invalid rules must block
the snapshot/reload, not fail at request time.

## Config Shape

Initial target:

```toml
[waf]
enabled = false
engine = "native"
rules_file = "/etc/fluxheim/waf/native-rules.toml"
default_mode = "dry_run"
default_fail_mode = "fail_closed"
max_header_bytes = 32768
max_cookie_count = 64
max_scan_bytes = 131072
score_threshold = 5

[[vhosts]]
name = "app.example.test"

[vhosts.waf]
enabled = true
mode = "block"
fail_mode = "fail_closed"
score_threshold = 5
scan_content_types = [
  "application/json",
  "application/x-www-form-urlencoded",
]
oversize_body = "skip"
```

## Logging And Metrics

WAF audit logs should include:

- timestamp
- request ID
- configured vhost
- phase
- rule ID
- action
- score
- final decision
- redacted target name

WAF audit logs must not include:

- authorization headers
- complete cookies
- complete request bodies
- raw secrets
- attacker-controlled label values

Metrics should use fixed labels only:

- `vhost`
- `mode`
- `phase`
- `action`
- `rule_id` only if the rule ID comes from validated config and the total rule
  count is bounded

Unknown or invalid hosts must map to fixed buckets such as `unknown` or
`invalid_host`.

## Security Guardrails

- Normalize paths before matching and before static/proxy routing.
- Reject malformed header framing before WAF evaluation.
- Apply request size limits before body scan allocation.
- Cap rule count, pattern length, cookie count, header count, and scan bytes.
- Time-box expensive engine calls.
- Treat WAF config/rules as part of the snapshot validation flow.
- Never let a WAF failure panic a Pingora worker.
- Keep `waf-hyperscan` and `waf-proxy-wasm` out of the default feature set.
- Pin external CRS versions and verify checksums if rule bundles are downloaded
  by tooling.

## Implementation Stages

1. Add feature guards and config schema with validation, but no request
   enforcement.
2. Add native header-phase rules with dry-run audit logging.
3. Add anomaly scoring and block mode.
4. Add bounded body-phase scanning for selected content types.
5. Add per-vhost WAF policy reload through snapshots.
6. Add metrics for WAF decisions and failures.
7. Evaluate `hyperscan` for large native rule sets.
8. Evaluate Proxy-Wasm/Coraza/OWASP CRS as a separate engine.

## Tests

Required tests:

- Default build does not compile WAF modules.
- `--features waf-native` enables config parsing and rule validation.
- Invalid rule files fail config validation before reload.
- Dry-run records audit events but allows requests.
- Block mode denies above-threshold requests.
- Oversized bodies follow the configured `oversize_body` policy.
- Binary content types are not scanned by default.
- Redaction removes secrets from audit logs.
- Unknown Host values do not create metric labels.
- Snapshot reload swaps WAF rules atomically.
- WAF engine failure follows `fail_closed` or `fail_open` exactly.
