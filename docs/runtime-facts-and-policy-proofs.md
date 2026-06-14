# Runtime Facts And Policy Proofs

Status: 1.6 planning policy

Fluxheim should understand its own runtime decisions without becoming a
database. The goal is a small, typed, bounded model for operational evidence:
what happened, which policy made the decision, and which public/redacted reason
can be shown to an operator.

This is inspired by two internal design patterns:

- Aesynx: no ambient authority, typed handles, explicit capability movement,
  bounded telemetry, fail-closed admission gates.
- Skrifheim: canonical facts, worlds, policy decisions, redacted debug output,
  and deterministic proof objects.

Fluxheim should adopt the discipline, not the database engine.

## Non-Goals

This work must not put a database, graph engine, AI system, or unbounded audit
store in the request hot path.

Runtime facts are not a replacement for logs, metrics, traces, or admin status.
They are a typed internal shape that those systems can export safely.

## Core Concepts

### Runtime Fact

A runtime fact is a bounded statement about Fluxheim state or behavior.

Examples:

- config candidate loaded;
- config reload promoted;
- route matched;
- route access policy denied;
- GeoIP context unavailable;
- auth-request allowed or denied;
- rate limit delayed or rejected;
- load-balancer backend selected;
- backend ejected or restored;
- cache object admitted, bypassed, purged, or served stale;
- ACME certificate installed or rollback attempted;
- admin mutation accepted or rejected.

Facts should carry enough metadata for diagnostics without leaking secrets:

- fact kind;
- config or policy epoch;
- vhost and route identifier where safe;
- bounded decision reason;
- source subsystem;
- monotonic event id or timestamp;
- redacted subject identifiers;
- optional causal parent or request correlation id;
- public classification of whether it is safe for logs, metrics, traces, or
  admin status.

### Policy Proof

Security-relevant decisions should move toward small proof objects:

```text
decision = allow | deny | redact | defer
reason = bounded enum
policy_epoch = current config/runtime policy epoch
input_count = bounded count
output_classification = public | sensitive | secret-internal
```

The proof is not verbose per-request logging. It is a typed result that keeps
policy decisions consistent across access control, cache admission,
load-balancer selection, admin mutation, auth-request, GeoIP, rate limiting,
Wasm hooks, and future WAF behavior.

### Runtime World

Fluxheim already has implicit worlds:

- current running config;
- reload candidate;
- known-good snapshot;
- rollback target;
- runtime load-balancer state;
- cache status;
- admin-visible status.

The 1.6 line should start treating those as explicit versioned views with
epochs and clear promotion rules. A candidate config should not become current
state without validation evidence. Runtime mutations should record the policy
epoch they were made under.

## 1.6 Adoption Plan

`v1.6.0` should document the initial runtime fact kinds, policy-proof shape,
redaction levels, and epoch terminology. It should not change request behavior.

Early 1.6 releases should introduce small types in a focused crate or
`fluxheim-common` if the shape is still tiny:

- `RuntimeFactKind`
- `RuntimeDecisionKind`
- `RuntimeDecisionReason`
- `PolicyProof`
- `PolicyEpoch`
- `RuntimeFactVisibility`

Mid 1.6 releases should route selected decision paths through proof objects
while replacing Pingora boundaries:

- route access policy;
- GeoIP allow/deny behavior;
- rate limiting;
- auth-request;
- cache admission and origin protection;
- load-balancer backend selection/ejection;
- admin runtime mutations.

Later 1.6 releases may add a bounded in-memory fact ring for admin diagnostics.
The ring must be optional, fixed-size, redacted by type, and safe to disable.
It must never be required for request forwarding.

## Security Rules

- Runtime facts do not create authority.
- Policy proofs are deterministic and bounded.
- Sensitive identifiers are redacted at type boundaries, not manually at each
  log site.
- Metrics stay low-cardinality.
- Admin views expose bounded reasons, not raw secrets or private addresses in
  privacy-mode builds.
- AI or Wasm consumers may only receive facts explicitly granted by policy.
- Derived or advisory facts are never authoritative unless promoted through a
  deterministic path.
- If fact collection fails, request handling must keep its configured
  fail-open/fail-closed behavior and record only a bounded diagnostic if safe.

## Why This Matters

Fluxheim has grown beyond a simple proxy. It now has cache, load balancing,
admin mutation, snapshots, ACME, stream/UDP work, metrics, traces, and future
Wasm/WAF/HTTP3 plans. A typed runtime-fact model lets operators and reviewers
ask:

- why was this request denied?
- why did this backend stop receiving traffic?
- why was this object not cached?
- which config epoch made this decision?
- which admin action changed this pool?
- which facts are safe to export?

That makes Fluxheim more self-aware and makes pentest review more local,
without turning the proxy into a database.
