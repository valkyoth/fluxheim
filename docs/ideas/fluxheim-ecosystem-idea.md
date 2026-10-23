# Fluxheim Ecosystem Idea

This note records a long-term ecosystem direction. It is not part of the
current release commitment and should not blur Fluxheim's core scope as an edge
proxy, cache, and load balancer.

The useful direction is a set of separate crates and projects that can
integrate with Fluxheim while keeping each product boundary reviewable.

## Proposed Shape

```text
fluxheim             HTTP/TCP edge proxy, cache, and load balancer
fluxheim-sdk         Application integration helpers for services behind Fluxheim
fluxheim-defense     DDoS/edge-defense detection and mitigation orchestration
fluxheim-router      Routing and network-edge control-plane tooling
fluxheim-common      Shared auth, telemetry, policy, IDs, and wire protocols
```

`fluxheim` should stay focused. The other projects should be real packages with
their own README, tests, examples, security model, and release gates. They may
start in a `crates/` workspace directory for shared CI, but each boundary
should be clean enough that it can move to its own repository later.

## fluxheim-sdk

`fluxheim-sdk` is the near-term ecosystem crate. It should help Rust
applications cooperate with Fluxheim without turning the app into a hidden
control plane.

Possible scope:

- Tower/Axum middleware for trusted Fluxheim request context.
- Request ID and trace-context helpers.
- Safe client-IP extraction from Fluxheim-forwarded context.
- Typed TLS client-certificate and Geo-Context extractors.
- Health/readiness response schemas.
- Graceful drain state helpers.
- Cache-control helpers and authenticated internal cache-purge clients.

Out of first scope:

- automatic backend self-registration;
- dynamic runtime weight changes from application code;
- UDP heartbeats;
- persistent control streams.

Those belong after Fluxheim's authenticated runtime backend-management model is
stable enough to expose to application code.

## fluxheim-defense

`fluxheim-defense` is the long-term edge-defense platform idea. It should not
be described as an Arbor clone in product text, but the architectural category
is similar: detect DDoS/anomalous traffic and orchestrate mitigations across
host, router, and upstream boundaries.

Possible inputs:

- Fluxheim per-route request rates and anomaly scores.
- Source IP, subnet, ASN, and Geo-Context signals.
- HTTP/2 abuse signals and malformed/protocol-limit events.
- Load-balancer saturation, queue, retry, and passive-health events.
- NetFlow, sFlow, or IPFIX from routers in a later phase.

Possible actions:

- local Fluxheim deny, delay, tarpit, or challenge policy;
- `fluxheim-ddosd` XDP/eBPF drop-map updates on Linux hosts;
- BGP RTBH route injection;
- BGP FlowSpec rules;
- alerts, incident records, and forensics exports;
- provider/upstream integration where supported.

Important boundary:

Fluxheim or `fluxheim-defense` cannot replace upstream scrubbing for attacks
that saturate the network link before packets reach the host. A realistic
system complements provider-level DDoS protection, it does not remove the need
for it in high-volume scenarios.

## fluxheim-router

`fluxheim-router` is an exploratory network-edge project. It would be a
separate routing/control-plane tool, not a module inside the proxy.

Possible future scope:

- BGP session management and policy;
- route table and prefix policy;
- RTBH/FlowSpec integration with `fluxheim-defense`;
- firewall/NAT/VRF abstractions where the platform supports them;
- eventually WireGuard/IPsec or TLS VPN gateway functions if a separate threat
  model and release gate are defined.

This is a much larger domain than the proxy. It should be treated as a new
product line with its own security evidence, not as a normal Fluxheim minor
release.

## Shared Foundation

If the ecosystem grows, use a small shared crate such as `fluxheim-common` or
`fluxheim-protocol` only for stable cross-project pieces:

- authentication and signed control-plane messages;
- common IDs and bounded labels;
- telemetry labels and event schemas;
- policy/result enums;
- versioned wire formats.

Do not put proxy internals in the shared crate. Shared code should reduce
duplication between ecosystem projects without making the proxy depend on
router or DDoS product logic.

## Repository Rule

New ecosystem crates should live outside the proxy binary modules, for example:

```text
crates/fluxheim-sdk/
crates/fluxheim-common/
```

Longer-lived projects such as `fluxheim-defense` and `fluxheim-router` may
start in the workspace only if that helps CI and dependency hygiene. Their code
should still be isolated enough to become standalone GitHub projects.
