# Sentinel Mesh: Smart WireGuard Load Balancing

Sentinel Mesh is a future Fluxheim architecture for a self-healing smart load
balancer. It combines Pingora's proxy and load-balancing hooks with a private
WireGuard transport and real-time backend telemetry. The goal is to route by
observed health and load instead of only round-robin or static weights.

This is a design target, not an implemented module.

## Goals

- Keep backend traffic private and encrypted even across clouds or sites.
- Support rootless/local operation where possible.
- Route requests to the healthiest backend using current telemetry.
- Expose clear operator state showing why a backend was selected.
- Allow manual drain and maintenance controls without restarting Fluxheim.
- Keep all state transitions testable as ordinary Rust logic.

## Non-Goals

- Replacing kernel WireGuard for every deployment. Kernel WireGuard should
  remain an option when host networking is available and preferred.
- Building a general service mesh in the first version.
- Trusting backend-reported telemetry without authentication and sanity checks.
- Adding this to the default binary until the dependency, license, and runtime
  risks are reviewed with `cargo deny` and `cargo audit`.

## Current Crate Findings

- `pingora 0.8.0` exposes `ProxyHttp`, `LoadBalancer`, background services,
  health checks, and backend selection primitives.
- `boringtun 0.7.0` is Cloudflare's userspace WireGuard implementation. Its
  library surface is low-level, so Fluxheim would need a networking/tunnel
  integration layer around it.
- `tokio-wireguard 0.1.3` provides an in-process WireGuard interface with
  Tokio-like TCP and UDP sockets. It is built on `boringtun` and `smoltcp`, and
  may be the faster prototype path.
- `arc-swap 1.9.1` is a good fit for read-heavy, write-rare shared routing
  snapshots because proxy workers can read without taking a lock.

Before implementation, re-check crate versions, maintenance, advisories, and
license compatibility. The first implementation should be behind a feature such
as `smart-lb` or `wireguard-transport`.

## High-Level Architecture

```text
[ Internet ]
     |
     v  HTTPS :443
+---------------------------------------------------------+
|              Fluxheim Smart Load Balancer               |
|                                                         |
|  +---------------- Pingora Proxy Engine --------------+ |
|  | ProxyHttp::request_filter / upstream_peer          | |
|  +-------------------------+---------------------------+ |
|                            |                             |
|  +-------------------------v-------------------------+   |
|  | Atomic Backend State                              |   |
|  | ArcSwap<Vec<BackendStatus>>                       |   |
|  +-------------------------^-------------------------+   |
|                            |                             |
|  +-------------------------+-------------------------+   |
|  | Background Observer                               |   |
|  | telemetry poller, health scorer, drain controller |   |
|  +-------------------------+-------------------------+   |
|                            |                             |
|  +-------------------------v-------------------------+   |
|  | WireGuard Transport                               |   |
|  | boringtun/tokio-wireguard or kernel WireGuard     |   |
|  +------+------------------+------------------+------+   |
+---------|------------------|------------------|----------+
          |                  |                  |
    UDP encrypted      UDP encrypted      UDP encrypted
          |                  |                  |
   +------v------+    +------v------+    +------v------+
   | Node A      |    | Node B      |    | Node C      |
   | 10.70.0.11  |    | 10.70.0.12  |    | 10.70.0.13  |
   | /internal/* |    | /internal/* |    | /internal/* |
   +-------------+    +-------------+    +-------------+
```

## Components

### Controller

The controller is the Fluxheim process receiving public traffic. It owns:

- Fluxheim proxy service.
- Optional Fluxheim load-balancing service.
- WireGuard interface or connector.
- Background observer.
- Atomic backend state.
- Restricted operator endpoints.

### Nodes

Nodes are ordinary backend web servers plus a small telemetry surface reachable
only over WireGuard. The telemetry endpoint can be implemented inside the app or
as a local sidecar.

Minimum node endpoints:

- `GET /internal/stats`: current load and health.
- `GET /internal/ready`: fast readiness probe.
- Optional `POST /internal/drain`: local drain request for maintenance.

Example stats payload:

```json
{
  "node_id": "node-a",
  "cpu_percent": 45,
  "memory_percent": 62,
  "active_connections": 120,
  "queue_depth": 3,
  "p95_latency_ms": 38,
  "is_draining": false
}
```

## Data Model

The proxy path should read a single immutable snapshot. The observer builds a
new vector and swaps it atomically.

```rust
pub struct BackendStatus {
    pub id: String,
    pub public_endpoint: String,
    pub tunnel_addr: String,
    pub score: u32,
    pub healthy: bool,
    pub draining: bool,
    pub last_seen_unix_ms: u64,
}

pub struct SmartLbState {
    pub backends: arc_swap::ArcSwap<Vec<BackendStatus>>,
}
```

Selection rule for the first version:

1. Filter out unhealthy backends.
2. Filter out draining backends unless no other backend is available.
3. Select the backend with the lowest score.
4. Fall back to the configured static round-robin pool only if smart state is
   empty and the config explicitly allows fallback.

## Scoring

Use a transparent weighted score so operators can understand decisions.

Initial formula:

```text
score =
  cpu_percent * 3
  + memory_percent * 2
  + active_connections
  + queue_depth * 20
  + p95_latency_ms
  + drain_penalty
  + stale_penalty
```

Suggested penalties:

- `drain_penalty = 1_000_000`
- `stale_penalty = 500_000` when telemetry is older than the configured stale
  threshold
- hard unhealthy when telemetry is older than the configured dead threshold

## WireGuard Transport Options

### Kernel WireGuard

Best for production hosts where Fluxheim can rely on OS-managed interfaces.

Pros:

- Mature operational model.
- Strong performance.
- Less in-process tunnel complexity.

Cons:

- Requires host network setup and privileges.
- Less portable for rootless Podman.

### `tokio-wireguard`

Best candidate for a rootless prototype. It exposes Tokio-like TCP/UDP sockets
over an in-process WireGuard interface.

Pros:

- Rootless-friendly design.
- Integrates naturally with async Rust.
- Built on `boringtun`.

Cons:

- Young crate.
- Needs careful load, reliability, and audit review.
- Pingora's connector path may need an adapter to dial through its socket type.

### Direct `boringtun`

Best when Fluxheim needs lower-level control over the WireGuard protocol.

Pros:

- Cloudflare-origin implementation.
- Portable userspace WireGuard core.

Cons:

- Lower-level library surface.
- More Fluxheim code needed for packet routing, timers, and integration.

## Request Flow

1. Client connects to Fluxheim over HTTPS.
2. `request_filter` applies security checks and optionally serves admin status.
3. `upstream_peer` reads the current `ArcSwap` backend snapshot.
4. The lowest-score healthy backend is selected.
5. Fluxheim dials the backend over the WireGuard transport.
6. Backend processes the request and responds through the tunnel.
7. The observer continues polling node telemetry and swaps in a new snapshot.

## Observer Flow

The observer is a Pingora background service or Tokio task supervised by the
runtime:

1. Tick every `500ms` to `2s`.
2. Poll each backend's `/internal/stats` over WireGuard.
3. Validate response schema and age.
4. Calculate score.
5. Preserve manual drain overrides.
6. Atomically swap the full backend vector.
7. Emit metrics and logs for state changes.

Failure handling:

- One failed poll marks the backend suspect.
- Consecutive failures mark it unhealthy.
- A stale backend is removed from routing before normal client traffic can
  accumulate TCP timeouts.

## Control Plane

Expose a restricted admin surface on a separate listener or protected path.

Suggested endpoints:

- `GET /_fluxheim/lb/status`: JSON state snapshot.
- `POST /_fluxheim/lb/drain/{node_id}`: stop sending new traffic.
- `POST /_fluxheim/lb/undrain/{node_id}`: return node to normal scoring.
- `GET /_fluxheim/lb/decision`: explain current selection order.

Security requirements:

- Bind admin listener to localhost by default.
- Require mTLS, signed admin token, or both before remote exposure.
- Never expose WireGuard private keys or raw secrets.
- Redact peer public endpoints when configured.
- Rate-limit admin endpoints.

## Configuration Sketch

```toml
[smart_lb]
enabled = true
transport = "tokio-wireguard"
poll_interval = "1s"
telemetry_timeout = "250ms"
stale_after = "5s"
dead_after = "15s"
allow_static_fallback = false

[smart_lb.wireguard]
private_key_file = "/var/lib/fluxheim/wireguard/controller.key"
listen = "0.0.0.0:51820"
address = "10.70.0.1/24"

[[smart_lb.backends]]
id = "node-a"
tunnel_addr = "10.70.0.11:8080"
telemetry_url = "http://10.70.0.11:8081/internal/stats"
public_key_file = "/etc/fluxheim/peers/node-a.pub"
endpoint = "203.0.113.11:51820"
allowed_ips = ["10.70.0.11/32"]

[[smart_lb.backends]]
id = "node-b"
tunnel_addr = "10.70.0.12:8080"
telemetry_url = "http://10.70.0.12:8081/internal/stats"
public_key_file = "/etc/fluxheim/peers/node-b.pub"
endpoint = "198.51.100.12:51820"
allowed_ips = ["10.70.0.12/32"]
```

## Security Requirements

- Store WireGuard private keys with `0600` permissions or use a secret manager.
- Pin each peer by public key.
- Reject telemetry from unknown node IDs.
- Sign or mTLS-protect telemetry if it is not exclusively reachable over the
  tunnel.
- Treat telemetry as advisory; do not allow a compromised backend to make all
  peers look unhealthy.
- Add hysteresis to avoid rapid backend flapping.
- Add circuit breakers for repeated upstream failures.
- Test downgrade behavior when the tunnel or observer is unavailable.

## Implementation Phases

1. **Design-only tracking**
   - Keep this document and roadmap entry updated.
   - Re-check crates and licenses before adding dependencies.

2. **Smart state without WireGuard**
   - Add `smart-lb` feature.
   - Implement `BackendStatus`, score calculation, and selection tests.
   - Use plain HTTP telemetry in local tests.

3. **Observer**
   - Add background observer with mockable telemetry client.
   - Add stale/dead thresholds and drain overrides.
   - Add metrics and status JSON.

4. **WireGuard transport prototype**
   - Evaluate `tokio-wireguard` first for rootless operation.
   - Keep kernel WireGuard as the production fallback.
   - Prove that Pingora upstream dialing can use the chosen tunnel path.

5. **Production hardening**
   - Add admin auth.
   - Add integration tests with multiple backend containers.
   - Add chaos tests for dropped tunnel, stale telemetry, and partial node
     failure.
   - Run `cargo deny`, `cargo audit`, and load tests before enabling by default.

## Open Questions

- Should Fluxheim own the WireGuard tunnel, or should production recommend
  kernel WireGuard and keep userspace WireGuard as rootless/dev mode?
- Can Pingora's connector APIs cleanly dial through `tokio-wireguard` socket
  types, or do we need a custom connector layer?
- Should telemetry be pull-based, push-based, or both?
- What is the minimum safe admin authentication model for local deployments?
- Should the smart selector integrate with Pingora `LoadBalancer` or remain a
  separate selector with its own state model?
