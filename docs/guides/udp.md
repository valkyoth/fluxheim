# UDP Forwarding (Beta)

Fluxheim has an opt-in UDP experiment with two behaviors: forward one datagram
and wait for one reply, or forward one datagram without waiting. It is **not a
production UDP platform**. Normal release profiles, including `profile-full`,
do not enable it. Build with `udp-proxy` explicitly for a controlled evaluation.

The `dns-load-balance` name describes request/response forwarding, not a DNS
implementation. Fluxheim does not parse questions, validate transaction IDs,
cache records, implement DNSSEC, synthesize GSLB answers or retry truncated DNS
responses over TCP. It also does not implement QUIC, HTTP/3, game-session
affinity, DTLS, a VPN or a firewall. `quic-pass-through` and `game-proxy` are
reserved enum values and are rejected both by validation and runtime creation.

Use [TCP streams](tcp-streams.md) for raw TCP, or the
[reverse proxy](reverse-proxy.md) for HTTP. HTTP vhosts, auth, access policies,
headers, cache, rate/concurrency limits and GeoIP do not apply to UDP routes.

## Evaluate Request/Response Forwarding

Set `[udp]` `enabled` to `true` and add listeners using `[[udp.routes]]`.
The `routes` array contains the independent forwarding policies described below.

[Complete private example](../../examples/udp/local.toml): a UDP listener at
`127.0.0.1:15353` sends to an independently running UDP service at
`127.0.0.1:19053`. These are unprivileged loopback ports, not public DNS services.

```sh
cargo build --locked --bin fluxheim --no-default-features --features udp-proxy
target/debug/fluxheim --config examples/udp/local.toml --validate-config
target/debug/fluxheim --config examples/udp/local.toml
```

The example disables HTTP listeners and cache and puts process files beside
the config. Keep that directory private and writable by the service user.
Start your upstream separately; validation checks configuration, not reachability.

The relevant route is:

```toml
[udp]
enabled = true

[[udp.routes]]
name = "local-datagrams"
mode = "dns-load-balance"
listen = ["127.0.0.1:15353"]
upstream = "127.0.0.1:19053"
idle_timeout_secs = 30
response_timeout_secs = 1
max_datagram_bytes = 1232
max_sessions = 32
max_sessions_per_source = 8
max_responses_per_source_per_second = 64
```

For each admitted datagram, Fluxheim opens a new connected UDP socket to one
selected upstream, sends the payload unchanged, waits for one reply, and sends
that reply back to the original source address/port. Then the exchange ends.
There is no persistent flow table; repeated packets from the same source can
use different members and upstream source ports. Only the connected upstream
peer can reply to that socket, but this is not application authentication.
Additional replies are not streamed back to the client.

The same upstream may serve real DNS, but qualification with arbitrary bytes
does not prove DNS correctness. Set caps for the application's actual packets
and network MTU; Fluxheim does not rewrite oversized DNS replies with a TC bit.

## Evaluate One-Way Syslog Forwarding

[Complete syslog example](../../examples/udp/syslog.toml) listens at
`127.0.0.1:15514` and forwards to `127.0.0.1:19514`. The route-specific section is:

```toml
[[udp.routes]]
name = "local-syslog"
mode = "syslog-forward"
listen = ["127.0.0.1:15514"]
upstream = "127.0.0.1:19514"
max_datagram_bytes = 8192
max_sessions = 64
max_sessions_per_source = 8
```

The process sends bytes, not parsed syslog events. It does not validate a
syslog RFC, alter timestamps, add client identity, encrypt messages or maintain
a durable spool. An upstream reply is not relayed. A successful local UDP send
does **not** prove the collector received or persisted anything.
`max_responses_per_source_per_second` has no effect on one-way mode because
there are no downstream replies; it is not an ingress rate limiter.

## Selection And Passive Health

Inside a route, replace the singular `upstream` with a plural list:

```toml
upstreams = ["127.0.0.1:19053", "127.0.0.1:19054"]
upstream_weights = [2, 1]
upstream_aliases = ["dns-a", "dns-b"]
passive_health_enabled = true
passive_health_failures = 3
passive_health_ejection_secs = 10
```

With healthy members this selects A, A, B in repeated weighted cycles. Without
weights all members have weight one. Selection is per datagram, not per client,
DNS name, geographic region or session. There is no backup/drain list or active
health-check configuration on this UDP path.

A failed exchange is **not replayed** to another member. Passive failures affect
later packets. When the failure threshold is reached, the member is skipped
until its ejection deadline; selection scans subsequent members for a ready one.
If every member is ejected, the originally weighted candidate is still tried.
Successful completion clears both failure and ejection state, including a
success from work already in flight. With concurrent packets, success/failure
order is completion order, not original receive order.

Timeout/connect/send/receive errors can count as failures. Oversized upstream
replies and locally response-rate-limited replies do not. In syslog mode the
runtime records a successful send as success, so passive health cannot reliably
detect a collector silently losing messages. Setting
`passive_health_enabled = false` disables ejection, not limits or diagnostics.

Hostnames use the system resolver during UDP connect. Unlike TCP streams, there
is **no private/reserved DNS-answer guard** and no corresponding allow-private
option. Trust your configured destinations and resolver. Numeric addresses
avoid hostname address-family ambiguity: numeric origins choose a matching
socket family; hostname origins use the listener's family for the local socket.
Do not assume dual-stack hostname failover or TCP stream policy parity.

## Limits And Timeout Boundaries

A UDP "session" here means one in-flight datagram task, not a persistent client
connection. `max_sessions` is shared by all listeners of one route.
`max_sessions_per_source` groups by source IP, not source port: clients behind
the same NAT share it. Slots are acquired before copying/spawning admitted work
and returned on completion, timeout or cancellation. Rejected datagrams are
dropped; no error datagram or application retry is generated.

Both caps use zero as explicit unlimited. Keep nonzero caps: per-source
protection does not bound aggregate work from many distinct source IPs. Kernel
socket buffers, upstream capacity and the application's own retry strategy
still matter.

`response_timeout_secs` is used separately for UDP connect and for receiving
the first response. It is not a single end-to-end deadline. Send operations are
outside those timeout wrappers. One-way mode has a connect timeout but no reply
wait.

**Current limitation:** `idle_timeout_secs` is accepted and validated but
never stored or consumed by the runtime. It must currently be at least the
response timeout, yet does not create a flow expiry, total task deadline or
idle timer. Do not count on it to bound the entire exchange. The correction
will define meaningful timeout semantics or explicitly retire the unused knob.

`max_datagram_bytes` caps each inbound packet and each reply, not the sum of
bytes across an exchange or route. Oversized input is normally dropped before
upstream contact; oversized replies are dropped without notifying the client.
The default is 4096. Smaller application-appropriate limits reduce exposure;
the request/response recipe chooses 1232, not a guarantee against fragmentation.

**Current limitation:** at the maximum configured cap of 65507, Linux IPv6
can deliver a larger packet into the fixed 65507-byte receive buffer. The runtime
sees the truncated length equal to the cap and forwards it. The live test sends
65508 bytes and the origin receives 65507. This violates whole-datagram/drop
semantics. Until fixed, keep the cap **below 65507**, preferably far below it;
do not treat truncated packets as validated application messages. Upstream
reply buffering separately reserves cap-plus-one to detect over-limit replies.

## Response Rate And Exposure

`max_responses_per_source_per_second` limits downstream responses, after the
upstream has already been contacted and replied. It does not limit requests
sent to a backend, total bytes per second or amplification ratio.

The counter uses fixed wall-clock second windows, not a sliding window/token
bucket. A burst on each side of a second boundary can exceed the configured
count within a short interval. Old entries are cleared on the next window.
Tracked distinct sources are bounded by
`max(4096, max_sessions, max_sessions_per_source)`; a new source is denied when
that table is full. Zero disables response-rate tracking entirely. Passive
ejection timestamps also use wall clock; time adjustments affect these policies.

UDP source IPs can be spoofed outside a trusted network. A tiny query can cause
a much larger reply, so this can become a reflector. Neither per-source budgets
nor a non-loopback startup warning make a public listener safe. Bind beta
listeners to loopback or a tightly controlled network and enforce ingress and
egress restrictions outside Fluxheim. There is no UDP `allow_sources`, bearer
authentication or trusted PROXY framing option. Do not copy HTTP/TCP ACL
settings into this route and assume they run.

For a deliberate container experiment, the custom image must contain a binary
compiled with `udp-proxy`. Publish only the intended UDP port, for example
`127.0.0.1:15353:15353/udp`; a default TCP port mapping will not carry UDP.
The container listener must be reachable through that mapping. This guide does
not qualify public exposure or claim a native-platform/container release gate.

## Complete Options

All route options below belong to `[[udp.routes]]`. Unknown fields are rejected.
Timeout values are integer seconds. Options with defaults may be omitted.

| Option | Default | Meaning and accepted range |
| --- | --- | --- |
| `[udp].enabled` | `false` | Requires `udp-proxy` when enabled; enabled config needs routes |
| `[udp].routes` | Empty | At most 64; routes with enabled=false are rejected |
| `name` | Required | Nonempty, at most 128 bytes; unique ignoring ASCII case |
| `mode` | `dns-load-balance` | Also `syslog-forward`; QUIC/game values reserved and rejected |
| `listen` | Empty | Required numeric socket addresses, at most 64 per route; duplicate strings across UDP routes rejected |
| `upstream` | Absent | One host:port, mutually exclusive with plural form |
| `upstreams` | Empty | 1..64 unique host:port authorities, compared ignoring ASCII case |
| `upstream_weights` | Empty | Plural only; one per upstream, 1..1000 each, total at most 65535 |
| `upstream_aliases` | Empty | Plural only; one per upstream, unique ignoring ASCII case; 1..64 ASCII letters/digits/dot/underscore/dash |
| `idle_timeout_secs` | `30` | 1..86400; validation only in current runtime, see the documented limitation |
| `response_timeout_secs` | `3` | 1..86400 and at most idle timeout; separate connect/reply budgets |
| `max_datagram_bytes` | `4096` | 1..65507 per packet; avoid maximum until the documented limitation is fixed |
| `max_sessions` | `4096` | 0..1000000 in-flight datagrams per route; zero unlimited |
| `max_sessions_per_source` | `64` | 0..1000000 per source IP; zero unlimited |
| `max_responses_per_source_per_second` | `256` | 0..1000000 replies/source/epoch second; zero unlimited |
| `passive_health_enabled` | `true` | Enable failure-based member ejection |
| `passive_health_failures` | `3` | 1..1000 when enabled; otherwise ignored |
| `passive_health_ejection_secs` | `10` | 1..86400 when enabled; otherwise ignored |

The current alias error text incorrectly mentions 128 bytes and colons; the
shared validator actually enforces the 64-byte/no-colon rule above. The
configuration-contract work in the local follow-up includes correcting this diagnostic.

An included `[udp]` fragment replaces the **whole UDP configuration**, not only
the fields it spells out. Include its enabled flag and complete route list.
UDP changes are classified as requiring process restart; the admin API is not
a live route/member editor, and existing datagram tasks are not migrated.

## Observe And Troubleshoot

Compile `metrics` and enable a private metrics listener to scrape:

```toml
[metrics]
enabled = true
listen = "127.0.0.1:9091"
require_loopback = true
# token_file = "/etc/fluxheim/secrets/metrics-token"
```

| Metric | Interpretation |
| --- | --- |
| `fluxheim_udp_datagrams_total{route,mode,direction,outcome}` | Stage events, not unique packets: one exchange can count downstream accepted, upstream sent and downstream sent |
| `fluxheim_udp_drops_total{route,reason}` | Local size/admission/response-rate drops; upstream timeouts instead produce upstream error events |
| `fluxheim_udp_active_sessions{route}` | In-flight tasks, not distinct clients; see unlimited-cap defect below |

Modes use bounded underscore labels such as `dns_load_balance`; route names
come from configuration. No DNS questions, syslog messages or client IPs become
metric labels. Logs can contain source addresses and configured member labels.
Drop and ejection warning logs are throttled per route; do not infer exact drop
counts from warning line counts. Upstream failure debug logs are separate.

**Current limitation:** `max_sessions = 0` disables the active counter as
well as the cap. The gauge then reports zero while real work is pending, even
when per-source accounting still holds a slot. Keep a finite cap if monitoring
this gauge; zero is not proof that the route is idle. The correction will
separate counting from enforcement and qualify concurrent gauge updates.

With `admin` and `udp-proxy` compiled, authenticated control-token
`GET /_fluxheim/udp/status` reports **configured** route counts, limits and public
exposure warnings. It does not report live ejections, reachability, queued work
or delivery acknowledgements. Observer tokens cannot access this endpoint.

| Symptom | Check |
| --- | --- |
| Configuration rejected | Beta feature, reserved mode, enabled/routes combination and singular/plural upstream conflict |
| No reply | Upstream service, request/response versus syslog mode, caps, firewall and response timeout |
| Failure despite another healthy member | No replay; health affects future packets only |
| One source port works and another drops | Per-source limits are shared by IP, including NAT clients |
| Syslog reports sent but collector is empty | UDP send success is not delivery or durability proof |
| Zero active gauge with traffic | Unlimited route cap currently disables accounting |
| Changed route has no effect | UDP service restart required; check include replacement semantics |

## Reproduce The Guide Checks

```sh
cargo build --locked --bin fluxheim --no-default-features --features udp-proxy,metrics
python3 scripts/smoke_udp_examples.py
sh scripts/smoke_udp_proxy.sh
```

The guide smoke uses only loopback sockets and the trusted local binary. It
requires working IPv6 for the maximum-size characterization and fails rather
than silently skipping that proof. It verifies raw request/response, one-way
delivery, selection, caps, passive ejection, rate-window recovery and metrics.
It does not run a real DNS resolver or qualify QUIC, production load, public
reflection resistance, Windows/macOS or container networking.

Known-defect assertions describe today's behavior, not a successful fix. Follow
the [coverage ledger](../reference/documentation-coverage.md) and
[correction plan](../roadmap/observability-commit-plan.md) before changing claims.
