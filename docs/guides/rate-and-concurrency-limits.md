# Rate and Concurrency Limits

Rate limits control how frequently a client can start work. Concurrency limits
control how much request-handler work may run at once. They solve different
problems and often belong together: a slow origin can exhaust capacity even at
a modest request rate, while a fast origin can receive too many requests without
ever reaching a concurrency cap.

Both are local to a Fluxheim process and configured per vhost and/or route.
They are not distributed quotas, billing counters or application authentication.
Use [access policy](access-control.md) and application authorization separately.
TCP stream limits and PHP-pool capacity have separate controls.

Two current limitations matter when sizing a deployment:

- **Current limitation:** `table_max_entries` is rounded across 16 independent shards.
  A value of 1 currently allows 16 identities, not one. A busy shard can also
  reject new identities while other shards have spare capacity.
- **Current limitation:** HTTP takeover releases concurrency permits before the
  upstream WebSocket handshake/tunnel. Two active tunnels can pass limits of
  one. Ordinary handler permits also end before writing the response downstream;
  they are not a full connection/download-lifetime budget.

Commits 70 and 71 track these corrections. Do not treat these settings as a
complete connection or memory ceiling. Keep independently qualified listener,
upstream and deployment-level resource controls in place.

## Start With a Small Local Example

The [complete recipe](../../examples/limits/local.toml) forwards to a loopback
origin on port 9001. The vhost allows one active handler and rejects excess work
immediately. `/limited` additionally allows one request per second per client,
with an initial burst of one. Other paths have no rate limit in this demo.

```toml
[vhosts.concurrency]
enabled = true
max_in_flight = 1
max_queue = 0
queue_timeout_ms = 0
status = 503

[[vhosts.routes]]
name = "limited"
path_prefix = "/limited"
[vhosts.routes.proxy]
upstreams = ["127.0.0.1:9001"]
[vhosts.routes.rate_limit]
enabled = true
requests_per_second = 1
burst = 1
status = 429
```

These tiny values make tests observable; they are not recommended production
capacity. Measure origin latency, resource use and burst requirements before
choosing production limits. Requests from users behind the same NAT may share
one client-IP bucket.

## Every Rate-Limit Option

The fields are identical under `[vhosts.rate_limit]` and
`[vhosts.routes.rate_limit]`. There is no global `[rate_limit]` table.

| Field | Default | Meaning / validation when enabled |
| --- | --- | --- |
| `enabled` | `false` | Activate this scope's token buckets. |
| `requests_per_second` | `0` | Refill rate; must be an integer from 1 to 1,000,000 when enabled. |
| `burst` | `0` | Bucket capacity, not extra requests added to the rate. Zero uses requests_per_second; otherwise 1 to 1,000,000. New buckets start full. |
| `status` | `429` | HTTP rejection code; any integer 400 through 599 is accepted. |
| `table_max_entries` | `65536` | Intended identity-table budget; 1 to 1,000,000. Current sharded rounding is described below. |
| `entry_ttl_secs` | `300` | Inactive-entry cleanup threshold; 1 to 86,400 seconds. Not a periodic reset of every bucket. |
| `mode` | `nodelay` | `nodelay` spends available tokens or rejects; `delay` reserves future capacity and waits within limits. |
| `max_delay_ms` | `1000` | Maximum individual rate-delay decision. At most 60,000; must be positive in delay mode. Zero is accepted in nodelay mode. |
| `reject_indeterminate` | `false` | Reject when client IP is unavailable; otherwise missing identities share one anonymous bucket in this scope. |

Unknown fields and invalid TOML types/enums fail parsing. Disabled rate policy
skips these numeric validation checks; revalidate before enabling it. Disabled
does not mean permissive parsing of unknown names or arbitrary types.

### Token-Bucket Behavior

For example, `requests_per_second = 10` and `burst = 20` starts with 20 tokens,
consumes one per admitted rate decision, and replenishes continuously at ten
per second up to 20. It is not a fixed calendar-second counter. The bucket is
per client IP, not per URL, method, login, request ID or API key.

With no trusted proxy context, the socket peer determines the client. Only
configured trusted peers may supply the forwarded chain used by ACL/rate
selection. [Request forwarding](request-headers.md) explains the current
ACL/upstream identity mismatch; do not widen trust to evade a shared bucket.
In privacy builds, forwarded-header restoration is disabled, so a proxy may
share one peer-IP bucket. Existing validated listener effective context remains
distinct from trusting an arbitrary HTTP header.

Newly constructed policies start with empty tables/full new buckets. State is
in memory, not durable or shared between processes. Restart or policy
reconstruction is not a way to preserve a strict long-term client quota.

### Delay Mode

```toml
[vhosts.rate_limit]
enabled = true
requests_per_second = 20
burst = 10
mode = "delay"
max_delay_ms = 250
reject_indeterminate = true
```

Available tokens still proceed immediately. When depleted, delay mode reserves
future tokens and sleeps; it rejects when debt is already at the burst boundary
or the calculated wait exceeds max_delay_ms. This is not an unlimited queue.
Cancelling a delayed request does not refund its reserved rate token; elapsed
time refills the bucket normally.

Pair delay mode with enabled concurrency limits. Ordinary request processing
holds the vhost permit during vhost delay and the relevant route permits during
route delay. Without enabled concurrency controls, a short sleep is not by itself
a bound on the total number of tasks. Different scopes have separate waits;
max_delay_ms is not a single end-to-end request deadline.

### Table Size and Cleanup

The native implementation splits identities among 16 shards. Each gets
`ceil(table_max_entries / 16)` slots, at least one. Thus the current total can
exceed the configured number by up to 15; a value of 1 allows 16. Choosing a
multiple of 16 avoids rounding but does not avoid uneven-shard exhaustion.
This behavior is tracked by the documented limitation, not advertised as an exact total cap.

When a shard is full and a new identity arrives, cleanup examines at most 128
queued entries and no more often than once per second per shard. Entries whose
last-seen age is strictly greater than the TTL can be removed. If the shard
remains full, the new identity receives the configured rejection status. Existing
identities are not evicted merely to admit a new one. Rejected checks of existing
buckets still refresh their last-seen time. Expired entries may remain until
capacity pressure triggers scanning; TTL does not mean immediate deletion.

## Every Concurrency Option

The same settings work under `[vhosts.concurrency]` and
`[vhosts.routes.concurrency]`.

| Field | Default | Meaning / validation when enabled |
| --- | --- | --- |
| `enabled` | `false` | Activate this scope's shared semaphore and waiting count. |
| `max_in_flight` | `0` | Active handler permits; 1 to 1,000,000 when enabled. Shared across client IPs. |
| `max_queue` | `0` | Waiting tasks; 0 to 1,000,000. Zero derives min(4 * max_in_flight, 1,000,000), rather than disabling the queue. |
| `status` | `503` | Rejection code; 400 through 599. |
| `queue_timeout_ms` | `0` | Zero rejects immediately when no permit is available. Positive values allow waiting, at most 60,000 milliseconds per acquisition. |

To disable waiting, use **queue_timeout_ms = 0**, not max_queue = 0.
A small bounded queue can absorb a short spike:

```toml
[vhosts.concurrency]
enabled = true
max_in_flight = 32
max_queue = 16
queue_timeout_ms = 100
status = 503
```

When active capacity is exhausted, a request joins only if a queue slot is
available. It rejects immediately when the queue is full, or on timeout while
waiting. Dropping a queued acquisition releases its queue slot; dropping a held
permit releases active capacity. A cloned handler shares these budgets, rather
than creating fresh capacity for each connection. Disabled policies skip numeric
validation just as rate policies do.

An admitted vhost request may hold its vhost permit while waiting for a route
permit. Therefore one busy route can consume shared vhost capacity. Queue sizes
are per scope and not one global memory allocation budget.

### Lifetime Limitation

Normal route handling acquires permits around action execution and drops them
when the response object is returned. The connection layer writes that response
afterward. A slow download or subsequent response-body processing is not covered
by a promise that the handler permit survives until the client finishes.

The takeover path explicitly drops its permits even earlier: before upstream
WebSocket handshake/tunnelling. The live example opens and exchanges frames on
two tunnels while both vhost and route max_in_flight equal one. This is
the documented limitation. It does not mean all server-wide transport protections are absent,
but these route/vhost settings do not currently cap simultaneous tunnels.

## Scope, Ordering and Rejections

Ordinary request handling checks access first, then acquires vhost concurrency,
checks/waits for vhost rate, acquires route concurrency and checks/waits for route
rate before executing the selected action. Both vhost and route limits apply;
disabling a route limiter does not disable its vhost limiter. Different route
policies have separate state, while the vhost rate budget spans its routes.

The decoded-policy route and selected route can both contribute limits, without
double-checking the same route object. The takeover path currently chooses only
one of that pair; full admission parity belongs in the the local follow-up review. This
is source-reviewed scope, not new live proof of an encoded WebSocket bypass.

Rate consumption is not transactional across scopes. For example, a vhost token
already spent is not refunded if route admission later rejects. Failed origin
requests also consume admission. ACL rejections occur before rate consumption;
requests with no action can return 404 before admission. These are not successful
response quotas.

Generated rate and concurrency rejections include `Retry-After: 1`. It is a fixed
hint, not an exact next-slot calculation; selected status numbers may differ from
the generic HTTP/1 reason phrase. Ordinary HTTP/1 rejection closes the connection.
The early-response policy gap the documented limitation still applies. Do not assume a custom
error page or every response header is applied before admission.

The legacy `fluxheim_edge_policy_events_total` has no native production producer
for these decisions. Shared the local follow-up now covers auth, ACL and admission metric
wiring. Bounded operational security observations for rejected work are separate
from per-scope legacy policy counts; they are not proof that every allowed/delayed
decision was recorded. Inspect actual response codes and upstream contact as well
as [operational metrics](observability.md).

## Test and Troubleshoot

With the local origin available:

```bash
fluxheim --config examples/limits/local.toml --validate-config
fluxheim --config examples/limits/local.toml
curl -i -H 'Host: api.example.test' http://127.0.0.1:8080/limited
curl -i -H 'Host: api.example.test' http://127.0.0.1:8080/limited
```

Two requests within one refill interval should show a successful first response
and a 429 second response. A slow human pause may refill the token, so use the
bounded automated smoke for repeatable rejection, queued work and recovery:

```bash
cargo build --locked --bin fluxheim --no-default-features --features proxy,web,tls-rustls
python3 scripts/test_admission_examples.py
python3 scripts/smoke_admission_examples.py
```

The smoke starts actual loopback server/origin processes, holds a request with
explicit synchronization, observes rejection and recovery, and reproduces both
open findings. Native unit tests separately cover cancellation, queue fullness,
missing identity and frozen token accounting. A local functional smoke is not a
load benchmark, native-platform qualification or denial-of-service guarantee.

| Symptom | Check |
| --- | --- |
| Many users share 429s | NAT/proxy peer identity, trusted-proxy configuration, privacy behavior and vhost-wide bucket. |
| A new client is rejected despite low rate | Its table shard may be full; TTL cleanup is pressure-driven. |
| max_queue = 0 still waits | Zero derives queue capacity; set queue_timeout_ms to zero to disable waiting. |
| 503 while another route is busy | Shared vhost concurrency, including its delayed or route-waiting requests. |
| Delayed client retries too soon | Retry-After is fixed, scopes are independent, and consumed tokens are not refunded. |
| More than one tunnel with max_in_flight = 1 | the documented limitation; do not rely on handler permits for tunnel lifetime. |
| Counters stay empty | Missing legacy native producers; the local follow-up, not evidence that admission was unused. |

The [coverage ledger](../reference/documentation-coverage.md) separates new Linux
HTTP/1.1/WebSocket proof from still-required HTTP/2, TLS, container and native
Windows/macOS qualification. No runtime fixes are delivered by this guide.
