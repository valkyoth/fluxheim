# Load Balancing

Fluxheim can distribute HTTP requests across several application servers. Each
server is a **backend**; the group of servers is a **pool**. Health checks remove
unavailable members from selection, and an optional persistence policy keeps a
client on the same available member.

Start with two identical application instances and round-robin selection. Add
affinity only if the application actually needs it. A shared session store is
usually easier to operate than depending on a particular application instance.

This guide covers native HTTP proxy pools. TCP stream routing has its own
[configuration](../reference/config-reference.md#tcp-stream-proxy); do not assume
that HTTP cookies, response-status rules or HTTP retry behavior apply to it.
For every field and default, see the
[load-balancer option reference](../reference/load-balancer-options.md).

## Before You Start

Use a binary with `proxy` and `load-balancer` enabled. The packaged load-balancer
profile includes them. For a small local HTTP-only build:

```sh
cargo build --locked --no-default-features --features proxy,load-balancer --bin fluxheim
```

Use a TLS-enabled [profile](../reference/features.md) for an Internet-facing
deployment. The examples below intentionally bind only to loopback and do not
configure certificates, public DNS, an admin listener or a metrics listener.

**Latency scope:** native HTTP supplies final-response-header wait samples to
`least-time` and passive `max_latency_ms`. These are not full response times;
use the measurement boundary below when choosing a threshold. See
[retry and latency boundaries](#retry-and-latency-boundaries).

## Try Two Local Backends

Run these commands from the repository root, each in a separate terminal:

```sh
python3 -m http.server 9001 --bind 127.0.0.1 --directory examples/load-balancer/origin-a
```

```sh
python3 -m http.server 9002 --bind 127.0.0.1 --directory examples/load-balancer/origin-b
```

Both serve `/healthz`; their home pages identify the origin. The complete
[local configuration](../../examples/load-balancer/local.toml) contains this pool:

```toml
[proxy]
upstreams = ["127.0.0.1:9001", "127.0.0.1:9002"]
upstream_aliases = ["app-a", "app-b"]
upstream_weights = [1, 1]
upstream_tls = false
connect_timeout_secs = 1
read_timeout_secs = 3

[proxy.load_balance]
selection = "round-robin"
all_down_status = 503

[proxy.load_balance.health_check]
enabled = true
protocol = "http"
path = "/healthz"
interval_secs = 1
consecutive_success = 1
consecutive_failure = 1
expected_statuses = [200]
expected_body_contains = ["ready"]
connect_timeout_secs = 1
read_timeout_secs = 1
```

Validate and start Fluxheim in a third terminal:

```sh
target/debug/fluxheim --config examples/load-balancer/local.toml --validate-config
target/debug/fluxheim --config examples/load-balancer/local.toml
```

Send several requests in another terminal:

```sh
for attempt in 1 2 3 4 5 6; do
    curl --fail --max-time 5 http://127.0.0.1:8088/
done
```

You should see both `origin-a` and `origin-b`. Stop origin A with Ctrl-C, wait a
few health-check intervals, and repeat: only B should respond. Restart A and it
should rejoin after a successful probe. Stop both origins and Fluxheim returns
503 once neither is selectable. During failure detection a request can instead
receive a transport-error response; health checks are not instantaneous.

The Python servers are test fixtures, not production application servers. Stop
all three processes with Ctrl-C when finished. On Windows, use the `.exe` binary
and repeat `curl.exe` requests instead of the shell loop.

## Apply The Recipes

`local.toml` is a complete configuration. The other files in
[examples/load-balancer](../../examples/load-balancer/) are annotated fragments.
Edit matching fields into the existing tables; **do not concatenate duplicate
`[proxy]` or `[proxy.load_balance]` tables**. The discovery recipes replace the
whole proxy block, including its nested tables, because a pool cannot use static
members and a discovery feed simultaneously.

The same pool settings can live under `[vhosts.proxy]` or
`[vhosts.routes.proxy]`. Use the corresponding nested prefix for its
`load_balance` tables. Keep the members and policy together; consult
[vhost configuration](vhost-config.md) for inheritance and route matching rather
than assuming that separate route pools share counters or persistence entries.

## Select Backends

| Need | Selection | What to expect |
| --- | --- | --- |
| Similar, stateless application instances | `round-robin` | Weighted distribution over eligible members; not a promise of exact alternation |
| Requests with different processing times | `least-connections` | Lowest weighted number of in-flight request permits, not the number of idle TCP sockets |
| Spread new sticky sessions | `least-sessions` | Lowest weighted number of local persistence entries; requires persistence enabled |
| Low-cost approximate balancing | `power-of-two` | Compare sampled candidates using current load |
| Stable mapping by source, URI, header or cookie | `*-hash` families | Use the matching request key; missing keys fall back rather than authenticating a client |
| Reduce remapping during membership changes | `consistent-*-hash` | Consistent hashing; not shared cross-node session state |
| Consistent hashing with load escape | `bounded-load-consistent-*-hash` | Allows selection away from the preferred hash member when its load is excessive |
| Static compatible hash layout | `nginx-consistent-*-hash` (Ketama), `maglev-*-hash` | Static-ring restrictions apply; no discovery or runtime backend-set edits |
| Latency-aware balancing | `least-time` | Prefer the lowest weighted response-header latency; unknown/stale eligible members are sampled first |

For a header key, change these fields in the pool:

```toml
[proxy.load_balance]
selection = "consistent-header-hash"
hash_header = "x-session"
```

For a cookie key, use `selection = "consistent-cookie-hash"` and
`hash_cookie = "session"`, removing `hash_header`. A bounded-load selector can
add `bounded_load_factor_per_mille = 1250`; larger values tolerate more imbalance.
The [reference](../reference/load-balancer-options.md#selection) lists all names,
aliases and required companion fields.

Source-based selection uses the native request's effective/peer address. Do not
assume an arbitrary `X-Forwarded-For` value changes that key. Configure trusted
ingress and PROXY protocol deliberately. Client-supplied headers and cookies are
not credentials, even when they are useful routing keys. Hashing is not an
authorization or tenant-isolation boundary.

## Weights, Tiers And Capacity

The lists alongside `upstreams` are positional: the first weight, locality and
limit belong to the first address. Keep them aligned when editing members.
Aliases give operators readable names; tags are status metadata, not selectors.

The [pool-policy recipe](../../examples/load-balancer/pool-policy.toml) illustrates
weights, priority groups, locality preference and in-flight limits together.
A weight of 2 versus 1 requests roughly twice the share with weighted round-robin;
least-connections instead compares load relative to weight. A cap limits active
request permits for that backend, not all connections to that machine.

Higher priority groups are preferred. `upstream_priority_group_min_active`
controls when lower groups are needed. Preferred localities are a preference
with fallback, not a strict regional routing or data-residency guarantee.

For a dedicated spare, use a third backend:

```toml
[proxy]
upstreams = ["10.0.0.10:8080", "10.0.0.11:8080", "10.0.1.10:8080"]
upstream_weights = [2, 2, 1]
backup_upstreams = ["10.0.1.10:8080"]
```

`drain_upstreams` and `disabled_upstreams` also contain configured addresses,
not aliases. They prevent new selection; they do not kill requests already in
flight. Backup, drain and disabled lists cannot overlap. Keep at least one
normal primary member in the static configuration. Use
[admin member controls](#operate-a-pool) for temporary maintenance instead of
repeatedly editing the configuration.

## Health Checks

Active checks run independently of customer requests. **They are enabled by
default**, using TCP checks every second. A successful TCP connection proves
reachability, not that an application or its database is ready.

| Protocol | What the monitor proves | Configuration example |
| --- | --- | --- |
| `tcp` | Connection establishment, with the configured upstream TLS policy where applicable | Set `protocol = "tcp"`; remove HTTP matchers |
| `http` | HTTP status and optional headers, body strings and JSON scalars | [HTTP recipe](../../examples/load-balancer/http-health.toml) |
| `grpc` | Standard gRPC health service reports serving | Set `protocol = "grpc"`, optionally `grpc_service = "my.application.Service"`; remove HTTP response matchers |
| `exec` | An explicitly allowlisted local helper exits successfully within its timeout | [Exec monitor](../../examples/load-balancer-exec-health.toml) |
| `redis` | Redis responds to a PING probe | [Redis monitor](../../examples/load-balancer-redis-health.toml) |
| `mysql` | MySQL/MariaDB handshake is recognizable | [MySQL monitor](../../examples/load-balancer-mysql-health.toml) |
| `postgres` | PostgreSQL responds to the pre-authentication SSLRequest probe | [PostgreSQL monitor](../../examples/load-balancer-postgres-health.toml) |

Database monitors do not log in, run application queries or prove schema health.
The Redis/MySQL/PostgreSQL monitors currently reject `upstream_tls = true`;
their probes are not TLS-enabled database clients.
They monitor a pool; they do not turn an HTTP proxy into a database proxy. Use
the appropriate TCP stream route for database traffic.

The advanced HTTP recipe expects `/healthz` to return status 200, header
`x-health-state: ready`, and a body such as:

```json
{"status":"ready","checks":{"database":true}}
```

Status values/ranges are alternatives; the other configured matchers must all
pass. With both status lists empty, exactly 200 is accepted. The simple Python
origins above do not send the extra header, so use the base recipe for them or
implement the advanced contract in your application.

Increase `consecutive_failure` to avoid removing an origin for one transient
failure, and `consecutive_success` to require stable recovery. `parallel = true`
probes members concurrently for supported protocols. Set timeouts below the
operational detection delay you can tolerate; a shorter interval alone cannot
make a slow probe finish sooner.

`X-Health-Weight` on an HTTP health response can reduce effective member weight,
bounded by `health_weight_min_percent`. It does not bypass failed readiness
checks. Only let trusted application instances supply this signal.

`reuse_connection = true` is accepted but does not currently reuse connections
in the native health client. `port_override` is applied by HTTP/gRPC monitors,
not the TCP monitor. Use a genuinely separate HTTP readiness port only with the
appropriate monitor type.

Exec helpers run as the Fluxheim service identity, without a shell and with a
restricted environment. They receive backend address/host/port through
`FLUXHEIM_HEALTH_BACKEND_ADDR`, `FLUXHEIM_HEALTH_BACKEND_HOST` and
`FLUXHEIM_HEALTH_BACKEND_PORT`. They are trusted local programs, **not sandboxed
plugins**. Keep secrets out of arguments; helpers should read protected files.
Do not depend on timeout handling to contain arbitrary helper descendants.

## Passive Health, Slow Start And Queueing

Passive checks observe actual transport failures and configured error responses.
After enough consecutive failures, the member is temporarily ejected. This is
separate from the active probe: a passing `/healthz` does not imply every request
works. Use [queue-passive.toml](../../examples/load-balancer/queue-passive.toml)
as a starting point.

With no explicit passive status list/ranges, all 5xx responses count as failures.
Specify `failure_statuses` or `failure_status_ranges` to narrow this. The minimum
healthy-member setting affects selection during ejection; it is not a promise
that the application always has that many healthy servers. In status, an `open`
circuit means passive ejection, not a separate configurable circuit-breaker.

Slow start gradually introduces newly seen and passively recovered members. It
is a selection ramp, not a hard requests-per-second limit; fallback can bypass
the ramp when otherwise no member is available.

Queueing is disabled by default. Set **both** `max_waiting` and `timeout_ms` to
positive values to wait briefly when no member can be selected. The queue is
bounded per pool and retries selection at `retry_interval_ms`. It does not
reserve a backend permit while waiting, guarantee FIFO fairness, or replace
application capacity planning. If admission/waiting fails, the first selection
returns `all_down_status` (502 by default; the example uses 503).

## Retry And Latency Boundaries

The unreleased 1.9.0 native HTTP pool dispatcher applies
`[proxy.load_balance.retry]` to ordinary requests, foreground revalidation,
background stale-while-revalidate and origin slice fills. This is a behavior
change: **disabled (the default) now means one application attempt per origin
fetch, with no pool
failover or hidden HTTP/1 connection-pool/HTTP/2 request replay**. Enable retries
explicitly when your service needs them:

```toml
[proxy.load_balance.retry]
enabled = true
max_retries = 1
methods = ["GET", "HEAD", "OPTIONS"]
statuses = [503]
budget_per_window = 100
budget_window_secs = 10
```

The initial attempt is not a retry. `max_retries = 1` allows at most two
application sends per origin fetch, and `0` allows only the initial send. Only configured safe
methods with an empty body, no trailers and no upgrade request can be replayed.
WebSocket/CONNECT tunnels are not retried. A transport failure does **not** prove
that the origin never received the request; safe-method application handlers
must genuinely tolerate replay.

Transport errors are eligible when retries are enabled. A received HTTP response
is eligible only when its status matches `statuses` or an inclusive
`status_ranges` entry. Each backend address is attempted at most once per
dispatch. Selection still respects health, capacity, priority and persistence,
but persistence cannot send a retry back to an already attempted member. If no
alternative is selectable, Fluxheim stops and handles the last response/error
normally, including stale-if-error and configured error pages. Only the initial
selection may enter the admission queue; retries do not wait for another slot.

`budget_per_window` limits retry admissions shared by the same pool's requests
and cache workers. When `enabled = true` and `max_retries > 0`, you must explicitly
set a value from 1 to 1000000; an omitted or zero budget is rejected. Runtime
admission also denies all retries for a zero budget if a programmatic caller
bypasses configuration validation. Disabled retries and `max_retries = 0` may
retain the default zero budget. Budget
windows use a monotonic clock and reset when the next reservation observes an expired
window. A new pool/configuration rebuild starts a new budget; this is not a
process-wide, cluster-wide or restart-persistent limit. Separately constructed
pools have separate budgets, so account for all pools when sizing aggregate
origin capacity. There is no global retry semaphore or token bucket. Prefer a
small budget during origin failures and combine it with admission/in-flight
limits; a large explicitly configured budget can still amplify traffic.
Unused reservations are returned.
An admitted send remains charged if it subsequently fails or is cancelled.
Status exposes the cumulative `retry.admitted` count for that pool instance;
ordinary request telemetry records each application attempt separately.

Responses remain buffered and bounded by the configured upstream limits before
downstream delivery. A slice fetch keeps its tighter slice-body cap on every
attempt. Multiple slices and a full-response fallback after an unsuccessful
slice fetch are separate origin fetches. Their initial sends do not consume
retry budget, but their retries share the same pool budget: fallback does not
reset it. Consequently, `max_retries` is not a bound on all origin requests
needed to assemble one downstream ranged response; also configure slice limits.
Use connection/read/write timeouts and in-flight caps as well: the retry count
does not impose a new end-to-end wall-clock deadline. Protocol negotiation
(including an h2c probe) is distinct from replaying the application request.

These settings apply to a native HTTP load-balancer pool (multiple configured
members or discovery), not to a single static upstream, static-proxy-only builds,
PHP/FastCGI or raw TCP/UDP. See the complete
[retry fragment](../../examples/load-balancer/retry-contract.toml).

### What Latency Measures

Native HTTP/1.1 and HTTP/2 measure **response-header wait** with a monotonic
clock: from handing the completed outbound request to the upstream transport
until the final response headers arrive. Informational responses do not end
the measurement. Connection/TLS setup, pool/queue waits, request upload,
response-body transfer, downstream backpressure and WebSocket tunnel lifetime
are excluded. This is neither end-to-end latency nor proof that the origin
application processed the request within that time.

A sample is published only after the bounded upstream response completes
successfully. A complete 4xx/5xx response still supplies a sample; its status may
also count as a passive failure. Transport/protocol/body failures count through
the existing failure policy without a latency sample. Cancellation supplies
neither a sample nor an invented failure and releases the connection permit.
Each retry reports only its own attempt. Cache hits supply no samples;
revalidation and slice origin fetches do. Active probes and upgraded tunnels do
not train this estimator. A successful response is not retried solely because
its latency crossed the passive threshold.

`least-time` stores a per-member microsecond EWMA (75% previous, 25% newest,
rounded to nearest) and compares latency divided by effective weight, using
weighted in-flight requests to break ties. Samples are clamped to at least one
microsecond. An eligible member without a sample is tried before sampled
members. After 30 seconds without a completed sample, its selection score becomes
unknown so ordinary traffic can try it again; the next sample replaces its stale
EWMA. Resampling needs traffic, remains subject to health, priority, affinity,
backup and capacity rules, and is not a dedicated background probe. Concurrent
requests can select the same unsampled member; use per-member in-flight caps.

For example, merge this into an existing pool:

```toml
[proxy.load_balance]
selection = "least-time"

[proxy.load_balance.passive_health]
enabled = true
max_latency_ms = 500
consecutive_failure = 3
ejection_secs = 30
min_healthy_backends = 1
```

A completed sample **at or above** 500 ms counts as a failure. Setting
`max_latency_ms = 0` disables latency classification, not status/transport
failure handling. The same latency threshold works with other selectors too.
Existing minimum-healthy and strict-health/fail-open rules still govern whether
an ejected member can be selected. Do not tune this threshold using full-body
download time. Parsing a config is not live proof or release acceptance evidence.

## Keep Related Requests Together

Persistence maintains a bounded **local** table of keys and member assignments.
It still respects backend eligibility; it cannot force requests onto a dead or
drained member. Choose one mode:

```toml
[proxy.load_balance.persistence]
enabled = true
mode = "source-ip"
ttl_secs = 300
table_max_entries = 4096
```

- `source-ip`: convenient, but many clients behind NAT can share one key.
- `header`: change mode to `"header"` and add `header = "x-session"`.
- `cookie`: change mode to `"cookie"` and add `cookie = "session"`; the
  application must already provide the request cookie.
- `managed-cookie`: Fluxheim issues its own affinity cookie. Use
  [managed-cookie.toml](../../examples/load-balancer/managed-cookie.toml) and set
  its domain to your actual site, or omit the domain for a host-only cookie.

Remove the previous mode's `header`/`cookie` fields when switching. Missing or
unusable keys fall back to normal selection. Table entries are not authenticated
user sessions; `least-sessions` measures these routing entries only.

Managed cookies default to Secure, HttpOnly and SameSite=Lax. Use HTTPS in a
browser; the loopback HTTP demo is not a browser cookie deployment recipe.
SameSite=None requires Secure. The signing keys are process-local and rotate;
they are not shared across nodes or restored by the runtime state file. A
restart or another node can therefore invalidate an affinity cookie.
Persistence is unavailable in privacy-mode builds.

## Discover Backends

Select exactly one source. Use `host:port` authorities, not upstream URLs.

**File:** replace the proxy block with
[discovery-file.toml](../../examples/load-balancer/discovery-file.toml). Its
[backends.txt](../../examples/load-balancer/backends.txt) uses one address per
line and supports comments. Keep the file and its parents trusted and readable
by the service user. Relative file paths are resolved from the configuration.

**DNS:** [discovery-dns.toml](../../examples/load-balancer/discovery-dns.toml)
periodically resolves configured service names. Set
`upstream_dns_allow_private_backends = true` only when private application
networks are intentional. Without a refresh interval, hostname resolution does
not provide periodic DNS discovery.

**HTTP control plane:** [discovery-http.toml](../../examples/load-balancer/discovery-http.toml)
polls a numeric-loopback test service. A real remote service must use HTTPS and
return HTTP 200 with an address array:

```json
{"upstreams":["10.0.0.10:8080","10.0.0.11:8080"]}
```

A bare array is also accepted. Send `Content-Type: application/json`; if a
content type is supplied, it must be JSON-compatible. Responses are bounded to
64 KiB, redirects are not followed, and fetches have a five-second timeout.
Private backend addresses require the explicit allow-private flag. Protect any
bearer-token file and use HTTPS for secrets. Do not publish this discovery API
without authorization and independent control-plane protection.

Discovered sets must have 2-64 distinct addresses. Invalid later refreshes keep
the previous set; an unusable initial source cannot establish a working pool.
Static parallel attributes (weights, aliases, tags, priorities, localities,
caps and backup/drain/disabled lists) are incompatible with discovery. Maglev
and nginx/Ketama static-ring modes also reject discovery. When file/HTTP pools
use upstream TLS, configure the explicit shared server name and trust roots.

## Operate A Pool

Enable a protected [admin listener](../reference/config-reference.md#admin)
before using these routes. A control token is required; the observer token is
not a load-balancer management credential. Do not expose an unprotected admin
port to the Internet.

| Operation | API |
| --- | --- |
| Inspect pools and members | `GET /_fluxheim/load-balancer/status` |
| Drain, disable, force down, resume or restore a member | `POST /_fluxheim/load-balancer/member-state` |
| Override/reset weight | `POST /_fluxheim/load-balancer/member-weight` |
| Add, remove or retarget a runtime member | `POST /_fluxheim/load-balancer/member-add`, `member-remove`, `member-update` |
| Clear affinity entries | `POST /_fluxheim/load-balancer/persistence/clear` |

The [admin reference](../reference/config-reference.md#admin) gives query
parameters and examples, including vhost/route targeting. For a named vhost
`app`, `member=app-a&state=drain` stops new work on that member. Watch in-flight
requests reach zero before maintenance. Removal checks are best-effort rather
than a transaction that stops all concurrent requests.

Runtime weight overrides apply to round-robin, least-connections, least-sessions
and least-time, not the hash/static-ring or power-of-two selectors. Runtime
backend-set edits are for static mutable pools, not discovery or static-ring
pools. They are not written back to the TOML file.

Optional `runtime_state_file = "/var/lib/fluxheim/load-balancer/app.json"` under
the pool's `load_balance` table saves supported member overrides and persistence
entries across restarts. It does **not** persist runtime backend-set edits or
managed-cookie signing keys and does not replicate state between servers. Header
and cookie persistence can write identifying values to disk: protect the file,
its directory and backups accordingly. Provision the private directory before
startup; do not use a shared writable temporary directory.

Pools with background health/discovery services impose process-upgrade reload
constraints. Do not assume every pool edit is a live snapshot change. Use the
configuration validation/reload classification and
[upgrade workflow](zero-downtime-upgrades.md) for the installed platform.

## Observe And Troubleshoot

Use [metrics and tracing](observability.md) with admin status. Inspect member
health, disabled/drain/backup flags, effective weights, in-flight permits,
passive ejection, discovery refresh errors and persistence counts together.
`latency_micros = null` means no sample has been recorded by a `least-time`
estimator (or that this selector has no estimator); it never means zero latency.
The numeric value is the last EWMA, not a percentile or a freshness promise:
status retains an expired sample even while selection treats it as unknown.

| Symptom | Check |
| --- | --- |
| Startup says a module is not compiled | Use a profile containing `proxy` and `load-balancer` |
| All requests return 503/502 | Reachability, probe Host/path/status/body, upstream TLS/SNI, drain/disable flags, caps and queue saturation |
| Only one backend receives traffic | Affinity, priority/locality preferences, backup status, weights and health |
| Slow backend still selected | Check header wait versus body time, sample warm-up/30-second resampling, affinity, weights, priorities and minimum-healthy/fail-open policy |
| Configured 503 retries do not occur | Check pool/profile selection, `enabled`, method/body restrictions, remaining count/budget and eligible unattempted members |
| Cookie affinity disappears | Cookie domain/path/Secure rules, TTL/table capacity, process restart or another Fluxheim node |
| Discovery changes do not appear | Source validity, refresh errors, private-address policy and whether DNS refresh was enabled |
| Reload requires an upgrade | Background health/discovery service lifecycle, not necessarily invalid configuration |

For migration comparisons, see [nginx, HAProxy and F5 examples](load-balancer-migration.md).
For test coverage and unqualified boundaries, see the
[documentation coverage ledger](../reference/documentation-coverage.md).
