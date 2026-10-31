# Load-Balancer Options

Use the [load-balancing guide](../guides/load-balancer.md) for a runnable example
and operational explanations. This reference inventories the HTTP pool fields;
shared proxy transport, TLS, headers, body limits and timeouts remain in the
[proxy reference](config-reference.md#proxy).

Table paths below use global `[proxy]`. Under a vhost or route, replace that
prefix with `[vhosts.proxy]` or `[vhosts.routes.proxy]`. An omitted optional field
is different from an empty string. Defaults apply when not overridden/inherited.
Unknown fields are rejected. Invalid nested policy may be rejected even when its
`enabled` switch is false; disabling a section is not a syntax-validation bypass.

## Pool Members

All these fields belong to `[proxy]`. The local
[base](../../examples/load-balancer/local.toml) and
[pool-policy fragment](../../examples/load-balancer/pool-policy.toml) demonstrate
the positional lists. A static pool needs at least two distinct members and
accepts at most 64 configured members. Single-upstream proxying uses `upstream`
instead and is not a multi-member load balancer.

| Field | Default | Meaning and constraints |
| --- | --- | --- |
| `upstreams` | `[]` | Backend authorities, e.g. `["127.0.0.1:9001", "127.0.0.1:9002"]`; no URL scheme; do not combine with `upstream`, file or HTTP discovery |
| `upstream_weights` | `[]` (weight 1 each) | One integer per member, each 1-1000, total at most 65535 |
| `upstream_priority_groups` | `[]` | One integer 0-1000 per member; higher groups preferred |
| `upstream_priority_group_min_active` | `1` | Required active-member threshold before lower groups participate; at least 1, no more than member count; nondefault requires groups |
| `upstream_localities` | `[]` | One locality token per member |
| `preferred_upstream_localities` | `[]` | Unique configured localities to prefer, with fallback |
| `upstream_max_in_flight` | `[]` | One positive request-permit cap per member, at most 1000000 each |
| `upstream_aliases` | `[]` | One unique human-readable alias per member |
| `upstream_tags` | `[]` | One list per member, at most 16 unique tags each; descriptive, not routing conditions |
| `backup_upstreams` | `[]` | Configured addresses eligible as spare members |
| `drain_upstreams` | `[]` | Configured addresses excluded from new selection |
| `disabled_upstreams` | `[]` | Configured addresses administratively excluded |

Locality, alias and tag tokens are 1-64 ASCII letters, digits, `.`, `_` or `-`;
uniqueness comparisons are case-insensitive where required. Address subsets
must reference real members, cannot overlap, and cannot leave every static
member backup/drained/disabled. They take **addresses**, not aliases.

## Discovery

All fields below belong to `[proxy]`. Discovery rejects the static attribute
lists above and static-ring selectors. A refreshed set must contain 2-64 unique
addresses. DNS seeds may contain one service name that resolves to a valid set.
Refresh failures preserve the last accepted set, not a newly supplied bad set.

| Field | Default | Meaning and constraints |
| --- | --- | --- |
| `upstreams_file` | Omitted | Trusted local text file; one authority per non-comment line; replaces `upstreams`/`upstream`/HTTP source |
| `upstreams_file_refresh_secs` | `5` | 1-300 seconds |
| `upstreams_http_url` | Omitted | HTTPS control-plane URL, or HTTP with a numeric loopback IP; no credentials, query or fragment |
| `upstreams_http_refresh_secs` | `5` | 1-300 seconds |
| `upstreams_http_bearer_token_file` | Omitted | Protected bearer-token file; bounded to 4096 bytes; use HTTPS when transmitting secrets |
| `upstreams_http_allow_private_backends` | `false` | Permit private/loopback backend addresses returned by the feed, not permission to use a remote plaintext collector |
| `upstream_dns_refresh_secs` | Omitted | 1-300 seconds enables periodic resolution of `upstreams` service names |
| `upstream_dns_allow_private_backends` | `false` | Permit private/loopback discovered addresses; requires DNS refresh enabled |

Examples: [file](../../examples/load-balancer/discovery-file.toml),
[HTTP](../../examples/load-balancer/discovery-http.toml),
[DNS](../../examples/load-balancer/discovery-dns.toml). Each replaces the whole
base proxy block; do not retain its aliases/weights. File paths resolve relative
to their configuration file. File/HTTP discovery with upstream TLS requires an
explicit shared `upstream_sni`; configure trusted CA roots as for other proxies.
See the guide for response format, bounds and security requirements.

## Selection

These fields belong to `[proxy.load_balance]`:

| Field | Default | Meaning and constraints |
| --- | --- | --- |
| `selection` | `"round-robin"` | One of the selectors below |
| `hash_header` | Omitted | Required for header-hash selectors; valid HTTP header name; rejected for other selectors |
| `hash_cookie` | Omitted | Required for cookie-hash selectors; valid cookie-name token; rejected for other selectors |
| `max_iterations` | `256` | Positive candidate-inspection bound; keep bounded operationally rather than choosing an arbitrarily large value |
| `all_down_status` | `502` | HTTP 500-599 returned when first selection cannot obtain a member |
| `bounded_load_factor_per_mille` | `1250` | 1000-10000; a nondefault value requires bounded-load consistent selection |
| `runtime_state_file` | Omitted | Protected local state file; supported overrides/persistence only, not backend-set edits or managed-cookie signing keys |

| Canonical selector(s) | Aliases / requirements |
| --- | --- |
| `round-robin` | Weighted eligible-member rotation |
| `least-connections` | `weighted-least-connections`, `ratio-least-connections` |
| `least-sessions` | `least-session`; requires persistence enabled |
| `least-time` | Weighted EWMA of completed native HTTP response-header wait; eligible unknown/stale members are resampled after 30 seconds without a sample |
| `power-of-two` | `power-of-two-choices`, `two-choice`, `weighted-two-choice`, `weighted-random-two-choice` |
| `source-hash`, `uri-hash`, `header-hash`, `cookie-hash` | Header/cookie variants require the respective key name |
| `consistent-source-hash`, `consistent-uri-hash`, `consistent-header-hash`, `consistent-cookie-hash` | Salted consistent mapping; header/cookie key required |
| `bounded-load-consistent-source-hash`, `bounded-load-consistent-uri-hash`, `bounded-load-consistent-header-hash`, `bounded-load-consistent-cookie-hash` | Consistent mapping with load escape; header/cookie key required |
| `nginx-consistent-source-hash` | `ketama`, `ketama-source-hash`, `nginx-consistent-hash`; static pool only |
| `nginx-consistent-uri-hash`, `nginx-consistent-header-hash`, `nginx-consistent-cookie-hash` | `ketama-uri-hash`, `ketama-header-hash`, `ketama-cookie-hash`; static pool only |
| `maglev-source-hash` | `maglev`, `maglev-hash`; static pool only |
| `maglev-uri-hash`, `maglev-header-hash`, `maglev-cookie-hash` | Static pool only; header/cookie key required |

Example: `selection = "bounded-load-consistent-header-hash"`,
`hash_header = "x-session"`, `bounded_load_factor_per_mille = 1500` in the same
table. Remove `hash_header` when switching to `round-robin`. Hashing chooses an
eligible member; it does not validate the identity behind a client-controlled key.

## Active Health

Fields belong to `[proxy.load_balance.health_check]`. The
[HTTP recipe](../../examples/load-balancer/http-health.toml) demonstrates HTTP
request/response matchers. For non-HTTP protocols, remove HTTP-only fields
rather than relying on them to be ignored.

| Field | Default | Meaning and constraints |
| --- | --- | --- |
| `enabled` | `true` | Run background health checks |
| `protocol` | `"tcp"` | `tcp`, `http`, `grpc`, `exec`, `redis`, `mysql`, `postgres` |
| `interval_secs` | `1` | Positive interval between check rounds |
| `consecutive_success` | `1` | Positive successful-probe threshold |
| `consecutive_failure` | `1` | Positive failed-probe threshold |
| `parallel` | `false` | Concurrent member probes; not accepted for exec/database monitors |
| `method` | `"GET"` | HTTP method token, at most 32 characters |
| `path` | `"/"` | HTTP absolute request path, ASCII, at most 2048 bytes, no fragment |
| `host` | Omitted | Optional health request host, at most 255 bytes |
| `request_headers` | `[]` | Up to 16 `{ name, value }` entries; unique names; values at most 1024 bytes; no controls or reserved transport headers |
| `grpc_service` | Omitted | gRPC service name; omitted means default service; supplied name 1-256 bytes of letters/digits/`.`/`_`/`-` |
| `expected_statuses` | `[]` | Up to 32 unique HTTP statuses, 100-599 |
| `expected_status_ranges` | `[]` | Up to 32 `{ start, end }` inclusive ranges, 100-599, start <= end |
| `expected_headers` | `[]` | Up to 32 `{ name, value }` exact matches; unique names; nonempty values at most 1024 bytes |
| `expected_body_contains` | `[]` | Up to 8 unique nonempty strings, each at most 1024 bytes; all must occur |
| `expected_body_json` | `[]` | Up to 8 `{ path, equals }` scalar matches; unique dotted paths at most 256 bytes, comparison strings at most 1024 bytes |
| `health_weight_min_percent` | `25` | 1-100; lower bound for HTTP `X-Health-Weight` reduction |
| `reuse_connection` | `false` | Accepted compatibility setting; native HTTP/gRPC probes open fresh connections even if true |
| `port_override` | Omitted | 1-65535; HTTP/gRPC alternate probe port; not applied by the TCP monitor |
| `connect_timeout_secs` | Omitted | 1-86400 if set; otherwise inherit proxy timeout or native default (1 second) |
| `read_timeout_secs` | Omitted | 1-86400 if set; otherwise inherit proxy timeout or native default (1 second) |
| `exec_command` | Omitted | Required absolute command path for exec mode, at most 512 bytes, no traversal/control characters |
| `exec_args` | `[]` | At most 16 arguments, each at most 256 bytes; no control characters; do not put secrets here |
| `exec_allowed_commands` | `[]` | Required explicit allowlist for exec mode, at most 16 unique paths; must contain `exec_command` |
| `exec_timeout_secs` | Omitted (1 second) | 1-86400; exec-specific timeout |

With empty status lists, only 200 passes. Otherwise status values and ranges are
ORed. Header, body and JSON matchers are additional AND conditions. JSON `equals`
is a string even when matching a boolean/number, e.g. `equals = "true"`.
The gRPC health protocol uses its own standard method/path and serving-status
interpretation, not arbitrary HTTP response matchers.

Nested matcher records use `name` and `value` for headers, `start` and `end` for
inclusive status ranges, and `path` and `equals` for JSON values. For example:
`expected_headers = [{ name = "x-health-state", value = "ready" }]`.

Exec mode rejects HTTP/gRPC settings, port override, parallel checks and the
HTTP connect/read timeout overrides. Database monitors also reject HTTP matchers,
gRPC service, host override, parallel checks, connection reuse and port override.
The Redis/MySQL/PostgreSQL runtime monitors do not support upstream TLS.
See the [guide's protocol examples](../guides/load-balancer.md#health-checks)
instead of mixing monitor-specific fields.

## Passive Health And Slow Start

Fields under `[proxy.load_balance.passive_health]`:

| Field | Default | Meaning and constraints |
| --- | --- | --- |
| `enabled` | `false` | Observe real upstream outcomes for temporary ejection |
| `consecutive_failure` | `3` | 1-1000 consecutive failures before ejection |
| `ejection_secs` | `30` | 1-3600 seconds |
| `min_healthy_backends` | `1` | 0-4096; below this floor passive ejection may be ignored for selection; 0 requests strict ejection |
| `failure_statuses` | `[]` | Up to 64 unique HTTP 500-599 statuses |
| `failure_status_ranges` | `[]` | Up to 64 inclusive `{ start, end }` ranges in 500-599 |
| `max_latency_ms` | `0` | 0-600000; 0 disables latency classification; completed native HTTP response-header wait at or above this threshold counts as a passive failure, subject to ejection/floor policy |

Empty status lists/ranges classify all 5xx as failures. A custom list narrows
that set; transport failures remain relevant independently.

Fields under `[proxy.load_balance.slow_start]`:

| Field | Default | Meaning and constraints |
| --- | --- | --- |
| `enabled` | `false` | Gradually introduce newly seen and passively recovered members |
| `duration_secs` | `30` | 1-3600 seconds; a selection ramp with availability fallback, not a hard rate cap |

Both sections are demonstrated in
[queue-passive.toml](../../examples/load-balancer/queue-passive.toml).

## Queue

Fields under `[proxy.load_balance.queue]`:

| Field | Default | Meaning and constraints |
| --- | --- | --- |
| `max_waiting` | `0` | Maximum waiting requests, 0-100000; 0 disables queueing |
| `timeout_ms` | `0` | 0-60000; must be positive exactly when `max_waiting` is positive |
| `retry_interval_ms` | `10` | 1-1000 milliseconds between selection attempts |

Example: `max_waiting = 32`, `timeout_ms = 200`, `retry_interval_ms = 10`.
Queueing is local per pool, bounded, and does not hold a backend permit while
waiting. It is unrelated to replaying a request after an upstream error.

## Retry Contract

These fields govern the unreleased native HTTP pool dispatcher, including cache
refresh and slice requests. The
[guide](../guides/load-balancer.md#retry-and-latency-boundaries) defines replay
safety, budget scope, the disabled-default compatibility change and limits.
Merge the [retry example](../../examples/load-balancer/retry-contract.toml) into
a configured native HTTP pool; it is not a standalone server configuration.

Fields under `[proxy.load_balance.retry]`:

| Field | Default | Accepted configuration |
| --- | --- | --- |
| `enabled` | `false` | Boolean; false prohibits pool redispatch |
| `max_retries` | `1` | 0-10 additional application attempts, excluding the initial send |
| `methods` | `["GET", "HEAD", "OPTIONS"]` | Unique subset of `GET`, `HEAD`, `OPTIONS`, `TRACE` |
| `statuses` | `[]` | Up to 32 unique HTTP 500-599 statuses |
| `status_ranges` | `[]` | Up to 32 inclusive `{ start, end }` ranges in 500-599 |
| `budget_per_window` | `0` | 1-1000000 required when enabled with positive `max_retries`; 0 denies retries at runtime and is valid configuration only when retries are disabled or `max_retries = 0` |
| `budget_window_secs` | `1` | 1-3600 seconds on a monotonic clock; reset on the next reservation after expiry |

`retry.admitted` in runtime status counts committed retry admissions since pool
construction. It excludes initial sends and unused reservations; cancellation
after admission does not decrement it. The counter saturates rather than wraps.
Budgets are per pool, not process-wide or cluster-wide. Initial sends do not
consume retry budget. Configuration rebuilds create fresh budgets; size the
aggregate of configured pools for the origins' available capacity.

## Persistence

Fields under `[proxy.load_balance.persistence]`; see the
[four-mode guide](../guides/load-balancer.md#keep-related-requests-together) and
[managed-cookie example](../../examples/load-balancer/managed-cookie.toml).

| Field | Default | Meaning and constraints |
| --- | --- | --- |
| `enabled` | `false` | Enable local affinity table; unavailable with privacy-mode |
| `mode` | `"source-ip"` | `source-ip`, `header`, `cookie`, `managed-cookie` |
| `header` | Omitted | Required valid header name for `header` mode only |
| `cookie` | Omitted | Required valid cookie-name token for `cookie`/`managed-cookie` only |
| `ttl_secs` | `300` | 1-86400; local entry lifetime |
| `table_max_entries` | `65536` | 1-1000000; bounded local table capacity |
| `managed_cookie_domain` | Omitted (host-only) | Optional nonempty ASCII domain up to 253 bytes; no controls, `;` or `,` |
| `managed_cookie_path` | Omitted (`"/"`) | Absolute ASCII cookie path up to 256 bytes; no controls, `;` or `,` |
| `managed_cookie_secure` | `true` | Browser sends cookie only over secure transport |
| `managed_cookie_http_only` | `true` | Browser scripts cannot read cookie |
| `managed_cookie_same_site` | `"lax"` | `strict`, `lax`, `none`; `none` requires Secure |
| `managed_cookie_max_age_secs` | Omitted (TTL) | 1-86400 if supplied |

Nondefault managed-cookie attributes are valid only in managed-cookie mode.
These attributes do not make an application session authenticated. Local signing
keys, entry tables and runtime overrides are not cluster-replicated. The optional
runtime state file does not preserve cookie signing keys and can contain raw
header/cookie persistence identifiers; treat it as private data.

## Verification Boundary

Configuration tests load the checked-in recipes, including negative overlays.
Native request tests cover retry enforcement and response-header latency boundaries. Live
native and container tests cover practical selection, persistence, failover and
recovery. See the [coverage ledger](documentation-coverage.md) for the exact
commands and native-platform/protocol gaps; parsing a recipe is not a live
qualification of every monitor or external discovery service.
