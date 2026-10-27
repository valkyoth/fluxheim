# Operational Status API

Fluxheim 1.9 adds `GET /_fluxheim/operational-status` on the **existing admin
listener**. It gives a CLI or future UI one bounded view of process capabilities,
configuration counts, recovery state, recent admin changes and telemetry health.
It does not enable a listener, provide a GUI, or implement full server management.

## Connect

Use the existing [admin and snapshot configuration](config-snapshots.md).
Keep the admin listener on loopback; tunnel to it or use a properly secured TLS
management gateway. Never expose a plaintext admin bearer token to the network.
The configured client-certificate policy applies as for other admin routes.
The new route always requires a token, even when health is public
or the Unix operations socket permits other tokenless local reads.

An API-only example client needs Python's standard library, not server-file access:

```sh
# With an SSH tunnel to the existing admin port, for example 19090:
python3 scripts/operational_status_client.py http://127.0.0.1:19090
```

The client prompts for the token without echoing it or putting it on the command
line. It verifies HTTPS certificates, refuses redirects, limits the response to
16 KiB, and allows plaintext only to numeric loopback addresses. Socket operations
have a five-second timeout. An HTTPS management gateway may require additional
client-certificate support beyond this small example client.

Give monitoring consumers a separate, status-only credential:

```toml
[admin]
enabled = true
listen = "127.0.0.1:9090"
token_file = "/etc/fluxheim/secrets/admin-token"
operational_token_file = "/etc/fluxheim/secrets/observer-token"
snapshot_store = "/var/lib/fluxheim/snapshots"
```

`operational_token_file` is optional. It authorizes **only GET on this exact
endpoint**, not legacy status, snapshot, recovery, reload, cache or load-balancer
routes. Both listener and Unix socket enforce this restriction. Existing tokenless
local reads on the Unix socket remain governed by its existing configuration.
The full control-plane token still works here, but do not distribute it to
monitoring consumers. Client-certificate policy and HTTP authentication throttling
also apply to observer requests.

An observer success does not reset failed-token attempts. Invalid credentials
share one bounded per-source budget across all protected routes, since a control
token can also authenticate on the observer route. Only a successful control-token
request clears that source's failures. A valid observer token used outside its
scope returns `403 forbidden` without clearing or incrementing this budget.
Source lockout still blocks both roles until expiry. The existing global
invalid-attempt lockout continues to permit valid credentials for incident
response; it is not a pre-authentication CPU-rate limit.

Create an independent random token, not a copy of the admin token. The server
rejects identical credentials (including after whitespace trimming), empty or
oversized credentials and unsafe secret paths. On Unix the observer file must be
root- or service-owned, readable by the service, with no group/other permissions
(normally `0600`); parent directories must be trusted. Windows uses the existing
confidential-file ACL policy. Symlinks and non-regular files are rejected. Secret
contents are read with a bound, zeroized after loading and retained only as a MAC.
Changing the file or configured path requires restarting the admin service;
reload cannot rotate credentials. Full role management remains future work.

## Contract

The [OpenAPI 3.1.0 description](../reference/operational-status.openapi.json),
[JSON Schema 2020-12 response](../reference/operational-status.schema.json),
[response fixture](../../tests/fixtures/observability/operational-status.json) and
[error fixtures](../../tests/fixtures/observability/operational-errors.json) are
versioned together. The description uses the
[OpenAPI 3.1 schema model](https://spec.openapis.org/oas/v3.1.0.html).
There are no query parameters, pagination, filtering, history queries or request
bodies for this operation. A query is rejected rather than silently ignored.
Responses have `Content-Type: application/json` and `Cache-Control: no-store`.

| Field | Meaning |
| --- | --- |
| `schema_version` | Contract major version, currently `1`; independent of the Fluxheim release version |
| `version`, `capabilities`, `platform` | Release version and compiled features; Windows reports managed PHP and Unix operations sockets unavailable |
| `instance_id` | Random process-local admin-instance identifier; changes on restart |
| `sampled_unix_secs`, `uptime_secs` | Sample wall time and monotonic uptime since admin initialization |
| `configuration.generation` | Starts at 1 for each instance; increments when this admin applies a runtime configuration, including rollback; not a persistent snapshot ID |
| `configuration.updated_unix_secs` | Time this configuration projection was published, not a collector heartbeat |
| `configuration.last_change` | Most recently completed reload/live rollback/self-heal rollback attempt that reached the operation, its outcome and time; `null` after restart |
| `health` | `responding`: the admin observer can respond; not an end-to-end application probe |
| `readiness` | `ready` (no pending recovery), `validating`, or `recovery_required` (expired validation, excessive failures or a failed rollback) |
| `consistency` | `best_effort`: individually safe samples, not a transaction across all workers |
| `stale` | True when the configuration inventory is incomplete; inspect `inventory.complete` before using counts to claim a feature is disabled |

Readiness describes **admin recovery eligibility only**. It does not prove that
every public listener, origin, PHP worker or certificate is healthy. A collector
failure does not make public serving unready. HTTP 200 means a sample is available;
clients must inspect `readiness` and the separate telemetry states.

Generation and last-change completion are separate observations. A failing apply
may already have changed the running configuration before persistence failed.
`failed` is not a promise of rollback or a durable audit record. A concurrent read
can see a new generation before the operation's completion record. Auth/audit
admission rejection before an operation does not replace its last-change record.
External certificate reloads, discovery and restart history are not represented
as admin configuration changes.

## Inventory And Telemetry

Inventory contains aggregate counts only: no vhost names, backend addresses,
paths, URLs, tokens, snapshot IDs, certificate identities or error messages.
`listeners` counts configured public HTTP/TLS listener entries, not successfully
bound sockets; it excludes admin, metrics, stream and UDP listeners. Upstream
items count explicit primary, list and backup entries, without deduplication or
DNS/discovery expansion. Cache, PHP and ACME count explicitly enabled sections,
not effective inherited routes, worker counts, stored objects or certificate count.

The summary visits at most 1,024 global/vhost/route scopes when a configuration
is published, never per status request. If truncated, counts describe only the
visited prefix and are lower bounds. In that case `disabled` means not configured
in that prefix, not globally disabled. `vhosts` remains the exact vector count.
The component `state` is `not_compiled`, `disabled` or `configured`.
Its `runtime: unavailable` is deliberate: this projection does not probe or
walk mutable subsystem inventories and must not invent healthy zero values.
Detailed existing routes remain available separately where needed.

Telemetry uses fixed fields and process-local counters:

- Logging and structured-event workers report `observed` when alive,
  `degraded` when a worker has stopped, or `unavailable` before initialization.
  Failure counters are cumulative; pending records are not durable persistence.
- Metrics/traces report `not_compiled`, `disabled`, `unavailable` before a
  completed attempt, `observed` after the most recent successful attempt, or
  `degraded` after partial/failed delivery. No new collector probe is sent.
- Export counters are cumulative since process start, not per configuration.
  Queue bytes and active requests are instantaneous best-effort gauges.
  The most recent outcome can be old when there is no traffic. An observed
  outcome is not a current collector reachability guarantee.
- Unknown values are `null`, not misleading zeros. Telemetry loss and
  degradation do not override the independent readiness field.

## Bounds And Recovery Safety

Collection uses only fixed-size cached summaries, atomic counters and nonblocking
state reads. At most four collectors run per admin instance. A busy/poisoned
state lock returns `503 operational_status_unavailable`, without waiting.
Serialization is capped before buffer growth at 16 KiB. Collection checks a
50 ms elapsed-time budget before returning; OS scheduling and network delivery
are not hard real-time guarantees. The normal admin listener connection,
request-header/body and write limits still apply.

The new observer never loads snapshot files, probes origins, contacts collectors,
reopens logs, acknowledges validation, changes configuration or triggers rollback.
An expired/failed recovery remains visible as `recovery_required`. The watchdog
and **all existing routes retain their previous recovery enforcement**. Existing
mutations still cannot confirm a candidate past a failed rollback.

Errors: `400` unsupported query; `401` missing/incorrect token; `403` credential scope or certificate
policy; `405` method; `414` existing request-target bounds; `429` authentication
throttling; `503` unavailable/busy/over-budget sample. Retry 503 with client-side
backoff rather than a tight loop. No new CORS policy or unauthenticated exception
is introduced.

## Existing Routes

These routes remain compatible, but are not redefined by the new fixed-size
OpenAPI contract. Authenticated HTTP reads can still enforce recovery before
returning. Some read snapshot files or enumerate detailed runtime state; do not
assume the new observer's 16 KiB/50 ms bounds apply to them.

| Method and route | Purpose |
| --- | --- |
| `GET /_fluxheim/status` | Existing snapshot/recovery, logging and feature-specific details |
| `GET /_fluxheim/cache/status` | Existing cache activity and configured tiers |
| `GET /_fluxheim/load-balancer/status` | Existing pool/member details |
| `GET /_fluxheim/udp/status` | Existing UDP status |
| `GET /_fluxheim/snapshots` | Existing persisted snapshot list |
| `GET /_fluxheim/health` | Configurable health path/mode; optionally unauthenticated; not the operational contract |

For existing mutations and their authorization/recovery behavior see
[snapshots and admin API](config-snapshots.md), [cache](cache-backends.md) and
[load balancing](load-balancer-migration.md). This checkpoint adds no mutations or roles.

## Verify

Install the pinned development-only schema tooling in a virtual environment:

```sh
python3 -m venv target/status-venv
target/status-venv/bin/python -m pip install -r scripts/operational_status_requirements.txt
target/status-venv/bin/python scripts/test_operational_status_contract.py
cargo build --locked --no-default-features --features profile-observability,php-fpm --bin fluxheim
target/status-venv/bin/python scripts/smoke_operational_status.py --binary target/debug/fluxheim
```

Windows uses `target/status-venv/Scripts/python.exe` and `fluxheim.exe`. The smoke
owns a private temporary fixture and local collector; it checks live auth/schema,
secret redaction, concurrency, telemetry outage/recovery and reload/rollback/restart.
`--reduced` tests a `proxy,web` build without OTLP. See the
[checkpoint evidence](../evidence/observability-09.md) for actual native results.
