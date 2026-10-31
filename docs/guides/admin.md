# Admin API And Local Operations

The admin API controls one running Fluxheim instance. Use it to inspect status,
manage supported cache and load-balancer operations, and apply verified
configuration snapshots. It is separate from your public website listener.

It is **not** a complete configuration editor, user-management service or fleet
controller. There is no general JSON configuration upload, arbitrary file API,
server restart endpoint, per-vhost role system or browser UI. Edit configuration
files through your deployment process; use the [snapshot workflow](config-snapshots.md)
for supported validation, publication, reload and rollback. Some changes require
a process restart. ACME issuance and incident commands remain in the
[ACME tools](acme.md), not a general-purpose admin certificate API.

## Choose An Interface

| Interface | Where | Purpose | Authentication |
| --- | --- | --- | --- |
| HTTP control listener | `admin.listen`; numeric loopback by default | Reads and supported mutations | Control bearer token; optional trusted-proxy certificate assertion |
| Operational status | Exact `GET /_fluxheim/operational-status` on either admin transport | Bounded, redacted observation | Control or separate observer token, always |
| Unix operations socket | Linux/macOS only; opt-in | Read-only local status | Filesystem access plus the token policy below |
| Public listener | `server.listen` / TLS listeners | Your applications | Does not become the admin listener when admin is enabled |

The HTTP admin listener speaks HTTP/1.1, not native HTTPS. Public-vhost TLS
configuration does not protect it. Keep it on loopback or behind an explicitly
trusted TLS terminator with a protected backend connection.

## Start With A Local Configuration

[Complete example](../../examples/admin/local.toml) serves a small static site
on `127.0.0.1:8080` and the admin API on `127.0.0.1:9090`. It needs a binary with
static web support. No metrics, collector, PHP or external origin is required.

On Unix, run this preparation as the intended Fluxheim service identity in a
trusted, non-shared directory, not directly beneath `/tmp`:

```sh
umask 077
mkdir -p "$HOME/fluxheim-admin-demo/public"
cd "$HOME/fluxheim-admin-demo"
chmod 0700.
openssl rand -hex 32 > control-token
openssl rand -hex 32 > observer-token
openssl rand -hex 32 > snapshot-integrity.key
chmod 0600 control-token observer-token snapshot-integrity.key
printf '%s\n' 'admin demo ready' > public/index.html
```

Put the example at `fluxheim.toml` in this directory, validate it, then start:

```sh
fluxheim --config "$HOME/fluxheim-admin-demo/fluxheim.toml" --validate-config
fluxheim --config "$HOME/fluxheim-admin-demo/fluxheim.toml"
```

Relative paths resolve against the configuration file's directory. An absent
snapshot-store leaf is created privately; its parent must already exist and be
trusted. An existing store must be service-owned and `0700` on Unix. Keep the
integrity key outside that store. Windows uses confidential ACL checks rather
than POSIX modes: grant the service identity access, not Everyone/Users/Guests,
and use a private service directory. Omit the Unix socket on Windows.

Do not reuse the observer credential as the control token. Tokens are trimmed,
nonempty UTF-8 strings; token files and resulting tokens are limited to 8 KiB.
Use randomly generated values, not passwords or the example names. Files are
loaded at startup; changing them is not credential rotation until restart.

**Current limitation:** the control
token reader rejects unsafe parents and symlinks but does not reject a readable
`0644` or group-writable `0660` leaf. Observer tokens do use the confidential
file policy. Set control tokens to service-owned `0600` yourself; successful
startup is not evidence that those leaf permissions were checked. Windows
control tokens use the confidential ACL policy. This gap is queued for correction.

## Send Requests Without Publishing Credentials

For the redacted status endpoint, the supplied client prompts for a token:

```sh
python3 scripts/operational_status_client.py http://127.0.0.1:9090
```

For other endpoints, a private curl header file avoids putting the token value
in the process command line. In the private demo directory:

```sh
umask 077
printf 'Authorization: Bearer %s\n' "$(cat control-token)" > control-header
chmod 0600 control-header
curl --fail-with-body --max-time 5 --header @control-header \
  http://127.0.0.1:9090/_fluxheim/status
curl --fail-with-body --max-time 5 --header @control-header \
  -X POST -H 'X-Fluxheim-Message: before route change' \
  http://127.0.0.1:9090/_fluxheim/snapshot
rm control-header
```

Do not use shell tracing, verbose credential dumps, URL tokens or public proxy
access logs containing credentials. The header file is itself a secret. Recreate
it privately for later commands; do not leave shared copies behind. The parser
expects the literal `Bearer ` scheme. Never send a real token over an untrusted
plaintext network, and never use `curl -k` to work around certificate errors.

The API takes parameters in documented headers or the query string, **not a JSON
request body**. Scalar headers normally take precedence over query parameters.
Bulk purge is an exception: repeated `path=` query values take precedence over
the comma-separated paths header. Boolean header/query switches are combined
with OR; `1`, `true`, `yes` and `on` are true, case-insensitively.
The query helper splits `&` and `=` without form/percent decoding: prefer headers
for names or paths needing spaces, `&`, `+` or percent escapes. Do not assume
`--data-urlencode` produces values this API will decode.

## Roles And Local Access

| Request | Control token over HTTP | Observer token over HTTP | Unix socket without token, default policy |
| --- | --- | --- | --- |
| Operational status GET | Allowed | Allowed | Denied: token always required |
| Legacy status/cache/load-balancer/UDP GET | Allowed | 403 | Allowed |
| Snapshot list GET | Allowed | 403 | Denied: control token always required |
| Health GET | Allowed | 403 unless explicitly public | Allowed |
| Supported mutation POST | Allowed, subject to validation/audit/recovery | 403 | Not routed, even with control token |

Set `admin.ops_socket.require_bearer_token = true` to require authentication for
all socket reads. When false, ordinary socket reads rely on filesystem access;
supplying an observer or invalid header does not turn those tokenless routes
into authenticated routes. Operational status and snapshot listing remain
authenticated exceptions. The Unix socket does not apply the HTTP certificate
assertion or HTTP source-throttle policy and does not enforce the self-healing
deadline while answering reads. Protect its directory and keep it owner-only.

For HTTP, authorization happens before mutation and recovery enforcement.
Authenticated legacy reads can trigger an expired validation rollback; the
operational-status endpoint deliberately cannot. A public health request also
bypasses authentication and recovery enforcement. Choose operational status for
observation without that recovery side effect.

## Complete Endpoint Inventory

All paths below are exact: an added trailing slash is a different path. HTTP
requests without a valid credential are rejected before normal routing, so an
unauthenticated 401 does not prove a route exists. After authorization, known
routes with the wrong method return 405; unknown GET/POST routes return 404.
An observer outside its exact GET route gets 403 instead.

### Read Operations

| Method and path | Meaning and detailed contract |
| --- | --- |
| `GET /_fluxheim/operational-status` | Redacted process/configuration/telemetry sample; rejects query parameters; [schema, errors and readiness](operational-status.md) |
| `GET /_fluxheim/status` | Snapshot/current/runtime/recovery state, logging status and feature-dependent subsystem summaries; not an application health probe |
| `GET /_fluxheim/cache/status` | Cache policy/activity/storage view; [cache operations](cache-operations.md) |
| `GET /_fluxheim/load-balancer/status` | Pool members, health and runtime state; [load balancing](load-balancer.md) |
| `GET /_fluxheim/udp/status` | UDP configuration summary, not a live session listing; [UDP](udp.md) |
| `GET /_fluxheim/snapshots` | Snapshot deployment history; [snapshots](config-snapshots.md) |
| `GET /_fluxheim/health` | Default configurable health path: 200 `{"status":"ok"}` or empty 204; not origin/collector readiness |

### Cache Operations

All use POST, require the control token and are HTTP-only. The
[cache operations guide](cache-operations.md) contains complete parameter,
scope, result and limitation tables. Optional `vhost`/`route` select a configured
cache scope, not an arbitrary filesystem path. Operations unavailable in the
compiled profile are not enabled by adding configuration.

| Path | Purpose / principal inputs |
| --- | --- |
| `/_fluxheim/cache/activity/reset` | Reset cache activity counters, not stored objects |
| `/_fluxheim/cache/purge` | Exact object identity: host, method, path, optional URL query |
| `/_fluxheim/cache/purge-bulk` | Multiple explicit paths |
| `/_fluxheim/cache/purge-index` | Bounded indexed scope traversal; limit/batches and optional soft purge |
| `/_fluxheim/cache/purge-prefix` | Indexed path prefix; same work controls |
| `/_fluxheim/cache/purge-tag` | Indexed cache tag; same work controls |
| `/_fluxheim/cache/purge-wildcard` | Indexed path pattern; same work controls |
| `/_fluxheim/cache/purge-stale` | Stale-object traversal; limit/batches and dry-run option |

Read the linked guide's outstanding soft-purge, progress and dry-run warnings
before production use. A successful HTTP response alone does not establish
complete purge across every tier or fix those recorded limitations.

### Load-Balancer Operations

All use POST. Supply `vhost` and optional `route`; identify members using the
supported member identity for the pool. The equivalent headers have prefix
`X-Fluxheim-Lb-`, for example `X-Fluxheim-Lb-Vhost`, `-Route` and `-Member`.
See [member operations and persistence](load-balancer.md) for values, addresses,
weights, feature requirements and state-file behavior.

| Path | Additional inputs |
| --- | --- |
| `/_fluxheim/load-balancer/member-state` | `member`, `state` |
| `/_fluxheim/load-balancer/member-weight` | `member`, `weight` |
| `/_fluxheim/load-balancer/member-add` | `member`, optional `weight` |
| `/_fluxheim/load-balancer/member-remove` | `member` |
| `/_fluxheim/load-balancer/member-update` | `member`, `new_member` (alias `address`), optional `weight`; new-address headers `X-Fluxheim-Lb-New-Member` or `X-Fluxheim-Lb-Address` |
| `/_fluxheim/load-balancer/persistence/clear` | Scope only; clears sticky entries |

These are runtime operations, not edits to source TOML or durable configuration
snapshots. Persistence depends on the pool's configured runtime state file.
Do not assume changes survive restart or override later service discovery.

### Configuration And Recovery Operations

| Method and path | Input / purpose |
| --- | --- |
| `POST /_fluxheim/snapshot` | Optional `X-Fluxheim-Message`; capture the running effective configuration, not edited source files; selects the new durable snapshot without applying a router |
| `POST /_fluxheim/reload` | Apply the selected verified snapshot, not arbitrary JSON or an automatic reread of edited files |
| `POST /_fluxheim/rollback` | `X-Fluxheim-Rollback-To` or `to`; `X-Fluxheim-Live-Apply` or `live`/`live_apply` requests live application |
| `POST /_fluxheim/self-heal/confirm` | Confirm the pending candidate |
| `POST /_fluxheim/self-heal/fail` | Report failure and initiate recovery |
| `POST /_fluxheim/self-heal/report` | `X-Fluxheim-Health` or `health`/`ok`/`success`: successful/failed health observation |

Read [snapshots and self-healing](config-snapshots.md) before these operations.
Confirmation must reflect checks of your application, not merely a successful
admin health response. Live apply supports only part of the configuration;
restart-required changes fail rather than silently changing bound listeners.

## Configuration Options

These tables cover every admin field. Defaults are not a complete enabled
configuration: enabling admin requires **exactly one control-token source and a
snapshot store**, even when you only intend to read status.

### `[admin]`

| Field | Default | Use |
| --- | --- | --- |
| `enabled` | `false` | Start admin services |
| `listen` | `"127.0.0.1:9090"` | Numeric IP:port; bracket IPv6, e.g. `[::1]:9090` |
| `require_loopback` | `true` | Reject non-loopback binding; disabling alone does not enable secure remote access |
| `token_env` | unset | Environment variable name, alternative to token file; inherited environment handling is your responsibility |
| `token_file` | unset | Private control token; do not also set token_env |
| `operational_token_file` | unset | Separate confidential observer token |
| `snapshot_store` | unset | Required dedicated private store |
| `snapshot_integrity_key_file` | unset | Optional 32..4096-byte private HMAC key outside store; recommended for authenticated snapshots |

### `[admin.transport]` And `[admin.client_certificate]`

Transport `mode` defaults to `"local_only"`; the other value is
`"trusted_tls_terminator"`. A non-loopback listener requires that mode and
`require_loopback = false`. This is an operator declaration, **not encryption or
an automatic proxy allowlist**. Firewall the backend so clients cannot bypass
the terminator, and protect the hop from terminator to Fluxheim.

| Certificate field | Default | Use |
| --- | --- | --- |
| `required` | `false` | Require the trusted terminator's certificate-fingerprint assertion |
| `sha256_header` | `"x-client-cert-sha256"` | Valid HTTP header name; terminator must strip client copies and inject its own |
| `allow_sha256` | `[]` | Allowed 64-hex SHA-256 fingerprints; nonempty also makes assertion required |
| `deny_sha256` | `[]` | Denied fingerprints; deny wins over allow |

Example for an existing **local, trusted mTLS terminator**, leaving the admin
listener on loopback:

```toml
[admin.transport]
mode = "trusted_tls_terminator"
[admin.client_certificate]
required = true
sha256_header = "x-client-cert-sha256"
# Replace with the real certificate's SHA-256 fingerprint (64 hex, no colons).
allow_sha256 = ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
deny_sha256 = []
```

This example does not install a proxy or validate a client certificate itself.
A local process can forge the assertion if it can reach the backend. Duplicate,
malformed or denied assertions return 403 (or 429 after throttling); comparisons
are case-insensitive. A deny-only list permits an absent assertion. The policy
is checked before tokens on HTTP, except explicitly public health, and does not
apply to the read-only Unix socket.

### `[admin.ops_socket]`

| Field | Default | Use |
| --- | --- | --- |
| `enabled` | `false` | Requires admin enabled and Unix support |
| `path` | `"/run/fluxheim/fluxheim-ops.sock"` | Short private socket path; parent must exist and be trusted |
| `mode` | `"0600"` | Octal string; validation permits owner read/write and non-world group access, but see limitation below |
| `require_bearer_token` | `false` | Require tokens on all local reads; snapshot/operational reads always require them |

Add this table to the local example **before** `[[vhosts]]` (or as an independent
root-level table), with a short absolute path in a private service directory:

```toml
[admin.ops_socket]
enabled = true
path = "/run/fluxheim/ops.sock"
mode = "0600"
require_bearer_token = true
```

Using the private header file prepared above:

```sh
curl --fail-with-body --max-time 5 --unix-socket /run/fluxheim/ops.sock \
  --header @control-header http://localhost/_fluxheim/status
```

`localhost` is a dummy HTTP host here; the connection is to the Unix path. There
is no Windows equivalent for this socket. The TCP admin interface works on
Windows. Unix socket path-length limits also apply on macOS: use short paths.

**Current limitation:** the native listener
always creates mode `0600`; the accepted `0660` value is not applied. Do not
promise group access based on TOML, or weaken the parent directory as a workaround.
Use owner-only `0600` until the mode contract is corrected.

### Health, Throttling And Self-Healing

| Table and field | Default | Meaning |
| --- | --- | --- |
| `admin.health.unauthenticated` | `false` | Public health only on loopback; skips token/certificate/throttle/recovery checks |
| `admin.health.response` | `"status"` | `status`: 200 JSON; `minimal`: empty 204 |
| `admin.auth_throttle.enabled` | `true` | Enable HTTP authentication failure accounting |
| `admin.auth_throttle.window_secs` | `60` | Positive failure window |
| `admin.auth_throttle.per_source_failures` | `10` | Positive per-direct-peer failure threshold |
| `admin.auth_throttle.global_failures` | `100` | Positive aggregate invalid-attempt threshold |
| `admin.auth_throttle.base_lockout_secs` | `30` | Positive initial progressive lockout |
| `admin.auth_throttle.max_lockout_secs` | `900` | At least base lockout |
| `admin.auth_throttle.max_sources` | `4096` | Positive bounded source-table capacity |
| `admin.self_healing.enabled` | `false` | Enable validation/recovery watchdog |
| `admin.self_healing.validation_window_secs` | `30` | Positive candidate-validation interval |
| `admin.self_healing.health_path` | `"/_fluxheim/health"` | Absolute path, at most 2048 bytes; no whitespace/control, backslash, query or fragment; reserved admin prefix forbidden except default |
| `admin.self_healing.min_successful_checks` | `1` | Positive confirmation threshold |
| `admin.self_healing.max_error_rate_per_mille` | `100` | 0..1000; 100 means 10%, not 100% |

Throttling uses the **direct socket peer**, not X-Forwarded-For. Clients behind
one proxy therefore share that source budget. Source lockout blocks both valid
roles until expiry. During global invalid-attempt lockout, valid credentials
still work unless their source is locked. Successful control authentication
resets source failures; successful observer requests never reset them. A valid
observer attempting a forbidden route does not consume/reset the failure budget.
Leave throttling enabled and protect the listener independently with a firewall.

## Responses, Audit And Troubleshooting

JSON replies use `Cache-Control: no-store`. Ordinary admin JSON is bounded to
1 MiB; operational status has its stricter 16 KiB contract. Routing caps paths
at 2048 bytes and queries at 16 KiB, in addition to the server's HTTP parser
limits. These bounds are not a promise that every long request reaches routing.

| Symptom | What to check |
| --- | --- |
| Startup rejects admin configuration | Exactly one control source, snapshot store, valid paths/permissions, supported build |
| Connection refused | Admin enabled, correct separate port, firewall/listen address, startup log |
| 401 | Correct `Authorization: Bearer` header and token loaded at startup |
| 403 | Observer outside its exact endpoint, or missing/invalid/denied certificate assertion |
| 429 | Direct-peer/global authentication failure policy; changing endpoint does not evade it |
| 400 | Endpoint parameters, operational query prohibition, unavailable snapshot or unsupported live change |
| 404/405 | Exact path and method; Unix socket is read-only |
| 503 | Operational collection busy or audit admission unavailable; inspect bounded response and local diagnostics |
| Mutation error after work began | Do not blindly retry; inspect state because the operation may already have completed |

Authenticated mutations reserve bounded audit capacity before work. Failure to
admit an event rejects the operation. Queue admission is **not durable audit
persistence**: a process crash or later sink failure can lose an admitted event.
Post-mutation enqueue failure is reported as potentially completed. These are
documented boundaries, not a transactional rollback guarantee; see
[logging](logging.md) and [snapshots](config-snapshots.md).

## Verification And Implementation

- [Live guide test](../../scripts/smoke_admin_examples.py) starts an actual server,
  checks roles, methods, credential restart behavior, certificate assertions,
  Unix read-only access and the two recorded configuration/runtime gaps.
- [Guide coverage tests](../../scripts/test_admin_examples.py) guard the complete
  route/field inventory and example syntax.
- [Existing operational smoke](../../scripts/smoke_operational_status.py) checks
  the bounded schema, reload/rollback generation, observer throttling and
  collector failure/recovery.
- [Router](../../src/admin/request_router.rs),
  [configuration](../../crates/fluxheim-config/src/config_admin.rs),
  [native listener](../../src/runtime_admin.rs) and
  [token loader](../../src/admin/security/token_store.rs) define the current contract.

```sh
python3 scripts/test_admin_examples.py
python3 scripts/smoke_admin_examples.py --binary target/debug/fluxheim
```

The live guide uses temporary owner-private data and numeric loopback listeners.
It is not a production administration client or a test against your live server.
