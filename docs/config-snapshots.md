# Config Snapshots And Rollback

Fluxheim uses two layers for reload safety:

- Runtime snapshots: immutable in-memory state behind `ArcSwap`.
- Durable snapshots: validated TOML configs stored on disk with a current
  pointer.

The runtime snapshot model means old requests can keep using the config they
started with while new requests use the new config after an atomic pointer swap.
The durable snapshot store gives operators an auditable rollback target and the
admin API a current pointer to apply.

## Store Layout

Use an operator-chosen state directory, for example
`/var/lib/fluxheim/snapshots`:

```text
/var/lib/fluxheim/snapshots
├── current
└── configs
    ├── s1777900000-123456789-42.toml
    └── s1777900000-123456789-42.meta.toml
```

`current` contains the active snapshot id. Fluxheim uses an atomically replaced
pointer file instead of a symlink. A symlink swap is a good Linux-only design,
but the pointer file keeps the store straightforward in rootless Podman,
restricted volume mounts, and non-Unix development environments while still
using write-temp-and-rename semantics.

Snapshot config files contain the validated effective config, written back as
TOML. Metadata files contain the snapshot id, creation time, and optional
operator message. Operator messages are trimmed and limited to 4096 bytes of
non-control text before they are written or loaded.
Generated snapshot ids contain Unix time plus a process-local sequence; they do
not include the Fluxheim process id.

The store is deliberately conservative about filesystem indirection. Snapshot
ids may only contain ASCII letters, digits, `_`, and `-`, and are limited to
128 bytes; the store root cannot contain `..` or sit below a symlinked parent
directory; the store root and `configs` directory must be real directories; the
`configs` directory must remain inside the snapshot store; and `current`,
snapshot TOML files, and metadata TOML files are opened as regular files.
Symlinked store roots, pointer, config, metadata, or `configs` paths are
rejected so a rollback cannot be redirected to an operator-unapproved file.
Atomic writes also require an already validated real parent directory and will
not replace a symlinked destination. Snapshot reads are bounded: `current` is
limited to 4 KiB and snapshot TOML/metadata reads are limited to 16 MiB.
Snapshot stores are limited to 1024 snapshots; operators should export or prune
old snapshots before that limit.

On Unix, Fluxheim normalizes the snapshot store root and `configs` directory to
mode `0700`, and writes `current`, config snapshots, and metadata snapshots as
mode `0600`. Operators should still run the service with a restrictive umask
such as `0077` or `0027` as defense in depth for any future state files.

## Commands

Create a snapshot from a config:

```bash
fluxheim --config /etc/fluxheim/fluxheim.toml snapshot \
  --store /var/lib/fluxheim/snapshots \
  --message "known good before cache change"
```

List snapshots:

```bash
fluxheim snapshots --store /var/lib/fluxheim/snapshots
```

Move the current pointer back to the previous snapshot:

```bash
fluxheim rollback --store /var/lib/fluxheim/snapshots
```

Move to a specific snapshot:

```bash
fluxheim rollback --store /var/lib/fluxheim/snapshots --to s1777900000-123456789-42
```

Rollback updates the durable current pointer by default. Before applying a
rollback to a live process, classify the change:

```bash
fluxheim --reload-from /var/lib/fluxheim/snapshots/configs/current.toml \
  --config /var/lib/fluxheim/snapshots/configs/target.toml
```

The admin reload endpoint performs this classification before it swaps runtime
proxy state.

## Admin API Shape

Fluxheim reserves a separate admin control plane for live operations:

```toml
[admin]
enabled = true
listen = "127.0.0.1:9090"
require_loopback = true
token_env = "FLUXHEIM_ADMIN_TOKEN"
snapshot_store = "/var/lib/fluxheim/snapshots"

[admin.transport]
mode = "local_only"

[admin.health]
unauthenticated = false
response = "status"

[admin.self_healing]
enabled = true
validation_window_secs = 30
health_path = "/_fluxheim/health"
min_successful_checks = 1
max_error_rate_per_mille = 100
```

The initial listener must be private by default. Remote exposure now requires
`admin.require_loopback = false` plus `[admin.transport] mode =
"trusted_tls_terminator"`, which is an explicit operator declaration that TLS
or mTLS is terminated by a trusted local sidecar, reverse proxy, or load
balancer before traffic reaches the plain admin listener. First-class admin
TLS/mTLS is still tracked as future work; do not expose the admin listener over
cleartext networks.

Implemented endpoints:

- `GET /_fluxheim/status`
- `GET /_fluxheim/health`
- `GET /_fluxheim/snapshots`
- `POST /_fluxheim/snapshot`
- `POST /_fluxheim/rollback`
- `POST /_fluxheim/reload`
- `POST /_fluxheim/self-heal/confirm`
- `POST /_fluxheim/self-heal/fail`
- `POST /_fluxheim/self-heal/report`

All admin endpoints, including `/_fluxheim/health`, require
`Authorization: Bearer <token>` by default. For local-only watchdogs, set
`[admin.health] unauthenticated = true` while keeping `admin.listen` loopback;
use `response = "minimal"` for an empty `204` probe response.

Create a snapshot over HTTP:

```bash
curl -sS -X POST \
  -H "Authorization: Bearer $FLUXHEIM_ADMIN_TOKEN" \
  -H "X-Fluxheim-Message: known good before upstream change" \
  http://127.0.0.1:9090/_fluxheim/snapshot
```

Move the durable current pointer back to the previous snapshot:

```bash
curl -sS -X POST \
  -H "Authorization: Bearer $FLUXHEIM_ADMIN_TOKEN" \
  http://127.0.0.1:9090/_fluxheim/rollback
```

Move the durable current pointer to a specific snapshot:

```bash
curl -sS -X POST \
  -H "Authorization: Bearer $FLUXHEIM_ADMIN_TOKEN" \
  "http://127.0.0.1:9090/_fluxheim/rollback?to=s1777900000-123456789-42"
```

Live-apply the previous snapshot when it is snapshot-safe:

```bash
curl -sS -X POST \
  -H "Authorization: Bearer $FLUXHEIM_ADMIN_TOKEN" \
  "http://127.0.0.1:9090/_fluxheim/rollback?live=true"
```

Live rollback validates the target before changing the durable current pointer.
If the target requires a process upgrade, Fluxheim returns `409 Conflict` and
leaves the pointer on the current snapshot.

Apply the durable current snapshot to the running proxy if the reload classifier
marks it `noop` or `snapshot`:

```bash
curl -sS -X POST \
  -H "Authorization: Bearer $FLUXHEIM_ADMIN_TOKEN" \
  http://127.0.0.1:9090/_fluxheim/reload
```

The reload endpoint returns `409 Conflict` when the current snapshot requires a
process upgrade, such as listener, TLS backend/mode, admin service, or
metrics service, or startup-owned load-balancer service changes. Existing
requests keep their old runtime snapshot; new requests use the freshly swapped
proxy snapshot.

## Self-Healing Guard

When `admin.self_healing.enabled = true`, a successful live reload enters a
pending validation state. `GET /_fluxheim/status` reports:

- `runtime_snapshot`
- `known_good_snapshot`
- `pending_validation`
- `load_balancer` when compiled with the load-balancer feature, including
  read-only vhost/route pool and backend runtime state

Confirm the candidate after local health checks succeed:

```bash
curl -sS -X POST \
  -H "Authorization: Bearer $FLUXHEIM_ADMIN_TOKEN" \
  http://127.0.0.1:9090/_fluxheim/self-heal/confirm
```

Force rollback to the previous known-good snapshot after local health checks
fail:

```bash
curl -sS -X POST \
  -H "Authorization: Bearer $FLUXHEIM_ADMIN_TOKEN" \
  http://127.0.0.1:9090/_fluxheim/self-heal/fail
```

The fail endpoint validates the previous snapshot and applies it with the same
snapshot-safe reload gate. It also moves the durable current pointer back only
after the running proxy accepts the rollback.

Report health-check results from a local watchdog:

```bash
curl -sS -X POST \
  -H "Authorization: Bearer $FLUXHEIM_ADMIN_TOKEN" \
  "http://127.0.0.1:9090/_fluxheim/self-heal/report?health=ok"

curl -sS -X POST \
  -H "Authorization: Bearer $FLUXHEIM_ADMIN_TOKEN" \
  "http://127.0.0.1:9090/_fluxheim/self-heal/report?health=error"
```

Successful reports confirm the pending snapshot once
`admin.self_healing.min_successful_checks` is reached. Failed reports roll back
when the observed error rate exceeds
`admin.self_healing.max_error_rate_per_mille`.

Pending validation fails closed. If the validation window expires before a
confirm request, the Pingora self-healing watchdog attempts the same known-good
rollback without waiting for operator traffic. Admin requests also enforce the
deadline as a secondary guard.

Fluxheim also records conservative proxy-integrated health signals while a
snapshot is pending validation. Successful downstream `2xx` and `3xx` responses
count toward `admin.self_healing.min_successful_checks`. Downstream `5xx`
responses and fatal Pingora proxy errors count toward the failure rate. Client
errors such as `4xx` are ignored because they often describe request behavior,
not whether the new config is broken.

The proxy-integrated path uses the same state transitions as the admin report
endpoint:

1. Mark the pre-reload snapshot as known-good.
2. Validate and apply a snapshot-safe reload through `POST /_fluxheim/reload`.
3. Watch a configurable health window with the background watchdog.
4. Treat clear failures as broken, for example local health-check failure,
   startup-owned service failure, rising 5xx rate, or repeated upstream
   selection failure.
5. Automatically swap back to the previous known-good runtime snapshot when the
   new snapshot is unhealthy.
6. Leave process-upgrade-only changes to the supervisor/Pingora upgrade path.

The first implementation should be conservative. It should prefer keeping the
old known-good config over guessing that a risky new config is healthy.
