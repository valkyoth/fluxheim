# Config Snapshots And Rollback

Fluxheim uses two layers for reload safety:

- Runtime snapshots: immutable in-memory state behind `ArcSwap`.
- Durable snapshots: validated TOML configs stored on disk with a current
  pointer.

The runtime snapshot model means old requests can keep using the config they
started with while new requests use the new config after an atomic pointer swap.
The durable snapshot store gives operators an auditable rollback target and the
admin API a current pointer to apply.

This is configuration history, not a backup of your website, database, cache,
certificates, PHP processes or external secret files. Snapshots serialize the
effective configuration and its resolved paths. Referenced assets remain external:
restoring old TOML does not restore their bytes. Retain compatible assets through
your deployment and backup process.

Start with the [admin guide](admin.md) and its
[local example](../../examples/admin/local.toml) for listeners, roles and private
credentials. The procedures here concern one instance, not a fleet transaction.

## Source, Selection And Runtime

| State | Meaning | What changes it |
| --- | --- | --- |
| Source TOML/includes | Deployment input selected by `--config` | Your deployment tooling/editor |
| Store `current` | Snapshot selected for the next admin reload | Snapshot creation or pointer rollback |
| Running router/configuration | Policy serving new requests | Startup or successful supported live apply |
| `runtime_snapshot` / `known_good_snapshot` | Recovery bookkeeping | Apply, confirmation, rollback and startup state restoration; limitations below |
| `pending_validation` | Candidate, rollback target, deadline and health counters | Self-healing reload, reports, confirmation or recovery |

- CLI `snapshot` loads source, validates and stores its effective TOML, then
  selects the new snapshot. It does not contact the server.
- HTTP `POST /_fluxheim/snapshot` captures **running in-memory configuration**,
  not edits on disk. It selects its new snapshot without applying a router.
- HTTP `POST /_fluxheim/reload` applies the selected snapshot. Editing a source
  file followed by this endpoint does not automatically capture the edit.
- CLI rollback and HTTP rollback without `live=true` change only the pointer,
  not active policy, source files or the next process's startup arguments.
- Normal startup loads `--config`. It does **not** automatically boot or verify
  the snapshot selected by `current`. Deploy the intended source before restart.

### Current Recovery Limitations

**Current limitation:** startup restores persisted snapshot labels
(or assumes the current pointer is the running baseline) without reconciling them
with the source actually loaded. After serving candidate B and restarting from
source A, status can still report B as runtime/known-good. In a fresh process,
creating snapshot A over HTTP also does not enroll A as the runtime baseline:
the first reload can have no automatic rollback target. IDs alone are not proof
of what is serving.

**Current limitation:** reloading while validation is pending replaces
that validation. Repeating the same reload resets health counters/window and
makes the candidate its own rollback target. Loading a further candidate can
make the previous **unconfirmed** candidate the rollback target; recovery then
labels it known-good. Serialize deployments, finish confirmation or explicit
rollback before another reload, and never blindly retry after a timeout.

These are confirmed gaps queued for correction. The conservative workflow below
avoids the reproduced sequential cases, but is not a concurrency/crash-atomicity
guarantee or a substitute for the fixes.

## Controlled Change Workflow

Use one deployment controller at a time, running filesystem commands as the
Fluxheim service identity. Prepare the private `control-header` file described
in the admin guide; it contains credentials and must not be publicly readable.
Adapt these paths consistently:

```sh
STORE=/var/lib/fluxheim/snapshots
KEY=/etc/fluxheim/snapshot-integrity.key
ADMIN=http://127.0.0.1:9090
```

1. **Capture and enroll the running baseline before trying a candidate.**

```sh
curl --fail-with-body --max-time 10 --header @control-header -X POST \
  -H 'X-Fluxheim-Message: verified running baseline' "$ADMIN/_fluxheim/snapshot"
```

Record the returned ID as `BASELINE_ID`. Verify actual public behavior. To work
around the fresh-store enrollment gap, explicitly live-apply that verified
baseline through rollback:

```sh
fluxheim snapshots --store "$STORE" --integrity-key-file "$KEY" verify "$BASELINE_ID"
curl --fail-with-body --max-time 10 --header @control-header -X POST \
  "$ADMIN/_fluxheim/rollback?live=true&to=$BASELINE_ID"
```

This is an explicit operator decision to mark the baseline known-good, without
opening a validation window. Check traffic and status. If live application is
unsupported or fails, stop here. See the storage-bin limitation below.

2. **Prepare and validate without publishing.**

```sh
fluxheim --config /etc/fluxheim/candidate.toml --validate-config
fluxheim --reload-from "$STORE/configs/$BASELINE_ID.toml" \
  --config /etc/fluxheim/candidate.toml
```

Classification prints `noop`, `snapshot` or `process-upgrade` with reasons. A
successfully classified process-upgrade change also exits zero: **zero exit
status is not approval for live reload**. Classification applies nothing and
does not prove origin reachability or all later runtime initialization.

3. **Publish an approved candidate with the key explicitly supplied.**

```sh
fluxheim --config /etc/fluxheim/candidate.toml snapshot \
  --store "$STORE" --integrity-key-file "$KEY" --message 'candidate route policy'
```

Record its ID as `CANDIDATE_ID`. This moves `current`; serving is unchanged.
The CLI key option does not inherit `admin.snapshot_integrity_key_file` from the
candidate. Supply it consistently on all CLI store operations, or use the
documented environment variable.

4. **Apply once, inspect, test the application, then confirm or recover.**

```sh
curl --fail-with-body --max-time 10 --header @control-header -X POST \
  "$ADMIN/_fluxheim/reload"
curl --fail-with-body --max-time 5 --header @control-header \
  "$ADMIN/_fluxheim/status"
```

With self-healing enabled, check that `pending_validation.previous_snapshot`
names the intended baseline. After meaningful tests of the public application,
not merely a green admin health response:

```sh
curl --fail-with-body --max-time 5 --header @control-header -X POST \
  "$ADMIN/_fluxheim/self-heal/confirm"
```

On failure, report failure or explicitly live-rollback to `BASELINE_ID`. When
self-healing is disabled, successful reload is immediately recorded known-good;
there is no confirmation window. After any timeout/error inspect traffic and
state before retrying: an error can follow a runtime change.

5. **Make restart behavior intentional.** Deploy the accepted source through
   configuration management; live reload does not rewrite the original source.
   Check source and selected snapshot before restart, then verify traffic and
   reconcile recovery identity afterward. Do not manually edit authenticated
   state files to make the status look consistent.

### Reload Classification

| Change | Behavior / boundary |
| --- | --- |
| Identical effective configuration | `noop`; currently still applied, so do not retry during validation |
| Routing/vhost, root proxy/static/cache/headers/compression/GeoIP, request access-log policy | Normally `snapshot`, unless startup-owned services change; feature-specific gaps still apply |
| Listener addresses, trusted proxies, PROXY protocol, server limits or process settings | `process-upgrade` |
| Logging level/format/target/file/crash file | `process-upgrade` |
| TLS mode/provider/protocol/ALPN/ciphers/curves/client authentication/compliance | `process-upgrade`; certificate lookup fields are classified separately, not proof of listener certificate replacement |
| Admin, metrics, tracing, cache-purger, TCP streams, UDP or Wasm runtime | `process-upgrade` |
| Managed PHP process or managed ACME service changes | `process-upgrade`; PHP request policy is classified separately |
| Load-balancer pools/discovery/startup services | `process-upgrade`; nonidentical router changes also reject active background health/discovery services |
| Unclassified startup state | `process-upgrade`, not assumed safe |

Classify complete effective configurations. A snapshot-safe result permits an
attempt; it does not resolve the feature gaps elsewhere in these guides. For
restart procedures, see [service lifecycle](service-lifecycle.md).

## Store Layout

Use an operator-chosen state directory, for example
`/var/lib/fluxheim/snapshots`:

```text
/var/lib/fluxheim/snapshots
├──.snapshot.lock
├── current
├── generation.toml
├── prune-boundaries.toml
├── self-healing.toml
└── configs
    ├── s1777900000-123456789-00000000000000000001-00000000000000000042.toml
    ├── s1777900000-123456789-00000000000000000001-00000000000000000042.meta.toml
    └── s1777900000-123456789-00000000000000000001-00000000000000000042.integrity.toml
```

`current` contains the selected durable snapshot id, not proof of the serving
router's identity. Fluxheim uses an atomically replaced
pointer file instead of a symlink. A symlink swap is a good Linux-only design,
but the pointer file keeps the store straightforward in rootless Podman,
restricted volume mounts, and non-Unix development environments while still
using write-temp-and-rename semantics.

Snapshot config files contain the validated effective config, written back as
TOML. Metadata files contain the snapshot id, creation time, explicit parent,
monotonic store generation, and optional operator message. Operator messages are
trimmed and limited to 4096 bytes of non-control text before they are written or
loaded. Rollback without `--to` follows explicit parent ancestry rather than
wall-clock filename ordering. Fixed-width generations and create-new file
publication prevent collisions from replacing existing history.
`generation.toml` is a durable high-water mark, so deleting a newer snapshot
cannot make a later snapshot reuse its audit generation. `prune-boundaries.toml`
records intentional ancestry cuts when retention removes an old parent while
keeping its child. Both files are authenticated when an integrity key is set.
Each authenticated integrity manifest includes a small generation witness, so
freshness checks scan at most 4 KiB per retained manifest and do not reread or
hash complete snapshot configurations while holding the store mutation lock.
Unverified stores scan metadata with a 16 KiB per-file bound.
Authenticated manifests created before generation witnesses remain readable.
Fluxheim fully verifies their original config digest and metadata HMAC for
current, rollback, and doctor operations. The next snapshot creation performs
that same verification under the store lock. If every retained authenticated
manifest predates generation witnesses and `generation.toml` does not exist,
Fluxheim bootstraps the authenticated counter from the highest fully verified
legacy generation. It persists that counter first, then atomically replaces each
legacy manifest with the witnessed format, and finally publishes the new
snapshot at generation `max + 1`. This ordering makes an interrupted migration
resumable without accepting a mixed store that has no authenticated counter. A
store with many legacy snapshots therefore pays one bounded upgrade scan that
may read their configs; subsequent mutations use only the small witnesses.
Fluxheim rejects a missing counter for a V2 or mixed manifest store, and rejects
a valid counter lower than any retained authenticated witness. An HMAC file
cannot detect coordinated rollback of the complete store after every newer
snapshot has been pruned,
because the counter and its evidence then share one rollback domain. Operators
requiring that stronger anti-rollback property must retain snapshots in
append-only storage or anchor generations in an external TPM, monotonic
counter, or equivalently protected audit system.

Every mutation holds the private `.snapshot.lock` advisory lock across capacity
validation and publication. For NFS, CSI, or another shared filesystem, verify
that cross-node file locking is reliable; otherwise enforce one writer at the
orchestration layer.

On Unix the lock file is opened relative to a no-symlink parent-directory
descriptor, using the same boundary as atomic snapshot publication. Linux uses
`openat2` with no-symlink and no-magic-link resolution when available; the
portable Unix fallback walks every component with descriptor-relative
`openat(..., DIRECTORY|NOFOLLOW)`. An intermediate path swap therefore cannot
redirect the lock to a different directory.

The store is deliberately conservative about filesystem indirection. Configure
`admin.snapshot_store` as a dedicated snapshot directory, never as `/`, `/etc`,
`/var`, a home directory, or another shared system/application directory. If
the store already exists, create it with mode `0700` and the Fluxheim service
identity as owner before startup; Fluxheim rejects a pre-existing non-private
directory and never repairs its permissions implicitly. If the final store
directory does not exist, its immediate parent must already exist and pass the
ownership, write-permission, and symlink checks; Fluxheim creates only that
dedicated final directory as `0700`.

Snapshot ids may only contain ASCII letters, digits, `_`, and `-`, and are limited to
128 bytes; the store root cannot contain `..` or sit below a symlinked parent
directory; the store root and `configs` directory must be real directories; the
`configs` directory must remain inside the snapshot store; and `current`,
snapshot TOML files, and metadata TOML files are opened as regular files.
Symlinked store roots, pointer, config, metadata, or `configs` paths are
rejected so a rollback cannot be redirected to an operator-unapproved file.
Atomic writes also require an already validated real parent directory and will
not replace a symlinked destination. Snapshot reads are bounded: `current` is
limited to 4 KiB and snapshot TOML/metadata reads are limited to 16 MiB.
Snapshot stores are limited to 1024 snapshots. Listing and doctor report corrupt
entries individually instead of hiding healthy snapshots behind one malformed
metadata file.

On Unix, Fluxheim creates a missing snapshot store root and `configs` directory
as mode `0700`, requires existing directories to already be `0700` or stricter,
and writes the lock, current pointer, recovery state, snapshots,
metadata, integrity manifests, generation state, and pruning boundaries as mode
`0600`. Reads reject existing state with any group or other permission bit; the
doctor command reports such state as unhealthy instead of silently accepting
it. The integrity key must also be a private regular file and must remain
outside the snapshot store. Operators should still run the service with a
restrictive umask such as `0077` or `0027` as defense in depth for any future
state files. Non-Unix deployments should additionally use platform ACLs to
grant access only to the Fluxheim service identity.

Snapshot configuration writes are capped at the same 16 MiB limit enforced by
all readers before a generation is allocated or any transaction file is
published. Persisted self-healing state has a separate 64 KiB envelope; its
operator-facing impact and rollback diagnostics are individually limited to
4 KiB and cannot contain control characters.

Snapshot TOML remains plaintext. Mode `0600` does not protect offline disks,
backups, or privileged support tooling. Encrypt the snapshot volume or backup
set when configurations contain secrets. Fluxheim authenticates but does not
encrypt snapshot contents.

For authenticated snapshots, create a random key outside the store:

```bash
openssl rand -out /etc/fluxheim/snapshot-integrity.key 32
chmod 0600 /etc/fluxheim/snapshot-integrity.key
```

The HMAC-SHA-256 manifest binds the exact config bytes, metadata, snapshot ID,
and external key identity. The same key authenticates persisted self-healing,
generation, and pruning-boundary state. Rollback and diff read once, verify,
and parse the same owned bytes; they do not reopen a verified pathname.
Fluxheim streams fields into the selected internal crypto provider without a
second concatenated config allocation. Normal builds use Ring, while
OpenSSL-FIPS and AWS-LC-FIPS profiles route snapshot cryptography through their
selected validated provider. Provider initialization or signing failures fail
only the snapshot administrative operation with an error; they do not terminate
the proxy data plane.
Existing stores remain readable as `Unverified`; configuring a key makes
missing or invalid manifests and recovery-state authentication fail closed.

## Commands

Create a snapshot from a config:

```bash
fluxheim --config /etc/fluxheim/fluxheim.toml snapshot \
  --store /var/lib/fluxheim/snapshots \
  --integrity-key-file /etc/fluxheim/snapshot-integrity.key \
  --message "known good before cache change"
```

List snapshots:

```bash
fluxheim snapshots --store "$STORE" --integrity-key-file "$KEY"
```

Inspect, compare, verify, diagnose, and safely prune snapshots:

```bash
fluxheim snapshots --store "$STORE" --integrity-key-file "$KEY" show SNAPSHOT_ID
fluxheim snapshots --store "$STORE" --integrity-key-file "$KEY" diff OLD_ID NEW_ID
fluxheim snapshots --store /var/lib/fluxheim/snapshots \
  --integrity-key-file /etc/fluxheim/snapshot-integrity.key verify SNAPSHOT_ID
fluxheim snapshots --store /var/lib/fluxheim/snapshots \
  --integrity-key-file /etc/fluxheim/snapshot-integrity.key doctor
fluxheim snapshots --store "$STORE" --integrity-key-file "$KEY" prune --keep 100
fluxheim snapshots --store "$STORE" --integrity-key-file "$KEY" prune --older-than-days 90
```

Pruning protects the durable current snapshot, persisted runtime and known-good
snapshots, pending validation and rollback targets, and their immediate parents.
When pruning removes an older ancestor of another retained snapshot, Fluxheim
writes an authenticated history-start boundary so `doctor` can distinguish the
intentional retention cut from filesystem damage.

### CLI Options And Output

| Command/option | Meaning |
| --- | --- |
| `snapshot --store PATH --message TEXT` | Load `--config`, validate, publish and select; optional trimmed message, at most 4096 bytes without controls |
| `rollback --store PATH --to ID` | Select a verified target; omit `--to` to follow current metadata's parent, not latest filename |
| `snapshots --store PATH` | List entries with current marker, integrity/status and message |
| `snapshots... show ID` | Metadata, generation, parent, timestamp, integrity and path; not raw config |
| `snapshots... diff OLD NEW` | Changed top-level field names, not a line-by-line secret-bearing diff |
| `snapshots... verify ID` | Print `authenticated` or `unverified` under supplied key policy; success without a key is not proof of HMAC verification |
| `snapshots... doctor` | Diagnose structure/history/integrity/temp files; failure exit if unhealthy, not automatic repair |
| `snapshots... prune --keep N` | Delete eligible entries outside newest N by generation/time; protected entries remain |
| `snapshots... prune --older-than-days DAYS` | Delete eligible entries at least that old; zero includes all ages except protected entries |
| `--integrity-key-file PATH` | Shared snapshot/rollback/snapshots option; put before snapshots subcommand |
| `FLUXHEIM_SNAPSHOT_STORE` | Environment default for required store path |
| `FLUXHEIM_SNAPSHOT_INTEGRITY_KEY_FILE` | Environment default for explicit CLI key option |

Prune needs a selector and has **no dry-run**. Supplying both selectors combines
them with OR, not AND: an eligible entry outside the keep window **or** old
enough can be deleted. `--keep 0` permits all unprotected entries to be removed.
Listing/doctor is not a deletion preview. Back up first and quiesce deployments;
do not run retention with ambiguous/unrecorded runtime identity. Retained counts
can exceed `--keep` because protection wins. Metadata and paths are sensitive
operational information even when tokens are not printed.

Move the current pointer back to the previous snapshot:

```bash
fluxheim rollback --store "$STORE" --integrity-key-file "$KEY"
```

Move to a specific snapshot:

```bash
fluxheim rollback --store "$STORE" --integrity-key-file "$KEY" --to "$BASELINE_ID"
```

Rollback updates the durable current pointer by default. Before applying a
rollback to a live process, classify the change:

```bash
CURRENT_ID=$(cat /var/lib/fluxheim/snapshots/current)
fluxheim --reload-from "/var/lib/fluxheim/snapshots/configs/${CURRENT_ID}.toml" \
  --config /path/to/candidate.toml
```

The admin reload endpoint performs this classification before it swaps runtime
proxy state. It builds the complete candidate host router first, then replaces
the active `ArcSwap` pointer in one operation. Existing requests retain the old
router across request timeout, context, takeover, and response handling while
requests pinned after the swap use the candidate. A candidate construction
failure leaves the active router and current pointer unchanged.

## Admin API Shape

Admin mutations require available audit admission before changing state. Keep
all audit outcomes enabled, including INFO successes: normal INFO logging works,
or use `RUST_LOG=warn,fluxheim::event::audit=info` for quieter general logging.
Disabled auditing, a failed writer or exhausted rate/queue capacity returns
503 `audit_unavailable` before mutation. Automatic deadline rollback also waits
for admission and retains pending recovery when it is unavailable.

If an already admitted operation returns 503 `audit_delivery_failed` with
`operation_may_have_completed: true`, inspect state before retrying. Admission
reserves memory, not durable storage; crashes and subsequent sink failures can
still lose records. See the [audit contract](../architecture/structured-events.md)
for counters and limitations. This API is not a durable intent journal.

Fluxheim reserves a separate admin control plane for live operations:

```toml
[admin]
enabled = true
listen = "127.0.0.1:9090"
require_loopback = true
token_env = "FLUXHEIM_ADMIN_TOKEN"
snapshot_store = "/var/lib/fluxheim/snapshots"
snapshot_integrity_key_file = "/etc/fluxheim/snapshot-integrity.key"

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

- `GET /_fluxheim/operational-status`: bounded read-only projection; an optional
  `admin.operational_token_file` grants access to this endpoint only. Use a
  distinct credential for monitoring rather than distributing the full admin
  token. See [Operational Status](operational-status.md) for permissions and examples.
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
When `[admin.ops_socket]` is enabled, `GET /_fluxheim/snapshots` still requires
the bearer token on the Unix ops socket because snapshot IDs and messages
expose deployment change history.

Create a snapshot over HTTP:

```bash
curl -sS -X POST \
  --header @control-header --fail-with-body --max-time 10 \
  -H "X-Fluxheim-Message: known good before upstream change" \
  http://127.0.0.1:9090/_fluxheim/snapshot
```

Move the durable current pointer back to the previous snapshot:

```bash
curl -sS -X POST \
  --header @control-header --fail-with-body --max-time 10 \
  http://127.0.0.1:9090/_fluxheim/rollback
```

Move the durable current pointer to a specific snapshot:

```bash
curl -sS -X POST \
  --header @control-header --fail-with-body --max-time 10 \
  "http://127.0.0.1:9090/_fluxheim/rollback?to=s1777900000-123456789-42"
```

Live-apply the previous snapshot when it is snapshot-safe:

```bash
curl -sS -X POST \
  --header @control-header --fail-with-body --max-time 10 \
  "http://127.0.0.1:9090/_fluxheim/rollback?live=true"
```

Live rollback validates the target before changing the durable current pointer.
If the target requires a process upgrade, Fluxheim returns `409 Conflict` and
leaves the pointer on the current snapshot.

Apply the durable current snapshot to the running proxy if the reload classifier
marks it `noop` or `snapshot`:

```bash
curl -sS -X POST \
  --header @control-header --fail-with-body --max-time 10 \
  http://127.0.0.1:9090/_fluxheim/reload
```

The reload endpoint returns `409 Conflict` when the current snapshot requires a
process upgrade, such as listener, TLS backend/mode, admin service, or
metrics service, or startup-owned load-balancer service changes. Existing
requests keep their old runtime snapshot; new requests use the freshly swapped
proxy snapshot.

**Current limitation:** the replacement router can fail
to acquire the old router's exclusive cache-root lease while reload still
reports success. Disk caching can disappear or a tiered policy can retain only
memory. Until the planned correction, use a controlled stop/start for bin-backed
routers and verify real disk reuse, not just reload status. See
[cache recovery](cache-recovery.md) for the current limitation and procedure.

Load-balancer service changes include adding or removing vhost/route pools and
changing static pool members, file/DNS/HTTP discovery sources, discovery refresh
intervals, or HTTP discovery bearer-token files. These refresh loops are
registered at process startup, so use the normal supervisor/process-upgrade path
for those changes.

Nonidentical router replacement also fails closed when an unchanged background
load-balancer health or discovery service is active, because replacing its
router without replacing the associated service would detach health state from
traffic selection. Use a zero-downtime process upgrade for snapshots in that
configuration.

## Live Lifecycle Smoke

Run the complete real-binary lifecycle proof with:

```bash
scripts/smoke_snapshot_lifecycle.sh
```

The smoke starts Fluxheim, captures an authenticated baseline through the admin
HTTP API, publishes a second validated config through the CLI, live-applies it,
verifies changed data-plane content without a PID change, performs a live
rollback, runs snapshot doctor, restarts Fluxheim, and verifies both baseline
serving behavior and the persisted current snapshot pointer. It restarts from
the baseline source explicitly: it does not prove automatic current-pointer
boot selection or correct recovery identity reconciliation.

The [guide smoke](../../scripts/smoke_snapshot_examples.py) adds real CLI/HTTP
proof of source-versus-memory capture, pointer-only selection, explicit baseline
enrollment, health reports, expiry recovery without admin traffic, and the
the documented limitation characterizations:

```sh
python3 scripts/test_snapshot_examples.py
python3 scripts/smoke_snapshot_examples.py --binary target/debug/fluxheim
```

## Self-Healing Guard

When `admin.self_healing.enabled = true`, a successful live reload enters a
pending validation state. `GET /_fluxheim/status` reports:

- `runtime_snapshot`
- `known_good_snapshot`
- `pending_validation`
- `load_balancer` when compiled with the load-balancer feature, including
  read-only vhost/route pool and backend runtime state
- `wasm` when compiled with the wasm feature, including read-only validation
  registry counts, plugin names, phases, fail modes, and expected SHA-256
  digests

Confirm the candidate after local health checks succeed:

```bash
curl -sS -X POST \
  --header @control-header --fail-with-body --max-time 10 \
  http://127.0.0.1:9090/_fluxheim/self-heal/confirm
```

Force rollback to the previous known-good snapshot after local health checks
fail:

```bash
curl -sS -X POST \
  --header @control-header --fail-with-body --max-time 10 \
  http://127.0.0.1:9090/_fluxheim/self-heal/fail
```

The fail endpoint validates the previous snapshot and applies it with the same
snapshot-safe reload gate. It also moves the durable current pointer back only
after the running proxy accepts the rollback.

Report health-check results from a local watchdog:

```bash
curl -sS -X POST \
  --header @control-header --fail-with-body --max-time 10 \
  "http://127.0.0.1:9090/_fluxheim/self-heal/report?health=ok"

curl -sS -X POST \
  --header @control-header --fail-with-body --max-time 10 \
  "http://127.0.0.1:9090/_fluxheim/self-heal/report?health=error"
```

Successful reports confirm the pending snapshot once
`admin.self_healing.min_successful_checks` is reached. Failed reports roll back
when the observed error rate exceeds
`admin.self_healing.max_error_rate_per_mille`.

These are explicit report counts, not measured HTTP traffic. The rate is integer
`failed * 1000 / (successful + failed)`. Rollback requires it to be **strictly
greater** than the threshold and is checked before confirmation. At the default
threshold 100, a first failed report is 1000 and immediately triggers rollback.
The default minimum of one successful report permits immediate confirmation.
Set desired thresholds before startup; changing admin policy requires restart.
Manual `confirm` is an operator decision and bypasses the report-count threshold,
but cannot override failed deadline enforcement.

Accepted values, case-insensitively: `ok`, `success`, `successful`, `healthy`,
`true`, `1`, `yes`, `on`; or `error`, `fail`, `failed`, `unhealthy`, `false`, `0`,
`no`, `off`. Header `X-Fluxheim-Health` wins over query `health`, then `ok`, then
`success`. Invalid input or absent pending validation returns 400. Reports do
not perform an application, origin or collector probe themselves.

Pending validation fails closed and is persisted in `self-healing.toml`,
including health counters and failed rollback attempts. If the validation
window expires before confirmation, the native watchdog retries its recorded
rollback target without waiting for operator traffic. A rollback decision
does not consume pending state; only successful runtime application plus a
durable current-pointer update clears it.

Startup restores persisted recovery bookkeeping and converts the remaining Unix
expiry to a monotonic deadline. Within a process, later wall-clock corrections
do not change that deadline; restart necessarily consults wall time again. This
does not reconcile startup configuration identity. The
watchdog checks at `validation_window_secs` clamped to 1..5 seconds, not an exact
expiry instant. Authenticated legacy admin requests also enforce recovery;
operational status and explicitly public health do not.

Public proxy traffic does not confirm or roll back pending snapshots. This keeps
unauthenticated data-plane clients from influencing admin reload state. Only
authenticated admin self-healing actions, local watchdog expiry, and explicit
operator-driven health reports can advance pending validation.

The watchdog is an expiry/error-report recovery loop, not an automatic public
HTTP checker or general startup-service fault detector. Verify/enroll a baseline,
apply one candidate, then confirm or recover before another change. Missing
targets, invalid manifests, runtime-construction failures or audit admission
failure can prevent automatic rollback. Check actual public behavior as well as
recovery state; a healthy admin listener does not imply successful recovery.

## Failure Handling

| Outcome | Action |
| --- | --- |
| Snapshot published but current update failed | History can remain; diagnose/verify before selecting an ID instead of blindly creating copies |
| Reload 409 `process_upgrade_required` | Live config not accepted; publication may already have selected the candidate; choose verified baseline or perform intentional restart |
| Candidate construction fails | Existing router retained; inspect selected pointer separately |
| Apply succeeds but recovery-state/pointer persistence fails | HTTP error does not mean no change; inspect traffic and runtime/store views before retrying |
| Expiry recovery fails | Keep pending recovery, repair the cause and observe retries; do not delete state to clear readiness |
| Doctor reports damage | Quiesce writers, preserve evidence/backups and restore a consistent verified store/key through deployment procedures |
| Integrity key lost/changed | A different key cannot verify old history; retain the original securely or establish an explicitly new trusted store |

Router publication, admin bookkeeping and filesystem writes are not one atomic
transaction. Serializing deployments limits operator overlap but cannot eliminate
crashes or disk failures between stages. HMAC authenticity also does not prove
freshness against coordinated whole-store rollback. See the store boundaries
above and the correction ledger.
