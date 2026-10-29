# Management API Handoff

Scope: implemented 1.9.0 contracts, not authorization for the proposed 1.10
management project. A separate UI must treat unsupported capabilities explicitly.
The [direction document](../ideas/management-api-direction.md) describes future
transactions, identities and fleet workflows; they are not existing features.

| Domain | Available now | Missing before complete UI management |
| --- | --- | --- |
| Observation | GET operational-status, published OpenAPI/JSON Schema, bounded API-only client | History, per-resource runtime inventory, fleet enrollment |
| Authentication | Control token, exact-route observer token, existing client-certificate policy and auth throttling | Per-user roles, tenant/resource scopes, rotation/revocation API |
| Configuration | File/CLI configuration, snapshots, verification and reload classification | Full typed read/edit API, revision preconditions, bounded draft transactions, idempotent commits |
| Recovery | Snapshot/reload/rollback and self-heal confirmation/report/failure routes | Durable job/result model and transactional persistence guarantees across all operations |
| Cache | Status, activity reset, purge variants; existing CLI inspection/warming | Consistent versioned job/config API for all cache backends |
| Load balancing | Status, member-state/weight/add/remove/update, persistence clear | Declarative persistence/reconciliation and concurrency control across file edits and runtime overrides |
| TLS/ACME | Existing certificate CLI, companion, reload socket and renewal automation | Credential-safe remote lifecycle jobs, progress, cancellation and publication contracts |
| PHP/Wasm/GeoIP | Config references and compiled/platform capability reporting | Validated module/data provisioning, complete reference/config workflow; never arbitrary upload/execute |
| Logging/metrics/tracing | Configuration, bounded counters, observer summary, external dashboards | Remote config transactions; no built-in raw log viewer, durable audit store or telemetry history |
| Process lifecycle | Existing service supervisor, platform shutdown and upgrade mechanisms | Narrow authenticated supervisor handoff; no OS-command, package, firewall or reboot endpoint |

Source of truth: `src/admin/request_router.rs`, `src/cli.rs`, the domain CLI
modules, and `crates/fluxheim-config/src/reload.rs`. Existing mutation routes use
the control credential, audit admission and recovery enforcement. The observer
credential authorizes only GET `/_fluxheim/operational-status`, including on the
Unix operations socket; it cannot read legacy status or invoke a mutation.

Only the new observer is covered by the bounded versioned
[operational contract](operational-status.openapi.json). Do not assume legacy
routes have its 16 KiB, 50 ms or side-effect-free guarantees: legacy reads can
enforce deadline rollback. Operational status returns aggregate configuration
counts, not an active configuration export, listener probe or full backend list.
The `generation` is process-local, not a durable revision suitable for If-Match.

Before a management release, derive a complete schema/CLI coverage inventory,
define persistent source-of-truth and conflict semantics, design bounded jobs and
write-only secret provisioning, and qualify failed rollback/restart paths on
every platform. Keep OS administration and site/database content outside Fluxheim.
Do not expose control tokens to browsers or represent a runtime member override
as a durable configuration transaction. The current best-effort audit mechanism
must not be advertised as a compliance journal.
