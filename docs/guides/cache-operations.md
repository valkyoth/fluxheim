# Cache Operations

Use this guide after [configuring a public-content cache](cache.md). Cache
operations do not replace application authentication, deployment rollback or
backups. Commands must use the same configuration, identity and filesystem
permissions as the server. Inspect output privately: keys, paths and tags can
reveal application structure even when response bodies are not printed.

## Current Invalidation Warnings

- **Current limitation:** native bounded indexed purges currently report
  `truncated = false` even when matches remain. Consequently `batches` can stop
  after one batch and `repeat_required = false` is not proof of completion.
  Stale scans can repeatedly inspect the same fresh front entries and never
  reach later stale ones. Both memory and disk reporting are affected.
- **Current limitation:** storage-bin `soft=true` currently performs a
  hard deletion. It does not retain the stale representation for revalidation
  or origin-failure fallback. Memory/filesystem soft purge retains the object,
  subject to its existing stale-serving policy.
- **Current limitation:** disk stale `dry_run=true` is not reliably
  non-mutating. Its lookup can remove fully expired or invalid objects before
  counting them, even while the response reports `purged = 0`. Do not use it
  as a guaranteed read-only inventory or safety preview.

These are pending corrections, not guarantees supplied by passing tests. Use
targeted exact/bulk invalidation for known public objects and verify subsequent
responses/origin counts. For a bounded index purge, inspect the remaining scope
explicitly rather than trusting completion flags. Avoid unrestricted retry loops
on a changing production cache. Changing a namespace or safely switching to a
fresh root is an alternative when complete invalidation cannot be established;
see [recovery](cache-recovery.md). Neither invalidation nor a namespace change
revokes content already delivered to clients or other caches.

## Choose The Right Tool

| Question | Tool | What it proves |
| --- | --- | --- |
| Would this request qualify, and which policy/key applies? | `cache-key` | Configuration-derived identity, not a live cache hit |
| Is a persisted filesystem object present and fresh? | `cache-lookup` | Metadata visible to a separate process; not live RAM or another process's storage-bin allocator |
| Can the running server fill and reuse an object? | `cache-warm` plus status assertions | Real HTTP behavior through the serving listener |
| What is happening in the running cache? | Admin `GET /_fluxheim/cache/status` | Live policy/activity/occupancy summary |
| Can I invalidate content? | Protected admin purge endpoints | Local-node invalidation with bounded progress/results |

These CLI commands require appropriate compiled features. `cache-key` and
`cache-lookup` need cache and proxy support. Configuration validation still
applies; running inspection as root is not a substitute for fixing service
permissions. `cache-keygen` generates a secret, not a cache identity; see
[encryption](cache-encryption.md) before using it.

## Inspect Before Warming

**Current limitation:** root-only proxy caching works
over HTTP, but offline preview requires a named vhost. Without one, `cache-key`
reports `no matching vhost` and `cache-lookup` cannot inspect the root cache.
This is a pending diagnostic correction, not proof that HTTP caching is off.

For the supported workflow, combine the [loopback example](../../examples/cache/local.toml)
with the [explicit-vhost fragment](../../examples/cache/operations.toml). Run
from the repository root; the generated file is local test configuration:

```sh
cat examples/cache/local.toml examples/cache/operations.toml > examples/cache/operations-local.toml
fluxheim --config examples/cache/operations-local.toml --validate-config
fluxheim --config examples/cache/operations-local.toml cache-key \
  --host cache.test --path /asset.css --expect-eligible \
  --expect-memory-tier-enabled --expect-storage-tiers 2

fluxheim --config examples/cache/operations-local.toml cache-key \
  --host cache.test --path /asset.css --method HEAD --expect-ineligible
```

Use `--query 'version=2'` separately from `--path` for key/lookup commands.
Supply variant headers with repeated `--header 'Name: value'`. `--host` selects
the configured virtual host; its name and its HTTP hostname can differ. Route
selection follows the configuration rather than a CLI route override.

The fragment explicitly enables a vhost-owned memory/filesystem cache; it does
not inherit the root cache policy. Prepare its service-owned private
`examples/cache/state/cache` directory as described in the caching guide, start
the server with this combined configuration and warm the named host. Then:

```sh
fluxheim --config examples/cache/operations-local.toml cache-lookup \
  --host cache.test --path /asset.css --require-object
```

Lookup prints freshness, status, body length, tier, tags and header names, not
the cached body. An empty lookup is expected for a memory-only server because
the command cannot inspect another process's RAM. It does not fetch an origin
to repair a miss. Encrypted storage needs the configured key/provider access.
Use the same host/query/variant inputs as the original request.

Standalone storage-bin lookup cannot construct an independent allocator; bin
inspection requires a cache registered in the same process. An empty CLI result
therefore does not prove that the running bin cache is empty. Use live responses
and protected status instead. The [recovery guide](cache-recovery.md) explains
the single-owner rule, reload limitations and safe layout changes.

For automation, both commands expose policy expectations such as scope, vhost,
route, namespace, lock, predictor, origin protection, peer fill and tier counts.
Lookup additionally offers object/freshness/status/header/tag expectations.
Run `fluxheim cache-key --help` and `fluxheim cache-lookup --help` for the exact
flags; the [backend reference](cache-backends.md) explains their output and
assertions. An assertion failure reports a failed check, but does not undo
earlier filesystem work. Standalone filesystem inspection can rebuild a cache
view and perform recovery/pruning; disk lookup is not guaranteed read-only.
Do not run it against production state when a non-mutating inventory is required.

## Warm Through The Server

Start the origin and Fluxheim as shown in the caching guide. For a cold cache:

```sh
fluxheim --config examples/cache/local.toml cache-warm \
  --listen 127.0.0.1:8088 --host cache.test --path /asset.css \
  --repeat 2 --expect-cache-status-sequence MISS,HIT
```

The first request should fetch the origin; the second should reuse the object.
If it was already warm, `HIT,HIT` is legitimate and the cold-cache assertion
will fail. Do not purge production content merely to satisfy a demonstration.
For an already deployed cache, `--expect-cache-status HIT` checks every attempt.
Use your configured `--cache-status-header` when it differs from `x-cache-status`.

`cache-warm` sends plaintext HTTP GET requests to a numeric socket address. It
does not negotiate TLS or follow redirects. Use a private HTTP listener on the
same host; do not point it at the HTTPS port. The default is the first
`server.listen`; wildcard bind addresses become loopback. Other numeric
addresses are accepted, so selecting a safe destination remains your job.

A warm input file contains one target per line:

```text
# Host may be explicit, or supplied with --host for path-only lines.
assets.example.test /assets/app.css
assets.example.test /assets/logo.png?version=2
```

```sh
fluxheim --config /etc/fluxheim/fluxheim.toml cache-warm \
  --listen 127.0.0.1:8080 --input /trusted/deploy/warm-targets.txt \
  --header 'Accept-Language: en' --max-targets 256 --dry-run
```

Review the plan, then omit `--dry-run`. Inputs are UTF-8 and limited to 1 MiB;
blank lines and lines beginning with `#` are ignored. Paths must start with `/`,
fit 8192 bytes and contain no raw whitespace/control characters. Headers must
pass the command's safe-header validation; never use warming to send credentials
into a shared cache. Variants still need the correct configured/origin policy.

| Option | Default / behavior |
| --- | --- |
| `--path` / `--input` | Repeat paths or read a target list; both contribute to the same target budget |
| `--host` | For path entries; defaults to a configured vhost hostname if available |
| `--header` | Repeat safe negotiation headers; not raw arbitrary HTTP |
| `--timeout-secs` | `10`, positive per-connect/read/write socket timeout, not a total job deadline |
| `--max-targets` | `256`, between 1 and 4096 |
| `--repeat` | `1`, between 1 and 16; targets times repeat must not exceed 4096 |
| `--fail-fast` | Stop after the first failed request; otherwise report the batch failures |
| `--dry-run` | Validate and print targets without network requests |
| `--allow-status` | Add an accepted status; 2xx and 3xx already count as successful responses |
| `--cache-status-header` | `x-cache-status`; choose the configured diagnostic header |
| `--expect-cache-status` | Repeat to allow any listed status on each attempt |
| `--expect-cache-status-sequence` | Comma-separated sequence with one value per repeat; cannot combine with the preceding option |

Requests are sequential, not a load generator. A counted 200/302 is not proof
of caching: use cache-status assertions and origin counts. `--allow-status 404`
is useful only when intentional negative caching is configured; it does not
enable storage of 404 responses by itself.

## Inspect And Invalidate The Running Cache

Use the protected admin listener described in
[configuration snapshots and administration](config-snapshots.md). The commands
below assume it is already bound to loopback port 9090 and use a private header
file `/run/secrets/fluxheim-admin-header` containing
`Authorization: Bearer <your-control-token>`. Create it through your secret
management workflow with restrictive service/operator-only permissions; never
commit it. The observer token cannot access cache status or mutate cache state.

Admin mutations also require audit admission. Set the following for the guide's
local example, which otherwise uses `level = "warn"`:

```toml
[logging]
level = "info"
format = "text"
```

Replace its existing logging table, do not append a duplicate. Keep audit events
enabled in any `RUST_LOG` override too. A filtered, full or failed audit pipeline
can return `503` with `audit_unavailable` before mutation. A post-mutation audit
failure can report `operation_may_have_completed`; inspect state before retrying.
Audit admission does not guarantee durable storage. See [logging](logging.md)
and the [accepted audit boundary](../evidence/observability-03.md).

```sh
curl --fail-with-body --header @/run/secrets/fluxheim-admin-header \
  http://127.0.0.1:9090/_fluxheim/cache/status

curl --fail-with-body --request POST \
  --header @/run/secrets/fluxheim-admin-header \
  --header 'x-fluxheim-cache-vhost: assets' \
  --header 'x-fluxheim-cache-host: assets.example.test' \
  --header 'x-fluxheim-cache-path: /assets/app.css' \
  http://127.0.0.1:9090/_fluxheim/cache/purge
```

Use the actual configured vhost name (`assets` here), not automatically its
hostname. Add `x-fluxheim-cache-route` for a route-owned policy. Exact purge
defaults to GET; use `x-fluxheim-cache-method` and `x-fluxheim-cache-query` if
needed. Exact identities include query values when the policy includes them;
the path must not smuggle traversal or encoded separators. All stored variants
of a matched primary identity are invalidated.

All routes below start with `/_fluxheim/cache/`. Query parameters are an
alternative to the corresponding `x-fluxheim-cache-*` headers; encode query
values correctly. These are POST routes, not JSON-body commands.

| Endpoint | Scope and parameters |
| --- | --- |
| `purge` | One `vhost`, optional `route`, `host`, `method`, `path`, `url_query`/`cache_query` |
| `purge-bulk` | Multiple `path` parameters, same identity scope/query for each |
| `purge-index` | Whole indexed `vhost` or `route`; `limit`, `batches`, optional `soft` |
| `purge-prefix` | Indexed `path_prefix`, such as `/assets/`; `/` is deliberately rejected |
| `purge-wildcard` | Indexed `pattern`, such as `/assets/*.css`; not an arbitrary regular expression |
| `purge-tag` | Indexed `cache_tag`, matching tags retained from configured origin tag headers |
| `purge-stale` | Bounded scan of expired entries; `limit`, `batches`, optional `dry_run` |
| `activity/reset` | Reset activity counters, without removing objects |

Prefix, wildcard and tag purges also accept `limit`, `batches` and `soft`.
For example, preview stale cleanup, then perform a targeted hard invalidation:

```sh
curl --fail-with-body --request POST \
  --header @/run/secrets/fluxheim-admin-header \
  'http://127.0.0.1:9090/_fluxheim/cache/purge-stale?vhost=assets&limit=500&dry_run=true'

curl --fail-with-body --request POST \
  --header @/run/secrets/fluxheim-admin-header \
  'http://127.0.0.1:9090/_fluxheim/cache/purge-prefix?vhost=assets&path_prefix=/assets/&limit=500&batches=4'
```

Hard purge is the default. Memory/filesystem indexed `soft=true` marks objects
stale but retains their bodies for permitted revalidation/stale serving;
storage-bin currently deletes them instead. Soft purge is not suitable for
removing disclosed/private content. Hard invalidation is not secure disk erasure
either. Neither operation removes browser/CDN copies or copies on peers. A peer
can refill an old object unless invalidation/version changes are coordinated.

Check response counts and actual remaining objects, not just HTTP status.
`truncated`, `repeat_required` and `batches_exhausted` are currently unreliable
completion indicators. The request has a bounded result/scan
limit; that is not a complete filesystem inventory or a hard bound on all index
traversal work. Stale dry-run executes one scan, but can delete objects as noted
above. `increase_limit_required` cannot currently be relied on
to expose a partial native scan. Exact/bulk responses distinguish purged and
not-purged objects and per-tier results; verify content independently.

## Schedule Stale Cleanup

```toml
[cache_purger]
enabled = true
interval_secs = 300
limit = 512
batches = 1
```

This is a global background indexed disk-cleanup task, not request-time TTL or
an origin warm-up job. Defaults are disabled, 300 seconds, 512 entries and one
batch. Bounds are 1-86400 seconds, 1-100000 entries and 1-100 batches. Watch
purger truncation, duration and entry counts before increasing work per tick.

Until the local follow-up, the background disk purger has the same fresh-prefix and false
completion problem as the admin path. More configured batches do not repair
that behavior. Monitor disk usage separately and do not assume each periodic
run eventually visits every stale object.

## Verified Recipe Scope

`scripts/smoke_cache_operations.py` starts an actual local server with the
checked-in named-vhost recipe, private control/observer tokens and loopback-only
listeners. It exercises status, exact/header purge, bulk, prefix, wildcard, tag,
indexed purge, fresh-only stale preview and activity reset, across memory,
filesystem-only and storage-bin-only policies. It verifies denied anonymous and
observer access, bodies, origin counts and the incomplete-purge defect. Dedicated
Rust fixtures reproduce stale-prefix starvation, bin soft deletion and expired
disk deletion during dry-run. Passing these characterizations does not close
the findings; native Windows/macOS and encrypted-operation proof remain separate.

Do not remove live cache directories by hand. Preserve encrypted root/nonce
state during supported operations, do not share one root between nodes, and
do not assume reload clears every retained cache object. Verify invalidation
through live responses and counters; use an explicit namespace/version change
when deploying incompatible public representations. The
[encryption guide](cache-encryption.md) covers key/root rotation separately.
