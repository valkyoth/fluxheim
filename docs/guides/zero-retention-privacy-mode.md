# Privacy Profile And Data Handling

`profile-privacy` is an implemented **compile-time** static/proxy profile. It
removes access-event capture, metrics/exporter capabilities and normal response
caching, and suppresses known client-forwarding headers. It is useful when you
want less request telemetry inside Fluxheim.

It is **not an anonymity service or a whole-deployment zero-retention guarantee**.
The historical filename of this guide is retained for links. There is no
supported `[privacy]` TOML table or runtime switch that converts a normal
package into this profile. Adding that table fails configuration parsing.

An upstream still receives the request path, query, body and ordinary
application headers, including cookies and authorization. The OS still handles
peer addresses, sockets and memory. A container logger can persist stderr even
when Fluxheim file logging is disabled. Choose the profile and the deployment's
data policy together.

## Build And Start

Privacy is a custom build, not an extra official portable artifact:

```sh
cargo build --release --locked --no-default-features \
  --features profile-privacy --bin fluxheim
target/release/fluxheim --version
target/release/fluxheim --config examples/privacy/local.toml --validate-config
target/release/fluxheim --config examples/privacy/local.toml
```

Use the [local example](../../examples/privacy/local.toml) as a starting point.
It binds only `127.0.0.1:8080`. The included
[static page](../../examples/privacy/public/index.html) is reachable with:

```sh
curl --fail -H 'Host: private.example.test' http://127.0.0.1:8080/
```

Its second vhost, `app.example.test`, proxies to an application you must run on
`127.0.0.1:3000`. The example does not launch an origin. Keep the bind local while
testing; public use also needs reviewed firewall and [TLS](tls.md) configuration.
On Windows use the `.exe` executable and Windows filesystem paths.

The older [container-oriented example](../../examples/privacy.toml) uses
`/run/fluxheim` and `/srv/fluxheim`; those paths must exist with service-user
permissions. See [container builds](build-and-podman.md) and
[installation](installation.md). Neither example's logging settings make a
non-privacy binary a privacy build.

`profile-privacy` selects `proxy`, `web`, `tls-rustls`, `privacy-mode` and
`security`. Always use `--no-default-features`: normal defaults contain cache.
The build flag propagates to config, headers, native server and structured-event
capture, not just a top-level log setting.

## What The Build Enforces

| Surface | Current behavior |
| --- | --- |
| Structured access events | Suppressed by compile-time privacy policy, even if an internal caller asks to capture one |
| `logging.access.enabled = true` | Configuration rejected; default is false in this build |
| Fluxheim-generated request IDs | Not generated for correlation; an inbound `x-request-id` is not automatically removed |
| Trace handling | No trace generation/export; the native request telemetry boundary removes inbound `traceparent`, `tracestate` and `baggage` |
| `logging.file.enabled = true` | Configuration rejected |
| `logging.crash_file` | Configuration rejected; runtime logging initialization also refuses it before file creation |
| Structured error/security/admin audit events | Still possible; resource and request/trace correlation fields are suppressed. Bounded reason/operation/outcome and timing information remain |
| Known client-forwarding headers | Removed from native proxy requests, including when request-header policy is disabled |
| Forwarding synthesis | Native `x_forwarded_for`, `x_real_ip`, `x_forwarded_host`, `x_forwarded_proto` and `forwarded` synthesis is not compiled into the privacy path |
| Header template `{remote_addr}` | Resolves to no value; this is not suppression of every other template or application field |
| Ordinary response cache | The `cache` feature is incompatible; enabled cache configuration is rejected by the privacy server's module check |
| Metrics and OTLP | Features are incompatible; no exporter or scrape service in the baseline privacy build. See the validation gap below |
| Load-balancer persistence | Enabled persistence is rejected by privacy-aware config validation; this does not remove every transient connection or admission state |

The current Rust feature graph rejects these combinations:

- `privacy-mode` with `cache` or `geoip`.
- `privacy-mode` with `compression` or compression codecs that select it.
- `privacy-mode` with `metrics`, `metrics-otlp`, `otel-tracing` or `otel-otlp`.
- `privacy-mode` with `wasm`, `wasm-proxy-abi` or `wasm-wasi`.

Use the [feature reference](../reference/features.md) for dependency expansion.
The shell feature preflight is not authoritative for every nested/conflicting
combination; the real locked build remains required.

Do not infer that every other feature combination is rejected. PHP, auxiliary
protocols, ACME, external authorization and other additions are not part of the
baseline qualification here. Some have independent filesystem/network effects.
An earlier design listed additional proposed exclusions; those were not all
implemented build guards. Do not advertise a custom extended build as having
the baseline's tested boundary without reviewing and testing its data paths.

**Current limitation:** `metrics.enabled = true`
currently passes `--validate-config` and service startup in a privacy binary,
but no metrics listener is created. It does not cause metrics disclosure; it
silently accepts an unavailable service. Keep `metrics.enabled = false`.
the local follow-up will reject unavailable service configuration consistently, including
non-privacy binaries missing the feature. `tracing.enabled = true` already fails
when its feature is absent (and privacy policy separately rejects tracing).

## Configure The Baseline Explicitly

The local example uses these ordinary configuration sections, not a special
privacy table:

```toml
[logging]
level = "info"
format = "json"
target = "stderr"

[logging.access]
enabled = false
request_id = false

[logging.file]
enabled = false

[metrics]
enabled = false

[tracing]
enabled = false

[cache]
enabled = false

[admin]
enabled = false
```

Leave cache memory/disk tiers and peer fill disabled as well. Explicit choices
make review easier, but compile-time restrictions are the protection against
enabling access logs in this profile. Ordinary logging remains available.
`RUST_LOG` affects filtering; inventory the service environment rather than
assuming `logging.level` is the final effective filter.

## Headers Are Not Anonymization

The native header policy strips this case-insensitive list:

| Removed header | Removed header | Removed header |
| --- | --- | --- |
| `x-forwarded-for` | `x-real-ip` | `forwarded` |
| `x-forwarded-host` | `x-forwarded-proto` | `cf-connecting-ip` |
| `true-client-ip` | `x-client-ip` | `client-ip` |
| `x-cluster-client-ip` | `fastly-client-ip` | `x-envoy-external-address` |
| `x-original-forwarded-for` | `x-azure-clientip` | `fly-client-ip` |
| `x-proxyuser-ip` | `x-forwarded-client-cert` | |

Stripping happens even if `headers.request.enabled = false` or
`strip_inbound_client_ip_headers = false`. In an enabled policy it happens after
custom set/append processing, so re-adding a listed name does not override it.
Header-derived client-IP restoration is not performed in the privacy path;
access decisions can still use the immediate/effective connection identity.
Do not assume all IP-based transient state disappears.

These ordinary application fields are **not** blanket-stripped:

- `Authorization`, `Cookie`, `User-Agent`, `Referer`, `Host` and custom headers.
- Inbound `x-request-id` and `x-correlation-id` when no explicit removal policy
  owns them. Not generating an ID is different from deleting one.
- Paths, queries and bodies; TLS encrypts transport, not what the origin sees.
- Administrator-configured URI, query, request-ID and certificate-identity
  templates; `{remote_addr}` suppression does not cover them all.

If your application does not need diagnostic identifiers or referrers, remove
them explicitly at the appropriate root/vhost/route scope:

```toml
[vhosts.headers.request]
enabled = true
unset = ["x-request-id", "x-correlation-id", "referer"]
```

Keep authentication/session headers unless your application is designed to work
without them. Broad removal can break login and authorization. This profile
does not make untrusted IDs trustworthy. An upstream must still treat diagnostic
IDs as metadata, not credentials. Follow [request-header scope and mutation
rules](request-headers.md), including documented template limitations.

## Static Files, TLS And Application Traffic

The example disables directory listing and sends `Cache-Control: no-store` for
static files. These are explicit deployment choices, not privacy-only schema
restrictions. The profile does not itself forbid directory listing.

```toml
[vhosts.web]
root = "public"
deny_dotfiles = true
cache_control = "no-store"

[vhosts.web.directory_listing]
enabled = false
```

Static response headers do not automatically change proxied application
responses. Configure the origin or a scoped [response-header policy](response-headers.md)
when you need a proxy response's cache directives changed. Browser/intermediary
behavior is outside Fluxheim's retention boundary.

Static certificates work with the rustls backend; follow the [HTTPS guide](tls.md)
for fallback/SNI certificates, key permissions and listener configuration.
Upstream HTTPS separately needs [certificate/hostname verification](upstream-tls.md).
Using TLS does not remove application logging or prevent either endpoint from
seeing request content. Configured certificate identities and keys are retained
for their operational purpose; they are not visitor request logs.

## Operational And Administrative Data

Privacy builds still have operational logging. Typed security/error events can
describe a policy rejection or failed operation, and opt-in admin mutations can
emit audit operation/outcome/actor events. These disclose that an event occurred
and when, even without request identity. They are not access logs, but they are
also not silence.

The bounded legacy logger escapes control characters; it is **not a general
secret redactor** for arbitrary dependency messages. CLI configuration dumps and
parse diagnostics can contain configured values. Avoid public debug output and
unrestricted `RUST_LOG=trace`; see [logging](logging.md) and [CLI guidance](command-line.md).
Canary tests for specific paths do not prove all possible dependency/error
messages safe.

Admin is disabled in the baseline, not removed from the binary. If you enable
it, its role/authentication rules still apply. Snapshot operations can persist
effective configuration; self-healing records recovery state; authentication
throttles maintain bounded transient source state. Enabling admin is a data
policy decision, not a no-retention operation. Follow [admin](admin.md) and
[snapshot/recovery](config-snapshots.md) guidance, including current corrections.

Do not set logging to off to bypass auditing: audited admin operations can
fail closed when required audit admission is unavailable. Audit enqueue success
is not durable persistence, and stdout/stderr collectors may retain a record
outside the process. Neither property is a tamper-proof audit guarantee.

## Where Data Can Remain

| Location | Privacy-profile boundary / operator action |
| --- | --- |
| Live requests, TLS buffers, sockets, connection pools | Transient data is required to serve traffic. This is not secure erasure of every allocation, allocator page or kernel buffer |
| Rate limits and authentication throttles | Bounded in-memory state can be keyed by source. Review its lifetime and disable only with an explicit abuse-protection decision |
| Fluxheim access/file/crash logs | Access capture and configured file/crash sinks are restricted as above; ordinary stdout/stderr still exists |
| systemd journal, Podman/Docker log driver, terminal captures | Independent retention; inventory collectors, permissions, storage and deletion schedules |
| Config and snapshots | May contain inline credentials, URLs and internal topology; protect originals, stores and backups. HMAC authentication does not encrypt snapshot contents |
| Normal-build disk cache / PHP spool / extension output | Not covered by the baseline; replacing a normal binary with a privacy build does not delete pre-existing state |
| Origin, auth service, CDN, firewall and load balancer | Independently receive/log traffic and identities. Configure their policies separately |
| Swap, hibernation, crash dumps, host memory inspection | Deployment controls remain necessary. Linux entrypoints establish verified non-dumpable state, but this is not protection from privileged inspection or a Windows/macOS dump policy |
| Filesystem metadata, backups and snapshots | Reading static files can affect metadata; deleting a log is not secure erasure from filesystem snapshots or backups |
| Browsers and clients | Request history, cookies and caches are outside server control; `no-store` is a response policy, not a deletion command |

For a change from an existing deployment: inventory old logs/caches/spools,
stop old writers, choose retention/deletion according to your obligations,
configure external collectors, build and verify the privacy artifact, then run
real traffic tests. Do not indiscriminately delete keys or recovery state.

## Qualification And Limits

```sh
cargo build --locked --no-default-features --features profile-privacy --bin fluxheim
python3 scripts/test_privacy_examples.py
python3 scripts/smoke_privacy_examples.py --binary target/debug/fluxheim --tls
```

`--tls` adds a locally generated, verified certificate test and needs OpenSSL.
Without it the portable harness tests HTTP, not HTTPS. It sends synthetic
canaries to a loopback origin, checks every listed forwarding header, verifies
trace-field removal and intentional application-header retention, exercises
disabled/custom header policies, checks static no-store behavior, and scans
captured process output after shutdown. It also verifies file/access/crash/
trace/cache rejection, rejects the nonexistent privacy table, characterizes
the metrics admission gap, and proves opt-in snapshot/audit behavior.

The tests are bounded local observations, not continuous attestation or proof
against a compromised process. Full HTTP/2/WebSocket/custom-feature retention,
load/cancellation, external log drivers, and native Windows/macOS behavior need
their own platform/scenario evidence. Do not relabel a Linux smoke as proof of
all three operating systems. The [documentation ledger](../reference/documentation-coverage.md)
records completed checks and outstanding qualification.
