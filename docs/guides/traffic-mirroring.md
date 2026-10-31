# Traffic Mirroring

Mirroring sends a shadow request to another service while the real origin still
supplies the primary response. It is not failover, response comparison or
guaranteed request recording. Shadow failures/statuses do not replace the
primary result.

Use an authorized isolated destination without production side effects. GET
can still cause application side effects despite its HTTP classification.
Paths and query strings are copied, including secrets they contain; header
allowlisting does not redact URLs.

## Configure A Shadow Destination

Use the complete [local recipe](../../examples/proxy/mirror.toml), with origin
port 9001 and mirror port 9003. Under an existing vhost proxy:

```toml
[vhosts.proxy.mirror]
enabled = true
base_url = "http://127.0.0.1:9003/shadow"
sample_per_mille = 1000
methods = ["GET", "HEAD", "OPTIONS"]
forward_headers = ["x-request-id"]
timeout_secs = 1
max_response_bytes = "1KiB"
max_in_flight = 4
```

Equivalent blocks exist at `proxy.mirror` and `vhosts.routes.proxy.mirror`.
Binaries require `traffic-mirror`; privacy builds reject enabled mirroring.
`/asset?q=1` becomes `/shadow/asset?q=1`. The hook sees any route rewrite already
applied, not necessarily the original browser target.

Main proxy TLS settings do not configure this separate HTTP client. Use HTTPS
for remote mirrors. FIPS/ISO-required mode permits only numeric loopback HTTP
sidecars. See [authorization transport](external-authorization.md#options-and-transport)
for the same separate-client boundary.

## Sampling And Admission

Selection is deterministic for a method/target/Host tuple within one process,
with a random per-process salt. The target includes the query. A sample of 100
means roughly ten percent of keys, not every tenth request: repeated requests
to one URL can all be selected or all skipped. Restart can change the set.
Use 1000 for small deterministic tests, not as a traffic-budget guarantee.

Mirroring is scheduled after ordinary authorization and before origin/cache
dispatch, so it can also run on cache hits. Static/PHP actions and WebSocket
takeover do not pass through this hook. Work is asynchronous, without a durable
delivery queue; primary success does not acknowledge shadow completion.

`max_in_flight` uses a shared counter keyed by the literal `base_url`. Equal
destinations across routes/vhosts share it; this is not per-route isolation.
Each caller compares the shared count to its own configured limit, so configure
consistent limits for a shared destination. A process-wide blocking-work mirror
class cap of 8 further limits workers. Saturation skips shadow work.

## Current Projection Limits

**Current limitation:** The selector checks method but not
body presence. A GET with a body is selected and mirrored without that body.
The live harness confirms four bytes at the origin and zero at the shadow.
Do not treat mirroring as exact request replay or use it to qualify
body-dependent behavior.

Repeated Cookie fields are also joined with a comma instead of the `; ` used
by normal/auth paths. Keep credentials/cookies out of `forward_headers`.
Bodyless admission and faithful allowed-header handling are planned corrections.

## Options

| Field | Default | Meaning / limits |
| --- | --- | --- |
| `enabled` | false | Opt in |
| `base_url` | absent | Required when enabled; HTTP(S), no userinfo/query/fragment; optional path prefix |
| `sample_per_mille` | 1000 | 1 through 1000; use `enabled = false` to disable |
| `methods` | GET, HEAD, OPTIONS | Only GET/HEAD/OPTIONS/TRACE accepted; distinct uppercase entries, at most 16; empty selects nothing |
| `forward_headers` | empty | At most 32 distinct input header names |
| `timeout_secs` | 2 | Global HTTP deadline, 1 through 86400 seconds |
| `max_response_bytes` | 16 KiB | Drained response-body limit, 1 byte through 1 MiB |
| `max_in_flight` | 64 | Caller ceiling on shared destination counter, 1 through 1024 |

Authorization/Cookie are not copied by default. Request IDs may already have
been replaced by correlation policy; untrusted inbound values need not survive.
Auth-derived identity can be mirrored if allowlisted, making the destination a
recipient of sensitive identity data.

Fluxheim adds `Cache-Control: no-store` and internal mirror-marker headers.
The authenticated marker prevents arbitrary client markers from disabling local
mirroring. Its secret is per process, not a cross-instance loop protocol. Never
configure cycles between mirroring gateways. Internal markers are stripped from
ordinary primary requests in mirror-enabled builds. Do not allowlist marker or
HTTP framing headers.

## Verify And Troubleshoot

Run the [local hook harness](../../scripts/smoke_proxy_hooks.py) using the build
command in [external authorization](external-authorization.md#test-the-integration).
It checks path/query, diagnostic headers, excluded credentials, POST exclusion
and primary success despite shadow 503. Its body-bearing GET deliberately
characterizes the open flaw.

| Symptom | Check |
| --- | --- |
| No shadow | Feature/privacy gate, methods, deterministic sampling, shared capacity |
| Same URL always selected/skipped | Per-key sampling is not a per-request lottery |
| Different shadow identity/path | Route rewrite, correlation, auth injection, header allowlist |
| Primary succeeds while shadow fails | Expected; observe the shadow service independently |
| Empty shadow body | the documented limitation: body-bearing requests are not currently excluded |

These are Linux loopback tests, not native macOS/Windows qualification,
independent delivery accounting or approval to mirror production traffic.
