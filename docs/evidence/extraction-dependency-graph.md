# Extraction Dependency Graph

Status: `1.6.0` Pingora-exit planning baseline

Fluxheim should split large modules by dependency direction, not by line count
alone. The root crate should keep orchestration and adapters while pure domain
logic moves into focused crates that can be tested without the current Pingora
runtime.

## Dependency Direction

Target dependency direction:

```text
fluxheim-common
  -> fluxheim-protocol
  -> fluxheim-config
  -> domain crates
  -> runtime/server/proxy adapters
  -> root fluxheim binary
```

The root crate may temporarily adapt Pingora request, response, listener, cache,
and service types. Domain crates should not depend on those adapters.

## Extraction Order

| Current area | Target boundary | Why this order |
| --- | --- | --- |
| `snapshot.rs` | `fluxheim-snapshot` | Mostly filesystem/config snapshot policy; already has a crate and should keep shrinking root admin/runtime coupling. |
| `proxy_protocol.rs` | `fluxheim-protocol` | Pure framing plus the current Pingora L4 connector adapter; split protocol bytes before stream/server replacement. |
| `trace_context.rs` and OTLP helpers | `fluxheim-observability` | Pure parsing/export formatting can move before HTTP runtime changes. |
| `headers.rs` | `fluxheim-headers` or `fluxheim-http-policy` | Security-sensitive but mostly request/response policy; extract pure rules before replacing Pingora HTTP types. |
| `tls.rs` listener/provider policy | `fluxheim-tls` | Own downstream listener planning, certificate selection, SNI matching, ALPN/cipher policy, and TLS provider/FIPS checks before replacing the Pingora listener adapter. |
| `acme.rs` | `fluxheim-acme` | Large filesystem/TLS/runtime integration surface; extract after listener/TLS boundary traits exist. |
| `runtime.rs` | `fluxheim-runtime` and `fluxheim-server` | Own task, shutdown, listener, TLS, and server bootstrap abstractions before removing Pingora server services. |
| `cache.rs` | `fluxheim-cache` | Continue moving admission, keys, headers, storage plans, and purge logic; keep only Pingora cache adapters in root until HTTP proxy cutover. |
| `proxy.rs` | `fluxheim-proxy` | Last large HTTP cutover; depends on config, protocol, headers, cache, PHP, observability, auth, mirror, compression, TLS, and server boundaries. |
| `admin.rs` | `fluxheim-admin` | Depends on nearly every domain. Split after domain crates own status DTOs and mutation APIs. |

## 1.6 Rules

- Do not create a crate that depends back on the root `fluxheim` crate.
- Prefer pure request/response view traits over concrete Pingora request
  headers in domain crates.
- Keep temporary Pingora adapters narrow and named as adapters.
- When moving code, move tests with the owned logic rather than leaving all
  private behavior tests in root modules.
- If a moved file would exceed 500 lines, split it during extraction instead of
  creating a new oversized exception.

## Review Use

Pentest and SAST reviews should use this graph to scope findings:

- pure parser or policy bug: fix in the domain crate;
- adapter bug: fix in the root adapter and add a domain-crate regression where
  possible;
- runtime lifecycle bug: fix through `fluxheim-runtime` / `fluxheim-server`
  abstractions before touching HTTP proxy orchestration;
- broad proxy lifecycle bug: keep it in the `1.6.x` HTTP cutover queue unless
  it is a release-blocking security fix.
