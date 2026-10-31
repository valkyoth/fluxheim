# Proxy Transport Options

Use these in `[proxy]`, `[vhosts.proxy]` or `[vhosts.routes.proxy]`. Start with
the [reverse-proxy guide](../guides/reverse-proxy.md) and its complete recipe.
This reference covers transport and local gateway pages; origin selection,
discovery and health are in [load-balancer options](load-balancer-options.md),
TLS in [upstream TLS](../guides/upstream-tls.md), and request hooks in
[authorization](../guides/external-authorization.md) and
[mirroring](../guides/traffic-mirroring.md).

| Field | Default / bounds / meaning |
| --- | --- |
| `upstream` / `upstreams` | Single authority or list, not both; no URL scheme/path; explicit vhost tables need an origin to proxy |
| `upstream_http_version` | `http1`, `http2`, `http1-and-http2`; see mode restrictions below |
| `upstream_proxy_protocol` | `off`, `v1`, `v2`; native HTTP/1 only; sends connection metadata before TLS and disables idle connection reuse |
| `upstream_h2c_upgrade` | `false`; requires plaintext `http1-and-http2`; sends an OPTIONS upgrade probe |
| `websocket` | `false`; requires `http1`; separate upgrade tunnel, not ordinary HTTP response buffering |
| `upstream_h2_max_streams` | Unset uses native H2 default 32; explicit 1-1024; shared stream admission only on pooled H2 path |
| `upstream_h2_ping_interval_secs` | Unset disables; positive seconds up to 86400; H2-capable modes only |
| `connect_timeout_secs` | Unset uses native 5s; DNS/TCP and separately TLS handshake |
| `upstream_total_connection_timeout_secs` | Unset adds no overall setup timer; see first-H2-response caveat |
| `upstream_idle_timeout_secs` | Unset adds no age expiry; HTTP/1 idle pool only, checked on reuse |
| `read_timeout_secs` | Unset native HTTP/1 30s; explicit value also sets H2 response-head and body policies |
| `send_timeout_secs` | Unset native HTTP/1 30s; explicit value also sets H2 request-write lifetime |
| `downstream_read_timeout_secs` | 60s request-body policy |
| `downstream_write_timeout_secs` | 30s response-write policy |
| `downstream_total_response_timeout_secs` | 300s response-write lifetime |
| `downstream_min_send_rate_bytes_per_sec` | Unset disables; positive bytes/second when configured |
| `upstream_tcp_keepalive_idle_secs` | Unset; idle delay before TCP probes; positive, at most 86400s |
| `upstream_tcp_keepalive_interval_secs` | Unset; TCP probe interval; positive, at most 86400s |
| `upstream_tcp_keepalive_count` | Unset; 1-128 probes; set all three keepalive fields together |
| `upstream_tcp_user_timeout_ms` | Unset; positive milliseconds; requires the three keepalive fields; native support on Linux/Android/Fuchsia/Cygwin, rejected on macOS/Windows |
| `upstream_tcp_recv_buffer_bytes` | Unset uses OS default; positive byte-size value, at most 256MiB; requested socket receive buffer, actual allocation is OS-dependent |
| `upstream_dscp` | Unset; 0-63, shifted into traffic-class bits; setting may fail by address family/OS, notably native IPv6 Windows is unsupported |
| `upstream_tcp_fast_open` | `false`; `true` is currently rejected by native runtime construction, not a portable optimization |
| `error_pages` | Empty list; at most 64 entries; internal static fallback on selected gateway failures only |

Optional timeout seconds must be positive and at most 86400. An omitted field
is not the same as setting zero. Transport OS calls can still fail even for a
validated value; qualify custom socket settings on each deployed platform.

## TCP Probe Example

```toml
[vhosts.proxy]
upstreams = ["127.0.0.1:9001"]
upstream_tcp_keepalive_idle_secs = 60
upstream_tcp_keepalive_interval_secs = 10
upstream_tcp_keepalive_count = 3
upstream_tcp_recv_buffer_bytes = "256KiB"
upstream_dscp = 0
# Linux-specific deployment, not the portable recipe:
# upstream_tcp_user_timeout_ms = 30000
```

Do not use TCP probe timing as a substitute for request timeouts. PROXY protocol
also needs an origin explicitly configured to parse it; an ordinary HTTP or TLS
listener cannot consume that preamble. It conveys the trusted-proxy-aware client
address; restored IPs have unknown source port 0. Without a usable same-family
pair, v1 sends UNKNOWN and v2 sends UNSPEC. This is not authentication or
encryption. Restrict which hosts can connect to the origin's PROXY listener.

## Error-Page Fields

| Field | Meaning |
| --- | --- |
| `error_pages[].status` | 400-599; duplicates rejected; used only at implemented fallback triggers |
| `error_pages[].path` | Internal absolute request path under this page's static root |
| `error_pages[].web` | Static web configuration; a `root` enables it and is required; there is no `enabled` switch; normal static validation applies |

See the [worked page example](../guides/reverse-proxy.md#serve-a-friendly-gateway-error).
Origin error responses are not intercepted. Static-file caching and its policy
are explained in [caching](../guides/cache.md); these pages are not a second
application execution pipeline.

## Current Mode Boundaries

- Plaintext mixed mode without `upstream_h2c_upgrade` passes general validation
  but native construction rejects it. Use explicit `http1` today.
- Mixed TLS mode negotiates ALPN but opens a fresh connection for each request,
  bypassing the reusable H1/H2 pools and shared H2 stream admission. Explicit H2
  uses the pooled path; HTTP/1 idle controls do not expire an H2 connection.
  This is the documented limitation, planned the local follow-up.
- A fresh pooled H2 request additionally caps its response-header wait by
  `upstream_total_connection_timeout_secs`; reused H2 requests do not. This
  is the documented limitation, planned the local follow-up. It is not an end-to-end timer.
- Hostname connection attempts use only the first resolved socket address.
  DNS address fallback is tracked as the documented limitation, the local follow-up; a deterministic
  multi-address reproducer is still required before correction acceptance.

These are existing limitations, not runtime fixes or new support promises.
