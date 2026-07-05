# Fluxheim 1.7.2 Release Notes

Fluxheim 1.7.2 continues the optional WebAssembly extensibility line with the
first live native HTTP/1 request-header and response-header hook family. The
new hooks use a constrained `fluxheim_policy_v1` host-call surface so plugins
can perform approved synthetic policy mutations without receiving raw headers,
bodies, filesystem access, network access, or admin APIs.

## Highlights

- Add live native HTTP/1 `request-headers` and `response-headers` Wasm hook
  execution for vhost and route attachments.
- Extend `fluxheim-wasm` with bounded integer host functions while preserving
  the existing fuel, memory, table, instance, compile-timeout, wall-time, and
  admission controls.
- Add symbolic `fluxheim_policy_v1` host calls for coarse request context,
  approved request header setting, approved response header setting, and
  approved response header removal.
- Support the first nginx-Lua/OpenResty-style header-policy example: add an
  `x-policy-tier` request header before upstream forwarding, remove origin
  `x-powered-by`, and add `x-fluxheim-policy-branch` before the response is
  sent to the client.
- Add live listener tests proving the upstream observes the plugin-added
  request header and the client observes the plugin-added response header.
- Add fail-closed coverage for forbidden header mutations. Invalid host-call
  IDs trap the plugin invocation and return `503` unless the plugin is
  explicitly configured for fail-open behavior on a non-security phase.
- Apply vhost-level Wasm header hooks to PHP-FPM fallback responses as well as
  route, static, and generic proxy paths.
- Apply the shared fallback response header policy to PHP-FPM fallback
  responses, including the default `x-powered-by` removal.
- Compute Wasm header-hook path context from the matched pre-rewrite request
  path so path-class policy stays stable when a route strips or rewrites the
  upstream target.

## Security Notes

- The header hook ABI is intentionally not a raw header API. Plugins receive
  only bounded symbolic inputs, such as a path class, and can request only
  allow-listed synthetic mutations.
- `Authorization`, `Cookie`, `Set-Cookie`, request bodies, private keys,
  admin credentials, filesystem, network, and process APIs are not exposed to
  the current Wasm host-call surface.
- Built-in Fluxheim ACLs and the `access-decision` chain still run before
  header hooks. Wasm header hooks cannot override built-in access policy.
- PHP-FPM fallback traffic now goes through the same vhost-level header-hook
  and fallback response-header post-processing as other fallback response
  paths.
- The `wasm` feature remains optional and is still rejected with
  `privacy-mode`.

## Operator Notes

- Plugins that use `request-headers` export
  `fluxheim_request_headers() -> i32`.
- Plugins that use `response-headers` export
  `fluxheim_response_headers() -> i32`.
- The current preview host calls live under the `fluxheim_policy_v1` namespace
  and use integer IDs rather than strings. This keeps the surface auditable
  while the broader `1.7.x` ABI settles.
- General raw header read/write, body access, filesystem access, outbound
  network access, and Proxy-Wasm compatibility remain staged for later
  reviewed releases.
