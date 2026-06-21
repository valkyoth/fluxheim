# Fluxheim 1.6.26 Release Notes

Fluxheim 1.6.26 continues the Pingora-exit route/policy parity work. After
1.6.25 added the native HTTP/1 route proxy for ordinary proxy routes, this
release adds native route redirect actions so redirect-only routes can be
represented and tested without falling back to Pingora's `ProxyHttp` callback
surface. It also moves route-level response header overlays onto the native
route proxy for the already-supported native response paths.

## Changed

- Add native HTTP/1 route redirect actions to `NativeHttp1RouteProxyRoute`.
- Support `{uri}`, `{path}`, and `{query}` expansion for native route redirects.
- Enforce route-level `max_request_body_bytes` in the native HTTP/1 route
  proxy before forwarding matched requests.
- Apply route-level native response header overlays for native route proxy
  responses, including set, append, unset, HSTS, CSP, frame-options,
  content-type-options, and referrer-policy shortcuts.
- Allow native route proxy construction from redirect-only route config without
  requiring a dummy upstream proxy.
- Update release metadata, RPM metadata, and container tag documentation for
  `v1.6.26`.

## Security

- Validate native redirect locations before writing the response.
- Reject unsafe redirect expansions containing control characters, whitespace,
  braces, backslashes, non-HTTP(S) schemes, or ambiguous double-slash request
  paths.
- Reject expanded native redirect `Location` URL paths containing dot segments
  or double slashes, including `{query}` path-position traversal attempts.
- Reject redirect templates that would place `{path}` or `{uri}` immediately
  after a literal slash in the URL path, preventing predictable `//` expansion.
- Exclude route proxy configs shadowed by route redirects from native proxy
  cutover candidate accounting.
- Return `413 Payload Too Large` for native route-proxy requests that exceed a
  matched route-specific body limit.
- Keep regex routes, request-header mutation, response-header rewrites, access
  policy, and richer proxy integrations on the compatibility path until their
  native execution has dedicated parity tests.

## Compatibility Boundary

- Normal proxy profiles still compile the Pingora compatibility runtime in this
  release. The native route proxy now covers exact/prefix/fallback proxy routes
  plus route redirects, route request-body limits, and route response header
  overlays. Request header mutation, response-header rewrites, access and
  compression policy, plus rich proxy integrations remain targeted for the next
  1.6.x slices.
