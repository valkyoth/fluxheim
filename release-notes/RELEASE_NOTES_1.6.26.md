# Fluxheim 1.6.26 Release Notes

Fluxheim 1.6.26 continues the Pingora-exit route/policy parity work. After
1.6.25 added the native HTTP/1 route proxy for ordinary proxy routes, this
release adds native route redirect actions so redirect-only routes can be
represented and tested without falling back to Pingora's `ProxyHttp` callback
surface.

## Changed

- Add native HTTP/1 route redirect actions to `NativeHttp1RouteProxyRoute`.
- Support `{uri}`, `{path}`, and `{query}` expansion for native route redirects.
- Allow native route proxy construction from redirect-only route config without
  requiring a dummy upstream proxy.
- Update release metadata, RPM metadata, and container tag documentation for
  `v1.6.26`.

## Security

- Validate native redirect locations before writing the response.
- Reject unsafe redirect expansions containing control characters, whitespace,
  braces, backslashes, non-HTTP(S) schemes, or ambiguous double-slash request
  paths.
- Keep regex routes and richer route policies on the compatibility path until
  their native execution has dedicated parity tests.

## Compatibility Boundary

- Normal proxy profiles still compile the Pingora compatibility runtime in this
  release. The native route proxy now covers exact/prefix/fallback proxy routes
  plus route redirects, but header/access/body/compression policy and rich
  proxy integrations remain targeted for the next 1.6.x slices.
