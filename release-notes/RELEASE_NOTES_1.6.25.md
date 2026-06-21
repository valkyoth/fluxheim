# Fluxheim 1.6.25 Release Notes

Fluxheim 1.6.25 is a Pingora-exit evidence release. The previous plan placed
the final dependency deletion immediately after the HTTP/2 parity proof, but
the remaining compatibility runtime still owns rich proxy behavior such as
cache, web/PHP fallback, auth-request, traffic mirror, redirects, rewrites,
compression, and advanced load-balancer policy. This release makes those
remaining blockers visible per configured proxy scope instead of removing the
adapter before parity is finished. It also starts the route/policy parity work
inside the same release by adding a tested native HTTP/1 route-proxy primitive
for ordinary exact, prefix, and fallback proxy routes.

## Changed

- Add `native-http1-proxy-candidate` rows to
  `fluxheim-config-tester --runtime-cutover`.
- Report each configured proxy scope as `native-ready` or
  `compatibility-required` with the exact native HTTP/1 proxy reason.
- Add native HTTP/1 route proxy handling for exact, prefix, and fallback
  routes with method filters, longest-prefix selection, prefix strip/rewrite,
  and query preservation.
- Re-scope remaining Pingora dependency exceptions to `1.6.28`; `1.6.26` and
  `1.6.27` are now the remaining native policy and rich proxy integration
  parity slices.
- Update release metadata, RPM metadata, and container tag documentation for
  `v1.6.25`.

## Security

- Keep blocker rows in the native runtime cutover evidence strictly validated
  while allowing candidate-detail rows for audit visibility.
- Reject invalid native route-proxy request targets and unsafe rewritten paths
  before forwarding.
- Reject ambiguous interior double-slash forward paths in the native
  route-proxy strip/rewrite path.
- Keep regex routes marked as compatibility-required until native regex route
  matching is implemented.
- Validate native HTTP/1 proxy candidate row shape in the runtime cutover gate
  before ignoring those rows for blocker status.
- Reject single-dot route path segments during config validation.
- Keep the dependency exception gate active so documented Pingora removal
  targets remain enforced by CI.

## Compatibility Boundary

- Normal proxy profiles still compile the Pingora compatibility runtime in this
  release. That is intentional: deleting it now would either break shipped
  proxy features or make the release less honest than the evidence shows.
