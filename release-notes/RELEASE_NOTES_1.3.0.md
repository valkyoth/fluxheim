# Fluxheim 1.3.0 Release Notes

Status: draft.

## Scope

Fluxheim 1.3.0 starts the shared ingress/TLS feature-graph split. The goal is
to make TLS and ACME usable by focused builds such as cache, proxy, and future
load-balancer images without forcing every deployment to compile unrelated
webserver or cache modules.

## Highlights

- TLS backends now depend on the shared `ingress` feature instead of forcing
  the full `proxy` feature.
- Added focused profile aliases:
  - `profile-full`
  - `profile-web-server`
  - `profile-cache-edge`
  - `profile-proxy-edge`
  - `profile-load-balancer-edge`
- Added CI validation for the new focused profile aliases.
- Added focused container configs for cache-edge and proxy-edge image builds.
- Added runtime config guardrails so binaries compiled without `web` or
  `cache` reject configs that require those modules.
- Expanded local and GitHub clippy coverage for TLS-only, full, web-server,
  cache-edge, proxy-edge, and load-balancer-edge builds.
- Updated the roadmap:
  - `1.3.1+`: PHP/FastCGI and PHP runtime follow-ups.
  - `1.4`: advanced proxy parity.
  - `1.5`: enterprise load-balancer parity.
  - `1.6`: shared Wasm extensibility.

## Compatibility Notes

The focused profiles are a compatibility step toward stricter images. Static
web serving still uses the shared proxy runtime in this first split, so
`profile-web-server` intentionally includes `proxy`.

The load-balancer image profile is prepared in CI but remains gated until the
`1.5` load-balancer line unless explicitly requested in a manual image
workflow run.

## Checksums And Signatures

To be filled during release.
