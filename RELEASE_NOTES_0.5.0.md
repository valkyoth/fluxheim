# Fluxheim 0.5.0 Release Notes

## Version

- Version: `0.5.0`
- Release date: 2026-05-06
- Git tag: `v0.5.0` after release validation
- Git commit: fill in from `git rev-parse HEAD` before tagging
- License: EUPL-1.2

## Scope

Fluxheim `0.5.0` is the basic-sites preview. It is intended for normal static
HTML websites and simple whole-vhost reverse proxying with static TLS
certificates.

Stable preview scope:

- static web serving for HTML, CSS, JavaScript, images, fonts, and other normal
  site assets;
- vhost routing by Host header;
- static downstream TLS certificates, with rustls as the default backend;
- optional global HTTP-to-HTTPS redirect;
- simple whole-vhost reverse proxying to one upstream;
- request/header/body limits;
- default `Server: fluxheim` response header, removable by config;
- secure header mutation policy;
- static cache headers, ETag, conditional requests, and byte ranges;
- rootless Podman/container examples for Wolfi, Alpine, SUSE Micro, and Debian
  runtime variants;
- RPM packaging spec for RHEL/openSUSE-style builds from vendored Cargo
  dependencies;
- release checks for formatting, linting, tests, dependency policy, advisory
  policy, CodeQL, and local smoke coverage.

Default Cargo features:

- `proxy`
- `web`
- `cache`
- `tls-rustls`
- `security`

## Highlights

- Basic vhost static hosting and simple reverse proxying are now documented as
  the preview release promise.
- Container deployment examples include explicit graceful shutdown settings so
  normal `podman compose down` does not fall back to `SIGKILL`.
- The public `1.0.0` target is now defined as the gateway-ready release needed
  for representative real multi-site configs.

## Security And Stability Gate

Fill this in immediately before tagging:

- Gate command: `scripts/stable_release_gate.sh check` or stronger
- Gate report directory:
- Result:
- `cargo audit` result:
- `cargo deny check` result:
- TLS scan result:
- Load smoke result:
- Request-framing smoke result:
- Fuzz target compile result:
- Podman smoke result:

## Reviewed Advisory Exceptions

- `protobuf < 3.7.2` may appear transitively through Pingora dependencies until
  upstream updates. Do not accept this exception silently: record the exact
  dependency path from `cargo audit`, confirm whether Fluxheim parses
  attacker-supplied protobuf through that dependency in this release, and remove
  the exception as soon as the upstream fix is available.

## Breaking Changes

- This is a pre-`1.0.0` preview release. Config shape and behavior may still
  change when the change improves security or the `1.0.0` gateway target.

## Upgrade Notes

- Prefer `upstreams = ["host:port"]` over the older single `upstream = "host:port"`
  field. Do not configure both in the same proxy block.
- Use `[headers.*.add]`/`remove` for user-friendly header changes. The older
  `set`/`unset` names remain compatible.
- For containers, keep the container stop timeout higher than
  `server.process.grace_period_seconds + graceful_shutdown_timeout_seconds`.

## Known Limitations

These are intentional `1.0.0` blockers, not `0.5.0` promises:

- no multi-certificate SNI selection at runtime yet;
- no route/location layer yet;
- no route-level redirect/proxy/static actions yet;
- no websocket-specific upgrade support yet;
- no per-route body limits or upstream timeouts yet;
- no custom upstream error pages yet;
- no static alias or directory listing support yet;
- no runtime ACME issuance yet.

## Container Images

Planned image tags after release validation:

- GitHub Container Registry: `ghcr.io/valkyoth/fluxheim:v0.5.0-wolfi`
- GitHub Container Registry: `ghcr.io/valkyoth/fluxheim:v0.5.0-alpine`
- GitHub Container Registry: `ghcr.io/valkyoth/fluxheim:v0.5.0-suse-micro`
- GitHub Container Registry: `ghcr.io/valkyoth/fluxheim:v0.5.0-debian`
- Docker Hub: matching variant tags when Docker Hub credentials are configured
- Runtime user: `65532:65532` by default
- Default config path: `/etc/fluxheim/fluxheim.toml`
- Static site path: operator-mounted, commonly `/srv/sites/...`
- Cache path: `/var/cache/fluxheim`
- State path: `/var/lib/fluxheim`

## RPM Packaging

The release includes [packaging/rpm/fluxheim.spec](packaging/rpm/fluxheim.spec)
and [packaging/rpm/fluxheim.tmpfiles](packaging/rpm/fluxheim.tmpfiles).

The spec expects a source tarball plus a vendored Cargo dependency tarball, then
builds with `cargo --offline`:

```bash
cargo vendor vendor > /tmp/fluxheim-cargo-config.toml
tar -czf fluxheim-0.5.0-vendor.tar.gz vendor
```

The default RPM feature set is `profile-core`. Builders can override it with:

```bash
rpmbuild -ba packaging/rpm/fluxheim.spec --define 'fluxheim_features profile-static-site'
```

## Checksums And Signatures

Fill this in during the release:

- Source archive checksum:
- Binary checksums:
- Container digests:
- Tag signature:
