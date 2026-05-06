# Production Readiness

Fluxheim is still pre-`1.0`. This page states what the first stable release is
intended to support, what is deliberately outside the stable promise, and what
operators should verify before using a build beyond local testing.

## Stable 1.0 Target

The `1.0` line is intentionally small:

- static file hosting from configured vhost roots;
- reverse proxying to one configured upstream target;
- vhost routing by exact and wildcard host names;
- cache code compiled by default, with runtime caching disabled until a storage
  tier is configured;
- static certificate loading for user-managed certificates;
- rustls as the default TLS backend;
- secure default response header policy with configurable request and response
  header operations;
- explicit request header, URI, and body limits;
- optional cleartext-to-HTTPS redirect;
- rootless Podman deployment paths and container examples;
- local release gates for formatting, linting, tests, license policy,
  dependency advisories, core feature profiles, and localhost smoke checks.

## Not Stable In 1.0

These features may exist in code, documentation, or feature flags, but they are
not part of the `1.0` stable support promise:

- ACME runtime issuance or automatic renewal;
- load balancing and health-check policy;
- admin snapshot and rollback API;
- remote logging pipelines;
- metrics exporters;
- OpenTelemetry tracing;
- WAF, auth-request, image filters, media modules, or WASM extension points;
- PHP, CGI, or any dynamic script execution;
- Cloudflare automation;
- legacy HTTP compatibility listeners;
- WireGuard/Sentinel Mesh or clustered state.

Treat these as design or incubator work until a later versioning-plan milestone
promotes them.

## Operator Checks

Before using a Fluxheim build for a real site, run the stable gate from the repo
root:

```bash
scripts/stable_release_gate.sh check
```

For a release candidate, also run the deeper optional checks that fit the
deployment:

```bash
FLUXHEIM_GATE_TLS_BACKENDS=1 \
FLUXHEIM_GATE_TLS_SCAN=1 \
FLUXHEIM_GATE_LOAD=1 \
FLUXHEIM_GATE_FRAMING=1 \
FLUXHEIM_GATE_FUZZ_CHECK=1 \
scripts/stable_release_gate.sh check
```

Run the Podman smoke when container paths or image definitions change:

```bash
FLUXHEIM_GATE_PODMAN=1 scripts/stable_release_gate.sh check
```

Keep the generated release evidence with the release notes:

```bash
scripts/capture_release_gate_report.sh
```

## Configuration Review

Before starting the server:

- validate every config with `fluxheim --check-config --config <path>`;
- prefer split `conf.d` files with one `[[vhosts]]` per file;
- use `upstreams = ["host:port"]` for proxy targets;
- do not mix compatibility aliases such as `upstream` with preferred fields
  such as `upstreams`;
- keep TLS private keys, ACME storage, log files, cache roots, runtime paths,
  admin token files, and snapshot stores outside world-writable directories;
- keep admin and metrics listeners loopback-only unless a trusted local
  sidecar or network policy protects them;
- explicitly decide whether access logging may include raw host and path
  values.

## Deployment Notes

The recommended container mode is rootless with host ports mapped to the
container's high internal listener ports. If a deployment deliberately runs the
container as root for direct low-port binding, keep mounted config, content,
certificate, cache, and runtime directories separate and permission them for the
chosen runtime user.

Fluxheim's memory-safety baseline does not replace operational security checks.
Continue running dependency audits, license checks, malformed request framing
tests, TLS scans, and load smoke tests for every stable release branch.
