# Certificate Renewal And Reload

Fluxheim should support both operator-owned certificates and ACME-managed
certificates. Manual certificates are configured with `cert_path` and `key_path`.
ACME certificates are configured per vhost and managed under `tls.acme.storage`.
Fluxheim derives managed certificate paths under
`<storage>/certificates/<safe-vhost-segment>/fullchain.pem` and
`<storage>/certificates/<safe-vhost-segment>/privkey.pem`; the segment is
sanitized and hash-suffixed by Fluxheim, not supplied by the operator.
For HTTP-01, Fluxheim also derives a local challenge store at
`<storage>/http-01/<safe-vhost-segment>/` and serves safe challenge token files
directly when `tls.acme.challenge = "http-01"`.
TLS-ALPN-01 is also supported in `1.1.0` for the default rustls backend. During
renewal, Fluxheim writes short-lived challenge certificates under
`<storage>/tls-alpn-01/<safe-domain-segment>/` and the rustls SNI resolver serves
them only when the client offers the `acme-tls/1` ALPN protocol. DNS-01 remains
future work because secure provider integrations need explicit, provider-specific
secret handling rather than generic shell hooks.
Challenge publication uses the same managed store: HTTP-01 tokens are restricted
to one URL-safe path segment, key-authorizations are bounded and checked for
control bytes, TLS-ALPN-01 certificates are generated with the ACME identifier
extension, files are written through temporary files, and symlinked destinations
are rejected.
ACME account credentials are stored separately at
`<storage>/accounts/<safe-issuer-segment>/credentials.json`, again using a
Fluxheim-generated sanitized and hash-suffixed segment rather than a raw config
value.

Downstream TLS listeners are explicit in `server.tls_listen`. The runtime uses
the first global `[[tls.certificates]]` entry as the default certificate for
those listeners. If no global certificate is configured, `server.default_vhost`
may provide the fallback through either `[vhosts.tls.certificate]` or
`[vhosts.tls.acme]`. Other vhosts can override that certificate with their own
static or ACME-managed source; Fluxheim selects the matching certificate by SNI
during the downstream TLS handshake.

Managed ACME certificates may be absent during first issuance. Reloadable SNI
TLS backends, including the default rustls build, treat missing
Fluxheim-managed ACME certificate files as pending instead of refusing startup.
HTTP-01 challenge routes and the cleartext listener can still serve the issuer
validation request, while HTTPS handshakes for that pending SNI either use an
available fallback certificate or fail until the certificate files are issued.
After the background ACME worker installs the files, Fluxheim reloads the
downstream SNI certificate resolver so new handshakes can use them without a
process restart. Static certificate paths remain fail-closed: a missing
operator-owned certificate is still a configuration/runtime error.

## Storage Permissions

Fluxheim has a runtime storage checker for operator-owned certificates and ACME
storage directories.

Recommended Unix permissions:

- private keys: `0600`
- ACME storage directory: `0700`
- public certificate chains: normal read permissions are acceptable, for example
  `0644`

The checker reports missing certificate/key files, non-file certificate/key
paths, non-directory ACME storage paths, symlinked certificate/key/EAB/storage
paths including symlinked parent directories, group/world-readable private keys,
and group/world-accessible ACME storage directories. Config parsing stays
separate from filesystem checks so configuration can still be validated before
files are provisioned.

```bash
fluxheim --config path/to/fluxheim.toml --check-tls-storage
```

## Secret Handling

ACME issuers that require External Account Binding, such as Actalis and Google
Trust Services, need a key identifier and HMAC key. Fluxheim supports
environment variables and files for these values, but production deployments
should prefer file-backed secrets:

- systemd credentials mounted under `/run/credentials/<unit>/`
- Docker or Podman secrets mounted under `/run/secrets/`
- Kubernetes secret volumes

These mechanisms keep secrets out of static config files, process environment
listings, and container image metadata. They also fit Fluxheim's existing
storage checks because the application only needs to read ordinary files with
tight ownership and permissions.
At runtime, Fluxheim reads EAB secrets with a bounded file reader, trims only
surrounding whitespace, rejects empty or oversized values, opens files without
following final symlinks on Linux, and stores the loaded strings in zeroizing
memory wrappers.

Example systemd service override:

```ini
[Service]
LoadCredential=actalis-eab-kid:/etc/fluxheim/secrets/actalis-eab-kid.cred
LoadCredential=actalis-eab-hmac-key:/etc/fluxheim/secrets/actalis-eab-hmac-key.cred
```

Matching Fluxheim config. Credential names resolve below
`$CREDENTIALS_DIRECTORY` when Fluxheim is launched by systemd, and below
`/run/secrets` for normal container-style secret mounts:

```toml
[[tls.acme.issuers]]
name = "actalis"
directory_url = "https://acme-api.actalis.com/acme/directory"

[tls.acme.issuers.eab]
key_id_credential = "actalis-eab-kid"
hmac_key_credential = "actalis-eab-hmac-key"
```

Built-in issuer names:

- `letsencrypt`: `https://acme-v02.api.letsencrypt.org/directory`
- `letsencrypt-staging`: `https://acme-staging-v02.api.letsencrypt.org/directory`
- `actalis`: `https://acme-api.actalis.com/acme/directory`, EAB required
- `google-trust-services`: `https://dv.acme-v02.api.pki.goog/directory`, EAB required
- `google-trust-services-staging`: `https://dv.acme-v02.test-api.pki.goog/directory`, EAB required

Google Trust Services EAB credentials are environment-specific and single-use
for account registration. Fluxheim keeps separate production and staging
defaults:

- production: `FLUXHEIM_GTS_EAB_KID`, `FLUXHEIM_GTS_EAB_HMAC_KEY`
- staging: `FLUXHEIM_GTS_STAGING_EAB_KID`, `FLUXHEIM_GTS_STAGING_EAB_HMAC_KEY`

For containers, mount the same two values as secrets and point Fluxheim at the
mounted files:

```toml
[tls.acme.issuers.eab]
key_id_credential = "actalis-eab-kid"
hmac_key_credential = "actalis-eab-hmac-key"
```

Environment variables remain useful for local testing, but they should not be
the recommended production path for EAB secrets.

## Account Credentials

ACME account credentials contain account identity and private key material. They
are not kept in the TOML config. Fluxheim derives their storage path from the
issuer name and writes them below `tls.acme.storage`:

```text
<storage>/accounts/<safe-issuer-segment>/credentials.json
```

The credential file is bounded, parsed as JSON, written through a temporary
file, installed with owner-only permissions on Unix, and opened without
following the final symlink on Linux. The exact path segment is generated by
Fluxheim, so issuer names cannot create path traversal or hidden filesystem
locations.

When Fluxheim is built with `acme-client`, it can load existing credentials from
that path or create a new issuer account through `instant-acme` and immediately
persist the returned credentials. EAB HMAC keys are treated as base64/base64url
encoded ACME MAC keys before they are passed to the issuer client. The same
feature also contains the live HTTP-01 and rustls TLS-ALPN-01 order paths:
create order, publish challenge material, mark challenges ready, finalize the
generated CSR, retrieve the certificate chain, install it atomically, and clean
up challenge files.

Production packages and container images ship the `fluxheim-acme` companion as
the preferred external renewal command. It uses the same ACME engine, storage
layout, issuer credentials, and vhost target planner as the integrated gateway,
but keeps renewal scheduling outside the traffic-serving process:

```bash
fluxheim-acme --config /etc/fluxheim/fluxheim.toml targets
fluxheim-acme --config /etc/fluxheim/fluxheim.toml status
fluxheim-acme --config /etc/fluxheim/fluxheim.toml renew
```

By default `renew` observes the managed certificate files and attempts only
missing or due certificates. If nothing needs renewal, it exits successfully
with `acme attempted: 0` and a status message saying no certificates are due.
First issuance normally does not need `--force-renew`: missing certificate files
are due targets. The command prints every target with `status=due`,
`status=skipped`, or `status=forced`, then reports per-target `renewed:` and
`failed:` lines. For HTTP-01 failures after challenge files are published, the
failure includes `published_http_01=` URLs so operators can test the exact
public challenge paths that the issuer should have reached. It exits non-zero
if any target failed, while still reporting successful renewals from the same
run.

`fluxheim-acme renew` also asks the running gateway to reload its certificate
handles after a successful renewal when `server.process.certificate_reload_sock`
is reachable. Use `reload` explicitly after manually installing managed files:

```bash
fluxheim-acme --config /etc/fluxheim/fluxheim.toml reload
```

The legacy integrated command is kept for manual compatibility, but new
automation should use `fluxheim-acme`:

```bash
fluxheim --config /etc/fluxheim/fluxheim.toml acme-renew
```

Use `--force-renew` only for deliberate emergency rotation or testing when you
really need to reissue certificates that are still valid; repeated forced
renewals can hit issuer rate limits:

```bash
fluxheim-acme --config /etc/fluxheim/fluxheim.toml renew --force-renew
```

`--all` is accepted as a backward-compatible alias for `--force-renew`, but it
prints a deprecation warning and should not be used in new automation.

Official RPM and container release assets include `acme-client` by default. If
you compile from source with a custom feature list, include it explicitly:

```bash
cargo build --release --locked --no-default-features --features profile-core,acme-client
```

## Initialize ACME

Packaged builds include a guided initializer for the global issuer setup:

```bash
sudo fluxheim acme-init actalis
sudo fluxheim acme-init letsencrypt
sudo fluxheim acme-init letsencrypt-staging
```

For Actalis, the command asks for the contact email, EAB key id, and EAB HMAC
key. The HMAC prompt is hidden. By default it writes:

- `/etc/fluxheim/conf.d/acme.toml`
- `/etc/fluxheim/secrets/actalis-eab-kid`
- `/etc/fluxheim/secrets/actalis-eab-hmac-key`
- `/etc/systemd/system/fluxheim.service.d/actalis-eab.conf`

It refuses to overwrite existing files unless `--force` is supplied.

Automation should pass secrets through files, not command-line values:

```bash
sudo fluxheim acme-init actalis \
  --email info@example.com \
  --kid-file /root/actalis-eab-kid \
  --hmac-key-file /root/actalis-eab-hmac-key \
  --non-interactive
```

After initialization, add `[vhosts.tls.acme]` blocks to the vhosts that should
receive managed certificates, reload systemd when a drop-in was created, and run
the renewal command:

```bash
sudo systemctl daemon-reload
sudo systemctl restart fluxheim
sudo fluxheim-acme --config /etc/fluxheim/fluxheim.toml renew
```

## Packaged Actalis Credentials

RPM installs create `/etc/fluxheim/secrets` with root-only permissions and ship
an optional systemd drop-in example at:

```text
/usr/share/doc/fluxheim/systemd/actalis-eab.conf
```

To use Actalis EAB with systemd credentials:

```bash
sudo install -d -m 0700 -o root -g root /etc/fluxheim/secrets
sudo install -m 0600 -o root -g root actalis-eab-kid /etc/fluxheim/secrets/actalis-eab-kid
sudo install -m 0600 -o root -g root actalis-eab-hmac-key /etc/fluxheim/secrets/actalis-eab-hmac-key

sudo install -d /etc/systemd/system/fluxheim.service.d
sudo cp /usr/share/doc/fluxheim/systemd/actalis-eab.conf \
  /etc/systemd/system/fluxheim.service.d/actalis-eab.conf
sudo systemctl daemon-reload
sudo systemctl restart fluxheim
```

Then point the issuer EAB sources at credential names. The same TOML works for
`fluxheim.service`, `fluxheim-acme.service`, and container secrets:

```toml
[[tls.acme.issuers]]
name = "actalis"
directory_url = "https://acme-api.actalis.com/acme/directory"

[tls.acme.issuers.eab]
key_id_credential = "actalis-eab-kid"
hmac_key_credential = "actalis-eab-hmac-key"
```

## Renewal Queue Planning

Fluxheim derives renewal targets from validated vhost ACME config. The planner
is implemented and produces queue items with:

- vhost name
- issuer name
- concrete certificate domains
- challenge type
- certificate expiration time
- next renewal time

The first renewal time should be the later of:

- `certificate_not_after - tls.acme.renewal.renew_before_secs`
- `tls.acme.renewal.renew_after`, when set

`renew_after` lets an operator defer automatic renewal until a chosen TOML
offset datetime, for example `2026-06-01T00:00:00Z`. Local TOML datetimes are
rejected so the queue cannot interpret operator intent in the wrong timezone.

When Fluxheim is built with `acme-client`, the runtime registers a background
renewal service when ACME-managed vhosts are configured and
`tls.acme.automation = "background"`. This is the default for simple
single-process installs. The service observes managed certificate expiry, wakes
every `tls.acme.renewal.check_interval_secs`, and renews missing or due
certificates through the same ACME challenge path used by the CLI.

After successful renewal, Fluxheim reloads the downstream SNI certificate
resolver or callback so new handshakes can use the freshly installed files
without restarting. If a TLS backend or listener shape cannot provide a reload
handle, Fluxheim logs that a restart or process reload is required.

This reload happens inside the long-running Fluxheim process. The gateway also
owns a local Unix-domain certificate reload socket at
`server.process.certificate_reload_sock`, defaulting to:

```text
/run/fluxheim/fluxheim-cert-reload.sock
```

The socket accepts only the narrow `reload-certificates` operation and is
created with owner-only permissions by the running gateway. It is intended for
the same runtime user or container pod, not remote administration. The
companion reads the gateway response with a small fixed bound so a compromised
or replaced local socket cannot grow companion memory without limit.

Production packages include the `fluxheim-acme` companion binary while keeping
the integrated background worker for simple installs. In this model,
`fluxheim.service` stays focused on serving traffic and challenge files, while
the one-shot `fluxheim-acme.service` and scheduled `fluxheim-acme.timer` run
renewals as the Fluxheim runtime user. The companion command reuses the same
ACME engine and storage layout as the legacy `fluxheim acme-renew` command,
uses systemd credentials or container secrets for EAB material, and writes
certificates below the configured `tls.acme.storage`. When certificates are
renewed, it asks the running gateway to reload its certificate handles through
`server.process.certificate_reload_sock`. Set `tls.acme.automation =
"external"` in this mode so the webserver does not also run the background
renewal loop.

Preview targets without contacting the issuer:

```bash
sudo fluxheim-acme --config /etc/fluxheim/fluxheim.toml targets
```

Check due/missing/valid state before issuing:

```bash
sudo fluxheim-acme --config /etc/fluxheim/fluxheim.toml status
sudo fluxheim-acme --config /etc/fluxheim/fluxheim.toml status --vhost example.com
```

Run renewal and request live certificate activation after successful issuance:

```bash
sudo fluxheim-acme --config /etc/fluxheim/fluxheim.toml renew
sudo fluxheim-acme --config /etc/fluxheim/fluxheim.toml renew --vhost example.com
```

Request only the live certificate-handle reload, for example after manually
installing files below `tls.acme.storage`:

```bash
sudo fluxheim-acme --config /etc/fluxheim/fluxheim.toml reload
```

Enable the packaged timer after ACME config and credentials are installed:

```bash
sudo install -d /etc/systemd/system/fluxheim-acme.service.d
sudo cp /usr/share/doc/fluxheim/systemd/actalis-eab-acme.conf \
  /etc/systemd/system/fluxheim-acme.service.d/actalis-eab.conf
sudo systemctl daemon-reload
sudo systemctl enable --now fluxheim-acme.timer
sudo systemctl start fluxheim-acme.service
```

Do not make the webserver spawn a long-lived helper process; let the service
manager or container orchestrator supervise the companion.

## Container Renewal

Runtime images include both `/usr/local/bin/fluxheim` and
`/usr/local/bin/fluxheim-acme`. The companion can run inside the already running
gateway container with `podman exec`, or as a separate one-shot container. In
both cases it must see the same config, ACME storage, secrets, and
`/run/fluxheim` directory as the gateway.

The gateway and companion must share `server.process.certificate_reload_sock`.
The packaged container configs use:

```toml
[server.process]
certificate_reload_sock = "/run/fluxheim/fluxheim-cert-reload.sock"
```

Keep the host-side run directory private to the container runtime user and mount
it read-write into both containers:

```bash
install -d -m 0700 /srv/infra/fluxheim/run
```

If the gateway container is already running, the simplest operational commands
are:

```bash
podman exec fluxheim_gateway \
  /usr/local/bin/fluxheim-acme \
  --config /etc/fluxheim/fluxheim.toml \
  targets

podman exec fluxheim_gateway \
  /usr/local/bin/fluxheim-acme \
  --config /etc/fluxheim/fluxheim.toml \
  status

podman exec fluxheim_gateway \
  /usr/local/bin/fluxheim-acme \
  --config /etc/fluxheim/fluxheim.toml \
  renew
```

`podman exec` naturally shares the gateway container filesystem, secrets, and
reload socket. It is useful for manual checks, but scheduled renewals are often
cleaner as a one-shot companion container:

```bash
podman run --rm \
  --name fluxheim_acme_due \
  --network gateway_net \
  --entrypoint /usr/local/bin/fluxheim-acme \
  -v /srv/infra/fluxheim/config/fluxheim.toml:/etc/fluxheim/fluxheim.toml:ro,Z \
  -v /srv/infra/fluxheim/config/conf.d:/etc/fluxheim/conf.d:ro,Z \
  -v /srv/infra/fluxheim/run:/run/fluxheim:Z,U \
  -v /srv/infra/fluxheim/state:/var/lib/fluxheim:Z,U \
  -v /srv/infra/fluxheim/cache:/var/cache/fluxheim:Z,U \
  -v /srv/infra/fluxheim/logs:/var/log/fluxheim:Z,U \
  -v /srv/infra/fluxheim/html:/srv/fluxheim:ro,Z \
  -v /srv/infra/fluxheim/secrets/actalis-eab-kid:/run/secrets/actalis-eab-kid:ro \
  -v /srv/infra/fluxheim/secrets/actalis-eab-hmac-key:/run/secrets/actalis-eab-hmac-key:ro \
  ghcr.io/valkyoth/fluxheim:latest-wolfi \
  --config /etc/fluxheim/fluxheim.toml \
  renew
```

Use `status` before `renew` when testing a new mount layout:

```bash
podman run --rm \
  --network gateway_net \
  --entrypoint /usr/local/bin/fluxheim-acme \
  -v /srv/infra/fluxheim/config/fluxheim.toml:/etc/fluxheim/fluxheim.toml:ro,Z \
  -v /srv/infra/fluxheim/config/conf.d:/etc/fluxheim/conf.d:ro,Z \
  -v /srv/infra/fluxheim/run:/run/fluxheim:Z,U \
  -v /srv/infra/fluxheim/state:/var/lib/fluxheim:Z,U \
  -v /srv/infra/fluxheim/secrets/actalis-eab-kid:/run/secrets/actalis-eab-kid:ro \
  -v /srv/infra/fluxheim/secrets/actalis-eab-hmac-key:/run/secrets/actalis-eab-hmac-key:ro \
  ghcr.io/valkyoth/fluxheim:latest-wolfi \
  --config /etc/fluxheim/fluxheim.toml \
  status
```

For Compose, keep `fluxheim` and `fluxheim-acme` on the same network and use
the same bind mounts. The companion service should override only the entrypoint
and command:

```yaml
services:
  fluxheim:
    image: ghcr.io/valkyoth/fluxheim:latest-wolfi
    ports:
      - "80:8080"
      - "443:8443"
    volumes:
      - /srv/infra/fluxheim/config/fluxheim.toml:/etc/fluxheim/fluxheim.toml:ro,Z
      - /srv/infra/fluxheim/config/conf.d:/etc/fluxheim/conf.d:ro,Z
      - /srv/infra/fluxheim/run:/run/fluxheim:Z,U
      - /srv/infra/fluxheim/state:/var/lib/fluxheim:Z,U
      - /srv/infra/fluxheim/secrets/actalis-eab-kid:/run/secrets/actalis-eab-kid:ro
      - /srv/infra/fluxheim/secrets/actalis-eab-hmac-key:/run/secrets/actalis-eab-hmac-key:ro

  fluxheim-acme:
    image: ghcr.io/valkyoth/fluxheim:latest-wolfi
    entrypoint: ["/usr/local/bin/fluxheim-acme"]
    command: ["--config", "/etc/fluxheim/fluxheim.toml", "renew"]
    depends_on:
      - fluxheim
    volumes:
      - /srv/infra/fluxheim/config/fluxheim.toml:/etc/fluxheim/fluxheim.toml:ro,Z
      - /srv/infra/fluxheim/config/conf.d:/etc/fluxheim/conf.d:ro,Z
      - /srv/infra/fluxheim/run:/run/fluxheim:Z,U
      - /srv/infra/fluxheim/state:/var/lib/fluxheim:Z,U
      - /srv/infra/fluxheim/secrets/actalis-eab-kid:/run/secrets/actalis-eab-kid:ro
      - /srv/infra/fluxheim/secrets/actalis-eab-hmac-key:/run/secrets/actalis-eab-hmac-key:ro
```

Run it on demand with:

```bash
podman compose run --rm fluxheim-acme
```

For scheduled container renewals, use a host systemd timer, Kubernetes CronJob,
or the platform scheduler to start the one-shot companion. Keep
`tls.acme.automation = "external"` so the gateway does not also run the
background renewal loop.

## Runtime Crate Candidates

Latest checked ACME runtime candidates:

- `instant-acme 0.8.5`: Apache-2.0, async pure-Rust ACME client with EAB
  support. This is the current first candidate because it does not own the TLS
  listener model.
- `rustls-acme 0.15.1`: Apache-2.0 OR MIT, useful reference for rustls-focused
  certificate management, but less aligned with Fluxheim's multiple Pingora TLS
  backend targets.

## FIPS/ISO-Required Deployments

Managed Fluxheim ACME is intentionally outside the strict FIPS/ISO-required
runtime boundary in `1.3.6`. A config with `[tls.fips] required = true` or
`[tls.iso19790] required = true` rejects `[tls.acme] enabled = true` because
ACME account key generation, JWS account signing, External Account Binding
HMAC, outbound ACME HTTPS transport, and TLS-ALPN challenge certificate
generation are not fully routed through the selected validated provider.

For regulated deployments, use local static certificate files in
`[vhosts.tls.certificate]` and renew them with an external process that has its
own evidence package. If that external process is ACME-based, keep the ACME
client version, host FIPS/ISO mode, key-generation policy, CA/audit evidence,
and renewal logs with the deployment evidence. Conservative public-Web PKI
profiles should request RSA 2048 or RSA 3072 certificate keys unless the
assessor explicitly accepts the selected ECDSA certificate profile and chain.

The Fluxheim ACME storage path hashing uses SHA-256 and does not use MD5 for
local account or certificate directory labels, but that is not enough to make
managed ACME part of the approved cryptographic boundary. Treat `fluxheim-acme`
as a normal automation tool unless and until managed ACME has provider-routed
signing, key generation, EAB, and outbound TLS evidence.

## Retry Policy

Failed renewal attempts should retry with bounded backoff:

- start at `tls.acme.renewal.retry_initial_secs`
- grow up to `tls.acme.renewal.retry_max_secs`
- never remove the currently active certificate because of a failed renewal

The scheduler should wake at least every
`tls.acme.renewal.check_interval_secs` to catch newly due certificates and config
changes.

## Atomic Install

Renewed certificates must be installed atomically:

1. Write certificate and key to temporary files in the ACME storage directory.
2. Validate that the certificate parses, matches the private key, and covers the
   configured domains.
3. Flush files and directory metadata where the platform supports it.
4. Rename temporary files into place.
5. Keep the previous certificate available until the new one is active.

The current install helper implements the filesystem side of that contract. It
validates basic PEM shape and size, writes temporary files next to the managed
destination, rejects symlinked directories or destination files, keeps backups
of existing files while staging, and cleans temporary files on failure. Full
certificate/key matching and domain coverage validation belongs in the ACME
client step before this helper is called. Failed issuer calls and failed
certificate installs do not remove the previous active certificate.

## No-Downtime Reload

Runtime state should be immutable snapshots behind an atomic pointer. Existing
requests keep their current snapshot. New requests use the latest snapshot after
reload. Fluxheim's proxy routing state already uses this model for vhost,
upstream, cache, and static web policy snapshots. This model applies to:

- vhost routing
- upstream pools
- cache policies
- certificate lookup maps

Listener changes are process-level changes and should use Pingora's
zero-downtime upgrade path rather than in-place mutation.

## Reload Classification

Fluxheim classifies a config change before applying it:

- `Noop`: old and new config are identical.
- `Snapshot`: safe for in-place snapshot swap.
- `ProcessUpgrade`: requires Pingora's process-level zero-downtime upgrade path.

Operators can check the impact of a planned config change:

```bash
fluxheim --reload-from /etc/fluxheim/current.toml --config /etc/fluxheim/next.toml
```

Durable config history and rollback commands are documented in
[Config Snapshots And Rollback](config-snapshots.md).

Snapshot reload is intended for routing, cache policy, static web policy, and
certificate lookup changes that do not alter listeners or startup-owned
background services.

Process upgrade is required when:

- listener addresses change
- downstream TLS mode changes
- the configured TLS backend changes
- Pingora load-balancer background service ownership changes

This keeps the hot-reload path conservative until Fluxheim has explicit runtime
ownership for adding and removing background services after startup.
