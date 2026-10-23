# systemd Deployment

Fluxheim can run as a native systemd service when you manually compile the
binary or install an RPM package.

The packaged unit is intentionally conservative:

- runs as the `fluxheim` user and group;
- validates the config before starting;
- uses `/run/fluxheim`, `/var/lib/fluxheim`, `/var/cache/fluxheim`, and
  `/var/log/fluxheim` as writable service paths;
- keeps `/etc/fluxheim` and `/srv/fluxheim` readable but not writable by the
  service;
- runs with `NoNewPrivileges` and grants only `CAP_NET_BIND_SERVICE`, allowing
  the unprivileged `fluxheim` user to bind production ports `80` and `443`
  without running the service as root;
- uses strict system path protection, private temporary and device namespaces,
  kernel/control-group write protection, namespace restrictions, native syscall
  architecture filtering, and a conservative system-service/network syscall
  allow-list;
- limits address families to IPv4, IPv6, and Unix domain sockets;
- stops with `SIGTERM` and lets Fluxheim shut down gracefully.

These systemd controls are the supported `1.0` host sandbox. They are
deployment-level controls and do not require a special Fluxheim binary.

The packaged native config listens on `0.0.0.0:80` by default. HTTPS uses
`0.0.0.0:443` once `server.tls_listen` and certificate paths are enabled. This
matches normal bare-metal web server expectations while keeping the process
unprivileged.

## Manual Binary Install

Build Fluxheim:

```bash
cargo build --release --locked
```

Install the binary where the provided unit expects it:

```bash
sudo install -Dm0755 target/release/fluxheim /usr/bin/fluxheim
```

Install the service user, runtime directories, default config, and default
static page:

```bash
sudo install -Dm0644 packaging/systemd/fluxheim.sysusers /usr/lib/sysusers.d/fluxheim.conf
sudo systemd-sysusers fluxheim.conf

sudo install -Dm0644 packaging/rpm/fluxheim.tmpfiles /usr/lib/tmpfiles.d/fluxheim.conf
sudo systemd-tmpfiles --create fluxheim.conf

sudo scripts/prepare-server.py --owner fluxheim:fluxheim
```

The prepare script is intentionally path-restricted. Any path override must be
absolute, must not pass through a symlinked existing directory, and must stay
below one of Fluxheim's standard native roots: `/etc/fluxheim`, `/run/fluxheim`,
`/var/lib/fluxheim`, `/var/cache/fluxheim`, `/var/log/fluxheim`, or
`/srv/fluxheim`.

Install the systemd service, optional socket unit, and environment file:

```bash
sudo install -Dm0644 packaging/systemd/fluxheim.service /etc/systemd/system/fluxheim.service
sudo install -Dm0644 packaging/systemd/fluxheim.socket /etc/systemd/system/fluxheim.socket
sudo install -Dm0644 packaging/systemd/fluxheim.env /etc/sysconfig/fluxheim
sudo systemctl daemon-reload
```

Validate before starting:

```bash
sudo -u fluxheim /usr/bin/fluxheim --config /etc/fluxheim/fluxheim.toml --validate-config
```

Start and enable:

```bash
sudo systemctl enable --now fluxheim.service
sudo systemctl status fluxheim.service
```

View logs:

```bash
journalctl -u fluxheim.service -f
```

## Config Path Override

The unit defaults to:

```text
FLUXHEIM_CONFIG=/etc/fluxheim/fluxheim.toml
```

To use another config, edit `/etc/sysconfig/fluxheim`:

```text
FLUXHEIM_CONFIG=/etc/fluxheim/fluxheim.toml
```

Then reload systemd and restart:

```bash
sudo systemctl daemon-reload
sudo systemctl restart fluxheim.service
```

## Reload And Restart

For `1.0`, treat native service changes as validate-then-restart unless a
specific runtime reload path is documented for the setting you changed:

```bash
sudo -u fluxheim /usr/bin/fluxheim --config /etc/fluxheim/fluxheim.toml --validate-config
sudo systemctl restart fluxheim.service
```

Fluxheim exits on `SIGTERM`; the unit uses `TimeoutStopSec=30s` so the process
has time to drain and shut down cleanly before systemd escalates.

Starting with `1.7.11`, native listeners stop accepting after the configured
grace interval and wait for established connection tasks within the configured
graceful-shutdown timeout. Public HTTP/HTTPS listeners can also be inherited
through systemd socket activation. This makes restarts bounded and
connection-aware and lets systemd retain the listening socket between process
generations.

RPM packages ship a disabled `fluxheim.socket` matching the packaged
`server.listen = ["0.0.0.0:80"]` default. The addresses in the socket unit must
exactly match `server.listen` and `server.tls_listen`. For example, for a config
listening on `0.0.0.0:80` and `0.0.0.0:443`, replace the socket unit with:

```ini
[Unit]
Description=Fluxheim public listeners

[Socket]
ListenStream=0.0.0.0:80
ListenStream=0.0.0.0:443
NoDelay=true
Service=fluxheim.service

[Install]
WantedBy=sockets.target
```

The first conversion from a directly bound service requires one stop/start and
therefore is not itself zero-downtime. Disable the direct service owner, then
activate the persistent socket owner:

```bash
sudo systemctl daemon-reload
sudo systemctl disable --now fluxheim.service
sudo systemctl enable --now fluxheim.socket
sudo systemctl start fluxheim.service
```

Keep `fluxheim.socket` enabled and do not re-enable `fluxheim.service`; incoming
traffic can activate the service, and explicit service restarts retain the
socket in systemd. After this one-time conversion, validate an update and use
`systemctl restart fluxheim.service` while the socket unit remains active.

Do not add addresses that are absent from the Fluxheim config and do not omit
configured public addresses. Fluxheim rejects partial activation, wrong-process
descriptors, non-TCP descriptors, duplicate addresses, and address mismatches;
it never silently binds a fallback public socket once activation was requested.
The packaged service uses `Type=notify` and considers startup successful only
after Fluxheim reports that native startup completed. The complete rollout
model and current limitation are documented in
[Zero-Downtime Upgrades](zero-downtime-upgrades.md).

## ACME Timer

RPM packages install a one-shot renewal unit and timer:

- `fluxheim-acme.service`
- `fluxheim-acme.timer`

The service runs `fluxheim-acme --config ${FLUXHEIM_CONFIG} renew` as the same
`fluxheim` user, with the same runtime/state/cache/log directories as the web
service. It does not bind ports and does not receive `CAP_NET_BIND_SERVICE`.
After successful renewal it requests live certificate activation through
`/run/fluxheim/fluxheim-cert-reload.sock`.
Set `tls.acme.automation = "external"` when using the timer so the main
webserver does not also run the background renewal loop.

For issuers with External Account Binding, install the ACME credential drop-in
for the ACME unit and use credential names in the TOML:

```bash
sudo install -d /etc/systemd/system/fluxheim-acme.service.d
sudo cp /usr/share/doc/fluxheim/systemd/actalis-eab-acme.conf \
  /etc/systemd/system/fluxheim-acme.service.d/actalis-eab.conf
sudo systemctl daemon-reload
```

```toml
[tls.acme.issuers.eab]
key_id_credential = "actalis-eab-kid"
hmac_key_credential = "actalis-eab-hmac-key"
```

Enable scheduled renewal:

```bash
sudo systemctl enable --now fluxheim-acme.timer
sudo systemctl start fluxheim-acme.service
```

## Sandbox Overrides

The default unit is strict enough for normal static/proxy deployments. If a
deployment needs extra host access, prefer a local drop-in instead of editing
the packaged unit:

```bash
sudo systemctl edit fluxheim.service
```

For example, add another read-only content root:

```ini
[Service]
ReadOnlyPaths=/etc/fluxheim /srv/fluxheim /srv/sites
```

Then validate and restart:

```bash
sudo systemctl daemon-reload
sudo systemctl restart fluxheim.service
```

## TLS And Content Paths

The default native paths are:

| Path | Purpose |
| --- | --- |
| `/etc/fluxheim/fluxheim.toml` | Main config. |
| `/etc/fluxheim/conf.d` | Optional split config directory. |
| `/etc/fluxheim/tls` | Static certificate chains and private keys. |
| `/srv/fluxheim` | Default static site root. |
| `/var/lib/fluxheim` | State and future ACME/snapshot storage. |
| `/var/cache/fluxheim` | Cache storage. |
| `/var/log/fluxheim` | Optional file logs. |
| `/run/fluxheim` | PID file, upgrade socket, and certificate reload socket. |

Keep private keys mode `0600` or stricter and owned by the runtime user when
Fluxheim reads them directly:

```bash
sudo chown fluxheim:fluxheim /etc/fluxheim/tls/key.pem
sudo chmod 0600 /etc/fluxheim/tls/key.pem
```
