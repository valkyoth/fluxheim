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
- stops with `SIGTERM` and lets Fluxheim/Pingora shut down gracefully.

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

Install the systemd unit and optional environment file:

```bash
sudo install -Dm0644 packaging/systemd/fluxheim.service /etc/systemd/system/fluxheim.service
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
| `/run/fluxheim` | PID and upgrade socket. |

Keep private keys mode `0600` or stricter and owned by the runtime user when
Fluxheim reads them directly:

```bash
sudo chown fluxheim:fluxheim /etc/fluxheim/tls/key.pem
sudo chmod 0600 /etc/fluxheim/tls/key.pem
```
