# Certificate Renewal And Reload

Fluxheim should support both operator-owned certificates and ACME-managed
certificates. Manual certificates are configured with `cert_path` and `key_path`.
ACME certificates are configured per vhost and managed under `tls.acme.storage`.

Downstream TLS listeners are explicit in `server.tls_listen`. The runtime uses
the first global `[[tls.certificates]]` entry as the default certificate for
those listeners, so config validation rejects `server.tls_listen` unless
`tls.enabled = true` and a global static certificate is configured. Vhosts can
override that certificate with `[vhosts.tls.certificate]`; Fluxheim selects the
matching certificate by SNI during the downstream TLS handshake.

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

The background service that owns the priority queue and performs ACME
account/order/challenge calls is still pending.

## Runtime Crate Candidates

Latest checked ACME runtime candidates:

- `instant-acme 0.8.5`: Apache-2.0, async pure-Rust ACME client with EAB
  support. This is the current first candidate because it does not own the TLS
  listener model.
- `rustls-acme 0.15.1`: Apache-2.0 OR MIT, useful reference for rustls-focused
  certificate management, but less aligned with Fluxheim's multiple Pingora TLS
  backend targets.

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
