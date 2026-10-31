# Service Lifecycle And Process Settings

Fluxheim runs in the foreground. A supervisor such as systemd or your container
runtime should start it, collect its logs and restart it after failure. On a
terminal, keep the process attached and use Ctrl+C to stop it normally.

## Start A Local Server

The complete [example](../../examples/service-lifecycle/fluxheim.toml) serves a
small static page on numeric loopback. From the repository root:

```bash
cargo build --locked --no-default-features --features profile-static-site
target/debug/fluxheim --config examples/service-lifecycle/fluxheim.toml --validate-config
target/debug/fluxheim --config examples/service-lifecycle/fluxheim.toml
```

From a second terminal:

```bash
curl --fail -H 'Host: lifecycle.example.test' http://127.0.0.1:8080/
```

Expect `service-lifecycle-ok`. The example uses two worker threads, a two-second
handoff delay and a five-second drain timeout. It does not enable TLS, ACME,
admin, cache or telemetry exporters. Paths are relative to the TOML file.
See [configuration loading](configuration.md) before splitting it into files.

## Process Options

Every current `[server.process]` field is listed below. These are process-wide
settings, not per-vhost limits. Validating a field does not mean the native
runtime implements its requested behavior: the inactive fields are explicitly
marked. **Current limitation:** tracks this mismatch in the local follow-up.

| Setting | Default / accepted values | Actual native behavior |
| --- | --- | --- |
| `threads` | `1`; integer `1..1024` | Number of Tokio async worker threads. Not the total OS thread count or a request concurrency limit. |
| `upstream_keepalive_pool_size` | `128`; integer `1..16384` | Passed to native HTTP proxy client construction for connection reuse. Not a global connection/admission budget; see [proxy transport](reverse-proxy.md). |
| `grace_period_seconds` | Omitted; positive integer seconds when set | Wait before asking listeners/background services to stop. New requests can still arrive during this delay. Omit it for no delay; `0` is rejected. |
| `graceful_shutdown_timeout_seconds` | Omitted means effective `30`; positive integer seconds when set | Bounds the tracked async task drain after the grace delay. Ongoing work is aborted on timeout. It is not a total process-exit deadline. |
| `certificate_reload_sock` | `/run/fluxheim/fluxheim-cert-reload.sock`; nonempty safe path | Unix ACME certificate-reload endpoint when that service is enabled. Not an HTTP socket or general config-reload endpoint. Windows does not provide this Unix endpoint. |
| `daemon` | `false`; boolean | Accepted but inactive: even `true` keeps the native process in the foreground. Use your supervisor. |
| `error_log` | Omitted; optional safe path | Accepted but inactive. Use `[logging]` / `[logging.file]`, not this field, for output. |
| `pid_file` | `/run/fluxheim/fluxheim.pid`; nonempty safe path | Validated and retained, but the native runtime does not create a PID file. Use the supervisor's process identity. |
| `upgrade_sock` | `/run/fluxheim/fluxheim-upgrade.sock`; nonempty safe path | Validated and retained, but no native upgrade socket is opened. It cannot trigger a handoff. |
| `listener_tasks_per_fd` | `1`; integer `1..1024` | Accepted but inactive; does not change the native accept-task count. |
| `work_stealing` | `true`; boolean | Accepted but inactive; setting `false` does not reconfigure Tokio's scheduler. |
| `max_retries` | `16`; integer `0..1024` | Accepted but inactive in the native request path. Not an enforced origin retry limit. The separate [load-balancer retry finding](load-balancer.md) also remains open. |

Keep the inactive settings at defaults except for safe path overrides needed
by your deployment. Paths are still checked even when no file/socket is created;
an unsafe PID path can therefore fail validation. Relative paths use the defining
configuration file's directory, not the working directory. These fields do not
create missing runtime directories or relax filesystem ownership requirements.

The runtime also has a fixed maximum of 384 Tokio blocking threads; this is not
a TOML tuning option. Additional components can have their own workers. Use
supervisor CPU/memory limits and the documented [request admission controls](rate-and-concurrency-limits.md)
instead of interpreting `threads` as a complete resource bound.

## Stop Without Dropping All Work Immediately

After startup, Unix builds handle SIGINT (Ctrl+C), SIGTERM and SIGQUIT through
the same shutdown path. Windows handles console CTRL_C and CTRL_BREAK. Forced
termination, SIGKILL, Task Manager termination and a service wrapper's stop
behavior are not equivalent to these handled signals. This is not a native
Windows Service Control Manager registration or a promise about console-close
events. No SIGHUP/SIGUSR2 reload/upgrade protocol is implemented here.

For example, ask your supervisor to stop the tracked process:

```bash
sudo systemctl stop fluxheim.service
# For a container configured with SIGTERM as its stop signal:
podman stop --time 45 fluxheim
```

The shutdown sequence is:

1. On Linux, send best-effort `STOPPING=1` notification to the supervisor.
2. Wait the configured grace period, if any. Accept loops remain active.
3. Request process-wide shutdown; listeners stop accepting new connections.
4. Allow established tasks to finish within the drain timeout. Existing
   keep-alive, HTTP/2 and WebSocket sessions can keep this phase busy.
5. Abort remaining tracked work at timeout, then perform remaining teardown.

A drain timeout is logged as a warning but can still produce exit status zero.
Zero is not proof that every request finished. Clients need ordinary timeout,
reconnect and safe-retry behavior. Already executing blocking work and exporter
shutdown can outlast async task cancellation; the process's Tokio runtime is
dropped normally after `block_on`. Keep an external hard stop limit with room
for teardown rather than relying on the drain timeout as a whole-process bound.

For the example's 2 + 5 second timing, a 20-second supervisor budget leaves
headroom. For default 30-second draining, use at least a 45-second budget and
increase it when adding a grace period or slower teardown. These are deployment
examples, not hard upper bounds for arbitrary workloads.

**Current limitation:** the shipped systemd service currently uses
`TimeoutStopSec=30s`, equal to the default drain with no teardown margin. Apply
the [systemd override](systemd.md#reload-and-restart) until packaging is corrected.

## Readiness And Replacement

`--validate-config` checks configuration but does not bind listeners, complete
every runtime initialization or prove origins/collectors are healthy. Normal
startup constructs the runtime, prepares public/admin listeners and waits for
configured background readiness acknowledgements before starting those accept
loops. Linux then emits `READY=1`; an invalid/unreachable configured
`NOTIFY_SOCKET` causes startup to fail. Other platforms do not emit systemd
notifications. The supervisor must enforce its own startup deadline.

Readiness is not a successful request, a fresh ACME certificate, verified cache
persistence or exporter delivery. In particular, the known
[disk initialization finding](cache.md) remains open. Probe the actual route,
TLS identity and dependencies you need before switching traffic.

For replacement, see [zero-downtime upgrades](zero-downtime-upgrades.md).
Ordinary `systemctl restart` stops the old service before starting its
replacement. A persistent socket can queue new connections during the gap, but
does not preserve old connections or provide automatic old-generation rollback.
Readiness-gated overlap needs a separate supervisor/fronting layer, independent
generation paths and a tested state-sharing policy.

Use the [admin/snapshot workflow](config-snapshots.md) for documented live config
changes and [ACME](acme.md) for certificate activation. Do not assume every
process field can be changed live or use the inactive `upgrade_sock` as a reload
API. Keep `[server.process]` in one authoritative fragment until the configuration
composition correction is complete.

## Reproduce The Checks

```bash
python3 scripts/test_service_lifecycle.py
cargo build --locked --no-default-features --features profile-static-site
python3 scripts/smoke_service_lifecycle.py
sh scripts/smoke_systemd_socket_activation.sh
sh scripts/smoke_zero_downtime_upgrade.sh
```

The lifecycle smoke is Linux-only and runs the trusted local binary with private
fixtures, loopback HTTP and bounded child cleanup. It checks readiness/stopping,
grace-period requests, established-connection drain, timeout termination and
inactive path/daemon settings. The activation and handoff smokes emulate the
supervisor; they do not test an installed systemd unit. No new native macOS or
Windows shutdown qualification is implied by these Linux results.
