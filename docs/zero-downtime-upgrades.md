# Zero-Downtime Upgrades

Fluxheim `1.7.11` starts the zero-downtime process-upgrade line. This document
defines the safety model before listener inheritance, readiness signaling, and
deployment automation are promoted as stable behavior.

Zero downtime requires one component outside the replaceable Fluxheim process
to keep ownership of the public listening socket. Replacing a process that is
the sole owner of a bound port necessarily creates a listener gap, regardless
of how quickly the replacement starts.

## Current 1.7.11 Drain Contract

The first implementation slice makes native shutdown behavior explicit:

1. Fluxheim receives `SIGTERM`, `SIGQUIT`, or the platform shutdown signal.
2. An optional `server.process.grace_period_seconds` delay allows a supervisor
   to finish its handoff sequence before Fluxheim starts draining.
3. Fluxheim requests process-wide shutdown. Native HTTP, HTTPS, HTTP/2, admin,
   and local Unix HTTP listeners stop accepting and drop their listener handle.
4. Accepted connection tasks remain alive. Existing HTTP/1 keep-alive,
   WebSocket/takeover, TLS, and HTTP/2 connections may finish normally.
5. The complete drain is bounded by
   `server.process.graceful_shutdown_timeout_seconds`. If the field is omitted,
   Fluxheim applies a 30-second effective timeout.
6. Work still active at the timeout is terminated when the runtime exits.

The service manager or container stop timeout must exceed the grace period plus
the graceful drain timeout. Otherwise it can send `SIGKILL` before Fluxheim's
own bound is reached.

This drain contract improves normal restarts. The second implementation slice
also supports inherited public HTTP/HTTPS TCP listeners so an external socket
owner can remove connection refusal during replacement.

## Native Binary And systemd Design

The supported native design uses systemd socket activation:

- a `.socket` unit owns each public TCP listener;
- systemd passes those already-listening file descriptors to Fluxheim;
- Fluxheim validates the descriptor count, socket type, and bound address
  against the native launch plan before serving;
- Fluxheim never silently mixes inherited and newly bound public listeners;
- the new process validates configuration, initializes TLS/routes/cache policy,
  adopts every expected listener, and reports readiness;
- only after readiness does the supervisor ask the old process to drain;
- systemd retains the listening sockets while either process exits.

The inherited descriptor environment is part of the trusted process-launch
boundary. Fluxheim must fail closed on missing, duplicate, unexpected, or
wrong-address descriptors. It must not infer HTTP versus HTTPS from a port;
descriptor assignment remains tied to the explicit `listen` and `tls_listen`
launch plan.

Fluxheim accepts only the standard systemd FD-3 protocol. `LISTEN_FDS` must be
between 1 and 128, `LISTEN_PID` must equal the current process, and an optional
`LISTEN_FDNAMES` list must contain the declared number of names. The
non-standard `LISTEN_FDS_FIRST_FD` extension is rejected. Every inherited item
must be a TCP listener whose bound address exactly matches one planned public
HTTP/HTTPS address; configured port `0` is therefore not valid for activated
production listeners.

When any activation variable is present, validation failure is fatal. Fluxheim
does not bind missing listeners as a fallback. This prevents a partially
activated process from serving a different listener set than its supervisor
intended.

Socket activation for public HTTP/HTTPS listeners is the first target. Admin,
metrics, stream, UDP, and local control sockets remain separately owned until
their handoff semantics have dedicated tests.

## Readiness Requirements

Opening or inheriting a socket is not sufficient readiness. The replacement is
ready only after all startup-blocking work succeeds, including:

- complete configuration validation and `conf.d` merge;
- route and vhost construction;
- TLS certificate/key loading and SNI resolver construction;
- cache storage/lease initialization;
- load-balancer pool construction;
- required Wasm module validation and compilation;
- binding or adopting every required listener;
- starting critical background services.

If readiness fails, the old process must remain active and the replacement must
exit without asking it to drain. A timeout or failed health probe is a failed
upgrade, not permission to continue.

## Podman Design

A Podman container that directly publishes `80:8080` and `443:8443` owns those
host-port forwarding rules for its lifetime. A second container cannot replace
the same published ports atomically. Stopping the old container before starting
the new one therefore has a real listener gap.

True zero-downtime Podman upgrades require a stable fronting owner. Supported
design candidates are:

- a host systemd socket or small host-level listener that passes/forwards to
  the active Fluxheim generation;
- a stable, separately upgraded front proxy/load balancer that readiness-gates
  blue and green Fluxheim containers;
- an orchestrator service/load-balancer abstraction that keeps the public
  listener stable while endpoints roll.

The blue/green sequence is:

1. Start the green container on a distinct private address/port without
   changing public routing.
2. Wait for Fluxheim readiness and an external functional probe.
3. Atomically switch the stable fronting layer to green.
4. Put blue into drain mode.
5. Wait for blue to exit within the configured bound, then remove it.
6. Roll back routing to blue if green fails before the switch.

Two containers using `SO_REUSEPORT` directly are not the default design. It
does not provide deterministic readiness-gated routing, and traffic may still
reach the old generation until its listener closes.

## Shared State

Blue and green processes must not concurrently mutate storage that has a
single-writer contract. Cache storage-bin leases, snapshot stores, ACME state,
managed PHP-FPM state, PID/control sockets, and other process-owned paths need
separate generation paths or an explicit shared-state handoff.

Read-only configuration, certificate material, and static content may be shared
when their existing filesystem trust requirements are preserved. Operators
must not bypass storage leases to make overlapping generations start.

## Acceptance Evidence

The completed release must provide a live upgrade smoke that proves:

- an old process serves a persistent connection;
- a new process adopts the same externally owned public listener;
- readiness is observed before old-process drain starts;
- new connections reach the new generation without connection refusal;
- the established old-process connection completes during drain;
- the old process exits within the configured timeout;
- failed replacement startup leaves the old generation serving;
- direct-published Podman limitations are reported clearly rather than called
  zero downtime.

Inherited-listener adoption and bounded drain are implemented. Until readiness
signaling and the complete two-generation handoff smoke land, `1.7.11` should
still be described as zero-downtime groundwork rather than complete transparent
upgrade automation.
