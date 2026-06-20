# Fluxheim 1.6.23 Release Notes

Fluxheim 1.6.23 cuts the stream and UDP proxy startup boundary over to
Fluxheim-owned native task primitives. The data paths were already Tokio-based;
this release removes the Pingora-owned accept-loop lifecycle from those
services and keeps the old runtime only as a narrow registration adapter until
the final 1.6.x cutover.

## Changed

- Move stream proxy listener startup into a native `FluxBackgroundTask`
  boundary.
- Move UDP proxy listener startup into a native `FluxBackgroundTask` boundary.
- Keep Pingora service registration as a thin compatibility wrapper that
  delegates to the same native stream/UDP tasks.
- Mark config-derived stream and UDP service plans native-ready in the native
  runtime cutover summary.
- Extend native runtime cutover evidence with a representative UDP route and
  update the expected blocker report so only HTTP/2 remains for that
  representative stream/UDP config.
- Update release metadata, RPM metadata, and container tag documentation for
  `v1.6.23`.

## Security

- Add `FluxShutdown::wait_for_shutdown()` so native service loops can wait on
  shutdown without depending on Pingora's `ShutdownWatch` API.
- Make `wait_for_shutdown()` return immediately when shutdown was already
  requested before a task starts waiting, preventing stalled startup/shutdown
  handoff.
- Make native background-task joins abort-on-cancel, so cancelling a `join()`
  future cannot silently detach a task that should still be supervised.
- Make the shutdown waiter cancellation-safe for native stream/UDP
  `tokio::select!` loops.
- Preserve query strings on pathless absolute-form admin request targets such
  as `http://admin.local?reload=true`, mapping them to `/` plus query instead
  of dropping the query.
- Preserve live stream and UDP smoke coverage after the lifecycle change.
- Keep final HTTP proxy and HTTP/2 runtime parity as explicit blockers until
  the final Pingora-free proof release.

## Compatibility Boundary

- Normal proxy profiles still retain the Pingora compatibility runtime in this
  release. Stream and UDP service startup now uses Fluxheim-native task
  boundaries, but final production runtime/listener removal remains scheduled
  for the last Pingora-exit proof release.
