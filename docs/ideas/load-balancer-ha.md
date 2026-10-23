# Load Balancer HA Design Notes

Fluxheim `1.5.3` ships managed affinity cookies for one process. This document
records the active-active HA design boundary for later `1.5.x` work so
operators can separate shipped behavior from planned cluster behavior.

## Current 1.5.3 Behavior

- `mode = "managed-cookie"` emits a signed, opaque cookie on eligible 2xx/3xx
  backend responses.
- Cookie values map to the local bounded persistence table.
- Signing keys are generated locally, rotate daily, and verify the current or
  previous generation.
- Persistence tables and signing keys are not shared between Fluxheim nodes.
- Process restart invalidates unmanaged local state and starts a new signing
  key lineage.

## Future Active-Active Shape

The planned HA track should replicate only bounded, operationally useful state:

- managed-cookie key-to-backend affinity table entries;
- application-cookie or header persistence decisions when explicitly opted in;
- administrative member overrides such as `disable`, `forced_down`, and
  `drain`;
- optionally passive-health/circuit state after split-brain and freshness rules
  are proven.

Retry budgets, queue counters, high-cardinality telemetry, and low-value
per-request counters should stay node-local unless a later design proves that
replication is bounded and useful.

## Peer Protocol Requirements

Any cookie-mirroring implementation must include:

- mutually authenticated peers;
- bounded message size and bounded table sizes;
- per-entry TTL and table eviction;
- replay protection through monotonic sequence numbers or signed timestamps;
- explicit fail-open/fail-closed behavior when peers are unavailable;
- audit events for peer joins, state import/export, and rejected updates;
- metrics for replication lag, dropped updates, rejected updates, and peer
  health;
- key rotation that supports overlap across the cluster, not only one process.

## Non-Goals For 1.5.3

`1.5.3` does not implement shared signing keys, restart-persistent state,
cross-node persistence-table synchronization, or active-active cookie mirroring.
Those remain future HA/control-plane work after the local managed-cookie path
has passed release and pentest coverage.
