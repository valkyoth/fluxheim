# Configuration Composition Reference

Use the [configuration-loading guide](../guides/configuration.md) for complete
recipes, trust requirements and troubleshooting. These are **current** loader
semantics, not a promise of generic recursive TOML merging. Request-time policy
inheritance is documented separately by each feature.

## Top-Level Inventory

| Root key | Cross-file behavior | Feature details |
| --- | --- | --- |
| `include_conf_d` | Defaults false; only the selected main file's value controls sibling inclusion; directory mode always includes the immediate child | [Loading guide](../guides/configuration.md#split-a-configuration) |
| `server` | Explicit top-level fields merge; nested exceptions below | [Server](config-reference.md#server) |
| `admin` | Optional-field fragments merge, including nested transport, socket, health, throttle, self-healing and client-certificate policies | [Admin](config-reference.md#admin) |
| `metrics` | Whole section replaces earlier section, including omitted fields' defaults | [Observability](../guides/observability.md) |
| `tracing` | Whole section replaces earlier section | [Tracing](../guides/opentelemetry-tracing.md) |
| `logging` | Whole section replaces earlier section | [Logging](../guides/logging.md) |
| `headers` | Whole section replaces earlier global request/response/CORS policy; this is not a vhost overlay | [Request headers](../guides/request-headers.md), [response headers](../guides/response-headers.md), [CORS](../guides/cors.md) |
| `tls` | Explicit fields and nested policy fragments merge; supplied certificate/cipher/curve arrays replace their earlier arrays | [TLS options](tls-options.md) |
| `proxy` | Explicit fields and nested auth/mirror/load-balancer fragments merge; upstream-source rules and explicit list replacement still apply | [Proxy options](proxy-transport-options.md) |
| `compression` | Explicit fields merge | [Compression](../guides/compression.md) |
| `cache` | Explicit fields and nested cache fragments merge; presets apply after file composition | [Cache options](cache-options.md) |
| `cache_purger` | Explicit fields merge | [Cache operations](../guides/cache-operations.md) |
| `web` | Explicit fields merge | [Static files](../guides/static-files.md) |
| `geoip` | Whole section replaces earlier section, including databases | [GeoIP](../guides/geoip.md) |
| `stream` | Explicit enabled/routes fields merge; an explicitly supplied routes list replaces, not appends | [TCP streams](../guides/tcp-streams.md) |
| `udp` | Whole section replaces earlier section | [UDP](../guides/udp.md) |
| `wasm` | Optional scalars/default fields merge; roots, plugins and attachments append; final validation checks conflicts and bounds | [Wasm options](wasm-options.md) |
| `vhosts` | Append declarations; not a merge by name; final duplicate-name/host checks apply | [Vhosts](../guides/vhost-config.md) |

The whole-section cases and nested server replacements are the subject of
**Current limitation:**. Keep those policies together in one file until
the correction is implemented. An empty table can still materialize a whole
default policy; it is not always a no-op. Explicit array/map operations are
type-specific and are not automatically element-by-element merges.

## Server Exceptions

| Field | Current merge rule |
| --- | --- |
| `listen`, `tls_listen` | Supplied array replaces; an explicit empty array clears it, subject to final listener validation |
| `default_vhost` | Supplied value replaces; omission retains the earlier value; empty name is invalid |
| `trusted_proxies` | Append entries not already present by exact string equality; empty array does not clear previous entries |
| `proxy_protocol`, `regex_enabled` | Explicit scalar replaces |
| `limits` | Whole nested policy replaces; omitted values reset to defaults |
| `process` | Whole nested policy replaces; omitted paths/limits reset to defaults |
| `https_redirect` | Whole nested policy replaces |
| `host_routing` | Whole nested policy replaces |

TOML does not provide a general `null` reset. To remove an earlier optional
path or empty an append-only list, edit its defining configuration rather than
assuming omission/`[]` in a later fragment erases it. Validation happens against
the final object; declarations can refer to vhosts introduced in later files.

## Path Resolution

Each fragment resolves its configured relative filesystem paths before merge.
The loader delegates to the owning policy's path resolver:

| Scope | Examples of resolved paths |
| --- | --- |
| `server.process` | PID, upgrade/certificate-reload sockets, error log |
| `admin` | Control/observer token files, snapshot/key paths, Unix operations socket |
| `metrics`, `tracing` | Token files, OTLP bearer files and CA files |
| `logging` | Managed log path and optional crash file |
| `tls` | Certificate/key pairs, mTLS CA/CRL, ACME storage and issuer file inputs |
| `proxy` | Upstream discovery file/bearer token, TLS/mTLS inputs, load-balancer state and error-page web roots |
| `cache` | Disk storage, encryption/key-provider and peer-fill files |
| `web`, `geoip` | Static roots and database paths |
| `stream` | Route TLS and client-certificate inputs |
| `wasm` | Plugin roots and module paths |
| `vhosts` and their routes | Feature-owned web/PHP/proxy/TLS/cache paths, resolved from that vhost's file |

No resolver is needed for plain policy sections without filesystem fields.
This is path joining, not shell/environment expansion or permission repair.
Feature-specific validation may require an existing file, permit a missing
final state directory, or require a private secret file; consult that feature's
guide. Do not treat accepted path syntax as proof a later runtime open succeeds.

## Implementation And Proof

- [Fragment schema](../../crates/fluxheim-config/src/config_fragment.rs).
- [File/directory composition and final validation](../../crates/fluxheim-config/src/config_root_load.rs).
- [Selection, bounds and retained-file reading](../../crates/fluxheim-config/src/config_loader.rs).
- [Filesystem trust and identity](../../crates/fluxheim-config/src/config_loader_trust.rs).
- [Server merge rules](../../crates/fluxheim-config/src/config_server.rs).
- [Guide and composition regressions](../../crates/fluxheim-config/src/config_tests_loader_contract.rs).
- [Live configuration recipes](../../scripts/smoke_configuration_examples.py).

Per-file checks are not an atomic multi-file snapshot. Fresh native macOS and
Windows recipe execution, snapshot operations and service-manager deployment
remain distinct qualification work, not implied by Linux loader tests.
