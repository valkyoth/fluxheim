# Structured Event Contract

Schema version 1, introduced in Commit 02. Commit 03 connects operational owners
through `operational.rs` and the existing runtime logger. Commit 04 adds async
dispatch; Commit 06 connects native request completion/correlation. Unmigrated
legacy logs and OTLP encoders do not inherit this contract merely by depending
on the crate. Existing configuration stays valid.

## Capture Boundary

`StructuredEvent::capture` accepts a typed `EventData`, a numeric configuration
identity, borrowed correlation candidates, policy and the effective filter
decision. It neither writes files nor logs, queues, starts threads, contacts
collectors or reads environment variables. `structured-events` enables this API;
without it, standalone observability consumers do not acquire serde dependencies.
The application and native server enable it. Operational callers use a narrower
API accepting only finite event data, with no request correlation or resources.

There is deliberately no arbitrary field map, message string, URL, path, host,
IP, HTTP header, query value, body, credential or `Display`/`Error` input. Owners
must map errors to a finite reason code, not format error chains first. A nested
error of arbitrary depth therefore cannot trigger traversal, allocation or
secret disclosure through this API. A compile-fail test protects that boundary.
This does not sanitize unrelated uses of `log!` or arbitrary caller formatting.

| Family | Typed data | Default level / admission class |
| --- | --- | --- |
| Access | completed/cancelled/failed outcome, finite HTTP method, optional 100..599 status, duration_micros, bytes_sent, attempts | INFO / ordinary |
| Error | finite failure reason, optional retry attempt | ERROR / ordinary |
| Security | finite policy-decision reason | WARN / protected |
| Audit | finite operation/outcome, actor class, optional configuration revision | INFO success, WARN rejected, ERROR failed / protected |

Failure codes: dns, connection_refused, connection_timeout, read_timeout,
write_timeout, tls_verification, tls_handshake, upstream_protocol, cache_read, cache_write,
cache_encryption, php_connect, php_protocol, php_timeout, wasm_trap, wasm_timeout,
wasm_execution, acme, reload, rollback,
telemetry and internal. Security codes: authentication_rejected,
authorization_rejected, host_rejected, request_limit, rate_limit,
admission_rejected, path_rejected, wasm_denied and invalid_trace_context.

Audit operations: reload, snapshot, rollback, self_heal, cache_purge,
cache_activity_reset, load_balancer_update, persistence_clear,
certificate_renewal and certificate_revocation. Outcomes are succeeded, failed
or rejected; actors are admin_token, local_operations or automatic, never an
invented human identity behind a shared token. Additional reasons require a
reviewed schema change and producer coverage in Commit 03, not raw fallback text.

Resource identity is `{kind, generation, index}` from trusted configuration.
Kinds are listener, vhost, route, upstream, cache, php_pool, acme_issuer and
wasm_module. Never populate the index by hashing request input. Generation
disambiguates reused indices after reload; do not use these identities or
correlation IDs as metric labels. Human-readable configuration mapping is later
status/producer work, not a reason to log backend addresses here.

`timestamp_unix_nanos` is a u64 wall-clock timestamp (0 means unavailable), not
a duration or promise of monotonic ordering. Access duration is measured with
a monotonic clock by the producer. `bytes_sent` counts bytes accepted by the
downstream write interface, not proof the client consumed them. `attempts`
counts upstream attempts (0 if none); a logical request emits one access outcome.
Per-attempt error events use one-based attempt numbers when known. Native
completion/cancellation accounting remains Commit 06 work.

## Policy And Redaction

1. The runtime resolves `RUST_LOG` versus `logging.level` using the existing
   env_logger semantics: an environment filter replaces the configured default,
   including module directives and optional message regex. New event targets
   are `fluxheim::event::{access,error,security,audit}`. Test the filter against
   the typed level/target and fixed message, not a raw error or encoded envelope.
2. Pass that decision to capture before allocating optional strings. An explicit
   off/filter rejection applies to every family; protected does not mean forced
   logging. Commit 03 checks the log facade's metadata filter first; env_logger
   applies the final message regex to the fixed message before formatting/output.
   No optional strings are captured by these producers. A regex rejection may
   still incur bounded encoding work, but never sinks an event.
3. The access switch gates only access events. Turning it off cannot implicitly
   disable otherwise permitted error/security/audit events.
4. Privacy mode suppresses access events and all optional resources/correlation
   in other families. The application forwards its compile-time privacy feature
   to this crate; a caller cannot override it with `privacy_mode = false`.
5. Correlation and resource capture default off in the library. Callers must
   deliberately map existing settings to policy without changing operator choices.
   Path/host/client-IP options remain configuration-compatible but gain no new
   output through the current operational producers.

Correlation candidates are borrowed and their Debug implementation redacts
everything. Privacy-disabled capture still requires both the corresponding
include flag and trusted provenance. `trusted` must reflect a locally generated
ID or an explicitly trusted peer, not an input field or a syntactically valid ID.
Request IDs use the existing 1..128-byte ASCII alphanumeric/dot/hyphen/underscore
grammar. Trace and span IDs must both be present, be nonzero hexadecimal strings
of exactly 32/16 bytes, and are normalized to lowercase. Validation never slices
untrusted Unicode at byte offsets. Trust/syntax checks are not secret detection:
a secret deliberately placed in a trusted, opted-in valid ID could be logged.
The safe default is omission; IDs confer no authorization.

Rejected candidates are never retained or partially echoed. `redacted = true`
means supplied optional data was omitted by policy or validation. `truncated =
true` means an allowed/trusted candidate was oversized and omitted in full,
not shortened into a different identifier. No raw error text is used to explain
why a field was rejected. Privacy suppression does not expose size categories.

## Encoding And Limits

- Maximum encoded event: 8192 bytes including text framing and one newline.
  The writer checks every write BEFORE buffer growth. Failure returns a finite
  error with no partial event. JSON escape expansion counts against the limit.
- The closed schema has fewer than 32 fields counting nested object members.
  Tests cover every envelope at maximum numeric/optional values; adding fields
  requires retaining that bound. There is no extensible unbounded field bag.
- Strings are at most 1024 encoded bytes (message ceiling 4096). Current messages
  are fixed short literals; dynamic retained strings are only bounded ASCII IDs.
  No scan/copy is made of an arbitrarily long rejected ID: length is checked first.
- Encoding allocates at most an 8 KiB working buffer; the returned boxed byte
  slice has exactly the encoded length, without retained capacity slack. During
  shrinking an allocator may temporarily hold the working and result buffers.
  Queue accounting must include entry overhead, not only wire bytes, in Commit 04.
- JSON is one versioned object per line. Text is `LEVEL kind ` followed by the
  SAME JSON object and newline. Both formats share capture/redaction and
  serialization; text is not an alternative raw-string escape hatch. The old
  four-field runtime JSON and legacy text format remain unchanged.

The envelope includes schema_version, service_version (compiled crate version),
timestamp_unix_nanos, level, message,
data (with kind), optional resource, correlation, redacted and truncated.
No Deserialize implementation is provided for captured events. Producers,
not unauthenticated JSON clients, construct them. See the
[audit fixture](../../tests/fixtures/observability/structured-audit.json), whose
PACKAGE_VERSION marker is substituted with the compiled version by the test.

## Protected Admission Design For Commit 04

Commit 03 has a fixed-state sink admission limiter: separate ordinary and
protected windows each admit at most 100 records per second. Windows use monotonic
time; boundary-adjacent bursts can total 200 per class. Contention/poisoning drops
instead of waiting on the budget mutex. Drops are counted with saturation, but
are not yet exposed by the operational API. Filtering happens before admission.
There is NO asynchronous queue or lossless delivery guarantee yet. The existing
synchronous writer can still block: Commit 04 must address this, not describe
rate limiting as async delivery. Its dispatcher must:

- Use the Commit 01 default total of 4096 entries/8 MiB with a protected reserve
  of 256 entries/1 MiB INSIDE those totals. Ordinary access/error events cannot
  consume that reserve. Saturation must count losses separately by family/reason.
- Apply a proposed aggregate protected-lane token budget of 100 events/second
  with burst 256, using monotonic time and bounded state (not a per-client map).
  Denied-request floods must not exhaust RAM or block request workers. Review
  these defaults with the dispatcher tests before acceptance; they are not new
  configuration keys or an operational promise in this checkpoint.
- Keep audit/security exhaustion visible locally without recursive logging.
  Priority is finite reserved capacity, not guaranteed retention, authentication
  of an event, or permission to bypass configured filters/privacy.

## Verification And Remaining Gates

Permanent tests cover schema fixtures, all envelope size/field bounds, exact
encoding limits including newline, escape expansion, controls/Unicode, secret
canaries, oversized and malformed IDs, filter/module/message-regex precedence,
feature-off builds, privacy feature override resistance and 512 randomized
input cases per property-test run. Existing runtime/OTLP baseline fixtures remain.

Commit 03 adds owner-to-sink verification; see its
[coverage and limitations](../evidence/observability-03.md). Public responses,
authentication, filesystem trust and recovery transitions remain unchanged.
Automatic ACME renewal outcomes now omit legacy raw domain/error text in favor
of typed events. Other legacy messages remain and must not be mistaken for
sanitized events. Incremental pentest, exact-SHA GitHub checks and user approval
are required before Commit 04. Native Windows/macOS execution must be supplied
by CI or native hosts, not inferred from Linux or cross-compilation.
