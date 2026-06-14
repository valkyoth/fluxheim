# Fluxheim Modularity Policy

Status: 1.6 planning policy

Fluxheim treats large files and unclear crate boundaries as security review
risk, not only style debt. The 1.6 Pingora-exit line should move Fluxheim
toward the same discipline used by smaller security-focused workspace projects:
focused crates, small files, explicit adapters, and release-gated exceptions.

## Core Rule

The root `fluxheim` crate should become orchestration glue. Major domains
belong in focused workspace crates with one-way dependencies back to common
types, never circular dependencies through admin, proxy, or runtime modules.

Target crates include:

- `fluxheim-common`
- `fluxheim-config`
- `fluxheim-cache`
- `fluxheim-load-balancer`
- `fluxheim-web`
- `fluxheim-php-fpm`
- `fluxheim-compression`
- `fluxheim-geoip`
- `fluxheim-observability`
- `fluxheim-protocol`
- `fluxheim-snapshot`
- `fluxheim-acme`
- `fluxheim-headers` or `fluxheim-http-policy`
- `fluxheim-runtime`
- `fluxheim-server`
- `fluxheim-proxy`
- future `fluxheim-wasm`, `fluxheim-http3`, and ecosystem crates

## File Size Rule

New or newly split Rust implementation files should follow:

- normal target: 300 lines or less;
- hard target: 500 lines or less;
- tests should be split by behavior before they make a production file hard to
  review;
- generated, vendored, or machine-owned files must be isolated and excluded
  from human-review line limits.

Existing large files are legacy debt. Do not block 1.6.0 on the current file
sizes, but do not let them grow without a documented reason.

## 1.6 Migration Gate

`v1.6.0` should add a report-only gate that lists non-generated `.rs` files over
500 lines and records the exception inventory. The gate should fail only for:

- new non-generated `.rs` files over 500 lines;
- files that exceed 500 lines after being split below the threshold;
- legacy exception files that grow without an exception update.

Each legacy exception should record:

```text
Path:
Reason:
Owner:
Split plan:
Target release:
```

By the end of the 1.6 line, the exception list should be materially smaller.
After Pingora is gone and the root runtime is split, the gate can become a hard
rule for all non-exempt files.

## Split Rules

Split by reason to change, not by arbitrary size alone.

Prefer modules such as:

```text
src/
|-- lib.rs
|-- error.rs
|-- types.rs
|-- validate.rs
|-- adapter.rs
`-- subsystem/
    |-- mod.rs
    |-- state.rs
    |-- policy.rs
    |-- protocol.rs
    |-- storage.rs
    `-- tests.rs
```

Avoid mixing parser code, validation, I/O, policy decisions, state mutation,
telemetry, and tests in one file. Pure logic should move into crates that can
be unit-tested without a running server.

## Security Rationale

Small files and focused crates make pentest and code review more reliable:

- reviewers can reason about one trust boundary at a time;
- duplicated security controls are easier to spot;
- fuzz and fixture coverage can target pure logic;
- adapters to external crates stay narrow;
- redaction, authority checks, and failure modes are local;
- future Wasm and HTTP/3 work starts from clean domain APIs.
