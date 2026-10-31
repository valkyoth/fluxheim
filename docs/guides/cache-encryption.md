# Cache Encryption

Fluxheim can encrypt disk cache objects before they are written to the
filesystem or storage-bin backend. This is optional and disabled by default.
Use it when otherwise cacheable response bodies require at-rest protection and
the cache device must not expose plaintext while Fluxheim is stopped.

Cache encryption does not encrypt in-process memory cache contents, request or
response logs, upstream responses in transit, or files served directly by
`[vhosts.web]` before they enter an opt-in cache path. It is cache-at-rest
protection.

Encryption does not make personalized responses safe to share. Keep normal
credential/cookie bypass and private-response admission rules from the
[caching guide](cache.md). Anyone who controls the running process or its
decryption credentials can still obtain plaintext. File sizes, configured key
IDs and storage activity are not concealed by object encryption.

## What Gets Encrypted

Cache encryption wraps objects stored by `[cache.disk]`, `[vhosts.cache.disk]`,
and `[vhosts.routes.cache.disk]`. It works with both disk backends:

- `backend = "filesystem"`: each persisted cache object is encrypted before it
  is written to its object file.
- `backend = "storage-bin"`: each persisted cache object is encrypted before it
  is placed into a bin file.

Memory cache remains plaintext inside the Fluxheim process. In a tiered
memory-plus-disk cache, memory hits stay fast and the persisted disk copy is
encrypted at rest.

This applies to native reverse-proxy disk objects. Native local/static caching
is memory-only and cannot use this encrypted disk tier. Fixed slices also have
a pending persistent-storage gap; see [range caching](cache-ranges.md).

Native runtime status: the native HTTP/1 proxy cache supports local-key and
OpenBao Transit encrypted `backend = "filesystem"` and `backend =
"storage-bin"` cache objects. OpenBao Transit support is enabled in Fluxheim's
normal cache profile through the server crate's optional
`openbao-cache-encryption` feature.

## Providers

`provider = "local"` uses AES-256-GCM with a 64-character hex key loaded from
one safe file or credential. It is simple and fast, but Fluxheim must be able
to read the raw cache key at startup. Storage encryption supports bounded chunks,
but native ordinary proxy admission still receives a materialized response.
Do not interpret disk-only encryption as zero-buffering origin streaming.

`provider = "openbao-transit"` sends object bytes to OpenBao Transit
`encrypt` and `decrypt` endpoints and stores only the returned `vault:v...`
ciphertext in the cache backend. Use this when key custody, audit trails, and
centralized rotation matter more than the added call latency on disk-cache
reads and writes. Because the Transit API encrypts one complete plaintext value
per request, Fluxheim caps concurrent OpenBao encrypted commit heap usage and
can refuse a large cache fill under pressure rather than buffering too many
objects at once.

Both providers bind the configured `key_id` as authenticated data. The combined
cache key remains inside the encrypted object and is checked after decryption,
so a stored encrypted object cannot be silently moved to another cache key and
cache URLs are not exposed in envelope metadata. Encrypted filesystem names and
storage-bin index entries use HMAC-SHA-256 with a separate root-bound index key,
not an unkeyed digest, so offline readers cannot verify guessed URLs against
persisted lookup identities.

## Quick Start: Local Key

This is the simplest encrypted disk cache. It keeps the raw AES-256-GCM key on
the host as a root-owned secret and exposes it to Fluxheim through a
systemd/container credential.

The following is a vhost fragment for an existing server, not a complete TLS
setup. It proxies a public asset origin rather than using unsupported
disk-backed local-static caching. A complete loopback policy is available in
[cache-encryption-local.toml](../../examples/cache-encryption-local.toml).

```toml
[[vhosts]]
name = "assets"
hosts = ["assets.example.com"]

[vhosts.cache]
enabled = true
status_header = "x-cache-status"
image_extensions = ["webp", "png", "jpg", "jpeg"]
content_types = ["image/webp", "image/png", "image/jpeg"]
max_object_bytes = "32MiB"

[vhosts.cache.memory]
enabled = true
max_size_bytes = "512MiB"

[vhosts.cache.disk]
enabled = true
backend = "storage-bin"
path = "/var/cache/fluxheim/assets.example.com"
max_size_bytes = "20GiB"

[vhosts.cache.disk.encryption]
enabled = true
provider = "local"
algorithm = "aes-256-gcm"
key_id = "assets-cache-v1"
key_credential = "fluxheim-cache-key"

[vhosts.proxy]
upstreams = ["127.0.0.1:3000"]
upstream_tls = false
```

Generate the key once in an administrator/root shell. The no-clobber subshell
refuses an existing file; do not accidentally rotate a working key by rerunning
initial setup:

```bash
install -d -m 0700 -o root -g root /etc/fluxheim/secrets
(umask 077; set -C; fluxheim cache-keygen > /etc/fluxheim/secrets/fluxheim-cache-key)
```

For systemd:

```ini
[Service]
LoadCredential=fluxheim-cache-key:/etc/fluxheim/secrets/fluxheim-cache-key
```

For containers, mount the same value at:

```text
/run/secrets/fluxheim-cache-key
```

## Local Key Setup

Prefer credentials over paths so the same TOML works with systemd credentials,
Podman/Docker secrets, and Kubernetes secrets:

```toml
[cache.disk.encryption]
enabled = true
provider = "local"
algorithm = "aes-256-gcm"
key_id = "local-cache-v1"
key_credential = "fluxheim-cache-key"
```

Create the key once using the no-clobber instructions above. `cache-keygen`
prints a secret to stdout; do not run it into terminal recording, CI logs or a
public paste. It does not install the key or configure Fluxheim for you.

For systemd, expose it to Fluxheim with a drop-in:

```ini
[Service]
LoadCredential=fluxheim-cache-key:/etc/fluxheim/secrets/fluxheim-cache-key
```

Then run:

```bash
systemctl daemon-reload
systemctl restart fluxheim
```

For containers, mount the secret at `/run/secrets/fluxheim-cache-key`.

## Quick Start: OpenBao Transit

Use OpenBao Transit when the cache encryption key should stay outside the
Fluxheim host and when key operations should be auditable in a central service.
Fluxheim stores only Transit ciphertext such as `vault:v...` in the cache
backend.

```toml
[[vhosts]]
name = "repo"
hosts = ["repo.example.com"]

[vhosts.cache]
enabled = true
status_header = "x-cache-status"
content_types = ["application/octet-stream", "application/x-rpm"]
extensions = ["rpm", "bin"]
max_object_bytes = "256MiB"

[vhosts.cache.disk]
enabled = true
backend = "storage-bin"
path = "/var/cache/fluxheim/repo.example.com"
max_size_bytes = "200GiB"

[vhosts.cache.disk.encryption]
enabled = true
provider = "openbao-transit"
key_id = "repo-cache-openbao-v1"

[vhosts.cache.disk.encryption.openbao]
address = "https://openbao.internal.example"
mount = "transit"
key_name = "fluxheim-repo-cache"
token_credential = "openbao-token"

[vhosts.proxy]
upstreams = ["repo-backend:8080"]
upstream_tls = false
```

Create a minimal Transit policy:

```hcl
path "transit/encrypt/fluxheim-repo-cache" {
  capabilities = ["update"]
}

path "transit/decrypt/fluxheim-repo-cache" {
  capabilities = ["update"]
}
```

Then expose the OpenBao token as a systemd/container credential named
`openbao-token`.

## OpenBao Transit Setup

The OpenBao provider expects a Transit key and a token that can encrypt and
decrypt with that key:

```toml
[cache.disk.encryption]
enabled = true
provider = "openbao-transit"
key_id = "openbao-cache-v1"

[cache.disk.encryption.openbao]
address = "https://openbao.internal.example"
mount = "transit"
key_name = "fluxheim-cache"
token_credential = "openbao-token"
```

A minimal OpenBao policy for one cache key is:

```hcl
path "transit/encrypt/fluxheim-cache" {
  capabilities = ["update"]
}

path "transit/decrypt/fluxheim-cache" {
  capabilities = ["update"]
}
```

Fluxheim accepts HTTPS OpenBao URLs, plus loopback HTTP URLs for local testing.
Non-loopback plaintext HTTP OpenBao addresses are rejected.
Transit encrypt/decrypt calls do not follow HTTP redirects, and Transit JSON
responses are read through a bounded buffer before parsing so a compromised or
misconfigured OpenBao endpoint cannot stream unbounded response bodies into the
cache process.

## All Encryption Options

The `openbao` subtable holds Transit-specific options; it is not used by the
local provider.

Paths are config-relative unless absolute. A credential name resolves under
`CREDENTIALS_DIRECTORY` when set, otherwise `/run/secrets`. Mounting a Kubernetes
secret elsewhere does not automatically make it discoverable. On Windows use
an explicit service-readable `key_file`/`token_file` or deliberately set the
credential directory; do not assume the Unix credential directory exists.

| Field under `disk.encryption` | Default | Meaning |
| --- | --- | --- |
| `enabled` | `false` | Encrypt objects in an enabled disk tier |
| `provider` | `"local"` | `local` or `openbao-transit` |
| `algorithm` | `"aes-256-gcm"` | Local mode supports only AES-256-GCM; the parsed xchacha20-poly1305 name is rejected for enabled local encryption, not an implemented alternative |
| `key_id` | unset | Optional nonsecret authenticated label; native fallback label is `local`; set it explicitly for operational clarity |
| `key_file` | unset | Local provider: private file containing exactly 64 hexadecimal characters after trimming whitespace |
| `key_credential` | unset | Alternative local secret source by credential name; cannot coexist with key_file |
| `openbao.address` | unset | Required for Transit: HTTPS, or numeric-loopback HTTP; no credentials/query/fragment |
| `openbao.mount` | unset | Required Transit mount, e.g. `"transit"` |
| `openbao.key_name` | unset | Required pre-created Transit key, e.g. `"fluxheim-cache"` |
| `openbao.token_file` | unset | Private file holding a nonempty Transit token |
| `openbao.token_credential` | unset | Alternative Transit token source; cannot coexist with token_file |

Local key sources and OpenBao settings cannot be mixed. Transit chooses its
cryptographic algorithm through the OpenBao key, not the Fluxheim local
algorithm selector. Label fields are bounded to 128 safe ASCII characters and
reject traversal-like labels. Secret files are regular, bounded to 4096 bytes
and read through the platform's trusted-file path. Use restrictive permissions
and grant only the intended service access; a valid path does not grant access.

The Transit transport does not expose per-policy CA/mTLS/timeout configuration
in this table. Do not invent `ca_file`, `verify = false` or timeout fields.
FIPS/ISO-required configuration has additional restrictions, including local
numeric-loopback OpenBao transport; consult [FIPS guidance](fips.md) before
choosing that mode. An encrypted cache is not itself a compliance certification.

## Verifying Runtime Behavior

Enable a cache status header while validating a new policy:

```toml
[vhosts.cache]
status_header = "x-cache-status"
status_reason_header = "x-cache-reason"
```

Then request the same cacheable object twice:

```bash
curl -sD - -o /dev/null https://assets.example.com/logo.webp
curl -sD - -o /dev/null https://assets.example.com/logo.webp
```

Expected behavior:

- first request: `x-cache-status: MISS`
- second request: `x-cache-status: HIT`
- disk cache files or bin files should not contain the plaintext response body

With a memory tier enabled, the second request may only prove a memory hit.
For disk qualification, use disk-only storage or restart Fluxheim with the same
root/key and request again before freshness expires. Check exact body equality
as well as the header. A missing plaintext string is a smoke check, not a
cryptographic proof. Do not print decrypted production objects during diagnosis.

For a storage-bin cache, inspect the bin directory:

```bash
find /var/cache/fluxheim/assets.example.com -maxdepth 2 -type f -ls
```

For OpenBao Transit, persisted objects should contain `vault:v...` ciphertext
markers rather than plaintext response bodies.

## Rotation

For local-key encryption, changing the raw key should also change `key_id`.
Fluxheim detects the effective root-key change and cold-purges the encrypted
cache before accepting objects under the new key. Moving to a new
`cache.disk.path` remains useful for an explicit namespace cutover.

The local provider creates a persistent random root identity and derives
separate AES-256-GCM and HMAC index keys from the configured master key. This
makes the effective encryption key unique to each independently initialized
cache root even when operators reuse one master secret. Fluxheim durably
reserves each random-nonce object-encryption invocation in a locked counter,
warns as the effective root key approaches `2^32` invocations, and fails closed
at that bound. Preserve `.fluxheim-encryption-*`, `.fluxheim-gcm-*`, and
`.fluxheim-index-key-*` files with the cache root. Missing or damaged state on
an established root is never allowed to reuse an AES key with a reset counter:
missing active-key or counter state rejects disk-cache initialization, while a
missing root identity creates a new effective key and requires a cold purge.
That is an encryption boundary, not a guarantee that the server exits: native
router construction can currently continue without a failed disk tier
. Inspect errors and verify actual disk caching. See
[recovery and reload limitations](cache-recovery.md); do not repair this by
removing cryptographic state files.

The first `1.7.12` startup against an older encrypted root creates root-bound
state and cold-purges legacy objects and indexes. Envelope v1 objects are no
longer accepted. Never clone one initialized encrypted root into multiple live
replicas, and do not roll its hidden cryptographic state back from a snapshot.
A complete filesystem rollback cannot be detected using only state stored on
that filesystem. Use independent roots plus peer fill; use OpenBao or another
external key-management boundary when externally enforced rollback resistance
is required.

For OpenBao Transit, the usual rotation path is to keep the same Fluxheim
`key_id`, `mount`, and `key_name`, then rotate the Transit key inside OpenBao.
OpenBao can decrypt older `vault:v...` ciphertext while retaining the necessary
old key versions. If you change Fluxheim `key_id` or `key_name`, treat it as a
cache namespace cutover and purge or move the disk cache.

OpenBao-backed roots generate a random index-HMAC key once and persist only its
Transit-encrypted ciphertext. Preserve that state file with the active root;
the bearer token is not used as deterministic index-key material.

## Local Validation

Run the local-key storage-bin smoke without external services:

```bash
cargo build
scripts/smoke_cache_encryption_local.sh
```

Run the optional OpenBao Transit smoke with Podman:

```bash
cargo build
scripts/smoke_openbao_cache_encryption.sh
```

The OpenBao smoke starts a disposable OpenBao dev container, enables Transit,
creates a cache key, runs Fluxheim against a local origin, verifies `MISS`
followed by `HIT`, and checks that the cache object contains Transit
ciphertext rather than the plaintext response body.

## Operational Notes

- Keep cache encryption opt-in. It adds CPU work for local-key encryption and
  network/service dependency for OpenBao Transit.
- Prefer the local provider to avoid an external crypto round trip; neither
  native mode promises an unbuffered origin fill. OpenBao is a whole-object
  external crypto boundary and needs its own availability/capacity planning.
- Prefer `storage-bin` for high-churn encrypted caches that would otherwise
  create many small encrypted object files.
- Use memory plus encrypted disk when hot objects should remain fast but disk
  persistence must be protected.
- Treat `key_id` as cache-object authentication metadata. Changing it is a
  cache namespace cutover.
- Keep cache-status headers disabled in normal production responses unless
  they are needed for debugging.
