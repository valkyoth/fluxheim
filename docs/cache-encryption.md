# Cache Encryption

Fluxheim can encrypt disk cache objects before they are written to the
filesystem or storage-bin backend. This is optional and disabled by default.
Use it when cache files may contain private or regulated response bodies and
the cache device must not expose plaintext while Fluxheim is stopped.

Cache encryption does not encrypt in-process memory cache contents, request or
response logs, upstream responses in transit, or files served directly by
`[vhosts.web]` before they enter an opt-in cache path. It is cache-at-rest
protection.

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

The same encryption layer applies to reverse-proxy cache responses and to
local/static cache responses when the selected cache policy has
`local_static = true`.

## Providers

`provider = "local"` uses AES-256-GCM with a 64-character hex key loaded from
one safe file or credential. It is simple and fast, but Fluxheim must be able
to read the raw cache key at startup.

`provider = "openbao-transit"` sends object bytes to OpenBao Transit
`encrypt` and `decrypt` endpoints and stores only the returned `vault:v...`
ciphertext in the cache backend. Use this when key custody, audit trails, and
centralized rotation matter more than the added call latency on disk-cache
reads and writes.

Both providers bind the configured `key_id` and the combined cache key as
authenticated data. A stored encrypted object cannot be silently moved to a
different cache key.

## Quick Start: Local Key

This is the simplest encrypted disk cache. It keeps the raw AES-256-GCM key on
the host as a root-owned secret and exposes it to Fluxheim through a
systemd/container credential.

```toml
[[vhosts]]
name = "assets"
hosts = ["assets.example.com"]

[vhosts.tls]
enabled = true

[vhosts.cache]
enabled = true
local_static = true
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
key_id = "assets-cache-2026-05"
key_credential = "fluxheim-cache-key"

[vhosts.web]
root = "/srv/sites/assets.example.com"
index_files = ["index.html"]
deny_dotfiles = true
```

Generate and install the key:

```bash
install -d -m 0700 -o root -g root /etc/fluxheim/secrets
fluxheim cache-keygen | install -m 0600 -o root -g root /dev/stdin /etc/fluxheim/secrets/fluxheim-cache-key
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

Create the key as a root-owned secret:

```bash
install -d -m 0700 -o root -g root /etc/fluxheim/secrets
fluxheim cache-keygen | install -m 0600 -o root -g root /dev/stdin /etc/fluxheim/secrets/fluxheim-cache-key
```

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
upstreams = ["repo_backend:8080"]
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

For a storage-bin cache, inspect the bin directory:

```bash
find /var/cache/fluxheim/assets.example.com -maxdepth 2 -type f -ls
```

For OpenBao Transit, persisted objects should contain `vault:v...` ciphertext
markers rather than plaintext response bodies.

## Rotation

For local-key encryption, changing the raw key should also change `key_id` and
either purge the disk cache or move to a new `cache.disk.path`. Existing cache
objects encrypted with the old local key are intentionally unreadable once
Fluxheim starts with only the new key.

For OpenBao Transit, the usual rotation path is to keep the same Fluxheim
`key_id`, `mount`, and `key_name`, then rotate the Transit key inside OpenBao.
OpenBao can decrypt older `vault:v...` ciphertext while retaining the necessary
old key versions. If you change Fluxheim `key_id` or `key_name`, treat it as a
cache namespace cutover and purge or move the disk cache.

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
- Prefer `storage-bin` for high-churn encrypted caches that would otherwise
  create many small encrypted object files.
- Use memory plus encrypted disk when hot objects should remain fast but disk
  persistence must be protected.
- Treat `key_id` as cache-object authentication metadata. Changing it is a
  cache namespace cutover.
- Keep cache-status headers disabled in normal production responses unless
  they are needed for debugging.
