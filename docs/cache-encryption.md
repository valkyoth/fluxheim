# Cache Encryption

Fluxheim can encrypt disk cache objects before they are written to the
filesystem or storage-bin backend. This is optional and disabled by default.
Use it when cache files may contain private or regulated response bodies and
the cache device must not expose plaintext while Fluxheim is stopped.

Cache encryption does not encrypt in-process memory cache contents, request or
response logs, upstream responses in transit, or files served directly by
`[vhosts.web]` before they enter an opt-in cache path. It is cache-at-rest
protection.

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
python3 - <<'PY' | install -m 0600 -o root -g root /dev/stdin /etc/fluxheim/secrets/fluxheim-cache-key
import secrets
print(secrets.token_hex(32))
PY
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
