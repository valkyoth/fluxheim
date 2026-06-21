# Fluxheim 1.6.27 Release Notes

Fluxheim 1.6.27 continues the Pingora-exit work by moving route-level static
web serving onto the native HTTP/1 route adapter.

## Highlights

- Native HTTP/1 route static-web adapter backed by the `fluxheim-web` crate.
- Native static file responses support ETags, conditional requests, byte
  ranges, `HEAD`, cache-control metadata, and directory listings.
- The server crate now depends directly on `fluxheim-web` for pure web response
  planning instead of using the root compatibility adapter.
- Static-web route tests run through a real local native HTTP/1 listener.

## Security Notes

- Native static-web path resolution rejects decoded dot segments, NUL bytes,
  backslashes, denied dotfiles, and symlink escapes.
- Static response body reads re-check the rooted path and regular-file status
  before opening the file.
- Buffered native static responses are capped at 64 MiB until the final native
  streaming body path is completed.

## Compatibility

The remaining rich proxy integrations, including cache lookup/fill/stale
handling, PHP-FPM routing, auth-request, traffic mirror, compression, and
advanced load-balancer policy selection, remain on the compatibility path until
their native parity tests land.
