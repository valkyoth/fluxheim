# Fluxheim 1.6.24 Release Notes

Fluxheim 1.6.24 finishes the native HTTP/2 downstream parity proof for the
Pingora-exit line. The representative native runtime cutover report is now
blocker-free for the simple HTTP/1 + HTTP/2 + admin + metrics + stream + UDP
configuration, while the remaining Pingora runtime/listener adapter crates stay
targeted for a focused `1.6.25` deletion release.

## Changed

- Promote the native HTTP/2 downstream preview to cutover-ready after every
  required safety hook is represented and tested.
- Update the native runtime cutover evidence script so the representative
  config expects no blockers.
- Move remaining Pingora dependency exceptions to `1.6.25`, keeping the gate
  active while avoiding a rushed mixed release that both changes HTTP/2 parity
  status and deletes the final compatibility crates.
- Update release metadata, RPM metadata, and container tag documentation for
  `v1.6.24`.

## Security

- Keep decoded HTTP/2 header-count enforcement before routing and document the
  paired decoded header-list byte bound from `h2` `max_header_list_size`.
- Join aborted native stream and UDP listener tasks during shutdown, closing
  the short file-descriptor release window after an operator-triggered stop.
- Add an explicit zero-blocker assertion to the native runtime cutover evidence
  script for the representative config.
- Preserve native HTTP/2 tests for oversized URI rejection, oversized request
  bodies, decoded header count, request trailers, response trailers, prohibited
  HTTP/2 response headers, request flow-control release, response flow-control
  hold timeout, slow request-body timeout, and handler timeout.
- Keep the Pingora dependency policy enforceable: all remaining normal-profile
  Pingora crates must be deleted by the next dependency-removal checkpoint.

## Compatibility Boundary

- Normal proxy profiles still compile the Pingora compatibility runtime in this
  release. The change in `1.6.24` is the HTTP/2 parity proof and blocker-report
  cleanup, not the final dependency deletion.
