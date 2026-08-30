# Windows Filesystem Security Audit

Audit date: 2026-08-30

This record covers the Windows filesystem security boundary used by Fluxheim
1.8.2. It is a scoped source audit, not a claim that every public API in the
dependency is safe for arbitrary use.

## windows-permissions 0.2.4

- Registry source: crates.io
- Cargo.lock checksum:
  `9e2ccdc3c6bf4d4a094e031b63fadd08d8e42abd259940eb8aa5fdc09d4bf9be`
- Reviewed criterion: safe to deploy for the exact API graph used by Fluxheim

The review followed every production call from
`crates/fluxheim-config/src/fs_trust_windows.rs` through:

- `LocalBox` allocation ownership and `LocalFree` destruction;
- current-process token opening, bounded `GetTokenInformation`, SID copying,
  and handle closure;
- SDDL-to-descriptor and string-to-SID allocations;
- handle-based `GetSecurityInfo` and `SetSecurityInfo`;
- owner and DACL references whose lifetime remains bounded by the owning
  security descriptor;
- `GetAclInformation` ACE counts and `GetAce` bounds;
- ACE header, mask, flags, and SID extraction;
- SID equality; and
- the conditional `Send` and `Sync` implementations on `LocalBox<T>`.

The reviewed allocation APIs return memory documented for `LocalFree`; each
successful allocation is owned by one `LocalBox`. ACL and SID references point
inside the live descriptor allocation and are not retained. ACE indexes are
bounded by the count returned by `GetAclInformation`. Process token handles are
closed on success and non-resize error paths. `LocalBox<T>` only implements
`Send` or `Sync` when `T` does, and Windows serializes the process local heap.

Fluxheim does not use the dependency's name-based descriptor lookup in
production. Name-based `SetNamedSecurityInfo` is confined to Windows tests.
APIs outside this call graph are not approved by this review and must not be
introduced without extending this record.

## Fluxheim Windows capability helper

`crates/fluxheim-windows-security` is the only first-party crate permitted to
use unsafe Rust for handle-relative Windows path traversal. Its unsafe calls
are limited to `NtCreateFile`, NTSTATUS conversion, and transfer of a successful
owned handle into `std::fs::File`.

The helper validates relative components, rejects alternate data stream and
separator syntax, retains each parent handle, and combines
`OBJ_DONT_REPARSE`, `FILE_OPEN_REPARSE_POINT`, and explicit directory/file type
requirements. Returned handles are checked again for reparse attributes and
object type before exposure to safe crates.

Any expansion of this crate's unsafe API or any `windows-permissions` lockfile
change requires a new dated review and updated checksum evidence.
