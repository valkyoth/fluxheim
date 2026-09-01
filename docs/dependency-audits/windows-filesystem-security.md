# Windows Filesystem Security Audit

Audit date: 2026-09-01

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

The trusted owner set includes the fixed Windows Modules Installer
(`TrustedInstaller`) service SID
`S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464`. This is a
well-known service identity defined by Windows, not a deployment-specific
account. Any change to that value requires a fresh ACL-policy review.

## Fluxheim Windows capability helper

`crates/fluxheim-windows-security` is the only first-party crate permitted to
use unsafe Rust for handle-relative Windows path traversal and mutation. The
reviewed source digest is
`de216c1b695ed735b2bae3ac196e85f639cac228a1beb423d045aa1f96b3eb9a`.
It covers, in this order, each UTF-8 path, a NUL delimiter, the complete file,
and another NUL delimiter for:

- `crates/fluxheim-windows-security/src/lib.rs`;
- `crates/fluxheim-windows-security/src/file_mutation.rs`; and
- `crates/fluxheim-windows-security/src/path_handles.rs`.

First-party unsafe operations and their reviewed invariants are:

- `NtCreateFile` receives live, aligned `OBJECT_ATTRIBUTES`, `UNICODE_STRING`,
  and status storage; every relative open is rooted in a live parent handle,
  disables reparse traversal, and requests an explicit object type;
- successful native handles are transferred exactly once into
  `std::fs::File`, while failed calls never construct an owning Rust handle;
- `RtlNtStatusToDosError` is called only with the status returned by the
  immediately preceding native operation;
- `NtSetInformationFile` receives live source and destination-directory
  handles plus bounded, aligned rename or hard-link structures whose UTF-16
  payload lengths are checked before allocation and raw writes;
- `SetFileInformationByHandle` receives a live file handle opened with delete
  access and an exact `FILE_DISPOSITION_INFO` value;
- `CreateDirectoryW` receives a NUL-terminated path and a live protected
  security descriptor through a correctly sized `SECURITY_ATTRIBUTES`; and
- raw writes into variable-length rename and link structures stay within the
  checked allocation and use the Windows-declared field layout.

The helper validates relative components, rejects alternate data stream and
separator syntax, retains each parent handle, and combines
`OBJ_DONT_REPARSE`, `FILE_OPEN_REPARSE_POINT`, and explicit directory/file type
requirements. Returned handles are checked again for reparse attributes and
object type before exposure to safe crates.

The configuration trust checker consumes the retained handle chain directly:
it evaluates the target, creation parent, and ancestors without reopening
their names between inspection and use.

The reviewed public surface comprises regular-file open/create/update,
handle-relative traversal, retained path inspection, exclusive confidential
creation, directory ACL-update and synchronization opens, private-directory
creation, regular-file rename/hard-link/removal, handle-based removal, and the
`RetainedPathHandles` target/ancestor accessors. New ordinary-file creation
handles include delete access because callers may reject and remove a file
after evaluating its retained parent ACLs.

Any expansion of this crate's unsafe API or any `windows-permissions` lockfile
change requires a new dated review and updated checksum evidence. The normal
validator hashes the complete first-party boundary, so any source change also
requires an explicit review-date and digest update.
