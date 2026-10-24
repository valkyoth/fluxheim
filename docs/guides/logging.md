# Logging And File Lifecycle

Applies to unreleased 1.9.0. This guide describes implemented ordinary logging,
not future access-log completion hooks, correlation or remote log exporters.
See the [configuration reference](../reference/config-reference.md),
[structured event contract](../architecture/structured-events.md) and
[logging architecture](../architecture/logging-architecture.md).

## Select An Output

The default is stderr. For container or service-manager collection, use the
existing stdout/stderr target without an internal file:

```toml
[logging]
level = "info"
format = "json"
target = "stderr" # or "stdout"
```

To write ordinary records to a dedicated file instead, add:

```toml
[logging.file]
enabled = true
path = "/var/log/fluxheim/events.log"
append = true
```

Create the parent directory first, owned by the service identity or root, with
no untrusted write access. A Unix deployment can use mode 0700 or an appropriate
0750 directory and a 0600 file. Newly created files use 0600. Existing files
must be private regular files with no group/other permission bits: 0640 and 0644
are rejected, not just writable modes such as 0666. Symlink components are
rejected. Do not use a shared writable log directory to bypass these checks.
On Windows, use a local absolute path such as `C:/Fluxheim/logs/events.log` and
the same trusted-owner/ACL rules as other Fluxheim state files. Reparse points
and untrusted ACLs fail closed; creation installs the protected confidential ACL.
Existing files and replacements must also satisfy the confidential-file ACL
policy: read access for untrusted principals is rejected, including Everyone
and Guests. Fluxheim does not silently change existing files' permissions.

Each process needs its own log file. Unix uses append mode; Windows seeks to EOF
under the shared sink lock. Neither policy promises safe concurrent rotation
or record ordering across different processes. Do not point overlapping upgrade
processes at the same file; prefer service-manager collection in that workflow.

`append = false` truncates only during startup, after validating the opened file
and checking that it is not the crash sink. Reopen always appends, including to
a pre-existing replacement. Logging configuration changes require restart;
configuration snapshot reload is not a log-reopen command.

Privacy-mode builds prohibit file logging. This change does not relax their
configuration policy or introduce additional diagnostic fields.

## Rotate By Renaming

Rename `events.log` to an archive name in the same trusted directory. Fluxheim
checks the configured path at most once per second, on the next record processed
by any logging worker. It opens or creates a safe replacement and atomically
switches the shared handle. No signal or admin command is required. An idle
server has no timer that opens files; there must be a record to trigger the check.

All four workers (legacy, ordinary, security and audit) share the handle. Each
whole encoded record is written under one lock, including short OS writes.
Rotation cannot split a record across handles. Within a lane, queue order is
preserved; ordering between lanes is unspecified. Records already queued before
rotation can go to the replacement. Records processed before the next check can
still go to the renamed file. Wait for the reopen counter before compressing or
removing the old file. Archive naming, compression and retention are external
operator responsibilities; Fluxheim does not manage them.

On Unix, deletion causes safe recreation at the next check. Until then records
can still go to an unlinked/open old file and become inaccessible. Windows
[DeleteFile](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-deletefilew)
can keep deletion pending until the last handle closes, preventing reopen.
In that case Fluxheim retains its trusted handle and increments `reopen_errors`;
restart to release the pending deletion and recreate the file. Use rename, not
delete, for Windows rotation. If removal unlinks the name immediately and a
replacement can be safely opened, recreation proceeds normally. Do not assume
that every Windows removal leaves a pending delete. Truncation of the same
file resumes at its new EOF, without an offset-sized hole. Copy-and-truncate has
an unavoidable race with the external copier and is not a lossless policy.
Prefer rename and retain the old file until the reopen succeeds.

## Failures And Recovery

- **Replacement cannot be opened or trusted:** keep writing to the previous
  trusted handle; increment `reopen_errors`. Try again on a subsequent worker
  record after one second. This includes directory/symlink replacements,
  crash-file aliases, ACL failures and Windows sharing conflicts. It does not
  redirect to stdout/stderr. Fix the path or permissions to recover.
- **Rotation tool creates a readable file:** configure it to create mode 0600
  (or a confidential Windows ACL), or let Fluxheim create the replacement.
  A 0644/0640 replacement is rejected and the old private handle is retained.
- **Opened file loses trust or writing fails:** latch the shared sink as failed.
  This includes ENOSPC, confidentiality loss (even 0600 to 0644/0640) and partial
  writes followed by error. The opened handle is checked before each record,
  independently of the one-second reopen interval.
  No record is retried, replayed, or redirected to another sink. A partial final
  record may remain. Freeing space or restoring permissions does not clear the
  latch: inspect the log, correct the cause and restart Fluxheim.
- **Worker behavior:** existing bounded queues and loss counters still apply.
  A lane encountering the failed sink stops; other lanes discover failure on
  their next write. Do not treat an idle lane's worker flag as sink health.
  Normal HTTP service remains independent of log I/O. Admin mutations continue
  to depend on the existing audit-admission rules, not durable sink completion.
- **Shutdown:** stop admissions and perform the existing bounded drain. File
  handles close after the final worker releases them; status counters alone do
  not retain them. An OS write that never returns cannot be cancelled by this
  mutex. Shutdown may abandon a blocked worker until process exit; it must not
  block the main shutdown path indefinitely.

The fatal sink (`logging.crash_file`, or stderr when unset) is separate and
restart-only. Ordinary rotation never reopens it or uses it as a fallback.
Crash hard-link aliases are rejected before truncation and during reopen.

## Observe The Sink

An already-enabled, authenticated `/_fluxheim/status` response contains
`legacy_logging.file_sink` (null for stdout/stderr). No listener or public
diagnostic header is enabled by this feature.

| Field | Meaning |
| --- | --- |
| `check_interval_ms` | Minimum interval between worker-triggered checks: 1000 |
| `checks` | Reopen checks attempted, including unchanged safe files |
| `reopens` | Successful switches to a different file identity |
| `reopen_errors` | Failed candidate checks; the old handle is retained |
| `write_errors` | First failing sink write, including trust-check failure |
| `failed` | Shared terminal failure; restart required |
| `handle_open` | A worker still retains the shared sink |

Counters saturate and are read without taking the writer lock. The snapshot
is not a transaction across counters. No paths, raw OS errors or record contents
are exposed. Use the existing per-lane counters to inspect admission losses.

## Assurance Boundary

This is bounded best-effort logging, not a durable journal: no per-record fsync,
integrity chain, replay spool or external acknowledgement is added. An audit
mutation may finish before its queued outcome reaches the sink. A crash, disk
failure or saturation can lose records. Same-identity/root attackers remain
outside the filesystem trust boundary; directory checks are not protection from
a compromised privileged administrator. See the
[qualification record](../evidence/observability-05.md) for tests and platform gaps.
