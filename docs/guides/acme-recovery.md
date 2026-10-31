# ACME Storage, Recovery And Incident Operations

Use [ACME setup](acme.md) for first deployment and the
[option reference](../reference/acme-options.md) for configuration. This guide
explains what to preserve, what the recovery code can do, and when to stop for
operator investigation. A command failure does not necessarily mean that the
CA or the local filesystem remained unchanged.

## Know The Three States

Keep these separate when diagnosing a certificate incident:

1. **CA state:** whether an account/order/certificate was created, deactivated
   or revoked remotely. Losing a response does not undo a request.
2. **Disk state:** the managed certificate/key pair, account credentials,
   temporary challenges, backups and transaction journals.
3. **Serving state:** certificate objects already loaded by the gateway. Changing
   files does not remove those objects from memory or terminate existing TLS
   connections. Verify activation using a new connection with the intended SNI.

`status` is a local renewal report, not a CA revocation lookup or a test of the
certificate served publicly. `doctor` can change disk state through recovery;
it is not a forensic read-only command.

## Preserve Persistent State

`tls.acme.storage` contains both long-lived secrets and temporary material:

| Location under storage | Purpose | Handling |
| --- | --- | --- |
| `accounts/<issuer-segment>/credentials.json` | Account identity and private key | Private persistent secret; retain across upgrades |
| `accounts/<issuer-segment>/.credentials.bootstrap.pending` | Recoverable registration key and issuer binding | Do not delete to force a new registration |
| `accounts/<issuer-segment>/.credentials.deactivation.pending` | Quarantined credentials during deactivation | Ambiguous state requires investigation |
| `certificates/<vhost-segment>/fullchain.pem` and `privkey.pem` | Installed site certificate/key | Treat as one coherent pair |
| `.install.transaction` and `.revocation.transaction` in a certificate directory | Install/revocation phase records | Preserve with their referenced files; never hand-edit phases |
| `.fullchain.pem.previous`, `.privkey.pem.previous`, `.revoked-<transaction>-...` files | Recovery/incident material | Not arbitrary cache; private-key material remains sensitive |
| `http-01/<vhost-segment>/` | HTTP-01 token responses | Temporary, but deletion can invalidate an active order |
| `tls-alpn-01/<domain-segment>/` | Challenge certificate/key pairs | Not the site's normal TLS identity; native serving integration is currently incomplete |

Segments are generated and hash-suffixed by Fluxheim. Do not construct them by
concatenating an untrusted domain or rename them after changing a vhost/issuer
name. Use the paths reported by the installed tooling and preserve their layout.

For backups, first stop renewal writers and other certificate/account mutations.
Stop or isolate the gateway too if you cannot establish that the whole state is
quiescent. Back up the complete protected state, configuration and required EAB
sources with restrictive permissions and encrypted storage. A copy made halfway
through a two-file transaction is not automatically a consistent backup.

Do not back up only `fullchain.pem`, mix a private key from another generation,
or restore old credentials after a confirmed account deactivation. Filesystem
backup does not reverse a CA-side mutation. Keep backup access restricted just
like live access; deleting files is not guaranteed physical erasure on SSD/COW
storage. Restore drills belong on isolated state, not the serving directory.

## Pause Before Recovery

For a deployment controlled by an external scheduler, stop that timer/job and
ensure the gateway uses:

```toml
[tls.acme]
# Keep storage, contact and issuer configuration unchanged.
automation = "external"
```

Replace the field in the existing table. Apply the change through the supported
service lifecycle; merely editing a file does not change the running process.
Do not rely on `renew_after` as a hold until the documented limitation is fixed. Monitor expiry
while paused. The companion's incident-target gate currently also rejects
`renewal.enabled = false`, so disabling that flag is not equivalent
to pausing just the scheduler. Do not turn it back on under an active background
worker simply to make an incident command accept the target.

Before a recovery attempt, preserve a restricted backup, the error and the
affected target/issuer names. Do not include account JSON, private keys or EAB
values in a support report. Run tooling as the same service identity with the
same protected mounts/configuration, rather than making state world-readable.

## Install Recovery

Fluxheim validates issued material before publication: parsing, current leaf
validity, server-auth use, requested DNS names and private-key match. Installation
uses temporary files, backups, a journal and a per-target lock. This is a
transactional two-file operation, not one filesystem rename covering both files.
Cooperating TLS readers take a shared lock when loading the pair; the journal
supports recovery after an interrupted writer.

| Install journal phase | Current recovery action |
| --- | --- |
| `prepared` | Active files have not entered publication; remove transaction temporary/backup material |
| `publishing` | Restore the old files where they existed; remove newly introduced active slots otherwise |
| `published` | Keep the newly published pair and finish temporary/backup cleanup |

Recovery runs before another install and through `doctor` for renewal targets:

```bash
fluxheim-acme --config /etc/fluxheim/fluxheim.toml doctor
fluxheim-acme --config /etc/fluxheim/fluxheim.toml status --vhost site.example.test
```

**Current limitation:** recovery itself is not restart-idempotent during `publishing`.
Restoring a backup consumes its name, but the journal does not record that
progress. An interruption after the first restore leaves an old certificate
and new key; another recovery attempt fails because the certificate backup is
missing, even though the old key backup remains. Interruption after both restores
can also block cleanup despite the active pair being restored. Local tests
exercise both boundaries. Do not repeatedly delete journals or rename backups
until the error disappears: preserve state and obtain a verified recovery plan.

An install can also publish the new pair and then report a cleanup error.
Therefore “command failed” does not universally mean “old files are still
active.” Inspect the phase and coherent pair, then the served identity. If disk
state is incomplete/ambiguous, keep the affected listener isolated until repaired.

## Challenge Cleanup

Normal completed renewal paths attempt to remove published challenges. Two
important limits remain under **Current limitation:**

- Cleanup is after the awaited operation. Dropping/cancelling that future or
  the outer renewal timeout can skip it; there is no cancellation-owned cleanup
  guard in that path. This is source-confirmed; a local-CA cancellation test is
  still required for the correction.
- Each cleanup list stops on its first error. Tests prove that an unsafe first
  HTTP token or TLS challenge path leaves later valid challenges untouched.
  TLS pair removal can delete the certificate before failing on the key path.

The async renewal timeout is not a guarantee that synchronous filesystem work
or lock acquisition can always be preempted. A failed or interrupted order
must not be assumed to have left an empty challenge store. Conversely, a leftover
challenge is not proof that the CA issued a certificate or that someone can
obtain one without the matching order/account authorization.

Do not use a recursive cleanup command against live storage. First stop the
responsible writer, identify the exact failed order's artifacts, and preserve
evidence. Do not remove another order's challenge or follow links placed in an
unexpected path. There is no documented general-purpose “sweep all leftovers”
command. Cleanup ownership, restart reconciliation and bounded retention are
part of the planned correction.

## Revocation

Revocation tells the issuer to invalidate the installed certificate. It is not
renewal and does not automatically create a replacement. Only run this command
after choosing the affected identity and planning traffic isolation/replacement:

```bash
fluxheim-acme --config /etc/fluxheim/fluxheim.toml revoke --vhost site.example.test --confirm
```

The engine quarantines the pair under the certificate mutation lock, reads the
quarantined certificate and journals the remote-operation phase:

| Revocation phase | Recovery behavior |
| --- | --- |
| `prepared` / `pair-quarantined` | Remote contact has not started; restore the pair |
| `remote-pending` | Remote outcome may be ambiguous; retain quarantine and fail closed on disk |
| `remote-confirmed` | Retain quarantine for review; permit replacement issuance after transaction cleanup |

The library can select managed incident targets even when renewal is disabled.
**Current limitation:** the companion currently applies a renewal-only target check
first and rejects that situation. Its test confirms the mismatch without making
a remote request. It needs a separate incident-target guard, not weaker general
configuration or path validation.

After successful remote revocation, the companion requests the Unix reload
socket. On failure or an ambiguous remote result, do not assume the running
server stopped presenting the old in-memory certificate. Stop/isolate the
listener and investigate. The external Windows path cannot use that Unix socket;
do not interpret a command's reload error as proof that remote revocation did
not happen. Never blindly repeat a destructive command just because it failed.

There is no safe general command to resolve `remote-pending` by removing its
journal. Establish the issuer's outcome and intended replacement first. Preserve
quarantined keys privately; do not put their contents in logs or issue reports.

## Account Lifecycle

Registration records a pending key before remote creation. A retry can recover
the same key/account rather than silently creating another identity. A matching
pending record left beside active credentials can be reconciled; mismatched
issuer/key state fails closed. Do not manually copy credentials between issuer
directories to bypass that check.

`account-rollover --issuer NAME --confirm` currently fails before remote mutation
because safe pre-journaling of the replacement account key is unavailable.
It is not a working rotation command despite being listed in CLI help.

Account deactivation is destructive and requires explicit confirmation:

```bash
fluxheim-acme --config /etc/fluxheim/fluxheim.toml account-deactivate --issuer letsencrypt --confirm
```

**Current limitation:**
It first moves credentials to pending state under a lock, but the current client
does not validate the deactivation response status before reporting success.
A local TLS fixture returned HTTP 503 without applying deactivation: the
operation nevertheless succeeded locally and deleted both active and pending
credentials. A successful exit is therefore not proof of CA confirmation.

The opposite mismatch is also reproduced: the fixture applied deactivation,
then truncated the response. Fluxheim returned an error, restored the active
credentials and allowed ordinary credential loading again. This does not mean
the CA reactivated the account. Outer timeout/interruption can instead leave
pending state blocking ordinary access; these outcomes are not interchangeable.

Pause automation and preserve a private backup before any account incident
operation. Establish account status through the issuer's authenticated support
or account-management channel. Do not retry blindly, remove pending records or
copy a backup into active use just because the command failed. Deactivating an
account is not a substitute for certificate revocation. See
[accounts and issuers](acme-accounts.md) for the normal registration workflow
and the planned outcome-handling correction.

## Verify Recovery Separately From Activation

After a verified repair, check storage and local target status, load the pair
through the supported server lifecycle, and inspect a new HTTPS connection from
outside the deployment. On Unix the companion reload command is:

```bash
fluxheim-acme --config /etc/fluxheim/fluxheim.toml reload
```

The reply byte cap is not a client-side timeout: the current socket client can
wait for EOF without a read deadline. A local Unix socket test confirms that
even a received `ok` line does not finish the call until the peer closes; it
also checks a silent peer. The bounded test releases each peer after observation,
not after a built-in client timeout. Bound maintenance jobs using your
supervisor and treat a timeout as an unknown activation outcome. The reload
correction plan includes this transport issue. Never turn a timeout into a claim
that an earlier install/revoke did not happen.

Record the target, public certificate fingerprint/expiry, CA-side outcome,
recovery result and independently observed serving result. Keep secrets out of
that record. The [coverage ledger](../reference/documentation-coverage.md)
states which failure paths have local tests and which still need real-CA/native
qualification; none of the documented defects is fixed merely by this guide.
