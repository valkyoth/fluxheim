# ACME Accounts And Issuers

An ACME **account** identifies Fluxheim to a certificate authority (CA). Its
private key signs account and order requests. A site's **certificate key** is
different: that key identifies the HTTPS server to clients. Back up both kinds
of state privately; neither replaces the other.

Start with [ACME setup](acme.md) for a complete listener/vhost example. This
guide covers account choices and operations, not a second standalone server
configuration. All fields are listed in the [option reference](../reference/acme-options.md).

## Choose An Issuer Explicitly

An issuer combines a name, an HTTPS directory URL, an agreement and optional
registration credentials. Vhosts select an issuer by name; otherwise they use
`tls.acme.default_issuer`. A list of issuers is not an automatic failover chain.

For example, these are fragments to merge into the corresponding tables of a
complete configuration:

```toml
[tls.acme]
enabled = true
storage = "/var/lib/fluxheim/acme"
contact_email = "operations@example.test"
default_issuer = "lab-ca"

[[tls.acme.issuers]]
name = "lab-ca"
directory_url = "https://ca.example.test/acme/directory"
terms_of_service_agreed = false
# Set the exact reviewed HTTPS terms URL and acceptance before registration.
# terms_of_service_url = "https://ca.example.test/terms/v1"
# For a private CA, optionally supply its protected trust bundle:
# ca_bundle_file = "/etc/fluxheim/secrets/lab-ca.pem"

# Inside an existing [[vhosts]] entry:
[vhosts.tls.acme]
enabled = true
issuer = "lab-ca"
domains = ["site.example.test"]
```

The example domain and CA are placeholders. This deliberately does not accept
terms on your behalf or provide a usable public issuance target. Add the TLS
listener, vhost hosts/root and challenge configuration from the setup guide.
Do not paste duplicate TOML tables into an existing file.

An explicit `issuers` list replaces the built-in list. Include every issuer
referenced by your vhosts and default. Use separate names/state for staging and
production; staging certificates are not trusted by ordinary browsers.

Keep issuer names stable across upgrades. Storage uses a safe, hash-suffixed
segment of that name. Renaming it selects a different account location. Changing
the configured URL is not a supported account migration: stored credentials
contain their own account/directory identity and restoration uses that identity.
Do not rewrite account JSON or copy it between issuers. Plan a distinct issuer
and deliberate registration instead.

## Register And Retain The Account

There is no separate companion `account-create` command. Renewal loads an
existing account, or creates one when needed. Before a first issuance:

1. Choose the intended CA environment and configure all managed vhosts.
2. Review the issuer's terms, set the exact `terms_of_service_url`, then explicitly
   set `terms_of_service_agreed = true` if you accept them.
3. Mount persistent, private storage and any EAB sources for the service identity.
4. Run the checks below, then use the issuance workflow in the setup guide.

```bash
fluxheim-acme --config /etc/fluxheim/fluxheim.toml doctor
fluxheim-acme --config /etc/fluxheim/fluxheim.toml doctor --online
fluxheim-acme --config /etc/fluxheim/fluxheim.toml status
```

`doctor` can recover certificate transactions; it is not a read-only forensic
check. Its online mode checks issuer connectivity/agreement and can publish a
temporary HTTP-01 probe. It does not register an account or prove that a public
CA can reach your listener. `status` reports local certificate renewal state,
not remote account validity. Existing credentials being loadable is not proof
that the account is still active at the CA.

New registration checks the advertised terms against the configured URL. The
private-CA `allow_unadvertised_terms_of_service = true` exception permits missing
advertised terms only; it does not allow a mismatched advertised URL or implicit
acceptance. Existing accounts can be loaded without fresh registration acceptance
so incident operations are not blocked solely by that setting. Changing
`contact_email` is not an account contact-update command for an existing account.

Before registration contacts the CA, Fluxheim persists a protected pending key.
Recovery asks for the existing account with that same key, rather than assuming
a lost response means registration never happened. Do not delete pending records
to get past an error. The [storage/recovery guide](acme-recovery.md) explains the
locations and when to pause writers.

## External Account Binding

Some issuers require **EAB** to link the new ACME account to an account you already
have with them. The issuer supplies a key identifier and an encoded HMAC secret.
They are not the site private key, an account JSON file, or the contact email.

Add this table directly after the intended `[[tls.acme.issuers]]` entry:

```toml
[tls.acme.issuers.eab]
key_id_file = "/run/secrets/acme-eab-kid"
hmac_key_file = "/run/secrets/acme-eab-hmac-key"
```

The [Actalis template](../../examples/acme-actalis.toml) shows the surrounding
configuration. Do not put secret contents directly in TOML or command-line
arguments. Mount the files privately and read-only, with permissions acceptable
to the Fluxheim service identity. Replacing a secret with a world-readable file
is not a permission fix.

For an environment-based deployment, choose these instead of the file fields:

```toml
[tls.acme.issuers.eab]
key_id_env = "FLUXHEIM_LAB_EAB_KID"
hmac_key_env = "FLUXHEIM_LAB_EAB_HMAC_KEY"
```

The values above are variable names, not secrets. The service/container must
receive both variables through its protected deployment environment. Avoid
shell history, diagnostics or support bundles that expose their values.

For systemd-managed credentials, use credential names:

```toml
[tls.acme.issuers.eab]
key_id_credential = "lab-eab-kid"
hmac_key_credential = "lab-eab-hmac-key"
```

The service manager must supply those credentials. This is not a portable
Windows secret store. Choose exactly one source per value; do not leave file,
environment and credential alternatives enabled together. EAB is used for new
registration, not as a replacement for the persistent account signing key.

## Account Incident Commands

| Operation | Current behavior / limitation |
| --- | --- |
| `account-rollover --issuer NAME --confirm` | Fails before remote mutation; safe replacement-key journaling is not implemented |
| `account-deactivate --issuer NAME --confirm` | Destructive; **Current limitation:** makes success/error an unreliable indicator of CA state |
| `revoke --vhost NAME --confirm` | Certificate operation, not account deactivation; separate quarantine/reload limitations apply |

**Current limitation:** a loopback TLS outcome fixture proves that HTTP 503 from the
account endpoint can be accepted as success, deleting local credentials despite
the fixture not applying deactivation. Conversely, a truncated response after
applying deactivation causes credential rollback and ordinary local loading.
These are tests of the actual Fluxheim/client path, not evidence about a
particular public CA. the local follow-up must correct response validation and preserve
ambiguous outcomes before this workflow is reliable.

Until then, do not build automated incident closure around deactivation's exit
status or `status=ok` output. Pause renewal writers, preserve a private backup,
and use the issuer's authenticated account/support channel to establish remote
status. Do not delete pending records, create another account or reactivate a
backup blindly. Never assume deactivation revoked existing site certificates;
use the separate certificate incident process where required.

No companion command currently performs account contact updates, account import,
issuer migration or general pending-deactivation reconciliation. This is an
explicit functionality boundary, not a reason to hand-edit secret state.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Terms not accepted | Exact reviewed URL, explicit acceptance, and the selected issuer rather than an unused entry |
| EAB missing/invalid | Both sources available to the service identity, issuer-provided key format, and no competing sources |
| Pending bootstrap | Preserve the key and issuer binding; retry through supported registration recovery, not a new identity |
| Pending deactivation | Pause automation and determine remote outcome before any local recovery |
| Credentials load but orders fail | Local parsing is not remote account-status validation; check issuer response without publishing secrets |
| New account after deployment change | Compare issuer name, environment and persistent storage mounts with the previous deployment |

For failures involving already installed certificates, use
[storage and incident recovery](acme-recovery.md). Keep private keys, account
JSON and EAB values out of reports; names, bounded errors and public certificate
fingerprints are usually the appropriate starting evidence.
