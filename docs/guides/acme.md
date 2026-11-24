# Automatic Certificates With ACME

ACME lets a certificate authority (CA) verify that you control a domain and
issue its TLS certificate. Fluxheim can obtain, store and renew that certificate,
then load it for new HTTPS connections. It does not create DNS records or open
your firewall. You still own those parts of deployment.

This guide describes the current implementation, including known scheduling
limitations. See the [complete ACME options](../reference/acme-options.md) for
defaults, [recovery and incident operations](acme-recovery.md), and the
[certificate lifecycle guide](certificate-renewal.md) for deeper details. Configuration
examples are templates: replace domains, paths, contact and issuer agreement.
They do not authorize accepting a CA's terms on your behalf.

## Choose A Workflow

| Workflow | Configuration | Who runs renewal? |
| --- | --- | --- |
| One serving process | `automation = "background"` | Fluxheim checks certificates, then sleeps for `check_interval_secs` after each tick |
| Timer or separate renewal container | `automation = "external"` | Your scheduler runs `fluxheim-acme renew`; the server still serves challenges |
| Certificates supplied by another tool | Static `[vhosts.tls.certificate]` paths | That tool; do not enable managed ACME for the same certificate |

Use a build with `acme-client` for issuance. The companion validates the ACME
parts of the same server configuration without requiring unrelated cache/PHP
features or a PHP executable. Starting the webserver still requires full server
validation. Do not switch to a full image just to renew a PHP site's certificate.

Choose one renewal owner per deployment. Sharing state does not make two
independent schedulers a coordinated fleet. Keep the server and companion on
the same protected storage and compatible configuration; do not independently
copy only the certificate file while dropping its private key or account state.

## First HTTP-01 Deployment

Start with [the HTTP-01 template](../../examples/acme-http-01.toml). It explicitly
listens on loopback HTTP 8080 and HTTPS 8443. Those are application ports, not a
promise of public reachability. A container deployment would normally bind
inside the container on its interfaces and publish public TCP 80 to 8080 and
TCP 443 to 8443. A loopback-only listener inside a container cannot receive that
published traffic. On a host, configure the desired public listen addresses
and arrange port forwarding or privileged-port binding separately.

1. Point every requested public domain at the gateway. Make any advertised
   IPv6 path work as well as IPv4. Use real domains you control, not `.test`.
2. Create a private persistent ACME directory accessible to the service user.
   On Unix use mode `0700`; private keys and EAB secret files need `0600`.
   On Windows use the documented private ACL policy, not Unix mode commands.
3. Set the contact email, storage, vhost hosts and certificate domains. `hosts`
   selects requests; `domains` selects names on the certificate. Adding a name
   to a certificate alone does not configure HTTP routing for that name.
4. Begin with a staging CA. Define an explicit issuer entry and review its
   advertised HTTPS terms URL. Only then set agreement to true. An explicit
   issuer array replaces the built-in list, so include every issuer you use.
5. Validate the configuration and storage as the service user, then run the
   server. Ensure public HTTP port 80 reaches its challenge handler.
6. After issuance, verify HTTPS from outside the deployment, including SNI and
   the returned chain. Staging certificates are not publicly trusted. Change to
   your intended production issuer only after testing and reviewing its terms.

The template intentionally leaves agreement false:

```toml
[[tls.acme.issuers]]
name = "letsencrypt-staging"
directory_url = "https://acme-staging-v02.api.letsencrypt.org/directory"
terms_of_service_agreed = false
# After reviewing the CA's exact advertised URL:
# terms_of_service_url = "https://..."
# Change terms_of_service_agreed above to true; do not duplicate the key.
```

These commands check local configuration/state, not public validation:

```bash
fluxheim --config /etc/fluxheim/fluxheim.toml --check-tls-storage
fluxheim-acme --config /etc/fluxheim/fluxheim.toml targets
fluxheim-acme --config /etc/fluxheim/fluxheim.toml status
fluxheim-acme --config /etc/fluxheim/fluxheim.toml doctor
```

`doctor` is offline by default but is **not read-only**: it creates storage and
recovers managed certificate transactions. With `doctor --online`, HTTP-01
also writes a temporary probe and requests the domain's HTTP port 80. The
TLS-ALPN-01 doctor check is only TCP reachability to port 443, not proof that a
CA can complete an ALPN challenge. Neither doctor mode replaces real issuance.

Managed certificates can initially be missing. The server may start with that
SNI pending; HTTPS then uses an available fallback or fails until issuance and
reload. This exception does not allow missing operator-provided static keys.

## Challenge Selection

HTTP-01 serves token files beneath `/.well-known/acme-challenge/`. Keep that
path reachable by the CA even when the rest of the site redirects to HTTPS.
Fluxheim's managed challenge handling has its own route; an external HTTP-01
forwarder takes precedence if you enable one on the same vhost.

**the documented limitation: native TLS-ALPN-01 serving is incomplete. Use HTTP-01 for
managed issuance today.** The accepted configuration below is not a working
alternative merely because it validates:

```toml
[tls.acme]
# Keep the other settings from the base template.
challenge = "tls-alpn-01"
```

This is a replacement field in the existing table, not a second table to paste
at the bottom. It requires rustls and a TLS listener. However, the native listener
does not attach the challenge-capable resolver/store: with the root application's
ACME/TLS features it negotiates `acme-tls/1` but serves an ordinary fallback
certificate, even when challenge files exist and after certificate reload. The
loopback handshake characterization checks that mismatch. The certificate-generation
and resolver primitives exist; their production integration does not.

The correction must prove actual CA validation, in-process and external
publication/removal, correct SNI and strict ALPN selection. Public port 443 and a
TLS path that preserves `acme-tls/1` remain prerequisites, not a fix for the missing
integration. DNS-01 and wildcard certificate issuance are not supported.

To forward HTTP-01 to a different ACME agent instead of Fluxheim's token store:

```toml
[vhosts.acme_challenge]
enabled = true
upstream = "127.0.0.1:8090"
connect_timeout_secs = 5
read_timeout_secs = 10
send_timeout_secs = 10
```

That agent must actually serve the challenge path. This does not run the agent,
register an account, copy its certificate or reload Fluxheim for it. Prefer a
single challenge owner. See the option reference for multiple upstreams/TLS.

## Issuers And External Account Binding

The built-in names are `letsencrypt`, `letsencrypt-staging`, `actalis`,
`google-trust-services` and `google-trust-services-staging`. These are configured
directory mappings, not guarantees of current CA availability or eligibility.
Custom issuers require a unique name and HTTPS directory URL. Use a private
`ca_bundle_file` trust configuration for an internal test CA; do not disable
server verification to make a staging endpoint work.

Some issuers require External Account Binding (EAB). This binds a new ACME
account to credentials from that issuer. The [Actalis template](../../examples/acme-actalis.toml)
uses systemd credentials. Containers can instead mount two read-only secret
files and replace its EAB table with:

```toml
[tls.acme.issuers.eab]
key_id_file = "/run/secrets/actalis-eab-kid"
hmac_key_file = "/run/secrets/actalis-eab-hmac-key"
```

Environment and systemd-credential alternatives, constraints and defaults are
listed in the reference. Select exactly one source for each value. Never put
the HMAC secret into a command argument, checked-in TOML, diagnostic output or
this documentation. Protect secret parents as well as the files themselves.

## Renewal, Holds And Reload

`fluxheim-acme status` shows the local plan and observed expiry, not a live CA
decision. Choose the policy under `[tls.acme.renewal]`:

| Goal | Settings | What happens |
| --- | --- | --- |
| Normal renewal (default) | `enabled = true`, no `renew_after` | Use the local schedule and issuer renewal information (ARI). |
| Delay routine renewals | Future `renew_after`, `hold_mode = "elective"` (default) | Missing certificates, expiry within seven days (inclusive), or a due issuer-advised renewal can override the date. |
| Freeze automatic issuance | Future `renew_after`, `hold_mode = "absolute"` | No unforced order or ARI lookup until the deadline. Explicit force still works. A missing certificate can stay missing. |
| Turn renewal off | `enabled = false` | No background or CLI renewal targets, even with force. Existing certificates stay installed. Re-enable explicitly; no date re-enables renewal. |

For example, to freeze automatic issuance until a maintenance window:

```toml
[tls.acme.renewal]
hold_mode = "absolute"
renew_after = 2027-01-01T02:00:00+02:00
```

Before midnight UTC on January 1 in this example, background and CLI due runs
skip even missing and expired certificates, without contacting the CA. Neither
issuer renewal information (ARI) nor the emergency window overrides the hold.
At the deadline normal scheduling resumes; it does not force a fresh certificate
to renew. Only an explicit forced renewal bypasses the hold. Choose the deadline
carefully: a held site can remain without a usable certificate.

To delay only routine work, change the example to `hold_mode = "elective"`.
If upgrading from a development build that treated every date as an absolute
freeze, set `hold_mode = "absolute"` explicitly to preserve that behavior.
To switch off both scheduled and forced renewals, use:

```toml
[tls.acme.renewal]
enabled = false
```

With renewal off, run `fluxheim-acme --config /etc/fluxheim/fluxheim.toml status`
to check the installed leaf certificate for every managed vhost. Add
`--vhost NAME` after `status` to check just one. This is a local read:
it does not create storage, read the private key, contact the CA or renew.
For example, `target: shop status=missing renewal=off not_after=missing`
means the vhost is managed but no certificate is installed.

The exit status is nonzero if a selected leaf is missing, invalid, unreadable,
not yet valid, expired, or expires within seven days (inclusive). All selected
vhosts are reported even when one fails. A parsed leaf reports its expiry as
Unix seconds. A successful inventory checks dates only: it does not prove that
the live listener serves the leaf or that a client trusts the chain.

Other scheduling considerations:
- After a failed background issuance, only that vhost waits: the delay starts at
  `retry_initial_secs`, doubles after consecutive failures up to `retry_max_secs`,
  and resets on success. If the certificate is missing or has seven days or less
  left, the cooldown is capped at one hour. The worker retries on a normal check,
  not on a separate timer; an absolute hold still takes precedence.
  CLI invocations do not share this history. See the [retry example](certificate-renewal.md#retry-policy).
- Background and companion renewals install on disk before attempting activation.
  Set `reload_after_renewal = false` to leave the current listener unchanged.
  See the [reload migration](certificate-renewal.md#reload-migration) for older
  configurations and external Windows activation.

For a deliberate pause, stop the external timer/renewal invocation and use
`automation = "external"` to stop background scheduling. Leaving
`renewal.enabled = true` keeps targets available for intentional companion
operations. Setting it false removes renewal targets, including forced
renewals. Apply changes through the supported config/service lifecycle; editing
the TOML alone does not update a running process. Monitor expiry during any pause.

ARI is an advisory CA renewal window. The implementation uses bounded lookups
and a process-local cache, with expiry-based fallback and an emergency
seven-day window. It is separate from failed-issuance backoff. A fresh companion
process does not inherit a previous process's ARI cache.

For an external workflow on Unix:

```bash
fluxheim-acme --config /etc/fluxheim/fluxheim.toml renew
fluxheim-acme --config /etc/fluxheim/fluxheim.toml status --vhost site.example.test
fluxheim-acme --config /etc/fluxheim/fluxheim.toml reload
```

`renew --vhost NAME` selects one target; `--force-renew` bypasses ordinary due
selection and can consume CA limits. `--no-reload` installs without requesting
the gateway's Unix certificate-reload socket. The legacy `fluxheim acme-renew`
also installs but does not request that socket. Installation and serving the
new certificate are distinct steps; verify the certificate on a new connection.

The companion's reload command requires Unix sockets and is unavailable on
Windows. For external Windows renewal use `--no-reload`, then the supported
server lifecycle to load the new pair. Background renewal uses the in-process
handle and is a different path. Do not infer socket support from Windows ACME
issuance support.

## Operations And Troubleshooting

| Symptom | Check |
| --- | --- |
| No targets | Global TLS/ACME, vhost TLS/ACME, concrete domains and renewal enabled |
| Agreement error | Exact issuer entry, reviewed terms URL, explicit acceptance |
| HTTP-01 failure | DNS, public port 80, container listen/publish addresses, correct vhost, external-forwarder precedence |
| TLS-ALPN-01 failure | Native challenge serving is incomplete; use HTTP-01 rather than repeatedly forcing orders |
| Files renewed but old certificate served | Reload result, serving process storage, default-vhost/SNI routing; use a new TLS connection |
| EAB/ownership error | Secret source, service identity, mounts, symlinks and writable ancestors; do not solve by making keys public |
| Repeated renewal failures | Check CA limits, clock and credentials; allow for the background retry delay, or correct the external timer's cadence |

For issuer selection, registration, EAB and account incident limitations, see
[ACME accounts and issuers](acme-accounts.md). In particular, account deactivation
can misreport remote outcomes; do not use its exit status as
confirmation that an account was deactivated.

Keep the persistent storage through upgrades; account credentials are not
disposable cache. Use the [recovery guide](acme-recovery.md) for backups, ambiguous transaction
recovery and revocation. `account-deactivate --issuer NAME --confirm` and
`revoke --vhost NAME --confirm` are destructive remote operations, not smoke
tests. `account-rollover` is exposed by the CLI but currently fails closed
because crash-safe key rollover is not implemented. Do not delete recovery
journals to force an ambiguous operation through.

The [coverage ledger](../reference/documentation-coverage.md#review-records-and-publication)
separates configuration tests, current-behavior reproductions and outstanding
real-CA/platform qualification. This guide is not a claim that all certificate
lifecycle failure cases have been freshly retested.
