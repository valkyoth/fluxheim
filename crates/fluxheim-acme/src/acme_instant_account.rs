use super::*;

pub(super) const ACME_ACCOUNT_OPERATION_TIMEOUT: Duration = Duration::from_secs(60);

pub async fn probe_instant_acme_issuer(
    config: &Config,
    issuer_name: &str,
) -> Result<(), AcmeInstantClientError> {
    let issuer = config
        .tls
        .acme
        .issuers
        .iter()
        .find(|issuer| issuer.name == issuer_name)
        .ok_or_else(|| AcmeInstantClientError::UnknownIssuer {
            issuer: issuer_name.to_owned(),
        })?;
    acme_instant_http::probe_acme_directory(issuer).await
}

pub async fn load_or_create_instant_acme_account(
    config: &Config,
    issuer_name: &str,
) -> Result<instant_acme::Account, AcmeInstantClientError> {
    let storage = config
        .tls
        .acme
        .storage
        .as_deref()
        .ok_or(AcmeInstantClientError::MissingStorage)?;
    let issuer = config
        .tls
        .acme
        .issuers
        .iter()
        .find(|issuer| issuer.name == issuer_name)
        .ok_or_else(|| AcmeInstantClientError::UnknownIssuer {
            issuer: issuer_name.to_owned(),
        })?;

    let bootstrap = acme_account_async::begin_account_bootstrap_async(
        storage,
        issuer_name,
        &issuer.directory_url,
    )
    .await?;
    let bootstrap = match bootstrap {
        AccountBootstrap::Existing(credentials) => {
            return bounded_acme_account_builder(issuer)?
                .from_credentials(credentials)
                .await
                .map_err(|error| AcmeInstantClientError::Account {
                    issuer: issuer_name.to_owned(),
                    message: error.to_string(),
                });
        }
        AccountBootstrap::Pending(bootstrap) => bootstrap,
    };

    let contact_storage;
    let contacts: &[&str] = if let Some(email) = config.tls.acme.contact_email.as_deref() {
        contact_storage = [format!("mailto:{email}")];
        &[&contact_storage[0]]
    } else {
        &[]
    };
    if !issuer.terms_of_service_agreed || issuer.terms_of_service_url.is_none() {
        return Err(AcmeInstantClientError::TermsOfServiceNotAccepted {
            issuer: issuer_name.to_owned(),
        });
    }
    acme_instant_http::probe_acme_directory(issuer).await?;
    let account_request = instant_acme::NewAccount {
        contact: contacts,
        terms_of_service_agreed: issuer.terms_of_service_agreed,
        only_return_existing: false,
    };
    let eab = load_external_account_binding(config, issuer_name)
        .map_err(AcmeInstantClientError::ExternalAccountBinding)?;
    let eab_key = match eab.as_ref() {
        Some(secrets) => Some(external_account_key_from_secrets(issuer_name, secrets)?),
        None => None,
    };
    let mut bootstrap = bootstrap;
    let restored = if bootstrap.recovered() {
        let key = bootstrap
            .existing_key_pair()
            .map_err(AcmeInstantClientError::AccountStore)?;
        match bounded_acme_account_builder(issuer)?
            .from_secret_key(key, issuer.directory_url.clone())
            .await
        {
            Ok(account) => Some(account),
            Err(error) if acme_account_does_not_exist(&error) => None,
            Err(error) => {
                return Err(account_error(issuer_name, error.to_string()));
            }
        }
    } else {
        None
    };
    let (account, credentials) = match restored {
        Some(account) => account,
        None => {
            let key = bootstrap
                .key_pair()
                .map_err(AcmeInstantClientError::AccountStore)?;
            bounded_acme_account_builder(issuer)?
                .create_with_key(
                    &account_request,
                    key,
                    issuer.directory_url.clone(),
                    eab_key.as_ref(),
                )
                .await
                .map_err(|error| account_error(issuer_name, error.to_string()))?
        }
    };
    acme_account_async::promote_account_bootstrap_async(bootstrap, credentials, issuer_name)
        .await?;
    Ok(account)
}

fn acme_account_does_not_exist(error: &instant_acme::Error) -> bool {
    matches!(
        error,
        instant_acme::Error::Api(problem)
            if problem.r#type.as_deref()
                == Some("urn:ietf:params:acme:error:accountDoesNotExist")
    )
}

pub async fn rollover_instant_acme_account_key(
    _config: &Config,
    issuer_name: &str,
) -> Result<(), AcmeInstantClientError> {
    Err(account_error(
        issuer_name,
        "safe ACME account rollover is unavailable because the client cannot persist a caller-generated key before remote activation",
    ))
}

pub async fn deactivate_instant_acme_account(
    config: &Config,
    issuer_name: &str,
) -> Result<(), AcmeInstantClientError> {
    account_outcome(config, issuer_name, false, ACME_ACCOUNT_OPERATION_TIMEOUT)
        .await
        .map(|_| ())
}

/// Resolve a pending local transaction only from the issuer's current account object.
pub async fn reconcile_instant_acme_account(
    config: &Config,
    issuer_name: &str,
) -> Result<&'static str, AcmeInstantClientError> {
    account_outcome(config, issuer_name, true, ACME_ACCOUNT_OPERATION_TIMEOUT).await
}

pub(super) async fn account_outcome(
    config: &Config,
    issuer_name: &str,
    reconcile: bool,
    timeout: Duration,
) -> Result<&'static str, AcmeInstantClientError> {
    use instant_acme::AuthorizationStatus::{Deactivated, Valid};
    let acme = &config.tls.acme;
    let storage = acme
        .storage
        .as_deref()
        .ok_or(AcmeInstantClientError::MissingStorage)?;
    let issuer = acme
        .issuers
        .iter()
        .find(|i| i.name == issuer_name)
        .ok_or_else(|| AcmeInstantClientError::UnknownIssuer {
            issuer: issuer_name.into(),
        })?;
    let builder = bounded_acme_account_builder(issuer)?;
    let (transaction, credentials) =
        acme_account_async::begin_account_deactivation_async(storage, issuer_name, reconcile)
            .await?;
    let deadline = tokio::time::Instant::now() + timeout;
    let account = if credentials.directory_url() == Some(issuer.directory_url.as_str()) {
        tokio::time::timeout_at(deadline, builder.from_credentials(credentials))
            .await
            .ok()
            .and_then(Result::ok)
    } else {
        None
    };
    let Some(account) = account else {
        if !reconcile {
            // No mutation was sent; this is the only automatic rollback.
            acme_account_async::rollback_account_deactivation_async(transaction, issuer_name)
                .await?;
        }
        return Err(account_error(
            issuer_name,
            "no account request sent: cannot open stored account with configured issuer",
        ));
    };
    let outcome = tokio::time::timeout_at(deadline, async {
        if reconcile {
            account.account_status().await
        } else {
            account.deactivate().await.map(|()| Deactivated)
        }
    })
    .await;
    match outcome {
        Ok(Ok(Deactivated)) => {
            acme_account_async::complete_account_deactivation_async(transaction, issuer_name)
                .await
                .map_err(|_| {
                    account_error(
                        issuer_name,
                        "remote=deactivated; local credential cleanup not confirmed",
                    )
                })?;
            Ok("deactivated")
        }
        Ok(Ok(Valid)) if reconcile => {
            acme_account_async::rollback_account_deactivation_async(transaction, issuer_name)
                .await
                .map_err(|_| {
                    account_error(
                        issuer_name,
                        "remote=valid; local credential restoration not confirmed",
                    )
                })?;
            Ok("valid")
        }
        _ => Err(account_error(
            issuer_name,
            "remote=unconfirmed; credentials remain quarantined; use account-reconcile after verifying the incident with the issuer",
        )),
    }
}

pub async fn revoke_instant_acme_certificate(
    config: &Config,
    vhost_name: &str,
) -> Result<AcmeRevocationOutcome, AcmeInstantClientError> {
    let target = managed_acme_targets(config)
        .into_iter()
        .find(|target| target.vhost_name == vhost_name)
        .ok_or_else(|| {
            account_error(
                "unknown",
                format!("unknown ACME vhost target {vhost_name:?}"),
            )
        })?;
    let account = load_or_create_instant_acme_account(config, &target.issuer).await?;
    let mut quarantine =
        begin_managed_certificate_quarantine(&target.certificate).map_err(|error| {
            account_error(
                &target.issuer,
                format!("failed to quarantine certificate before revocation: {error}"),
            )
        })?;
    let certificate_pem = quarantine.read_quarantined_certificate().map_err(|error| {
        account_error(
            &target.issuer,
            format!("failed to read quarantined certificate: {error}"),
        )
    })?;
    use rustls::pki_types::pem::PemObject as _;
    let leaf = rustls::pki_types::CertificateDer::pem_slice_iter(&certificate_pem)
        .next()
        .transpose()
        .map_err(|error| {
            account_error(
                &target.issuer,
                format!("failed to parse quarantined certificate: {error}"),
            )
        })?
        .ok_or_else(|| {
            account_error(
                &target.issuer,
                "quarantined certificate has no leaf certificate",
            )
        })?;
    quarantine.mark_remote_pending().map_err(|error| {
        account_error(
            &target.issuer,
            format!("failed to persist pending revocation state: {error}"),
        )
    })?;
    let revocation = tokio::time::timeout(
        ACME_ACCOUNT_OPERATION_TIMEOUT,
        account.revoke(&instant_acme::RevocationRequest {
            certificate: &leaf,
            reason: None,
        }),
    )
    .await
    .map_err(|_| account_error(&target.issuer, "ACME certificate revocation timed out"))
    .and_then(|result| result.map_err(|error| account_error(&target.issuer, error.to_string())));
    if let Err(primary) = revocation {
        let (certificate, private_key) = quarantine.quarantine_paths();
        return Err(account_error(
            &target.issuer,
            format!(
                "remote revocation outcome is ambiguous ({primary}); certificate remains quarantined at {} and {}; operator resolution is required",
                certificate.display(),
                private_key.display()
            ),
        ));
    }
    quarantine.mark_remote_confirmed().map_err(|error| {
        account_error(
            &target.issuer,
            format!("certificate was revoked but confirmation journaling failed: {error}"),
        )
    })?;
    let (quarantined_certificate, quarantined_private_key) = quarantine
        .complete()
        .map_err(|error| account_error(&target.issuer, error.to_string()))?;
    Ok(AcmeRevocationOutcome {
        certificate: target.certificate,
        quarantined_certificate,
        quarantined_private_key,
        replacement_required: true,
    })
}

fn account_error(issuer: &str, message: impl Into<String>) -> AcmeInstantClientError {
    AcmeInstantClientError::Account {
        issuer: issuer.to_owned(),
        message: message.into(),
    }
}
