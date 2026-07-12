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

    if let Some(credentials) = load_account_credentials(storage, issuer_name)
        .map_err(AcmeInstantClientError::AccountStore)?
    {
        return bounded_acme_account_builder(issuer)?
            .from_credentials(credentials)
            .await
            .map_err(|error| AcmeInstantClientError::Account {
                issuer: issuer_name.to_owned(),
                message: error.to_string(),
            });
    }

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
    let (account, credentials) = bounded_acme_account_builder(issuer)?
        .create(
            &account_request,
            issuer.directory_url.clone(),
            eab_key.as_ref(),
        )
        .await
        .map_err(|error| AcmeInstantClientError::Account {
            issuer: issuer_name.to_owned(),
            message: error.to_string(),
        })?;
    store_account_credentials(storage, issuer_name, &credentials)
        .map_err(AcmeInstantClientError::AccountStore)?;
    Ok(account)
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
    let storage = existing_account_storage(config, issuer_name)?;
    let account = load_or_create_instant_acme_account(config, issuer_name).await?;
    let transaction = begin_account_deactivation(storage, issuer_name)
        .map_err(AcmeInstantClientError::AccountStore)?;
    let result = tokio::time::timeout(ACME_ACCOUNT_OPERATION_TIMEOUT, account.deactivate())
        .await
        .map_err(|_| account_error(issuer_name, "ACME account deactivation timed out"))?
        .map_err(|error| account_error(issuer_name, error.to_string()));
    match result {
        Ok(()) => transaction
            .complete()
            .map_err(AcmeInstantClientError::AccountStore),
        Err(primary) => match transaction.rollback() {
            Ok(()) => Err(primary),
            Err(rollback) => Err(account_error(
                issuer_name,
                format!(
                    "remote deactivation failed ({primary}); local credential rollback also failed ({rollback})"
                ),
            )),
        },
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

fn existing_account_storage<'a>(
    config: &'a Config,
    issuer_name: &str,
) -> Result<&'a Path, AcmeInstantClientError> {
    let storage = config
        .tls
        .acme
        .storage
        .as_deref()
        .ok_or(AcmeInstantClientError::MissingStorage)?;
    if load_account_credentials(storage, issuer_name)
        .map_err(AcmeInstantClientError::AccountStore)?
        .is_none()
    {
        return Err(account_error(issuer_name, "no stored ACME account exists"));
    }
    Ok(storage)
}

fn account_error(issuer: &str, message: impl Into<String>) -> AcmeInstantClientError {
    AcmeInstantClientError::Account {
        issuer: issuer.to_owned(),
        message: message.into(),
    }
}
