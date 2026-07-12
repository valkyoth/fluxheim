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
    config: &Config,
    issuer_name: &str,
) -> Result<(), AcmeInstantClientError> {
    let storage = existing_account_storage(config, issuer_name)?;
    let mut account = load_or_create_instant_acme_account(config, issuer_name).await?;
    let credentials = tokio::time::timeout(ACME_ACCOUNT_OPERATION_TIMEOUT, account.update_key())
        .await
        .map_err(|_| account_error(issuer_name, "ACME account key rollover timed out"))?
        .map_err(|error| account_error(issuer_name, error.to_string()))?;
    store_account_credentials(storage, issuer_name, &credentials)
        .map_err(AcmeInstantClientError::AccountStore)?;
    Ok(())
}

pub async fn deactivate_instant_acme_account(
    config: &Config,
    issuer_name: &str,
) -> Result<(), AcmeInstantClientError> {
    let storage = existing_account_storage(config, issuer_name)?;
    let account = load_or_create_instant_acme_account(config, issuer_name).await?;
    tokio::time::timeout(ACME_ACCOUNT_OPERATION_TIMEOUT, account.deactivate())
        .await
        .map_err(|_| account_error(issuer_name, "ACME account deactivation timed out"))?
        .map_err(|error| account_error(issuer_name, error.to_string()))?;
    remove_account_credentials(storage, issuer_name)
        .map_err(AcmeInstantClientError::AccountStore)?;
    Ok(())
}

pub async fn revoke_instant_acme_certificate(
    config: &Config,
    vhost_name: &str,
) -> Result<(), AcmeInstantClientError> {
    let target = renewal_targets(config)
        .into_iter()
        .find(|target| target.vhost_name == vhost_name)
        .ok_or_else(|| {
            account_error(
                "unknown",
                format!("unknown ACME vhost target {vhost_name:?}"),
            )
        })?;
    let certificate_pem = read_bounded_certificate_file(&target.certificate.cert_path)
        .map_err(|error| {
            account_error(
                &target.issuer,
                format!("failed to read managed certificate: {error}"),
            )
        })?
        .ok_or_else(|| account_error(&target.issuer, "managed certificate is missing"))?;
    let leaf = rustls_pemfile::certs(&mut certificate_pem.as_slice())
        .next()
        .transpose()
        .map_err(|error| {
            account_error(
                &target.issuer,
                format!("failed to parse managed certificate: {error}"),
            )
        })?
        .ok_or_else(|| {
            account_error(
                &target.issuer,
                "managed certificate has no leaf certificate",
            )
        })?;
    let account = load_or_create_instant_acme_account(config, &target.issuer).await?;
    tokio::time::timeout(
        ACME_ACCOUNT_OPERATION_TIMEOUT,
        account.revoke(&instant_acme::RevocationRequest {
            certificate: &leaf,
            reason: None,
        }),
    )
    .await
    .map_err(|_| account_error(&target.issuer, "ACME certificate revocation timed out"))?
    .map_err(|error| account_error(&target.issuer, error.to_string()))
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
