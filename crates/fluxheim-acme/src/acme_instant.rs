use super::*;

#[cfg(feature = "acme-client")]
const ACME_RENEWAL_TIMEOUT: Duration = Duration::from_secs(180);

#[cfg(feature = "acme-client")]
pub async fn execute_instant_acme_renewal(
    config: &Config,
    item: &AcmeRenewalItem,
) -> Result<AcmeRenewalOutcome, AcmeRenewalError> {
    tokio::time::timeout(
        ACME_RENEWAL_TIMEOUT,
        execute_instant_acme_renewal_inner(config, item),
    )
    .await
    .map_err(|_| AcmeRenewalError::Client {
        issuer: item.target.issuer.clone(),
        message: format!(
            "ACME renewal exceeded its {} second deadline",
            ACME_RENEWAL_TIMEOUT.as_secs()
        ),
    })?
}

#[cfg(feature = "acme-client")]
async fn execute_instant_acme_renewal_inner(
    config: &Config,
    item: &AcmeRenewalItem,
) -> Result<AcmeRenewalOutcome, AcmeRenewalError> {
    match item.target.challenge {
        AcmeChallenge::Http01 => execute_instant_http_01_renewal(config, item).await,
        AcmeChallenge::TlsAlpn01 => execute_instant_tls_alpn_01_renewal(config, item).await,
    }
}

#[cfg(feature = "acme-client")]
async fn execute_instant_http_01_renewal(
    config: &Config,
    item: &AcmeRenewalItem,
) -> Result<AcmeRenewalOutcome, AcmeRenewalError> {
    let storage = config
        .tls
        .acme
        .storage
        .as_deref()
        .ok_or(AcmeRenewalError::MissingStorage)?;
    let account = load_or_create_instant_acme_account(config, &item.target.issuer)
        .await
        .map_err(instant_client_error_to_renewal_error)?;
    let challenge_store = AcmeHttp01ChallengeStore::new(storage, &item.target.vhost_name);
    let mut published = Vec::with_capacity(item.target.domains.len());

    let result = async {
        let identifiers: Vec<instant_acme::Identifier> = item
            .target
            .domains
            .iter()
            .map(|domain| instant_acme::Identifier::Dns(domain.clone()))
            .collect();
        let mut order = account
            .new_order(&instant_acme::NewOrder::new(&identifiers))
            .await
            .map_err(|error| AcmeRenewalError::Client {
                issuer: item.target.issuer.clone(),
                message: error.to_string(),
            })?;

        {
            let mut authorizations = order.authorizations();
            while let Some(authorization) = authorizations.next().await {
                let mut authorization =
                    authorization.map_err(|error| AcmeRenewalError::Client {
                        issuer: item.target.issuer.clone(),
                        message: error.to_string(),
                    })?;
                if authorization.status == instant_acme::AuthorizationStatus::Valid {
                    continue;
                }

                let identifier = authorization.identifier().to_string();
                let mut challenge = authorization
                    .challenge(instant_acme::ChallengeType::Http01)
                    .ok_or_else(|| AcmeRenewalError::Client {
                        issuer: item.target.issuer.clone(),
                        message: format!(
                            "authorization for {} did not include an http-01 challenge",
                            identifier
                        ),
                    })?;
                let token = challenge.token.clone();
                let key_authorization = challenge.key_authorization().as_str().to_owned();

                challenge_store
                    .install_key_authorization(&token, &key_authorization)
                    .map_err(|error| AcmeRenewalError::Challenge {
                        token: token.clone(),
                        error,
                    })?;
                published.push(token.clone());
                challenge
                    .set_ready()
                    .await
                    .map_err(|error| AcmeRenewalError::Client {
                        issuer: item.target.issuer.clone(),
                        message: acme_client_error_message_with_http_01_context(
                            error,
                            &item.target.domains,
                            &published,
                        ),
                    })?;
            }
        }

        let retry_policy = instant_acme::RetryPolicy::new().timeout(Duration::from_secs(60));
        order
            .poll_ready(&retry_policy)
            .await
            .map_err(|error| AcmeRenewalError::Client {
                issuer: item.target.issuer.clone(),
                message: acme_client_error_message_with_http_01_context(
                    error,
                    &item.target.domains,
                    &published,
                ),
            })?;
        let private_key_pem = SecretVec::from_vec(
            order
                .finalize()
                .await
                .map_err(|error| AcmeRenewalError::Client {
                    issuer: item.target.issuer.clone(),
                    message: acme_client_error_message_with_http_01_context(
                        error,
                        &item.target.domains,
                        &published,
                    ),
                })?
                .into_bytes(),
        );
        let fullchain_pem = order
            .poll_certificate(&retry_policy)
            .await
            .map_err(|error| AcmeRenewalError::Client {
                issuer: item.target.issuer.clone(),
                message: acme_client_error_message_with_http_01_context(
                    error,
                    &item.target.domains,
                    &published,
                ),
            })?
            .into_bytes();
        let certificate = private_key_pem
            .with_secret(|private_key| {
                install_managed_certificate(
                    storage,
                    &item.target.vhost_name,
                    &fullchain_pem,
                    private_key,
                    &item.target.domains,
                )
            })
            .map_err(AcmeRenewalError::CertificateInstall)?;

        Ok(AcmeRenewalOutcome {
            vhost_name: item.target.vhost_name.clone(),
            issuer: item.target.issuer.clone(),
            certificate,
            published_challenges: published.len(),
        })
    }
    .await;

    let cleanup = cleanup_http_01_challenges(&challenge_store, &published);
    finish_renewal_cleanup(result, cleanup)
}

#[cfg(feature = "acme-client")]
async fn execute_instant_tls_alpn_01_renewal(
    config: &Config,
    item: &AcmeRenewalItem,
) -> Result<AcmeRenewalOutcome, AcmeRenewalError> {
    let storage = config
        .tls
        .acme
        .storage
        .as_deref()
        .ok_or(AcmeRenewalError::MissingStorage)?;
    let account = load_or_create_instant_acme_account(config, &item.target.issuer)
        .await
        .map_err(instant_client_error_to_renewal_error)?;
    let challenge_store = AcmeTlsAlpn01ChallengeStore::new(storage);
    let mut published = Vec::with_capacity(item.target.domains.len());

    let result = async {
        let identifiers: Vec<instant_acme::Identifier> = item
            .target
            .domains
            .iter()
            .map(|domain| instant_acme::Identifier::Dns(domain.clone()))
            .collect();
        let mut order = account
            .new_order(&instant_acme::NewOrder::new(&identifiers))
            .await
            .map_err(|error| AcmeRenewalError::Client {
                issuer: item.target.issuer.clone(),
                message: error.to_string(),
            })?;

        {
            let mut authorizations = order.authorizations();
            while let Some(authorization) = authorizations.next().await {
                let mut authorization =
                    authorization.map_err(|error| AcmeRenewalError::Client {
                        issuer: item.target.issuer.clone(),
                        message: error.to_string(),
                    })?;
                if authorization.status == instant_acme::AuthorizationStatus::Valid {
                    continue;
                }

                let identifier = authorization.identifier().to_string();
                let mut challenge = authorization
                    .challenge(instant_acme::ChallengeType::TlsAlpn01)
                    .ok_or_else(|| AcmeRenewalError::Client {
                        issuer: item.target.issuer.clone(),
                        message: format!(
                            "authorization for {} did not include a tls-alpn-01 challenge",
                            identifier
                        ),
                    })?;
                let digest = challenge.key_authorization().digest();
                let (cert_pem, key_pem) = tls_alpn_01_certificate(&identifier, digest.as_ref())?;
                key_pem
                    .with_secret(|private_key| {
                        challenge_store.install_challenge_certificate(
                            &identifier,
                            &cert_pem,
                            private_key,
                        )
                    })
                    .map_err(AcmeRenewalError::CertificateInstall)?;
                published.push(identifier.clone());
                challenge
                    .set_ready()
                    .await
                    .map_err(|error| AcmeRenewalError::Client {
                        issuer: item.target.issuer.clone(),
                        message: error.to_string(),
                    })?;
            }
        }

        let retry_policy = instant_acme::RetryPolicy::new().timeout(Duration::from_secs(60));
        order
            .poll_ready(&retry_policy)
            .await
            .map_err(|error| AcmeRenewalError::Client {
                issuer: item.target.issuer.clone(),
                message: error.to_string(),
            })?;
        let private_key_pem = SecretVec::from_vec(
            order
                .finalize()
                .await
                .map_err(|error| AcmeRenewalError::Client {
                    issuer: item.target.issuer.clone(),
                    message: error.to_string(),
                })?
                .into_bytes(),
        );
        let fullchain_pem = order
            .poll_certificate(&retry_policy)
            .await
            .map_err(|error| AcmeRenewalError::Client {
                issuer: item.target.issuer.clone(),
                message: error.to_string(),
            })?
            .into_bytes();
        let certificate = private_key_pem
            .with_secret(|private_key| {
                install_managed_certificate(
                    storage,
                    &item.target.vhost_name,
                    &fullchain_pem,
                    private_key,
                    &item.target.domains,
                )
            })
            .map_err(AcmeRenewalError::CertificateInstall)?;

        Ok(AcmeRenewalOutcome {
            vhost_name: item.target.vhost_name.clone(),
            issuer: item.target.issuer.clone(),
            certificate,
            published_challenges: published.len(),
        })
    }
    .await;

    let cleanup = cleanup_tls_alpn_01_challenges(&challenge_store, &published);
    finish_renewal_cleanup(result, cleanup)
}

#[cfg(feature = "acme-client")]
pub async fn renew_all_instant_acme_targets(
    config: &Config,
    now: SystemTime,
) -> Result<AcmeRenewalRun, AcmeRenewalError> {
    let queue = plan_renewal_queue(config, &[], now);
    execute_instant_acme_queue(config, &queue).await
}

#[cfg(feature = "acme-client")]
pub async fn renew_due_instant_acme_targets(
    config: &Config,
    now: SystemTime,
) -> Result<AcmeRenewalRun, AcmeRenewalError> {
    let observations = observe_configured_certificates(config);
    let queue = plan_renewal_queue(config, &observations, now);
    execute_due_instant_acme_queue(config, &queue, now).await
}

async fn execute_due_instant_acme_queue(
    config: &Config,
    queue: &[AcmeRenewalItem],
    now: SystemTime,
) -> Result<AcmeRenewalRun, AcmeRenewalError> {
    acme_ari::execute_due_queue(config, queue, now).await
}

#[cfg(feature = "acme-client")]
pub async fn renew_selected_instant_acme_targets(
    config: &Config,
    now: SystemTime,
    vhost_name: &str,
    force_renew: bool,
) -> Result<AcmeRenewalRun, AcmeRenewalError> {
    let queue = if force_renew {
        plan_renewal_queue(config, &[], now)
    } else {
        let observations = observe_configured_certificates(config);
        plan_renewal_queue(config, &observations, now)
    };
    let mut selected_queue = Vec::new();
    for item in queue
        .into_iter()
        .filter(|item| item.target.vhost_name == vhost_name)
    {
        if force_renew || acme_ari::allows_renewal_now_bounded(config, &item, now).await {
            selected_queue.push(item);
        }
    }
    execute_instant_acme_queue(config, &selected_queue).await
}

#[cfg(feature = "acme-client")]
async fn execute_instant_acme_queue(
    config: &Config,
    queue: &[AcmeRenewalItem],
) -> Result<AcmeRenewalRun, AcmeRenewalError> {
    let mut run = AcmeRenewalRun {
        attempted: 0,
        renewed: Vec::with_capacity(queue.len()),
        failed: Vec::new(),
    };
    for item in queue {
        execute_instant_acme_item(config, item, &mut run).await;
    }
    Ok(run)
}

pub(super) async fn execute_instant_acme_item(
    config: &Config,
    item: &AcmeRenewalItem,
    run: &mut AcmeRenewalRun,
) {
    run.attempted = run.attempted.saturating_add(1);
    match execute_instant_acme_renewal(config, item).await {
        Ok(outcome) => run.renewed.push(outcome),
        Err(error) => run.failed.push(AcmeRenewalFailure {
            vhost_name: item.target.vhost_name.clone(),
            issuer: item.target.issuer.clone(),
            domains: item.target.domains.clone(),
            error: error.to_string(),
        }),
    }
}
