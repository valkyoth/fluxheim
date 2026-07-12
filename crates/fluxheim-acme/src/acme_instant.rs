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
    let mut due_queue = Vec::new();
    for item in queue {
        if ari_allows_renewal_now(config, &item, now).await {
            due_queue.push(item);
        }
    }
    execute_instant_acme_queue(config, &due_queue).await
}

#[cfg(feature = "acme-client")]
async fn ari_allows_renewal_now(config: &Config, item: &AcmeRenewalItem, now: SystemTime) -> bool {
    let fallback = item.due_now;
    let Some(storage) = config.tls.acme.storage.as_deref() else {
        return fallback;
    };
    let Ok(Some(credentials)) = load_account_credentials(storage, &item.target.issuer) else {
        return fallback;
    };
    let Some(issuer) = config
        .tls
        .acme
        .issuers
        .iter()
        .find(|issuer| issuer.name == item.target.issuer)
    else {
        return fallback;
    };
    let Ok(Some(certificate_pem)) =
        read_bounded_certificate_file(&item.target.certificate.cert_path)
    else {
        return fallback;
    };
    let Some(Ok(leaf)) = rustls_pemfile::certs(&mut certificate_pem.as_slice()).next() else {
        return fallback;
    };
    let Ok(identifier) = instant_acme::CertificateIdentifier::try_from(&leaf) else {
        return fallback;
    };
    let Ok(builder) = bounded_acme_account_builder(issuer) else {
        return fallback;
    };
    let Ok(Ok(account)) = tokio::time::timeout(
        ACME_ACCOUNT_OPERATION_TIMEOUT,
        builder.from_credentials(credentials),
    )
    .await
    else {
        return fallback;
    };
    let renewal_info = tokio::time::timeout(
        ACME_ACCOUNT_OPERATION_TIMEOUT,
        account.renewal_info(&identifier),
    )
    .await;
    let info = match renewal_info {
        Ok(Ok((info, _retry_after))) => info,
        Ok(Err(instant_acme::Error::Unsupported(_))) => return fallback,
        Ok(Err(error)) => {
            log::warn!(
                target: "fluxheim::acme",
                "ACME ARI lookup failed for vhost {}: {error}; using configured renewal window",
                item.target.vhost_name
            );
            return fallback;
        }
        Err(_) => {
            log::warn!(
                target: "fluxheim::acme",
                "ACME ARI lookup timed out for vhost {}; using configured renewal window",
                item.target.vhost_name
            );
            return fallback;
        }
    };
    let start = info.suggested_window.start.unix_timestamp();
    let end = info.suggested_window.end.unix_timestamp();
    if end <= start {
        return fallback;
    }
    let scheduled = deterministic_ari_renewal_time(leaf.as_ref(), start, end);
    let now = now
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    now >= scheduled.max(0) as u64
}

#[cfg(feature = "acme-client")]
fn deterministic_ari_renewal_time(certificate_der: &[u8], start: i64, end: i64) -> i64 {
    if end <= start {
        return start;
    }
    use sha2::Digest as _;
    let digest = sha2::Sha256::digest(certificate_der);
    let mut seed = [0_u8; 8];
    seed.copy_from_slice(&digest[..8]);
    let offset = u64::from_be_bytes(seed) % (end - start) as u64;
    start.saturating_add(offset as i64)
}

#[cfg(all(feature = "acme-client", test))]
mod ari_tests {
    #[test]
    fn ari_schedule_is_stable_and_inside_the_suggested_window() {
        let first = super::deterministic_ari_renewal_time(b"certificate", 100, 200);
        let second = super::deterministic_ari_renewal_time(b"certificate", 100, 200);
        assert_eq!(first, second);
        assert!((100..200).contains(&first));
        assert_eq!(
            super::deterministic_ari_renewal_time(b"certificate", 50, 50),
            50
        );
    }
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
        if force_renew || ari_allows_renewal_now(config, &item, now).await {
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
    let mut renewed = Vec::with_capacity(queue.len());
    let mut failed = Vec::new();

    for item in queue {
        match execute_instant_acme_renewal(config, item).await {
            Ok(outcome) => renewed.push(outcome),
            Err(error) => failed.push(AcmeRenewalFailure {
                vhost_name: item.target.vhost_name.clone(),
                issuer: item.target.issuer.clone(),
                domains: item.target.domains.clone(),
                error: error.to_string(),
            }),
        }
    }

    Ok(AcmeRenewalRun {
        attempted: queue.len(),
        renewed,
        failed,
    })
}
