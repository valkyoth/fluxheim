use super::*;

const ACCOUNT_LOCK_WAIT_TIMEOUT: Duration = Duration::from_secs(10);
const ACCOUNT_LOCK_RETRY_INTERVAL: Duration = Duration::from_millis(25);

pub(crate) async fn load_account_credentials_async(
    storage: &Path,
    issuer_name: &str,
) -> Result<Option<instant_acme::AccountCredentials>, AcmeInstantClientError> {
    load_account_credentials_async_with_timeout(storage, issuer_name, ACCOUNT_LOCK_WAIT_TIMEOUT)
        .await
}

async fn load_account_credentials_async_with_timeout(
    storage: &Path,
    issuer_name: &str,
    wait_timeout: Duration,
) -> Result<Option<instant_acme::AccountCredentials>, AcmeInstantClientError> {
    let storage = storage.to_path_buf();
    let issuer = issuer_name.to_owned();
    run_account_store_attempt(issuer_name, "credential load", wait_timeout, move || {
        try_load_account_credentials(&storage, &issuer)
    })
    .await
}

pub(crate) async fn begin_account_bootstrap_async(
    storage: &Path,
    issuer_name: &str,
    issuer_directory: &str,
) -> Result<AccountBootstrap, AcmeInstantClientError> {
    let storage = storage.to_path_buf();
    let issuer = issuer_name.to_owned();
    let directory = issuer_directory.to_owned();
    run_account_store_attempt(
        issuer_name,
        "bootstrap lock",
        ACCOUNT_LOCK_WAIT_TIMEOUT,
        move || try_begin_account_bootstrap(&storage, &issuer, &directory),
    )
    .await
}

pub(crate) async fn promote_account_bootstrap_async(
    bootstrap: PendingAccountBootstrap,
    credentials: instant_acme::AccountCredentials,
    issuer_name: &str,
) -> Result<(), AcmeInstantClientError> {
    run_account_store_task(issuer_name, "credential promotion", move || {
        bootstrap.promote(&credentials)
    })
    .await
}

pub(crate) async fn begin_account_deactivation_async(
    storage: &Path,
    issuer_name: &str,
) -> Result<AccountDeactivationTransaction, AcmeInstantClientError> {
    let storage = storage.to_path_buf();
    let issuer = issuer_name.to_owned();
    run_account_store_attempt(
        issuer_name,
        "deactivation lock",
        ACCOUNT_LOCK_WAIT_TIMEOUT,
        move || try_begin_account_deactivation(&storage, &issuer),
    )
    .await
}

pub(crate) async fn complete_account_deactivation_async(
    transaction: AccountDeactivationTransaction,
    issuer_name: &str,
) -> Result<(), AcmeInstantClientError> {
    run_account_store_task(issuer_name, "deactivation completion", move || {
        transaction.complete()
    })
    .await
}

pub(crate) async fn rollback_account_deactivation_async(
    transaction: AccountDeactivationTransaction,
    issuer_name: &str,
) -> Result<(), AcmeInstantClientError> {
    run_account_store_task(issuer_name, "deactivation rollback", move || {
        transaction.rollback()
    })
    .await
}

async fn run_account_store_attempt<T, F>(
    issuer_name: &str,
    operation_name: &'static str,
    wait_timeout: Duration,
    operation: F,
) -> Result<T, AcmeInstantClientError>
where
    T: Send + 'static,
    F: Fn() -> Result<AccountStoreAttempt<T>, AcmeAccountStoreError> + Clone + Send + 'static,
{
    let started = std::time::Instant::now();
    let mut contention_logged = false;
    loop {
        let attempt = tokio::task::spawn_blocking(operation.clone())
            .await
            .map_err(|error| {
                account_async_error(
                    issuer_name,
                    format!("ACME account {operation_name} task failed: {error}"),
                )
            })?
            .map_err(AcmeInstantClientError::AccountStore)?;
        match attempt {
            AccountStoreAttempt::Acquired(value) => return Ok(value),
            AccountStoreAttempt::Contended => {
                if !contention_logged {
                    log::warn!(
                        target: "fluxheim::acme",
                        "ACME account {operation_name} waiting for issuer {issuer_name:?} lifecycle lock"
                    );
                    contention_logged = true;
                }
                if started.elapsed() >= wait_timeout {
                    return Err(account_async_error(
                        issuer_name,
                        format!(
                            "ACME account {operation_name} timed out after {} seconds",
                            wait_timeout.as_secs_f64()
                        ),
                    ));
                }
                tokio::time::sleep(ACCOUNT_LOCK_RETRY_INTERVAL).await;
            }
        }
    }
}

async fn run_account_store_task<T, F>(
    issuer_name: &str,
    operation_name: &'static str,
    operation: F,
) -> Result<T, AcmeInstantClientError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, AcmeAccountStoreError> + Send + 'static,
{
    tokio::task::spawn_blocking(operation)
        .await
        .map_err(|error| {
            account_async_error(
                issuer_name,
                format!("ACME account {operation_name} task failed: {error}"),
            )
        })?
        .map_err(AcmeInstantClientError::AccountStore)
}

fn account_async_error(issuer: &str, message: impl Into<String>) -> AcmeInstantClientError {
    AcmeInstantClientError::Account {
        issuer: issuer.to_owned(),
        message: message.into(),
    }
}

#[cfg(test)]
pub(crate) async fn load_account_credentials_with_test_timeout(
    storage: &Path,
    issuer_name: &str,
    wait_timeout: Duration,
) -> Result<Option<instant_acme::AccountCredentials>, AcmeInstantClientError> {
    load_account_credentials_async_with_timeout(storage, issuer_name, wait_timeout).await
}
