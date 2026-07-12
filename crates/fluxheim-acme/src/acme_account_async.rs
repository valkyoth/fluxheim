use super::*;
use std::sync::Arc;

const ACCOUNT_LOCK_WAIT_TIMEOUT: Duration = Duration::from_secs(10);
const ACCOUNT_LOCK_RETRY_INTERVAL: Duration = Duration::from_millis(25);

/// Loads ACME credentials without blocking a Tokio worker.
///
/// Returns an error when the issuer lifecycle lock cannot be acquired within
/// Fluxheim's bounded account-lock deadline.
pub async fn load_account_credentials_async(
    storage: &Path,
    issuer_name: &str,
) -> Result<Option<instant_acme::AccountCredentials>, AcmeInstantClientError> {
    load_account_credentials_async_with_timeout(storage, issuer_name, ACCOUNT_LOCK_WAIT_TIMEOUT)
        .await
}

/// Persists ACME credentials without blocking a Tokio worker.
///
/// Returns an error when the issuer lifecycle lock cannot be acquired within
/// Fluxheim's bounded account-lock deadline.
pub async fn store_account_credentials_async(
    storage: &Path,
    issuer_name: &str,
    credentials: instant_acme::AccountCredentials,
) -> Result<AcmeAccountCredentialsPath, AcmeInstantClientError> {
    store_account_credentials_async_with_timeout(
        storage,
        issuer_name,
        credentials,
        ACCOUNT_LOCK_WAIT_TIMEOUT,
    )
    .await
}

async fn store_account_credentials_async_with_timeout(
    storage: &Path,
    issuer_name: &str,
    credentials: instant_acme::AccountCredentials,
    wait_timeout: Duration,
) -> Result<AcmeAccountCredentialsPath, AcmeInstantClientError> {
    let storage = storage.to_path_buf();
    let issuer = issuer_name.to_owned();
    let credentials = Arc::new(credentials);
    run_account_store_attempt(issuer_name, "credential store", wait_timeout, move || {
        try_store_account_credentials(&storage, &issuer, credentials.as_ref())
    })
    .await
}

/// Removes ACME credentials without blocking a Tokio worker.
///
/// Returns an error when the issuer lifecycle lock cannot be acquired within
/// Fluxheim's bounded account-lock deadline.
pub async fn remove_account_credentials_async(
    storage: &Path,
    issuer_name: &str,
) -> Result<bool, AcmeInstantClientError> {
    remove_account_credentials_async_with_timeout(storage, issuer_name, ACCOUNT_LOCK_WAIT_TIMEOUT)
        .await
}

async fn remove_account_credentials_async_with_timeout(
    storage: &Path,
    issuer_name: &str,
    wait_timeout: Duration,
) -> Result<bool, AcmeInstantClientError> {
    let storage = storage.to_path_buf();
    let issuer = issuer_name.to_owned();
    run_account_store_attempt(issuer_name, "credential removal", wait_timeout, move || {
        try_remove_account_credentials(&storage, &issuer)
    })
    .await
}

fn try_store_account_credentials(
    storage: &Path,
    issuer_name: &str,
    credentials: &instant_acme::AccountCredentials,
) -> Result<AccountStoreAttempt<AcmeAccountCredentialsPath>, AcmeAccountStoreError> {
    let credentials_path = account_credentials_path(storage, issuer_name);
    let directory = account_directory(&credentials_path)?;
    ensure_safe_account_directory(directory)?;
    let Some(_lock) = AcmeMutationLock::try_acquire(directory).map_err(|error| {
        account_async_store_io_error(&directory.join(".fluxheim-acme.lock"), error)
    })?
    else {
        return Ok(AccountStoreAttempt::Contended);
    };
    let pending = directory.join(".credentials.bootstrap.pending");
    if pending
        .try_exists()
        .map_err(|error| account_async_store_io_error(&pending, error))?
    {
        return Err(AcmeAccountStoreError::UnsafePath {
            path: pending,
            message: "account bootstrap is pending; credentials must be promoted by the bootstrap transaction"
                .to_owned(),
        });
    }
    store_account_credentials_locked(&credentials_path, directory, credentials)
        .map(AccountStoreAttempt::Acquired)
}

fn try_remove_account_credentials(
    storage: &Path,
    issuer_name: &str,
) -> Result<AccountStoreAttempt<bool>, AcmeAccountStoreError> {
    let credentials_path = account_credentials_path(storage, issuer_name);
    let directory = account_directory(&credentials_path)?;
    ensure_safe_account_directory(directory)?;
    let Some(_lock) = AcmeMutationLock::try_acquire(directory).map_err(|error| {
        account_async_store_io_error(&directory.join(".fluxheim-acme.lock"), error)
    })?
    else {
        return Ok(AccountStoreAttempt::Contended);
    };
    ensure_safe_account_destination(&credentials_path.path)?;
    let removed = match fs::remove_file(&credentials_path.path) {
        Ok(()) => {
            let directory_file = fs::File::open(directory)
                .map_err(|error| account_async_store_io_error(directory, error))?;
            directory_file
                .sync_all()
                .map_err(|error| account_async_store_io_error(directory, error))?;
            true
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => return Err(account_async_store_io_error(&credentials_path.path, error)),
    };
    Ok(AccountStoreAttempt::Acquired(removed))
}

fn account_directory(
    credentials_path: &AcmeAccountCredentialsPath,
) -> Result<&Path, AcmeAccountStoreError> {
    credentials_path
        .path
        .parent()
        .ok_or_else(|| AcmeAccountStoreError::UnsafePath {
            path: credentials_path.path.clone(),
            message: "credentials path has no parent directory".to_owned(),
        })
}

fn account_async_store_io_error(path: &Path, error: io::Error) -> AcmeAccountStoreError {
    AcmeAccountStoreError::Io {
        path: path.to_path_buf(),
        error,
    }
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

#[cfg(test)]
pub(crate) async fn store_account_credentials_with_test_timeout(
    storage: &Path,
    issuer_name: &str,
    credentials: instant_acme::AccountCredentials,
    wait_timeout: Duration,
) -> Result<AcmeAccountCredentialsPath, AcmeInstantClientError> {
    store_account_credentials_async_with_timeout(storage, issuer_name, credentials, wait_timeout)
        .await
}

#[cfg(test)]
pub(crate) async fn remove_account_credentials_with_test_timeout(
    storage: &Path,
    issuer_name: &str,
    wait_timeout: Duration,
) -> Result<bool, AcmeInstantClientError> {
    remove_account_credentials_async_with_timeout(storage, issuer_name, wait_timeout).await
}
