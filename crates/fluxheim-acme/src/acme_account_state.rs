use std::fs;
use std::io;
use std::path::Path;

use super::AcmeAccountStoreError;

pub(crate) const ACCOUNT_BOOTSTRAP_PENDING_FILE: &str = ".credentials.bootstrap.pending";
pub(crate) const ACCOUNT_DEACTIVATION_PENDING_FILE: &str = ".credentials.deactivation.pending";

pub(crate) fn reject_pending_account_mutation(
    directory: &Path,
) -> Result<(), AcmeAccountStoreError> {
    reject_pending_account_bootstrap(directory)?;
    reject_pending_account_deactivation(directory)
}

pub(crate) fn reject_pending_account_bootstrap(
    directory: &Path,
) -> Result<(), AcmeAccountStoreError> {
    reject_pending_account_state(
        directory,
        ACCOUNT_BOOTSTRAP_PENDING_FILE,
        "account bootstrap is pending; bootstrap recovery must complete",
    )
}

pub(crate) fn reject_pending_account_deactivation(
    directory: &Path,
) -> Result<(), AcmeAccountStoreError> {
    reject_pending_account_state(
        directory,
        ACCOUNT_DEACTIVATION_PENDING_FILE,
        "account deactivation is in an ambiguous pending state; operator recovery is required",
    )
}

fn reject_pending_account_state(
    directory: &Path,
    name: &str,
    message: &str,
) -> Result<(), AcmeAccountStoreError> {
    let path = directory.join(name);
    match fs::symlink_metadata(&path) {
        Ok(_) => Err(AcmeAccountStoreError::UnsafePath {
            path,
            message: message.to_owned(),
        }),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(AcmeAccountStoreError::Io { path, error }),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn pending_mutation_guard_rejects_dangling_symlink() {
        let storage = fluxheim_common::test_support::unique_temp_path("acme-account-state-link");
        let credentials = crate::account_credentials_path(&storage, "issuer");
        let directory = credentials.path.parent().unwrap().to_path_buf();
        fs::create_dir_all(&directory).unwrap();
        std::os::unix::fs::symlink(
            directory.join("missing-target"),
            directory.join(ACCOUNT_BOOTSTRAP_PENDING_FILE),
        )
        .unwrap();

        let error = reject_pending_account_mutation(&directory).unwrap_err();
        assert!(matches!(error, AcmeAccountStoreError::UnsafePath { .. }));
        let load_error = match crate::load_account_credentials(&storage, "issuer") {
            Ok(_) => panic!("expected dangling pending state to fail closed"),
            Err(error) => error,
        };
        assert!(matches!(
            load_error,
            AcmeAccountStoreError::UnsafePath { .. }
        ));
    }
}
