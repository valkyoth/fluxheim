use super::{
    existing_path_has_insecure_write_permissions, harden_confidential_file,
    opened_file_has_insecure_confidential_permissions,
    opened_file_has_insecure_owner_or_write_permissions, sync_directory,
};
use windows_permissions::constants::{SeObjectType, SecurityInformation};
use windows_permissions::{LocalBox, SecurityDescriptor};

#[test]
fn default_temporary_file_is_trusted() {
    let file = tempfile::NamedTempFile::new().unwrap();
    assert!(!existing_path_has_insecure_write_permissions(file.path()).unwrap());
    assert!(!opened_file_has_insecure_owner_or_write_permissions(file.as_file()).unwrap());
}

#[test]
fn shared_fluxheim_test_root_and_missing_descendant_are_trusted() {
    let root = fluxheim_common::test_support::test_root();
    let missing = root.join("missing-security-test").join("config.toml");
    assert!(!existing_path_has_insecure_write_permissions(&root).unwrap());
    assert!(!existing_path_has_insecure_write_permissions(&missing).unwrap());
}

#[test]
fn canonical_executable_path_is_inspectable() {
    let executable = std::env::current_exe().unwrap().canonicalize().unwrap();
    existing_path_has_insecure_write_permissions(&executable).unwrap();
}

#[test]
fn newly_created_file_beside_executable_is_inspectable() {
    let executable = std::env::current_exe().unwrap().canonicalize().unwrap();
    let file = tempfile::NamedTempFile::new_in(executable.parent().unwrap()).unwrap();
    existing_path_has_insecure_write_permissions(file.path()).unwrap();
    opened_file_has_insecure_owner_or_write_permissions(file.as_file()).unwrap();
}

#[test]
fn missing_descendant_uses_trusted_existing_parent_handle() {
    let directory = tempfile::tempdir().unwrap();
    let missing = directory.path().join("missing").join("config.toml");
    assert!(!existing_path_has_insecure_write_permissions(&missing).unwrap());
}

fn install_everyone_acl(path: &std::path::Path, access: &str) {
    let current = windows_permissions::utilities::current_process_sid().unwrap();
    let descriptor: LocalBox<SecurityDescriptor> = format!(
        "D:P(A;;FA;;;{})(A;;FA;;;SY)(A;;FA;;;BA)(A;;{access};;;WD)",
        current
    )
    .parse()
    .unwrap();
    windows_permissions::wrappers::SetNamedSecurityInfo(
        path,
        SeObjectType::SE_FILE_OBJECT,
        SecurityInformation::Dacl,
        None,
        None,
        descriptor.dacl(),
        None,
    )
    .unwrap();
}

#[test]
fn everyone_write_access_is_rejected() {
    let file = tempfile::NamedTempFile::new().unwrap();
    install_everyone_acl(file.path(), "FW");
    assert!(opened_file_has_insecure_owner_or_write_permissions(&file.reopen().unwrap()).unwrap());
}

#[test]
fn everyone_read_access_is_only_rejected_for_confidential_files() {
    let file = tempfile::NamedTempFile::new().unwrap();
    install_everyone_acl(file.path(), "FR");
    let opened = file.reopen().unwrap();
    assert!(!opened_file_has_insecure_owner_or_write_permissions(&opened).unwrap());
    assert!(opened_file_has_insecure_confidential_permissions(&opened).unwrap());
}

#[test]
fn confidential_hardening_removes_inherited_everyone_access() {
    let file = tempfile::NamedTempFile::new().unwrap();
    install_everyone_acl(file.path(), "FR");
    let mut opened = file.reopen().unwrap();
    assert!(opened_file_has_insecure_confidential_permissions(&opened).unwrap());
    harden_confidential_file(&mut opened).unwrap();
    assert!(!opened_file_has_insecure_confidential_permissions(&opened).unwrap());
}

#[test]
fn everyone_delete_child_access_on_directory_is_rejected() {
    let directory = tempfile::tempdir().unwrap();
    install_everyone_acl(directory.path(), "DC");

    assert!(existing_path_has_insecure_write_permissions(directory.path()).unwrap());
}

#[test]
fn real_directory_flush_succeeds() {
    let directory = tempfile::tempdir().unwrap();

    sync_directory(directory.path()).unwrap();
}
