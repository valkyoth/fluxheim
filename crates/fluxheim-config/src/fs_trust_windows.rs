use std::path::{Component, Path, PathBuf};

use windows_permissions::constants::{SeObjectType, SecurityInformation};
use windows_permissions::{LocalBox, SecurityDescriptor};
use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

#[path = "fs_trust_windows_acl.rs"]
mod acl;
use acl::{InspectedPathRole, TrustPolicy, security_descriptor_is_insecure};

pub fn existing_parent_has_insecure_write_permissions(path: &Path) -> std::io::Result<bool> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    existing_path_has_insecure_write_permissions(parent)
}

pub fn existing_path_or_parent_has_insecure_write_permissions(
    path: &Path,
) -> std::io::Result<bool> {
    existing_path_has_insecure_write_permissions(path)
}

pub fn opened_file_has_insecure_owner_or_write_permissions(
    file: &std::fs::File,
) -> std::io::Result<bool> {
    opened_file_has_insecure_permissions(file, TrustPolicy::IntegrityOnly)
}

pub fn opened_file_has_insecure_confidential_permissions(
    file: &std::fs::File,
) -> std::io::Result<bool> {
    opened_file_has_insecure_permissions(file, TrustPolicy::ConfidentialSecret)
}

pub fn open_confidential_file(path: &Path) -> std::io::Result<std::fs::File> {
    open_existing_regular_file(path, false, TrustPolicy::ConfidentialSecret)
}

pub fn open_regular_file(path: &Path) -> std::io::Result<std::fs::File> {
    open_existing_regular_file(path, false, TrustPolicy::IntegrityOnly)
}

pub fn open_regular_file_for_update(path: &Path) -> std::io::Result<std::fs::File> {
    open_existing_regular_file(path, true, TrustPolicy::IntegrityOnly)
}

pub fn existing_path_is_non_regular_file(path: &Path) -> std::io::Result<bool> {
    let absolute = absolute_path(path)?;
    let opened = fluxheim_windows_security::inspect_absolute_path(&absolute)?;
    if !opened.target_exists() {
        return Ok(false);
    }
    let metadata = opened.target()?.metadata()?;
    Ok(!metadata.is_file())
}

pub fn create_regular_file(path: &Path, read: bool) -> std::io::Result<std::fs::File> {
    let absolute = absolute_path(path)?;
    let opened =
        fluxheim_windows_security::create_new_regular_file_with_ancestors(&absolute, read)?;
    let ancestor_count = opened.handles().len().saturating_sub(1);
    let insecure_parent = match retained_handles_have_insecure_permissions(
        &opened.handles()[..ancestor_count],
        InspectedPathRole::CreationParent,
        TrustPolicy::IntegrityOnly,
    ) {
        Ok(insecure) => insecure,
        Err(error) => return Err(reject_created_file(&opened, error)),
    };
    if insecure_parent {
        return Err(reject_created_file(
            &opened,
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "new file has an untrusted parent ACL",
            ),
        ));
    }
    opened.into_target()
}

pub fn open_or_create_regular_file(path: &Path) -> std::io::Result<std::fs::File> {
    match create_regular_file(path, true) {
        Ok(file) => Ok(file),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            open_regular_file_for_update(path)
        }
        Err(error) => Err(error),
    }
}

pub fn create_confidential_file(path: &Path) -> std::io::Result<std::fs::File> {
    let absolute = absolute_path(path)?;
    let mut opened =
        fluxheim_windows_security::create_new_exclusive_regular_file_with_ancestors(&absolute)?;
    let ancestor_count = opened.handles().len().saturating_sub(1);
    let insecure_parent = match retained_handles_have_insecure_permissions(
        &opened.handles()[..ancestor_count],
        InspectedPathRole::CreationParent,
        TrustPolicy::IntegrityOnly,
    ) {
        Ok(insecure) => insecure,
        Err(error) => return Err(reject_created_file(&opened, error)),
    };
    if insecure_parent {
        return Err(reject_created_file(
            &opened,
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "confidential file has an untrusted parent ACL",
            ),
        ));
    }
    if let Err(error) = opened.target_mut().and_then(harden_object) {
        return Err(reject_created_file(&opened, error));
    }
    match opened
        .target()
        .and_then(opened_file_has_insecure_confidential_permissions)
    {
        Ok(false) => {}
        Ok(true) => {
            return Err(reject_created_file(
                &opened,
                std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "new confidential file retained an untrusted ACL after hardening",
                ),
            ));
        }
        Err(error) => return Err(reject_created_file(&opened, error)),
    }
    opened.into_target()
}

pub fn open_or_create_confidential_file(path: &Path) -> std::io::Result<std::fs::File> {
    match create_confidential_file(path) {
        Ok(file) => {
            drop(file);
            open_existing_regular_file(path, true, TrustPolicy::ConfidentialSecret)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            open_existing_regular_file(path, true, TrustPolicy::ConfidentialSecret)
        }
        Err(error) => Err(error),
    }
}

fn open_existing_regular_file(
    path: &Path,
    write: bool,
    policy: TrustPolicy,
) -> std::io::Result<std::fs::File> {
    let absolute = absolute_path(path)?;
    let opened =
        fluxheim_windows_security::open_existing_regular_file_with_ancestors(&absolute, write)?;
    if retained_handles_have_insecure_permissions(
        opened.handles(),
        InspectedPathRole::ExistingObject,
        policy,
    )? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            if policy == TrustPolicy::ConfidentialSecret {
                "confidential file has an untrusted owner, ACL, or parent ACL"
            } else {
                "file has an untrusted owner, ACL, or parent ACL"
            },
        ));
    }
    opened.into_target()
}

fn opened_file_has_insecure_permissions(
    file: &std::fs::File,
    policy: TrustPolicy,
) -> std::io::Result<bool> {
    let metadata = file.metadata()?;
    if metadata_is_reparse_point(&metadata) || !metadata.is_file() {
        return Ok(true);
    }
    let descriptor = file_security_descriptor(file)?;
    security_descriptor_is_insecure(&descriptor, InspectedPathRole::ExistingObject, policy)
}

pub fn harden_confidential_file(file: &mut std::fs::File) -> std::io::Result<()> {
    harden_object(file)
}

pub fn harden_private_directory(path: &Path) -> std::io::Result<()> {
    let mut directory = open_path_for_acl_update(path)?;
    let metadata = directory.metadata()?;
    if metadata_is_reparse_point(&metadata) || !metadata.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "private directory is a reparse point or is not a directory",
        ));
    }
    harden_object(&mut directory)
}

pub fn create_private_directory_all(path: &Path) -> std::io::Result<()> {
    if existing_path_has_insecure_write_permissions(path)? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "private directory has an untrusted creation parent ACL",
        ));
    }
    let absolute = absolute_path(path)?;
    let mut current = PathBuf::new();
    for component in absolute.components() {
        current.push(component.as_os_str());
        if matches!(component, Component::Prefix(_) | Component::RootDir) {
            continue;
        }
        let inspected = fluxheim_windows_security::inspect_absolute_path(&current)?;
        if inspected.target_exists() {
            let directory = inspected.into_target()?;
            let metadata = directory.metadata()?;
            if metadata_is_reparse_point(&metadata) || !metadata.is_dir() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "private directory component is a reparse point or not a directory",
                ));
            }
        } else {
            match fluxheim_windows_security::create_private_directory(&current) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    let raced = fluxheim_windows_security::inspect_absolute_path(&current)?;
                    if !raced.target_exists() {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::NotFound,
                            "private directory creation raced with a missing object",
                        ));
                    }
                    let directory = raced.into_target()?;
                    let metadata = directory.metadata()?;
                    if metadata_is_reparse_point(&metadata) || !metadata.is_dir() {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::PermissionDenied,
                            "private directory creation raced with an unsafe object",
                        ));
                    }
                }
                Err(error) => return Err(error),
            }
        }
    }
    harden_private_directory(&absolute)
}

pub fn sync_directory(path: &Path) -> std::io::Result<()> {
    let absolute = absolute_path(path)?;
    let opened = fluxheim_windows_security::open_existing_directory_for_sync(&absolute)?;
    if retained_handles_have_insecure_permissions(
        opened.handles(),
        InspectedPathRole::ExistingObject,
        TrustPolicy::IntegrityOnly,
    )? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "directory sync target has an untrusted ACL",
        ));
    }
    let directory = opened.into_target()?;
    let metadata = directory.metadata()?;
    if metadata_is_reparse_point(&metadata) || !metadata.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "directory sync target is a reparse point or is not a directory",
        ));
    }
    directory.sync_all()
}

fn harden_object<H: std::os::windows::io::AsRawHandle>(handle: &mut H) -> std::io::Result<()> {
    let current = windows_permissions::utilities::current_process_sid()?;
    let descriptor: LocalBox<SecurityDescriptor> =
        format!("D:P(A;;FA;;;{current})(A;;FA;;;SY)(A;;FA;;;BA)").parse()?;
    windows_permissions::wrappers::SetSecurityInfo(
        handle,
        SeObjectType::SE_FILE_OBJECT,
        SecurityInformation::Dacl | SecurityInformation::ProtectedDacl,
        None,
        None,
        descriptor.dacl(),
        None,
    )
}

fn existing_path_has_insecure_write_permissions(path: &Path) -> std::io::Result<bool> {
    let absolute = absolute_path(path)
        .map_err(|error| inspection_error("normalize ACL inspection path", error))?;
    let opened = fluxheim_windows_security::inspect_absolute_path(&absolute)
        .map_err(|error| inspection_error("open ACL inspection path", error))?;
    let role = if opened.target_exists() {
        InspectedPathRole::ExistingObject
    } else {
        InspectedPathRole::CreationParent
    };
    retained_handles_have_insecure_permissions(opened.handles(), role, TrustPolicy::IntegrityOnly)
}

fn retained_handles_have_insecure_permissions(
    handles: &[std::fs::File],
    first_role: InspectedPathRole,
    policy: TrustPolicy,
) -> std::io::Result<bool> {
    if handles.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "path has no existing ancestor",
        ));
    }
    for (index, opened) in handles.iter().rev().enumerate() {
        let metadata = opened
            .metadata()
            .map_err(|error| inspection_error("read ACL inspection metadata", error))?;
        if metadata_is_reparse_point(&metadata) {
            return Ok(true);
        }
        let descriptor = file_security_descriptor(opened)
            .map_err(|error| inspection_error("read ACL security descriptor", error))?;
        let role = if index == 0 {
            first_role
        } else {
            InspectedPathRole::Ancestor
        };
        // Confidentiality is enforced by the leaf file's protected DACL.
        // Ancestors only need integrity protection against replacement or
        // takeover; ordinary directory read/list access cannot expose the
        // protected file contents.
        let handle_policy = if index == 0 {
            policy
        } else {
            TrustPolicy::IntegrityOnly
        };
        if security_descriptor_is_insecure(&descriptor, role, handle_policy)
            .map_err(|error| inspection_error("evaluate ACL security descriptor", error))?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn inspection_error(operation: &'static str, error: std::io::Error) -> std::io::Error {
    std::io::Error::new(error.kind(), format!("{operation}: {error}"))
}

fn reject_created_file(
    opened: &fluxheim_windows_security::RetainedPathHandles,
    rejection: std::io::Error,
) -> std::io::Error {
    match opened
        .target()
        .and_then(fluxheim_windows_security::remove_open_regular_file)
    {
        Ok(()) => rejection,
        Err(cleanup) => std::io::Error::new(
            rejection.kind(),
            format!("{rejection}; rejected file cleanup failed: {cleanup}"),
        ),
    }
}

fn open_path_for_acl_update(path: &Path) -> std::io::Result<std::fs::File> {
    let absolute = absolute_path(path)?;
    fluxheim_windows_security::open_existing_directory_for_acl_update(&absolute)
}

fn file_security_descriptor(file: &std::fs::File) -> std::io::Result<LocalBox<SecurityDescriptor>> {
    windows_permissions::wrappers::GetSecurityInfo(
        file,
        SeObjectType::SE_FILE_OBJECT,
        SecurityInformation::Owner | SecurityInformation::Dacl,
    )
}

fn absolute_path(path: &Path) -> std::io::Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                normalized.push(component.as_os_str());
            }
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "path escapes its Windows volume root",
                    ));
                }
            }
        }
    }
    Ok(normalized)
}

fn metadata_is_reparse_point(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;

    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(test)]
#[path = "fs_trust_windows_tests.rs"]
mod tests;
