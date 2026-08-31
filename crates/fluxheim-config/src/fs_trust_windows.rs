use std::os::windows::fs::OpenOptionsExt as _;
use std::path::{Component, Path, PathBuf};

use windows_permissions::constants::{SeObjectType, SecurityInformation};
use windows_permissions::{LocalBox, SecurityDescriptor};
use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL,
    SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT, WRITE_DAC,
};

const MAX_PERMISSION_INSPECTION_DEPTH: usize = 256;
const DELETE_ACCESS: u32 = 0x0001_0000;

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

pub fn create_confidential_file(path: &Path) -> std::io::Result<std::fs::File> {
    // Inspect the missing child path so INHERIT_ONLY ACEs on its creation
    // parent are evaluated as permissions that would apply to the new file.
    if existing_path_has_insecure_write_permissions(path)? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "confidential file has an untrusted parent ACL",
        ));
    }
    let mut options = std::fs::OpenOptions::new();
    options
        .access_mode(GENERIC_READ | GENERIC_WRITE | DELETE_ACCESS | READ_CONTROL | WRITE_DAC)
        .create_new(true)
        .share_mode(0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .security_qos_flags(SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION);
    let mut file = options.open(path)?;
    if let Err(error) = verify_opened_regular_file(path, &file, None, "confidential") {
        let _ = fluxheim_windows_security::remove_open_regular_file(&file);
        return Err(error);
    }
    if let Err(error) = harden_object(&mut file) {
        let _ = fluxheim_windows_security::remove_open_regular_file(&file);
        return Err(error);
    }
    match opened_file_has_insecure_confidential_permissions(&file) {
        Ok(false) => {}
        Ok(true) => {
            let _ = fluxheim_windows_security::remove_open_regular_file(&file);
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "new confidential file retained an untrusted ACL after hardening",
            ));
        }
        Err(error) => {
            let _ = fluxheim_windows_security::remove_open_regular_file(&file);
            return Err(error);
        }
    }
    Ok(file)
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
    let expected = same_file::Handle::from_path(path)?;
    if existing_parent_has_insecure_write_permissions(path)? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "file has an untrusted parent ACL",
        ));
    }
    let mut options = std::fs::OpenOptions::new();
    let access =
        GENERIC_READ | READ_CONTROL | FILE_READ_ATTRIBUTES | if write { GENERIC_WRITE } else { 0 };
    options
        .access_mode(access)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .security_qos_flags(SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION);
    let file = options.open(path)?;
    verify_opened_regular_file(path, &file, Some(expected), "file")?;
    if opened_file_has_insecure_permissions(&file, policy)? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            if policy == TrustPolicy::ConfidentialSecret {
                "confidential file has an untrusted ACL"
            } else {
                "file has an untrusted ACL"
            },
        ));
    }
    Ok(file)
}

fn verify_opened_regular_file(
    path: &Path,
    file: &std::fs::File,
    expected: Option<same_file::Handle>,
    label: &str,
) -> std::io::Result<()> {
    let metadata = file.metadata()?;
    if metadata_is_reparse_point(&metadata) || !metadata.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("{label} path is a reparse point or is not a regular file"),
        ));
    }
    if let Some(expected) = expected
        && expected != same_file::Handle::from_file(file.try_clone()?)?
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "{label} path changed during secure open: {}",
                path.display()
            ),
        ));
    }
    Ok(())
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
        match open_path_for_trust_inspection(&current) {
            Ok(directory) => {
                let metadata = directory.metadata()?;
                if metadata_is_reparse_point(&metadata) || !metadata.is_dir() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "private directory component is a reparse point or not a directory",
                    ));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                match fluxheim_windows_security::create_private_directory(&current) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                        let directory = open_path_for_trust_inspection(&current)?;
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
            Err(error) => return Err(error),
        }
    }
    harden_private_directory(&absolute)
}

pub fn sync_directory(path: &Path) -> std::io::Result<()> {
    let expected = same_file::Handle::from_path(path)?;
    if existing_path_has_insecure_write_permissions(path)? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "directory sync target has an untrusted ACL",
        ));
    }
    let directory = open_path_for_directory_sync(path)?;
    let metadata = directory.metadata()?;
    if metadata_is_reparse_point(&metadata) || !metadata.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "directory sync target is a reparse point or is not a directory",
        ));
    }
    if expected != same_file::Handle::from_file(directory.try_clone()?)? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "directory sync target changed during secure open",
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
    let mut current = absolute_path(path)
        .map_err(|error| inspection_error("normalize ACL inspection path", error))?;
    let mut inspected_depth = 0usize;
    let mut missing_component = false;

    let mut opened = loop {
        check_inspection_depth(&mut inspected_depth)?;
        match open_path_for_trust_inspection(&current) {
            Ok(file) => break file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                missing_component = true;
                if !current.pop() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "path has no existing ancestor",
                    ));
                }
            }
            Err(error) => {
                return Err(inspection_error("open existing ACL inspection path", error));
            }
        }
    };

    let mut role = if missing_component {
        InspectedPathRole::CreationParent
    } else {
        InspectedPathRole::ExistingObject
    };
    loop {
        check_inspection_depth(&mut inspected_depth)?;
        let metadata = opened
            .metadata()
            .map_err(|error| inspection_error("read ACL inspection metadata", error))?;
        if metadata_is_reparse_point(&metadata) {
            return Ok(true);
        }
        let descriptor = file_security_descriptor(&opened)
            .map_err(|error| inspection_error("read ACL security descriptor", error))?;
        if security_descriptor_is_insecure(&descriptor, role, TrustPolicy::IntegrityOnly)
            .map_err(|error| inspection_error("evaluate ACL security descriptor", error))?
        {
            return Ok(true);
        }
        role = InspectedPathRole::Ancestor;
        if !current.pop() {
            return Ok(false);
        }
        opened = open_path_for_trust_inspection(&current)
            .map_err(|error| inspection_error("open ACL ancestor path", error))?;
    }
}

fn inspection_error(operation: &'static str, error: std::io::Error) -> std::io::Error {
    std::io::Error::new(error.kind(), format!("{operation}: {error}"))
}

fn open_path_for_trust_inspection(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options
        .access_mode(READ_CONTROL | FILE_READ_ATTRIBUTES)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .security_qos_flags(SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION);
    options.open(path)
}

fn open_path_for_acl_update(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options
        .access_mode(READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .security_qos_flags(SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION);
    options.open(path)
}

fn open_path_for_directory_sync(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options
        .access_mode(GENERIC_WRITE | READ_CONTROL | FILE_READ_ATTRIBUTES)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .security_qos_flags(SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION);
    options.open(path)
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

fn check_inspection_depth(inspected_depth: &mut usize) -> std::io::Result<()> {
    *inspected_depth = inspected_depth.saturating_add(1);
    if *inspected_depth > MAX_PERMISSION_INSPECTION_DEPTH {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "path exceeds maximum depth for permission inspection",
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "fs_trust_windows_tests.rs"]
mod tests;
