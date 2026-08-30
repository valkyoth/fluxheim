use std::os::windows::fs::OpenOptionsExt as _;
use std::path::{Component, Path, PathBuf};

use windows_permissions::constants::{
    AccessRights, AceFlags, AceType, SeObjectType, SecurityInformation,
};
use windows_permissions::{LocalBox, SecurityDescriptor, Sid};
use windows_sys::Win32::Foundation::GENERIC_WRITE;
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_READ_ATTRIBUTES, READ_CONTROL, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
};

const MAX_PERMISSION_INSPECTION_DEPTH: usize = 256;
const TRUSTED_INSTALLER_SID: &str =
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

#[derive(Clone, Copy)]
enum InspectedPathRole {
    ExistingObject,
    CreationParent,
    Ancestor,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum TrustPolicy {
    IntegrityOnly,
    ConfidentialSecret,
}

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
    if existing_parent_has_insecure_write_permissions(path)? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "confidential file has an untrusted parent ACL",
        ));
    }
    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .security_qos_flags(SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION);
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if metadata_is_reparse_point(&metadata) || !metadata.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "confidential path is a reparse point or is not a regular file",
        ));
    }
    if same_file::Handle::from_path(path)? != same_file::Handle::from_file(file.try_clone()?)? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "confidential path changed during secure open",
        ));
    }
    if opened_file_has_insecure_confidential_permissions(&file)? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "confidential file has an untrusted ACL",
        ));
    }
    Ok(file)
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

pub fn sync_directory(path: &Path) -> std::io::Result<()> {
    let directory = open_path_for_directory_sync(path)?;
    let metadata = directory.metadata()?;
    if metadata_is_reparse_point(&metadata) || !metadata.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "directory sync target is a reparse point or is not a directory",
        ));
    }
    if same_file::Handle::from_path(path)? != same_file::Handle::from_file(directory.try_clone()?)?
    {
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
    use windows_sys::Win32::Storage::FileSystem::WRITE_DAC;

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

fn security_descriptor_is_insecure(
    descriptor: &SecurityDescriptor,
    role: InspectedPathRole,
    policy: TrustPolicy,
) -> std::io::Result<bool> {
    let trusted_sids = trusted_sids()?;
    let Some(owner) = descriptor.owner() else {
        return Ok(true);
    };
    if !sid_is_trusted(owner, &trusted_sids) {
        return Ok(true);
    }
    let Some(dacl) = descriptor.dacl() else {
        return Ok(true);
    };
    let dangerous_rights = dangerous_rights(role, policy);
    for index in 0..dacl.len() {
        let Some(ace) = dacl.get_ace(index) else {
            return Ok(true);
        };
        if ace.flags().contains(AceFlags::InheritOnly) || !ace_is_allow(ace.ace_type()) {
            continue;
        }
        if !ace.mask().intersects(dangerous_rights) {
            continue;
        }
        let Some(sid) = ace.sid() else {
            return Ok(true);
        };
        if !sid_is_trusted(sid, &trusted_sids) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn dangerous_rights(role: InspectedPathRole, policy: TrustPolicy) -> AccessRights {
    let takeover = AccessRights::GenericAll
        | AccessRights::Delete
        | AccessRights::WriteDac
        | AccessRights::WriteOwner
        | AccessRights::Bit6;
    let writes = match role {
        InspectedPathRole::Ancestor => takeover | AccessRights::Bit6,
        InspectedPathRole::ExistingObject | InspectedPathRole::CreationParent => {
            takeover
                | AccessRights::GenericWrite
                | AccessRights::Bit1
                | AccessRights::Bit2
                | AccessRights::Bit4
                | AccessRights::Bit8
        }
    };
    if policy == TrustPolicy::ConfidentialSecret {
        writes
            | AccessRights::GenericRead
            | AccessRights::FileGenericRead
            | AccessRights::Bit0
            | AccessRights::Bit3
    } else {
        writes
    }
}

fn ace_is_allow(ace_type: AceType) -> bool {
    matches!(
        ace_type,
        AceType::ACCESS_ALLOWED_ACE_TYPE
            | AceType::ACCESS_ALLOWED_CALLBACK_ACE_TYPE
            | AceType::ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE
            | AceType::ACCESS_ALLOWED_OBJECT_ACE_TYPE
    )
}

fn trusted_sids() -> std::io::Result<Vec<LocalBox<Sid>>> {
    Ok(vec![
        windows_permissions::utilities::current_process_sid()?,
        parse_sid("S-1-5-18")?,
        parse_sid("S-1-5-32-544")?,
        parse_sid(TRUSTED_INSTALLER_SID)?,
    ])
}

fn parse_sid(value: &str) -> std::io::Result<LocalBox<Sid>> {
    value.parse()
}

fn sid_is_trusted(sid: &Sid, trusted_sids: &[LocalBox<Sid>]) -> bool {
    trusted_sids.iter().any(|trusted| sid == trusted.as_ref())
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
