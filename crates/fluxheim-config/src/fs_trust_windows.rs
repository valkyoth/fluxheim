use std::path::{Component, Path, PathBuf};

use windows_permissions::constants::{AccessRights, AceFlags, AceType, SecurityInformation};
use windows_permissions::{LocalBox, SecurityDescriptor, Sid, WindowsSecure as _};
use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

const MAX_PERMISSION_INSPECTION_DEPTH: usize = 256;
const TRUSTED_INSTALLER_SID: &str =
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

#[derive(Clone, Copy)]
enum InspectedPathRole {
    ExistingObject,
    CreationParent,
    Ancestor,
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

pub(crate) fn opened_file_has_insecure_owner_or_write_permissions(
    file: &std::fs::File,
) -> std::io::Result<bool> {
    let metadata = file.metadata()?;
    if metadata_is_reparse_point(&metadata) || !metadata.is_file() {
        return Ok(true);
    }
    let descriptor =
        file.security_descriptor(SecurityInformation::Owner | SecurityInformation::Dacl)?;
    security_descriptor_is_insecure(&descriptor, InspectedPathRole::ExistingObject)
}

fn existing_path_has_insecure_write_permissions(path: &Path) -> std::io::Result<bool> {
    let mut current = absolute_path(path)?;
    let mut inspected_depth = 0usize;
    let mut missing_component = false;

    loop {
        check_inspection_depth(&mut inspected_depth)?;
        match std::fs::symlink_metadata(&current) {
            Ok(_) => break,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                missing_component = true;
                if !current.pop() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "path has no existing ancestor",
                    ));
                }
            }
            Err(error) => return Err(error),
        }
    }

    let mut role = if missing_component {
        InspectedPathRole::CreationParent
    } else {
        InspectedPathRole::ExistingObject
    };
    loop {
        check_inspection_depth(&mut inspected_depth)?;
        let metadata = std::fs::symlink_metadata(&current)?;
        if metadata_is_reparse_point(&metadata) {
            return Ok(true);
        }
        let descriptor = current
            .as_os_str()
            .security_descriptor(SecurityInformation::Owner | SecurityInformation::Dacl)?;
        if security_descriptor_is_insecure(&descriptor, role)? {
            return Ok(true);
        }
        role = InspectedPathRole::Ancestor;
        if !current.pop() {
            return Ok(false);
        }
    }
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
    let dangerous_rights = dangerous_rights(role);
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

fn dangerous_rights(role: InspectedPathRole) -> AccessRights {
    let takeover = AccessRights::GenericAll
        | AccessRights::Delete
        | AccessRights::WriteDac
        | AccessRights::WriteOwner;
    match role {
        InspectedPathRole::Ancestor => takeover | AccessRights::Bit6,
        InspectedPathRole::ExistingObject | InspectedPathRole::CreationParent => {
            takeover
                | AccessRights::GenericWrite
                | AccessRights::Bit1
                | AccessRights::Bit2
                | AccessRights::Bit4
                | AccessRights::Bit8
        }
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
mod tests {
    use super::{
        existing_path_has_insecure_write_permissions,
        opened_file_has_insecure_owner_or_write_permissions,
    };
    use windows_permissions::{LocalBox, SecurityDescriptor, WindowsSecure as _};

    #[test]
    fn default_temporary_file_is_trusted() {
        let file = tempfile::NamedTempFile::new().unwrap();

        assert!(!existing_path_has_insecure_write_permissions(file.path()).unwrap());
        assert!(!opened_file_has_insecure_owner_or_write_permissions(file.as_file()).unwrap());
    }

    #[test]
    fn everyone_write_access_is_rejected() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let current = windows_permissions::utilities::current_process_sid().unwrap();
        let descriptor: LocalBox<SecurityDescriptor> = format!(
            "D:P(A;;FA;;;{})(A;;FA;;;SY)(A;;FA;;;BA)(A;;FW;;;WD)",
            current
        )
        .parse()
        .unwrap();
        let mut opened = file.reopen().unwrap();
        opened.set_dacl(descriptor.dacl().unwrap()).unwrap();

        assert!(opened_file_has_insecure_owner_or_write_permissions(&opened).unwrap());
    }

    #[test]
    fn everyone_read_access_is_accepted() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let current = windows_permissions::utilities::current_process_sid().unwrap();
        let descriptor: LocalBox<SecurityDescriptor> = format!(
            "D:P(A;;FA;;;{})(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;WD)",
            current
        )
        .parse()
        .unwrap();
        let mut opened = file.reopen().unwrap();
        opened.set_dacl(descriptor.dacl().unwrap()).unwrap();

        assert!(!opened_file_has_insecure_owner_or_write_permissions(&opened).unwrap());
    }
}
