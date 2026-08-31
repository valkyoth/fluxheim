use windows_permissions::constants::{AccessRights, AceFlags, AceType};
use windows_permissions::{LocalBox, SecurityDescriptor, Sid};

const TRUSTED_INSTALLER_SID: &str =
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

#[derive(Clone, Copy)]
pub(super) enum InspectedPathRole {
    ExistingObject,
    CreationParent,
    Ancestor,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum TrustPolicy {
    IntegrityOnly,
    ConfidentialSecret,
}

pub(super) fn security_descriptor_is_insecure(
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
        if !ace_is_allow(ace.ace_type()) || ace_is_inapplicable(ace.flags(), role) {
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

fn ace_is_inapplicable(flags: AceFlags, role: InspectedPathRole) -> bool {
    if !flags.contains(AceFlags::InheritOnly) {
        return false;
    }
    !matches!(role, InspectedPathRole::CreationParent)
        || !flags.intersects(AceFlags::ObjectInherit | AceFlags::ContainerInherit)
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
