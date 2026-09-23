pub use smb_dtyp::{
    ACE, ACL, AccessAce, AccessCallbackAce, AccessMask, AccessObjectAce, AccessObjectCallbackAce,
    AceFlags, AceType, AceValue, AclRevision, SID, SecurityDescriptor, SecurityDescriptorControl,
};

use super::{Operation, Resource, Share, SharePath};

fn ace_trustee_sid(ace: &ACE) -> &SID {
    match &ace.value {
        AceValue::AccessAllowed(value)
        | AceValue::AccessDenied(value)
        | AceValue::SystemAudit(value)
        | AceValue::SystemScopedPolicyId(value) => &value.sid,
        AceValue::AccessAllowedObject(value)
        | AceValue::AccessDeniedObject(value)
        | AceValue::SystemAuditObject(value) => &value.sid,
        AceValue::AccessAllowedCallback(value)
        | AceValue::AccessDeniedCallback(value)
        | AceValue::SystemAuditCallback(value) => &value.sid,
        AceValue::AccessAllowedCallbackObject(value)
        | AceValue::AccessDeniedCallbackObject(value)
        | AceValue::SystemAuditCallbackObject(value) => &value.sid,
        AceValue::SystemMandatoryLabel(value) => &value.sid,
        AceValue::SystemResourceAttribute(value) => &value.sid,
    }
}

fn is_supported_acl_trustee_sid(sid: &SID) -> bool {
    let account_domain = sid.identifier_authority == 5
        && sid.sub_authority.first() == Some(&21)
        && sid.sub_authority.len() >= 5;
    let posix_mapped =
        sid.identifier_authority == 22 && matches!(sid.sub_authority.as_slice(), [1 | 2, _]);
    let everyone = sid.identifier_authority == 1 && sid.sub_authority.as_slice() == [0];
    let local_system = sid.identifier_authority == 5 && sid.sub_authority.as_slice() == [18];
    account_domain || posix_mapped || everyone || local_system
}

fn retain_supported_aces(descriptor: &mut SecurityDescriptor) {
    if let Some(dacl) = descriptor.dacl.as_mut() {
        dacl.ace
            .retain(|ace| is_supported_acl_trustee_sid(ace_trustee_sid(ace)));
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SecuritySelection {
    dacl: bool,
}

impl SecuritySelection {
    pub const fn dacl(mut self, include: bool) -> Self {
        self.dacl = include;
        self
    }

    pub const fn includes_dacl(self) -> bool {
        self.dacl
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SecurityOpenOptions {
    write_dacl: bool,
}

impl SecurityOpenOptions {
    pub const fn write_dacl(mut self, write: bool) -> Self {
        self.write_dacl = write;
        self
    }

    pub(crate) const fn writes_dacl(self) -> bool {
        self.write_dacl
    }
}

impl Resource {
    pub fn query_security(
        &self,
        selection: SecuritySelection,
    ) -> Operation<'_, SecurityDescriptor> {
        Operation::new(move |context| {
            Box::pin(async move {
                context.remaining()?;
                let mut descriptor = match self {
                    Resource::File(file) => file.inner.query_security(selection.dacl).await,
                    Resource::Directory(directory) => {
                        directory.inner.query_security(selection.dacl).await
                    }
                    Resource::Pipe(pipe) => pipe.inner.query_security(selection.dacl).await,
                }?;
                retain_supported_aces(&mut descriptor);
                Ok(descriptor)
            })
        })
    }

    pub fn set_security(
        &self,
        descriptor: SecurityDescriptor,
        selection: SecuritySelection,
    ) -> Operation<'_, ()> {
        Operation::new(move |context| {
            Box::pin(async move {
                context.remaining()?;
                let mut descriptor = descriptor;
                retain_supported_aces(&mut descriptor);
                match self {
                    Resource::File(file) => {
                        file.inner.set_security(descriptor, selection.dacl).await
                    }
                    Resource::Directory(directory) => {
                        directory
                            .inner
                            .set_security(descriptor, selection.dacl)
                            .await
                    }
                    Resource::Pipe(pipe) => {
                        pipe.inner.set_security(descriptor, selection.dacl).await
                    }
                }
            })
        })
    }
}

impl Share {
    /// Reads the selected security information for one path.
    ///
    /// The temporary SMB handle is opened, queried, and closed inside this
    /// operation. Before returning, smb-rs retains account-domain and
    /// POSIX-mapped user/group ACEs plus the `Everyone` and `SYSTEM` ACEs.
    /// Other non-account trustees are omitted. The interface remains
    /// transparent to the server's backing ACL implementation and does not
    /// expose an ACL-style discriminator.
    pub fn query_security<'a>(
        &'a self,
        path: &'a SharePath,
        selection: SecuritySelection,
    ) -> Operation<'a, SecurityDescriptor> {
        Operation::new(move |context| {
            Box::pin(async move {
                context.remaining()?;
                let mut descriptor = self
                    .inner
                    .runtime
                    .query_path_security(path.as_str(), selection.dacl)
                    .await?;
                retain_supported_aces(&mut descriptor);
                Ok(descriptor)
            })
        })
    }

    /// Replaces the selected security information for one path.
    ///
    /// For a selected DACL, the descriptor's `dacl_protected` control bit is
    /// sent as the corresponding protected/unprotected security-information
    /// flag. The server performs one SMB `SET_INFO`; this method does not
    /// merge, reorder, or translate retained ACEs. Account-domain and
    /// POSIX-mapped user/group ACEs plus `Everyone` and `SYSTEM` are retained;
    /// other non-account trustees are omitted before the request is sent.
    /// Windows and POSIX-mapped servers therefore use this same atomic
    /// interface without exposing a server-style discriminator.
    pub fn set_security<'a>(
        &'a self,
        path: &'a SharePath,
        descriptor: SecurityDescriptor,
        selection: SecuritySelection,
    ) -> Operation<'a, ()> {
        Operation::new(move |context| {
            Box::pin(async move {
                context.remaining()?;
                let mut descriptor = descriptor;
                retain_supported_aces(&mut descriptor);
                self.inner
                    .runtime
                    .set_path_security(path.as_str(), descriptor, selection.dacl)
                    .await
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    fn allow(sid: &str) -> ACE {
        ACE {
            ace_flags: AceFlags::new(),
            value: AceValue::AccessAllowed(AccessAce {
                access_mask: AccessMask::from_bytes(0x001f_01ff_u32.to_le_bytes()),
                sid: SID::from_str(sid).unwrap(),
            }),
        }
    }

    #[test]
    fn only_accounts_everyone_and_system_are_retained_without_exposing_acl_style() {
        let mut descriptor = SecurityDescriptor {
            sbz1: 0,
            control: SecurityDescriptorControl::new()
                .with_self_relative(true)
                .with_dacl_present(true),
            owner_sid: None,
            group_sid: None,
            sacl: None,
            dacl: Some(ACL {
                acl_revision: AclRevision::Nt4,
                ace: vec![
                    allow("S-1-5-21-100-200-300-1001"),
                    allow("S-1-22-1-1000"),
                    allow("S-1-22-2-4001"),
                    allow("S-1-1-0"),
                    allow("S-1-5-11"),
                    allow("S-1-5-18"),
                    allow("S-1-5-32-544"),
                ],
            }),
        };

        retain_supported_aces(&mut descriptor);

        let trustees = descriptor
            .dacl
            .unwrap()
            .ace
            .into_iter()
            .map(|ace| ace.value.unwrap_access_allowed().sid.to_string())
            .collect::<Vec<_>>();
        assert_eq!(
            trustees,
            [
                "S-1-5-21-100-200-300-1001",
                "S-1-22-1-1000",
                "S-1-22-2-4001",
                "S-1-1-0",
                "S-1-5-18",
            ]
        );
    }
}
