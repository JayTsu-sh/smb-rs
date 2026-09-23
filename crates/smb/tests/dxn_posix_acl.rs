//! DXN CIFS ACL acceptance for a Linux/POSIX-backed Samba share.
//!
//! The test never invents a Windows well-known trustee. It selects an existing
//! Samba Unix-group SID (`S-1-22-2-*`) from the server's own DACL and performs
//! every mutation with that already-resolved principal.

#![cfg(feature = "real-server-tests")]

mod common;

use smb::{
    ACE, AccessMask, AceFlags, Client, DirectoryOpenOptions, Error, FileOpenOptions, SID,
    SecurityDescriptor, SecuritySelection, Share, SharePath, ShareTarget,
};
use smb_msg::Status;

#[derive(Debug)]
struct PosixAclObservations {
    mapped_group_sid: String,
    parent_inheritable_ace_preserved: bool,
    child_directory_copied_parent_ace: bool,
    child_directory_marks_ace_inherited: bool,
    child_file_copied_parent_ace: bool,
    child_file_marks_ace_inherited: bool,
    file_self_dacl_roundtrip: bool,
    inheritance_disabled: bool,
    protected_child_blocks_parent_change: bool,
    existing_unprotected_file_tracks_parent_change: bool,
    new_sibling_copies_updated_parent_ace: bool,
    new_sibling_marks_ace_inherited: bool,
    inheritance_unprotected_without_merge: bool,
    unprotect_only_synthesizes_parent_change: bool,
    atomic_target_dacl_applied: bool,
}

#[test_log::test(tokio::test(flavor = "multi_thread"))]
#[ignore = "requires an isolated writable DXN Linux/POSIX-backed CIFS share with WRITE_DAC"]
async fn dxn_posix_mapped_acl_copy_protection_and_atomic_restore() -> smb::Result<()> {
    let client = Client::new();
    let share = client
        .connect_share(
            &ShareTarget::new(common::smb_tests_server(), common::smb_tests_share())?,
            common::smb_test_credentials(),
        )
        .await?;
    let suffix = format!("{}-{:08x}", std::process::id(), rand::random::<u32>());
    let parent_path = SharePath::new(format!("smb-rs-posix-acl-{suffix}"))?;
    let child_directory_path = SharePath::new(format!("{}\\directory", parent_path.as_str()))?;
    let sibling_directory_path = SharePath::new(format!("{}\\sibling", parent_path.as_str()))?;
    let child_file_path = SharePath::new(format!("{}\\file.bin", parent_path.as_str()))?;

    let observations = exercise_posix_acl(
        &share,
        &parent_path,
        &child_directory_path,
        &sibling_directory_path,
        &child_file_path,
    )
    .await;
    let cleanup = cleanup(
        &share,
        &parent_path,
        &child_directory_path,
        &sibling_directory_path,
        &child_file_path,
    )
    .await;
    let close_result = share.close().await;
    let client_close_result = client.close().await;

    let observations = observations?;
    record_observations(&observations);
    assert!(cleanup, "DXN POSIX ACL run left a residual object");
    close_result?;
    client_close_result?;
    assert!(
        observations.parent_inheritable_ace_preserved,
        "parent did not preserve OI/CI on its mapped-group ACE: {observations:?}"
    );
    assert!(
        observations.child_directory_copied_parent_ace,
        "child directory omitted the mapped-group parent ACE: {observations:?}"
    );
    assert!(
        observations.child_file_copied_parent_ace,
        "child file omitted the mapped-group parent ACE: {observations:?}"
    );
    assert!(
        observations.file_self_dacl_roundtrip,
        "file self DACL did not round-trip: {observations:?}"
    );
    assert!(
        observations.inheritance_disabled,
        "DACL protection was not preserved: {observations:?}"
    );
    assert!(
        observations.protected_child_blocks_parent_change,
        "protected child changed with its parent: {observations:?}"
    );
    assert!(
        observations.new_sibling_copies_updated_parent_ace,
        "new sibling omitted the updated mapped-group ACE: {observations:?}"
    );
    assert!(
        observations.inheritance_unprotected_without_merge,
        "clearing DACL_PROTECTED did not round-trip: {observations:?}"
    );
    assert!(
        observations.atomic_target_dacl_applied,
        "complete POSIX-style target DACL was not applied: {observations:?}"
    );
    Ok(())
}

async fn exercise_posix_acl(
    share: &Share,
    parent_path: &SharePath,
    child_directory_path: &SharePath,
    sibling_directory_path: &SharePath,
    child_file_path: &SharePath,
) -> smb::Result<PosixAclObservations> {
    let selection = SecuritySelection::default().dacl(true);
    let parent = share
        .open_directory(parent_path, DirectoryOpenOptions::create_new())
        .await?;
    parent.close().await?;

    let mut parent_descriptor = share.query_security(parent_path, selection).await?;
    record_descriptor("parent-before-posix-mutation", "parent", &parent_descriptor);
    let (mapped_group_sid, original_mask) = existing_unix_group_ace(&parent_descriptor)
        .ok_or_else(|| Error::InvalidState("server DACL has no S-1-22-2 mapped group".into()))?;
    update_allow_ace(
        &mut parent_descriptor,
        &mapped_group_sid,
        original_mask,
        AceFlags::new()
            .with_object_inherit(true)
            .with_container_inherit(true),
    )?;
    share
        .set_security(parent_path, parent_descriptor, selection)
        .await?;
    let parent_descriptor = share.query_security(parent_path, selection).await?;
    record_descriptor(
        "parent-after-posix-inheritable-ace",
        "parent",
        &parent_descriptor,
    );
    let parent_inheritable_ace_preserved = contains_allow_ace(
        &parent_descriptor,
        &mapped_group_sid,
        original_mask,
        Some((true, true, false)),
    );

    let child_directory = share
        .open_directory(child_directory_path, DirectoryOpenOptions::create_new())
        .await?;
    child_directory.close().await?;
    let child_file = share
        .open_file(child_file_path, FileOpenOptions::create_new())
        .await?;
    child_file.close().await?;

    let mut child_directory_descriptor = share
        .query_security(child_directory_path, selection)
        .await?;
    record_descriptor(
        "child-directory-after-create",
        "child-directory",
        &child_directory_descriptor,
    );
    let child_directory_copied_parent_ace = contains_allow_ace(
        &child_directory_descriptor,
        &mapped_group_sid,
        original_mask,
        None,
    );
    let child_directory_marks_ace_inherited = matching_allow_ace(
        &child_directory_descriptor,
        &mapped_group_sid,
        original_mask,
    )
    .is_some_and(|ace| ace.ace_flags.inherited());

    let child_file_descriptor = share.query_security(child_file_path, selection).await?;
    record_descriptor(
        "child-file-after-create",
        "child-file",
        &child_file_descriptor,
    );
    let child_file_copied_parent_ace = contains_allow_ace(
        &child_file_descriptor,
        &mapped_group_sid,
        original_mask,
        None,
    );
    let child_file_marks_ace_inherited =
        matching_allow_ace(&child_file_descriptor, &mapped_group_sid, original_mask)
            .is_some_and(|ace| ace.ace_flags.inherited());

    share
        .set_security(child_file_path, child_file_descriptor.clone(), selection)
        .await?;
    let child_file_after_self_set = share.query_security(child_file_path, selection).await?;
    record_descriptor(
        "child-file-after-self-dacl-roundtrip",
        "child-file",
        &child_file_after_self_set,
    );
    let file_self_dacl_roundtrip = child_file_after_self_set == child_file_descriptor;

    for ace in child_directory_descriptor
        .dacl
        .iter_mut()
        .flat_map(|dacl| &mut dacl.ace)
    {
        ace.ace_flags = ace.ace_flags.with_inherited(false);
    }
    child_directory_descriptor.control =
        child_directory_descriptor.control.with_dacl_protected(true);
    share
        .set_security(child_directory_path, child_directory_descriptor, selection)
        .await?;
    let protected_child = share
        .query_security(child_directory_path, selection)
        .await?;
    record_descriptor(
        "child-directory-after-protect",
        "child-directory",
        &protected_child,
    );
    let inheritance_disabled = protected_child.control.dacl_protected();

    let updated_mask = original_mask | 0x0000_0040;
    let mut updated_parent = parent_descriptor;
    update_allow_ace(
        &mut updated_parent,
        &mapped_group_sid,
        updated_mask,
        AceFlags::new()
            .with_object_inherit(true)
            .with_container_inherit(true),
    )?;
    share
        .set_security(parent_path, updated_parent, selection)
        .await?;
    let updated_parent = share.query_security(parent_path, selection).await?;
    record_descriptor("parent-after-posix-mask-change", "parent", &updated_parent);

    let protected_child_after_parent_change = share
        .query_security(child_directory_path, selection)
        .await?;
    record_descriptor(
        "protected-child-after-parent-change",
        "child-directory",
        &protected_child_after_parent_change,
    );
    let protected_child_blocks_parent_change = contains_allow_ace(
        &protected_child_after_parent_change,
        &mapped_group_sid,
        original_mask,
        None,
    ) && !contains_allow_ace(
        &protected_child_after_parent_change,
        &mapped_group_sid,
        updated_mask,
        None,
    );

    let existing_file_after_parent_change =
        share.query_security(child_file_path, selection).await?;
    record_descriptor(
        "existing-child-file-after-parent-change",
        "child-file",
        &existing_file_after_parent_change,
    );
    let existing_unprotected_file_tracks_parent_change = contains_allow_ace(
        &existing_file_after_parent_change,
        &mapped_group_sid,
        updated_mask,
        None,
    );

    let sibling = share
        .open_directory(sibling_directory_path, DirectoryOpenOptions::create_new())
        .await?;
    sibling.close().await?;
    let sibling_descriptor = share
        .query_security(sibling_directory_path, selection)
        .await?;
    record_descriptor(
        "sibling-directory-after-create",
        "sibling-directory",
        &sibling_descriptor,
    );
    let new_sibling_copies_updated_parent_ace =
        contains_allow_ace(&sibling_descriptor, &mapped_group_sid, updated_mask, None);
    let new_sibling_marks_ace_inherited =
        matching_allow_ace(&sibling_descriptor, &mapped_group_sid, updated_mask)
            .is_some_and(|ace| ace.ace_flags.inherited());

    let mut unprotected_child = protected_child_after_parent_change;
    unprotected_child.control = unprotected_child.control.with_dacl_protected(false);
    share
        .set_security(child_directory_path, unprotected_child, selection)
        .await?;
    let unprotected_child = share
        .query_security(child_directory_path, selection)
        .await?;
    record_descriptor(
        "child-directory-after-unprotect-only",
        "child-directory",
        &unprotected_child,
    );
    let inheritance_unprotected_without_merge = !unprotected_child.control.dacl_protected();
    let unprotect_only_synthesizes_parent_change =
        contains_allow_ace(&unprotected_child, &mapped_group_sid, updated_mask, None);

    let mut atomic_target = unprotected_child;
    update_allow_ace(
        &mut atomic_target,
        &mapped_group_sid,
        updated_mask,
        AceFlags::new()
            .with_object_inherit(true)
            .with_container_inherit(true),
    )?;
    share
        .set_security(child_directory_path, atomic_target, selection)
        .await?;
    let atomic_target = share
        .query_security(child_directory_path, selection)
        .await?;
    record_descriptor(
        "child-directory-after-atomic-target-dacl",
        "child-directory",
        &atomic_target,
    );
    let atomic_target_dacl_applied = contains_allow_ace(
        &atomic_target,
        &mapped_group_sid,
        updated_mask,
        Some((true, true, false)),
    ) && !atomic_target.control.dacl_protected();

    Ok(PosixAclObservations {
        mapped_group_sid: mapped_group_sid.to_string(),
        parent_inheritable_ace_preserved,
        child_directory_copied_parent_ace,
        child_directory_marks_ace_inherited,
        child_file_copied_parent_ace,
        child_file_marks_ace_inherited,
        file_self_dacl_roundtrip,
        inheritance_disabled,
        protected_child_blocks_parent_change,
        existing_unprotected_file_tracks_parent_change,
        new_sibling_copies_updated_parent_ace,
        new_sibling_marks_ace_inherited,
        inheritance_unprotected_without_merge,
        unprotect_only_synthesizes_parent_change,
        atomic_target_dacl_applied,
    })
}

fn existing_unix_group_ace(descriptor: &SecurityDescriptor) -> Option<(SID, u32)> {
    descriptor.dacl.as_ref()?.ace.iter().find_map(|ace| {
        let access = ace.value.as_access_allowed()?;
        (access.sid.identifier_authority == 22
            && access.sid.sub_authority.first() == Some(&2)
            && access.sid.sub_authority.len() == 2)
            .then(|| {
                (
                    access.sid.clone(),
                    u32::from_le_bytes(access.access_mask.into_bytes()),
                )
            })
    })
}

fn update_allow_ace(
    descriptor: &mut SecurityDescriptor,
    sid: &SID,
    mask: u32,
    flags: AceFlags,
) -> smb::Result<()> {
    let ace = descriptor
        .dacl
        .as_mut()
        .and_then(|dacl| {
            dacl.ace.iter_mut().find(|ace| {
                ace.value
                    .as_access_allowed()
                    .is_some_and(|access| access.sid == *sid)
            })
        })
        .ok_or_else(|| Error::InvalidState("mapped group ACE disappeared".into()))?;
    ace.ace_flags = flags;
    ace.value
        .as_mut_access_allowed()
        .expect("selected ACE remains AccessAllowed")
        .access_mask = AccessMask::from_bytes(mask.to_le_bytes());
    Ok(())
}

fn matching_allow_ace<'a>(
    descriptor: &'a SecurityDescriptor,
    sid: &SID,
    mask: u32,
) -> Option<&'a ACE> {
    descriptor.dacl.as_ref()?.ace.iter().find(|ace| {
        ace.value.as_access_allowed().is_some_and(|access| {
            access.sid == *sid && u32::from_le_bytes(access.access_mask.into_bytes()) == mask
        })
    })
}

fn contains_allow_ace(
    descriptor: &SecurityDescriptor,
    sid: &SID,
    mask: u32,
    flags: Option<(bool, bool, bool)>,
) -> bool {
    matching_allow_ace(descriptor, sid, mask).is_some_and(|ace| {
        flags.is_none_or(|(object_inherit, container_inherit, inherited)| {
            ace.ace_flags.object_inherit() == object_inherit
                && ace.ace_flags.container_inherit() == container_inherit
                && ace.ace_flags.inherited() == inherited
        })
    })
}

fn record_descriptor(stage: &str, path_role: &str, descriptor: &SecurityDescriptor) {
    let aces = descriptor
        .dacl
        .as_ref()
        .map(|dacl| {
            dacl.ace
                .iter()
                .enumerate()
                .map(|(index, ace)| {
                    let (trustee_sid, access_mask) = ace
                        .value
                        .as_access_allowed()
                        .or_else(|| ace.value.as_access_denied())
                        .map(|access| {
                            (
                                Some(access.sid.to_string()),
                                Some(format!(
                                    "0x{:08x}",
                                    u32::from_le_bytes(access.access_mask.into_bytes())
                                )),
                            )
                        })
                        .unwrap_or((None, None));
                    serde_json::json!({
                        "index": index,
                        "type": format!("{:?}", ace.ace_type()),
                        "trustee_sid": trustee_sid,
                        "access_mask": access_mask,
                        "flags": {
                            "object_inherit": ace.ace_flags.object_inherit(),
                            "container_inherit": ace.ace_flags.container_inherit(),
                            "no_propagate_inherit": ace.ace_flags.no_propagate_inherit(),
                            "inherit_only": ace.ace_flags.inherit_only(),
                            "inherited": ace.ace_flags.inherited(),
                        }
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    println!(
        "ACL_RECORD {}",
        serde_json::json!({
            "record_type": "acl_descriptor",
            "stage": stage,
            "path_role": path_role,
            "control": {
                "raw_le_hex": format!(
                    "0x{:04x}",
                    u16::from_le_bytes(descriptor.control.into_bytes())
                ),
                "dacl_present": descriptor.control.dacl_present(),
                "dacl_auto_inherited": descriptor.control.dacl_auto_inherited(),
                "dacl_protected": descriptor.control.dacl_protected(),
            },
            "dacl": { "ace_count": aces.len(), "aces": aces },
        })
    );
}

fn record_observations(observations: &PosixAclObservations) {
    println!(
        "ACL_RECORD {}",
        serde_json::json!({
            "record_type": "acl_observations",
            "mapped_group_sid": observations.mapped_group_sid,
            "parent_inheritable_ace_preserved": observations.parent_inheritable_ace_preserved,
            "child_directory_copied_parent_ace": observations.child_directory_copied_parent_ace,
            "child_directory_marks_ace_inherited": observations.child_directory_marks_ace_inherited,
            "child_file_copied_parent_ace": observations.child_file_copied_parent_ace,
            "child_file_marks_ace_inherited": observations.child_file_marks_ace_inherited,
            "file_self_dacl_roundtrip": observations.file_self_dacl_roundtrip,
            "inheritance_disabled": observations.inheritance_disabled,
            "protected_child_blocks_parent_change": observations.protected_child_blocks_parent_change,
            "existing_unprotected_file_tracks_parent_change": observations.existing_unprotected_file_tracks_parent_change,
            "new_sibling_copies_updated_parent_ace": observations.new_sibling_copies_updated_parent_ace,
            "new_sibling_marks_ace_inherited": observations.new_sibling_marks_ace_inherited,
            "inheritance_unprotected_without_merge": observations.inheritance_unprotected_without_merge,
            "unprotect_only_synthesizes_parent_change": observations.unprotect_only_synthesizes_parent_change,
            "atomic_target_dacl_applied": observations.atomic_target_dacl_applied,
        })
    );
}

async fn cleanup(
    share: &Share,
    parent_path: &SharePath,
    child_directory_path: &SharePath,
    sibling_directory_path: &SharePath,
    child_file_path: &SharePath,
) -> bool {
    if let Ok(file) = share
        .open_file(child_file_path, FileOpenOptions::open_existing())
        .await
    {
        let _ = file.delete().await;
        let _ = file.close().await;
    }
    for path in [sibling_directory_path, child_directory_path, parent_path] {
        if let Ok(directory) = share
            .open_directory(path, DirectoryOpenOptions::open_existing())
            .await
        {
            let _ = directory.delete().await;
            let _ = directory.close().await;
        }
    }
    match share
        .open_directory(parent_path, DirectoryOpenOptions::open_existing())
        .await
    {
        Ok(directory) => {
            let _ = directory.close().await;
            false
        }
        Err(Error::ReceivedErrorMessage(status, _)) => {
            status == Status::ObjectNameNotFound as u32
                || status == Status::ObjectPathNotFound as u32
        }
        Err(_) => false,
    }
}
