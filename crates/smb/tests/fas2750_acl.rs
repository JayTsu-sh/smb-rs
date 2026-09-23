//! FAS2750 CIFS DACL acceptance on an NTFS security-style volume.
//!
//! The test creates only run-owned objects. It verifies smb-rs primitives;
//! source/target ACL filtering and merge policy remain upper-layer concerns.

#![cfg(feature = "real-server-tests")]

mod common;

use smb::{
    ACE, ACL, AccessAce, AccessMask, AceFlags, AceValue, AclRevision, Client, Credentials,
    DirectoryOpenOptions, FileOpenOptions, SID, SecurityDescriptor, SecuritySelection, Share,
    SharePath, ShareTarget,
};
use smb_msg::Status;
use std::{env, fs, str::FromStr, sync::OnceLock};
use zeroize::Zeroizing;

const FAS_LOCAL_PROFILE_PREFIX: &str = "SMB_CIFS_ACCEPTANCE_FAS_LOCAL_";
const DIRECTORY_ACE_MASK: u32 = 0x0002_0080;
const NEW_PARENT_ACE_MASK: u32 = 0x0002_0010;
const LATER_PARENT_ACE_MASK: u32 = 0x0002_0020;
const FILE_ACE_MASK: u32 = 0x0002_0008;
const DENY_ACE_MASK: u32 = 0x0002_0080;

#[derive(Debug)]
struct AclObservations {
    directory_explicit: bool,
    directory_ace_inheritable: bool,
    directory_inheritance_enabled: bool,
    child_directory_inherited: bool,
    child_file_inherited: bool,
    file_explicit: bool,
    file_explicit_deny: bool,
    file_explicit_deny_removed: bool,
    directory_inheritance_disabled: bool,
    disabled_directory_blocks_new_parent_ace: bool,
    existing_unprotected_file_receives_new_parent_ace: bool,
    enabled_sibling_inherits_new_parent_ace: bool,
    existing_unprotected_directory_receives_later_parent_ace: bool,
    directory_unprotected_without_merge: bool,
    unprotect_only_synthesizes_new_parent_ace: bool,
    directory_inheritance_reenabled: bool,
    reenabled_directory_contains_parent_inherited_ace: bool,
}

#[derive(Debug)]
struct AutoInheritRequestObservations {
    request_retained_by_parent: bool,
    parent_reports_auto_inherited: bool,
    child_reports_auto_inherited: bool,
    existing_child_had_requested_right: bool,
    existing_child_has_requested_right_after: bool,
}

struct FasAclTestConfig {
    server: String,
    share: String,
    credentials: Credentials,
}

#[derive(Clone)]
struct FasLocalProfile {
    server: Zeroizing<String>,
    share: Zeroizing<String>,
    username: Zeroizing<String>,
    password: Zeroizing<String>,
}

static FAS_LOCAL_PROFILE: OnceLock<Result<FasLocalProfile, String>> = OnceLock::new();

#[test_log::test(tokio::test(flavor = "multi_thread"))]
#[ignore = "requires an isolated writable FAS2750 NTFS CIFS share with WRITE_DAC and controlled profile descriptors"]
async fn fas2750_directory_file_aces_and_inheritance() -> smb::Result<()> {
    let client = Client::new();
    let config = fas_acl_test_config()?;
    let share = client
        .connect_share(
            &ShareTarget::new(config.server, config.share)?,
            config.credentials,
        )
        .await?;
    let suffix = format!("{}-{}", std::process::id(), random_suffix());
    let parent_path = SharePath::new(format!("smb-rs-acl-{suffix}"))?;
    let child_directory_path = SharePath::new(format!("{}\\directory", parent_path.as_str()))?;
    let sibling_directory_path = SharePath::new(format!("{}\\sibling", parent_path.as_str()))?;
    let child_file_path = SharePath::new(format!("{}\\file.bin", parent_path.as_str()))?;

    let observations = exercise_acl_primitives(
        &share,
        &parent_path,
        &child_directory_path,
        &sibling_directory_path,
        &child_file_path,
    )
    .await;
    cleanup(
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
    close_result?;
    client_close_result?;
    record_observations(&observations);
    assert!(
        observations.directory_explicit,
        "parent directory omitted its explicit ACE: {observations:?}"
    );
    assert!(
        observations.directory_ace_inheritable,
        "parent directory stripped the ACE inheritance flags: {observations:?}"
    );
    assert!(
        observations.directory_inheritance_enabled,
        "parent directory unexpectedly reported a protected DACL: {observations:?}"
    );
    assert!(
        observations.child_directory_inherited,
        "child directory omitted the inherited parent ACE: {observations:?}"
    );
    assert!(
        observations.child_file_inherited,
        "child file omitted the inherited parent ACE: {observations:?}"
    );
    assert!(
        observations.file_explicit,
        "child file omitted its explicit ACE: {observations:?}"
    );
    assert!(
        observations.file_explicit_deny,
        "child file omitted its explicit deny ACE: {observations:?}"
    );
    assert!(
        observations.file_explicit_deny_removed,
        "child file retained the removed explicit deny ACE: {observations:?}"
    );
    assert!(
        observations.directory_inheritance_disabled,
        "child directory did not report protected DACL after disabling inheritance: {observations:?}"
    );
    assert!(
        observations.disabled_directory_blocks_new_parent_ace,
        "protected child directory received the new parent ACE: {observations:?}"
    );
    assert!(
        observations.enabled_sibling_inherits_new_parent_ace,
        "unprotected sibling directory omitted the new inherited parent ACE: {observations:?}"
    );
    assert!(
        observations.directory_unprotected_without_merge,
        "child directory remained protected after clearing DACL_PROTECTED: {observations:?}"
    );
    assert!(
        observations.directory_inheritance_reenabled,
        "child directory remained protected after re-enabling inheritance: {observations:?}"
    );
    assert!(
        observations.reenabled_directory_contains_parent_inherited_ace,
        "re-enabled child directory omitted the submitted inherited parent ACE: {observations:?}"
    );
    Ok(())
}

/// Reports whether this ONTAP target implements the optional Windows
/// auto-inheritance propagation contract for existing descendants. This is
/// deliberately separate from ordinary create-time ACE inheritance: an absent
/// `SE_DACL_AUTO_INHERITED` result is a supported capability outcome, not a
/// failure of the basic DACL API.
#[test_log::test(tokio::test(flavor = "multi_thread"))]
#[ignore = "requires an isolated writable FAS2750 NTFS CIFS share with WRITE_DAC and controlled profile descriptors"]
async fn fas2750_auto_inherit_request_capability() -> smb::Result<()> {
    let client = Client::new();
    let config = fas_acl_test_config()?;
    let share = client
        .connect_share(
            &ShareTarget::new(config.server, config.share)?,
            config.credentials,
        )
        .await?;
    let suffix = format!("{}-{}", std::process::id(), random_suffix());
    let parent_path = SharePath::new(format!("smb-rs-auto-inherit-{suffix}"))?;
    let child_file_path = SharePath::new(format!("{}\\existing.bin", parent_path.as_str()))?;

    let observations = exercise_auto_inherit_request(&share, &parent_path, &child_file_path).await;
    cleanup_auto_inherit_request(&share, &parent_path, &child_file_path).await;
    let close_result = share.close().await;
    let client_close_result = client.close().await;

    let observations = observations?;
    close_result?;
    client_close_result?;
    record_auto_inherit_request_observations(&observations);
    assert!(
        !observations.parent_reports_auto_inherited
            || (observations.child_reports_auto_inherited
                && observations.existing_child_has_requested_right_after),
        "server reported automatic inheritance without propagating the requested ACE: {observations:?}"
    );
    Ok(())
}

/// Loads a FAS ACL target from the controlled `fas-local` profile when that
/// profile is present. The generic real-server inputs remain a local/manual
/// fallback for the existing test harness, but a partially supplied profile is
/// rejected rather than silently falling back to another target.
fn fas_acl_test_config() -> smb::Result<FasAclTestConfig> {
    if fas_local_profile_present() {
        let profile = FAS_LOCAL_PROFILE
            .get_or_init(load_fas_local_profile)
            .as_ref()
            .map_err(|error| smb::Error::InvalidState(error.clone()))?;
        return Ok(FasAclTestConfig {
            server: profile.server.to_string(),
            share: profile.share.to_string(),
            credentials: Credentials::ntlm(
                profile.username.to_string(),
                profile.password.to_string(),
            ),
        });
    }

    Ok(FasAclTestConfig {
        server: common::smb_tests_server(),
        share: common::smb_tests_share(),
        credentials: common::smb_test_credentials(),
    })
}

fn load_fas_local_profile() -> Result<FasLocalProfile, String> {
    let server = fas_local_profile_descriptor("SERVER_FD").map_err(|error| error.to_string())?;
    let share = fas_local_profile_descriptor("SHARE_FD").map_err(|error| error.to_string())?;
    let username =
        fas_local_profile_descriptor("USERNAME_FD").map_err(|error| error.to_string())?;
    let password =
        fas_local_profile_descriptor("PASSWORD_FD").map_err(|error| error.to_string())?;
    let expected_server =
        fas_local_profile_descriptor("EXPECTED_SERVER_FD").map_err(|error| error.to_string())?;
    let expected_share =
        fas_local_profile_descriptor("EXPECTED_SHARE_FD").map_err(|error| error.to_string())?;
    if server != expected_server || share != expected_share {
        return Err(
            "FAS local profile endpoint or share does not match its controlled-runner binding"
                .into(),
        );
    }
    Ok(FasLocalProfile {
        server,
        share,
        username,
        password,
    })
}

fn fas_local_profile_present() -> bool {
    ["SERVER_FD", "SHARE_FD", "USERNAME_FD", "PASSWORD_FD"]
        .into_iter()
        .any(|suffix| env::var_os(fas_local_profile_variable(suffix)).is_some())
}

fn fas_local_profile_descriptor(suffix: &str) -> smb::Result<Zeroizing<String>> {
    let variable = fas_local_profile_variable(suffix);
    let descriptor = env::var(&variable).map_err(|_| {
        smb::Error::InvalidState(format!(
            "missing controlled FAS local profile descriptor {variable}"
        ))
    })?;
    let descriptor = descriptor.parse::<i32>().map_err(|_| {
        smb::Error::InvalidState(format!(
            "controlled FAS local profile descriptor {variable} is invalid"
        ))
    })?;
    if descriptor < 3 {
        return Err(smb::Error::InvalidState(format!(
            "controlled FAS local profile descriptor {variable} must be at least 3"
        )));
    }
    let value = fs::read_to_string(format!("/proc/self/fd/{descriptor}")).map_err(|_| {
        smb::Error::InvalidState(format!(
            "controlled FAS local profile descriptor {variable} is unavailable"
        ))
    })?;
    let value = value.trim_end_matches(['\r', '\n']);
    if value.is_empty() {
        return Err(smb::Error::InvalidState(format!(
            "controlled FAS local profile descriptor {variable} is empty"
        )));
    }
    Ok(Zeroizing::new(value.to_string()))
}

fn fas_local_profile_variable(suffix: &str) -> String {
    format!("{FAS_LOCAL_PROFILE_PREFIX}{suffix}")
}

async fn exercise_auto_inherit_request(
    share: &Share,
    parent_path: &SharePath,
    child_file_path: &SharePath,
) -> smb::Result<AutoInheritRequestObservations> {
    let selection = SecuritySelection::default().dacl(true);
    let parent = share
        .open_directory(parent_path, DirectoryOpenOptions::create_new())
        .await?;
    parent.close().await?;
    let child = share
        .open_file(child_file_path, FileOpenOptions::create_new())
        .await?;
    child.close().await?;

    let mut parent_descriptor = share.query_security(parent_path, selection).await?;
    let trustee = existing_account_trustee(&parent_descriptor)
        .or_else(|| {
            std::env::var("SMB_FAS_ACL_TEST_TRUSTEE_SID")
                .ok()
                .and_then(|value| SID::from_str(&value).ok())
        })
        .ok_or_else(|| {
            smb::Error::InvalidState("server DACL contains no usable account user/group SID".into())
        })?;
    let child_before = share.query_security(child_file_path, selection).await?;
    let child_had_requested_right =
        contains_ace(&child_before, &trustee, NEW_PARENT_ACE_MASK, true)
            || contains_ace(&child_before, &trustee, NEW_PARENT_ACE_MASK, false);

    insert_allow_ace(
        &mut parent_descriptor,
        trustee.clone(),
        NEW_PARENT_ACE_MASK,
        AceFlags::new()
            .with_object_inherit(true)
            .with_container_inherit(true),
    );
    parent_descriptor.control = parent_descriptor.control.with_dacl_auto_inherit_req(true);
    share
        .set_security(parent_path, parent_descriptor, selection)
        .await?;
    let parent_after = share.query_security(parent_path, selection).await?;
    let child_after = share.query_security(child_file_path, selection).await?;
    record_descriptor("auto-inherit-request-parent", "parent", &parent_after);
    record_descriptor(
        "auto-inherit-request-existing-child",
        "child-file",
        &child_after,
    );

    let child_has_requested_right = contains_ace(&child_after, &trustee, NEW_PARENT_ACE_MASK, true)
        || contains_ace(&child_after, &trustee, NEW_PARENT_ACE_MASK, false);
    Ok(AutoInheritRequestObservations {
        request_retained_by_parent: parent_after.control.dacl_auto_inherit_req(),
        parent_reports_auto_inherited: parent_after.control.dacl_auto_inherited(),
        child_reports_auto_inherited: child_after.control.dacl_auto_inherited(),
        existing_child_had_requested_right: child_had_requested_right,
        existing_child_has_requested_right_after: child_has_requested_right,
    })
}

async fn exercise_acl_primitives(
    share: &Share,
    parent_path: &SharePath,
    child_directory_path: &SharePath,
    sibling_directory_path: &SharePath,
    child_file_path: &SharePath,
) -> smb::Result<AclObservations> {
    let selection = SecuritySelection::default().dacl(true);
    let parent = share
        .open_directory(parent_path, DirectoryOpenOptions::create_new())
        .await?;
    parent.close().await?;

    let mut parent_descriptor = share.query_security(parent_path, selection).await?;
    record_descriptor("parent-before-custom-ace", "parent", &parent_descriptor);
    // Use only an account-domain or POSIX-mapped user/group SID already
    // accepted by this server. Real-device acceptance must not manufacture a
    // well-known trustee that the target ACL backend cannot represent.
    let trustee = existing_account_trustee(&parent_descriptor)
        .or_else(|| {
            std::env::var("SMB_FAS_ACL_TEST_TRUSTEE_SID")
                .ok()
                .and_then(|value| SID::from_str(&value).ok())
        })
        .ok_or_else(|| {
            smb::Error::InvalidState("server DACL contains no usable account user/group SID".into())
        })?;
    let new_trustee = trustee.clone();
    let deny_trustee = trustee.clone();
    let later_trustee = trustee.clone();
    insert_allow_ace(
        &mut parent_descriptor,
        trustee.clone(),
        DIRECTORY_ACE_MASK,
        AceFlags::new()
            .with_object_inherit(true)
            .with_container_inherit(true),
    );
    share
        .set_security(parent_path, parent_descriptor, selection)
        .await?;
    let parent_descriptor = share.query_security(parent_path, selection).await?;
    record_descriptor(
        "parent-after-inheritable-allow",
        "parent",
        &parent_descriptor,
    );
    let directory_explicit = contains_ace(&parent_descriptor, &trustee, DIRECTORY_ACE_MASK, false);
    let directory_ace_inheritable =
        contains_inheritable_ace(&parent_descriptor, &trustee, DIRECTORY_ACE_MASK);
    let directory_inheritance_enabled = !parent_descriptor.control.dacl_protected();

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
    let child_directory_inherited = contains_ace(
        &child_directory_descriptor,
        &trustee,
        DIRECTORY_ACE_MASK,
        true,
    );
    let mut child_file_descriptor = share.query_security(child_file_path, selection).await?;
    record_descriptor(
        "child-file-after-create",
        "child-file",
        &child_file_descriptor,
    );
    let child_file_inherited =
        contains_ace(&child_file_descriptor, &trustee, DIRECTORY_ACE_MASK, true);
    insert_allow_ace(
        &mut child_file_descriptor,
        trustee.clone(),
        FILE_ACE_MASK,
        AceFlags::new(),
    );
    share
        .set_security(child_file_path, child_file_descriptor, selection)
        .await?;
    let child_file_descriptor = share.query_security(child_file_path, selection).await?;
    record_descriptor(
        "child-file-after-explicit-allow",
        "child-file",
        &child_file_descriptor,
    );
    let mut file_with_deny = child_file_descriptor.clone();
    insert_deny_ace(
        &mut file_with_deny,
        deny_trustee.clone(),
        DENY_ACE_MASK,
        AceFlags::new(),
    );
    share
        .set_security(child_file_path, file_with_deny, selection)
        .await?;
    let mut file_with_deny = share.query_security(child_file_path, selection).await?;
    record_descriptor(
        "child-file-after-explicit-deny",
        "child-file",
        &file_with_deny,
    );
    let file_explicit_deny =
        contains_denied_ace(&file_with_deny, &deny_trustee, DENY_ACE_MASK, false);
    remove_denied_ace(&mut file_with_deny, &deny_trustee, DENY_ACE_MASK);
    share
        .set_security(child_file_path, file_with_deny, selection)
        .await?;
    let file_after_deny_removal = share.query_security(child_file_path, selection).await?;
    record_descriptor(
        "child-file-after-deny-removal",
        "child-file",
        &file_after_deny_removal,
    );

    // Disabling inheritance is an atomic DACL replacement. This acceptance
    // scenario chooses the Windows "convert inherited permissions" policy so
    // existing access is preserved; smb-rs itself intentionally owns no such
    // migration policy.
    protect_dacl_preserving_access(&mut child_directory_descriptor);
    share
        .set_security(child_directory_path, child_directory_descriptor, selection)
        .await?;
    let disabled_descriptor = share
        .query_security(child_directory_path, selection)
        .await?;
    record_descriptor(
        "child-directory-after-disable-inheritance",
        "child-directory",
        &disabled_descriptor,
    );

    let mut parent_descriptor = share.query_security(parent_path, selection).await?;
    insert_allow_ace(
        &mut parent_descriptor,
        new_trustee.clone(),
        NEW_PARENT_ACE_MASK,
        AceFlags::new()
            .with_object_inherit(true)
            .with_container_inherit(true),
    );
    share
        .set_security(parent_path, parent_descriptor, selection)
        .await?;
    let parent_descriptor_after_second_ace = share.query_security(parent_path, selection).await?;
    record_descriptor(
        "parent-after-second-inheritable-allow",
        "parent",
        &parent_descriptor_after_second_ace,
    );
    let child_file_after_parent_change = share.query_security(child_file_path, selection).await?;
    record_descriptor(
        "existing-child-file-after-parent-change",
        "child-file",
        &child_file_after_parent_change,
    );
    let existing_unprotected_file_receives_new_parent_ace = contains_ace(
        &child_file_after_parent_change,
        &new_trustee,
        NEW_PARENT_ACE_MASK,
        true,
    ) || contains_ace(
        &child_file_after_parent_change,
        &new_trustee,
        NEW_PARENT_ACE_MASK,
        false,
    );

    let sibling_directory = share
        .open_directory(sibling_directory_path, DirectoryOpenOptions::create_new())
        .await?;
    sibling_directory.close().await?;
    let sibling_descriptor = share
        .query_security(sibling_directory_path, selection)
        .await?;
    record_descriptor(
        "sibling-directory-after-create",
        "sibling-directory",
        &sibling_descriptor,
    );

    let mut parent_descriptor_after_later_ace = parent_descriptor_after_second_ace;
    insert_allow_ace(
        &mut parent_descriptor_after_later_ace,
        later_trustee.clone(),
        LATER_PARENT_ACE_MASK,
        AceFlags::new()
            .with_object_inherit(true)
            .with_container_inherit(true),
    );
    share
        .set_security(parent_path, parent_descriptor_after_later_ace, selection)
        .await?;
    let parent_descriptor_after_later_ace = share.query_security(parent_path, selection).await?;
    record_descriptor(
        "parent-after-later-inheritable-allow",
        "parent",
        &parent_descriptor_after_later_ace,
    );
    let sibling_after_parent_change = share
        .query_security(sibling_directory_path, selection)
        .await?;
    record_descriptor(
        "existing-sibling-after-parent-change",
        "sibling-directory",
        &sibling_after_parent_change,
    );
    let existing_unprotected_directory_receives_later_parent_ace = contains_ace(
        &sibling_after_parent_change,
        &later_trustee,
        LATER_PARENT_ACE_MASK,
        true,
    ) || contains_ace(
        &sibling_after_parent_change,
        &later_trustee,
        LATER_PARENT_ACE_MASK,
        false,
    );
    let disabled_descriptor_after_parent_change = share
        .query_security(child_directory_path, selection)
        .await?;
    record_descriptor(
        "protected-child-after-parent-change",
        "child-directory",
        &disabled_descriptor_after_parent_change,
    );

    let mut unprotected_descriptor = disabled_descriptor_after_parent_change.clone();
    unprotected_descriptor.control = unprotected_descriptor.control.with_dacl_protected(false);
    share
        .set_security(child_directory_path, unprotected_descriptor, selection)
        .await?;
    let unprotected_descriptor = share
        .query_security(child_directory_path, selection)
        .await?;
    record_descriptor(
        "child-directory-after-unprotect-only",
        "child-directory",
        &unprotected_descriptor,
    );
    let directory_unprotected_without_merge = !unprotected_descriptor.control.dacl_protected();
    let unprotect_only_synthesizes_new_parent_ace = contains_ace(
        &unprotected_descriptor,
        &new_trustee,
        NEW_PARENT_ACE_MASK,
        true,
    ) || contains_ace(
        &unprotected_descriptor,
        &new_trustee,
        NEW_PARENT_ACE_MASK,
        false,
    );

    let mut reenabled_descriptor = unprotected_descriptor;
    // ONTAP clears DACL protection but does not retroactively synthesize ACEs
    // that were added to the parent while this directory was protected. The
    // migration layer therefore supplies its complete target DACL atomically;
    // this test adds the missing parent-derived ACE explicitly as inherited.
    insert_allow_ace(
        &mut reenabled_descriptor,
        new_trustee.clone(),
        NEW_PARENT_ACE_MASK,
        AceFlags::new()
            .with_object_inherit(true)
            .with_container_inherit(true)
            .with_inherited(true),
    );
    reenabled_descriptor.control = reenabled_descriptor.control.with_dacl_protected(false);
    share
        .set_security(child_directory_path, reenabled_descriptor, selection)
        .await?;
    let reenabled_descriptor = share
        .query_security(child_directory_path, selection)
        .await?;
    record_descriptor(
        "child-directory-after-reenable-inheritance",
        "child-directory",
        &reenabled_descriptor,
    );

    Ok(AclObservations {
        directory_explicit,
        directory_ace_inheritable,
        directory_inheritance_enabled,
        child_directory_inherited,
        child_file_inherited,
        file_explicit: contains_ace(&child_file_descriptor, &trustee, FILE_ACE_MASK, false),
        file_explicit_deny,
        file_explicit_deny_removed: !contains_denied_ace(
            &file_after_deny_removal,
            &deny_trustee,
            DENY_ACE_MASK,
            false,
        ),
        directory_inheritance_disabled: disabled_descriptor.control.dacl_protected(),
        disabled_directory_blocks_new_parent_ace: !contains_ace(
            &disabled_descriptor_after_parent_change,
            &new_trustee,
            NEW_PARENT_ACE_MASK,
            false,
        ) && !contains_ace(
            &disabled_descriptor_after_parent_change,
            &new_trustee,
            NEW_PARENT_ACE_MASK,
            true,
        ),
        existing_unprotected_file_receives_new_parent_ace,
        enabled_sibling_inherits_new_parent_ace: contains_ace(
            &sibling_descriptor,
            &new_trustee,
            NEW_PARENT_ACE_MASK,
            true,
        ),
        existing_unprotected_directory_receives_later_parent_ace,
        directory_unprotected_without_merge,
        unprotect_only_synthesizes_new_parent_ace,
        directory_inheritance_reenabled: !reenabled_descriptor.control.dacl_protected(),
        reenabled_directory_contains_parent_inherited_ace: contains_ace(
            &reenabled_descriptor,
            &new_trustee,
            NEW_PARENT_ACE_MASK,
            true,
        ),
    })
}

fn contains_inheritable_ace(descriptor: &SecurityDescriptor, sid: &SID, mask: u32) -> bool {
    descriptor.dacl.as_ref().is_some_and(|dacl| {
        dacl.ace.iter().any(|ace| {
            ace.ace_flags.object_inherit()
                && ace.ace_flags.container_inherit()
                && ace.value.as_access_allowed().is_some_and(|access| {
                    access.sid == *sid
                        && u32::from_le_bytes(access.access_mask.into_bytes()) == mask
                })
        })
    })
}

fn existing_account_trustee(descriptor: &SecurityDescriptor) -> Option<SID> {
    descriptor.dacl.as_ref()?.ace.iter().find_map(|ace| {
        let sid = &ace.value.as_access_allowed()?.sid;
        let account_domain_sid = sid.identifier_authority == 5
            && sid.sub_authority.first() == Some(&21)
            && sid.sub_authority.len() >= 2;
        let posix_mapped_sid = sid.identifier_authority == 22
            && matches!(sid.sub_authority.first(), Some(1 | 2))
            && sid.sub_authority.len() == 2;
        (account_domain_sid || posix_mapped_sid).then(|| sid.clone())
    })
}

fn protect_dacl_preserving_access(descriptor: &mut SecurityDescriptor) {
    if let Some(dacl) = descriptor.dacl.as_mut() {
        for ace in &mut dacl.ace {
            ace.ace_flags = ace.ace_flags.with_inherited(false);
        }
    }
    descriptor.control = descriptor.control.with_dacl_protected(true);
}

fn insert_allow_ace(descriptor: &mut SecurityDescriptor, sid: SID, mask: u32, flags: AceFlags) {
    descriptor.control = descriptor
        .control
        .with_dacl_present(true)
        .with_dacl_protected(false);
    let dacl = descriptor.dacl.get_or_insert_with(|| ACL {
        acl_revision: AclRevision::Nt4,
        ace: Vec::new(),
    });
    dacl.insert_ace(ACE {
        ace_flags: flags,
        value: AceValue::AccessAllowed(AccessAce {
            access_mask: AccessMask::from_bytes(mask.to_le_bytes()),
            sid,
        }),
    });
}

fn insert_deny_ace(descriptor: &mut SecurityDescriptor, sid: SID, mask: u32, flags: AceFlags) {
    descriptor.control = descriptor
        .control
        .with_dacl_present(true)
        .with_dacl_protected(false);
    let dacl = descriptor.dacl.get_or_insert_with(|| ACL {
        acl_revision: AclRevision::Nt4,
        ace: Vec::new(),
    });
    dacl.insert_ace(ACE {
        ace_flags: flags,
        value: AceValue::AccessDenied(AccessAce {
            access_mask: AccessMask::from_bytes(mask.to_le_bytes()),
            sid,
        }),
    });
}

fn remove_denied_ace(descriptor: &mut SecurityDescriptor, sid: &SID, mask: u32) {
    if let Some(dacl) = descriptor.dacl.as_mut() {
        dacl.ace.retain(|ace| {
            !ace.value.as_access_denied().is_some_and(|access| {
                access.sid == *sid && u32::from_le_bytes(access.access_mask.into_bytes()) == mask
            })
        });
    }
}

fn contains_ace(descriptor: &SecurityDescriptor, sid: &SID, mask: u32, inherited: bool) -> bool {
    descriptor.dacl.as_ref().is_some_and(|dacl| {
        dacl.ace.iter().any(|ace| {
            ace.ace_flags.inherited() == inherited
                && ace.value.as_access_allowed().is_some_and(|access| {
                    access.sid == *sid
                        && u32::from_le_bytes(access.access_mask.into_bytes()) & mask == mask
                })
        })
    })
}

fn contains_denied_ace(
    descriptor: &SecurityDescriptor,
    sid: &SID,
    mask: u32,
    inherited: bool,
) -> bool {
    descriptor.dacl.as_ref().is_some_and(|dacl| {
        dacl.ace.iter().any(|ace| {
            ace.ace_flags.inherited() == inherited
                && ace.value.as_access_denied().is_some_and(|access| {
                    access.sid == *sid
                        && u32::from_le_bytes(access.access_mask.into_bytes()) == mask
                })
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
    let record = serde_json::json!({
        "record_type": "acl_descriptor",
        "stage": stage,
        "path_role": path_role,
        "control": {
            "raw_le_hex": format!(
                "0x{:04x}",
                u16::from_le_bytes(descriptor.control.into_bytes())
            ),
            "dacl_present": descriptor.control.dacl_present(),
            "dacl_defaulted": descriptor.control.dacl_defaulted(),
            "dacl_auto_inherit_req": descriptor.control.dacl_auto_inherit_req(),
            "dacl_auto_inherited": descriptor.control.dacl_auto_inherited(),
            "dacl_protected": descriptor.control.dacl_protected(),
            "self_relative": descriptor.control.self_relative(),
        },
        "dacl": {
            "ace_count": aces.len(),
            "aces": aces,
        }
    });
    println!(
        "ACL_RECORD {}",
        serde_json::to_string(&record).expect("ACL record is JSON serializable")
    );
}

fn record_auto_inherit_request_observations(observations: &AutoInheritRequestObservations) {
    let record = serde_json::json!({
        "record_type": "acl_auto_inherit_request_capability",
        "request_retained_by_parent": observations.request_retained_by_parent,
        "parent_reports_auto_inherited": observations.parent_reports_auto_inherited,
        "child_reports_auto_inherited": observations.child_reports_auto_inherited,
        "existing_child_had_requested_right": observations.existing_child_had_requested_right,
        "existing_child_has_requested_right_after": observations.existing_child_has_requested_right_after,
    });
    println!(
        "ACL_RECORD {}",
        serde_json::to_string(&record).expect("ACL record is JSON serializable")
    );
}

async fn cleanup_auto_inherit_request(
    share: &Share,
    parent_path: &SharePath,
    child_file_path: &SharePath,
) {
    match share
        .open_file(child_file_path, FileOpenOptions::open_existing())
        .await
    {
        Ok(file) => {
            let delete = file.delete().await;
            let close = file.close().await;
            record_cleanup(
                "auto-inherit-child-file",
                "file",
                "passed",
                cleanup_status(&delete),
                cleanup_status(&close),
            );
        }
        Err(error) => record_cleanup(
            "auto-inherit-child-file",
            "file",
            &format!("failed: {error}"),
            cleanup_not_run(),
            cleanup_not_run(),
        ),
    }
    match share
        .open_directory(parent_path, DirectoryOpenOptions::open_existing())
        .await
    {
        Ok(directory) => {
            let delete = directory.delete().await;
            let close = directory.close().await;
            record_cleanup(
                "auto-inherit-parent",
                "directory",
                "passed",
                cleanup_status(&delete),
                cleanup_status(&close),
            );
        }
        Err(error) => record_cleanup(
            "auto-inherit-parent",
            "directory",
            &format!("failed: {error}"),
            cleanup_not_run(),
            cleanup_not_run(),
        ),
    }
}

fn record_observations(observations: &AclObservations) {
    let record = serde_json::json!({
        "record_type": "acl_observations",
        "directory_explicit": observations.directory_explicit,
        "directory_ace_inheritable": observations.directory_ace_inheritable,
        "directory_inheritance_enabled": observations.directory_inheritance_enabled,
        "child_directory_inherited": observations.child_directory_inherited,
        "child_file_inherited": observations.child_file_inherited,
        "file_explicit": observations.file_explicit,
        "file_explicit_deny": observations.file_explicit_deny,
        "file_explicit_deny_removed": observations.file_explicit_deny_removed,
        "directory_inheritance_disabled": observations.directory_inheritance_disabled,
        "disabled_directory_blocks_new_parent_ace": observations.disabled_directory_blocks_new_parent_ace,
        "existing_unprotected_file_receives_new_parent_ace": observations.existing_unprotected_file_receives_new_parent_ace,
        "enabled_sibling_inherits_new_parent_ace": observations.enabled_sibling_inherits_new_parent_ace,
        "existing_unprotected_directory_receives_later_parent_ace": observations.existing_unprotected_directory_receives_later_parent_ace,
        "directory_unprotected_without_merge": observations.directory_unprotected_without_merge,
        "unprotect_only_synthesizes_new_parent_ace": observations.unprotect_only_synthesizes_new_parent_ace,
        "directory_inheritance_reenabled": observations.directory_inheritance_reenabled,
        "reenabled_directory_contains_parent_inherited_ace": observations.reenabled_directory_contains_parent_inherited_ace,
    });
    println!(
        "ACL_RECORD {}",
        serde_json::to_string(&record).expect("ACL observation record is JSON serializable")
    );
}

fn record_cleanup(
    path_role: &str,
    object_type: &str,
    open: &str,
    delete: serde_json::Value,
    close: serde_json::Value,
) {
    let record = serde_json::json!({
        "record_type": "acl_cleanup",
        "path_role": path_role,
        "object_type": object_type,
        "open": open,
        "delete": delete,
        "close": close,
    });
    println!(
        "ACL_RECORD {}",
        serde_json::to_string(&record).expect("ACL cleanup record is JSON serializable")
    );
}

fn cleanup_status<T>(result: &smb::Result<T>) -> serde_json::Value {
    match result {
        Ok(_) => serde_json::json!({ "status": "passed" }),
        Err(error) => serde_json::json!({
            "status": "failed",
            "error": error.to_string(),
        }),
    }
}

fn cleanup_not_run() -> serde_json::Value {
    serde_json::json!({ "status": "not-run" })
}

fn record_residual_check(status: &str, error: Option<&smb::Error>) {
    let record = serde_json::json!({
        "record_type": "acl_residual_check",
        "path_role": "parent",
        "status": status,
        "error": error.map(ToString::to_string),
    });
    println!(
        "ACL_RECORD {}",
        serde_json::to_string(&record).expect("ACL residual record is JSON serializable")
    );
}

#[test]
fn contains_ace_accepts_a_server_coalesced_allow_mask() {
    let sid = SID::from_str("S-1-5-21-1-2-3-4").expect("valid test SID");
    let descriptor = SecurityDescriptor {
        sbz1: 0,
        control: smb::SecurityDescriptorControl::new()
            .with_self_relative(true)
            .with_dacl_present(true),
        owner_sid: None,
        group_sid: None,
        sacl: None,
        dacl: Some(ACL {
            acl_revision: AclRevision::Nt4,
            ace: vec![ACE {
                ace_flags: AceFlags::new().with_inherited(true),
                value: AceValue::AccessAllowed(AccessAce {
                    access_mask: AccessMask::from_bytes(
                        (DIRECTORY_ACE_MASK | NEW_PARENT_ACE_MASK).to_le_bytes(),
                    ),
                    sid: sid.clone(),
                }),
            }],
        }),
    };

    assert!(contains_ace(&descriptor, &sid, NEW_PARENT_ACE_MASK, true));
}

async fn cleanup(
    share: &Share,
    parent_path: &SharePath,
    child_directory_path: &SharePath,
    sibling_directory_path: &SharePath,
    child_file_path: &SharePath,
) {
    match share
        .open_file(child_file_path, FileOpenOptions::open_existing())
        .await
    {
        Ok(file) => {
            let delete = file.delete().await;
            let close = file.close().await;
            record_cleanup(
                "child-file",
                "file",
                "passed",
                cleanup_status(&delete),
                cleanup_status(&close),
            );
        }
        Err(error) => record_cleanup(
            "child-file",
            "file",
            &format!("failed: {error}"),
            cleanup_not_run(),
            cleanup_not_run(),
        ),
    }
    match share
        .open_directory(
            sibling_directory_path,
            DirectoryOpenOptions::open_existing(),
        )
        .await
    {
        Ok(directory) => {
            let delete = directory.delete().await;
            let close = directory.close().await;
            record_cleanup(
                "sibling-directory",
                "directory",
                "passed",
                cleanup_status(&delete),
                cleanup_status(&close),
            );
        }
        Err(error) => record_cleanup(
            "sibling-directory",
            "directory",
            &format!("failed: {error}"),
            cleanup_not_run(),
            cleanup_not_run(),
        ),
    }
    match share
        .open_directory(child_directory_path, DirectoryOpenOptions::open_existing())
        .await
    {
        Ok(directory) => {
            let delete = directory.delete().await;
            let close = directory.close().await;
            record_cleanup(
                "child-directory",
                "directory",
                "passed",
                cleanup_status(&delete),
                cleanup_status(&close),
            );
        }
        Err(error) => record_cleanup(
            "child-directory",
            "directory",
            &format!("failed: {error}"),
            cleanup_not_run(),
            cleanup_not_run(),
        ),
    }
    match share
        .open_directory(parent_path, DirectoryOpenOptions::open_existing())
        .await
    {
        Ok(directory) => {
            let delete = directory.delete().await;
            let close = directory.close().await;
            record_cleanup(
                "parent",
                "directory",
                "passed",
                cleanup_status(&delete),
                cleanup_status(&close),
            );
        }
        Err(error) => record_cleanup(
            "parent",
            "directory",
            &format!("failed: {error}"),
            cleanup_not_run(),
            cleanup_not_run(),
        ),
    }
    match share
        .open_directory(parent_path, DirectoryOpenOptions::open_existing())
        .await
    {
        Ok(directory) => {
            record_residual_check("residual-object-present", None);
            let _ = directory.close().await;
        }
        Err(smb::Error::ReceivedErrorMessage(status, _))
            if status == Status::ObjectNameNotFound as u32
                || status == Status::ObjectPathNotFound as u32 =>
        {
            record_residual_check("no-residual-object", None);
        }
        Err(error) => record_residual_check("residual-check-inconclusive", Some(&error)),
    }
}

fn random_suffix() -> String {
    let bytes: [u8; 8] = rand::random();
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
