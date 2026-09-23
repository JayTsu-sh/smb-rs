//! Repeatable, destructive-but-contained CIFS acceptance matrix.
//!
//! Every case is opt-in and accepts credentials only through inherited file
//! descriptors.  It creates one uniquely named directory and removes only
//! exact paths beneath that directory; it never scans or cleans by prefix.

#![cfg(feature = "real-server-tests")]

use bytes::Bytes;
use futures_util::future::try_join_all;
use smb::{
    ACE, ACL, AccessAce, AccessMask, AceFlags, AceValue, AclRevision, Client, Credentials,
    DirectoryOpenOptions, Error, FileOpenOptions, Resource, SID, SecurityDescriptor,
    SecurityOpenOptions, SecuritySelection, Share, SharePath, ShareTarget, TransferOptions,
};
use std::{
    env, fs,
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

#[derive(Clone, Copy)]
struct Profile {
    name: &'static str,
    prefix: &'static str,
}

impl Profile {
    const FAS_NTFS: Self = Self {
        name: "fas-ntfs",
        prefix: "FAS_NTFS",
    };
    const DXN_ACL: Self = Self {
        name: "dxn-acl",
        prefix: "DXN_ACL",
    };
    const OPENFS_GUEST: Self = Self {
        name: "openfs-guest",
        prefix: "OPENFS_GUEST",
    };
    const WINDOWS_LOCAL: Self = Self {
        name: "windows-local",
        prefix: "WINDOWS_LOCAL",
    };

    fn variable(self, suffix: &str) -> String {
        format!("SMB_CIFS_MATRIX_{}_{}", self.prefix, suffix)
    }
}

struct Config {
    server: Zeroizing<String>,
    share: Zeroizing<String>,
    user: Zeroizing<String>,
    password: Zeroizing<String>,
    dacl_write: bool,
    inheritance: Option<InheritanceExpectation>,
    acl_trustee: Option<SID>,
}

#[derive(Clone, Copy)]
enum InheritanceExpectation {
    WindowsMarked,
    PosixMapped,
}

#[test_log::test(tokio::test(flavor = "multi_thread"))]
#[ignore = "requires the controlled FAS_NTFS profile for an isolated NTFS security-style share"]
async fn real_cifs_matrix_fas_ntfs() {
    run(Profile::FAS_NTFS).await;
}

#[test_log::test(tokio::test(flavor = "multi_thread"))]
#[ignore = "requires the controlled DXN_ACL profile for the approved ACL share"]
async fn real_cifs_matrix_dxn_acl() {
    run(Profile::DXN_ACL).await;
}

#[test_log::test(tokio::test(flavor = "multi_thread"))]
#[ignore = "requires the controlled OPENFS_GUEST profile"]
async fn real_cifs_matrix_openfs_guest() {
    run(Profile::OPENFS_GUEST).await;
}

#[test_log::test(tokio::test(flavor = "multi_thread"))]
#[ignore = "requires the controlled WINDOWS_LOCAL profile"]
async fn real_cifs_matrix_windows_local() {
    run(Profile::WINDOWS_LOCAL).await;
}

async fn run(profile: Profile) {
    let config = Config::load(profile)
        .unwrap_or_else(|error| panic!("{} matrix configuration failed: {error}", profile.name));
    let client = Client::new();
    let share = client
        .connect_share(
            &ShareTarget::new(config.server.to_string(), config.share.to_string())
                .expect("controlled target is valid"),
            Credentials::ntlm(config.user.to_string(), config.password.to_string()),
        )
        .await
        .unwrap_or_else(|error| panic!("{} connect failed: {error}", profile.name));

    let run_id = format!("smb-rs-matrix-{}-{}", std::process::id(), unique_suffix());
    let root = SharePath::new(&run_id).expect("run-owned root is valid");
    let result = exercise(
        &share,
        &root,
        config.dacl_write,
        config.inheritance,
        config.acl_trustee,
    )
    .await;
    let cleanup = cleanup(&share, &root).await;
    let close = share.close().await;
    let client_close = client.close().await;

    result.unwrap_or_else(|error| panic!("{} matrix failed: {error}", profile.name));
    cleanup.unwrap_or_else(|error| {
        panic!(
            "{} matrix cleanup failed for run-owned root {}: {error}",
            profile.name,
            root.as_str()
        )
    });
    close.unwrap_or_else(|error| panic!("{} share close failed: {error}", profile.name));
    client_close.unwrap_or_else(|error| panic!("{} client close failed: {error}", profile.name));
}

async fn exercise(
    share: &Share,
    root: &SharePath,
    dacl_write: bool,
    inheritance: Option<InheritanceExpectation>,
    acl_trustee: Option<SID>,
) -> smb::Result<()> {
    // An SMB CREATE for the share root must use an empty wire name.  This
    // validates the Windows-compatible root mapping without assuming it is empty.
    let share_root = SharePath::new(".")?;
    let root_handle = share
        .open_directory(&share_root, DirectoryOpenOptions::open_existing())
        .await?;
    let _ = root_handle.collect_entries("*").await?;
    root_handle.close().await?;

    let directory = share
        .open_directory(root, DirectoryOpenOptions::create_new())
        .await?;
    assert!(directory.collect_entries("*").await?.is_empty());
    directory.close().await?;

    let lifecycle = child(root, "lifecycle.bin")?;
    let renamed = child(root, "renamed.bin")?;
    let file = share
        .open_file(&lifecycle, FileOpenOptions::create_new())
        .await?;
    let payload = Bytes::from_static(b"smb-rs real CIFS matrix");
    file.write_all_at(0, payload.clone()).await?;
    file.flush().await?;
    assert_eq!(file.read_exact_at(0, payload.len() as u32).await?, payload);
    assert_eq!(file.metadata().await?.len(), payload.len() as u64);
    file.rename(&renamed).await?;
    file.close().await?;

    if dacl_write {
        let resource = share
            .open_security(&renamed, SecurityOpenOptions::default().write_dacl(true))
            .await?;
        let selection = SecuritySelection::default().dacl(true);
        let descriptor = resource.query_security(selection).await?;
        resource.set_security(descriptor, selection).await?;
        close_resource(resource).await?;
    }

    if let Some(expectation) = inheritance {
        assert_create_time_acl_inheritance(share, root, expectation, acl_trustee).await?;
    }

    let source_path = child(root, "transfer-source.bin")?;
    let destination_path = child(root, "transfer-destination.bin")?;
    let payload = Bytes::from(
        (0..(1024 * 1024 + 29))
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>(),
    );
    let source = share
        .open_file(&source_path, FileOpenOptions::create_new())
        .await?;
    source.write_all_at(0, payload.clone()).await?;
    source.close().await?;
    let source = share
        .open_file(&source_path, FileOpenOptions::open_existing())
        .await?;
    let destination = share
        .open_file(&destination_path, FileOpenOptions::create_new())
        .await?;
    let report = source
        .transfer_to(
            &destination,
            TransferOptions::default()
                .concurrency(4)
                .chunk_size(128 * 1024),
        )
        .await?;
    assert_eq!(report.bytes(), payload.len() as u64);
    assert_eq!(
        destination.read_exact_at(0, payload.len() as u32).await?,
        payload
    );
    source.close().await?;
    destination.close().await?;

    let small_writes = (0..16).map(|index| {
        let share = share.clone();
        let path = child(root, &format!("parallel-{index:02}.bin"));
        async move {
            let path = path?;
            let file = share
                .open_file(&path, FileOpenOptions::create_new())
                .await?;
            let payload = Bytes::from(format!("parallel-{index}").into_bytes());
            file.write_all_at(0, payload.clone()).await?;
            file.flush().await?;
            assert_eq!(file.read_exact_at(0, payload.len() as u32).await?, payload);
            file.close().await
        }
    });
    try_join_all(small_writes).await?;
    Ok(())
}

async fn cleanup(share: &Share, root: &SharePath) -> smb::Result<()> {
    let mut names = vec![
        "lifecycle.bin".to_owned(),
        "renamed.bin".to_owned(),
        "transfer-source.bin".to_owned(),
        "transfer-destination.bin".to_owned(),
        "acl-child.bin".to_owned(),
    ];
    names.extend((0..16).map(|index| format!("parallel-{index:02}.bin")));
    for name in names {
        delete_exact_if_present(share, &child(root, &name)?).await?;
    }
    let directory = share
        .open_directory(root, DirectoryOpenOptions::open_existing())
        .await?;
    directory.delete().await?;
    directory.close().await.map(|_| ())
}

/// Validates inheritance only at child creation time.  Windows-style targets
/// must mark the resulting ACE inherited; POSIX-mapped targets are allowed to
/// materialize equivalent access without that Windows marker.  Neither mode
/// asserts that a later parent change rewrites already-existing children.
async fn assert_create_time_acl_inheritance(
    share: &Share,
    root: &SharePath,
    expectation: InheritanceExpectation,
    configured_trustee: Option<SID>,
) -> smb::Result<()> {
    const READ_CONTROL: u32 = 0x0002_0000;
    let selection = SecuritySelection::default().dacl(true);
    let mut parent = share.query_security(root, selection).await?;
    let trustee = configured_trustee
        .or_else(|| existing_account_trustee(&parent))
        // Some appliances expose only well-known principals in an inherited
        // root DACL.  Reusing any allow-ACE trustee that the server just
        // returned is safer and more interoperable than inventing a SID.
        .or_else(|| existing_allowed_trustee(&parent))
        .ok_or_else(|| {
            Error::InvalidState("server DACL contains no access-allowed trustee SID".into())
        })?;
    insert_inheritable_allow(&mut parent, trustee.clone(), READ_CONTROL);
    if matches!(expectation, InheritanceExpectation::WindowsMarked) {
        // Windows applies its automatic-inheritance materialization policy
        // when this request bit accompanies an inheritable replacement DACL.
        // It is deliberately a test-mode request: other targets may ignore it.
        parent.control = parent.control.with_dacl_auto_inherit_req(true);
    }
    share.set_security(root, parent, selection).await?;
    let parent_after_set = share.query_security(root, selection).await?;
    record_acl_observation("parent-after-inheritable-set", &parent_after_set);

    let child_path = child(root, "acl-child.bin")?;
    let child = share
        .open_file(&child_path, FileOpenOptions::create_new())
        .await?;
    child.close().await?;
    let child = share.query_security(&child_path, selection).await?;
    record_acl_observation("child-after-create", &child);
    let inherited = contains_allow(&child, &trustee, READ_CONTROL, true);
    let effective = inherited || contains_allow(&child, &trustee, READ_CONTROL, false);
    assert!(effective, "new child omitted the parent inheritable ACE");
    if matches!(expectation, InheritanceExpectation::WindowsMarked) {
        assert!(
            inherited,
            "Windows ACL target omitted INHERITED_ACE on a new child"
        );
    }
    tracing::info!(inherited, "ACL create-time inheritance observation");
    Ok(())
}

fn existing_account_trustee(descriptor: &SecurityDescriptor) -> Option<SID> {
    descriptor.dacl.as_ref()?.ace.iter().find_map(|ace| {
        let sid = &ace.value.as_access_allowed()?.sid;
        let account_domain = sid.identifier_authority == 5
            && sid.sub_authority.first() == Some(&21)
            && sid.sub_authority.len() >= 2;
        let posix_mapped = sid.identifier_authority == 22
            && matches!(sid.sub_authority.first(), Some(1 | 2))
            && sid.sub_authority.len() == 2;
        (account_domain || posix_mapped).then(|| sid.clone())
    })
}

fn existing_allowed_trustee(descriptor: &SecurityDescriptor) -> Option<SID> {
    descriptor.dacl.as_ref()?.ace.iter().find_map(|ace| {
        ace.value
            .as_access_allowed()
            .map(|access| access.sid.clone())
    })
}

fn insert_inheritable_allow(descriptor: &mut SecurityDescriptor, sid: SID, mask: u32) {
    descriptor.control = descriptor
        .control
        .with_dacl_present(true)
        .with_dacl_protected(false);
    let dacl = descriptor.dacl.get_or_insert_with(|| ACL {
        acl_revision: AclRevision::Nt4,
        ace: Vec::new(),
    });
    dacl.insert_ace(ACE {
        ace_flags: AceFlags::new()
            .with_object_inherit(true)
            .with_container_inherit(true),
        value: AceValue::AccessAllowed(AccessAce {
            access_mask: AccessMask::from_bytes(mask.to_le_bytes()),
            sid,
        }),
    });
}

fn contains_allow(descriptor: &SecurityDescriptor, sid: &SID, mask: u32, inherited: bool) -> bool {
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

/// A deliberately secret-free record used to compare a server's returned
/// descriptor with an independent ACL tool.  It has no path, account name, or
/// credential; SIDs and ACE bit fields are protocol data.
fn record_acl_observation(stage: &str, descriptor: &SecurityDescriptor) {
    let aces = descriptor
        .dacl
        .as_ref()
        .map(|dacl| {
            dacl.ace
                .iter()
                .filter_map(|ace| {
                    ace.value.as_access_allowed().map(|access| {
                        serde_json::json!({
                            "sid": access.sid.to_string(),
                            "mask": format!("0x{:08x}", u32::from_le_bytes(access.access_mask.into_bytes())),
                            "object_inherit": ace.ace_flags.object_inherit(),
                            "container_inherit": ace.ace_flags.container_inherit(),
                            "inherited": ace.ace_flags.inherited(),
                        })
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    println!(
        "ACL_MATRIX {}",
        serde_json::json!({
            "stage": stage,
            "dacl_auto_inherit_req": descriptor.control.dacl_auto_inherit_req(),
            "dacl_auto_inherited": descriptor.control.dacl_auto_inherited(),
            "dacl_protected": descriptor.control.dacl_protected(),
            "dacl_aces": aces,
        })
    );
}

async fn delete_exact_if_present(share: &Share, path: &SharePath) -> smb::Result<()> {
    match share
        .open_file(path, FileOpenOptions::open_existing())
        .await
    {
        Ok(file) => {
            file.delete().await?;
            file.close().await.map(|_| ())
        }
        Err(error) if is_not_found(&error) => Ok(()),
        Err(error) => Err(error),
    }
}

async fn close_resource(resource: Resource) -> smb::Result<()> {
    match resource {
        Resource::File(file) => file.close().await.map(|_| ()),
        Resource::Directory(directory) => directory.close().await.map(|_| ()),
        Resource::Pipe(pipe) => pipe.close().await.map(|_| ()),
    }
}

fn child(root: &SharePath, name: &str) -> smb::Result<SharePath> {
    SharePath::new(format!("{}\\{name}", root.as_str()))
}

fn is_not_found(error: &Error) -> bool {
    matches!(error, Error::UnexpectedMessageStatus(status) | Error::ReceivedErrorMessage(status, _)
        if *status == smb::protocol::Status::ObjectNameNotFound as u32)
}

impl Config {
    fn load(profile: Profile) -> Result<Self, String> {
        let server = descriptor(profile, "SERVER_FD")?;
        let share = descriptor(profile, "SHARE_FD")?;
        let user = descriptor(profile, "USERNAME_FD")?;
        if server != descriptor(profile, "EXPECTED_SERVER_FD")?
            || share != descriptor(profile, "EXPECTED_SHARE_FD")?
        {
            return Err("endpoint does not match its controlled-profile binding".into());
        }
        let password = match env::var(profile.variable("PASSWORD_EMPTY")).as_deref() {
            Ok("yes") => Zeroizing::new(String::new()),
            Ok(_) => return Err("PASSWORD_EMPTY must be exactly yes when supplied".into()),
            Err(_) => descriptor(profile, "PASSWORD_FD")?,
        };
        let dacl_write = matches!(
            env::var(profile.variable("DACL_WRITE")).as_deref(),
            Ok("yes")
        );
        let inheritance = match env::var(profile.variable("ACL_INHERITANCE")).as_deref() {
            Ok("windows-marked") => Some(InheritanceExpectation::WindowsMarked),
            Ok("posix-mapped") => Some(InheritanceExpectation::PosixMapped),
            Ok(value) => {
                return Err(format!(
                    "ACL_INHERITANCE must be windows-marked or posix-mapped, got {value}"
                ));
            }
            Err(_) => None,
        };
        if inheritance.is_some() && !dacl_write {
            return Err("ACL_INHERITANCE requires DACL_WRITE=yes".into());
        }
        let trustee_variable = profile.variable("ACL_TRUSTEE_SID_FD");
        let acl_trustee = match env::var_os(&trustee_variable) {
            Some(_) => Some(
                SID::from_str(&descriptor(profile, "ACL_TRUSTEE_SID_FD")?)
                    .map_err(|_| format!("{trustee_variable} was not a SID"))?,
            ),
            None => None,
        };
        Ok(Self {
            server,
            share,
            user,
            password,
            dacl_write,
            inheritance,
            acl_trustee,
        })
    }
}

fn descriptor(profile: Profile, suffix: &str) -> Result<Zeroizing<String>, String> {
    let variable = profile.variable(suffix);
    let fd = env::var(&variable)
        .map_err(|_| format!("missing {variable}"))?
        .parse::<i32>()
        .map_err(|_| format!("{variable} must be a descriptor number"))?;
    if fd < 3 {
        return Err(format!("{variable} must be at least 3"));
    }
    let value = fs::read_to_string(format!("/proc/self/fd/{fd}"))
        .map_err(|_| format!("{variable} is unavailable"))?;
    let value = value.trim_end_matches(['\r', '\n']);
    if value.is_empty() {
        return Err(format!("{variable} was empty"));
    }
    Ok(Zeroizing::new(value.to_owned()))
}

fn unique_suffix() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos()
}
