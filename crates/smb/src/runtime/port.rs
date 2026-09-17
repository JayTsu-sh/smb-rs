//! Runtime port consumed by the domain layer.
//!
//! This module owns no lifecycle state. It is the single crate-private
//! boundary that keeps protocol and runtime implementation types out of the
//! domain API. Legacy protocol mechanics remain an implementation detail behind
//! this stable port while callers use the domain object hierarchy.

use std::{pin::Pin, sync::Arc, time::SystemTime};

use bytes::Bytes;
use futures_core::{Stream, future::BoxFuture};
use futures_util::TryStreamExt;
use smb_dtyp::SecurityDescriptor;
use smb_fscc::{
    FileAccessMask, FileAttributes, FileBasicInformation, FileDirectoryInformation,
    FileDispositionInformation, FileRenameInformation, FileStandardInformation, NotifyAction,
};
use smb_msg::{AdditionalInfo, CreateOptions, NotifyFilter, SrvEnumerateSnapshotsRequest};
use sspi::{AuthIdentity, Secret, Username};
use zeroize::Zeroizing;

use super::metadata;
use crate::{
    Error,
    client::{Client as ProtocolClient, ClientConfig as ProtocolClientConfig, UncPath},
    resource::{
        Directory as ProtocolDirectory, File as ProtocolFile, FileCreateArgs, Pipe as ProtocolPipe,
        Resource as ProtocolResource, file::FileOperationOptions,
    },
    session::{
        Session as ProtocolSession,
        credential::{SessionCredentialProvider, SharedCredentialProvider},
    },
    tree::Tree as ProtocolShare,
};

pub(crate) struct RuntimeCredentials {
    pub(crate) username: Zeroizing<String>,
    pub(crate) password: Zeroizing<String>,
}

pub(crate) trait RuntimeCredentialProvider: Send + Sync {
    fn credentials(&self) -> BoxFuture<'_, crate::Result<RuntimeCredentials>>;
}

struct RefreshingCredentialAdapter {
    provider: Arc<dyn RuntimeCredentialProvider>,
}

impl SessionCredentialProvider for RefreshingCredentialAdapter {
    fn identity(&self) -> futures_core::future::BoxFuture<'_, crate::Result<AuthIdentity>> {
        Box::pin(async move {
            let credentials = self.provider.credentials().await?;
            Ok(AuthIdentity {
                username: Username::parse(credentials.username.as_str())
                    .map_err(|error| Error::SspiError(error.into()))?,
                password: Secret::from(credentials.password.to_string()),
            })
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OpenMode {
    CreateNew,
    OpenExisting,
    Overwrite,
}

/// Protocol configuration behind every facade client.
///
/// Negotiation always opens with an SMB2 NEGOTIATE. `ConnectionConfig` defaults
/// `smb2_only_negotiate` to `false`, which would begin with the legacy SMB1 multi-protocol
/// NEGOTIATE that advertises the SMB2 dialect string (MS-SMB2 3.2.4.2.2.1). That form costs an
/// extra round trip and is rejected outright by servers that have SMB1 removed, so the facade
/// does not use it.
fn client_config(signing: crate::SigningPolicy, guest: crate::GuestPolicy) -> ProtocolClientConfig {
    let mut config = ProtocolClientConfig::default();
    config.connection.signing_policy = signing;
    config.connection.allow_unsigned_guest_access = guest.allows_unsigned();
    config.connection.smb2_only_negotiate = true;
    config
}

pub(crate) struct RuntimeClient {
    inner: Arc<ProtocolClient>,
}

impl RuntimeClient {
    pub(crate) fn with_policies(signing: crate::SigningPolicy, guest: crate::GuestPolicy) -> Self {
        Self {
            inner: Arc::new(ProtocolClient::new(client_config(signing, guest))),
        }
    }

    pub(crate) async fn authenticate(
        &self,
        server: &str,
        username: &str,
        password: String,
    ) -> crate::Result<RuntimeSession> {
        let connection = self.inner.connect(server).await?;
        let identity = AuthIdentity {
            username: Username::parse(username).map_err(|error| Error::SspiError(error.into()))?,
            password: Secret::from(password),
        };
        let session = connection.authenticate(identity).await?;
        Ok(RuntimeSession {
            inner: Arc::new(session),
            server: server.to_owned(),
        })
    }

    pub(crate) async fn authenticate_with_provider(
        &self,
        server: &str,
        provider: Arc<dyn RuntimeCredentialProvider>,
    ) -> crate::Result<RuntimeSession> {
        let connection = self.inner.connect(server).await?;
        let provider: SharedCredentialProvider = Arc::new(RefreshingCredentialAdapter { provider });
        let session = connection
            .authenticate_with_credential_provider(provider)
            .await?;
        Ok(RuntimeSession {
            inner: Arc::new(session),
            server: server.to_owned(),
        })
    }

    pub(crate) async fn close(&self) -> crate::Result<()> {
        self.inner.close().await
    }
}

pub(crate) struct RuntimeSession {
    inner: Arc<ProtocolSession>,
    server: String,
}

impl RuntimeSession {
    pub(crate) fn object_identity(&self) -> crate::Result<(u64, u64, u64)> {
        Ok(self.inner.object_token()?.identity())
    }

    pub(crate) async fn connect_share(&self, share: &str) -> crate::Result<RuntimeShare> {
        let target = UncPath::new(&self.server)?.with_share(share)?;
        let share = Arc::new(self.inner.tree_connect(&target).await?);
        Ok(RuntimeShare { inner: share })
    }

    pub(crate) async fn close(&self) -> crate::Result<()> {
        self.inner.logoff().await
    }
}

pub(crate) struct RuntimeShare {
    inner: Arc<ProtocolShare>,
}

pub(crate) enum RuntimeResource {
    File(RuntimeFile),
    Directory(RuntimeDirectory),
    Pipe(RuntimePipe),
}

pub(crate) struct RuntimeMetadata {
    pub(crate) created: SystemTime,
    pub(crate) accessed: SystemTime,
    pub(crate) written: SystemTime,
    pub(crate) changed: SystemTime,
    pub(crate) len: u64,
}

impl RuntimeShare {
    pub(crate) fn object_identity(&self) -> (u64, u64, u64) {
        self.inner.object_token().identity()
    }

    pub(crate) async fn open_resource(&self, path: &str) -> crate::Result<RuntimeResource> {
        let resource = self
            .inner
            .create(
                path,
                &FileCreateArgs::make_open_existing(FileAccessMask::new().with_generic_read(true)),
            )
            .await?;
        Ok(match resource {
            ProtocolResource::File(file) => RuntimeResource::File(RuntimeFile { inner: file }),
            ProtocolResource::Directory(directory) => {
                RuntimeResource::Directory(RuntimeDirectory {
                    inner: Arc::new(directory),
                })
            }
            ProtocolResource::Pipe(pipe) => RuntimeResource::Pipe(RuntimePipe { inner: pipe }),
        })
    }

    pub(crate) async fn open_metadata_resource(
        &self,
        path: &str,
        write_attributes: bool,
    ) -> crate::Result<RuntimeResource> {
        let access = FileAccessMask::new()
            .with_file_read_attributes(true)
            .with_file_write_attributes(write_attributes);
        let args = FileCreateArgs {
            options: CreateOptions::new().with_open_reparse_point(true),
            ..FileCreateArgs::make_open_existing(access)
        };
        let resource = self.inner.create(path, &args).await?;
        if let Some(handle) = resource.handle() {
            if let Err(error) = metadata::reject_reparse(handle).await {
                let _ = handle.close().await;
                return Err(error);
            }
        }
        Ok(match resource {
            ProtocolResource::File(file) => RuntimeResource::File(RuntimeFile { inner: file }),
            ProtocolResource::Directory(directory) => {
                RuntimeResource::Directory(RuntimeDirectory {
                    inner: Arc::new(directory),
                })
            }
            ProtocolResource::Pipe(pipe) => RuntimeResource::Pipe(RuntimePipe { inner: pipe }),
        })
    }

    pub(crate) async fn open_security_resource(
        &self,
        path: &str,
        write_dacl: bool,
    ) -> crate::Result<RuntimeResource> {
        let access = FileAccessMask::new()
            .with_read_control(true)
            .with_write_dacl(write_dacl);
        let resource = self
            .inner
            .create(path, &FileCreateArgs::make_open_existing(access))
            .await?;
        Ok(match resource {
            ProtocolResource::File(file) => RuntimeResource::File(RuntimeFile { inner: file }),
            ProtocolResource::Directory(directory) => {
                RuntimeResource::Directory(RuntimeDirectory {
                    inner: Arc::new(directory),
                })
            }
            ProtocolResource::Pipe(pipe) => RuntimeResource::Pipe(RuntimePipe { inner: pipe }),
        })
    }

    pub(crate) async fn open_file(
        &self,
        path: &str,
        mode: OpenMode,
        persistent_timeout_millis: Option<u32>,
    ) -> crate::Result<RuntimeFile> {
        let mut args = match mode {
            OpenMode::CreateNew => {
                FileCreateArgs::make_create_new(Default::default(), Default::default())
            }
            OpenMode::OpenExisting => FileCreateArgs::make_open_existing(
                FileAccessMask::new()
                    .with_generic_read(true)
                    .with_generic_write(true)
                    .with_delete(true),
            ),
            OpenMode::Overwrite => {
                FileCreateArgs::make_overwrite(Default::default(), Default::default())
            }
        };
        if let Some(timeout) = persistent_timeout_millis {
            args = args.with_durable(crate::resource::DurableOpenRequest::persistent(
                timeout,
                smb_dtyp::Guid::generate(),
            ));
        }
        match self.inner.create(path, &args).await? {
            ProtocolResource::File(file) => Ok(RuntimeFile { inner: file }),
            _ => Err(Error::InvalidState(
                "server returned a non-file resource".into(),
            )),
        }
    }

    pub(crate) async fn open_file_at_version(
        &self,
        path: &str,
        timestamp: u64,
    ) -> crate::Result<RuntimeFile> {
        let args =
            FileCreateArgs::make_open_existing(FileAccessMask::new().with_generic_read(true))
                .with_timewarp(smb_dtyp::binrw_util::prelude::FileTime::from(timestamp));
        match self.inner.create(path, &args).await? {
            ProtocolResource::File(file) => Ok(RuntimeFile { inner: file }),
            _ => Err(Error::InvalidState(
                "server returned a non-file Previous Version".into(),
            )),
        }
    }

    pub(crate) async fn open_directory(
        &self,
        path: &str,
        create: bool,
    ) -> crate::Result<RuntimeDirectory> {
        let args = if create {
            FileCreateArgs::make_create_new(
                FileAttributes::new().with_directory(true),
                CreateOptions::new().with_directory_file(true),
            )
        } else {
            FileCreateArgs {
                options: CreateOptions::new().with_directory_file(true),
                ..FileCreateArgs::make_open_existing(
                    FileAccessMask::new()
                        .with_generic_read(true)
                        .with_generic_write(true)
                        .with_delete(true),
                )
            }
        };
        match self.inner.create(path, &args).await? {
            ProtocolResource::Directory(directory) => Ok(RuntimeDirectory {
                inner: Arc::new(directory),
            }),
            _ => Err(Error::InvalidState(
                "server returned a non-directory resource".into(),
            )),
        }
    }

    pub(crate) async fn open_pipe(&self, name: &str) -> crate::Result<RuntimePipe> {
        match self
            .inner
            .create(name, &FileCreateArgs::make_pipe())
            .await?
        {
            ProtocolResource::Pipe(pipe) => Ok(RuntimePipe { inner: pipe }),
            _ => Err(Error::InvalidState(
                "server returned a non-pipe resource".into(),
            )),
        }
    }

    pub(crate) async fn close(&self) -> crate::Result<()> {
        self.inner.disconnect().await
    }
}

pub(crate) struct RuntimePipe {
    inner: ProtocolPipe,
}

impl RuntimePipe {
    pub(crate) async fn query_security(&self, dacl: bool) -> crate::Result<SecurityDescriptor> {
        query_security(&self.inner, dacl).await
    }

    pub(crate) async fn set_security(
        &self,
        descriptor: SecurityDescriptor,
        dacl: bool,
    ) -> crate::Result<()> {
        set_security(&self.inner, descriptor, dacl).await
    }

    pub(crate) async fn read(
        &self,
        max_len: u32,
        timeout: Option<std::time::Duration>,
        cancellation: tokio_util::sync::CancellationToken,
        replay: crate::runtime::ReplayPolicy,
    ) -> crate::Result<Bytes> {
        self.inner
            .read_bytes_with_options(
                max_len,
                FileOperationOptions {
                    timeout,
                    cancellation: Some(cancellation),
                    replay,
                },
            )
            .await
    }

    pub(crate) async fn write(
        &self,
        bytes: Bytes,
        timeout: Option<std::time::Duration>,
        cancellation: tokio_util::sync::CancellationToken,
        replay: crate::runtime::ReplayPolicy,
    ) -> crate::Result<usize> {
        self.inner
            .write_bytes_with_options(
                bytes,
                FileOperationOptions {
                    timeout,
                    cancellation: Some(cancellation),
                    replay,
                },
            )
            .await
    }

    pub(crate) async fn transact(
        &self,
        request: Bytes,
        max_response: u32,
        timeout: Option<std::time::Duration>,
        cancellation: tokio_util::sync::CancellationToken,
    ) -> crate::Result<Bytes> {
        self.inner
            .transact_bytes(
                request,
                max_response,
                FileOperationOptions {
                    timeout,
                    cancellation: Some(cancellation),
                    replay: crate::runtime::ReplayPolicy::NeverReplay,
                },
            )
            .await
    }

    pub(crate) async fn close(&self) -> crate::Result<()> {
        self.inner.close().await
    }
}

pub(crate) struct RuntimeDirectoryEntry {
    pub(crate) name: String,
    pub(crate) is_directory: bool,
    pub(crate) len: u64,
    pub(crate) created: SystemTime,
    pub(crate) accessed: SystemTime,
    pub(crate) written: SystemTime,
    pub(crate) changed: SystemTime,
    pub(crate) readonly: bool,
    pub(crate) reparse_point: bool,
}

pub(crate) enum RuntimeDirectoryEventKind {
    Added,
    Removed,
    Modified,
    RenamedOld,
    RenamedNew,
    StreamAdded,
    StreamRemoved,
    StreamModified,
    IdentifierUnavailable,
    IdentifierCollision,
}

pub(crate) struct RuntimeDirectoryEvent {
    pub(crate) kind: RuntimeDirectoryEventKind,
    pub(crate) path: String,
}

pub(crate) struct RuntimeDirectory {
    inner: Arc<ProtocolDirectory>,
}

impl RuntimeDirectory {
    pub(crate) async fn set_metadata(
        &self,
        created: Option<SystemTime>,
        accessed: Option<SystemTime>,
        written: Option<SystemTime>,
    ) -> crate::Result<()> {
        metadata::set_metadata(&self.inner, created, accessed, written).await
    }

    pub(crate) async fn query_security(&self, dacl: bool) -> crate::Result<SecurityDescriptor> {
        query_security(&self.inner, dacl).await
    }

    pub(crate) async fn set_security(
        &self,
        descriptor: SecurityDescriptor,
        dacl: bool,
    ) -> crate::Result<()> {
        set_security(&self.inner, descriptor, dacl).await
    }

    pub(crate) async fn metadata(&self) -> crate::Result<RuntimeMetadata> {
        metadata(&self.inner).await
    }

    pub(crate) fn entries<'a>(
        &'a self,
        pattern: &'a str,
    ) -> Pin<Box<dyn Stream<Item = crate::Result<RuntimeDirectoryEntry>> + Send + 'a>> {
        Box::pin(
            futures_util::stream::once(async move {
                ProtocolDirectory::query::<FileDirectoryInformation>(&self.inner, pattern).await
            })
            .try_flatten()
            .map_ok(|entry| RuntimeDirectoryEntry {
                name: entry.file_name.to_string(),
                is_directory: entry.file_attributes.directory(),
                len: entry.end_of_file,
                created: entry.creation_time.into(),
                accessed: entry.last_access_time.into(),
                written: entry.last_write_time.into(),
                changed: entry.change_time.into(),
                readonly: entry.file_attributes.readonly(),
                reparse_point: entry.file_attributes.reparse_point(),
            }),
        )
    }

    pub(crate) fn watch<'a>(
        &'a self,
        recursive: bool,
        cancellation: tokio_util::sync::CancellationToken,
    ) -> Pin<Box<dyn Stream<Item = crate::Result<RuntimeDirectoryEvent>> + Send + 'a>> {
        Box::pin(
            futures_util::stream::once(async move {
                ProtocolDirectory::watch_stream_cancellable(
                    &self.inner,
                    NotifyFilter::all(),
                    recursive,
                    cancellation,
                )
            })
            .try_flatten()
            .map_ok(|event| RuntimeDirectoryEvent {
                kind: match event.action {
                    NotifyAction::Added => RuntimeDirectoryEventKind::Added,
                    NotifyAction::Removed => RuntimeDirectoryEventKind::Removed,
                    NotifyAction::Modified => RuntimeDirectoryEventKind::Modified,
                    NotifyAction::RenamedOldName => RuntimeDirectoryEventKind::RenamedOld,
                    NotifyAction::RenamedNewName => RuntimeDirectoryEventKind::RenamedNew,
                    NotifyAction::AddedStream => RuntimeDirectoryEventKind::StreamAdded,
                    NotifyAction::RemovedStream => RuntimeDirectoryEventKind::StreamRemoved,
                    NotifyAction::ModifiedStream => RuntimeDirectoryEventKind::StreamModified,
                    NotifyAction::RemovedByDelete => RuntimeDirectoryEventKind::Removed,
                    NotifyAction::IdNotTunnelled => {
                        RuntimeDirectoryEventKind::IdentifierUnavailable
                    }
                    NotifyAction::TunnelledIdCollision => {
                        RuntimeDirectoryEventKind::IdentifierCollision
                    }
                },
                path: event.file_name.to_string(),
            }),
        )
    }

    pub(crate) async fn delete(&self) -> crate::Result<()> {
        self.inner
            .set_info(FileDispositionInformation::default())
            .await
    }

    /// Renames the open directory through `FileRenameInformation`, exactly like a file.
    pub(crate) async fn rename(&self, path: &str, replace: bool) -> crate::Result<()> {
        self.inner
            .set_info(FileRenameInformation {
                replace_if_exists: replace.into(),
                root_directory: 0,
                file_name: path.into(),
            })
            .await
    }

    pub(crate) async fn close(&self) -> crate::Result<()> {
        self.inner.close().await
    }
}

pub(crate) struct RuntimeFile {
    inner: ProtocolFile,
}

impl RuntimeFile {
    pub(crate) async fn set_metadata(
        &self,
        created: Option<SystemTime>,
        accessed: Option<SystemTime>,
        written: Option<SystemTime>,
    ) -> crate::Result<()> {
        metadata::set_metadata(&self.inner, created, accessed, written).await
    }

    pub(crate) async fn flush(&self) -> crate::Result<()> {
        self.inner.flush().await.map_err(Error::IoError)
    }

    pub(crate) fn persistent_granted(&self) -> bool {
        self.inner
            .durable_granted()
            .is_some_and(|grant| grant.persistent)
    }
    pub(crate) async fn previous_versions(&self) -> crate::Result<Vec<String>> {
        let response = self
            .inner
            .fsctl_with_options(SrvEnumerateSnapshotsRequest::new(()), 64 * 1024)
            .await?;
        Ok(response.snap_shots.into_iter().collect())
    }
    pub(crate) async fn query_security(&self, dacl: bool) -> crate::Result<SecurityDescriptor> {
        query_security(&self.inner, dacl).await
    }

    pub(crate) async fn set_security(
        &self,
        descriptor: SecurityDescriptor,
        dacl: bool,
    ) -> crate::Result<()> {
        set_security(&self.inner, descriptor, dacl).await
    }

    pub(crate) async fn metadata(&self) -> crate::Result<RuntimeMetadata> {
        metadata(&self.inner).await
    }

    pub(crate) fn opened_len(&self) -> u64 {
        self.inner.end_of_file()
    }

    pub(crate) fn maximum_read_size(&self) -> u32 {
        self.inner.maximum_read_size()
    }

    pub(crate) fn maximum_write_size(&self) -> u32 {
        self.inner.maximum_write_size()
    }

    pub(crate) async fn len(&self) -> crate::Result<u64> {
        Ok(self
            .inner
            .query_info::<FileStandardInformation>()
            .await?
            .end_of_file)
    }

    pub(crate) async fn read_at(
        &self,
        offset: u64,
        max_len: u32,
        timeout: Option<std::time::Duration>,
        cancellation: tokio_util::sync::CancellationToken,
        replay: crate::runtime::ReplayPolicy,
    ) -> crate::Result<Bytes> {
        self.inner
            .read_block_bytes_with_options(
                max_len,
                offset,
                None,
                false,
                FileOperationOptions {
                    timeout,
                    cancellation: Some(cancellation),
                    replay,
                },
            )
            .await
    }

    pub(crate) async fn write_at(
        &self,
        offset: u64,
        bytes: Bytes,
        timeout: Option<std::time::Duration>,
        cancellation: tokio_util::sync::CancellationToken,
        replay: crate::runtime::ReplayPolicy,
    ) -> crate::Result<usize> {
        self.inner
            .write_block_zc_with_options(
                bytes,
                offset,
                None,
                FileOperationOptions {
                    timeout,
                    cancellation: Some(cancellation),
                    replay,
                },
            )
            .await
    }

    pub(crate) async fn delete(&self) -> crate::Result<()> {
        self.inner
            .set_info(FileDispositionInformation::default())
            .await
    }

    pub(crate) async fn rename(&self, path: &str, replace: bool) -> crate::Result<()> {
        self.inner
            .set_info(FileRenameInformation {
                replace_if_exists: replace.into(),
                root_directory: 0,
                file_name: path.into(),
            })
            .await
    }

    pub(crate) async fn close(&self) -> crate::Result<()> {
        self.inner.close().await
    }
}

async fn metadata(resource: &crate::resource::ResourceHandle) -> crate::Result<RuntimeMetadata> {
    let basic = resource.query_info::<FileBasicInformation>().await?;
    let standard = resource.query_info::<FileStandardInformation>().await?;
    Ok(RuntimeMetadata {
        created: basic.creation_time.into(),
        accessed: basic.last_access_time.into(),
        written: basic.last_write_time.into(),
        changed: basic.change_time.into(),
        len: standard.end_of_file,
    })
}

fn security_selection(dacl: bool) -> AdditionalInfo {
    AdditionalInfo::new().with_dacl_security_information(dacl)
}

async fn query_security(
    resource: &crate::resource::ResourceHandle,
    dacl: bool,
) -> crate::Result<SecurityDescriptor> {
    resource.query_security_info(security_selection(dacl)).await
}

async fn set_security(
    resource: &crate::resource::ResourceHandle,
    descriptor: SecurityDescriptor,
    dacl: bool,
) -> crate::Result<()> {
    resource
        .set_security_info(descriptor, security_selection(dacl))
        .await
}

#[cfg(test)]
mod tests {
    use super::client_config;
    use crate::{GuestPolicy, SigningPolicy};

    #[test]
    fn negotiation_never_opens_with_the_smb1_multi_protocol_frame() {
        for signing in [SigningPolicy::Required, SigningPolicy::WhenRequired] {
            for guest in [GuestPolicy::Deny, GuestPolicy::AllowUnsigned] {
                let config = client_config(signing, guest);
                assert!(
                    config.connection.smb2_only_negotiate,
                    "signing={signing:?} guest={guest:?}"
                );
                assert_eq!(config.connection.signing_policy, signing);
            }
        }
    }

    #[test]
    fn the_protocol_default_would_send_smb1_which_is_why_the_facade_overrides_it() {
        assert!(
            !super::ProtocolClientConfig::default()
                .connection
                .smb2_only_negotiate
        );
    }
}
