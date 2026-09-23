//! Runtime port consumed by the domain layer.
//!
//! This module owns no lifecycle state. It is the single crate-private
//! boundary that keeps protocol and runtime implementation types out of the
//! domain API. Legacy protocol mechanics remain an implementation detail behind
//! this stable port while callers use the domain object hierarchy.

use std::{pin::Pin, sync::Arc, time::SystemTime};

use bytes::Bytes;
use futures_core::{Stream, future::BoxFuture};
use futures_util::{StreamExt, TryStreamExt};
use smb_dtyp::SecurityDescriptor;
use smb_dtyp::binrw_util::prelude::FileTime;
use smb_fscc::{
    FileAccessMask, FileAttributes, FileBasicInformation, FileDirectoryInformation,
    FileDispositionInformation, FileIdExtdDirectoryInformation, FileIdFullDirectoryInformation,
    FileRenameInformation, FileStandardInformation, NotifyAction,
};
use smb_msg::{AdditionalInfo, CreateOptions, NotifyFilter, SrvEnumerateSnapshotsRequest, Status};
use sspi::{AuthIdentity, Secret, Username};
use tokio_util::task::TaskTracker;
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
        Ok(RuntimeShare {
            inner: share,
            security_cleanup: SecurityCleanup::new(),
        })
    }

    pub(crate) async fn close(&self) -> crate::Result<()> {
        self.inner.logoff().await
    }
}

pub(crate) struct RuntimeShare {
    inner: Arc<ProtocolShare>,
    security_cleanup: SecurityCleanup,
}

pub(crate) enum RuntimeResource {
    File(RuntimeFile),
    Directory(RuntimeDirectory),
    Pipe(RuntimePipe),
}

struct SecurityResourceGuard {
    resource: Option<RuntimeResource>,
    cleanup: SecurityCleanup,
}

impl SecurityResourceGuard {
    fn new(resource: RuntimeResource, cleanup: SecurityCleanup) -> Self {
        Self {
            resource: Some(resource),
            cleanup,
        }
    }

    fn resource(&self) -> crate::Result<&RuntimeResource> {
        self.resource
            .as_ref()
            .ok_or_else(|| Error::InvalidState("security resource was already closed".to_string()))
    }

    async fn close(mut self) -> crate::Result<()> {
        let resource = self.resource.take().ok_or_else(|| {
            Error::InvalidState("security resource was already closed".to_string())
        })?;
        let cleanup = self.cleanup.spawn(close_security_resource(resource));
        cleanup.await.map_err(|error| {
            Error::InvalidState(format!("security resource cleanup task failed: {error}"))
        })?
    }
}

#[derive(Clone)]
struct SecurityCleanup {
    tasks: TaskTracker,
    runtime: tokio::runtime::Handle,
}

impl SecurityCleanup {
    fn new() -> Self {
        Self {
            tasks: TaskTracker::new(),
            runtime: tokio::runtime::Handle::current(),
        }
    }

    fn spawn<F, T>(&self, cleanup: F) -> tokio::task::JoinHandle<T>
    where
        F: std::future::Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        self.tasks.spawn_on(cleanup, &self.runtime)
    }

    async fn close_and_wait(&self) {
        self.tasks.close();
        self.tasks.wait().await;
    }
}

impl Drop for SecurityResourceGuard {
    fn drop(&mut self) {
        let Some(resource) = self.resource.take() else {
            return;
        };
        let cleanup = self.cleanup.spawn(close_security_resource(resource));
        std::mem::drop(cleanup);
    }
}

async fn close_security_resource(resource: RuntimeResource) -> crate::Result<()> {
    let result = resource.close().await;
    if let Err(error) = &result {
        tracing::warn!(?error, "security resource cleanup failed");
    }
    result
}

impl RuntimeResource {
    async fn query_security(&self, dacl: bool) -> crate::Result<SecurityDescriptor> {
        match self {
            Self::File(file) => file.query_security(dacl).await,
            Self::Directory(directory) => directory.query_security(dacl).await,
            Self::Pipe(pipe) => pipe.query_security(dacl).await,
        }
    }

    async fn set_security(&self, descriptor: SecurityDescriptor, dacl: bool) -> crate::Result<()> {
        match self {
            Self::File(file) => file.set_security(descriptor, dacl).await,
            Self::Directory(directory) => directory.set_security(descriptor, dacl).await,
            Self::Pipe(pipe) => pipe.set_security(descriptor, dacl).await,
        }
    }

    async fn close(&self) -> crate::Result<()> {
        match self {
            Self::File(file) => file.close().await,
            Self::Directory(directory) => directory.close().await,
            Self::Pipe(pipe) => pipe.close().await,
        }
    }
}

pub(crate) struct RuntimeMetadata {
    pub(crate) created: SystemTime,
    pub(crate) accessed: SystemTime,
    pub(crate) written: SystemTime,
    pub(crate) changed: SystemTime,
    pub(crate) len: u64,
    pub(crate) readonly: bool,
    pub(crate) reparse_point: bool,
    pub(crate) file_id: Option<u64>,
    pub(crate) volume_id: Option<u64>,
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
        if let Some(handle) = resource.handle()
            && let Err(error) = metadata::reject_reparse(handle).await
        {
            let _ = handle.close().await;
            return Err(error);
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
        read_control: bool,
        write_dacl: bool,
    ) -> crate::Result<RuntimeResource> {
        let access = security_resource_access(read_control, write_dacl);
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

    pub(crate) async fn query_path_security(
        &self,
        path: &str,
        dacl: bool,
    ) -> crate::Result<SecurityDescriptor> {
        let resource = SecurityResourceGuard::new(
            self.open_security_resource(path, true, false).await?,
            self.security_cleanup.clone(),
        );
        let result = resource.resource()?.query_security(dacl).await;
        let close = resource.close().await;
        match result {
            Err(error) => Err(error),
            Ok(descriptor) => {
                close?;
                Ok(descriptor)
            }
        }
    }

    pub(crate) async fn set_path_security(
        &self,
        path: &str,
        descriptor: SecurityDescriptor,
        dacl: bool,
    ) -> crate::Result<()> {
        let resource = SecurityResourceGuard::new(
            self.open_security_resource(path, false, dacl).await?,
            self.security_cleanup.clone(),
        );
        let result = resource.resource()?.set_security(descriptor, dacl).await;
        let close = resource.close().await;
        result?;
        close
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
        self.security_cleanup.close_and_wait().await;
        self.inner.disconnect().await
    }
}

fn security_resource_access(read_control: bool, write_dacl: bool) -> FileAccessMask {
    FileAccessMask::new()
        .with_read_control(read_control)
        .with_write_dacl(write_dacl)
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
    /// 64-bit file identifier, when the server accepted an information class that carries one.
    ///
    /// The same width the `QFid` create context reports on an open, so a listing and an open of
    /// the same object agree on every filesystem (ReFS also has a 128-bit form, whose low half
    /// is this value). `None` means the server rejected every wide class, not that the entry
    /// has no identity. A zero identifier is also reported as `None`: FAT and other back ends
    /// that do not track one answer with zero rather than refusing the class.
    pub(crate) file_id: Option<u64>,
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

    pub(crate) fn opened_metadata(&self) -> RuntimeMetadata {
        opened_metadata(&self.inner.handle)
    }

    pub(crate) fn entries<'a>(
        &'a self,
        pattern: &'a str,
    ) -> Pin<Box<dyn Stream<Item = crate::Result<RuntimeDirectoryEntry>> + Send + 'a>> {
        Box::pin(
            futures_util::stream::once(async move { self.entry_stream(pattern).await })
                .try_flatten(),
        )
    }

    /// Enumerates with the widest information class the server accepts.
    ///
    /// `FileIdFullDirectoryInformation` carries the 64-bit identifier the `QFid` create context
    /// also reports, and `FileIdExtdDirectoryInformation` a 128-bit one whose low half is that
    /// value; both arrive in the same `QUERY_DIRECTORY` responses as the narrow class, so an
    /// identifier costs no extra round trip. Servers that do not implement a class answer
    /// `STATUS_INVALID_INFO_CLASS`, and that answer only appears once the query has actually
    /// run — `query` hands back a stream whose first item carries it — so each rung is probed
    /// by reading that first item. A rejected stream is dropped, which releases the directory's
    /// query lock and cancels its fetch loop before the next rung is tried.
    async fn entry_stream<'a>(
        &'a self,
        pattern: &'a str,
    ) -> crate::Result<Pin<Box<dyn Stream<Item = crate::Result<RuntimeDirectoryEntry>> + Send + 'a>>>
    {
        if let Some(stream) = probe_class(
            &self.inner,
            pattern,
            |entry: FileIdFullDirectoryInformation| {
                let file_id = entry.file_id;
                runtime_entry(
                    entry.file_name.to_string(),
                    entry.file_attributes,
                    entry.end_of_file,
                    (
                        entry.creation_time,
                        entry.last_access_time,
                        entry.last_write_time,
                        entry.change_time,
                    ),
                    identifier(file_id),
                )
            },
        )
        .await?
        {
            return Ok(stream);
        }
        if let Some(stream) = probe_class(
            &self.inner,
            pattern,
            |entry: FileIdExtdDirectoryInformation| {
                // Low 64 bits: the width every other source of this identifier reports.
                let file_id = (entry.file_id & u128::from(u64::MAX)) as u64;
                runtime_entry(
                    entry.file_name.to_string(),
                    entry.file_attributes,
                    entry.end_of_file,
                    (
                        entry.creation_time,
                        entry.last_access_time,
                        entry.last_write_time,
                        entry.change_time,
                    ),
                    identifier(file_id),
                )
            },
        )
        .await?
        {
            return Ok(stream);
        }
        tracing::debug!(
            "server rejected every file-id directory class; enumerating without identifiers"
        );
        let stream = ProtocolDirectory::query::<FileDirectoryInformation>(&self.inner, pattern)
            .await?
            .map_ok(|entry| {
                runtime_entry(
                    entry.file_name.to_string(),
                    entry.file_attributes,
                    entry.end_of_file,
                    (
                        entry.creation_time,
                        entry.last_access_time,
                        entry.last_write_time,
                        entry.change_time,
                    ),
                    None,
                )
            });
        Ok(Box::pin(stream))
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

    pub(crate) fn opened_metadata(&self) -> RuntimeMetadata {
        opened_metadata(self.inner.handle())
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

/// Zero means "this back end does not track one" rather than a real identifier: FAT and similar
/// volumes accept the wide class and answer zero instead of refusing it.
fn identifier(file_id: u64) -> Option<u64> {
    (file_id != 0).then_some(file_id)
}

fn runtime_entry(
    name: String,
    attributes: FileAttributes,
    len: u64,
    times: (FileTime, FileTime, FileTime, FileTime),
    file_id: Option<u64>,
) -> RuntimeDirectoryEntry {
    let (created, accessed, written, changed) = times;
    RuntimeDirectoryEntry {
        name,
        is_directory: attributes.directory(),
        len,
        created: created.into(),
        accessed: accessed.into(),
        written: written.into(),
        changed: changed.into(),
        readonly: attributes.readonly(),
        reparse_point: attributes.reparse_point(),
        file_id,
    }
}

/// Runs one rung of the information-class ladder.
///
/// `Ok(None)` means the server rejected the class and the caller should try a narrower one. Any
/// other failure belongs to the caller, not to the ladder, and is propagated.
async fn probe_class<'a, T, F>(
    directory: &'a Arc<ProtocolDirectory>,
    pattern: &'a str,
    convert: F,
) -> crate::Result<
    Option<Pin<Box<dyn Stream<Item = crate::Result<RuntimeDirectoryEntry>> + Send + 'a>>>,
>
where
    T: smb_fscc::QueryDirectoryInfoValue
        + for<'b> binrw::prelude::BinWrite<Args<'b> = ()>
        + Unpin
        + Send
        + 'a,
    F: Fn(T) -> RuntimeDirectoryEntry + Send + 'a,
{
    let mut stream = ProtocolDirectory::query::<T>(directory, pattern).await?;
    let first = stream.next().await;
    match first {
        Some(Err(error)) if is_invalid_info_class(&error) => Ok(None),
        Some(Err(error)) => Err(error),
        // The probe consumed the first item, so put it back in front of the rest.
        Some(Ok(entry)) => Ok(Some(Box::pin(
            futures_util::stream::once(std::future::ready(Ok(convert(entry))))
                .chain(stream.map_ok(convert)),
        ))),
        None => Ok(Some(Box::pin(futures_util::stream::empty()))),
    }
}

fn is_invalid_info_class(error: &crate::Error) -> bool {
    matches!(
        error,
        crate::Error::ReceivedErrorMessage(status, _)
            | crate::Error::UnexpectedMessageStatus(status)
            if *status == Status::U32_INVALID_INFO_CLASS
    )
}

async fn metadata(resource: &crate::resource::ResourceHandle) -> crate::Result<RuntimeMetadata> {
    let basic = resource.query_info::<FileBasicInformation>().await?;
    let standard = resource.query_info::<FileStandardInformation>().await?;
    let opened = resource.opened();
    Ok(RuntimeMetadata {
        created: basic.creation_time.into(),
        accessed: basic.last_access_time.into(),
        written: basic.last_write_time.into(),
        changed: basic.change_time.into(),
        len: standard.end_of_file,
        // `FileBasicInformation` already carries the attributes; reporting them costs nothing
        // beyond the query that was being made anyway.
        readonly: basic.file_attributes.readonly(),
        reparse_point: basic.file_attributes.reparse_point(),
        // Identity does not change over the life of an open, so the `CREATE` answer is as
        // authoritative as a fresh query and costs nothing.
        file_id: opened.file_id(),
        volume_id: opened.volume_id(),
    })
}

/// Metadata as the `CREATE` response reported it, with no `QUERY_INFO` round trip.
///
/// Accurate for anything observed at open time. A caller that has written through the handle
/// since and needs the current length or timestamps must use [`metadata`] instead.
fn opened_metadata(resource: &crate::resource::ResourceHandle) -> RuntimeMetadata {
    let opened = resource.opened();
    RuntimeMetadata {
        created: opened.created().into(),
        accessed: opened.accessed().into(),
        written: opened.written().into(),
        changed: opened.changed().into(),
        len: opened.end_of_file(),
        readonly: opened.attributes().readonly(),
        reparse_point: opened.attributes().reparse_point() || opened.is_reparse_point(),
        file_id: opened.file_id(),
        volume_id: opened.volume_id(),
    }
}

fn query_security_selection(dacl: bool) -> AdditionalInfo {
    AdditionalInfo::new().with_dacl_security_information(dacl)
}

fn set_security_selection(dacl: bool, dacl_protected: bool) -> AdditionalInfo {
    AdditionalInfo::new()
        .with_dacl_security_information(dacl)
        .with_protected_dacl_security_information(dacl && dacl_protected)
        .with_unprotected_dacl_security_information(dacl && !dacl_protected)
}

async fn query_security(
    resource: &crate::resource::ResourceHandle,
    dacl: bool,
) -> crate::Result<SecurityDescriptor> {
    resource
        .query_security_info(query_security_selection(dacl))
        .await
}

async fn set_security(
    resource: &crate::resource::ResourceHandle,
    descriptor: SecurityDescriptor,
    dacl: bool,
) -> crate::Result<()> {
    let additional_information = set_security_selection(dacl, descriptor.control.dacl_protected());
    resource
        .set_security_info(descriptor, additional_information)
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
