//! Runtime port consumed by the domain layer.
//!
//! This module owns no lifecycle state. It is the single crate-private
//! boundary that keeps protocol and runtime implementation types out of the
//! domain API. Legacy protocol mechanics remain an implementation detail behind
//! this stable port while callers use the domain object hierarchy.

use std::{pin::Pin, sync::Arc};

use bytes::Bytes;
use futures_core::Stream;
use futures_util::TryStreamExt;
use smb_dtyp::SecurityDescriptor;
use smb_fscc::{
    FileAccessMask, FileAttributes, FileBasicInformation, FileDirectoryInformation,
    FileDispositionInformation, FileRenameInformation, FileStandardInformation, NotifyAction,
};
use smb_msg::{AdditionalInfo, CreateOptions, NotifyFilter, SrvEnumerateSnapshotsRequest};
use sspi::{AuthIdentity, Secret, Username};

use crate::{
    Error,
    client::{Client as LegacyClient, ClientConfig as LegacyClientConfig, UncPath},
    resource::{
        Directory as LegacyDirectory, File as LegacyFile, FileCreateArgs, Pipe as LegacyPipe,
        Resource as LegacyResource, file::FileOperationOptions,
    },
    session::Session as LegacySession,
    tree::Tree as LegacyShare,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OpenMode {
    CreateNew,
    OpenExisting,
    Overwrite,
}

pub(crate) struct RuntimeClient {
    inner: Arc<LegacyClient>,
}

impl RuntimeClient {
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(LegacyClient::new(LegacyClientConfig::default())),
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

    pub(crate) async fn close(&self) -> crate::Result<()> {
        self.inner.close().await
    }
}

pub(crate) struct RuntimeSession {
    inner: Arc<LegacySession>,
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
    inner: Arc<LegacyShare>,
}

pub(crate) enum RuntimeResource {
    File(RuntimeFile),
    Directory(RuntimeDirectory),
    Pipe(RuntimePipe),
}

pub(crate) struct RuntimeMetadata {
    pub(crate) created: std::time::SystemTime,
    pub(crate) accessed: std::time::SystemTime,
    pub(crate) written: std::time::SystemTime,
    pub(crate) changed: std::time::SystemTime,
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
            LegacyResource::File(file) => RuntimeResource::File(RuntimeFile { inner: file }),
            LegacyResource::Directory(directory) => RuntimeResource::Directory(RuntimeDirectory {
                inner: Arc::new(directory),
            }),
            LegacyResource::Pipe(pipe) => RuntimeResource::Pipe(RuntimePipe { inner: pipe }),
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
            LegacyResource::File(file) => RuntimeResource::File(RuntimeFile { inner: file }),
            LegacyResource::Directory(directory) => RuntimeResource::Directory(RuntimeDirectory {
                inner: Arc::new(directory),
            }),
            LegacyResource::Pipe(pipe) => RuntimeResource::Pipe(RuntimePipe { inner: pipe }),
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
            LegacyResource::File(file) => Ok(RuntimeFile { inner: file }),
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
            LegacyResource::File(file) => Ok(RuntimeFile { inner: file }),
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
            LegacyResource::Directory(directory) => Ok(RuntimeDirectory {
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
            LegacyResource::Pipe(pipe) => Ok(RuntimePipe { inner: pipe }),
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
    inner: LegacyPipe,
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
    inner: Arc<LegacyDirectory>,
}

impl RuntimeDirectory {
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
                LegacyDirectory::query::<FileDirectoryInformation>(&self.inner, pattern).await
            })
            .try_flatten()
            .map_ok(|entry| RuntimeDirectoryEntry {
                name: entry.file_name.to_string(),
                is_directory: entry.file_attributes.directory(),
                len: entry.end_of_file,
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
                LegacyDirectory::watch_stream_cancellable(
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

    pub(crate) async fn close(&self) -> crate::Result<()> {
        self.inner.close().await
    }
}

pub(crate) struct RuntimeFile {
    inner: LegacyFile,
}

impl RuntimeFile {
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

    pub(crate) async fn rename(&self, path: &str) -> crate::Result<()> {
        self.inner
            .set_info(FileRenameInformation {
                replace_if_exists: false.into(),
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
