//! Temporary W5 bridge from domain handles to the accepted W4 runtime path.
//!
//! This module owns no lifecycle state. It wraps the existing W4-backed
//! objects while their implementations are moved behind the runtime/domain
//! boundary during W5.

use std::{pin::Pin, sync::Arc};

use bytes::Bytes;
use futures_core::Stream;
use futures_util::TryStreamExt;
use smb_fscc::{
    FileAccessMask, FileAttributes, FileDirectoryInformation, FileDispositionInformation,
    FileRenameInformation, FileStandardInformation, NotifyAction,
};
use smb_msg::{CreateOptions, NotifyFilter};
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
            shares: tokio::sync::Mutex::new(Vec::new()),
        })
    }

    pub(crate) async fn close(&self) -> crate::Result<()> {
        self.inner.close().await
    }
}

pub(crate) struct RuntimeSession {
    inner: Arc<LegacySession>,
    server: String,
    shares: tokio::sync::Mutex<Vec<std::sync::Weak<LegacyShare>>>,
}

impl RuntimeSession {
    pub(crate) async fn connect_share(&self, share: &str) -> crate::Result<RuntimeShare> {
        let target = UncPath::new(&self.server)?.with_share(share)?;
        let share = Arc::new(self.inner.tree_connect(&target).await?);
        let mut shares = self.shares.lock().await;
        shares.retain(|entry| entry.strong_count() != 0);
        shares.push(Arc::downgrade(&share));
        Ok(RuntimeShare { inner: share })
    }

    pub(crate) async fn close(&self) -> crate::Result<()> {
        let shares = {
            let mut registry = self.shares.lock().await;
            let shares = registry
                .iter()
                .filter_map(std::sync::Weak::upgrade)
                .collect::<Vec<_>>();
            registry.clear();
            shares
        };
        let mut first_error = None;
        for share in shares {
            if let Err(error) = share.disconnect().await {
                first_error.get_or_insert(error);
            }
        }
        let logoff = self.inner.logoff().await;
        match (first_error, logoff) {
            (Some(error), _) => Err(error),
            (None, result) => result,
        }
    }
}

pub(crate) struct RuntimeShare {
    inner: Arc<LegacyShare>,
}

impl RuntimeShare {
    pub(crate) async fn open_file(&self, path: &str, mode: OpenMode) -> crate::Result<RuntimeFile> {
        let args = match mode {
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
        match self.inner.create(path, &args).await? {
            LegacyResource::File(file) => Ok(RuntimeFile { inner: file }),
            _ => Err(Error::InvalidState(
                "server returned a non-file resource".into(),
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
