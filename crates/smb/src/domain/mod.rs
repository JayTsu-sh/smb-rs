//! SMB domain handles.

mod batch;
mod cursor;
mod metadata;
mod operation;
mod rpc;
mod security;
mod transfer;
pub use batch::{Batch, BatchCommand, BatchOutcome, BatchRef, BatchResult};
pub use cursor::FileCursor;
pub use metadata::{MetadataOpenOptions, MetadataUpdate};
pub use operation::{CancelToken, Deadline, Operation, ReplayPolicy};
pub use rpc::RpcPipeConnection;
pub use security::{SecurityDescriptor, SecurityOpenOptions, SecuritySelection};
pub use transfer::{Transfer, TransferEvents, TransferOptions, TransferProgress, TransferReport};

use std::{
    collections::HashMap,
    sync::{
        Arc, Weak,
        atomic::{AtomicUsize, Ordering},
    },
};

use bytes::Bytes;
use futures_core::{Stream, future::BoxFuture};
use futures_util::{StreamExt, TryStreamExt};
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, OnceCell};
use zeroize::Zeroizing;

use crate::{
    Error,
    runtime::port::{
        OpenMode, RuntimeClient, RuntimeCredentialProvider, RuntimeCredentials, RuntimeFile,
        RuntimeResource, RuntimeSession, RuntimeShare,
    },
};

/// Authentication material for establishing a logical SMB Session.
///
/// This type intentionally has no `Debug` implementation.
pub enum Credentials {
    Ntlm {
        username: Zeroizing<String>,
        password: Zeroizing<String>,
    },
    Anonymous,
    Provider(Arc<dyn CredentialProvider>),
}

/// Refreshable authentication source owned by a logical Session.
pub trait CredentialProvider: Send + Sync {
    /// Stable, non-secret identity used only for Session cache partitioning.
    fn cache_key(&self) -> &str;

    /// Obtain fresh authentication material for one SessionSetup attempt.
    fn credentials(&self) -> BoxFuture<'_, crate::Result<Credentials>>;
}

struct DomainCredentialAdapter {
    provider: Arc<dyn CredentialProvider>,
}

impl RuntimeCredentialProvider for DomainCredentialAdapter {
    fn credentials(&self) -> BoxFuture<'_, crate::Result<RuntimeCredentials>> {
        Box::pin(async move {
            match self.provider.credentials().await? {
                Credentials::Ntlm { username, password } => {
                    Ok(RuntimeCredentials { username, password })
                }
                Credentials::Anonymous => Err(Error::UnsupportedOperation(
                    "anonymous authentication is not activated".into(),
                )),
                Credentials::Provider(_) => Err(Error::InvalidArgument(
                    "credential providers must return concrete credentials".into(),
                )),
            }
        })
    }
}

/// Aggregate result of closing a logical parent handle and its descendants.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CloseReport {
    sessions: usize,
    shares: usize,
    resources: usize,
    first_teardown_cause: Option<String>,
}

impl CloseReport {
    pub const fn sessions(&self) -> usize {
        self.sessions
    }

    pub const fn shares(&self) -> usize {
        self.shares
    }

    pub const fn resources(&self) -> usize {
        self.resources
    }

    pub fn first_teardown_cause(&self) -> Option<&str> {
        self.first_teardown_cause.as_deref()
    }

    fn record_error(&mut self, error: Error) {
        if self.first_teardown_cause.is_none() {
            self.first_teardown_cause = Some(error.to_string());
        }
    }

    fn merge(&mut self, other: Self) {
        self.sessions += other.sessions;
        self.shares += other.shares;
        self.resources += other.resources;
        if self.first_teardown_cause.is_none() {
            self.first_teardown_cause = other.first_teardown_cause;
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionInfo {
    server: String,
}

impl SessionInfo {
    pub fn server(&self) -> &str {
        &self.server
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShareInfo {
    server: String,
    share: String,
}

impl ShareInfo {
    pub fn server(&self) -> &str {
        &self.server
    }

    pub fn share(&self) -> &str {
        &self.share
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenKind {
    File,
    Directory,
    Pipe,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenInfo {
    kind: OpenKind,
    name: String,
}

impl OpenInfo {
    fn new(kind: OpenKind, name: impl Into<String>) -> Self {
        Self {
            kind,
            name: name.into(),
        }
    }

    pub const fn kind(&self) -> OpenKind {
        self.kind
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

impl Credentials {
    pub fn ntlm(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self::Ntlm {
            username: Zeroizing::new(username.into()),
            password: Zeroizing::new(password.into()),
        }
    }

    pub fn provider(provider: impl CredentialProvider + 'static) -> Self {
        Self::Provider(Arc::new(provider))
    }
}

/// Validated server/share identity.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ShareTarget {
    server: String,
    share: String,
}

impl ShareTarget {
    pub fn new(server: impl Into<String>, share: impl Into<String>) -> crate::Result<Self> {
        let server = server.into();
        let share = share.into();
        if server.trim().is_empty() || server.contains(['\\', '/']) {
            return Err(Error::InvalidArgument("invalid SMB server identity".into()));
        }
        if share.trim().is_empty() || share.contains(['\\', '/']) {
            return Err(Error::InvalidArgument("invalid SMB share identity".into()));
        }
        Ok(Self { server, share })
    }

    pub fn server(&self) -> &str {
        &self.server
    }

    pub fn share(&self) -> &str {
        &self.share
    }
}

/// Normalized path relative to one Share root.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct SharePath(String);

impl SharePath {
    pub fn new(path: impl Into<String>) -> crate::Result<Self> {
        let path = path.into().replace('/', "\\");
        if path.is_empty()
            || path.starts_with('\\')
            || path
                .split('\\')
                .any(|component| component == ".." || component.is_empty())
        {
            return Err(Error::InvalidArgument(
                "path must remain within the Share".into(),
            ));
        }
        Ok(Self(path))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct PipeName(String);

impl PipeName {
    pub fn new(name: impl Into<String>) -> crate::Result<Self> {
        let name = name.into();
        if name.is_empty()
            || name == "."
            || name == ".."
            || name.contains(['/', '\\'])
            || name.chars().any(char::is_control)
        {
            return Err(Error::InvalidArgument(
                "pipe name must be one non-empty relative component".into(),
            ));
        }
        Ok(Self(name))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileOpenOptions {
    mode: OpenMode,
    persistent_timeout_millis: Option<u32>,
}

/// A validated server Previous Versions token.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreviousVersion {
    gmt_token: String,
    timestamp: u64,
}

impl PreviousVersion {
    pub fn from_gmt_token(token: impl Into<String>) -> crate::Result<Self> {
        let token = token.into();
        let fields = token
            .strip_prefix("@GMT-")
            .ok_or_else(|| Error::InvalidArgument("invalid Previous Version token".into()))?;
        if fields.len() != 19
            || fields.as_bytes()[4] != b'.'
            || fields.as_bytes()[7] != b'.'
            || fields.as_bytes()[10] != b'-'
            || fields.as_bytes()[13] != b'.'
            || fields.as_bytes()[16] != b'.'
        {
            return Err(Error::InvalidArgument(
                "invalid Previous Version token".into(),
            ));
        }
        let number = |range: std::ops::Range<usize>| {
            fields[range]
                .parse::<u8>()
                .map_err(|_| Error::InvalidArgument("invalid Previous Version token".into()))
        };
        let year = fields[..4]
            .parse::<i32>()
            .map_err(|_| Error::InvalidArgument("invalid Previous Version token".into()))?;
        let month = time::Month::try_from(number(5..7)?)
            .map_err(|_| Error::InvalidArgument("invalid Previous Version token".into()))?;
        let date = time::Date::from_calendar_date(year, month, number(8..10)?)
            .map_err(|_| Error::InvalidArgument("invalid Previous Version token".into()))?;
        let time = time::Time::from_hms(number(11..13)?, number(14..16)?, number(17..19)?)
            .map_err(|_| Error::InvalidArgument("invalid Previous Version token".into()))?;
        let timestamp = *smb_dtyp::binrw_util::prelude::FileTime::from(
            time::PrimitiveDateTime::new(date, time),
        );
        Ok(Self {
            gmt_token: token,
            timestamp,
        })
    }

    pub fn gmt_token(&self) -> &str {
        &self.gmt_token
    }
}

impl FileOpenOptions {
    pub const fn create_new() -> Self {
        Self {
            mode: OpenMode::CreateNew,
            persistent_timeout_millis: None,
        }
    }

    pub const fn open_existing() -> Self {
        Self {
            mode: OpenMode::OpenExisting,
            persistent_timeout_millis: None,
        }
    }

    pub const fn overwrite() -> Self {
        Self {
            mode: OpenMode::Overwrite,
            persistent_timeout_millis: None,
        }
    }

    pub const fn persistent(mut self, timeout_millis: u32) -> Self {
        self.persistent_timeout_millis = Some(timeout_millis);
        self
    }

    pub const fn requests_persistent_handle(&self) -> bool {
        self.persistent_timeout_millis.is_some()
    }

    pub const fn durable_timeout_millis(&self) -> Option<u32> {
        self.persistent_timeout_millis
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectoryOpenOptions {
    create: bool,
}

impl DirectoryOpenOptions {
    pub const fn open_existing() -> Self {
        Self { create: false }
    }

    pub const fn create_new() -> Self {
        Self { create: true }
    }
}

#[derive(Clone)]
pub(crate) struct DomainClient {
    inner: Arc<DomainClientInner>,
}

struct DomainClientInner {
    runtime: RuntimeClient,
    sessions: Mutex<SessionCache>,
    close_report: OnceCell<CloseReport>,
}

type SessionCacheKey = (String, [u8; 32]);
type SessionCache = HashMap<SessionCacheKey, Weak<SessionInner>>;

impl DomainClient {
    pub(crate) fn new() -> Self {
        Self::with_signing_policy(crate::SigningPolicy::default())
    }

    pub(crate) fn with_signing_policy(policy: crate::SigningPolicy) -> Self {
        Self {
            inner: Arc::new(DomainClientInner {
                runtime: RuntimeClient::with_signing_policy(policy),
                sessions: Mutex::new(HashMap::new()),
                close_report: OnceCell::new(),
            }),
        }
    }

    pub(crate) async fn authenticate(
        &self,
        server: &str,
        credentials: Credentials,
    ) -> crate::Result<Session> {
        let credential_digest: [u8; 32] = match &credentials {
            Credentials::Ntlm { username, password } => Sha256::new()
                .chain_update(username.as_bytes())
                .chain_update([0])
                .chain_update(password.as_bytes())
                .finalize()
                .into(),
            Credentials::Provider(provider) => Sha256::new()
                .chain_update(provider.cache_key().as_bytes())
                .finalize()
                .into(),
            Credentials::Anonymous => {
                return Err(Error::UnsupportedOperation(
                    "anonymous authentication is not activated".into(),
                ));
            }
        };
        let key = (server.to_owned(), credential_digest);
        if let Some(inner) = self
            .inner
            .sessions
            .lock()
            .await
            .get(&key)
            .and_then(Weak::upgrade)
        {
            return Ok(Session { inner });
        }
        let runtime = Arc::new(match credentials {
            Credentials::Ntlm { username, password } => {
                self.inner
                    .runtime
                    .authenticate(server, username.as_str(), password.to_string())
                    .await?
            }
            Credentials::Provider(provider) => {
                self.inner
                    .runtime
                    .authenticate_with_provider(
                        server,
                        Arc::new(DomainCredentialAdapter { provider }),
                    )
                    .await?
            }
            Credentials::Anonymous => unreachable!("anonymous credentials were rejected above"),
        });
        let inner = Arc::new(SessionInner {
            runtime,
            server: server.to_owned(),
            close_report: OnceCell::new(),
            shares: AtomicUsize::new(0),
            resources: AtomicUsize::new(0),
        });
        self.inner
            .sessions
            .lock()
            .await
            .insert(key, Arc::downgrade(&inner));
        Ok(Session { inner })
    }

    pub(crate) async fn close(&self) -> CloseReport {
        self.inner
            .close_report
            .get_or_init(|| async {
                let sessions = {
                    let mut cache = self.inner.sessions.lock().await;
                    let sessions = cache.values().filter_map(Weak::upgrade).collect::<Vec<_>>();
                    cache.clear();
                    sessions
                };
                let mut report = CloseReport {
                    sessions: sessions.len(),
                    ..CloseReport::default()
                };
                for session in sessions {
                    report.merge(session.close().await);
                }
                if let Err(error) = self.inner.runtime.close().await {
                    report.record_error(error);
                }
                report
            })
            .await
            .clone()
    }
}

/// Stable logical authenticated Session handle.
#[derive(Clone)]
pub struct Session {
    inner: Arc<SessionInner>,
}

struct SessionInner {
    runtime: Arc<RuntimeSession>,
    server: String,
    close_report: OnceCell<CloseReport>,
    shares: AtomicUsize,
    resources: AtomicUsize,
}

impl SessionInner {
    async fn close(&self) -> CloseReport {
        self.close_report
            .get_or_init(|| async {
                let mut report = CloseReport {
                    shares: self.shares.load(Ordering::Acquire),
                    resources: self.resources.load(Ordering::Acquire),
                    ..CloseReport::default()
                };
                if let Err(error) = self.runtime.close().await {
                    report.record_error(error);
                }
                report
            })
            .await
            .clone()
    }
}

/// Opaque identity of one published Session or Share generation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ObjectGeneration {
    identity: (u64, u64, u64),
}

impl Session {
    pub fn info(&self) -> SessionInfo {
        SessionInfo {
            server: self.inner.server.clone(),
        }
    }

    pub fn generation(&self) -> crate::Result<ObjectGeneration> {
        Ok(ObjectGeneration {
            identity: self.inner.runtime.object_identity()?,
        })
    }

    pub fn connect_share<'a>(&'a self, name: &'a str) -> Operation<'a, Share> {
        Operation::new(move |context| {
            Box::pin(async move {
                context.remaining()?;
                let runtime = self.inner.runtime.connect_share(name).await?;
                self.inner.shares.fetch_add(1, Ordering::AcqRel);
                Ok(Share {
                    inner: Arc::new(ShareInner {
                        runtime,
                        name: name.to_owned(),
                        close_report: OnceCell::new(),
                        resources: AtomicUsize::new(0),
                    }),
                    _session: self.inner.clone(),
                })
            })
        })
    }

    pub fn close(&self) -> Operation<'_, CloseReport> {
        Operation::new(move |context| {
            Box::pin(async move {
                context.remaining()?;
                Ok(self.inner.close().await)
            })
        })
    }
}

/// Stable logical Share handle. Wire-level Tree identity remains internal.
#[derive(Clone)]
pub struct Share {
    inner: Arc<ShareInner>,
    _session: Arc<SessionInner>,
}

struct ShareInner {
    runtime: RuntimeShare,
    name: String,
    close_report: OnceCell<CloseReport>,
    resources: AtomicUsize,
}

impl ShareInner {
    async fn close(&self) -> CloseReport {
        self.close_report
            .get_or_init(|| async {
                let mut report = CloseReport {
                    resources: self.resources.load(Ordering::Acquire),
                    ..CloseReport::default()
                };
                if let Err(error) = self.runtime.close().await {
                    report.record_error(error);
                }
                report
            })
            .await
            .clone()
    }
}

impl Share {
    pub fn info(&self) -> ShareInfo {
        ShareInfo {
            server: self._session.server.clone(),
            share: self.inner.name.clone(),
        }
    }
    fn record_resource_open(&self) {
        self.inner.resources.fetch_add(1, Ordering::AcqRel);
        self._session.resources.fetch_add(1, Ordering::AcqRel);
    }

    pub fn generation(&self) -> ObjectGeneration {
        ObjectGeneration {
            identity: self.inner.runtime.object_identity(),
        }
    }

    pub fn open<'a>(&'a self, path: &SharePath) -> Operation<'a, Resource> {
        let path = path.clone();
        Operation::new(move |context| {
            Box::pin(async move {
                context.remaining()?;
                if context.replay != ReplayPolicy::Never {
                    return Err(Error::UnsupportedOperation(
                        "resource open permits only ReplayPolicy::Never".into(),
                    ));
                }
                let resource = self.inner.runtime.open_resource(path.as_str()).await?;
                self.record_resource_open();
                Ok(match resource {
                    RuntimeResource::File(inner) => Resource::File(Box::new(File {
                        inner,
                        close_authority: FileCloseAuthority::new(),
                        info: OpenInfo::new(OpenKind::File, path.as_str()),
                    })),
                    RuntimeResource::Directory(inner) => Resource::Directory(Directory {
                        inner,
                        close_authority: FileCloseAuthority::new(),
                        info: OpenInfo::new(OpenKind::Directory, path.as_str()),
                    }),
                    RuntimeResource::Pipe(inner) => Resource::Pipe(Pipe {
                        inner,
                        close_authority: FileCloseAuthority::new(),
                        info: OpenInfo::new(OpenKind::Pipe, path.as_str()),
                    }),
                })
            })
        })
    }

    pub fn open_security<'a>(
        &'a self,
        path: &SharePath,
        options: SecurityOpenOptions,
    ) -> Operation<'a, Resource> {
        let path = path.clone();
        Operation::new(move |context| {
            Box::pin(async move {
                context.remaining()?;
                if context.replay != ReplayPolicy::Never {
                    return Err(Error::UnsupportedOperation(
                        "security open permits only ReplayPolicy::Never".into(),
                    ));
                }
                let resource = self
                    .inner
                    .runtime
                    .open_security_resource(path.as_str(), options.writes_dacl())
                    .await?;
                self.record_resource_open();
                Ok(match resource {
                    RuntimeResource::File(inner) => Resource::File(Box::new(File {
                        inner,
                        close_authority: FileCloseAuthority::new(),
                        info: OpenInfo::new(OpenKind::File, path.as_str()),
                    })),
                    RuntimeResource::Directory(inner) => Resource::Directory(Directory {
                        inner,
                        close_authority: FileCloseAuthority::new(),
                        info: OpenInfo::new(OpenKind::Directory, path.as_str()),
                    }),
                    RuntimeResource::Pipe(inner) => Resource::Pipe(Pipe {
                        inner,
                        close_authority: FileCloseAuthority::new(),
                        info: OpenInfo::new(OpenKind::Pipe, path.as_str()),
                    }),
                })
            })
        })
    }

    pub fn open_file<'a>(
        &'a self,
        path: &SharePath,
        options: FileOpenOptions,
    ) -> Operation<'a, File> {
        let path = path.clone();
        Operation::new(move |context| {
            Box::pin(async move {
                context.remaining()?;
                if context.replay != ReplayPolicy::Never {
                    return Err(Error::UnsupportedOperation(
                        "file open currently permits only ReplayPolicy::Never".into(),
                    ));
                }
                let inner = self
                    .inner
                    .runtime
                    .open_file(
                        path.as_str(),
                        options.mode,
                        options.persistent_timeout_millis,
                    )
                    .await?;
                self.record_resource_open();
                Ok(File {
                    inner,
                    close_authority: FileCloseAuthority::new(),
                    info: OpenInfo::new(OpenKind::File, path.as_str()),
                })
            })
        })
    }

    pub fn open_file_at_version<'a>(
        &'a self,
        path: &SharePath,
        version: &PreviousVersion,
    ) -> Operation<'a, File> {
        let path = path.clone();
        let timestamp = version.timestamp;
        Operation::new(move |context| {
            Box::pin(async move {
                context.remaining()?;
                if context.replay != ReplayPolicy::Never {
                    return Err(Error::UnsupportedOperation(
                        "Previous Version open permits only ReplayPolicy::Never".into(),
                    ));
                }
                let inner = self
                    .inner
                    .runtime
                    .open_file_at_version(path.as_str(), timestamp)
                    .await?;
                self.record_resource_open();
                Ok(File {
                    inner,
                    close_authority: FileCloseAuthority::new(),
                    info: OpenInfo::new(OpenKind::File, path.as_str()),
                })
            })
        })
    }

    pub fn open_directory<'a>(
        &'a self,
        path: &SharePath,
        options: DirectoryOpenOptions,
    ) -> Operation<'a, Directory> {
        let path = path.clone();
        Operation::new(move |context| {
            Box::pin(async move {
                context.remaining()?;
                if context.replay != ReplayPolicy::Never {
                    return Err(Error::UnsupportedOperation(
                        "directory open currently permits only ReplayPolicy::Never".into(),
                    ));
                }
                let inner = self
                    .inner
                    .runtime
                    .open_directory(path.as_str(), options.create)
                    .await?;
                self.record_resource_open();
                Ok(Directory {
                    inner,
                    close_authority: FileCloseAuthority::new(),
                    info: OpenInfo::new(OpenKind::Directory, path.as_str()),
                })
            })
        })
    }

    pub fn open_pipe<'a>(&'a self, name: &PipeName) -> Operation<'a, Pipe> {
        let name = name.clone();
        Operation::new(move |context| {
            Box::pin(async move {
                context.remaining()?;
                if context.replay != ReplayPolicy::Never {
                    return Err(Error::UnsupportedOperation(
                        "pipe open permits only ReplayPolicy::Never".into(),
                    ));
                }
                let inner = self.inner.runtime.open_pipe(name.as_str()).await?;
                self.record_resource_open();
                Ok(Pipe {
                    inner,
                    close_authority: FileCloseAuthority::new(),
                    info: OpenInfo::new(OpenKind::Pipe, name.as_str()),
                })
            })
        })
    }

    pub fn close(&self) -> Operation<'_, CloseReport> {
        Operation::new(move |context| {
            Box::pin(async move {
                context.remaining()?;
                Ok(self.inner.close().await)
            })
        })
    }
}

/// An opened domain Resource.
pub enum Resource {
    File(Box<File>),
    Directory(Directory),
    Pipe(Pipe),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceMetadata {
    created: std::time::SystemTime,
    accessed: std::time::SystemTime,
    written: std::time::SystemTime,
    changed: std::time::SystemTime,
    len: u64,
}

impl ResourceMetadata {
    fn from_runtime(value: crate::runtime::port::RuntimeMetadata) -> Self {
        Self {
            created: value.created,
            accessed: value.accessed,
            written: value.written,
            changed: value.changed,
            len: value.len,
        }
    }

    pub const fn created(&self) -> std::time::SystemTime {
        self.created
    }

    pub const fn accessed(&self) -> std::time::SystemTime {
        self.accessed
    }

    pub const fn written(&self) -> std::time::SystemTime {
        self.written
    }

    pub const fn changed(&self) -> std::time::SystemTime {
        self.changed
    }

    pub const fn len(&self) -> u64 {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Resource {
    pub fn metadata(&self) -> Operation<'_, ResourceMetadata> {
        Operation::new(move |context| {
            Box::pin(async move {
                context.remaining()?;
                let value = match self {
                    Resource::File(file) => file.inner.metadata().await?,
                    Resource::Directory(directory) => directory.inner.metadata().await?,
                    Resource::Pipe(_) => {
                        return Err(Error::UnsupportedOperation(
                            "Pipe metadata is not a domain operation".into(),
                        ));
                    }
                };
                Ok(ResourceMetadata::from_runtime(value))
            })
        })
    }
}

/// Non-cloneable positioned file handle.
pub struct File {
    inner: RuntimeFile,
    close_authority: FileCloseAuthority,
    info: OpenInfo,
}

/// Negotiated data-plane limits exposed to upper-layer I/O schedulers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IoCapabilities {
    maximum_read_chunk: u32,
    maximum_write_chunk: u32,
}

impl IoCapabilities {
    pub const fn maximum_read_chunk(self) -> u32 {
        self.maximum_read_chunk
    }

    pub const fn maximum_write_chunk(self) -> u32 {
        self.maximum_write_chunk
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CloseOutcome {
    Confirmed,
    AlreadyClosed,
    OutcomeUnknown,
}

#[derive(Clone, Copy)]
enum FileCloseState {
    Open,
    Confirmed,
    OutcomeUnknown,
}

struct FileCloseAuthority {
    state: Mutex<FileCloseState>,
}

impl FileCloseAuthority {
    fn new() -> Self {
        Self {
            state: Mutex::new(FileCloseState::Open),
        }
    }

    async fn close_with<F, Fut>(&self, close: F) -> crate::Result<CloseOutcome>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = crate::Result<()>>,
    {
        let mut state = self.state.lock().await;
        match *state {
            FileCloseState::Confirmed => return Ok(CloseOutcome::AlreadyClosed),
            FileCloseState::OutcomeUnknown => return Ok(CloseOutcome::OutcomeUnknown),
            FileCloseState::Open => {}
        }
        match close().await {
            Ok(()) => {
                *state = FileCloseState::Confirmed;
                Ok(CloseOutcome::Confirmed)
            }
            Err(Error::OutcomeUnknown) => {
                *state = FileCloseState::OutcomeUnknown;
                Ok(CloseOutcome::OutcomeUnknown)
            }
            Err(error) => Err(error),
        }
    }
}

impl File {
    pub fn info(&self) -> OpenInfo {
        self.info.clone()
    }

    /// Returns the maximum read and write request sizes negotiated by smb-rs.
    ///
    /// Upper layers may select smaller chunks for their concurrency and memory
    /// policy, but must not exceed these protocol limits.
    pub fn io_capabilities(&self) -> IoCapabilities {
        IoCapabilities {
            maximum_read_chunk: self.inner.maximum_read_size(),
            maximum_write_chunk: self.inner.maximum_write_size(),
        }
    }

    pub fn flush(&self) -> Operation<'_, ()> {
        Operation::new(move |context| {
            Box::pin(async move {
                context.remaining()?;
                self.inner.flush().await
            })
        })
    }

    pub fn persistent_granted(&self) -> bool {
        self.inner.persistent_granted()
    }
    pub fn previous_versions(&self) -> Operation<'_, Vec<PreviousVersion>> {
        Operation::new(move |context| {
            Box::pin(async move {
                context.remaining()?;
                self.inner
                    .previous_versions()
                    .await?
                    .into_iter()
                    .map(PreviousVersion::from_gmt_token)
                    .collect()
            })
        })
    }
    pub fn metadata(&self) -> Operation<'_, ResourceMetadata> {
        Operation::new(move |context| {
            Box::pin(async move {
                context.remaining()?;
                Ok(ResourceMetadata::from_runtime(self.inner.metadata().await?))
            })
        })
    }

    pub fn cursor(&self) -> FileCursor<'_> {
        FileCursor::new(self)
    }

    pub(crate) fn opened_len(&self) -> u64 {
        self.inner.opened_len()
    }

    pub fn len(&self) -> Operation<'_, u64> {
        Operation::new(move |context| {
            Box::pin(async move {
                context.remaining()?;
                self.inner.len().await
            })
        })
    }

    pub fn read_at(&self, offset: u64, max_len: u32) -> Operation<'_, Bytes> {
        Operation::new(move |context| {
            Box::pin(async move {
                let timeout = context.remaining()?;
                self.inner
                    .read_at(
                        offset,
                        max_len.min(self.inner.maximum_read_size()),
                        timeout,
                        context.cancellation.clone(),
                        context.runtime_replay(),
                    )
                    .await
            })
        })
    }

    pub fn write_at(&self, offset: u64, bytes: Bytes) -> Operation<'_, usize> {
        Operation::new(move |context| {
            Box::pin(async move {
                if bytes.len() > self.inner.maximum_write_size() as usize {
                    return Err(Error::InvalidArgument(
                        "positioned write exceeds the negotiated maximum write size".into(),
                    ));
                }
                let timeout = context.remaining()?;
                self.inner
                    .write_at(
                        offset,
                        bytes,
                        timeout,
                        context.cancellation.clone(),
                        context.runtime_replay(),
                    )
                    .await
            })
        })
    }

    pub fn read_at_into<'a>(&'a self, offset: u64, buffer: &'a mut [u8]) -> Operation<'a, usize> {
        Operation::new(move |context| {
            Box::pin(async move {
                let timeout = context.remaining()?;
                let bytes = self
                    .inner
                    .read_at(
                        offset,
                        u32::try_from(buffer.len())?.min(self.inner.maximum_read_size()),
                        timeout,
                        context.cancellation.clone(),
                        context.runtime_replay(),
                    )
                    .await?;
                buffer[..bytes.len()].copy_from_slice(&bytes);
                Ok(bytes.len())
            })
        })
    }

    pub fn write_at_from<'a>(&'a self, offset: u64, buffer: &'a [u8]) -> Operation<'a, usize> {
        Operation::new(move |context| {
            Box::pin(async move {
                let bytes = Bytes::copy_from_slice(buffer);
                if bytes.len() > self.inner.maximum_write_size() as usize {
                    return Err(Error::InvalidArgument(
                        "positioned write exceeds the negotiated maximum write size".into(),
                    ));
                }
                let timeout = context.remaining()?;
                self.inner
                    .write_at(
                        offset,
                        bytes,
                        timeout,
                        context.cancellation.clone(),
                        context.runtime_replay(),
                    )
                    .await
            })
        })
    }

    pub fn read_exact_at(&self, offset: u64, length: u32) -> Operation<'_, Bytes> {
        Operation::new(move |context| {
            Box::pin(async move {
                if length == 0 {
                    return Ok(Bytes::new());
                }
                let first_length = length.min(self.inner.maximum_read_size());
                let first = self
                    .inner
                    .read_at(
                        offset,
                        first_length,
                        context.remaining()?,
                        context.cancellation.clone(),
                        context.runtime_replay(),
                    )
                    .await?;
                if first.len() == length as usize {
                    return Ok(first);
                }
                if first.is_empty() {
                    return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
                }
                if first.len() > length as usize {
                    return Err(Error::InvalidMessage(
                        "read response exceeded the requested range".into(),
                    ));
                }
                let mut result = bytes::BytesMut::with_capacity(length as usize);
                result.extend_from_slice(&first);
                while result.len() < length as usize {
                    let position = offset.checked_add(result.len() as u64).ok_or_else(|| {
                        Error::InvalidArgument("read range exceeds u64 offsets".into())
                    })?;
                    let remaining = length - result.len() as u32;
                    let request_length = remaining.min(self.inner.maximum_read_size());
                    let bytes = self
                        .inner
                        .read_at(
                            position,
                            request_length,
                            context.remaining()?,
                            context.cancellation.clone(),
                            context.runtime_replay(),
                        )
                        .await?;
                    if bytes.is_empty() {
                        return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
                    }
                    if bytes.len() > remaining as usize {
                        return Err(Error::InvalidMessage(
                            "read response exceeded the requested range".into(),
                        ));
                    }
                    result.extend_from_slice(&bytes);
                }
                Ok(result.freeze())
            })
        })
    }

    pub fn write_all_at(&self, offset: u64, bytes: Bytes) -> Operation<'_, ()> {
        Operation::new(move |context| {
            Box::pin(async move {
                let mut written = 0_usize;
                while written < bytes.len() {
                    let position = offset.checked_add(written as u64).ok_or_else(|| {
                        Error::InvalidArgument("write range exceeds u64 offsets".into())
                    })?;
                    let count = self
                        .inner
                        .write_at(
                            position,
                            bytes.slice(
                                written
                                    ..(written + self.inner.maximum_write_size() as usize)
                                        .min(bytes.len()),
                            ),
                            context.remaining()?,
                            context.cancellation.clone(),
                            context.runtime_replay(),
                        )
                        .await?;
                    if count == 0 {
                        return Err(std::io::Error::from(std::io::ErrorKind::WriteZero).into());
                    }
                    if count > bytes.len() - written {
                        return Err(Error::InvalidMessage(
                            "write response exceeded the submitted payload".into(),
                        ));
                    }
                    written += count;
                }
                Ok(())
            })
        })
    }

    pub fn delete(&self) -> Operation<'_, ()> {
        Operation::new(move |context| {
            Box::pin(async move {
                context.remaining()?;
                if context.replay != ReplayPolicy::Never {
                    return Err(Error::UnsupportedOperation(
                        "file delete permits only ReplayPolicy::Never".into(),
                    ));
                }
                self.inner.delete().await
            })
        })
    }

    pub fn rename<'a>(&'a self, destination: &'a SharePath) -> Operation<'a, ()> {
        Operation::new(move |context| {
            Box::pin(async move {
                context.remaining()?;
                if context.replay != ReplayPolicy::Never {
                    return Err(Error::UnsupportedOperation(
                        "file rename permits only ReplayPolicy::Never".into(),
                    ));
                }
                self.inner.rename(destination.as_str(), false).await
            })
        })
    }

    /// Renames this file and atomically replaces an existing destination.
    pub fn rename_replace<'a>(&'a self, destination: &'a SharePath) -> Operation<'a, ()> {
        Operation::new(move |context| {
            Box::pin(async move {
                context.remaining()?;
                if context.replay != ReplayPolicy::Never {
                    return Err(Error::UnsupportedOperation(
                        "file replace permits only ReplayPolicy::Never".into(),
                    ));
                }
                self.inner.rename(destination.as_str(), true).await
            })
        })
    }

    pub fn close(&self) -> Operation<'_, CloseOutcome> {
        Operation::new(move |context| {
            Box::pin(async move {
                context.remaining()?;
                if context.replay != ReplayPolicy::Never {
                    return Err(Error::UnsupportedOperation(
                        "file close permits only ReplayPolicy::Never".into(),
                    ));
                }
                self.close_authority.close_with(|| self.inner.close()).await
            })
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectoryEntry {
    name: String,
    is_directory: bool,
    len: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DirectoryEvent {
    Added { path: String },
    Removed { path: String },
    Modified { path: String },
    Renamed { from: String, to: String },
    StreamAdded { path: String },
    StreamRemoved { path: String },
    StreamModified { path: String },
    IdentifierUnavailable { path: String },
    IdentifierCollision { path: String },
}

#[derive(Clone)]
pub struct DirectoryWatchOptions {
    recursive: bool,
    cancellation: CancelToken,
}

impl Default for DirectoryWatchOptions {
    fn default() -> Self {
        Self {
            recursive: false,
            cancellation: CancelToken::new(),
        }
    }
}

impl DirectoryWatchOptions {
    pub const fn recursive(mut self, recursive: bool) -> Self {
        self.recursive = recursive;
        self
    }

    pub fn cancellation(mut self, cancellation: CancelToken) -> Self {
        self.cancellation = cancellation;
        self
    }
}

impl DirectoryEntry {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub const fn is_directory(&self) -> bool {
        self.is_directory
    }

    pub const fn len(&self) -> u64 {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

pub struct Directory {
    inner: crate::runtime::port::RuntimeDirectory,
    close_authority: FileCloseAuthority,
    info: OpenInfo,
}

pub type DirectoryEntries<'a> =
    std::pin::Pin<Box<dyn Stream<Item = crate::Result<DirectoryEntry>> + Send + 'a>>;
pub type DirectoryEvents<'a> =
    std::pin::Pin<Box<dyn Stream<Item = crate::Result<DirectoryEvent>> + Send + 'a>>;

fn pair_directory_event(
    rename_from: &mut Option<String>,
    event: crate::runtime::port::RuntimeDirectoryEvent,
) -> crate::Result<Option<DirectoryEvent>> {
    use crate::runtime::port::RuntimeDirectoryEventKind as Kind;

    let value = match event.kind {
        Kind::RenamedOld => {
            *rename_from = Some(event.path);
            return Ok(None);
        }
        Kind::RenamedNew => DirectoryEvent::Renamed {
            from: rename_from.take().ok_or_else(|| {
                Error::InvalidMessage("rename new-name event has no old-name pair".into())
            })?,
            to: event.path,
        },
        Kind::Added => DirectoryEvent::Added { path: event.path },
        Kind::Removed => DirectoryEvent::Removed { path: event.path },
        Kind::Modified => DirectoryEvent::Modified { path: event.path },
        Kind::StreamAdded => DirectoryEvent::StreamAdded { path: event.path },
        Kind::StreamRemoved => DirectoryEvent::StreamRemoved { path: event.path },
        Kind::StreamModified => DirectoryEvent::StreamModified { path: event.path },
        Kind::IdentifierUnavailable => DirectoryEvent::IdentifierUnavailable { path: event.path },
        Kind::IdentifierCollision => DirectoryEvent::IdentifierCollision { path: event.path },
    };
    Ok(Some(value))
}

impl Directory {
    pub fn info(&self) -> OpenInfo {
        self.info.clone()
    }

    pub fn metadata(&self) -> Operation<'_, ResourceMetadata> {
        Operation::new(move |context| {
            Box::pin(async move {
                context.remaining()?;
                Ok(ResourceMetadata::from_runtime(self.inner.metadata().await?))
            })
        })
    }

    pub fn entries<'a>(&'a self, pattern: &'a str) -> DirectoryEntries<'a> {
        Box::pin(self.inner.entries(pattern).map(|result| {
            result.map(|entry| DirectoryEntry {
                name: entry.name,
                is_directory: entry.is_directory,
                len: entry.len,
            })
        }))
    }

    pub fn collect_entries<'a>(&'a self, pattern: &'a str) -> Operation<'a, Vec<DirectoryEntry>> {
        Operation::new(move |context| {
            Box::pin(async move {
                context.remaining()?;
                self.entries(pattern).try_collect().await
            })
        })
    }

    pub fn watch(&self, options: DirectoryWatchOptions) -> DirectoryEvents<'_> {
        let raw = self
            .inner
            .watch(options.recursive, options.cancellation.clone());
        Box::pin(futures_util::stream::unfold(
            (raw, None::<String>, false),
            |(mut raw, mut rename_from, done)| async move {
                if done {
                    return None;
                }
                loop {
                    let Some(result) = raw.next().await else {
                        return rename_from.map(|from| {
                            (
                                Err(Error::InvalidMessage(format!(
                                    "rename event for {from} has no new-name pair"
                                ))),
                                (raw, None, true),
                            )
                        });
                    };
                    let event = match result {
                        Ok(event) => event,
                        Err(error) => return Some((Err(error), (raw, rename_from, true))),
                    };
                    match pair_directory_event(&mut rename_from, event) {
                        Ok(Some(value)) => {
                            return Some((Ok(value), (raw, rename_from, false)));
                        }
                        Ok(None) => continue,
                        Err(error) => return Some((Err(error), (raw, None, true))),
                    }
                }
            },
        ))
    }

    pub fn delete(&self) -> Operation<'_, ()> {
        Operation::new(move |context| {
            Box::pin(async move {
                context.remaining()?;
                self.inner.delete().await
            })
        })
    }

    /// Renames this directory; an existing destination fails with
    /// `STATUS_OBJECT_NAME_COLLISION`.
    pub fn rename<'a>(&'a self, destination: &'a SharePath) -> Operation<'a, ()> {
        Operation::new(move |context| {
            Box::pin(async move {
                context.remaining()?;
                if context.replay != ReplayPolicy::Never {
                    return Err(Error::UnsupportedOperation(
                        "directory rename permits only ReplayPolicy::Never".into(),
                    ));
                }
                self.inner.rename(destination.as_str(), false).await
            })
        })
    }

    /// Renames this directory and replaces an existing destination when the server
    /// allows it (NTFS-style servers only replace empty directories).
    pub fn rename_replace<'a>(&'a self, destination: &'a SharePath) -> Operation<'a, ()> {
        Operation::new(move |context| {
            Box::pin(async move {
                context.remaining()?;
                if context.replay != ReplayPolicy::Never {
                    return Err(Error::UnsupportedOperation(
                        "directory replace permits only ReplayPolicy::Never".into(),
                    ));
                }
                self.inner.rename(destination.as_str(), true).await
            })
        })
    }

    pub fn close(&self) -> Operation<'_, CloseOutcome> {
        Operation::new(move |context| {
            Box::pin(async move {
                context.remaining()?;
                if context.replay != ReplayPolicy::Never {
                    return Err(Error::UnsupportedOperation(
                        "directory close permits only ReplayPolicy::Never".into(),
                    ));
                }
                self.close_authority.close_with(|| self.inner.close()).await
            })
        })
    }
}

pub struct Pipe {
    inner: crate::runtime::port::RuntimePipe,
    close_authority: FileCloseAuthority,
    info: OpenInfo,
}

impl Pipe {
    pub fn info(&self) -> OpenInfo {
        self.info.clone()
    }

    pub fn read(&self, max_len: u32) -> Operation<'_, Bytes> {
        Operation::new(move |context| {
            Box::pin(async move {
                self.inner
                    .read(
                        max_len,
                        context.remaining()?,
                        context.cancellation.clone(),
                        context.runtime_replay(),
                    )
                    .await
            })
        })
    }

    pub fn write(&self, bytes: Bytes) -> Operation<'_, usize> {
        Operation::new(move |context| {
            Box::pin(async move {
                self.inner
                    .write(
                        bytes,
                        context.remaining()?,
                        context.cancellation.clone(),
                        context.runtime_replay(),
                    )
                    .await
            })
        })
    }

    pub fn transact(&self, request: Bytes, max_response: u32) -> Operation<'_, Bytes> {
        Operation::new(move |context| {
            Box::pin(async move {
                context.remaining()?;
                if context.replay != ReplayPolicy::Never {
                    return Err(Error::UnsupportedOperation(
                        "pipe transact permits only ReplayPolicy::Never".into(),
                    ));
                }
                self.inner
                    .transact(
                        request,
                        max_response,
                        context.remaining()?,
                        context.cancellation.clone(),
                    )
                    .await
            })
        })
    }

    pub fn close(&self) -> Operation<'_, CloseOutcome> {
        Operation::new(move |context| {
            Box::pin(async move {
                context.remaining()?;
                if context.replay != ReplayPolicy::Never {
                    return Err(Error::UnsupportedOperation(
                        "pipe close permits only ReplayPolicy::Never".into(),
                    ));
                }
                self.close_authority.close_with(|| self.inner.close()).await
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use super::*;

    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn domain_handles_are_send_sync_and_paths_cannot_escape() {
        assert_send_sync::<Session>();
        assert_send_sync::<Share>();
        assert_send_sync::<File>();
        assert!(SharePath::new("dir/file.bin").is_ok());
        assert!(SharePath::new("../escape").is_err());
        assert!(SharePath::new("\\absolute").is_err());
    }

    #[tokio::test]
    async fn concurrent_file_close_invokes_the_wire_closure_once() {
        let authority = Arc::new(FileCloseAuthority::new());
        let calls = Arc::new(AtomicUsize::new(0));
        let close = |authority: Arc<FileCloseAuthority>, calls: Arc<AtomicUsize>| async move {
            authority
                .close_with(|| async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    tokio::task::yield_now().await;
                    Ok(())
                })
                .await
        };

        let (first, second) = tokio::join!(
            close(authority.clone(), calls.clone()),
            close(authority, calls.clone())
        );
        let outcomes = [first.unwrap(), second.unwrap()];
        assert!(outcomes.contains(&CloseOutcome::Confirmed));
        assert!(outcomes.contains(&CloseOutcome::AlreadyClosed));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn unknown_close_outcome_is_sticky_and_not_retried() {
        let authority = FileCloseAuthority::new();
        assert_eq!(
            authority
                .close_with(|| async { Err(Error::OutcomeUnknown) })
                .await
                .unwrap(),
            CloseOutcome::OutcomeUnknown
        );
        assert_eq!(
            authority.close_with(|| async { Ok(()) }).await.unwrap(),
            CloseOutcome::OutcomeUnknown
        );
    }

    #[test]
    fn directory_rename_events_are_paired_or_rejected() {
        use crate::runtime::port::{RuntimeDirectoryEvent, RuntimeDirectoryEventKind as Kind};

        let mut from = None;
        assert!(
            pair_directory_event(
                &mut from,
                RuntimeDirectoryEvent {
                    kind: Kind::RenamedOld,
                    path: "old".into(),
                },
            )
            .unwrap()
            .is_none()
        );
        assert_eq!(
            pair_directory_event(
                &mut from,
                RuntimeDirectoryEvent {
                    kind: Kind::RenamedNew,
                    path: "new".into(),
                },
            )
            .unwrap(),
            Some(DirectoryEvent::Renamed {
                from: "old".into(),
                to: "new".into(),
            })
        );
        assert!(
            pair_directory_event(
                &mut None,
                RuntimeDirectoryEvent {
                    kind: Kind::RenamedNew,
                    path: "orphan".into(),
                },
            )
            .is_err()
        );
    }
}
