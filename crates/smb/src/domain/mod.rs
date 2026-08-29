//! SMB domain handles.

mod operation;
pub use operation::{CancelToken, Deadline, Operation, ReplayPolicy};

use std::{
    collections::HashMap,
    sync::{Arc, Weak},
};

use bytes::Bytes;
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use crate::{
    Error,
    runtime::domain_bridge::{OpenMode, RuntimeClient, RuntimeFile, RuntimeSession, RuntimeShare},
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
}

impl Credentials {
    pub fn ntlm(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self::Ntlm {
            username: Zeroizing::new(username.into()),
            password: Zeroizing::new(password.into()),
        }
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileOpenOptions {
    mode: OpenMode,
}

impl FileOpenOptions {
    pub const fn create_new() -> Self {
        Self {
            mode: OpenMode::CreateNew,
        }
    }

    pub const fn open_existing() -> Self {
        Self {
            mode: OpenMode::OpenExisting,
        }
    }

    pub const fn overwrite() -> Self {
        Self {
            mode: OpenMode::Overwrite,
        }
    }
}

#[derive(Clone)]
pub(crate) struct DomainClient {
    inner: Arc<DomainClientInner>,
}

struct DomainClientInner {
    runtime: RuntimeClient,
    sessions: Mutex<SessionCache>,
}

type SessionCacheKey = (String, [u8; 32]);
type SessionCache = HashMap<SessionCacheKey, Weak<RuntimeSession>>;

impl DomainClient {
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(DomainClientInner {
                runtime: RuntimeClient::new(),
                sessions: Mutex::new(HashMap::new()),
            }),
        }
    }

    pub(crate) async fn authenticate(
        &self,
        server: &str,
        credentials: Credentials,
    ) -> crate::Result<Session> {
        let Credentials::Ntlm { username, password } = credentials else {
            return Err(Error::UnsupportedOperation(
                "anonymous authentication is not activated".into(),
            ));
        };
        let credential_digest: [u8; 32] = Sha256::new()
            .chain_update(username.as_bytes())
            .chain_update([0])
            .chain_update(password.as_bytes())
            .finalize()
            .into();
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
        let inner = Arc::new(
            self.inner
                .runtime
                .authenticate(server, username.as_str(), password.to_string())
                .await?,
        );
        self.inner
            .sessions
            .lock()
            .await
            .insert(key, Arc::downgrade(&inner));
        Ok(Session { inner })
    }

    pub(crate) async fn close(&self) -> crate::Result<()> {
        self.inner.runtime.close().await
    }
}

/// Stable logical authenticated Session handle.
#[derive(Clone)]
pub struct Session {
    inner: Arc<RuntimeSession>,
}

impl Session {
    pub async fn connect_share(&self, name: &str) -> crate::Result<Share> {
        let inner = self.inner.connect_share(name).await?;
        Ok(Share {
            inner: Arc::new(inner),
            _session: self.inner.clone(),
        })
    }

    pub async fn close(&self) -> crate::Result<()> {
        self.inner.close().await
    }
}

/// Stable logical Share handle. Wire-level Tree identity remains internal.
#[derive(Clone)]
pub struct Share {
    inner: Arc<RuntimeShare>,
    _session: Arc<RuntimeSession>,
}

impl Share {
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
                let inner = self.inner.open_file(path.as_str(), options.mode).await?;
                Ok(File { inner })
            })
        })
    }

    pub async fn close(&self) -> crate::Result<()> {
        self.inner.close().await
    }
}

/// An opened domain Resource.
pub enum Resource {
    File(Box<File>),
    Directory(Directory),
    Pipe(Pipe),
}

/// Non-cloneable positioned file handle.
pub struct File {
    inner: RuntimeFile,
}

impl File {
    pub fn read_at(&self, offset: u64, max_len: u32) -> Operation<'_, Bytes> {
        Operation::new(move |context| {
            Box::pin(async move {
                let timeout = context.remaining()?;
                self.inner
                    .read_at(
                        offset,
                        max_len,
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
                        u32::try_from(buffer.len())?,
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
                let mut result = bytes::BytesMut::with_capacity(length as usize);
                while result.len() < length as usize {
                    let position = offset.checked_add(result.len() as u64).ok_or_else(|| {
                        Error::InvalidArgument("read range exceeds u64 offsets".into())
                    })?;
                    let remaining = length - result.len() as u32;
                    let bytes = self
                        .inner
                        .read_at(
                            position,
                            remaining,
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
                            bytes.slice(written..),
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

    pub async fn delete(&self) -> crate::Result<()> {
        self.inner.delete().await
    }

    pub async fn close(&self) -> crate::Result<()> {
        self.inner.close().await
    }
}

pub struct Directory;
pub struct Pipe;

#[cfg(test)]
mod tests {
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
}
