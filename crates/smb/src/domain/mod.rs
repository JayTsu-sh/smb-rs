//! SMB domain handles.

mod operation;
pub use operation::{CancelToken, Deadline, Operation, ReplayPolicy};

use std::{collections::HashMap, sync::{Arc, Weak}};

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
            return Err(Error::InvalidArgument("path must remain within the Share".into()));
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
        let inner = Arc::new(self
            .inner
            .runtime
            .authenticate(server, username.as_str(), password.to_string())
            .await?);
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
                let _replay = context.replay;
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
                let _replay = context.replay;
                self.inner.read_at(offset, max_len).await
            })
        })
    }

    pub fn write_at(&self, offset: u64, bytes: Bytes) -> Operation<'_, usize> {
        Operation::new(move |context| {
            Box::pin(async move {
                let _replay = context.replay;
                self.inner.write_at(offset, bytes).await
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
