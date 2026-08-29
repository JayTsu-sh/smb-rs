//! Public async SMB facade.

use crate::domain::{Credentials, DomainClient, Session, Share, ShareTarget};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ClientConfig {
    _private: (),
}

/// Root handle for the domain-first async API.
#[derive(Clone)]
pub struct Client {
    domain: DomainClient,
}

impl Client {
    pub fn new(_config: ClientConfig) -> Self {
        Self {
            domain: DomainClient::new(),
        }
    }

    pub async fn authenticate(
        &self,
        server: &str,
        credentials: Credentials,
    ) -> crate::Result<Session> {
        self.domain.authenticate(server, credentials).await
    }

    pub async fn connect_share(
        &self,
        target: &ShareTarget,
        credentials: Credentials,
    ) -> crate::Result<Share> {
        self.authenticate(target.server(), credentials)
            .await?
            .connect_share(target.share())
            .await
    }

    pub async fn close(&self) -> crate::Result<()> {
        self.domain.close().await
    }
}
