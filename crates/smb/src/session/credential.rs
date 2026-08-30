use futures_core::future::BoxFuture;
use std::sync::Arc;

/// Capability used to obtain fresh authentication material for one SessionSetup.
///
/// Recovery owns the provider, while each authentication attempt owns the
/// returned identity. Implementations must not log or otherwise expose the
/// authentication material.
pub(crate) trait SessionCredentialProvider: Send + Sync {
    fn identity(&self) -> BoxFuture<'_, crate::Result<sspi::AuthIdentity>>;
}

pub(crate) type SharedCredentialProvider = Arc<dyn SessionCredentialProvider>;

pub(crate) struct StaticCredentialProvider {
    identity: sspi::AuthIdentity,
}

impl StaticCredentialProvider {
    pub(crate) fn new(identity: sspi::AuthIdentity) -> Self {
        Self { identity }
    }
}

impl SessionCredentialProvider for StaticCredentialProvider {
    fn identity(&self) -> BoxFuture<'_, crate::Result<sspi::AuthIdentity>> {
        let identity = self.identity.clone();
        Box::pin(async move { Ok(identity) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn static_provider_returns_fresh_identity_values() {
        let provider = StaticCredentialProvider::new(sspi::AuthIdentity {
            username: sspi::Username::parse("domain/user").unwrap(),
            password: sspi::Secret::from("secret".to_owned()),
        });

        let first = provider.identity().await.unwrap();
        let second = provider.identity().await.unwrap();

        assert_eq!(first.username.account_name(), "domain/user");
        assert_eq!(second.username.account_name(), "domain/user");
    }
}
