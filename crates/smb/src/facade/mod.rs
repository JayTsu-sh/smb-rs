//! Public async SMB facade.

use crate::{GuestPolicy, SigningPolicy};
use smb_rpc::interface::{ShareKind as RpcShareKind, SrvSvc};

use crate::domain::{
    CloseReport, Credentials, DomainClient, Operation, PipeName, RpcPipeConnection, Session, Share,
    ShareTarget,
};

/// Root handle for the domain-first async API.
#[derive(Clone)]
pub struct Client {
    domain: DomainClient,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShareKind {
    Disk,
    PrintQueue,
    Device,
    InterprocessCommunication,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoteShare {
    name: String,
    remark: Option<String>,
    kind: ShareKind,
    special: bool,
    temporary: bool,
}

impl RemoteShare {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn remark(&self) -> Option<&str> {
        self.remark.as_deref()
    }

    pub const fn kind(&self) -> ShareKind {
        self.kind
    }

    pub const fn is_special(&self) -> bool {
        self.special
    }

    pub const fn is_temporary(&self) -> bool {
        self.temporary
    }
}

impl Client {
    pub fn new() -> Self {
        Self {
            domain: DomainClient::new(),
        }
    }

    /// Create a client with an explicit negotiated signing policy.
    /// Every connection, cached session and reconnect uses this policy.
    pub fn with_signing_policy(policy: SigningPolicy) -> Self {
        Self {
            domain: DomainClient::with_signing_policy(policy),
        }
    }

    /// Create a client with explicit signing and guest-session policies.
    /// `GuestPolicy::AllowUnsigned` is required to use shares that map unknown or
    /// password-less users to a guest account; such sessions are unsigned.
    pub fn with_policies(signing: SigningPolicy, guest: GuestPolicy) -> Self {
        Self {
            domain: DomainClient::with_policies(signing, guest),
        }
    }

    pub fn authenticate<'a>(
        &'a self,
        server: &'a str,
        credentials: Credentials,
    ) -> Operation<'a, Session> {
        Operation::new(move |context| {
            Box::pin(async move {
                context.remaining()?;
                self.domain.authenticate(server, credentials).await
            })
        })
    }

    pub fn connect_share<'a>(
        &'a self,
        target: &'a ShareTarget,
        credentials: Credentials,
    ) -> Operation<'a, Share> {
        Operation::new(move |context| {
            Box::pin(async move {
                context.remaining()?;
                self.domain
                    .authenticate(target.server(), credentials)
                    .await?
                    .connect_share(target.share())
                    .await
            })
        })
    }

    /// Lazily enumerate the server's shares through the typed SRVSVC
    /// extension. RPC framing and the IPC$ Pipe remain internal.
    pub fn enumerate_shares(
        &self,
        server: impl Into<String>,
        credentials: Credentials,
    ) -> Operation<'static, Vec<RemoteShare>> {
        let client = self.clone();
        let server = server.into();
        Operation::new(move |context| {
            Box::pin(async move {
                context.remaining()?;
                let ipc = client
                    .connect_share(&ShareTarget::new(&server, "IPC$")?, credentials)
                    .await?;
                let result = async {
                    let pipe = ipc.open_pipe(&PipeName::new("srvsvc")?).await?;
                    let mut bind = pipe.bind_rpc::<SrvSvc<RpcPipeConnection>>();
                    bind = bind.cancellation(context.cancellation.clone());
                    if let Some(remaining) = context.remaining()? {
                        bind = bind.timeout(remaining);
                    }
                    let mut rpc = bind.await?;
                    let shares = rpc.netr_share_enum(&server).await?;
                    rpc.into_connection().close().await?;
                    Ok(shares
                        .into_iter()
                        .filter_map(|share| {
                            let name = share.netname.as_ref()?.to_string();
                            let kind = match share.share_type.kind() {
                                RpcShareKind::Disk => ShareKind::Disk,
                                RpcShareKind::PrintQ => ShareKind::PrintQueue,
                                RpcShareKind::Device => ShareKind::Device,
                                RpcShareKind::IPC => ShareKind::InterprocessCommunication,
                            };
                            Some(RemoteShare {
                                name: name.trim_end_matches('\0').to_owned(),
                                remark: share.remark.as_ref().map(|value| {
                                    value.to_string().trim_end_matches('\0').to_owned()
                                }),
                                kind,
                                special: share.share_type.special(),
                                temporary: share.share_type.temporary(),
                            })
                        })
                        .collect())
                }
                .await;
                let close = ipc.close().await;
                match (result, close) {
                    (Err(error), _) => Err(error),
                    (Ok(_), Err(error)) => Err(error),
                    (Ok(shares), Ok(_)) => Ok(shares),
                }
            })
        })
    }

    pub fn close(&self) -> Operation<'_, CloseReport> {
        Operation::new(move |context| {
            Box::pin(async move {
                context.remaining()?;
                Ok(self.domain.close().await)
            })
        })
    }
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}
