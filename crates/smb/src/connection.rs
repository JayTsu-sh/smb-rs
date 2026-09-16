pub mod config;
pub mod connection_info;
mod generation_runtime;
pub mod preauth_hash;
mod registry;

use crate::clock::TokioClock;
use crate::compression;
use crate::connection::preauth_hash::PreauthHashState;
use crate::dialects::DialectImpl;
use crate::lease::OplockSlot;
pub use crate::runtime::wire::TransformError;
use crate::runtime::{
    GenerationBootstrap, GenerationId, GenerationPublication, PreparedGeneration,
    RandomRecoveryJitter, RecoveryDriver, RecoveryError, RuntimeError,
};
use crate::{Error, command::*, crypto, session::Session};
use arc_swap::ArcSwapOption;
use binrw::prelude::*;
pub use config::*;
use connection_info::{ConnectionInfo, NegotiatedProperties};
use futures_core::future::BoxFuture;
use futures_util::FutureExt;
use generation_runtime::GenerationRuntime;
use rand::RngCore;
use rand::rngs::OsRng;
use registry::ConnectionRegistry;
use smb_dtyp::*;
use smb_msg::{
    OplockLevel, RequestContent, Response, ResponseContent, negotiate::*,
    smb1::SMB1NegotiateMessage,
};
use smb_transport::*;
use std::net::SocketAddr;
use std::sync::Weak;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::select;
use tokio_util::sync::CancellationToken;

/// Represents an SMB connection.
///
/// Each SMB connection has a single matching transport (e.g. TCP connection).
/// Usually, most use cases require a single connection per server-client communication.
pub struct Connection {
    context: Arc<ConnectionCore>,
    config: ConnectionConfig,

    server_name: String,
    server_address: SocketAddr,
}

struct ConnectionRecoveryBootstrap {
    context: Weak<ConnectionCore>,
    config: ConnectionConfig,
    server_name: String,
    server_address: SocketAddr,
}

struct ConnectionGenerationPublication {
    context: Arc<ConnectionCore>,
    generation_runtime: Arc<GenerationRuntime>,
    info: Arc<ConnectionInfo>,
}

impl GenerationPublication for ConnectionGenerationPublication {
    fn publish(self: Box<Self>) {
        self.context
            .publish_generation(self.generation_runtime, self.info);
    }
}

impl GenerationBootstrap for ConnectionRecoveryBootstrap {
    fn bootstrap(
        &self,
        generation: GenerationId,
        _deadline: crate::clock::MonotonicTime,
    ) -> BoxFuture<'static, Result<PreparedGeneration, RuntimeError>> {
        let context = self.context.clone();
        let config = self.config.clone();
        let server_name = self.server_name.clone();
        let server_address = self.server_address;
        async move {
            let context = context.upgrade().ok_or(RuntimeError::Closed)?;
            let connection = Connection {
                context: context.clone(),
                config: config.clone(),
                server_name: server_name.clone(),
                server_address,
            };
            let mut transport = make_transport(&config.transport, config.timeout())
                .map_err(|_| RuntimeError::Transport("recovery-make-transport"))?;
            let mut address = server_address;
            if address.port() == 0 {
                address.set_port(config.port.unwrap_or_else(|| transport.default_port()));
            }
            transport
                .connect(&server_name, address)
                .await
                .map_err(|_| RuntimeError::Transport("recovery-connect"))?;
            let generation_runtime = connection
                ._negotiate_switch_to_smb2(transport, config.smb2_only_negotiate, generation)
                .await
                .map_err(|_| RuntimeError::Wire("recovery-negotiate-switch"))?;
            let info = match connection._negotiate_smb2(&generation_runtime).await {
                Ok(info) => Arc::new(info),
                Err(_) => {
                    let _ = generation_runtime.stop().await;
                    return Err(RuntimeError::Wire("recovery-negotiate"));
                }
            };
            if generation_runtime.negotaite_complete(&info).await.is_err() {
                let _ = generation_runtime.stop().await;
                return Err(RuntimeError::Wire("recovery-negotiate-commit"));
            }
            Ok(PreparedGeneration::new(
                generation_runtime.runtime_handle(),
                Box::new(ConnectionGenerationPublication {
                    context,
                    generation_runtime,
                    info,
                }),
            ))
        }
        .boxed()
    }
}

impl Connection {
    /// Creates a new SMB connection, specifying a server configuration, without connecting to a server.
    /// Use the [`connect`](Connection::connect) method to establish a connection.
    pub fn build(
        server_name: &str,
        server_address: SocketAddr,
        client_guid: Guid,
        config: ConnectionConfig,
    ) -> crate::Result<Self> {
        config.validate()?;
        Ok(Connection {
            context: Arc::new(ConnectionCore::new(client_guid)),
            config,
            server_name: server_name.to_string(),
            server_address,
        })
    }

    /// Connects to the specified server, if it is not already connected, and negotiates the connection.
    #[tracing::instrument(level = "debug", skip_all, fields(server = %self.server_name))]
    pub async fn connect(&self) -> crate::Result<()> {
        if self.context.generation_runtime().is_some() {
            return Err(Error::InvalidState("Already connected".into()));
        }

        let mut transport = make_transport(&self.config.transport, self.config.timeout())?;

        let mut actual_connect_address = self.server_address;
        if actual_connect_address.port() == 0 {
            actual_connect_address
                .set_port(self.config.port.unwrap_or_else(|| transport.default_port()));
        }

        tracing::info!(addr = %actual_connect_address, "Connecting to server");
        transport
            .connect(&self.server_name, actual_connect_address)
            .await?;

        tracing::info!("Connected. Negotiating");
        self._negotiate(transport, self.config.smb2_only_negotiate, true)
            .await?;

        Ok(())
    }

    /// Closes the connection, and all of it's managed resources.
    ///
    /// Any session, tree, or file handles associated with the connection will be unusable after
    /// calling this method.
    ///
    /// See also [`Client::close`][`crate::Client::close`].
    #[tracing::instrument(level = "debug", skip_all, fields(server = %self.server_name))]
    pub async fn close(&self) -> crate::Result<()> {
        self.context.stop_notify();
        self.context.close_recovery().await;
        let result = match self.context.generation_runtime() {
            Some(c) => c.stop().await,
            None => Ok(()),
        };
        self.context.join_support_tasks().await;
        result
    }

    /// Switches the protocol to SMB2 against the server if required,
    /// and wraps the transport in a SMB2 generation_runtime.
    async fn _negotiate_switch_to_smb2(
        &self,
        mut transport: Box<dyn SmbTransport>,
        smb2_only_neg: bool,
        generation: GenerationId,
    ) -> crate::Result<Arc<GenerationRuntime>> {
        let mut initial_message_id = 0;
        // Multi-protocol negotiation: Begin with SMB1, expect SMB2.
        if !smb2_only_neg {
            tracing::debug!("Negotiating multi-protocol: Sending SMB1");
            // 1. Send SMB1 negotiate request
            let msg_bytes: Vec<u8> = SMB1NegotiateMessage::default().try_into()?;
            let frame =
                smb_transport::SendFrame::from_segments(vec![bytes::Bytes::from(msg_bytes)], 1)?;
            transport.send(&frame).await?;

            tracing::debug!("Sent SMB1 negotiate request, Receieving SMB2 response");
            // 2. Expect SMB2 negotiate response
            let recieved_bytes = transport.receive().await?;
            let response = Response::try_from(recieved_bytes.as_ref())?;
            let message = match response {
                Response::Plain(m) => m,
                _ => {
                    return Err(Error::InvalidMessage(
                        "Expected SMB2 negotiate response, got SMB1".to_string(),
                    ));
                }
            };

            let smb2_negotiate_response = message.content.to_negotiate()?;

            // 3. Make sure dialect is smb2*, message ID is 0.
            if smb2_negotiate_response.dialect_revision != NegotiateDialect::Smb02Wildcard {
                return Err(Error::InvalidMessage(
                    "Expected SMB2 wildcard dialect".to_string(),
                ));
            }
            if message.header.message_id != 0 {
                return Err(Error::InvalidMessage("Expected message ID 0".to_string()));
            }
            if message.header.credit_charge != 0 || message.header.credit_request != 1 {
                return Err(Error::InvalidMessage(
                    "Expected credit charge 0 and request 1 for initial message.".to_string(),
                ));
            }
            // Increase sequence number.
            initial_message_id = 1;
        }

        GenerationRuntime::start_generation_at(
            transport,
            self.config.timeout(),
            initial_message_id,
            u32::from(self.config.credits_backlog.unwrap_or(512)),
            generation,
        )
        .await
    }

    /// Negotiated connection information for conformance fixtures.
    #[cfg(feature = "test-support")]
    pub fn conn_info(&self) -> Option<Arc<ConnectionInfo>> {
        self.context.conn_info()
    }

    /// Builds a connection over a caller-supplied transport (transcript
    /// replay and conformance fixtures); production code goes through
    /// [`Client`](crate::client::Client).
    #[cfg(feature = "test-support")]
    #[tracing::instrument(level = "debug", skip_all, fields(server = %server))]
    pub async fn from_transport(
        transport: Box<dyn SmbTransport>,
        server: &str,
        client_guid: Guid,
        config: ConnectionConfig,
    ) -> crate::Result<Self> {
        let conn = Self::build(server, transport.remote_address()?, client_guid, config)?;
        conn._negotiate(transport, conn.config.smb2_only_negotiate, false)
            .await?;
        Ok(conn)
    }

    /// This method perofrms the SMB2 negotiation.
    async fn _negotiate_smb2(
        &self,
        generation_runtime: &Arc<GenerationRuntime>,
    ) -> crate::Result<ConnectionInfo> {
        tracing::debug!("Negotiating SMB2");

        // List possible versions to run with.
        let min_dialect = self.config.min_dialect.unwrap_or(Dialect::MIN);
        let max_dialect = self.config.max_dialect.unwrap_or(Dialect::MAX);
        let dialects: Vec<Dialect> = Dialect::ALL
            .iter()
            .filter(|dialect| **dialect >= min_dialect && **dialect <= max_dialect)
            .copied()
            .collect();

        if dialects.is_empty() {
            return Err(Error::InvalidConfiguration(
                "No dialects to negotiate".to_string(),
            ));
        }

        let encryption_algos = if !self.config.encryption_mode.is_disabled() {
            crypto::ENCRYPTING_ALGOS.into()
        } else {
            vec![]
        };

        // Send SMB2 negotiate request
        let (request_status, response) = self
            .context
            .execute_with_worker(
                generation_runtime,
                CommandRequest::new(
                    self._make_smb2_neg_request(
                        dialects,
                        crypto::SIGNING_ALGOS.to_vec(),
                        encryption_algos,
                        compression::SUPPORTED_ALGORITHMS.to_vec(),
                    )
                    .into(),
                )
                .with_return_raw_data(true)
                .with_protection(Protection::None),
            )
            .await?;

        let smb2_negotiate_response = response.message.content.to_negotiate()?;

        // well, only 3.1 is supported for starters.
        let dialect_rev = smb2_negotiate_response.dialect_revision.try_into()?;
        if dialect_rev > max_dialect || dialect_rev < min_dialect {
            return Err(Error::NegotiationError(
                "Server selected an unsupported dialect.".into(),
            ));
        }

        let dialect_impl = DialectImpl::new(dialect_rev);
        let mut negotiation = NegotiatedProperties {
            server_guid: smb2_negotiate_response.server_guid,
            signing_required: smb2_negotiate_response.security_mode.signing_required(),
            caps: smb2_negotiate_response.capabilities,
            max_transact_size: smb2_negotiate_response.max_transact_size,
            max_read_size: smb2_negotiate_response.max_read_size,
            max_write_size: smb2_negotiate_response.max_write_size,
            auth_buffer: smb2_negotiate_response.buffer.clone(),
            signing_algo: None,
            encryption_cipher: None,
            compression: None,
            dialect_rev,
        };

        dialect_impl.process_negotiate_request(
            &smb2_negotiate_response,
            &mut negotiation,
            &self.config,
        )?;
        if ((!u32::from_le_bytes(dialect_impl.get_negotiate_caps_mask().into_bytes()))
            & u32::from_le_bytes(negotiation.caps.into_bytes()))
            != 0
        {
            return Err(Error::NegotiationError(
                "Server capabilities are invalid for the selected dialect.".into(),
            ));
        }

        tracing::trace!(
            "Negotiated SMB results: dialect={:?}, state={:?}",
            dialect_rev,
            &negotiation
        );

        let preauth_hash = if dialect_impl.preauth_hash_supported() {
            let request_raw = request_status
                .raw
                .expect("Preauth hash must be calculated for supported dialect!");
            PreauthHashState::begin()
                .next(&request_raw)?
                .next(&response.raw)?
        } else {
            PreauthHashState::unsupported()
        };

        Ok(ConnectionInfo {
            negotiation,
            dialect: dialect_impl,
            config: self.config.clone(),
            server_name: self.server_name.clone(),
            preauth_hash,
        })
    }

    /// Creates an SMB2 negotiate request.
    fn _make_smb2_neg_request(
        &self,
        supported_dialects: Vec<Dialect>,
        signing_algorithms: Vec<SigningAlgorithmId>,
        encrypting_algorithms: Vec<EncryptionCipher>,
        compression_algorithms: Vec<CompressionAlgorithm>,
    ) -> NegotiateRequest {
        let client_guid = self.context.client_guid;
        let client_netname = self
            .config
            .client_name
            .clone()
            .unwrap_or_else(|| "smb-client".to_string());
        let has_signing = !signing_algorithms.is_empty();
        let has_encryption = !encrypting_algorithms.is_empty();

        // Context list supported on SMB3.1.1+
        let ctx_list = if supported_dialects.contains(&Dialect::Smb0311) {
            let mut preauth_integrity_hash = [0u8; 32];
            OsRng.fill_bytes(&mut preauth_integrity_hash);
            let mut ctx_list = vec![
                PreauthIntegrityCapabilities {
                    hash_algorithms: vec![HashAlgorithm::Sha512],
                    salt: preauth_integrity_hash.to_vec(),
                }
                .into(),
                NetnameNegotiateContextId {
                    netname: client_netname.into(),
                }
                .into(),
            ];
            Self::append_optional_negotiate_contexts(
                &mut ctx_list,
                encrypting_algorithms,
                compression_algorithms,
                signing_algorithms,
            );
            Some(ctx_list)
        } else {
            None
        };

        // Set capabilities to 0 if no SMB3 dialects are supported.
        let capabilities = if supported_dialects.iter().max() < Some(&Dialect::Smb030) {
            GlobalCapabilities::new()
        } else {
            let mut capabilities = GlobalCapabilities::new()
                .with_dfs(true)
                .with_leasing(true)
                .with_large_mtu(true)
                .with_multi_channel(self.config.multichannel.is_enabled())
                // SMB3 clients must advertise persistent-handle support before
                // a CA share can grant a DH2Q persistent create context.
                .with_persistent_handles(true)
                .with_directory_leasing(true);

            if has_encryption {
                capabilities.set_encryption(true);
            }

            // Enable notifications by client config + build config.
            if !self.config.disable_notifications && supported_dialects.contains(&Dialect::Smb0311)
            {
                capabilities.set_notifications(true);
            }
            capabilities
        };

        let security_mode = NegotiateSecurityMode::new()
            .with_signing_enabled(has_signing)
            .with_signing_required(has_signing && self.config.signing_policy.required(false));

        NegotiateRequest {
            security_mode,
            capabilities,
            client_guid,
            dialects: supported_dialects,
            negotiate_context_list: ctx_list,
        }
    }

    fn append_optional_negotiate_contexts(
        contexts: &mut Vec<NegotiateContext>,
        encrypting_algorithms: Vec<EncryptionCipher>,
        compression_algorithms: Vec<CompressionAlgorithm>,
        signing_algorithms: Vec<SigningAlgorithmId>,
    ) {
        if !encrypting_algorithms.is_empty() {
            contexts.push(
                EncryptionCapabilities {
                    ciphers: encrypting_algorithms,
                }
                .into(),
            );
        }
        if !compression_algorithms.is_empty() {
            contexts.push(
                CompressionCapabilities {
                    flags: CompressionCapsFlags::new().with_chained(true),
                    compression_algorithms,
                }
                .into(),
            );
        }
        if !signing_algorithms.is_empty() {
            contexts.push(SigningCapabilities { signing_algorithms }.into());
        }
    }

    /// Performs SMB negotiation post-connect.
    async fn _negotiate(
        &self,
        transport: Box<dyn SmbTransport>,
        smb2_only_neg: bool,
        recoverable: bool,
    ) -> crate::Result<()> {
        if self.context.conn_info().is_some() {
            return Err(Error::InvalidState("Already negotiated".into()));
        }

        // Negotiate SMB1, Switch to SMB2
        let generation_runtime = self
            ._negotiate_switch_to_smb2(transport, smb2_only_neg, GenerationId::new(1))
            .await?;

        // Negotiate SMB2
        let info = Arc::new(self._negotiate_smb2(&generation_runtime).await?);

        generation_runtime.negotaite_complete(&info).await?;
        self.context
            .publish_generation(generation_runtime.clone(), info.clone());

        // Always start the notify task unless the caller explicitly disabled
        // it. `caps.notifications()` is the SMB 3.1.1 ChangeNotify capability
        // and only modern Windows servers advertise it, but OplockBreak /
        // LeaseBreak notifications are part of the base SMB 2.x protocol and
        // every server can send them — we must always be ready to receive,
        // ack, and dispatch them, otherwise lease handling silently breaks.
        if !self.config.disable_notifications {
            tracing::debug!(
                "Starting Notification job (server notifications cap={}).",
                info.negotiation.caps.notifications()
            );
            self.context.start_notify().await?;
            tracing::debug!("Notification job started.");
        }

        if recoverable {
            self.context.start_recovery(
                generation_runtime,
                self.config.clone(),
                self.server_name.clone(),
                self.server_address,
            )?;
        }

        tracing::debug!("Negotiation successful");
        Ok(())
    }

    /// Starts a new session for the current connection, and authenticates it
    /// using the provided user name and password.
    ///
    /// ## Arguments
    /// * `user_name` - The user to authenticate with.
    /// * `password` - The password for the user.
    ///
    /// ## Returns
    /// A [`Session`] object representing the authenticated session.
    ///
    /// ## Notes:
    /// * Use the [`ConnectionConfig`] to configure authentication options.
    #[tracing::instrument(level = "debug", skip_all, fields(server = %self.server_name, user = %identity.username.account_name()))]
    pub async fn authenticate(&self, identity: sspi::AuthIdentity) -> crate::Result<Session> {
        let conn_info = self
            .context
            .conn_info()
            .ok_or_else(|| Error::InvalidState("Connection not negotiated.".to_string()))?;
        let session = Session::create(identity, &self.context, &conn_info).await?;
        let session_context = Arc::downgrade(&session.recovery_context());
        self.context
            .registry
            .insert_session(session.session_id(), session_context)
            .await;
        Ok(session)
    }

    pub(crate) async fn authenticate_with_credential_provider(
        &self,
        provider: crate::session::credential::SharedCredentialProvider,
    ) -> crate::Result<Session> {
        let conn_info = self
            .context
            .conn_info()
            .ok_or_else(|| Error::InvalidState("Connection not negotiated.".to_string()))?;
        let session = Session::create_with_provider(provider, &self.context, &conn_info).await?;
        let session_context = Arc::downgrade(&session.recovery_context());
        self.context
            .registry
            .insert_session(session.session_id(), session_context)
            .await;
        Ok(session)
    }

    /// Test-only: drive SessionSetup with a caller-supplied [`GssState`]
    /// implementor.
    ///
    /// Production code paths go through [`Self::authenticate`], which
    /// builds an sspi-backed `Authenticator` from the user's credentials.
    /// This method bypasses sspi entirely and is intended for
    /// deterministic transcript-replay tests where the GSS exchange
    /// must produce a known sequence of bytes.
    ///
    /// Behaviour, error semantics, and bookkeeping (session table,
    /// context weak ref) are identical to [`Self::authenticate`].
    #[cfg(feature = "test-support")]
    #[tracing::instrument(level = "debug", skip_all, fields(server = %self.server_name))]
    pub async fn authenticate_with_gss<G>(&self, gss: G) -> crate::Result<Session>
    where
        G: crate::session::gss::GssState + 'static,
    {
        let conn_info = self
            .context
            .conn_info()
            .ok_or_else(|| Error::InvalidState("Connection not negotiated.".to_string()))?;
        let session = Session::create_with_gss(gss, &self.context, &conn_info).await?;
        let session_context = Arc::downgrade(&session.recovery_context());
        self.context
            .registry
            .insert_session(session.session_id(), session_context)
            .await;
        Ok(session)
    }

    /// Test-only observation of the opaque runtime generation identity.
    #[cfg(feature = "test-support")]
    pub fn observed_generation(&self) -> Option<u64> {
        self.context
            .generation_runtime()
            .map(|generation_runtime| generation_runtime.generation().value())
    }
}

/// This struct is the internal message context for the SMB client.
pub(crate) struct ConnectionCore {
    client_guid: Guid,

    generation: ArcSwapOption<ConnectionGeneration>,

    recovery: OnceLock<Arc<RecoveryDriver>>,

    tasks: std::sync::Mutex<ConnectionTasks>,

    /// Cancellation token for stopping notifications.
    stop_notifications: CancellationToken,

    /// Domain-only lease/session registry. It owns no task and no request or
    /// transport authority; every lock is released before wire I/O.
    registry: ConnectionRegistry,
}

struct ConnectionGeneration {
    generation_runtime: Arc<GenerationRuntime>,
    conn_info: Arc<ConnectionInfo>,
}

#[derive(Default)]
struct ConnectionTasks {
    recovery: Option<tokio::task::JoinHandle<()>>,
    notifications: Vec<tokio::task::JoinHandle<()>>,
}

impl ConnectionCore {
    pub(crate) fn connection_object(&self) -> crate::Result<crate::runtime::ObjectToken> {
        Ok(self
            .generation_runtime()
            .ok_or_else(|| Error::InvalidState("Runtime is uninitialized".into()))?
            .connection_object())
    }

    pub(crate) async fn create_object(
        &self,
        parent: crate::runtime::ObjectToken,
        kind: crate::runtime::ObjectKind,
    ) -> crate::Result<crate::runtime::ObjectToken> {
        let parent = self.resolve_dependency(parent, None, None).await?;
        self.generation_runtime()
            .ok_or_else(|| Error::InvalidState("Runtime is uninitialized".into()))?
            .create_object(parent, kind)
            .await
    }

    pub(crate) async fn execute_for_with_replay(
        &self,
        mut msg: CommandRequest,
        mut options: ResponseOptions<'_>,
        dependency: crate::runtime::ObjectToken,
        replay: crate::runtime::ReplayPolicy,
    ) -> crate::Result<(CommandSubmission, CommandResponse)> {
        let timeout = options
            .timeout
            .or_else(|| self.conn_info().map(|info| info.config.timeout()));
        let dependency = self
            .resolve_dependency(dependency, timeout, options.async_cancel.clone())
            .await?;
        let channel_id = msg.channel_id;
        self.prepare_outgoing(&mut msg).await?;
        options.channel_id = channel_id;
        let result = self
            .generation_runtime()
            .ok_or_else(|| Error::InvalidState("Generation runtime is uninitialized.".to_string()))?
            .execute_for_with_replay(msg, &options, dependency, replay)
            .await?;
        if !result.1.message.header.flags.server_to_redir() {
            return Err(Error::InvalidMessage(
                "Expected server-to-redir message".into(),
            ));
        }
        Ok(result)
    }

    async fn execute_with_worker(
        &self,
        generation_runtime: &Arc<GenerationRuntime>,
        mut message: CommandRequest,
    ) -> crate::Result<(CommandSubmission, CommandResponse)> {
        let command = message.message.content.associated_cmd();
        // Candidate Connection negotiation must not inherit header policy
        // from the currently published generation.
        message.message.header.flags.set_priority_mask(0);
        let result = generation_runtime
            .execute_for(
                message,
                &ResponseOptions::new().with_cmd(Some(command)),
                generation_runtime.connection_object(),
            )
            .await?;
        if !result.1.message.header.flags.server_to_redir() {
            return Err(Error::InvalidMessage(
                "Expected server-to-redir message".into(),
            ));
        }
        Ok(result)
    }

    pub(crate) async fn receive(
        &self,
        options: ResponseOptions<'_>,
    ) -> crate::Result<CommandResponse> {
        Self::validate_incoming(
            self.generation_runtime()
                .ok_or_else(|| {
                    Error::InvalidState("Generation runtime is uninitialized.".to_string())
                })?
                .receive(&options)
                .await?,
            &options,
        )
    }

    fn validate_incoming(
        msg: CommandResponse,
        options: &ResponseOptions<'_>,
    ) -> crate::Result<CommandResponse> {
        if let Some(cmd) = options.cmd
            && msg.message.header.command != cmd
        {
            return Err(Error::UnexpectedMessageCommand(msg.message.header.command));
        }
        if !msg.message.header.flags.server_to_redir() {
            return Err(Error::InvalidMessage(
                "Expected server-to-redir message".into(),
            ));
        }
        if !options
            .status
            .iter()
            .any(|status| msg.message.header.status == *status as u32)
        {
            if let ResponseContent::Error(error) = msg.message.content {
                return Err(Error::ReceivedErrorMessage(
                    msg.message.header.status,
                    error,
                ));
            }
            return Err(Error::UnexpectedMessageStatus(msg.message.header.status));
        }
        Ok(msg)
    }

    fn new(client_guid: Guid) -> ConnectionCore {
        ConnectionCore {
            client_guid,
            generation: ArcSwapOption::empty(),
            recovery: OnceLock::new(),
            tasks: std::sync::Mutex::new(ConnectionTasks::default()),
            stop_notifications: Default::default(),
            registry: ConnectionRegistry::new(),
        }
    }

    pub(crate) async fn insert_oplock_slot(&self, slot: &Arc<OplockSlot>) {
        self.registry.insert_oplock(slot).await;
    }

    pub fn generation_runtime(&self) -> Option<Arc<GenerationRuntime>> {
        self.generation
            .load_full()
            .map(|generation| generation.generation_runtime.clone())
    }

    pub(crate) fn conn_info(&self) -> Option<Arc<ConnectionInfo>> {
        self.generation
            .load_full()
            .map(|generation| generation.conn_info.clone())
    }

    fn publish_generation(
        &self,
        generation_runtime: Arc<GenerationRuntime>,
        conn_info: Arc<ConnectionInfo>,
    ) {
        self.generation.store(Some(Arc::new(ConnectionGeneration {
            generation_runtime,
            conn_info,
        })));
    }

    fn start_recovery(
        self: &Arc<Self>,
        generation_runtime: Arc<GenerationRuntime>,
        config: ConnectionConfig,
        server_name: String,
        server_address: SocketAddr,
    ) -> crate::Result<()> {
        let clock = Arc::new(TokioClock::new());
        let bootstrap = Arc::new(ConnectionRecoveryBootstrap {
            context: Arc::downgrade(self),
            config: config.clone(),
            server_name,
            server_address,
        });
        let driver = Arc::new(RecoveryDriver::new(
            generation_runtime.connection_object(),
            config.auto_reconnect.runtime_policy(),
            clock,
            bootstrap,
            Arc::new(RandomRecoveryJitter::new(
                config.auto_reconnect.maximum_jitter,
            )),
        ));
        self.recovery
            .set(driver.clone())
            .map_err(|_| Error::InvalidState("Recovery coordinator already started".into()))?;
        let context = Arc::downgrade(self);
        let task = tokio::spawn(async move {
            let mut current = generation_runtime;
            loop {
                let exit = current.exited().await;
                match driver.recover(exit).await {
                    Ok(_) => {
                        let Some(context) = context.upgrade() else {
                            driver.close().await;
                            break;
                        };
                        let Some(replacement) = context.generation_runtime() else {
                            driver.close().await;
                            break;
                        };
                        context.recover_sessions().await;
                        if !config.disable_notifications
                            && let Err(error) = context.start_notify().await
                        {
                            tracing::warn!(?error, "recovered notification lane failed");
                        }
                        current = replacement;
                    }
                    Err(RecoveryError::NotRecoverable | RecoveryError::Closed) => break,
                    Err(error) => {
                        tracing::warn!(?error, "connection recovery terminated");
                        break;
                    }
                }
            }
        });
        self.tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .recovery = Some(task);
        Ok(())
    }

    async fn close_recovery(&self) {
        if let Some(driver) = self.recovery.get() {
            driver.close().await;
        }
    }

    async fn join_support_tasks(&self) {
        let tasks = {
            let mut tasks = self
                .tasks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let recovery = tasks.recovery.take();
            let notifications = std::mem::take(&mut tasks.notifications);
            (recovery, notifications)
        };
        if let Some(recovery) = tasks.0 {
            let _ = recovery.await;
        }
        for notification in tasks.1 {
            let _ = notification.await;
        }
    }

    async fn recover_sessions(&self) {
        let sessions = self.registry.recoverable_sessions().await;
        let results =
            futures_util::future::join_all(sessions.into_iter().map(|session| async move {
                let previous = session.session_id();
                let result = session.reauthenticate(previous).await;
                (session, result)
            }))
            .await;
        for (session, result) in results {
            match result {
                Ok((previous, replacement)) => {
                    self.registry
                        .replace_session(previous, replacement, Arc::downgrade(&session))
                        .await;
                }
                Err(error) => tracing::warn!(?error, "session reauthentication failed"),
            }
        }
    }

    pub(crate) async fn recover_session(&self, session_id: u64) -> crate::Result<()> {
        let session = self
            .registry
            .recoverable_sessions()
            .await
            .into_iter()
            .find(|session| session.session_id() == session_id)
            .ok_or_else(|| Error::InvalidState("Session recovery context is unavailable".into()))?;
        let (previous, replacement) = session.reauthenticate(session_id).await?;
        self.registry
            .replace_session(previous, replacement, Arc::downgrade(&session))
            .await;
        Ok(())
    }

    /// Stamp an [`CommandRequest`] with connection-level header policy.
    /// Callers that need the wire-bytes of a
    /// request *before* it goes through [`Self::submit`] (e.g. the
    /// session-setup driver hashing the final SessionSetup Request
    /// into the SMB 3.1.1 preauth integrity chain) invoke this
    /// directly, then call [`Self::dispatch_outgoing`] to hand the
    /// message off — bypassing `submit` so the sequencing logic does
    /// not run twice.
    pub(crate) async fn prepare_outgoing(&self, msg: &mut CommandRequest) -> crate::Result<()> {
        let priority_value = match self.conn_info() {
            Some(neg_info) => match neg_info.negotiation.dialect_rev {
                Dialect::Smb0311 => 1,
                _ => 0,
            },
            None => 0,
        };
        msg.message.header.flags = msg.message.header.flags.with_priority_mask(priority_value);

        if msg.message.content.as_cancel().is_ok() && msg.message.header.message_id == 0 {
            return Err(Error::InvalidState(
                "Cancel message must have a valid message ID".into(),
            ));
        }
        Ok(())
    }

    /// Hand a fully-prepared [`CommandRequest`] to the generation_runtime for
    /// transformation (sign/compress/encrypt) and transmission.
    /// Callers must have invoked [`Self::prepare_outgoing`] first.
    /// [`Self::submit`] is the public, all-in-one entry point that
    /// combines both.
    pub(crate) async fn dispatch_outgoing(
        &self,
        msg: CommandRequest,
    ) -> crate::Result<CommandSubmission> {
        let dependency = self.connection_object()?;
        let timeout = self.conn_info().map(|info| info.config.timeout());
        let dependency = self.resolve_dependency(dependency, timeout, None).await?;
        self.generation_runtime()
            .ok_or(Error::InvalidState(
                "Generation runtime is uninitialized".into(),
            ))?
            .send_for(msg, dependency)
            .await
    }

    async fn resolve_dependency(
        &self,
        dependency: crate::runtime::ObjectToken,
        timeout: Option<std::time::Duration>,
        cancellation: Option<CancellationToken>,
    ) -> crate::Result<crate::runtime::ObjectToken> {
        let Some(recovery) = self.recovery.get() else {
            return Ok(dependency);
        };
        let deadline = timeout.map(|timeout| recovery.deadline_after(timeout));
        recovery
            .resolve_dependency(dependency, deadline, cancellation)
            .await
            .map_err(|error| Error::InvalidState(error.to_string()))
    }

    async fn start_notify(self: &Arc<Self>) -> crate::Result<()> {
        let generation_runtime = self.generation_runtime().ok_or_else(|| {
            Error::InvalidState("Generation runtime is uninitialized.".to_string())
        })?;
        let generation_runtime = generation_runtime.clone();
        const CHANNEL_BUFFER_SIZE: usize = 10;
        let (tx, mut rx) = tokio::sync::mpsc::channel(CHANNEL_BUFFER_SIZE);
        generation_runtime.start_notify_channel(tx)?;
        let stop_notification = self.stop_notifications.clone();
        let self_clone = self.clone();
        let task = tokio::spawn(async move {
            // Race the cancellation token against each `rx.recv()` so that
            // (a) we keep draining notifications as they arrive and
            // (b) we exit promptly when the connection is shutting down.
            //
            // The previous form `select! { _ = cancelled() => break, else => { while let Some() } }`
            // never entered the inner loop: `select!`'s `else` branch only
            // fires when all named branches are *disabled* (via `if` guards),
            // not when they are pending — so the task only waited for
            // cancellation and never serviced any notification.
            loop {
                select! {
                    _ = stop_notification.cancelled() => {
                        tracing::info!("Notification context cancelled.");
                        break;
                    }
                    next = rx.recv() => {
                        match next {
                            Some(msg) => {
                                if let Err(e) = self_clone.notify(msg).await {
                                    tracing::error!("Error handling notification: {e:?}");
                                }
                            }
                            None => {
                                tracing::debug!(
                                    "Notification channel closed; exiting context."
                                );
                                break;
                            }
                        }
                    }
                }
            }
            tracing::info!("Notification context thread stopped.");
        });
        self.tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .notifications
            .push(task);
        Ok(())
    }

    pub fn stop_notify(&self) {
        self.stop_notifications.cancel();
        tracing::info!("Notification context stopped.");
    }
}

impl ConnectionCore {
    pub(crate) async fn submit(&self, mut msg: CommandRequest) -> crate::Result<CommandSubmission> {
        self.prepare_outgoing(&mut msg).await?;
        self.dispatch_outgoing(msg).await
    }

    pub(crate) async fn await_response(
        &self,
        options: ResponseOptions<'_>,
    ) -> crate::Result<CommandResponse> {
        self.receive(options).await
    }

    async fn notify(&self, msg: CommandResponse) -> crate::Result<()> {
        // Intercept LeaseBreakNotify *before* the session-id sanity check
        // because the server sends lease breaks with `session_id = 0` per
        // MS-SMB2 2.2.23.2 — the notification is keyed on lease_key, not
        // on any particular session. We must ack and fan out the event
        // promptly to stay within the 35-second break window.
        if matches!(msg.message.content, ResponseContent::LeaseBreakNotify(_)) {
            return self.handle_lease_break(msg).await;
        }
        if matches!(msg.message.content, ResponseContent::OplockBreakNotify(_)) {
            return self.handle_oplock_break(msg).await;
        }

        if msg.message.header.session_id == 0 {
            tracing::warn!("Received notification without session ID: {msg:?}");
            return Ok(());
        }

        // Lookup and weak-reference upgrade run in one registry critical section.
        // that distinguishes unknown session_id (warn and drop) from a
        // known-but-dropped session (raise InvalidState to surface the
        // ordering bug to callers).
        let session = match self
            .registry
            .get_session(msg.message.header.session_id)
            .await
        {
            Ok(Some(context)) => context,
            Ok(None) => {
                tracing::warn!(
                    "Received notification for unknown session ID {}: {msg:?}",
                    msg.message.header.session_id
                );
                return Ok(());
            }
            Err(registry::SessionGone) => {
                return Err(Error::InvalidState(format!(
                    "Session {} is no longer available",
                    msg.message.header.session_id
                )));
            }
        };

        session.notify(msg).await?;
        Ok(())
    }
}

impl ConnectionCore {
    async fn handle_oplock_break(&self, msg: CommandResponse) -> crate::Result<()> {
        let notify = match msg.message.content {
            ResponseContent::OplockBreakNotify(notify) => notify,
            other => {
                return Err(Error::InvalidState(format!(
                    "handle_oplock_break called with non-oplock content: {other:?}"
                )));
            }
        };
        let new_level = notify
            .oplock_level()
            .map_err(|error| Error::InvalidMessage(error.to_string()))?;
        let Some(slot) = self.registry.find_oplock(notify.file_id()).await else {
            tracing::warn!(file_id = ?notify.file_id(), "Unknown oplock break owner");
            return Ok(());
        };
        let Some(generation_runtime) = self.generation_runtime() else {
            return Err(Error::InvalidState("Runtime is uninitialized".into()));
        };
        if slot.object().generation() != generation_runtime.connection_object().generation() {
            tracing::debug!(file_id = ?notify.file_id(), "Ignoring stale-generation oplock break");
            return Ok(());
        }
        let previous_level = {
            let mut level = slot
                .level
                .write()
                .map_err(|_| Error::InvalidState("Oplock state is unavailable".into()))?;
            let previous = *level;
            *level = new_level;
            previous
        };
        // Level II breaks need no acknowledgement (MS-SMB2 3.2.5.19.1).
        if previous_level != OplockLevel::II {
            const ACK_DEADLINE: Duration = Duration::from_secs(35);
            match tokio::time::timeout(ACK_DEADLINE, self.send_oplock_break_ack(&slot, new_level))
                .await
            {
                Ok(Ok(())) => {}
                Ok(Err(error)) => tracing::warn!(?error, "OplockBreakAck failed"),
                Err(_) => tracing::warn!("OplockBreakAck timed out"),
            }
        }
        Ok(())
    }

    async fn send_oplock_break_ack(
        &self,
        slot: &Arc<OplockSlot>,
        level: OplockLevel,
    ) -> crate::Result<()> {
        let ack = smb_msg::OplockBreakAck::new(level, slot.file_id());
        slot.context
            .execute_for(
                CommandRequest::new(RequestContent::OplockBreakAck(ack)),
                ResponseOptions::new().with_cmd(Some(smb_msg::Command::OplockBreak)),
                slot.object(),
            )
            .await?;
        Ok(())
    }

    /// Process an incoming `LeaseBreakNotify`. Called from [`Self::notify`]
    /// before any session forwarding so that:
    ///
    /// 1. Subscribers (Phase C `lease_table`, Phase D `cifs.rs::handle_cache`)
    ///    learn about the broken lease as fast as possible and can flush
    ///    cached `FileId` entries.
    /// 2. The required `LeaseBreakAck` is sent back to the server inside
    ///    the 35-second window, otherwise the server revokes the lease
    ///    unilaterally and any deferred-close handles error on next use.
    ///
    /// Failures sending the ack are logged but not propagated — the
    /// connection-wide notify loop must keep draining notifications even
    /// if a single ack fails. Phase C will surface ack failures back to
    /// the affected handle through the broadcast event.
    async fn handle_lease_break(&self, msg: CommandResponse) -> crate::Result<()> {
        let notify = match msg.message.content {
            ResponseContent::LeaseBreakNotify(n) => n,
            // SAFETY: caller (`Self::notify`) just matched the variant.
            other => {
                return Err(Error::InvalidState(format!(
                    "handle_lease_break called with non-LeaseBreakNotify content: {other:?}"
                )));
            }
        };

        // This client never requests leases (see `FileCreateArgs`), so a break
        // cannot target an open it holds; record it and move on.
        tracing::debug!(
            lease_key = ?notify.lease_key,
            current = ?notify.current_lease_state,
            new = ?notify.new_lease_state,
            ack_required = notify.ack_required != 0,
            "LeaseBreakNotify received for a lease this client does not hold"
        );
        Ok(())
    }
}

impl Drop for ConnectionCore {
    fn drop(&mut self) {
        self.stop_notify();
        self.generation.store(None);
    }
}

#[cfg(test)]
mod negotiate_context_tests {
    use super::*;

    #[test]
    fn negotiation_advertises_support_without_requiring_optional_signing() {
        for (policy, required) in [
            (crate::SigningPolicy::Required, true),
            (crate::SigningPolicy::WhenRequired, false),
        ] {
            let connection = Connection::build(
                "signing.test",
                "127.0.0.1:445".parse().unwrap(),
                Guid::generate(),
                ConnectionConfig {
                    signing_policy: policy,
                    ..Default::default()
                },
            )
            .unwrap();
            let request = connection._make_smb2_neg_request(
                vec![Dialect::Smb0311],
                vec![SigningAlgorithmId::AesCmac],
                vec![],
                vec![],
            );
            assert!(request.security_mode.signing_enabled());
            assert_eq!(request.security_mode.signing_required(), required);
        }
    }

    #[test]
    fn disabled_algorithms_do_not_emit_empty_capability_contexts() {
        let mut contexts = Vec::new();
        Connection::append_optional_negotiate_contexts(&mut contexts, vec![], vec![], vec![]);
        assert!(contexts.is_empty());
    }
}
