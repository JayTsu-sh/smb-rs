pub mod config;
pub mod connection_info;
mod generation_runtime;
pub mod preauth_hash;
mod registry;

use crate::clock::TokioClock;
use crate::compression;
use crate::connection::preauth_hash::PreauthHashState;
use crate::dialects::DialectImpl;
use crate::lease::{
    LeaseBreakAckOutcome, LeaseBreakEvent, LeaseSlot, OplockBreakEvent, OplockSlot,
};
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
    OplockLevel, RequestContent, Response, ResponseContent, negotiate::*, oplock::LeaseBreakAck,
    smb1::SMB1NegotiateMessage,
};
use smb_transport::*;
use std::net::SocketAddr;
use std::sync::Weak;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::select;
use tokio_util::sync::CancellationToken;

/// Capacity of the per-connection lease-break broadcast. A handful of slow
/// subscribers wouldn't trail behind by more than this many events. Internal
/// cache invalidation is authoritative and does not depend on this channel.
const LEASE_BREAK_CHANNEL_CAPACITY: usize = 64;

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
            let remote_address = transport
                .remote_address()
                .map_err(|_| RuntimeError::Transport("recovery-remote-address"))?;
            let generation_runtime = connection
                ._negotiate_switch_to_smb2(transport, config.smb2_only_negotiate, generation)
                .await
                .map_err(|_| RuntimeError::Wire("recovery-negotiate-switch"))?;
            let info = match connection
                ._negotiate_smb2(remote_address, &generation_runtime)
                .await
            {
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

    /// Creates a SMB connection for an alternate channel,
    /// for the specified existing, primary connection.
    ///
    /// Returns the ID of the channel in the existing session.
    #[tracing::instrument(level = "debug", skip_all, fields(server = %self.server_name, user = %identity.username.account_name()))]
    pub async fn bind_session(
        &self,
        primary_session: &Session,
        identity: sspi::AuthIdentity,
    ) -> crate::Result<u32> {
        tracing::debug!("Binding alternate session to new connection");

        if self.conn_info().is_none() {
            return Err(Error::InvalidState(
                "Connection must be negotiated before binding a session.".to_string(),
            ));
        }

        if !self
            .conn_info()
            .as_ref()
            .ok_or_else(|| {
                Error::InvalidState(
                    "Connection info not available after negotiation check.".to_string(),
                )
            })?
            .negotiation
            .caps
            .multi_channel()
        {
            return Err(Error::InvalidState(
                "Server does not support multichannel.".to_string(),
            ));
        }

        primary_session
            .bind(
                identity,
                &self.context,
                &self.context.conn_info().ok_or_else(|| {
                    Error::InvalidState("Connection info not available.".to_string())
                })?,
            )
            .await
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

    /// Starts a new connection from an existing, connected transport.
    ///
    /// This is especially useful when you want to use a custom transport - otherwise,
    /// You should create a connection using the [`Client`][`crate::Client`] API.
    ///
    /// # Arguments
    /// * `transport` - The transport to use for the connection.
    /// * `server` - The name or address of the server to connect to.
    /// * `config` - The connection configuration. Note that the [`ConnectionConfig::transport`] field is NOT used when
    ///   creating the connection.
    /// # Returns
    /// A new [`Connection`] object with the specified transport and configuration.
    ///
    ///
    /// ```no_run
    /// # use smb::*;
    /// # use std::time::Duration;
    /// use smb_transport::TcpTransport;
    /// # #[tokio::main]
    /// # async fn main() -> Result<()> {
    /// let custom_tcp_transport = Box::new(TcpTransport::new(Duration::from_millis(10))); // you may also implement you own transport!
    /// let my_connection_config = ConnectionConfig { ..Default::default() };
    /// let connection = Connection::from_transport(custom_tcp_transport, "server", Guid::generate(), my_connection_config).await?;
    /// # Ok(())}
    /// ```
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

    /// Closes the connection, and all of it's managed resources.
    ///
    /// Any session, tree, or file handles associated with the connection will be unusable after
    /// calling this method.
    ///
    /// See also [`Client::close`][`crate::Client::close`].
    #[tracing::instrument(level = "debug", skip_all, fields(server = %self.server_name))]
    pub async fn close(&self) -> crate::Result<()> {
        self.context.stop_recovery().await;
        match self.context.generation_runtime() {
            Some(c) => c.stop().await,
            None => Ok(()),
        }
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
            u32::from(self.config.credits_backlog.unwrap_or(128)),
            generation,
        )
        .await
    }

    /// This method perofrms the SMB2 negotiation.
    async fn _negotiate_smb2(
        &self,
        server_address: std::net::SocketAddr,
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
                .with_return_raw_data(true),
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
            client_guid: self.context.client_guid,
            server_address,
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
            // QUIC
            #[cfg(feature = "quic")]
            if matches!(self.config.transport, TransportConfig::Quic(_)) {
                ctx_list.push(NegotiateContext {
                    context_type: NegotiateContextType::TransportCapabilities,
                    data: NegotiateContextValue::TransportCapabilities(
                        TransportCapabilities::new().with_accept_transport_layer_security(true),
                    ),
                });
            }
            // TODO: Add to config
            if cfg!(feature = "rdma") {
                ctx_list.push(NegotiateContext {
                    context_type: NegotiateContextType::RdmaTransformCapabilities,
                    data: NegotiateContextValue::RdmaTransformCapabilities(
                        RdmaTransformCapabilities {
                            transforms: vec![RdmaTransformId::None],
                        },
                    ),
                });
            }
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
                .with_persistent_handles(false)
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
            .with_signing_required(has_signing);

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

        let server_address = transport.remote_address()?;
        // Negotiate SMB1, Switch to SMB2
        let generation_runtime = self
            ._negotiate_switch_to_smb2(transport, smb2_only_neg, GenerationId::new(1))
            .await?;

        // Negotiate SMB2
        let info = Arc::new(
            self._negotiate_smb2(server_address, &generation_runtime)
                .await?,
        );

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

    /// Returns the connection information, if the connection has been negotiated.
    /// Otherwise, returns `None`.
    pub fn conn_info(&self) -> Option<Arc<ConnectionInfo>> {
        self.context.conn_info()
    }

    /// Test-only observation of the opaque runtime generation identity.
    #[cfg(feature = "test-support")]
    pub fn observed_generation(&self) -> Option<u64> {
        self.context
            .generation_runtime()
            .map(|generation_runtime| generation_runtime.generation().value())
    }

    /// Subscribe to lease-break notifications received on this connection.
    /// See [`ConnectionCore::subscribe_lease_breaks`] for semantics.
    pub fn subscribe_lease_breaks(&self) -> tokio::sync::broadcast::Receiver<LeaseBreakEvent> {
        self.context.subscribe_lease_breaks()
    }

    pub fn subscribe_oplock_breaks(&self) -> tokio::sync::broadcast::Receiver<OplockBreakEvent> {
        self.context.subscribe_oplock_breaks()
    }

    /// Install a [`crate::lease::LeaseSlot`] into this connection's
    /// lease cache. See [`ConnectionCore::insert_lease_slot`].
    pub async fn insert_lease_slot(&self, slot: Arc<LeaseSlot>) -> crate::Result<()> {
        self.context.insert_lease_slot(slot).await
    }

    /// Return the current number of cached lease slots.
    pub async fn lease_slot_count(&self) -> crate::Result<usize> {
        self.context.lease_slot_count().await
    }

    /// Look up a cached lease slot by path; `None` when absent.
    pub async fn peek_lease_slot(&self, path: &str) -> crate::Result<Option<Arc<LeaseSlot>>> {
        self.context.peek_lease_slot(path).await
    }

    /// Atomic cache-hit acquire: peek a slot and bump its refcount inside
    /// the `lease_table` lock. See
    /// [`ConnectionCore::try_acquire_lease`] for semantics and
    /// the rationale around lock ordering vs eviction.
    pub async fn try_acquire_lease(
        &self,
        path: &str,
        requested_access: smb_fscc::FileAccessMask,
        requested_disposition: smb_msg::CreateDisposition,
        wants_directory: bool,
    ) -> crate::Result<Option<Arc<LeaseSlot>>> {
        self.context
            .try_acquire_lease(
                path,
                requested_access,
                requested_disposition,
                wants_directory,
            )
            .await
    }

    /// Phase C.5: tombstone a lease slot and remove it from the table.
    /// See [`ConnectionCore::take_lease_for_evict`] for the
    /// race-free contract.
    pub async fn take_lease_for_evict(&self, path: &str) -> crate::Result<Option<LeaseEviction>> {
        self.context.take_lease_for_evict(path).await
    }

    /// Phase C.5: scan the connection's lease table and tombstone any
    /// slot whose `last_used` is older than `older_than`. Slots whose
    /// refcount is zero at sweep time are removed from the table and
    /// returned for the caller to flush the wire Close. Live-ref slots
    /// stay in the table tombstoned; their last release_one will send
    /// the deferred Close through the regular path.
    pub async fn sweep_idle_leases(
        &self,
        older_than: std::time::Duration,
    ) -> crate::Result<Vec<LeaseEviction>> {
        self.context.sweep_idle_leases(older_than).await
    }

    /// Send an SMB2 compound chain through this connection's generation_runtime and
    /// receive each member's response.
    ///
    /// For each message in `msgs` (in order) this:
    /// 1. Sets `priority_mask` per the negotiated dialect, matching the
    ///    single-command execution path.
    /// 2. Submits the entire typed batch atomically; the runtime owner
    ///    allocates MessageIds and credit charge/request values.
    /// 3. After all members are prepared, hands the whole batch to
    ///    [`crate::connection::generation_runtime::GenerationRuntime::send_compound`] for
    ///    the single TCP write.
    /// 4. Awaits each member's response separately via
    ///    `Generation runtime::receive` — server splits the compound response into
    ///    N parts; our compound-aware incoming-side parser routes each
    ///    part by message_id, and these receives just consume the
    ///    pre-routed entries.
    /// 5. The runtime owner applies every response grant before publishing
    ///    the corresponding typed result.
    ///
    /// The caller owns everything semantic: setting
    /// `flags.related_operations` on members 2..N to chain off the
    /// previous command's FileId/TreeId/SessionId, setting
    /// `FileId::FULL` on commands that should reuse the prior result,
    /// and validating each response's status code.
    ///
    /// On success returns `responses.len() == msgs.len()` in input order.
    ///
    /// **Size budget:** the whole chain (headers + bodies + 8-byte
    /// alignment padding between members) goes out as one transport
    /// write, which the server's NetBIOS-layer reader caps at the
    /// negotiated `max_transact_size`. Callers should keep the sum of
    /// per-member serialized sizes well below
    /// `conn.conn_info().unwrap().negotiation.max_transact_size`
    /// (typically 1 MiB on modern Windows / NetApp / Samba). Going
    /// over yields `STATUS_INVALID_PARAMETER` or a torn connection
    /// depending on the server. There is no client-side enforcement
    /// today — adding one would require pre-serializing each member
    /// twice, which defeats the point of the single-write path.
    pub async fn send_compound(
        &self,
        msgs: Vec<CommandRequest>,
    ) -> crate::Result<Vec<CommandResponse>> {
        self.send_compound_for(msgs, self.context.connection_object()?)
            .await
    }

    pub(crate) async fn send_compound_for(
        &self,
        mut msgs: Vec<CommandRequest>,
        dependency: crate::runtime::ObjectToken,
    ) -> crate::Result<Vec<CommandResponse>> {
        let dependency = self
            .context
            .resolve_dependency(dependency, Some(self.config.timeout()), None)
            .await?;
        // CancelRequest has its own bespoke path inside the single-message
        // `submit` (it reuses an already-allocated message_id and skips
        // owner admission). Bundling it into a compound chain
        // would either re-allocate its message_id — silently breaking the
        // cancel target — or skip the per-member accounting we run below.
        // Reject up front rather than letting either failure mode bite.
        for (i, m) in msgs.iter().enumerate() {
            if m.message.content.as_cancel().is_ok() {
                return Err(Error::InvalidArgument(format!(
                    "send_compound: member {i} is a CancelRequest, which is not \
                     supported in compound chains; cancel must be sent on its own"
                )));
            }
        }
        let priority_value = match self.context.conn_info() {
            Some(neg_info) => match neg_info.negotiation.dialect_rev {
                Dialect::Smb0311 => 1,
                _ => 0,
            },
            None => 0,
        };
        for m in msgs.iter_mut() {
            m.message.header.flags = m.message.header.flags.with_priority_mask(priority_value);
        }

        let generation_runtime = self
            .context
            .generation_runtime()
            .ok_or(Error::InvalidState(
                "Generation runtime is uninitialized".into(),
            ))?;
        let send_results = generation_runtime
            .send_compound_for(msgs, dependency)
            .await?;

        let mut responses = Vec::with_capacity(send_results.len());
        for r in send_results {
            let mut opts = ResponseOptions::new();
            opts.msg_id = r.msg_id;
            opts.allow_async = true;
            let incoming = generation_runtime.receive(&opts).await?;
            responses.push(incoming);
        }
        Ok(responses)
    }
}

/// Phase C.5: a slot that was just removed from the per-connection lease
/// table because either an explicit `evict_lease` or an idle-sweep
/// decided to flush it. The caller — `Client::evict_lease` /
/// `Client::flush_idle_leases` — is responsible for sending the wire
/// `Close` when `needs_wire_close` is true.
pub struct LeaseEviction {
    /// The slot that was removed from the table. Held as `Arc` since
    /// live `ResourceHandle`s may still reference it; their close()/Drop
    /// will see `tombstoned == true` and become no-ops on the table
    /// (we already removed the entry).
    pub slot: Arc<LeaseSlot>,
    /// `true` when this eviction owns the wire `Close`: at removal time
    /// the slot had zero live handles, so no `release_one` path will
    /// fire it. The caller must send `CloseRequest` against
    /// `slot.file_id` through `slot.proto.context`. `false` when at
    /// least one live handle was present; that handle's
    /// `release_one` -> `CloseAndEvict` path will own the wire Close.
    pub needs_wire_close: bool,
}

/// This struct is the internal message context for the SMB client.
pub(crate) struct ConnectionCore {
    client_guid: Guid,

    generation: ArcSwapOption<ConnectionGeneration>,

    recovery: OnceLock<Arc<RecoveryDriver>>,

    /// Cancellation token for stopping notifications.
    stop_notifications: CancellationToken,

    /// Broadcasts [`LeaseBreakEvent`] to any [`crate::Client::subscribe_lease_breaks`]
    /// consumers when the server sends a `LeaseBreakNotify`.
    lease_event_tx: tokio::sync::broadcast::Sender<LeaseBreakEvent>,
    oplock_event_tx: tokio::sync::broadcast::Sender<OplockBreakEvent>,

    /// Domain-only lease/session registry. It owns no task and no request or
    /// transport authority; every lock is released before wire I/O.
    registry: ConnectionRegistry,
}

struct ConnectionGeneration {
    generation_runtime: Arc<GenerationRuntime>,
    conn_info: Arc<ConnectionInfo>,
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

    pub(crate) async fn submit_for(
        &self,
        mut message: CommandRequest,
        dependency: crate::runtime::ObjectToken,
    ) -> crate::Result<CommandSubmission> {
        let timeout = self.conn_info().map(|info| info.config.timeout());
        let dependency = self.resolve_dependency(dependency, timeout, None).await?;
        self.prepare_outgoing(&mut message).await?;
        self.generation_runtime()
            .ok_or_else(|| Error::InvalidState("Runtime is uninitialized".into()))?
            .send_for(message, dependency)
            .await
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
        let (lease_event_tx, _) = tokio::sync::broadcast::channel(LEASE_BREAK_CHANNEL_CAPACITY);
        let (oplock_event_tx, _) = tokio::sync::broadcast::channel(LEASE_BREAK_CHANNEL_CAPACITY);

        ConnectionCore {
            client_guid,
            generation: ArcSwapOption::empty(),
            recovery: OnceLock::new(),
            stop_notifications: Default::default(),
            lease_event_tx,
            oplock_event_tx,
            registry: ConnectionRegistry::new(),
        }
    }

    /// Install a [`LeaseSlot`] into the per-connection cache. Called from
    /// [`crate::Client::create_file`] after a successful Create that
    /// carried an `RqLs` grant. Overwrites any prior entry for the same
    /// path — a stale slot (e.g., a previous open that was closed by the
    /// other side) is logically equivalent to no cache hit.
    pub async fn insert_lease_slot(&self, slot: Arc<LeaseSlot>) -> crate::Result<()> {
        use std::sync::atomic::Ordering;
        let displaced = self.registry.insert_lease(slot).await;
        if let Some(prev) = displaced {
            // Tombstone the displaced slot. If a live ResourceHandle is
            // still holding it (refcount > 0), its eventual close/Drop
            // will see `CloseAndEvict` on release_one and send the wire
            // `Close`. If the handle has already been dropped (refcount
            // == 0 at displacement time), nobody will call release_one
            // ever again, so we must send the wire Close ourselves —
            // otherwise the server-side FileId leaks until session
            // disconnect.
            prev.tombstoned.store(true, Ordering::Release);
            let live = prev.refcount.load(Ordering::Acquire);
            tracing::debug!(
                path = %prev.path,
                live_refs = live,
                "Replaced existing lease slot in cache; old slot tombstoned",
            );
            if live == 0 && prev.file_id != smb_msg::FileId::EMPTY {
                let file_id = prev.file_id;
                let context = prev.proto.context.clone();
                // The spawned task captures the `context` chain
                // (TreeContext -> SessionContext)
                // by Arc clone, but NOT this
                // ConnectionCore itself. If the Connection
                // races into Drop before the spawn runs, its
                // `generation_runtime.stop()` (in Connection::Drop) will complete
                // first and send_close_external will see a stopped
                // generation_runtime — at worst we lose this displaced FileId,
                // which the session-disconnect garbage-collects anyway.
                // The spawn does *not* extend the Connection's lifetime;
                // tying it to Connection would require Arc'ing the
                // context chain back up, which we explicitly avoid.
                tokio::spawn(async move {
                    if let Err(e) = crate::resource::ResourceHandle::send_close_external(
                        file_id,
                        &context,
                        prev.proto.object,
                    )
                    .await
                    {
                        tracing::warn!(
                            file_id = ?file_id,
                            error = ?e,
                            "Displaced-slot wire Close failed (FileId leaked until session end)",
                        );
                    }
                });
            }
        }
        Ok(())
    }

    pub(crate) async fn insert_oplock_slot(&self, slot: &Arc<OplockSlot>) {
        self.registry.insert_oplock(slot).await;
    }

    /// Return the current number of cached lease slots. Primarily for
    /// observability and tests; not in any hot path.
    pub async fn lease_slot_count(&self) -> crate::Result<usize> {
        Ok(self.registry.lease_slot_count().await)
    }

    /// Look up a cached lease slot by path. Returns `None` when there is
    /// no entry. Used by tests and the break-listener task; the cache-hit
    /// fast path in `Client::_create_file` goes through
    /// [`Self::try_acquire_lease`] instead so the bump is atomic with the
    /// lookup against concurrent evictions.
    pub async fn peek_lease_slot(&self, path: &str) -> crate::Result<Option<Arc<LeaseSlot>>> {
        Ok(self.registry.peek_lease(path).await)
    }

    /// Phase C.5 race-free acquire: look up `path` and call
    /// [`LeaseSlot::try_acquire_for_reuse`] *while still holding the
    /// `lease_table` lock*. This serializes the refcount bump against
    /// concurrent [`Self::take_lease_for_evict`] / [`Self::sweep_idle_leases`]
    /// callers that also take the lock; without the lock the evict path
    /// could observe `refcount == 0`, send a wire Close, and remove the
    /// slot between an acquirer's `peek` and `fetch_add`, leaving the
    /// acquirer with a stale FileId. Returns `Some(slot)` on a successful
    /// bump, `None` for any non-hit reason.
    pub async fn try_acquire_lease(
        &self,
        path: &str,
        requested_access: smb_fscc::FileAccessMask,
        requested_disposition: smb_msg::CreateDisposition,
        wants_directory: bool,
    ) -> crate::Result<Option<Arc<LeaseSlot>>> {
        Ok(self
            .registry
            .try_acquire_lease(
                path,
                requested_access,
                requested_disposition,
                wants_directory,
            )
            .await)
    }

    /// Phase C.5: atomically tombstone a slot keyed by `path`, remove it
    /// from the table, and report whether the caller owes a wire Close.
    /// The lock is held across the tombstone-store and the
    /// `refcount.load`, so an `Acquire`-ordered `try_acquire_for_reuse`
    /// running on another task either finishes its bump before this
    /// function reads `refcount` (so we observe > 0 and yield the
    /// close to that holder's `release_one`) or finds the slot gone
    /// from the table and falls back to the wire Create path.
    ///
    /// Returns `None` when `path` had no entry.
    pub async fn take_lease_for_evict(&self, path: &str) -> crate::Result<Option<LeaseEviction>> {
        Ok(self.registry.take_lease_for_evict(path).await)
    }

    /// Phase C.5 idle sweep: walk the lease table, tombstone every slot
    /// whose `last_used` predates `now - older_than`, and remove those
    /// entries from the table. Slots with zero refcount at sweep time
    /// are returned in the result so the caller can flush the wire
    /// Close; slots with live handles stay tombstoned and rely on the
    /// regular `release_one` -> `CloseAndEvict` path.
    pub async fn sweep_idle_leases(
        &self,
        older_than: std::time::Duration,
    ) -> crate::Result<Vec<LeaseEviction>> {
        Ok(self.registry.sweep_idle_leases(older_than).await)
    }

    /// Apply a single [`LeaseBreakEvent`] to the connection's lease table.
    /// All slots whose `lease_key` matches the event are tombstoned,
    /// removed from the table, and their `granted_state` snapshot
    /// updated to the server's new state.
    ///
    /// The tombstone-store, granted_state update, and table removal all
    /// happen inside one registry critical section so a concurrent `try_acquire_lease`
    /// either runs strictly before (and gets a still-valid slot for
    /// which the wire I/O may racily fail — recoverable) or strictly
    /// after (and finds the slot gone, falling back to a fresh wire
    /// Create). Without this fence the in-flight acquirer could observe
    /// `tombstoned == false`, bump refcount, and hand out a FileId the
    /// server has already revoked.
    async fn apply_lease_break(&self, event: &LeaseBreakEvent) -> Vec<Arc<LeaseSlot>> {
        let event_key = event.lease_key.as_u128();
        let matching = self
            .registry
            .apply_lease_break(event_key, event.new_state)
            .await;

        if matching.is_empty() {
            tracing::trace!(
                lease_key = ?event.lease_key,
                "Break event has no matching slot in this connection's cache",
            );
            return matching;
        }
        for slot in &matching {
            tracing::debug!(
                path = %slot.path,
                lease_key = %slot.lease_key,
                new_state = ?event.new_state,
                "Lease slot tombstoned + removed by server break",
            );
        }
        matching
    }

    /// Subscribe to lease-break notifications received on this connection.
    ///
    /// Each call returns a fresh `Receiver`; sending is broadcast, so multiple
    /// subscribers each see every event. Lagging subscribers may receive
    /// `RecvError::Lagged` and skip older events — the connection task has
    /// already sent the ack by that point, so missing the event only means
    /// the subscriber's cache invalidation is delayed, never that the
    /// protocol is left in a bad state.
    pub fn subscribe_lease_breaks(&self) -> tokio::sync::broadcast::Receiver<LeaseBreakEvent> {
        self.lease_event_tx.subscribe()
    }

    pub fn subscribe_oplock_breaks(&self) -> tokio::sync::broadcast::Receiver<OplockBreakEvent> {
        self.oplock_event_tx.subscribe()
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
        tokio::spawn(async move {
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
        Ok(())
    }

    async fn stop_recovery(&self) {
        if let Some(driver) = self.recovery.get() {
            driver.close().await;
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
        tokio::spawn(async move {
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
        let ack_required = previous_level != OplockLevel::II;
        let ack_outcome = if ack_required {
            const ACK_DEADLINE: Duration = Duration::from_secs(35);
            match tokio::time::timeout(ACK_DEADLINE, self.send_oplock_break_ack(&slot, new_level))
                .await
            {
                Ok(Ok(())) => LeaseBreakAckOutcome::Accepted,
                Ok(Err(error)) => {
                    tracing::warn!(?error, "OplockBreakAck failed");
                    LeaseBreakAckOutcome::Failed
                }
                Err(_) => LeaseBreakAckOutcome::TimedOut,
            }
        } else {
            LeaseBreakAckOutcome::NotRequired
        };
        let _ = self.oplock_event_tx.send(OplockBreakEvent {
            file_id: notify.file_id(),
            previous_level,
            new_level,
            ack_outcome,
            received_at: Instant::now(),
        });
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

        let ack_required = notify.ack_required != 0;
        tracing::debug!(
            lease_key = ?notify.lease_key,
            current = ?notify.current_lease_state,
            new = ?notify.new_lease_state,
            ack_required,
            "LeaseBreakNotify received"
        );

        let received_at = Instant::now();
        let mut event = LeaseBreakEvent {
            lease_key: notify.lease_key,
            current_state: notify.current_lease_state,
            new_state: notify.new_lease_state,
            epoch: notify.new_epoch,
            ack_required,
            ack_outcome: LeaseBreakAckOutcome::NotRequired,
            received_at,
        };

        // Invalidate under the registry's one critical section before any
        // acknowledgement can unblock the conflicting server operation.
        let invalidated = self.apply_lease_break(&event).await;
        if ack_required {
            const ACK_DEADLINE: Duration = Duration::from_secs(35);
            event.ack_outcome = match tokio::time::timeout(
                ACK_DEADLINE,
                self.send_lease_break_ack(invalidated.first(), &notify),
            )
            .await
            {
                Ok(Ok(())) => LeaseBreakAckOutcome::Accepted,
                Ok(Err(error)) => {
                    tracing::warn!(?error, "LeaseBreakAck failed");
                    LeaseBreakAckOutcome::Failed
                }
                Err(_) => {
                    tracing::warn!("LeaseBreakAck deadline elapsed");
                    LeaseBreakAckOutcome::TimedOut
                }
            };
        }

        // Public consumer lag cannot affect internal cache correctness: the
        // authoritative invalidation above has already completed.
        let _ = self.lease_event_tx.send(event);

        Ok(())
    }

    /// Construct and send a `LeaseBreakAck` for the given notification.
    ///
    /// MS-SMB2 requires the acknowledgement to use the SessionId and TreeId
    /// of the open that owns the lease. Route through the context retained in
    /// that lease slot so the normal context chain stamps both identifiers and
    /// applies the tree's signing/encryption policy.
    async fn send_lease_break_ack(
        &self,
        slot: Option<&Arc<LeaseSlot>>,
        notify: &smb_msg::LeaseBreakNotify,
    ) -> crate::Result<()> {
        let slot = slot.ok_or_else(|| {
            Error::InvalidState("Cannot acknowledge lease break without its owning Resource".into())
        })?;

        let ack = LeaseBreakAck {
            lease_key: notify.lease_key,
            lease_state: notify.new_lease_state,
        };
        slot.proto
            .context
            .send_recv(RequestContent::LeaseBreakAck(ack))
            .await?;
        tracing::debug!(
            lease_key = ?notify.lease_key,
            tree_id = slot.tree_id,
            "LeaseBreakAck accepted",
        );
        Ok(())
    }
}

impl Drop for ConnectionCore {
    fn drop(&mut self) {
        self.stop_notify();

        let generation = match self.generation.swap(None) {
            Some(generation) => generation,
            None => return,
        };
        let recovery = self.recovery.get().cloned();

        tokio::task::spawn(async move {
            if let Some(recovery) = recovery {
                recovery.close().await;
            }
            generation.generation_runtime.stop().await.ok();
        });
    }
}

#[cfg(test)]
mod negotiate_context_tests {
    use super::*;

    #[test]
    fn disabled_algorithms_do_not_emit_empty_capability_contexts() {
        let mut contexts = Vec::new();
        Connection::append_optional_negotiate_contexts(&mut contexts, vec![], vec![], vec![]);
        assert!(contexts.is_empty());
    }
}
