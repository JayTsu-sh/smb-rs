pub mod config;
pub mod connection_info;
pub mod preauth_hash;
pub mod transformer;
pub mod worker;

use crate::compression;
use crate::connection::preauth_hash::PreauthHashState;
use crate::dialects::DialectImpl;
use crate::lease::{LeaseBreakEvent, LeaseSlot};
use crate::session::ChannelMessageHandler;
use crate::sync_helpers::*;
use crate::{Error, crypto, msg_handler::*, session::Session};
use binrw::prelude::*;
pub use config::*;
use connection_info::{ConnectionInfo, NegotiatedProperties};
use rand::RngCore;
use rand::rngs::OsRng;
use smb_dtyp::*;
use smb_msg::{
    Command, RequestContent, Response, ResponseContent, negotiate::*, oplock::LeaseBreakAck,
    smb1::SMB1NegotiateMessage,
};
use smb_transport::*;
use std::cmp::max;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::time::Instant;
pub use transformer::TransformError;
use worker::{Worker, WorkerImpl};

/// Capacity of the per-connection lease-break broadcast. A handful of slow
/// subscribers wouldn't trail behind by more than this many events; if they
/// do, they receive `RecvError::Lagged` and miss the older notifications —
/// acceptable since the ack itself has already been sent by the connection
/// task and the subscriber's role is just to invalidate cached state.
const LEASE_BREAK_CHANNEL_CAPACITY: usize = 64;

/// Represents an SMB connection.
///
/// Each SMB connection has a single matching transport (e.g. TCP connection).
/// Usually, most use cases require a single connection per server-client communication.
pub struct Connection {
    handler: HandlerReference<ConnectionMessageHandler>,
    config: ConnectionConfig,

    server_name: String,
    server_address: SocketAddr,
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
            handler: HandlerReference::new(ConnectionMessageHandler::new(
                client_guid,
                config.credits_backlog,
            )),
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
                &self.handler,
                self.handler.conn_info.get().ok_or_else(|| {
                    Error::InvalidState("Connection info not available.".to_string())
                })?,
            )
            .await
    }

    /// Connects to the specified server, if it is not already connected, and negotiates the connection.
    #[tracing::instrument(level = "debug", skip_all, fields(server = %self.server_name))]
    pub async fn connect(&self) -> crate::Result<()> {
        if self.handler.worker().is_some() {
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
        self._negotiate(transport, self.config.smb2_only_negotiate)
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
        conn._negotiate(transport, conn.config.smb2_only_negotiate)
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
        match self.handler.worker() {
            Some(c) => c.stop().await,
            None => Ok(()),
        }
    }

    /// Switches the protocol to SMB2 against the server if required,
    /// and wraps the transport in a SMB2 worker.
    async fn _negotiate_switch_to_smb2(
        &self,
        mut transport: Box<dyn SmbTransport>,
        smb2_only_neg: bool,
    ) -> crate::Result<Arc<WorkerImpl>> {
        // Multi-protocol negotiation: Begin with SMB1, expect SMB2.
        if !smb2_only_neg {
            tracing::debug!("Negotiating multi-protocol: Sending SMB1");
            // 1. Send SMB1 negotiate request
            let msg_bytes: Vec<u8> = SMB1NegotiateMessage::default().try_into()?;
            transport.send(&IoVec::from(msg_bytes)).await?;

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
            self.handler.curr_msg_id.fetch_add(1, Ordering::Relaxed);
        }

        WorkerImpl::start(transport, self.config.timeout()).await
    }

    /// This method perofrms the SMB2 negotiation.
    async fn _negotiate_smb2(
        &self,
        server_address: std::net::SocketAddr,
    ) -> crate::Result<ConnectionInfo> {
        // Confirm that we're not already negotiated.
        if self.handler.conn_info.get().is_some() {
            return Err(Error::InvalidState("Already negotiated".into()));
        }

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
            .handler
            .sendor_recv(
                OutgoingMessage::new(
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
            let mut request_raw = request_status
                .raw
                .expect("Preauth hash must be calculated for supported dialect!");
            request_raw.consolidate();
            PreauthHashState::begin()
                .next(request_raw.first().ok_or_else(|| {
                    Error::InvalidState("Preauth hash request data is empty.".to_string())
                })?)?
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
            client_guid: self.handler.client_guid,
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
        let client_guid = self.handler.client_guid;
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
                EncryptionCapabilities {
                    ciphers: encrypting_algorithms,
                }
                .into(),
                CompressionCapabilities {
                    flags: CompressionCapsFlags::new()
                        .with_chained(!compression_algorithms.is_empty()),
                    compression_algorithms,
                }
                .into(),
                SigningCapabilities { signing_algorithms }.into(),
            ];
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
            if !self.config.disable_notifications
                && supported_dialects.contains(&Dialect::Smb0311)
            {
                capabilities.set_notifications(true);
            }
            capabilities
        };

        let security_mode = NegotiateSecurityMode::new().with_signing_enabled(has_signing);

        NegotiateRequest {
            security_mode,
            capabilities,
            client_guid,
            dialects: supported_dialects,
            negotiate_context_list: ctx_list,
        }
    }

    /// Performs SMB negotiation post-connect.
    async fn _negotiate(
        &self,
        transport: Box<dyn SmbTransport>,
        smb2_only_neg: bool,
    ) -> crate::Result<()> {
        if self.handler.conn_info.get().is_some() {
            return Err(Error::InvalidState("Already negotiated".into()));
        }

        let server_address = transport.remote_address()?;
        // Negotiate SMB1, Switch to SMB2
        let worker = self
            ._negotiate_switch_to_smb2(transport, smb2_only_neg)
            .await?;

        self.handler
            .worker
            .set(worker)
            .map_err(|_| Error::InvalidState("Worker already set.".to_string()))?;

        // Negotiate SMB2
        let info = Arc::new(self._negotiate_smb2(server_address).await?);

        self.handler
            .worker
            .get()
            .ok_or_else(|| Error::InvalidState("Worker is uninitialized.".to_string()))?
            .negotaite_complete(&info)
            .await;

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
            self.handler.handler.start_notify().await?;
            tracing::debug!("Notification job started.");

            // Phase C.2: the break-listener consumes the per-connection
            // lease_event_tx broadcast (fed by handle_lease_break) and
            // tombstones matching slots in lease_table so new opens
            // miss the cache after a server-side break.
            self.handler.handler.start_lease_break_listener();
        }

        self.handler
            .conn_info
            .set(info)
            .map_err(|_| Error::InvalidState("Connection info already set.".to_string()))?;

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
        let session = Session::create(
            identity,
            &self.handler,
            self.handler
                .conn_info
                .get()
                .ok_or_else(|| Error::InvalidState("Connection not negotiated.".to_string()))?,
        )
        .await?;
        let session_handler = session.handler.weak();
        self.handler
            .sessions
            .lock()
            .await
            .insert(session.session_id(), session_handler);
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
    /// handler weak ref) are identical to [`Self::authenticate`].
    #[cfg(feature = "test-support")]
    #[tracing::instrument(level = "debug", skip_all, fields(server = %self.server_name))]
    pub async fn authenticate_with_gss<G>(&self, gss: G) -> crate::Result<Session>
    where
        G: crate::session::gss::GssState + 'static,
    {
        let session = Session::create_with_gss(
            gss,
            &self.handler,
            self.handler
                .conn_info
                .get()
                .ok_or_else(|| Error::InvalidState("Connection not negotiated.".to_string()))?,
        )
        .await?;
        let session_handler = session.handler.weak();
        self.handler
            .sessions
            .lock()
            .await
            .insert(session.session_id(), session_handler);
        Ok(session)
    }

    /// Returns the connection information, if the connection has been negotiated.
    /// Otherwise, returns `None`.
    pub fn conn_info(&self) -> Option<&Arc<ConnectionInfo>> {
        self.handler.conn_info.get()
    }

    /// Subscribe to lease-break notifications received on this connection.
    /// See [`ConnectionMessageHandler::subscribe_lease_breaks`] for semantics.
    pub fn subscribe_lease_breaks(&self) -> tokio::sync::broadcast::Receiver<LeaseBreakEvent> {
        self.handler.subscribe_lease_breaks()
    }

    /// Install a [`crate::lease::LeaseSlot`] into this connection's
    /// lease cache. See [`ConnectionMessageHandler::insert_lease_slot`].
    pub async fn insert_lease_slot(&self, slot: Arc<LeaseSlot>) -> crate::Result<()> {
        self.handler.insert_lease_slot(slot).await
    }

    /// Return the current number of cached lease slots.
    pub async fn lease_slot_count(&self) -> crate::Result<usize> {
        self.handler.lease_slot_count().await
    }

    /// Look up a cached lease slot by path; `None` when absent.
    pub async fn peek_lease_slot(&self, path: &str) -> crate::Result<Option<Arc<LeaseSlot>>> {
        self.handler.peek_lease_slot(path).await
    }

    /// Atomic cache-hit acquire: peek a slot and bump its refcount inside
    /// the `lease_table` lock. See
    /// [`ConnectionMessageHandler::try_acquire_lease`] for semantics and
    /// the rationale around lock ordering vs eviction.
    pub async fn try_acquire_lease(
        &self,
        path: &str,
        requested_access: smb_fscc::FileAccessMask,
        requested_disposition: smb_msg::CreateDisposition,
        wants_directory: bool,
    ) -> crate::Result<Option<Arc<LeaseSlot>>> {
        self.handler
            .try_acquire_lease(
                path,
                requested_access,
                requested_disposition,
                wants_directory,
            )
            .await
    }

    /// Phase C.5: tombstone a lease slot and remove it from the table.
    /// See [`ConnectionMessageHandler::take_lease_for_evict`] for the
    /// race-free contract.
    pub async fn take_lease_for_evict(&self, path: &str) -> crate::Result<Option<LeaseEviction>> {
        self.handler.take_lease_for_evict(path).await
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
        self.handler.sweep_idle_leases(older_than).await
    }

    /// Send an SMB2 compound chain through this connection's worker and
    /// receive each member's response.
    ///
    /// For each message in `msgs` (in order) this:
    /// 1. Sets `priority_mask` per the negotiated dialect — matches the
    ///    single-message [`crate::msg_handler::MessageHandler::sendo`]
    ///    path.
    /// 2. Calls [`ConnectionMessageHandler::process_sequence_outgoing`]
    ///    to allocate `message_id` + credit_charge / credit_request.
    ///    Same accounting as a single-shot send, so server-side credit
    ///    windows stay consistent.
    /// 3. After all members are prepared, hands the whole batch to
    ///    [`crate::connection::worker::WorkerImpl::send_compound`] for
    ///    the single TCP write.
    /// 4. Awaits each member's response separately via
    ///    `Worker::receive` — server splits the compound response into
    ///    N parts; our compound-aware incoming-side parser routes each
    ///    part by message_id, and these receives just consume the
    ///    pre-routed entries.
    /// 5. Calls `process_sequence_incoming` on each response to return
    ///    credits to the pool (mirroring the single-message path).
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
        mut msgs: Vec<OutgoingMessage>,
    ) -> crate::Result<Vec<IncomingMessage>> {
        // CancelRequest has its own bespoke path inside the single-message
        // `sendo` (it reuses an already-allocated message_id and skips
        // `process_sequence_outgoing`). Bundling it into a compound chain
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
        let priority_value = match self.handler.conn_info.get() {
            Some(neg_info) => match neg_info.negotiation.dialect_rev {
                Dialect::Smb0311 => 1,
                _ => 0,
            },
            None => 0,
        };
        for m in msgs.iter_mut() {
            m.message.header.flags = m.message.header.flags.with_priority_mask(priority_value);
            self.handler.process_sequence_outgoing(m).await?;
        }

        let worker = self
            .handler
            .worker
            .get()
            .ok_or(Error::InvalidState("Worker is uninitialized".into()))?;
        let send_results = worker.send_compound(msgs).await?;

        let mut responses = Vec::with_capacity(send_results.len());
        for r in send_results {
            let mut opts = ReceiveOptions::new();
            opts.msg_id = r.msg_id;
            opts.allow_async = true;
            let incoming = worker.receive(&opts).await?;
            self.handler.process_sequence_incoming(&incoming).await?;
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
    /// `slot.file_id` through `slot.proto.handler`. `false` when at
    /// least one live handle was present; that handle's
    /// `release_one` -> `CloseAndEvict` path will own the wire Close.
    pub needs_wire_close: bool,
}

/// This struct is the internal message handler for the SMB client.
pub(crate) struct ConnectionMessageHandler {
    client_guid: Guid,

    /// The number of extra credits to be requested by the client
    /// to enable larger requests/multiple outstanding requests.
    credits_backlog: u16,

    worker: OnceCell<Arc<WorkerImpl>>,

    /// Cancellation token for stopping notifications.
    stop_notifications: CancellationToken,

    /// Holds the sessions created by this connection.
    sessions: Mutex<HashMap<u64, Weak<ChannelMessageHandler>>>,

    // Negotiation-related state.
    conn_info: OnceCell<Arc<ConnectionInfo>>,

    /// Number of credits available to the client at the moment, for the next requests.
    curr_credits: Semaphore,
    /// The current message ID to be used in the next message.
    curr_msg_id: AtomicU64,
    /// The number of credits granted to the client by the server, including the being-used ones.
    /// This field is used ONLY when large MTU is enabled.
    credit_pool: AtomicU16,

    /// Broadcasts [`LeaseBreakEvent`] to any [`crate::Client::subscribe_lease_breaks`]
    /// consumers when the server sends a `LeaseBreakNotify`.
    lease_event_tx: tokio::sync::broadcast::Sender<LeaseBreakEvent>,

    /// Per-connection cache of server-granted leases (Phase C). Keyed by
    /// the file path relative to the share. Entries are inserted when a
    /// `CreateResponse` carries an `RqLs` grant and removed when the last
    /// holder drops *and* the slot is tombstoned. The actual `Close`
    /// packet is deferred until destruction.
    lease_table: Mutex<HashMap<String, Arc<LeaseSlot>>>,
}

impl ConnectionMessageHandler {
    fn new(client_guid: Guid, credits_backlog: Option<u16>) -> ConnectionMessageHandler {
        let (lease_event_tx, _) = tokio::sync::broadcast::channel(LEASE_BREAK_CHANNEL_CAPACITY);

        ConnectionMessageHandler {
            client_guid,
            worker: OnceCell::new(),
            conn_info: OnceCell::new(),
            credits_backlog: credits_backlog.unwrap_or(128),
            curr_credits: Semaphore::new(1),
            curr_msg_id: AtomicU64::new(0),
            credit_pool: AtomicU16::new(1),
            stop_notifications: Default::default(),
            sessions: Mutex::new(HashMap::with_capacity(1)),
            lease_event_tx,
            lease_table: Mutex::new(HashMap::new()),
        }
    }

    /// Install a [`LeaseSlot`] into the per-connection cache. Called from
    /// [`crate::Client::create_file`] after a successful Create that
    /// carried an `RqLs` grant. Overwrites any prior entry for the same
    /// path — a stale slot (e.g., a previous open that was closed by the
    /// other side) is logically equivalent to no cache hit.
    pub async fn insert_lease_slot(&self, slot: Arc<LeaseSlot>) -> crate::Result<()> {
        use std::sync::atomic::Ordering;
        let key = slot.path.clone();
        let mut table = self.lease_table.lock().await;
        let displaced = table.insert(key, slot);
        drop(table);
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
                let handler = prev.proto.handler.clone();
                // The spawned task captures the `handler` chain
                // (ResourceMessageHandle -> TreeMessageHandle ->
                // SessionMessageHandler) by Arc clone, but NOT this
                // ConnectionMessageHandler itself. If the Connection
                // races into Drop before the spawn runs, its
                // `worker.stop()` (in Connection::Drop) will complete
                // first and send_close_external will see a stopped
                // worker — at worst we lose this displaced FileId,
                // which the session-disconnect garbage-collects anyway.
                // The spawn does *not* extend the Connection's lifetime;
                // tying it to Connection would require Arc'ing the
                // handler chain back up, which we explicitly avoid.
                tokio::spawn(async move {
                    if let Err(e) =
                        crate::resource::ResourceHandle::send_close_external(file_id, &handler)
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

    /// Return the current number of cached lease slots. Primarily for
    /// observability and tests; not in any hot path.
    pub async fn lease_slot_count(&self) -> crate::Result<usize> {
        Ok(self.lease_table.lock().await.len())
    }

    /// Look up a cached lease slot by path. Returns `None` when there is
    /// no entry. Used by tests and the break-listener task; the cache-hit
    /// fast path in `Client::_create_file` goes through
    /// [`Self::try_acquire_lease`] instead so the bump is atomic with the
    /// lookup against concurrent evictions.
    pub async fn peek_lease_slot(&self, path: &str) -> crate::Result<Option<Arc<LeaseSlot>>> {
        Ok(self.lease_table.lock().await.get(path).cloned())
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
        let table = self.lease_table.lock().await;
        let Some(slot) = table.get(path).cloned() else {
            return Ok(None);
        };
        if slot.try_acquire_for_reuse(requested_access, requested_disposition, wants_directory) {
            Ok(Some(slot))
        } else {
            Ok(None)
        }
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
        use std::sync::atomic::Ordering;
        let mut table = self.lease_table.lock().await;
        let Some(slot) = table.remove(path) else {
            return Ok(None);
        };
        slot.tombstoned.store(true, Ordering::Release);
        let live = slot.refcount.load(Ordering::Acquire);
        let needs_wire_close = live == 0;
        tracing::debug!(
            path = %slot.path,
            live_handles = live,
            needs_wire_close,
            "Lease slot tombstoned and removed from table",
        );
        Ok(Some(LeaseEviction {
            slot,
            needs_wire_close,
        }))
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
        use std::sync::atomic::Ordering;
        // If `older_than` exceeds the elapsed time since this `Instant`
        // monotonic clock began (e.g. caller passed `Duration::MAX`),
        // there is nothing older than the cutoff — return immediately
        // instead of the previous bug where the fallback `now` made
        // every slot eligible for eviction.
        let Some(cutoff) = std::time::Instant::now().checked_sub(older_than) else {
            return Ok(Vec::new());
        };
        let mut table = self.lease_table.lock().await;

        // Two-phase: collect victims first to avoid mutating while iterating.
        let victims: Vec<String> = table
            .iter()
            .filter_map(|(k, slot)| match slot.last_used.read() {
                Ok(ts) if *ts <= cutoff => Some(k.clone()),
                _ => None,
            })
            .collect();

        let mut out = Vec::with_capacity(victims.len());
        for path in victims {
            if let Some(slot) = table.remove(&path) {
                slot.tombstoned.store(true, Ordering::Release);
                let live = slot.refcount.load(Ordering::Acquire);
                let needs_wire_close = live == 0;
                tracing::debug!(
                    path = %slot.path,
                    live_handles = live,
                    needs_wire_close,
                    "Idle lease slot tombstoned and removed",
                );
                out.push(LeaseEviction {
                    slot,
                    needs_wire_close,
                });
            }
        }
        Ok(out)
    }

    /// Spawn a long-running task that consumes the lease-break broadcast
    /// and tombstones matching slots in `lease_table`. Idempotent — only
    /// the first call subscribes; subsequent calls are no-ops. Async-only:
    /// the broadcast channel doesn't exist in sync builds.
    fn start_lease_break_listener(self: &Arc<Self>) {
        let mut rx = self.lease_event_tx.subscribe();
        let self_clone = self.clone();
        let stop = self.stop_notifications.clone();
        tokio::spawn(async move {
            loop {
                select! {
                    _ = stop.cancelled() => {
                        tracing::debug!("Lease break listener cancelled.");
                        break;
                    }
                    next = rx.recv() => {
                        match next {
                            Ok(event) => {
                                self_clone.apply_lease_break(&event).await;
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                                // Listener fell behind the producer. The
                                // ack for the missed events has already
                                // been sent by handle_lease_break; the
                                // only consequence here is that we may
                                // miss some tombstones. The next break
                                // for the same lease_key will recover us.
                                tracing::warn!(
                                    skipped,
                                    "Lease break listener lagged; some tombstones may have been missed",
                                );
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                                tracing::debug!(
                                    "Lease break channel closed; exiting listener.",
                                );
                                break;
                            }
                        }
                    }
                }
            }
            tracing::debug!("Lease break listener task stopped.");
        });
    }

    /// Apply a single [`LeaseBreakEvent`] to the connection's lease table.
    /// All slots whose `lease_key` matches the event are tombstoned,
    /// removed from the table, and their `granted_state` snapshot
    /// updated to the server's new state.
    ///
    /// The tombstone-store, granted_state update, and table removal all
    /// happen inside the `lease_table` lock so a concurrent
    /// `try_acquire_lease` either runs first (and gets a still-valid
    /// slot for which the wire I/O may racily fail — recoverable) or
    /// runs after (and finds the slot gone, falling back to a fresh
    /// wire Create). Without this fence the in-flight acquirer could
    /// observe `tombstoned == false`, bump refcount, and hand out a
    /// FileId the server has already revoked.
    async fn apply_lease_break(&self, event: &LeaseBreakEvent) {
        use std::sync::atomic::Ordering;
        let event_key = event.lease_key.as_u128();

        let matching: Vec<Arc<LeaseSlot>> = {
            let mut table = self.lease_table.lock().await;

            // Two-phase under the same lock: find victim paths first to
            // sidestep "mutate while iterating", then remove + apply
            // state transitions. Keeping both phases inside the lock
            // closes the race against `try_acquire_lease`.
            let victim_paths: Vec<String> = table
                .iter()
                .filter(|(_, slot)| slot.lease_key == event_key)
                .map(|(k, _)| k.clone())
                .collect();
            victim_paths
                .into_iter()
                .filter_map(|p| {
                    let slot = table.remove(&p)?;
                    slot.tombstoned.store(true, Ordering::Release);
                    if let Ok(mut state) = slot.granted_state.write() {
                        *state = event.new_state;
                    }
                    Some(slot)
                })
                .collect()
        };

        if matching.is_empty() {
            tracing::trace!(
                lease_key = ?event.lease_key,
                "Break event has no matching slot in this connection's cache",
            );
            return;
        }
        for slot in &matching {
            tracing::debug!(
                path = %slot.path,
                lease_key = %slot.lease_key,
                new_state = ?event.new_state,
                "Lease slot tombstoned + removed by server break",
            );
        }
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

    pub fn worker(&self) -> Option<&Arc<WorkerImpl>> {
        self.worker.get()
    }

    const SET_CREDIT_CHARGE_CMDS: &'static [Command] = &[
        Command::Read,
        Command::Write,
        Command::Ioctl,
        Command::QueryDirectory,
    ];

    const CREDIT_CALC_RATIO: u32 = 65536;
    const CREDITS_PER_MSG_NO_LARGE_MTU: u32 = 1;

    /// Stamp an [`OutgoingMessage`] with priority, credit charge, and a
    /// fresh message_id. Idempotent guard: callers should set
    /// [`OutgoingMessage::pre_processed`] to `true` after invoking, so
    /// downstream [`Self::sendo`] doesn't re-run the sequencing logic
    /// (which would consume an extra msg_id and an extra credit slot).
    ///
    /// Used by the session-setup driver, which needs the message's
    /// final on-wire `header.message_id` *before* the wire bytes are
    /// hashed into the SMB 3.1.1 preauth integrity chain.
    pub(crate) async fn prepare_outgoing(&self, msg: &mut OutgoingMessage) -> crate::Result<()> {
        let priority_value = match self.conn_info.get() {
            Some(neg_info) => match neg_info.negotiation.dialect_rev {
                Dialect::Smb0311 => 1,
                _ => 0,
            },
            None => 0,
        };
        msg.message.header.flags = msg.message.header.flags.with_priority_mask(priority_value);

        let is_cancel = msg.message.content.as_cancel().is_ok();
        if !is_cancel {
            self.process_sequence_outgoing(msg).await?;
        } else if msg.message.header.message_id == 0 {
            return Err(Error::InvalidState(
                "Cancel message must have a valid message ID".into(),
            ));
        }
        Ok(())
    }

    /// Hand a pre-prepared [`OutgoingMessage`] to the worker for
    /// transformation (sign/compress/encrypt) and transmission. Callers
    /// must have invoked [`Self::prepare_outgoing`] first (or set
    /// [`OutgoingMessage::pre_processed`] to `true` if they manually
    /// stamped the header). [`Self::sendo`] is the public, all-in-one
    /// entry point that combines both.
    pub(crate) async fn dispatch_outgoing(
        &self,
        msg: OutgoingMessage,
    ) -> crate::Result<SendMessageResult> {
        self.worker
            .get()
            .ok_or(Error::InvalidState("Worker is uninitialized".into()))?
            .send(msg)
            .await
    }

    async fn process_sequence_outgoing(&self, msg: &mut OutgoingMessage) -> crate::Result<()> {
        if let Some(neg) = self.conn_info.get() {
            if neg.negotiation.caps.large_mtu() {
                // Calculate the cost of the message (charge).
                let cost = if Self::SET_CREDIT_CHARGE_CMDS.contains(&msg.message.header.command) {
                    let send_payload_size = msg.message.content.req_payload_size();
                    let expected_response_payload_size = msg.message.content.expected_resp_size();
                    (1 + (max(send_payload_size, expected_response_payload_size) - 1)
                        / Self::CREDIT_CALC_RATIO)
                        .try_into()
                        .map_err(|_| Error::InvalidState("Credit charge overflow.".to_string()))?
                } else {
                    1
                };

                // First, acquire credits from the semaphore, and forget them.
                // They may be returned via the response message, at `process_sequence_incoming` below.
                self.curr_credits.acquire_many(cost as u32).await?.forget();

                let mut request = cost;
                // Request additional credits if required: if balance < extra, add to request the diff:
                let current_pool_size = self.credit_pool.load(Ordering::Relaxed);
                if current_pool_size < self.credits_backlog {
                    request += self.credits_backlog - current_pool_size;
                }

                msg.message.header.credit_charge = cost;
                msg.message.header.credit_request = request;
                msg.message.header.message_id =
                    self.curr_msg_id.fetch_add(cost as u64, Ordering::Relaxed);

                return Ok(());
            } else {
                debug_assert_eq!(msg.message.header.credit_request, 0);
                debug_assert_eq!(msg.message.header.credit_charge, 0);
            }
        }

        // Default case: logically waiting for single credit per message,
        // which will make the client wait for next response before allowing next request.
        self.curr_credits
            .acquire_many(Self::CREDITS_PER_MSG_NO_LARGE_MTU)
            .await?
            .forget();
        debug_assert!(
            self.curr_credits.available_permits() == 0,
            "Expected 0 credits available with no large mtu, got {}",
            self.curr_credits.available_permits()
        );

        msg.message.header.message_id = self
            .curr_msg_id
            .fetch_add(Self::CREDITS_PER_MSG_NO_LARGE_MTU as u64, Ordering::Relaxed);

        Ok(())
    }

    async fn process_sequence_incoming(&self, msg: &IncomingMessage) -> crate::Result<()> {
        if let Some(neg) = self.conn_info.get() {
            if neg.negotiation.caps.large_mtu() {
                let granted_credits = msg.message.header.credit_request;
                let charged_credits = msg.message.header.credit_charge;
                // Update the pool size - return how many EXTRA credits were granted.
                // also, handle the case where the server granted less credits than charged.
                if charged_credits > granted_credits {
                    self.credit_pool
                        .fetch_sub(charged_credits - granted_credits, Ordering::Relaxed);
                } else {
                    self.credit_pool
                        .fetch_add(granted_credits - charged_credits, Ordering::Relaxed);
                }

                // Return the credits to the pool.
                self.curr_credits.add_permits(granted_credits as usize);
                return Ok(());
            }
        }

        // Default case: return a single credit to the pool.
        self.curr_credits
            .add_permits(Self::CREDITS_PER_MSG_NO_LARGE_MTU as usize);
        debug_assert!(
            self.curr_credits.available_permits() <= Self::CREDITS_PER_MSG_NO_LARGE_MTU as usize,
            "Expected at most {} credits available with no large mtu, got {}",
            Self::CREDITS_PER_MSG_NO_LARGE_MTU,
            self.curr_credits.available_permits()
        );
        Ok(())
    }

    async fn start_notify(self: &Arc<Self>) -> crate::Result<()> {
        let worker = self
            .worker
            .get()
            .ok_or_else(|| Error::InvalidState("Worker is uninitialized.".to_string()))?;
        let worker = worker.clone();
        const CHANNEL_BUFFER_SIZE: usize = 10;
        let (tx, mut rx) = tokio::sync::mpsc::channel(CHANNEL_BUFFER_SIZE);
        worker.start_notify_channel(tx)?;
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
                        tracing::info!("Notification handler cancelled.");
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
                                    "Notification channel closed; exiting handler."
                                );
                                break;
                            }
                        }
                    }
                }
            }
            tracing::info!("Notification handler thread stopped.");
        });
        Ok(())
    }

    pub fn stop_notify(&self) {
        self.stop_notifications.cancel();
        tracing::info!("Notification handler stopped.");
    }
}

impl MessageHandler for ConnectionMessageHandler {
    async fn sendo(&self, mut msg: OutgoingMessage) -> crate::Result<SendMessageResult> {
        if !msg.pre_processed {
            self.prepare_outgoing(&mut msg).await?;
        }
        self.dispatch_outgoing(msg).await
    }

    async fn recvo(&self, options: ReceiveOptions<'_>) -> crate::Result<IncomingMessage> {
        let msg = self
            .worker
            .get()
            .ok_or_else(|| Error::InvalidState("Worker is uninitialized.".to_string()))?
            .receive(&options)
            .await?;

        // Command matching (if needed).
        if let Some(cmd) = options.cmd {
            if msg.message.header.command != cmd {
                return Err(Error::UnexpectedMessageCommand(msg.message.header.command));
            }
        }

        // Direction matching.
        if !msg.message.header.flags.server_to_redir() {
            return Err(Error::InvalidMessage(
                "Expected server-to-redir message".into(),
            ));
        }

        self.process_sequence_incoming(&msg).await?;

        // Expected status matching. Error if no match.
        if !options
            .status
            .iter()
            .any(|s| msg.message.header.status == *s as u32)
        {
            if let ResponseContent::Error(error_res) = msg.message.content {
                return Err(Error::ReceivedErrorMessage(
                    msg.message.header.status,
                    error_res,
                ));
            }
            return Err(Error::UnexpectedMessageStatus(msg.message.header.status));
        }

        Ok(msg)
    }

    async fn notify(&self, msg: IncomingMessage) -> crate::Result<()> {
        // Intercept LeaseBreakNotify *before* the session-id sanity check
        // because the server sends lease breaks with `session_id = 0` per
        // MS-SMB2 2.2.23.2 — the notification is keyed on lease_key, not
        // on any particular session. We must ack and fan out the event
        // promptly to stay within the 35-second break window.
        if matches!(msg.message.content, ResponseContent::LeaseBreakNotify(_)) {
            return self.handle_lease_break(msg).await;
        }

        if msg.message.header.session_id == 0 {
            tracing::warn!("Received notification without session ID: {msg:?}");
            return Ok(());
        }

        // Avoid holding the lock while notifying the session further.
        let session = {
            let sessions = self.sessions.lock().await;
            match sessions.get(&msg.message.header.session_id) {
                None => {
                    tracing::warn!(
                        "Received notification for unknown session ID {}: {msg:?}",
                        msg.message.header.session_id
                    );
                    return Ok(());
                }
                Some(weak_session) => weak_session.upgrade().ok_or_else(|| {
                    Error::InvalidState(format!(
                        "Session {} is no longer available",
                        msg.message.header.session_id
                    ))
                })?,
            }
        };

        session.notify(msg).await?;
        Ok(())
    }
}

impl ConnectionMessageHandler {
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
    async fn handle_lease_break(&self, msg: IncomingMessage) -> crate::Result<()> {
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

        // ACK FIRST (latency-critical path): NetApp-class clustered storage
        // doesn't always wait the spec-mandated 60s for the ack before
        // completing the open that caused the break — some tear down the
        // lease entry as soon as they dispatch the notify, returning
        // STATUS_NETWORK_NAME_DELETED for a "stale" ack. Send it before
        // the in-memory broadcast so the wire-time gap is minimal.
        if ack_required {
            self.send_lease_break_ack(&notify).await;
        }

        // FAN OUT EVENT (after ack so wire-time is minimized)
        //
        // Subscribers (Phase C lease_table, Phase D cifs handle_cache)
        // see this event regardless of whether the ack reached the server
        // — they invalidate their cached state because the lease is
        // logically broken from this moment on.
        {
            let event = LeaseBreakEvent {
                lease_key: notify.lease_key,
                current_state: notify.current_lease_state,
                new_state: notify.new_lease_state,
                epoch: notify.new_epoch,
                ack_required,
                received_at: Instant::now(),
            };
            // send returns Err only when there are zero active receivers,
            // which is normal during early bring-up; ignore it.
            let _ = self.lease_event_tx.send(event);
        }

        Ok(())
    }

    /// Construct and send a `LeaseBreakAck` for the given notification.
    ///
    /// Fire-and-forget (`has_response = false`): the server's
    /// `LeaseBreakResponse` is purely informational, and waiting for it
    /// would block the notify task. If it arrives later, the worker's
    /// response router drops it as unmatched.
    ///
    /// The ack is sent through any active session on this connection so
    /// it gets signed under the session key — sending unsigned via the
    /// bare connection handler triggers STATUS_NETWORK_NAME_DELETED on
    /// Samba-based servers. Lease identity is in the lease_key, not the
    /// session, so the choice of session doesn't matter.
    async fn send_lease_break_ack(&self, notify: &smb_msg::LeaseBreakNotify) {
        let session_handler = {
            let sessions = self.sessions.lock().await;
            sessions.values().find_map(|w| w.upgrade())
        };

        let Some(h) = session_handler else {
            tracing::warn!(
                lease_key = ?notify.lease_key,
                "Cannot send LeaseBreakAck: no active session on this connection",
            );
            return;
        };

        let ack = LeaseBreakAck {
            lease_key: notify.lease_key,
            lease_state: notify.new_lease_state,
        };
        let mut out = OutgoingMessage::new(RequestContent::LeaseBreakAck(ack));
        out.has_response = false;
        match h.sendo(out).await {
            Ok(r) => tracing::debug!(
                lease_key = ?notify.lease_key,
                msg_id = r.msg_id,
                "LeaseBreakAck sent (fire-and-forget)",
            ),
            Err(e) => tracing::warn!(
                lease_key = ?notify.lease_key,
                error = ?e,
                "LeaseBreakAck send failed — server will revoke the lease",
            ),
        }
    }
}

impl Drop for ConnectionMessageHandler {
    fn drop(&mut self) {
        self.stop_notify();

        let worker = match self.worker.take() {
            Some(worker) => worker,
            None => return,
        };

        tokio::task::spawn(async move {
            worker.stop().await.ok();
        });
    }
}
