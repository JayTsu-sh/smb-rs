use crate::error::TimedOutTask;
use crate::session::authenticator::Authenticator;
use crate::session::gss::GssState;

use super::*;

/// Session setup processor.
///
/// This is an internal structure.
/// It is assume that T is properly implemented and tested in-crate,
/// and so, the wide use of unwrap() is acceptable.
///
/// `G` is the GSS-API authentication mechanism. Production builds pin
/// it to [`Authenticator`] via [`Self::new`]; tests inject a mock
/// implementor of [`GssState`] via [`Self::with_gss`].
pub(crate) struct SessionSetup<'a, T, G = Authenticator>
where
    T: SessionSetupProperties,
    G: GssState,
{
    last_setup_response: Option<SessionSetupResponse>,
    flags: Option<SessionFlags>,

    handler: Option<ChannelMessageHandler>,

    result: Option<Arc<RwLock<SessionAndChannel>>>,

    authenticator: G,
    upstream: &'a ChannelUpstream,
    conn_info: &'a Arc<ConnectionInfo>,

    // A place to store the current setup channel, until it is set into the info.
    channel: Option<ChannelInfo>,
    new_channel_id: u32,

    _phantom: std::marker::PhantomData<T>,
}

#[maybe_async]
impl<'a, T> SessionSetup<'a, T, Authenticator>
where
    T: SessionSetupProperties,
{
    /// sspi-backed convenience over [`Self::with_gss`].
    pub async fn new(
        identity: sspi::AuthIdentity,
        upstream: &'a ChannelUpstream,
        conn_info: &'a Arc<ConnectionInfo>,
        new_channel_id: u32,
        primary_session: Option<&Arc<RwLock<SessionAndChannel>>>,
    ) -> crate::Result<Self> {
        let authenticator = Authenticator::build(identity, conn_info)?;
        Self::with_gss(
            authenticator,
            upstream,
            conn_info,
            new_channel_id,
            primary_session,
        )
        .await
    }
}

#[maybe_async]
impl<'a, T, G> SessionSetup<'a, T, G>
where
    T: SessionSetupProperties,
    G: GssState,
{
    /// Accepts any [`GssState`] implementor — production goes through
    /// [`Self::new`]; tests inject a scripted mock GSS here.
    pub(crate) async fn with_gss(
        authenticator: G,
        upstream: &'a ChannelUpstream,
        conn_info: &'a Arc<ConnectionInfo>,
        new_channel_id: u32,
        primary_session: Option<&Arc<RwLock<SessionAndChannel>>>,
    ) -> crate::Result<Self> {
        let mut result = Self {
            last_setup_response: None,
            flags: None,
            result: None,
            handler: None,
            authenticator,
            upstream,
            conn_info,
            channel: None,
            new_channel_id,
            _phantom: std::marker::PhantomData,
        };

        if let Some(primary_session) = primary_session {
            let primary_session = primary_session.read().await?;

            let session = primary_session.session.clone();

            let channel = primary_session
                .channel
                .as_ref()
                .expect("A properly initialized session is expected in session setup.")
                .clone();
            #[cfg(feature = "ksmbd-multichannel-compat")]
            let channel = channel.with_binding(true);

            result.set_session(session).await?;
            result
                .result
                .as_ref()
                .expect("Should have been set up by set_session()")
                .write()
                .await?
                .channel = Some(channel);
        }

        Ok(result)
    }

    /// Common session setup logic.
    ///
    /// This function sets up a session against a connection, and it is somewhat abstract.
    /// by calling impl functions, this function's behavior is modified to support both new sessions and binding to existing sessions.
    pub(crate) async fn setup(&mut self) -> crate::Result<Arc<RwLock<SessionAndChannel>>> {
        tracing::debug!(
            "Setting up session for user {} (@{}).",
            self.authenticator.user_name().account_name(),
            self.authenticator.user_name().domain_name().unwrap_or("")
        );

        let result = self._setup_loop().await;
        match result {
            Ok(()) => Ok(self.result.take().ok_or_else(|| {
                Error::InvalidState("Session setup result is missing.".to_string())
            })?),
            Err(e) => {
                tracing::error!("Failed to setup session: {}", e);
                if let Err(ce) = T::error_cleanup(self).await {
                    tracing::error!("Failed to cleanup after setup error: {}", ce);
                }
                Err(e)
            }
        }
    }

    /// *DO NOT OVERLOAD*
    ///
    /// Performs the session setup negotiation.
    ///
    /// This function loops until the authentication is complete, requesting GSS tokens
    /// and passing them to the server.
    async fn _setup_loop(&mut self) -> crate::Result<()> {
        // While there's a response to process, do so.
        while !self.authenticator.is_authenticated()? {
            let next_buf = match self.last_setup_response.as_ref() {
                Some(response) => self.authenticator.next(&response.buffer).await?,
                None => self.authenticator.next(&[]).await?,
            };
            let is_auth_done = self.authenticator.is_authenticated()?;

            // Branches on is_auth_done; see send_final_setup_request for
            // the signing + preauth-hash contract.
            let request = self.send_setup_request(next_buf).await?;

            let response = self.receive_setup_response(request.msg_id).await?;
            let message_form = response.form;
            let session_id = response.message.header.session_id;
            let session_setup_response = response.message.content.to_sessionsetup()?;

            // First iteration: construct a session state object.
            // TODO: currently, there's a bug which prevents authentication on first attempt
            // to complete successfully: since we need the session ID to construct the session state,
            // which is required for channel construction and signature validation,
            // the first request must arrive here, and then be validated.
            if self.result.is_none() {
                tracing::trace!("Creating session state with id {session_id}.");
                self.set_session(T::init_session(self, session_id).await?)
                    .await?;
            }

            if is_auth_done {
                // Important: If we did NOT make sure the message's signature is valid,
                // we should do it now, as long as the session is not anonymous or guest.
                if !session_setup_response
                    .session_flags
                    .is_guest_or_null_session()
                    && !message_form.signed_or_encrypted()
                {
                    return Err(crate::error::SetupError::UnsignedFinalResponse.into());
                }
            }
            // Intermediate response preauth ingest is now done inside
            // `Transformer::transform_incoming` (S4-T2); no driver-side
            // bookkeeping needed.

            self.flags = Some(session_setup_response.session_flags);
            self.last_setup_response = Some(session_setup_response)
        }

        self.flags.ok_or(Error::InvalidState(
            "Failed to complete authentication properly.".to_string(),
        ))?;

        tracing::trace!("setup success, finishing up.");
        T::on_setup_success(self).await?;

        Ok(())
    }

    async fn set_session(&mut self, session: Arc<RwLock<SessionInfo>>) -> crate::Result<()> {
        let session_id = session.read().await?.id();
        let result = SessionAndChannel::new(session_id, session);
        let session = Arc::new(RwLock::new(result));

        let setup_handler = ChannelMessageHandler::make_for_setup(&session, self.upstream).await?;
        self.handler = Some(setup_handler);

        self.upstream
            .worker()
            .ok_or_else(|| Error::InvalidState("Worker not available!".to_string()))?
            .session_started(&session)
            .await?;

        self.result = Some(session);

        Ok(())
    }

    async fn receive_setup_response(&mut self, for_msg_id: u64) -> crate::Result<IncomingMessage> {
        let is_auth_done = self.authenticator.is_authenticated()?;

        let expected_status = if is_auth_done {
            &[Status::Success]
        } else {
            &[Status::MoreProcessingRequired]
        };

        let roptions = ReceiveOptions::new()
            .with_status(expected_status)
            .with_msg_id_filter(for_msg_id);

        let channel_set_up = match self.result.as_ref() {
            Some(result) => result.read().await?.channel.is_some(),
            None => false,
        };
        let skip_security_validation = !is_auth_done && !channel_set_up;
        let result = if let Some(handler) = &self.handler {
            tracing::trace!(
                "setup loop: receiving with channel handler; skip_security_validation={skip_security_validation}"
            );
            handler
                .recvo_internal(roptions, skip_security_validation)
                .await
        } else {
            assert!(skip_security_validation);
            tracing::trace!("setup loop: receiving with upstream handler");
            self.upstream.handler.recvo(roptions).await
        };

        // Upgrade generic transport / channel-layer errors to
        // setup-phase-specific SetupError variants so callers
        // (data-mover and friends) get a concrete remediation hint
        // instead of the raw "Operation timed out" / "Message not
        // signed or encrypted" strings.
        //
        // The `InvalidMessage` string match targets the rejection in
        // `ChannelMessageHandler::_verify_incoming`: on the final
        // SessionSetup Response that arrived unsigned, the channel
        // verifies *before* `_setup_loop` reaches its own sanity
        // check, so we re-tag the error here. (Long-term S5/S7 will
        // replace string-matching with a typed error from the channel
        // layer.)
        result.map_err(|e| match e {
            Error::OperationTimeout(TimedOutTask::ReceiveNextMessage, elapsed) => {
                crate::error::SetupError::Timeout { elapsed }.into()
            }
            Error::InvalidMessage(msg)
                if is_auth_done
                    && msg.contains("not signed or encrypted")
                    && msg.contains("signing is required") =>
            {
                crate::error::SetupError::UnsignedFinalResponse.into()
            }
            other => other,
        })
    }

    async fn send_setup_request(&mut self, buf: Vec<u8>) -> crate::Result<SendMessageResult> {
        let request = T::make_request(self, buf).await?;
        let is_auth_done = self.authenticator.is_authenticated()?;

        if is_auth_done {
            self.send_final_setup_request(request).await
        } else {
            self.send_intermediate_setup_request(request).await
        }
    }

    /// Never signed, so wire bytes == plain bytes (`signature = 0`).
    /// The connection-level preauth hash is fed by
    /// `Transformer::transform_outgoing` (S4-T2); the driver is hands-off.
    async fn send_intermediate_setup_request(
        &mut self,
        request: OutgoingMessage,
    ) -> crate::Result<SendMessageResult> {
        if let Some(handler) = self.handler.as_ref() {
            tracing::trace!("setup loop: sending intermediate with channel handler");
            handler.sendo(request).await
        } else {
            tracing::trace!("setup loop: sending intermediate with upstream handler");
            self.upstream.sendo(request).await
        }
    }

    /// Final SessionSetup Request (the one carrying the GSS authenticator
    /// that completes the exchange).
    ///
    /// Per MS-SMB2 §3.3.5.5.3 the server **requires** this request to
    /// be signed on any non-anonymous SMB 3.x session (Windows DCs in
    /// particular drop it silently otherwise). The transformer owns
    /// the preauth-hash plumbing: we just attach the GSS-derived
    /// SessionKey to the outgoing message via `setup_phase_signing_key`,
    /// and `Transformer::transform_outgoing` ingests the plain bytes,
    /// derives a one-shot signer from the resulting finalized hash, and
    /// signs in place — all in one pass.
    async fn send_final_setup_request(
        &mut self,
        mut request: OutgoingMessage,
    ) -> crate::Result<SendMessageResult> {
        self.upstream
            .handler
            .prepare_outgoing(&mut request)
            .await?;

        let session_id = self
            .result
            .as_ref()
            .ok_or_else(|| {
                Error::InvalidState("Session state must be set before the final request".into())
            })?
            .read()
            .await?
            .session_id;
        request.message.header.session_id = session_id;

        request.security = Some(crate::msg_handler::Protection::SnapshotKdfSign {
            session_key: self.session_key()?,
        });
        let mut request = request.into_signed_pre_prepared();
        // Inhibit any future encryption attempt on this message (Sign
        // and Encrypt are mutually exclusive per the transformer's
        // own debug_assert).
        request.encrypt = false;

        tracing::trace!(
            "setup loop: dispatching final signed SessionSetup msg_id={} session_id={:#x}",
            request.message.header.message_id,
            session_id
        );
        let result = self.upstream.handler.dispatch_outgoing(request).await?;

        // Install the channel into session_state *after* dispatch so
        // the receive path can verify the matching signed Response —
        // the channel signer is derived from the same preauth hash the
        // transformer used a moment ago (it's stable now: the
        // SessionSetup Response with status=Success does NOT update
        // the hash per MS-SMB2 §3.1.4.2).
        self.make_channel().await?;

        Ok(result)
    }

    /// Initializes the channel that is resulted from the current session setup.
    /// - Calls `T::on_session_key_exchanged` before setting up the channel.
    /// - Sets `self.channel` to the instantiated channel.
    /// - Calls `T::on_channel_set_up` after setting up the channel.
    async fn make_channel(&mut self) -> crate::Result<()> {
        T::on_session_key_exchanged(self).await?;
        tracing::trace!("Session keys are set.");

        // The preauth hash is owned by the transformer (S4-T1); snapshot
        // its current finalized value to derive the channel SigningKey.
        let preauth_snapshot = self
            .upstream
            .worker()
            .ok_or_else(|| Error::InvalidState("Worker not available!".to_string()))?
            .transformer()
            .snapshot_preauth_finalized()
            .await?;

        let channel_info = ChannelInfo::new(
            self.new_channel_id,
            &self.session_key()?,
            &preauth_snapshot,
            self.conn_info,
        )?;

        self.channel = Some(channel_info);

        let mut session_lock = self
            .result
            .as_ref()
            .ok_or_else(|| Error::InvalidState("Session setup result is missing.".to_string()))?
            .write()
            .await?;
        session_lock.set_channel(
            self.channel
                .take()
                .ok_or_else(|| Error::InvalidState("Channel info is missing.".to_string()))?,
        );

        tracing::trace!("Channel for current setup has been initialized");
        Ok(())
    }

    fn session_key(&self) -> crate::Result<KeyToDerive> {
        self.authenticator.session_key()
    }

    /// Snapshot the connection-level preauth hash from the transformer
    /// (S4-T1). Used by `SmbSessionNew::on_session_key_exchanged` to
    /// derive the per-session keys.
    async fn preauth_hash_snapshot(&self) -> crate::Result<Option<PreauthHashValue>> {
        self.upstream
            .worker()
            .ok_or_else(|| Error::InvalidState("Worker not available!".to_string()))?
            .transformer()
            .snapshot_preauth_finalized()
            .await
    }

    pub fn upstream(&self) -> &'a ChannelUpstream {
        self.upstream
    }

    pub fn conn_info(&self) -> &'a Arc<ConnectionInfo> {
        self.conn_info
    }
}

#[maybe_async(AFIT)]
pub(crate) trait SessionSetupProperties {
    /// This function is called when setup error is encountered, to perform any necessary cleanup.
    async fn error_cleanup<T, G>(setup: &mut SessionSetup<'_, T, G>) -> crate::Result<()>
    where
        T: SessionSetupProperties,
        G: GssState;

    fn _make_default_request(buffer: Vec<u8>, dfs: bool) -> OutgoingMessage {
        OutgoingMessage::new(
            SessionSetupRequest::new(
                buffer,
                SessionSecurityMode::new().with_signing_enabled(true),
                SetupRequestFlags::new(),
                NegotiateCapabilities::new().with_dfs(dfs),
            )
            .into(),
        )
        .with_return_raw_data(true)
    }

    async fn make_request<T, G>(
        _setup: &mut SessionSetup<'_, T, G>,
        buffer: Vec<u8>,
    ) -> crate::Result<OutgoingMessage>
    where
        T: SessionSetupProperties,
        G: GssState,
    {
        let has_dfs = _setup.conn_info().negotiation.caps.dfs();
        Ok(Self::_make_default_request(buffer, has_dfs))
    }

    async fn init_session<T, G>(
        _setup: &'_ SessionSetup<'_, T, G>,
        _session_id: u64,
    ) -> crate::Result<Arc<RwLock<SessionInfo>>>
    where
        T: SessionSetupProperties,
        G: GssState;

    async fn on_session_key_exchanged<T, G>(
        _setup: &mut SessionSetup<'_, T, G>,
    ) -> crate::Result<()>
    where
        T: SessionSetupProperties,
        G: GssState,
    {
        // Default implementation does nothing.
        Ok(())
    }

    async fn on_setup_success<T, G>(_setup: &mut SessionSetup<'_, T, G>) -> crate::Result<()>
    where
        T: SessionSetupProperties,
        G: GssState;
}

pub(crate) struct SmbSessionBind;

#[maybe_async(AFIT)]
impl SessionSetupProperties for SmbSessionBind {
    async fn make_request<T, G>(
        _setup: &mut SessionSetup<'_, T, G>,
        buffer: Vec<u8>,
    ) -> crate::Result<OutgoingMessage>
    where
        T: SessionSetupProperties,
        G: GssState,
    {
        // TODO: what about DFS in previous session?
        let has_dfs = _setup.conn_info().negotiation.caps.dfs();
        let mut request = Self::_make_default_request(buffer, has_dfs);
        request
            .message
            .content
            .as_mut_sessionsetup()
            .unwrap()
            .flags
            .set_binding(true);
        Ok(request)
    }

    async fn error_cleanup<T, G>(setup: &mut SessionSetup<'_, T, G>) -> crate::Result<()>
    where
        T: SessionSetupProperties,
        G: GssState,
    {
        if setup.result.is_none() {
            tracing::warn!("No session to cleanup in binding.");
            return Ok(());
        }
        setup
            .upstream
            .worker()
            .ok_or_else(|| Error::InvalidState("Worker not available!".to_string()))?
            .session_ended(setup.result.as_ref().unwrap())
            .await
    }

    async fn init_session<T, G>(
        _setup: &SessionSetup<'_, T, G>,
        _session_id: u64,
    ) -> crate::Result<Arc<RwLock<SessionInfo>>>
    where
        T: SessionSetupProperties,
        G: GssState,
    {
        panic!("(Primary) Session should be provided in construction, rather than during setup!");
    }

    async fn on_setup_success<T, G>(_setup: &mut SessionSetup<'_, T, G>) -> crate::Result<()>
    where
        T: SessionSetupProperties,
        G: GssState,
    {
        Ok(())
    }
}

pub(crate) struct SmbSessionNew;

#[maybe_async(AFIT)]
impl SessionSetupProperties for SmbSessionNew {
    async fn error_cleanup<T, G>(setup: &mut SessionSetup<'_, T, G>) -> crate::Result<()>
    where
        T: SessionSetupProperties,
        G: GssState,
    {
        if setup.result.is_none() {
            tracing::trace!("No session to cleanup in setup.");
            return Ok(());
        }

        tracing::trace!("Invalidating session before cleanup.");
        let session = setup.result.as_ref().unwrap();
        {
            let session_lock = session.read().await?;
            session_lock.session.write().await?.invalidate();
        }

        setup
            .upstream
            .worker()
            .ok_or_else(|| Error::InvalidState("Worker not available!".to_string()))?
            .session_ended(setup.result.as_ref().unwrap())
            .await
    }

    async fn on_session_key_exchanged<T, G>(
        setup: &mut SessionSetup<'_, T, G>,
    ) -> crate::Result<()>
    where
        T: SessionSetupProperties,
        G: GssState,
    {
        // Only on new sessions we need to initialize the session state with the keys.
        tracing::trace!("Session keys exchanged. Setting up session state.");
        setup
            .result
            .as_ref()
            .unwrap()
            .read()
            .await?
            .session
            .write()
            .await?
            .setup(
                &setup.session_key()?,
                &setup.preauth_hash_snapshot().await?,
                setup.conn_info,
            )
    }

    async fn on_setup_success<T, G>(setup: &mut SessionSetup<'_, T, G>) -> crate::Result<()>
    where
        T: SessionSetupProperties,
        G: GssState,
    {
        tracing::trace!("Session setup successful");
        let result = setup.result.as_ref().unwrap().read().await?;
        let mut session = result.session.write().await?;
        session.ready(setup.flags.unwrap(), setup.conn_info)
    }

    async fn init_session<T, G>(
        _setup: &SessionSetup<'_, T, G>,
        session_id: u64,
    ) -> crate::Result<Arc<RwLock<SessionInfo>>>
    where
        T: SessionSetupProperties,
        G: GssState,
    {
        let session_info = SessionInfo::new(session_id);
        let session_info = Arc::new(RwLock::new(session_info));

        Ok(session_info)
    }
}
