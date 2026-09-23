use crate::error::TimedOutTask;
use crate::session::authenticator::Authenticator;
use crate::session::gss::GssState;

use super::*;

/// Distinguishes the two SessionSetup flavours that share the same GSS
/// drive loop but differ in their session-state bookkeeping. Used by
/// [`SessionSetup`] to inline-dispatch the small per-flavour deltas
/// (request flags, cleanup behaviour, post-success hooks) instead of
/// the previous trait + marker-struct dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SetupKind {
    /// Brand-new session — `init_session` creates a fresh
    /// [`SessionInfo`] on the first response, `on_session_key_exchanged`
    /// transitions it to `SettingUp` and installs the cipher pair,
    /// `on_setup_success` flips it to `Ready`, and `error_cleanup`
    /// invalidates the session before ending it.
    New,
    /// Multichannel bind — the [`SessionInfo`] is provided in the
    /// constructor (no `init_session` is ever needed), keys/cipher
    /// pair are already on the primary session so there's nothing to
    /// install, and `error_cleanup` ends the session **without**
    /// invalidating it (the primary session remains usable on its
    /// original channel).
    Bind,
}

/// Session setup processor.
///
/// Drives the GSS exchange (NTLM or Kerberos) plus the surrounding SMB
/// SessionSetup Request/Response chain. `G` is the GSS-API
/// implementation; production builds pin it to [`Authenticator`] via
/// [`Self::new`], tests inject a scripted mock via [`Self::with_gss`].
/// The `kind` field selects between the new-session and channel-
/// binding sub-flows — see [`SetupKind`].
pub(crate) struct SessionSetup<'a, G = Authenticator>
where
    G: GssState,
{
    last_setup_response: Option<SessionSetupResponse>,
    flags: Option<SessionFlags>,

    context: Option<ChannelContext>,

    result: Option<Arc<SessionAndChannel>>,

    authenticator: G,
    upstream: &'a ChannelUpstream,
    conn_info: &'a Arc<ConnectionInfo>,

    // A place to store the current setup channel, until it is set into the info.
    channel: Option<ChannelInfo>,
    new_channel_id: u32,

    kind: SetupKind,
}

impl<'a> SessionSetup<'a, Authenticator> {
    /// sspi-backed convenience over [`Self::with_gss`].
    pub async fn new(
        identity: sspi::AuthIdentity,
        upstream: &'a ChannelUpstream,
        conn_info: &'a Arc<ConnectionInfo>,
        new_channel_id: u32,
        primary_session: Option<&Arc<SessionAndChannel>>,
        kind: SetupKind,
    ) -> crate::Result<Self> {
        let authenticator = Authenticator::build(identity, conn_info)?;
        Self::with_gss(
            authenticator,
            upstream,
            conn_info,
            new_channel_id,
            primary_session,
            kind,
        )
        .await
    }
}

impl<'a, G> SessionSetup<'a, G>
where
    G: GssState,
{
    /// Accepts any [`GssState`] implementor — production goes through
    /// [`Self::new`]; tests inject a scripted mock GSS here.
    pub(crate) async fn with_gss(
        authenticator: G,
        upstream: &'a ChannelUpstream,
        conn_info: &'a Arc<ConnectionInfo>,
        new_channel_id: u32,
        primary_session: Option<&Arc<SessionAndChannel>>,
        kind: SetupKind,
    ) -> crate::Result<Self> {
        debug_assert!(
            (kind == SetupKind::Bind) == primary_session.is_some(),
            "SetupKind::Bind requires a primary_session; SetupKind::New must not be given one"
        );

        let mut result = Self {
            last_setup_response: None,
            flags: None,
            result: None,
            context: None,
            authenticator,
            upstream,
            conn_info,
            channel: None,
            new_channel_id,
            kind,
        };

        if let Some(primary_session) = primary_session {
            let session = primary_session.session.clone();

            let channel = (*primary_session
                .channel()
                .expect("A properly initialized session is expected in session setup."))
            .clone()
            .with_binding(true);

            result.set_session(session).await?;
            result
                .result
                .as_ref()
                .expect("Should have been set up by set_session()")
                .set_channel(channel);
        }

        Ok(result)
    }

    /// Drive the SessionSetup state machine to completion.
    ///
    /// Loops on the GSS exchange, sending intermediate / final
    /// SessionSetup Requests and consuming their responses, until the
    /// GSS layer reports authentication complete. On any error the
    /// matching [`SetupKind`]-specific cleanup runs before propagating
    /// the error out.
    pub(crate) async fn setup(&mut self) -> crate::Result<Arc<SessionAndChannel>> {
        tracing::debug!(
            "Setting up session for user {}.",
            self.authenticator.user_name().inner()
        );

        let result = self._setup_loop().await;
        match result {
            Ok(()) => Ok(self.result.take().ok_or_else(|| {
                Error::InvalidState("Session setup result is missing.".to_string())
            })?),
            Err(e) => {
                tracing::error!("Failed to setup session: {}", e);
                if let Err(ce) = self.error_cleanup().await {
                    tracing::error!("Failed to cleanup after setup error: {}", ce);
                }
                Err(e)
            }
        }
    }

    /// Inner GSS drive loop. Sends successive SessionSetup Requests
    /// (intermediate then final) until the authenticator reports
    /// completion, consuming each matching response in between.
    async fn _setup_loop(&mut self) -> crate::Result<()> {
        while !self.authenticator.is_authenticated()? {
            let next_buf = match self.last_setup_response.as_ref() {
                Some(response) => self.authenticator.next(&response.buffer).await?,
                None => self.authenticator.next(&[]).await?,
            };
            let is_auth_done = self.authenticator.is_authenticated()?;
            if is_auth_done && next_buf.is_empty() {
                break;
            }
            let is_final_request = is_auth_done || self.authenticator.session_key().is_ok();

            // Branches on is_auth_done; see send_final_setup_request for
            // the signing + preauth-hash contract.
            let request = self.send_setup_request(next_buf, is_final_request).await?;

            let response = self
                .receive_setup_response(request.msg_id, is_final_request)
                .await?;
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
                let session_info = self.init_session(session_id).await?;
                self.set_session(session_info).await?;
            }

            if is_final_request
                && !session_setup_response
                    .session_flags
                    .is_guest_or_null_session()
                && !message_form.signed_or_encrypted()
            {
                // Important: If we did NOT make sure the message's signature is valid,
                // we should do it now, as long as the session is not anonymous or guest.
                return Err(crate::error::SetupError::UnsignedFinalResponse.into());
            }
            // Intermediate response preauth ingest is now done inside
            // `WirePipeline::transform_incoming` (S4-T2); no driver-side
            // bookkeeping needed.

            self.flags = Some(session_setup_response.session_flags);
            self.last_setup_response = Some(session_setup_response);
            if is_final_request {
                break;
            }
        }

        self.flags.ok_or(Error::InvalidState(
            "Failed to complete authentication properly.".to_string(),
        ))?;

        // New sessions intentionally admit the final unsigned response before
        // a primary channel exists. Once the GSS exchange succeeds, derive
        // and install that channel from the finalized request transcript.
        if self
            .result
            .as_ref()
            .is_some_and(|session| session.channel().is_none())
        {
            self.make_channel().await?;
        }

        tracing::trace!("setup success, finishing up.");
        self.on_setup_success().await?;

        Ok(())
    }

    // -------------------------------------------------------------------
    // Inlined hooks (formerly `SessionSetupProperties` trait + 2 markers).
    // -------------------------------------------------------------------

    /// Build the SessionSetup Request for the current GSS round. The
    /// only per-flavour delta is whether the `binding` flag in
    /// `SessionSetupRequest.flags` is set — true for channel binds,
    /// false for new sessions.
    fn make_request(&self, buffer: Vec<u8>) -> CommandRequest {
        let has_dfs = self.conn_info.negotiation.caps.dfs();
        let mut msg = CommandRequest::new(
            SessionSetupRequest::new(
                buffer,
                SessionSecurityMode::new()
                    .with_signing_enabled(true)
                    .with_signing_required(
                        self.conn_info
                            .config
                            .signing_policy
                            .required(self.conn_info.negotiation.signing_required),
                    ),
                SetupRequestFlags::new(),
                NegotiateCapabilities::new().with_dfs(has_dfs),
            )
            .into(),
        )
        .with_return_raw_data(true)
        .with_protection(crate::command::Protection::None);

        if self.kind == SetupKind::Bind {
            // TODO: what about DFS in previous session?
            msg.message
                .content
                .as_mut_sessionsetup()
                .unwrap()
                .flags
                .set_binding(true);
        }

        msg
    }

    /// Create or fetch the [`SessionInfo`] for the just-assigned
    /// session_id. Only called on the first response and only for new
    /// sessions; bind flows must have been constructed with a
    /// `primary_session` (asserted in the constructor).
    async fn init_session(&self, session_id: u64) -> crate::Result<Arc<RwLock<SessionInfo>>> {
        match self.kind {
            SetupKind::New => {
                let session_info = SessionInfo::new(session_id);
                Ok(Arc::new(RwLock::new(session_info)))
            }
            SetupKind::Bind => panic!(
                "(Primary) Session should be provided in construction, rather than during setup!"
            ),
        }
    }

    /// Run after the GSS layer reports completion but before the
    /// SignatureKey-bearing channel is built. For new sessions this
    /// transitions the session state to `SettingUp` and installs the
    /// cipher pair; for binds it's a no-op (the primary session
    /// already carries its keys).
    async fn on_session_key_exchanged(&mut self) -> crate::Result<()> {
        if self.kind == SetupKind::New {
            // Only on new sessions we need to initialize the session state with the keys.
            tracing::trace!("Session keys exchanged. Setting up session state.");
            let session_key = self.session_key()?;
            let preauth_hash = self.preauth_hash_snapshot().await?;
            let conn_info = self.conn_info;
            self.result
                .as_ref()
                .ok_or_else(|| {
                    Error::InvalidState("Session state must be set before keys exchange".into())
                })?
                .session
                .write()
                .await
                .setup(&session_key, &preauth_hash, conn_info)?;
        }
        Ok(())
    }

    /// Run on the `Ok` exit of [`Self::_setup_loop`]. For new sessions
    /// this flips the session state to `Ready` with the negotiated
    /// flags; for binds it's a no-op.
    async fn on_setup_success(&mut self) -> crate::Result<()> {
        if self.kind == SetupKind::New {
            tracing::trace!("Session setup successful");
            let flags = self.flags.ok_or_else(|| {
                Error::InvalidState("flags must be set before on_setup_success".into())
            })?;
            let result = self.result.as_ref().ok_or_else(|| {
                Error::InvalidState("Session state must be set on success path".into())
            })?;
            let mut session = result.session.write().await;
            session.ready(flags, self.conn_info)?;
        }
        Ok(())
    }

    /// Run on the `Err` exit of [`Self::_setup_loop`]. New-session
    /// cleanup invalidates the session before notifying the generation_runtime;
    /// bind cleanup only notifies the generation_runtime (the primary session
    /// stays usable on its original channel).
    async fn error_cleanup(&mut self) -> crate::Result<()> {
        let session = match self.result.as_ref() {
            Some(s) => s,
            None => {
                match self.kind {
                    SetupKind::New => tracing::trace!("No session to cleanup in setup."),
                    SetupKind::Bind => tracing::warn!("No session to cleanup in binding."),
                }
                return Ok(());
            }
        };

        if self.kind == SetupKind::New {
            tracing::trace!("Invalidating session before cleanup.");
            session.session.write().await.invalidate();
        }

        self.upstream
            .generation_runtime()
            .ok_or_else(|| Error::InvalidState("Generation runtime not available!".to_string()))?
            .session_ended(session)
            .await
    }

    // -------------------------------------------------------------------
    // Common helpers (unchanged from the pre-S3c state, just no longer
    // generic over the marker trait).
    // -------------------------------------------------------------------

    async fn set_session(&mut self, session: Arc<RwLock<SessionInfo>>) -> crate::Result<()> {
        let session_id = session.read().await.id();
        let session = Arc::new(SessionAndChannel::new(session_id, session));

        let setup_handler = ChannelContext::make_for_setup(&session, self.upstream).await?;
        self.context = Some(setup_handler);

        self.upstream
            .generation_runtime()
            .ok_or_else(|| Error::InvalidState("Generation runtime not available!".to_string()))?
            .session_started(&session)
            .await?;

        self.result = Some(session);

        Ok(())
    }

    async fn receive_setup_response(
        &mut self,
        for_msg_id: u64,
        is_final_request: bool,
    ) -> crate::Result<CommandResponse> {
        let is_auth_done = self.authenticator.is_authenticated()?;

        let expected_status = if is_final_request {
            &[Status::Success]
        } else {
            &[Status::MoreProcessingRequired]
        };

        let roptions = ResponseOptions::new()
            .with_status(expected_status)
            .with_msg_id_filter(for_msg_id);

        let channel_set_up = match self.result.as_ref() {
            Some(result) => result.channel().is_some(),
            None => false,
        };
        let skip_security_validation = self.kind == SetupKind::New && !channel_set_up;
        let result = if let Some(context) = &self.context {
            tracing::trace!(
                "setup loop: receiving with channel context; skip_security_validation={skip_security_validation}"
            );
            context
                .recvo_internal(roptions, skip_security_validation)
                .await
        } else {
            assert!(skip_security_validation);
            tracing::trace!("setup loop: receiving with upstream context");
            self.upstream.await_response(roptions).await
        };

        // Upgrade generic transport / channel-layer errors to
        // setup-phase-specific SetupError variants so callers
        // (data-mover and friends) get a concrete remediation hint
        // instead of the raw "Operation timed out" / "Message not
        // signed or encrypted" strings.
        //
        // The `InvalidMessage` string match targets the rejection in
        // `ChannelContext::_verify_incoming`: on the final
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

    async fn send_setup_request(
        &mut self,
        buf: Vec<u8>,
        is_final_request: bool,
    ) -> crate::Result<CommandSubmission> {
        let request = self.make_request(buf);

        if is_final_request {
            self.send_final_setup_request(request).await
        } else {
            self.send_intermediate_setup_request(request).await
        }
    }

    /// Never signed, so wire bytes == plain bytes (`signature = 0`).
    /// The connection-level preauth hash is fed by
    /// `WirePipeline::transform_outgoing` (S4-T2); the driver is hands-off.
    async fn send_intermediate_setup_request(
        &mut self,
        request: CommandRequest,
    ) -> crate::Result<CommandSubmission> {
        if let Some(context) = self.context.as_ref() {
            tracing::trace!("setup loop: sending intermediate with channel context");
            context.submit(request).await
        } else {
            tracing::trace!("setup loop: sending intermediate with upstream context");
            self.upstream.submit(request).await
        }
    }

    /// Final SessionSetup Request (the one carrying the GSS authenticator
    /// that completes the exchange).
    ///
    /// A new session remains unsigned until the server accepts its final GSS
    /// token. A multichannel binding uses an established session and is signed
    /// with that session's setup-phase key.
    async fn send_final_setup_request(
        &mut self,
        mut request: CommandRequest,
    ) -> crate::Result<CommandSubmission> {
        self.upstream.prepare_outgoing(&mut request).await?;

        let session_id = self
            .result
            .as_ref()
            .ok_or_else(|| {
                Error::InvalidState("Session state must be set before the final request".into())
            })?
            .session_id;
        request.message.header.session_id = session_id;

        match self.kind {
            SetupKind::New => {
                request.security = Some(crate::command::Protection::None);
                tracing::trace!(
                    "setup loop: dispatching final unsigned SessionSetup msg_id={} session_id={:#x}",
                    request.message.header.message_id,
                    session_id
                );
                let result = self.upstream.dispatch_outgoing(request).await?;

                // The final response is signed. Its preauth hash excludes the
                // success response, so the primary signer can be derived once
                // the final request has been dispatched and before the wire
                // pipeline admits that response.
                self.make_channel().await?;
                Ok(result)
            }
            SetupKind::Bind => {
                request.security = Some(crate::command::Protection::SnapshotKdfSign {
                    session_key: self.session_key()?,
                });
                let request = request.into_signed();
                tracing::trace!(
                    "setup loop: dispatching final signed binding SessionSetup msg_id={} session_id={:#x}",
                    request.message.header.message_id,
                    session_id
                );
                let result = self.upstream.dispatch_outgoing(request).await?;
                self.make_channel().await?;
                Ok(result)
            }
        }
    }

    /// Builds the [`ChannelInfo`] for this session's primary channel
    /// (or the bound channel) using the GSS SessionKey and the
    /// wire pipeline's finalized preauth hash, then installs it into the
    /// shared `session_state` so the wire pipeline can find the signer
    /// for the upcoming final SessionSetup Response.
    async fn make_channel(&mut self) -> crate::Result<()> {
        self.on_session_key_exchanged().await?;
        tracing::trace!("Session keys are set.");

        // The preauth hash is owned by the wire pipeline (S4-T1); snapshot
        // its current finalized value to derive the channel SigningKey.
        let preauth_snapshot = self.preauth_hash_snapshot().await?;

        let channel_info = ChannelInfo::new(
            self.new_channel_id,
            &self.session_key()?,
            &preauth_snapshot,
            self.conn_info,
        )?;

        self.channel = Some(channel_info);

        let session_lock = self
            .result
            .as_ref()
            .ok_or_else(|| Error::InvalidState("Session setup result is missing.".to_string()))?;
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

    /// Snapshot the connection-level preauth hash from the runtime wire pipeline
    /// (S4-T1).
    async fn preauth_hash_snapshot(&self) -> crate::Result<Option<PreauthHashValue>> {
        self.upstream
            .generation_runtime()
            .ok_or_else(|| Error::InvalidState("Generation runtime not available!".to_string()))?
            .preauth_snapshot()
            .await
    }

    pub fn upstream(&self) -> &'a ChannelUpstream {
        self.upstream
    }

    pub fn conn_info(&self) -> &'a Arc<ConnectionInfo> {
        self.conn_info
    }
}
