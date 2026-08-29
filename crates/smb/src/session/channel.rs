use crate::command::Protection;

use super::*;

pub(crate) type ChannelUpstream = Arc<ConnectionCore>;

pub struct Channel {
    channel_id: u32,

    pub(crate) context: Arc<ChannelContext>,
    pub(crate) conn_info: Arc<ConnectionInfo>,
}

impl Channel {
    pub(crate) async fn new(
        upstream: &ChannelUpstream,
        conn_info: &Arc<ConnectionInfo>,
        setup_result: &Arc<SessionAndChannel>,
    ) -> crate::Result<Self> {
        let (session_id, channel_id) = {
            let session = setup_result.session.read().await;
            let channel = setup_result
                .channel()
                .ok_or_else(|| Error::InvalidState("Channel not set in setup result".into()))?;
            (session.id(), channel.id())
        };
        if setup_result.object().is_err() {
            let token = upstream
                .create_object(
                    upstream.connection_object()?,
                    crate::runtime::ObjectKind::Session,
                )
                .await?;
            setup_result.set_object(token)?;
        }
        let context = ChannelContext::new(session_id, channel_id, upstream, setup_result);
        Ok(Self {
            channel_id,
            context,
            conn_info: conn_info.clone(),
        })
    }

    /// Returns the Session ID of this session.
    ///
    /// This ID is the same as the SMB's session id,
    /// so it is unique-per-connection, and may be seen on the wire as well.
    #[inline]
    pub fn session_id(&self) -> u64 {
        self.context.session_id()
    }

    #[inline]
    pub fn channel_id(&self) -> u32 {
        self.channel_id
    }

    /// Returns `true` when the session permits unsigned messages.
    ///
    /// Mirrors the check used inside [`ChannelContext::submit`]: a
    /// session enforces signing iff `allow_unsigned()` is `false` after
    /// it reaches `is_ready()`. Exposed publicly for callers that build
    /// SMB2 compound chains (P2.b) and need to set the `signed` flag on
    /// each chained header before going through the worker directly.
    pub async fn allow_unsigned(&self) -> crate::Result<bool> {
        let session = self.context.session_state.session.read().await;
        session.allow_unsigned()
    }

    /// Returns `true` when the session requires every outgoing request to be
    /// encrypted (either the session flags carry `encrypt_data` or the
    /// connection config forces it).
    ///
    /// Mirrors the check used inside [`ChannelContext::submit`]: when
    /// `should_encrypt()` is `true`, the single-message path sets
    /// `msg.encrypt = true` instead of merely signing. Callers that build
    /// SMB2 compound chains directly must use this to select whole-chain
    /// encryption instead of per-member signing.
    ///
    /// Errors with `InvalidState` when the underlying session has not
    /// reached the Ready state, matching `SessionInfo::should_encrypt`.
    pub async fn should_encrypt(&self) -> crate::Result<bool> {
        let session = self.context.session_state.session.read().await;
        session.should_encrypt()
    }
}

/// Message context a specific channel.
///
/// This only makes sense, since sessions are not actually able to send data
/// as "themselves", but rather, through a channel.
pub struct ChannelContext {
    session_id: u64,
    channel_id: u32,
    upstream: ChannelUpstream,

    session_state: Arc<SessionAndChannel>,
}

impl ChannelContext {
    pub(super) fn upstream(&self) -> ChannelUpstream {
        self.upstream.clone()
    }

    async fn prepare(&self, mut msg: CommandRequest) -> crate::Result<CommandRequest> {
        if msg.security.is_none() {
            let session = self.session_state.session.read().await;
            if session.is_invalid() {
                return Err(Error::InvalidState("Session is invalid".to_string()));
            }
            if session.is_ready() || session.is_setting_up() {
                msg.security = Some(if session.is_ready() && session.should_encrypt()? {
                    Protection::Encrypt
                } else if !session.allow_unsigned()? {
                    Protection::SignWithChannel
                } else {
                    Protection::None
                });
            } else {
                msg.security = Some(Protection::None);
            }
        }
        if matches!(
            msg.security,
            Some(Protection::SignWithChannel) | Some(Protection::SnapshotKdfSign { .. })
        ) {
            msg.message.header.flags.set_signed(true);
        }
        msg.message.header.session_id = self.session_id;
        Ok(msg)
    }

    pub(crate) async fn execute(
        &self,
        msg: CommandRequest,
        options: ResponseOptions<'_>,
    ) -> crate::Result<(CommandSubmission, CommandResponse)> {
        self.execute_for(msg, options, self.session_state.object()?)
            .await
    }

    pub(crate) async fn execute_for(
        &self,
        msg: CommandRequest,
        options: ResponseOptions<'_>,
        dependency: crate::runtime::ObjectToken,
    ) -> crate::Result<(CommandSubmission, CommandResponse)> {
        self.execute_for_with_replay(
            msg,
            options,
            dependency,
            crate::runtime::ReplayPolicy::NeverReplay,
        )
        .await
    }

    pub(crate) async fn execute_for_with_replay(
        &self,
        msg: CommandRequest,
        options: ResponseOptions<'_>,
        dependency: crate::runtime::ObjectToken,
        replay: crate::runtime::ReplayPolicy,
    ) -> crate::Result<(CommandSubmission, CommandResponse)> {
        let result = match self
            .upstream
            .execute_for_with_replay(self.prepare(msg).await?, options, dependency, replay)
            .await
        {
            Ok(result) => result,
            Err(error @ Error::SignatureVerificationFailed) => {
                if let Err(recovery_error) = self.upstream.recover_session(self.session_id).await {
                    tracing::warn!(?recovery_error, "session integrity recovery failed");
                }
                return Err(error);
            }
            Err(error) => return Err(error),
        };
        self._verify_incoming(&result.1).await?;
        Ok(result)
    }

    pub(crate) async fn create_child_object(
        &self,
        kind: crate::runtime::ObjectKind,
    ) -> crate::Result<crate::runtime::ObjectToken> {
        self.upstream
            .create_object(self.session_state.object()?, kind)
            .await
    }

    pub(crate) async fn create_object(
        &self,
        parent: crate::runtime::ObjectToken,
        kind: crate::runtime::ObjectKind,
    ) -> crate::Result<crate::runtime::ObjectToken> {
        self.upstream.create_object(parent, kind).await
    }

    pub(crate) async fn submit_for(
        &self,
        message: CommandRequest,
        dependency: crate::runtime::ObjectToken,
    ) -> crate::Result<CommandSubmission> {
        self.upstream
            .submit_for(self.prepare(message).await?, dependency)
            .await
    }

    fn new(
        session_id: u64,
        channel_id: u32,
        upstream: &ChannelUpstream,
        setup_result: &Arc<SessionAndChannel>,
    ) -> Arc<ChannelContext> {
        Arc::new(ChannelContext {
            session_id,
            channel_id,
            upstream: upstream.clone(),
            session_state: setup_result.clone(),
        })
    }

    pub(crate) async fn make_for_setup(
        setup_result: &Arc<SessionAndChannel>,
        upstream: &ChannelUpstream,
    ) -> crate::Result<Self> {
        let session_id = setup_result.session.read().await.id();
        Ok(Self {
            session_id,
            channel_id: u32::MAX,
            upstream: upstream.clone(),
            session_state: setup_result.clone(),
        })
    }

    /// (Internal)
    ///
    /// Verifies an [`CommandResponse`] for the current session.
    /// This is trustworthy only since we trust the [`WirePipeline`][crate::runtime::wire::WirePipeline] implementation
    /// to provide the correct IDs and verify signatures and encryption.
    ///
    /// # Arguments
    /// * `incoming` - The incoming message to verify.
    /// # Returns
    /// An empty [`crate::Result`] if the message is valid, or an error if the message is invalid.
    async fn _verify_incoming(&self, incoming: &CommandResponse) -> crate::Result<()> {
        // allow unsigned messages only if the session is anonymous or guest.
        // this is enforced against configuration when setting up the session.
        let (unsigned_allowed, encryption_required) = {
            let session = self.session_state.session.read().await;
            let encryption_required = session.is_ready() && session.should_encrypt()?;
            (session.allow_unsigned()?, encryption_required)
        };

        // Make sure that it's our session.
        if incoming.message.header.session_id == 0 {
            return Err(Error::InvalidMessage(
                "No session ID in message that got to session!".to_string(),
            ));
        }
        if incoming.message.header.session_id != self.session_id {
            return Err(Error::InvalidMessage(
                "Message not for this session!".to_string(),
            ));
        }
        // Make sure encryption is used when required.
        if !incoming.form.encrypted && encryption_required {
            return Err(Error::InvalidMessage(
                "Message not encrypted, but encryption is required for the session!".to_string(),
            ));
        }
        // and signed, unless allowed not to.
        if !incoming.form.signed_or_encrypted() && !unsigned_allowed {
            return Err(Error::InvalidMessage(
                "Message not signed or encrypted, but signing is required for the session!"
                    .to_string(),
            ));
        }

        Ok(())
    }

    /// **Insecure! Insecure! Insecure!**
    ///
    /// Same as [`ChannelContext::await_response`], but possible skips security validation.
    /// # Arguments
    /// * `options` - The options for receiving the message.
    /// * `skip_security_validation` - Whether to skip security validation of the incoming message.
    ///   This shall only be used when authentication is still being set up.
    /// # Returns
    /// An [`CommandResponse`] if the message is valid, or an error if the message is invalid.
    pub(crate) async fn recvo_internal(
        &self,
        options: ResponseOptions<'_>,
        skip_security_validation: bool,
    ) -> crate::Result<CommandResponse> {
        let incoming = self.upstream.await_response(options).await?;

        if !skip_security_validation {
            self._verify_incoming(&incoming).await?;
        } else {
            // Note: this is performed here for extra security,
            // while we could have just checked the session state, let's require
            // the caller to explicitly state that it is okay to skip security validation.
            let session = self.session_state.session.read().await;
            assert!(
                session.is_initial(),
                "Incorrect internal state: security checks are never skipped, unless the session is still being set up!"
            );
        }

        Ok(incoming)
    }

    /// (Internal)
    ///
    /// Assures the sessions may not be used anymore.
    async fn _invalidate(&self) -> crate::Result<()> {
        self.upstream
            .worker()
            .ok_or_else(|| Error::InvalidState("Worker not available!".to_string()))?
            .session_ended(&self.session_state)
            .await
    }

    pub fn session_id(&self) -> u64 {
        self.session_id
    }

    pub fn channel_id(&self) -> u32 {
        self.channel_id
    }

    pub fn session_state(&self) -> &Arc<SessionAndChannel> {
        &self.session_state
    }
}

impl ChannelContext {
    pub(crate) async fn submit(&self, msg: CommandRequest) -> crate::Result<CommandSubmission> {
        self.upstream.submit(self.prepare(msg).await?).await
    }

    pub(crate) async fn notify(&self, msg: CommandResponse) -> crate::Result<()> {
        self._verify_incoming(&msg).await?;

        match &msg.message.content {
            ResponseContent::ServerToClientNotification(s2c_notification) => {
                match s2c_notification.notification {
                    // TODO: Move this to primary session
                    Notification::NotifySessionClosed(_) => self._invalidate().await,
                }
            }
            _ => {
                tracing::warn!(
                    "Received unexpected message in session context: {:?}",
                    msg.message.content
                );
                Ok(())
            }
        }
    }
}
