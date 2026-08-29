//! Session logic module.
//!
//! This module contains the session setup logic, as well as the session message handling,
//! including encryption and signing of messages.

use crate::UncPath;
use crate::connection::connection_info::ConnectionInfo;
use crate::connection::preauth_hash::PreauthHashValue;
use crate::{
    Error,
    connection::ConnectionCore,
    crypto::KeyToDerive,
    command::{CommandResponse, CommandRequest, ResponseOptions, CommandSubmission},
    tree::Tree,
};
use arc_swap::ArcSwapOption;
use smb_msg::{Notification, RequestContent, ResponseContent, Status, session_setup::*};
use std::collections::HashMap;
use std::ops::Deref;
use std::sync::{Arc, OnceLock};
use std::sync::atomic::{AtomicBool, AtomicU32};
use tokio::sync::RwLock;

mod authenticator;
mod channel;
mod credential;
mod encryptor_decryptor;
pub(crate) mod gss;
mod setup;
mod recovery_attempt;
mod signer;
#[cfg(feature = "kerberos")]
mod sspi_network_client;
mod state;

pub use channel::*;
pub use encryptor_decryptor::{MessageDecryptor, MessageEncryptor};

pub use signer::MessageSigner;
pub use state::{ChannelInfo, SessionInfo};

use setup::*;
use credential::{SharedCredentialProvider, StaticCredentialProvider};
use recovery_attempt::run_bounded_attempt;

/// Channel id assigned to a session's primary channel.
///
/// Multichannel-bound alternate channels are allocated by
/// `channel_counter` starting from `PRIMARY_CHANNEL_ID + 1`. Kept
/// `pub(crate)` so [`Session::create`] / [`Session::create_with_gss`] /
/// [`Session::bind`] all agree on the same value without duplicating it
/// as a local constant in each call site.
pub(crate) const PRIMARY_CHANNEL_ID: u32 = 0;

pub struct Session {
    primary_channel: Channel,
    alt_channels: RwLock<HashMap<u32, Channel>>,
    channel_counter: AtomicU32,

    // Message context for this session.
    session_context: Arc<SessionContext>,
}

impl Session {
    /// Sets up a new session on the specified connection.
    /// This method is crate-internal; Use [`Connection::authenticate`] to create a new session.
    ///
    /// [Session::bind] may be used instead, to bind an existing session to a new connection.
    pub(crate) async fn create(
        identity: sspi::AuthIdentity,
        upstream: &ChannelUpstream,
        conn_info: &Arc<ConnectionInfo>,
    ) -> crate::Result<Session> {
        let credential_provider: SharedCredentialProvider =
            Arc::new(StaticCredentialProvider::new(identity));
        let setup_result = SessionSetup::new(
            credential_provider.identity().await?,
            upstream,
            conn_info,
            PRIMARY_CHANNEL_ID,
            None,
            SetupKind::New,
        )
        .await?;

        Self::_finish_create(setup_result, Some(credential_provider)).await
    }

    /// Test-only: drive `SessionSetup` with a caller-supplied
    /// [`GssState`][crate::session::gss::GssState] implementor instead
    /// of an sspi-backed `Authenticator`. See
    /// [`Connection::authenticate_with_gss`] for the rationale.
    #[cfg(feature = "test-support")]
    pub(crate) async fn create_with_gss<G>(
        gss: G,
        upstream: &ChannelUpstream,
        conn_info: &Arc<ConnectionInfo>,
    ) -> crate::Result<Session>
    where
        G: crate::session::gss::GssState + 'static,
    {
        let setup_result = SessionSetup::with_gss(
            gss,
            upstream,
            conn_info,
            PRIMARY_CHANNEL_ID,
            None,
            SetupKind::New,
        )
        .await?;

        Self::_finish_create(setup_result, None).await
    }

    async fn _finish_create<G>(
        setup_result: SessionSetup<'_, G>,
        credential_provider: Option<SharedCredentialProvider>,
    ) -> crate::Result<Session>
    where
        G: crate::session::gss::GssState,
    {
        let primary_channel = Self::_common_setup(setup_result).await?;

        let context = Arc::new(SessionContext::new(
            primary_channel.context.clone(),
            primary_channel.conn_info.clone(),
            credential_provider,
        ));

        Ok(Session {
            session_context: context,
            primary_channel,
            alt_channels: Default::default(),
            channel_counter: AtomicU32::new(PRIMARY_CHANNEL_ID + 1),
        })
    }

    /// Whether this session owns a capability that can supply fresh
    /// authentication material after a Connection generation change.
    pub fn supports_reauthentication(&self) -> bool {
        self.session_context.credential_provider.is_some()
    }

    pub fn session_id(&self) -> u64 {
        self.session_context.session_id()
    }

    pub async fn allow_unsigned(&self) -> crate::Result<bool> {
        let primary = self.session_context.primary_channel();
        primary.session_state().session.read().await.allow_unsigned()
    }

    pub async fn should_encrypt(&self) -> crate::Result<bool> {
        let primary = self.session_context.primary_channel();
        primary.session_state().session.read().await.should_encrypt()
    }

    pub(crate) fn recovery_context(&self) -> Arc<SessionContext> {
        self.session_context.clone()
    }

    /// Binds an existing session to a new connection.
    ///
    /// Returns the channel ID (in the scope of the current session) of the newly created channel.
    pub(crate) async fn bind(
        &self,
        identity: sspi::AuthIdentity,
        context: &Arc<ConnectionCore>,
        conn_info: &Arc<ConnectionInfo>,
    ) -> crate::Result<u32> {
        if self.conn_info.negotiation.dialect_rev != conn_info.negotiation.dialect_rev {
            return Err(Error::InvalidState(
                "Cannot bind session to connection with different dialect.".to_string(),
            ));
        }
        if self.conn_info.client_guid != conn_info.client_guid {
            return Err(Error::InvalidState(
                "Cannot bind session to connection with different client GUID.".to_string(),
            ));
        }

        {
            let session = self.context.session_state().session.read().await;
            if !session.is_ready() {
                return Err(Error::InvalidState(
                    "Cannot bind session that is not ready.".to_string(),
                ));
            }
            if session.allow_unsigned()? {
                return Err(Error::InvalidState(
                    "Cannot bind session that allows unsigned messages.".to_string(),
                ));
            }
        }

        let new_channel_id = self
            .channel_counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let setup_result = SessionSetup::new(
            identity,
            context,
            conn_info,
            new_channel_id,
            Some(self.context.session_state()),
            SetupKind::Bind,
        )
        .await?;

        let channel = Self::_common_setup(setup_result).await?;
        let channel_context = channel.context.clone();

        self.alt_channels
            .write()
            .await
            .insert(new_channel_id, channel);

        self.session_context
            .channel_contexts
            .write()
            .await
            .insert(new_channel_id, channel_context);

        Ok(new_channel_id)
    }

    async fn _common_setup<G>(mut session_setup: SessionSetup<'_, G>) -> crate::Result<Channel>
    where
        G: crate::session::gss::GssState,
    {
        let setup_result = session_setup.setup().await?;

        {
            let session = setup_result.session.read().await;
            tracing::debug!("Session setup complete.");
            if session.allow_unsigned()? {
                tracing::debug!("Session is guest/anonymous.");
            }
        };

        let channel = Channel::new(
            session_setup.upstream(),
            session_setup.conn_info(),
            &setup_result,
        )
        .await?;

        Ok(channel)
    }

    /// Connects to the specified tree on the current session.
    /// ## Arguments
    /// * `name` - The name of the tree to connect to.
    #[tracing::instrument(level = "debug", skip_all, fields(session_id = self.session_id(), share = %name))]
    pub async fn tree_connect(&self, name: &UncPath) -> crate::Result<Tree> {
        let name = name.clone().with_no_path().to_string();
        let conn_info = self.session_context.conn_info();
        let tree = Tree::connect(&name, &self.session_context, &conn_info).await?;
        Ok(tree)
    }

    /// Logs off the session.
    ///
    /// Any resources held by the session will be released,
    /// and any [`Tree`] objects and their resources will be unusable.
    #[tracing::instrument(level = "debug", skip_all, fields(session_id = self.session_id()))]
    pub async fn logoff(&self) -> crate::Result<()> {
        self.session_context.logoff().await
    }
}

impl Deref for Session {
    type Target = Channel;

    fn deref(&self) -> &Self::Target {
        &self.primary_channel
    }
}

/// Per-session state shared by the runtime wire pipeline (one entry per
/// `session_id` in [`crate::runtime::wire::WirePipeline::sessions`]).
///
/// # Lock layout (post-S7-T3 C2)
///
/// The outer `Arc<RwLock<SessionAndChannel>>` that the pre-T3 codebase
/// wrapped this struct in is gone — every mutator now operates through
/// `&self`:
///
/// - `session: Arc<RwLock<SessionInfo>>` still uses an inner `RwLock`
///   because the session state machine (`Initial` → `SettingUp` →
///   `Ready` / `Invalid`) is mutated during setup and teardown.
///   Mutations are bounded (≤2 sites) and reads are hot, so `RwLock` is
///   the right primitive there.
/// - `channel: ArcSwapOption<ChannelInfo>` uses [`arc_swap`] for the
///   set-once channel slot: `ChannelInfo` is installed exactly once at
///   session-setup completion (`setup.rs::make_channel`) and is then
///   read on every wire message that participates in signing.
///   `ArcSwapOption` gives us atomic store + lock-free load — no
///   write-lock acquired per signed message.
///
/// `Clone` is *not* derived. Instances always live behind `Arc`; clone
/// the `Arc` instead.
pub struct SessionAndChannel {
    pub session_id: u64,

    pub session: Arc<RwLock<SessionInfo>>,
    pub channel: ArcSwapOption<ChannelInfo>,
    object: OnceLock<crate::runtime::ObjectToken>,
}

impl SessionAndChannel {
    pub fn new(session_id: u64, session: Arc<RwLock<SessionInfo>>) -> Self {
        Self {
            session_id,
            session,
            channel: ArcSwapOption::const_empty(),
            object: OnceLock::new(),
        }
    }

    /// Install the channel slot. Takes `&self` because the underlying
    /// `ArcSwapOption` supports atomic store without an outer lock.
    /// Called exactly once per session setup (see
    /// `session/setup.rs::make_channel`).
    pub fn set_channel(&self, channel: ChannelInfo) {
        self.channel.store(Some(Arc::new(channel)));
    }

    /// Snapshot the currently installed channel (if any). Returns a
    /// fresh `Arc<ChannelInfo>` so callers can drop the
    /// `Arc<SessionAndChannel>` while holding a stable reference to
    /// the channel state they observed.
    pub fn channel(&self) -> Option<Arc<ChannelInfo>> {
        self.channel.load_full()
    }

    pub(crate) fn set_object(&self, token: crate::runtime::ObjectToken) -> crate::Result<()> {
        self.object
            .set(token)
            .map_err(|_| Error::InvalidState("Session object token already installed".into()))
    }

    pub(crate) fn object(&self) -> crate::Result<crate::runtime::ObjectToken> {
        self.object
            .get()
            .copied()
            .ok_or_else(|| Error::InvalidState("Session object token is unavailable".into()))
    }
}

struct SessionGeneration {
    primary_channel: Arc<ChannelContext>,
    conn_info: Arc<ConnectionInfo>,
}

pub(crate) struct SessionContext {
    generation: arc_swap::ArcSwap<SessionGeneration>,

    channel_contexts: RwLock<HashMap<u32, Arc<ChannelContext>>>,
    credential_provider: Option<SharedCredentialProvider>,
    recovery: tokio::sync::Mutex<()>,

    dropping: AtomicBool,
}

impl SessionContext {
    fn new(
        primary_channel: Arc<ChannelContext>,
        conn_info: Arc<ConnectionInfo>,
        credential_provider: Option<SharedCredentialProvider>,
    ) -> Self {
        let primary_channel_id = primary_channel.channel_id();
        Self {
            generation: arc_swap::ArcSwap::from_pointee(SessionGeneration {
                primary_channel: primary_channel.clone(),
                conn_info,
            }),
            channel_contexts: RwLock::new(HashMap::from([(primary_channel_id, primary_channel)])),
            credential_provider,
            recovery: tokio::sync::Mutex::new(()),
            dropping: AtomicBool::new(false),
        }
    }

    fn generation(&self) -> Arc<SessionGeneration> {
        self.generation.load_full()
    }

    pub(crate) fn primary_channel(&self) -> Arc<ChannelContext> {
        self.generation().primary_channel.clone()
    }

    pub(crate) fn session_id(&self) -> u64 {
        self.primary_channel().session_id()
    }

    fn conn_info(&self) -> Arc<ConnectionInfo> {
        self.generation().conn_info.clone()
    }

    pub(crate) async fn reauthenticate(
        &self,
        expected_session_id: u64,
    ) -> crate::Result<(u64, u64)> {
        let _recovery = self.recovery.lock().await;
        let previous = self.generation();
        let previous_channel = previous.primary_channel.clone();
        if previous_channel.session_id() != expected_session_id {
            return Ok((expected_session_id, previous_channel.session_id()));
        }
        let previous_state = previous_channel.session_state().clone();
        let previous_object = previous_state.object()?;
        let upstream = previous_channel.upstream();
        let worker = upstream
            .worker()
            .ok_or_else(|| Error::InvalidState("Worker is unavailable for reauthentication".into()))?;
        let connection = worker.connection_object();
        let same_generation = previous_object.generation() == connection.generation();

        if same_generation {
            worker.begin_object_recovery(previous_object).await?;
        }

        let policy = previous.conn_info.config.auto_reconnect;
        let clock: Arc<dyn crate::clock::Clock> = Arc::new(crate::clock::TokioClock::new());
        let provider = self.credential_provider.as_ref().ok_or_else(|| {
            Error::InvalidState("Session has no reauthentication capability".into())
        })?;
        let mut last_error = None;
        let mut candidate = None;
        for _attempt in 1..=policy.max_attempts {
            let future = async {
                let identity = provider.identity().await?;
                let conn_info = upstream
                    .conn_info()
                    .ok_or_else(|| Error::InvalidState("Connection is not negotiated".into()))?;
                let mut setup = SessionSetup::new(
                    identity,
                    &upstream,
                    &conn_info,
                    PRIMARY_CHANNEL_ID,
                    None,
                    SetupKind::New,
                )
                .await?;
                let setup_result = setup.setup().await?;
                crate::Result::Ok((setup_result, conn_info))
            };
            match run_bounded_attempt(clock.clone(), policy.attempt_timeout, future).await {
                Ok(Ok(prepared)) => {
                    candidate = Some(prepared);
                    break;
                }
                Ok(Err(error)) => last_error = Some(error),
                Err(_) => {
                    last_error = Some(Error::OperationTimeout(
                        crate::error::TimedOutTask::SessionReauthentication,
                        policy.attempt_timeout,
                    ));
                }
            }
        }
        let Some((setup_result, conn_info)) = candidate else {
            if same_generation {
                let _ = worker.fail_object_recovery(previous_object).await;
            }
            return Err(last_error.unwrap_or_else(|| {
                Error::InvalidState("Session reauthentication is disabled".into())
            }));
        };
        if same_generation {
            let replacement = worker
                .publish_object_replacement(previous_object)
                .await?;
            setup_result.set_object(replacement)?;
        }
        let channel = Channel::new(&upstream, &conn_info, &setup_result).await?;
        let new_session_id = channel.session_id();
        let old_session_id = previous_channel.session_id();
        let channel_context = channel.context.clone();
        self.generation.store(Arc::new(SessionGeneration {
            primary_channel: channel_context.clone(),
            conn_info,
        }));
        {
            let mut channels = self.channel_contexts.write().await;
            channels.clear();
            channels.insert(channel_context.channel_id(), channel_context);
        }
        previous_state.session.write().await.invalidate();
        if same_generation {
            let _ = worker.session_ended(&previous_state).await;
        }
        Ok((old_session_id, new_session_id))
    }

    pub async fn logoff(&self) -> crate::Result<()> {
        if self
            .dropping
            .swap(true, std::sync::atomic::Ordering::Relaxed)
        {
            return Ok(());
        }

        {
            let primary_channel = self.primary_channel();
            let state = primary_channel.session_state().session.read().await;
            if !state.is_ready() {
                tracing::trace!("Session not ready, or logged-off already, skipping logoff.");
                return Ok(());
            }
        }

        tracing::debug!("Logging off session.");

        let _response = self.send_recv(LogoffRequest {}.into()).await?;

        // This also invalidates the session object.
        tracing::info!("Session logged off.");
        self.primary_channel()
            .session_state()
            .session
            .write()
            .await
            .invalidate();

        Ok(())
    }

    async fn resolve_channel(&self, channel_id: Option<u32>) -> crate::Result<Arc<ChannelContext>> {
        let primary = self.primary_channel();
        match channel_id {
            None => Ok(primary),
            Some(id) if id == primary.channel_id() => Ok(primary),
            Some(id) => self
                .channel_contexts
                .read()
                .await
                .get(&id)
                .cloned()
                .ok_or(Error::ChannelNotFound(self.primary_channel().session_id(), id)),
        }
    }

    pub(crate) async fn execute(
        &self,
        msg: CommandRequest,
        options: ResponseOptions<'_>,
    ) -> crate::Result<(CommandSubmission, CommandResponse)> {
        self.resolve_channel(msg.channel_id)
            .await?
            .execute(msg, options)
            .await
    }

    pub(crate) async fn execute_for(
        &self,
        msg: CommandRequest,
        options: ResponseOptions<'_>,
        dependency: crate::runtime::ObjectToken,
    ) -> crate::Result<(CommandSubmission, CommandResponse)> {
        self.resolve_channel(msg.channel_id)
            .await?
            .execute_for(msg, options, dependency)
            .await
    }

    pub(crate) async fn create_child_object(
        &self,
        kind: crate::runtime::ObjectKind,
    ) -> crate::Result<crate::runtime::ObjectToken> {
        self.primary_channel().create_child_object(kind).await
    }

    pub(crate) async fn create_object(
        &self,
        parent: crate::runtime::ObjectToken,
        kind: crate::runtime::ObjectKind,
    ) -> crate::Result<crate::runtime::ObjectToken> {
        self.primary_channel().create_object(parent, kind).await
    }

    pub(crate) async fn submit_for(
        &self,
        message: CommandRequest,
        dependency: crate::runtime::ObjectToken,
    ) -> crate::Result<CommandSubmission> {
        self.resolve_channel(message.channel_id)
            .await?
            .submit_for(message, dependency)
            .await
    }

    pub(crate) async fn send_recv(
        &self,
        content: RequestContent,
    ) -> crate::Result<CommandResponse> {
        self.execute(CommandRequest::new(content), ResponseOptions::new())
            .await
            .map(|(_, incoming)| incoming)
    }

    /// Logs off the session and invalidates it.
    ///
    /// # Notes
    /// This method waits for the logoff response to be received from the server.
    /// It is used when dropping the session.
    async fn logoff_async(&self) {
        self.logoff().await.unwrap_or_else(|e| {
            tracing::error!("Failed to logoff: {e}");
        });
    }
}

impl SessionContext {
}

impl Drop for SessionContext {
    fn drop(&mut self) {
        if self
            .dropping
            .swap(true, std::sync::atomic::Ordering::Relaxed)
        {
            return;
        }

        let generation = self.generation();
        let primary_channel = generation.primary_channel.clone();
        let conn_info = generation.conn_info.clone();

        tokio::task::spawn(async move {
            let temp_handler = SessionContext {
                dropping: AtomicBool::new(false),
                generation: arc_swap::ArcSwap::from_pointee(SessionGeneration {
                    primary_channel,
                    conn_info,
                }),
                channel_contexts: Default::default(),
                credential_provider: None,
                recovery: tokio::sync::Mutex::new(()),
            };
            temp_handler.logoff_async().await;
        });
    }
}
