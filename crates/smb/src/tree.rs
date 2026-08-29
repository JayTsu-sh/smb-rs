use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use smb_msg::{FileId, FsctlRequest, IoctlRequest, IoctlRequestFlags};

use crate::FileCreateArgs;
use crate::connection::connection_info::ConnectionInfo;
use smb_fscc::{FileAccessMask, FileAttributes};
use smb_msg::{
    CreateOptions, RequestContent, ShareFlags, ShareType,
    create::CreateDisposition,
    tree_connect::{TreeConnectRequest, TreeDisconnectRequest},
};

use crate::{Error, Resource, command::Protection, session::SessionContext};
mod dfs_tree;
mod ipc_tree;
use crate::command::{CommandRequest, CommandResponse, CommandSubmission, ResponseOptions};
pub use dfs_tree::*;
pub use ipc_tree::*;

type Upstream = Arc<SessionContext>;

#[derive(Debug, Clone)]
pub struct TreeConnectInfo {
    share_type: ShareType,
    share_flags: ShareFlags,
}

fn validate_tree_connect(
    content: &smb_msg::TreeConnectResponse,
    conn_info: &ConnectionInfo,
    name: &str,
) -> crate::Result<TreeConnectInfo> {
    if ((!u32::from_le_bytes(conn_info.dialect.get_tree_connect_caps_mask().into_bytes()))
        & u32::from_le_bytes(content.capabilities.into_bytes()))
        != 0
    {
        return Err(Error::InvalidMessage(format!(
            "Invalid share capabilities received for tree '{name}': {:?}",
            content.capabilities
        )));
    }
    if ((!u32::from_le_bytes(conn_info.dialect.get_share_flags_mask().into_bytes()))
        & u32::from_le_bytes(content.share_flags.into_bytes()))
        != 0
    {
        return Err(Error::InvalidMessage(format!(
            "Invalid share flags received for tree '{name}': {:?}",
            content.share_flags
        )));
    }
    if content.share_flags.encrypt_data() && conn_info.config.encryption_mode.is_disabled() {
        return Err(Error::InvalidMessage(
            "Server requires encryption, but client does not support it".to_string(),
        ));
    }
    Ok(TreeConnectInfo {
        share_type: content.share_type,
        share_flags: content.share_flags,
    })
}

/// Represents an SMB share.
///
/// A Tree is the SMB protocol's representation of a connected share on the server.
pub struct Tree {
    context: Arc<TreeContext>,
}

impl Tree {
    pub(crate) fn connection_info(&self) -> Arc<ConnectionInfo> {
        self.context.upstream.conn_info()
    }

    pub(crate) fn requires_encryption(&self) -> crate::Result<bool> {
        Ok(self.context.info()?.share_flags.encrypt_data())
    }

    pub(crate) async fn connect(
        name: &str,
        upstream: &Upstream,
        conn_info: &Arc<ConnectionInfo>,
    ) -> crate::Result<Tree> {
        // send and receive tree request & response.
        let response = upstream
            .send_recv(TreeConnectRequest::new(name).into())
            .await?;

        let content = response.message.content.to_treeconnect()?;

        let tree_connect_info = validate_tree_connect(&content, conn_info, name)?;

        let tree_id = response
            .message
            .header
            .tree_id
            .ok_or(Error::InvalidMessage(
                "Tree ID is not set in the response".to_string(),
            ))?;

        tracing::info!("Connected to tree {name} (#{tree_id})");

        let object = upstream
            .create_child_object(crate::runtime::ObjectKind::Share)
            .await?;
        let session = upstream.session_object()?;

        let context = TreeContext::new(
                upstream,
                tree_id,
                name.to_string(),
                tree_connect_info,
                session,
                object,
            );
        upstream.register_share(Arc::downgrade(&context)).await;
        let t = Tree {
            context,
        };

        Ok(t)
    }

    /// Creates a resource (file, directory, pipe, or printer) on the remote server by it's name.
    /// See [Tree::create_file] and [Tree::create_directory] for an easier API.
    /// # Arguments
    /// * `file_name` - The name of the resource to create. This should NOT contain the share name, or begin with a backslash.
    /// * `args` - The arguments for the create operation. This includes the desired access, file attributes, and create options.
    ///     See [`FileCreateArgs`] for more information.
    /// # Returns
    /// * A [Resource] object representing the created resource. This can be a file, directory, pipe, or printer.
    /// # Notes
    /// This function automatically handles the following:
    /// * *DFS operations*: If the share has been opened as a DFS referral share, the create operation will modify the file name to include the DFS path.
    ///     That is, assuming it is NOT prefixed with "\\". This is rquired for a proper DFS referral file open. ("DFS normalization", MS-SMB2 2.2.13 + 3.3.5.9)
    #[tracing::instrument(level = "debug", skip_all, fields(file_name = %file_name))]
    pub async fn create(&self, file_name: &str, args: &FileCreateArgs) -> crate::Result<Resource> {
        let info = self.context.info()?;
        Resource::create(
            file_name,
            &self.context,
            args,
            &self.context.upstream.conn_info(),
            info.share_type,
            info.share_flags.dfs(),
        )
        .await
    }

    /// A wrapper around [Tree::create] that creates a file on the remote server.
    /// See [Tree::create] for more information.
    #[tracing::instrument(level = "debug", skip_all, fields(file_name = %file_name))]
    pub async fn create_file(
        &self,
        file_name: &str,
        disposition: CreateDisposition,
        desired_access: FileAccessMask,
    ) -> crate::Result<Resource> {
        self.create(
            file_name,
            &FileCreateArgs {
                disposition,
                options: CreateOptions::new(),
                desired_access,
                attributes: FileAttributes::new(),
                ..Default::default()
            },
        )
        .await
    }

    /// A wrapper around [Tree::create] that creates a directory on the remote server.
    /// See [Tree::create] for more information.
    #[tracing::instrument(level = "debug", skip_all, fields(dir_name = %dir_name))]
    pub async fn create_directory(
        &self,
        dir_name: &str,
        disposition: CreateDisposition,
        desired_access: FileAccessMask,
    ) -> crate::Result<Resource> {
        self.create(
            dir_name,
            &FileCreateArgs {
                disposition,
                options: CreateOptions::new().with_directory_file(true),
                desired_access,
                attributes: FileAttributes::new().with_directory(true),
                ..Default::default()
            },
        )
        .await
    }

    /// A wrapper around [create][crate::tree::Tree::create] that opens an existing file or directory on the remote server.
    /// See [create][crate::tree::Tree::create] for more information.
    #[tracing::instrument(level = "debug", skip_all, fields(file_name = %file_name))]
    pub async fn open_existing(
        &self,
        file_name: &str,
        access: FileAccessMask,
    ) -> crate::Result<Resource> {
        self.create(file_name, &FileCreateArgs::make_open_existing(access))
            .await
    }

    pub fn is_dfs_root(&self) -> crate::Result<bool> {
        let info = self.context.info()?;
        Ok(info.share_flags.dfs_root() && info.share_flags.dfs())
    }

    /// Returns the SMB-assigned tree id for this connected share.
    /// Used by the lease cache (Phase C) so cache hits can match opens
    /// against the same tree the original Create was issued on.
    pub fn tree_id(&self) -> u32 {
        self.context.generation().tree_id
    }

    pub(crate) fn object_token(&self) -> crate::runtime::ObjectToken {
        self.context.generation().object
    }

    /// Borrow the tree's underlying `Upstream` context reference.
    /// Phase C uses this from [`crate::resource::Resource::build_lease_proto`]
    /// so the lease cache can construct a `ResourceMessageHandle` against
    /// the same tree the Create was issued on. `pub(crate)` because the
    /// Crate-private because the per-connection context type is internal.
    pub(crate) fn context_ref(&self) -> &Arc<TreeContext> {
        &self.context
    }

    pub fn as_dfs_tree(&self) -> crate::Result<DfsRootTreeRef<'_>> {
        if !self.is_dfs_root()? {
            return Err(Error::InvalidState("Tree is not a DFS tree".to_string()));
        }
        Ok(DfsRootTreeRef::new(self))
    }

    pub fn as_ipc_tree(&self) -> crate::Result<IpcTreeRef<'_>> {
        let info = self.context.info()?;
        if info.share_type != ShareType::Pipe {
            return Err(Error::InvalidState(format!(
                "Tree is not IPC tree ({:?})",
                info.share_type
            )));
        }

        IpcTreeRef::new(self)
    }

    /// Disconnects from the tree (share) on the server.
    ///
    /// After calling this method, none of the resources held open by the tree are accessible.
    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn disconnect(&self) -> crate::Result<()> {
        self.context.disconnect().await?;
        Ok(())
    }

    // TODO: Make it common with ResourceHandle::fsctl_with_options
    pub(crate) async fn fsctl_with_options<T: FsctlRequest>(
        &self,
        request: T,
        max_output_response: u32,
    ) -> crate::Result<T::Response> {
        const NO_INPUT_IN_RESPONSE: u32 = 0;
        let response = self
            .context
            .send_recv(RequestContent::Ioctl(IoctlRequest {
                ctl_code: T::FSCTL_CODE as u32,
                file_id: FileId::FULL,
                max_input_response: NO_INPUT_IN_RESPONSE,
                max_output_response,
                flags: IoctlRequestFlags::new().with_is_fsctl(true),
                buffer: request.into(),
            }))
            .await?
            .message
            .content
            .to_ioctl()?
            .parse_fsctl::<T::Response>()?;
        Ok(response)
    }
}

struct TreeGeneration {
    tree_id: u32,
    info: TreeConnectInfo,
    session: crate::runtime::ObjectToken,
    object: crate::runtime::ObjectToken,
}

struct TreeRecoveryFlag<'a>(&'a AtomicBool);

impl Drop for TreeRecoveryFlag<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

pub(crate) struct TreeContext {
    generation: arc_swap::ArcSwap<TreeGeneration>,
    closed: AtomicBool,

    upstream: Upstream,

    tree_name: String,
    recovery: tokio::sync::Mutex<()>,
    recovery_slots: Arc<tokio::sync::Semaphore>,
    recovering: AtomicBool,
}

impl TreeContext {
    pub fn new(
        upstream: &Upstream,
        tree_id: u32,
        tree_name: String,
        info: TreeConnectInfo,
        session: crate::runtime::ObjectToken,
        object: crate::runtime::ObjectToken,
    ) -> Arc<TreeContext> {
        Arc::new(TreeContext {
            generation: arc_swap::ArcSwap::from_pointee(TreeGeneration {
                tree_id,
                info,
                session,
                object,
            }),
            closed: AtomicBool::new(false),
            upstream: upstream.clone(),
            tree_name,
            recovery: tokio::sync::Mutex::new(()),
            recovery_slots: Arc::new(tokio::sync::Semaphore::new(
                upstream.conn_info().config.auto_reconnect.max_waiting_operations,
            )),
            recovering: AtomicBool::new(false),
        })
    }

    fn generation(&self) -> Arc<TreeGeneration> {
        self.generation.load_full()
    }

    pub(crate) async fn reconnect(self: &Arc<Self>) -> crate::Result<()> {
        let _owner = self.recovery.lock().await;
        if self.closed.load(Ordering::Acquire) {
            return Err(Error::InvalidState("Tree is closed".into()));
        }
        let previous = self.generation();
        let session = self.upstream.session_object()?;
        if previous.session == session {
            return Ok(());
        }
        self.recovering.store(true, Ordering::Release);
        let recovering = TreeRecoveryFlag(&self.recovering);
        let conn_info = self.upstream.conn_info();
        let policy = conn_info.config.auto_reconnect;
        let clock: Arc<dyn crate::clock::Clock> = Arc::new(crate::clock::TokioClock::new());
        let mut last_error = None;
        let mut candidate = None;
        for _attempt in 1..=policy.max_attempts {
            let future = async {
                let response = self
                    .upstream
                    .send_recv_on_current_session(TreeConnectRequest::new(&self.tree_name).into())
                    .await?;
                let content = response.message.content.to_treeconnect()?;
                let info = validate_tree_connect(&content, &conn_info, &self.tree_name)?;
                let tree_id = response.message.header.tree_id.ok_or_else(|| {
                    Error::InvalidMessage("Tree ID is not set in replay response".into())
                })?;
                let object = self
                    .upstream
                    .create_child_object_on_current_session(crate::runtime::ObjectKind::Share)
                    .await?;
                crate::Result::Ok(TreeGeneration {
                    tree_id,
                    info,
                    session,
                    object,
                })
            };
            match crate::session::recovery_attempt::run_bounded_attempt(
                clock.clone(),
                policy.attempt_timeout,
                future,
            )
            .await
            {
                Ok(Ok(prepared)) => {
                    candidate = Some(prepared);
                    break;
                }
                Ok(Err(error)) => last_error = Some(error),
                Err(_) => last_error = Some(Error::ShareRecoveryWaitTimedOut),
            }
        }
        let Some(candidate) = candidate else {
            return Err(last_error.unwrap_or_else(|| {
                Error::InvalidState("Share recovery is disabled".into())
            }));
        };
        if self.closed.load(Ordering::Acquire) {
            return Err(Error::InvalidState("Tree closed during recovery".into()));
        }
        self.generation.store(Arc::new(candidate));
        drop(recovering);
        Ok(())
    }

    async fn wait_for_reconnect(
        self: &Arc<Self>,
        timeout: Option<std::time::Duration>,
        cancellation: Option<tokio_util::sync::CancellationToken>,
    ) -> crate::Result<()> {
        let generation = self.generation();
        if !self.recovering.load(Ordering::Acquire)
            && generation.session == self.upstream.session_object()?
        {
            return Ok(());
        }
        let permit = self
            .recovery_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::ShareRecoveryQueueFull)?;
        let replay = tokio::spawn({
            let context = self.clone();
            async move {
                let _permit = permit;
                context.reconnect().await
            }
        });
        tokio::pin!(replay);
        let deadline = async {
            match timeout {
                Some(timeout) => tokio::time::sleep(timeout).await,
                None => futures_util::future::pending().await,
            }
        };
        tokio::pin!(deadline);
        let cancelled = async {
            match cancellation {
                Some(cancellation) => cancellation.cancelled().await,
                None => futures_util::future::pending().await,
            }
        };
        tokio::pin!(cancelled);
        tokio::select! {
            result = &mut replay => result.map_err(Error::JoinError)?,
            _ = &mut deadline => Err(Error::ShareRecoveryWaitTimedOut),
            _ = &mut cancelled => Err(Error::Cancelled("Share recovery wait")),
        }
    }

    fn prepare(
        &self,
        mut msg: CommandRequest,
    ) -> crate::Result<(CommandRequest, Arc<TreeGeneration>)> {
        if self.closed.load(Ordering::Acquire) {
            return Err(Error::InvalidState("Tree is closed".to_string()));
        }
        let generation = self.generation();
        if !msg.message.header.flags.async_command() {
            msg.message.header.tree_id = generation.tree_id.into();
            if generation.info.share_flags.encrypt_data() && msg.security.is_none() {
                msg.security = Some(Protection::Encrypt);
            }
        }
        Ok((msg, generation))
    }

    pub(crate) async fn execute(
        self: &Arc<Self>,
        msg: CommandRequest,
        options: ResponseOptions<'_>,
    ) -> crate::Result<(CommandSubmission, CommandResponse)> {
        self.wait_for_reconnect(
            options.timeout.or_else(|| Some(self.upstream.conn_info().config.timeout())),
            options.async_cancel.clone(),
        )
        .await?;
        let object = self.generation().object;
        self.execute_for(msg, options, object).await
    }

    pub(crate) async fn create_resource_object(
        self: &Arc<Self>,
    ) -> crate::Result<crate::runtime::ObjectToken> {
        self.wait_for_reconnect(Some(self.upstream.conn_info().config.timeout()), None)
            .await?;
        self.upstream
            .create_object(self.generation().object, crate::runtime::ObjectKind::Resource)
            .await
    }

    pub(crate) async fn execute_for(
        &self,
        msg: CommandRequest,
        options: ResponseOptions<'_>,
        dependency: crate::runtime::ObjectToken,
    ) -> crate::Result<(CommandSubmission, CommandResponse)> {
        let (message, generation) = self.prepare(msg)?;
        let result = self
            .upstream
            .execute_for(message, options, dependency)
            .await?;
        let incoming = &result.1;
        if !incoming.message.header.flags.async_command()
            && incoming.message.header.tree_id.unwrap_or_default()
                != generation.tree_id
        {
            return Err(Error::InvalidMessage(
                "Received message for different tree, or tree disconnecting.".to_string(),
            ));
        }
        if !incoming.form.encrypted && generation.info.share_flags.encrypt_data() {
            return Err(Error::InvalidMessage(
                "Received unencrypted message on encrypted share".to_string(),
            ));
        }
        Ok(result)
    }

    pub(crate) async fn send_recv(
        self: &Arc<Self>,
        content: RequestContent,
    ) -> crate::Result<crate::command::CommandResponse> {
        self.execute_request(
            CommandRequest::new(content),
            crate::command::ResponseOptions::new(),
        )
        .await
    }

    pub(crate) async fn send_recv_for(
        &self,
        content: RequestContent,
        dependency: crate::runtime::ObjectToken,
    ) -> crate::Result<CommandResponse> {
        self.execute_for(CommandRequest::new(content), ResponseOptions::new(), dependency)
            .await
            .map(|(_, incoming)| incoming)
    }

    pub(crate) async fn execute_content(
        self: &Arc<Self>,
        content: RequestContent,
        options: crate::command::ResponseOptions<'_>,
    ) -> crate::Result<crate::command::CommandResponse> {
        self.execute_request(CommandRequest::new(content), options)
            .await
    }

    pub(crate) async fn execute_request(
        self: &Arc<Self>,
        message: CommandRequest,
        options: crate::command::ResponseOptions<'_>,
    ) -> crate::Result<crate::command::CommandResponse> {
        self.execute(message, options)
            .await
            .map(|(_, incoming)| incoming)
    }

    pub(crate) async fn submit_for(
        &self,
        message: CommandRequest,
        dependency: crate::runtime::ObjectToken,
    ) -> crate::Result<CommandSubmission> {
        self.upstream
            .submit_for(self.prepare(message)?.0, dependency)
            .await
    }

    async fn _disconnect(
        upstream: Upstream,
        tree_id: u32,
        encrypt: bool,
        object: crate::runtime::ObjectToken,
    ) -> crate::Result<()> {
        // send and receive tree disconnect request & response.
        let request_content: RequestContent = TreeDisconnectRequest::default().into();
        let mut message = CommandRequest::new(request_content);
        if encrypt {
            message.security = Some(Protection::Encrypt);
        }
        message.message.header.tree_id = Some(tree_id);

        let command = message.message.content.associated_cmd();
        let _response = upstream
            .execute_for(
                message,
                ResponseOptions::new().with_cmd(Some(command)),
                object,
            )
            .await?;

        Ok(())
    }

    async fn disconnect(&self) -> crate::Result<()> {
        if self.closed.swap(true, Ordering::AcqRel) {
            // Already disconnected
            return Ok(());
        }
        let generation = self.generation();
        Self::_disconnect(
            self.upstream.clone(),
            generation.tree_id,
            generation.info.share_flags.encrypt_data(),
            generation.object,
        )
        .await
    }

    pub fn info(&self) -> crate::Result<Arc<TreeConnectInfo>> {
        if self.closed.load(Ordering::Acquire) {
            return Err(Error::InvalidState("Tree is closed".to_string()));
        }
        Ok(Arc::new(self.generation().info.clone()))
    }
}

impl Drop for TreeContext {
    fn drop(&mut self) {
        if self.closed.load(Ordering::Acquire) {
            // Already dropped
            return;
        }

        let generation = self.generation();
        let upstream = self.upstream.clone();
        let tree_name = self.tree_name.clone();
        let tree_id = generation.tree_id;
        let encrypt = generation.info.share_flags.encrypt_data();
        let object = generation.object;
        tokio::task::spawn(async move {
            Self::_disconnect(upstream, tree_id, encrypt, object)
                .await
                .map_err(|e| {
                    tracing::warn!("Failed to disconnect from tree {}: {e}", tree_name);
                })
                .ok();
        });
    }
}
