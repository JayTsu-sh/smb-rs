use std::sync::{Arc, atomic::AtomicBool};

use smb_dtyp::SecurityDescriptor;
use smb_dtyp::binrw_util::prelude::FileTime;
use smb_fscc::*;
use smb_msg::*;

use crate::{
    Error,
    command::{CommandRequest, CommandResponse, ResponseOptions},
    connection::connection_info::ConnectionInfo,
    lease::OplockSlot,
    tree::TreeContext,
};

pub mod directory;
pub mod file;
pub mod pipe;

pub use directory::*;
pub use file::*;
pub use pipe::*;

type Upstream = Arc<TreeContext>;

/// Opt-in SMB3 durable-v2 open request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DurableOpenRequest {
    timeout: u32,
    create_guid: smb_dtyp::Guid,
    persistent: bool,
}

/// Durable-v2 properties granted by the server for this Resource.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DurableOpenGrant {
    pub timeout: u32,
    pub persistent: bool,
    pub create_guid: smb_dtyp::Guid,
}

impl DurableOpenRequest {
    pub const fn persistent(timeout: u32, create_guid: smb_dtyp::Guid) -> Self {
        Self {
            timeout,
            create_guid,
            persistent: true,
        }
    }
}

#[derive(Default)]
pub struct FileCreateArgs {
    pub disposition: CreateDisposition,
    pub attributes: FileAttributes,
    pub options: CreateOptions,
    pub desired_access: FileAccessMask,
    /// Optional lease request context (`RqLs`) attached to the CREATE.
    /// Set to `None` (default) to preserve the legacy "no lease" behavior.
    /// Set to `Some(RequestLease::RqLsReqv2(...))` on SMB 3.x to ask the
    /// server for read/handle/write caching; the granted state is reported
    /// back via [`ResourceHandle::lease_granted`].
    pub lease_request: Option<RequestLease>,
    /// Optional SMB3 durable-v2 or persistent open request.
    pub durable_request: Option<DurableOpenRequest>,
    /// Optional timestamp for opening a read-only Previous Version.
    pub timewarp: Option<smb_dtyp::binrw_util::prelude::FileTime>,
}

impl FileCreateArgs {
    pub fn make_open_existing(access: FileAccessMask) -> FileCreateArgs {
        FileCreateArgs {
            disposition: CreateDisposition::Open,
            attributes: FileAttributes::new(),
            options: CreateOptions::new(),
            desired_access: access,
            ..Default::default()
        }
    }

    /// Returns arguments for creating a new file with the data-mutation access needed by
    /// ordinary share `Change` permissions.  Do not request `GenericAll`: that also asks for
    /// ACL/ownership rights that a data mover neither needs nor receives from ONTAP shares.
    pub fn make_create_new(attributes: FileAttributes, options: CreateOptions) -> FileCreateArgs {
        FileCreateArgs {
            disposition: CreateDisposition::Create,
            attributes,
            options,
            desired_access: FileAccessMask::new()
                .with_generic_read(true)
                .with_generic_write(true)
                .with_delete(true),
            ..Default::default()
        }
    }

    /// Returns arguments for replacing a file with the data-mutation access needed by ordinary
    /// share `Change` permissions.  It overwrites an existing file when present.
    pub fn make_overwrite(attributes: FileAttributes, options: CreateOptions) -> FileCreateArgs {
        FileCreateArgs {
            disposition: CreateDisposition::OverwriteIf,
            attributes,
            options,
            desired_access: FileAccessMask::new()
                .with_generic_read(true)
                .with_generic_write(true)
                .with_delete(true),
            ..Default::default()
        }
    }

    /// Returns arguments for opening a duplex pipe (rw).
    pub fn make_pipe() -> FileCreateArgs {
        FileCreateArgs {
            disposition: CreateDisposition::Open,
            attributes: Default::default(),
            options: Default::default(),
            desired_access: FileAccessMask::new()
                .with_generic_read(true)
                .with_generic_write(true),
            ..Default::default()
        }
    }

    /// Request an SMB3 durable-v2 or persistent open.
    pub fn with_durable(mut self, request: DurableOpenRequest) -> Self {
        self.durable_request = Some(request);
        self
    }

    pub(crate) fn with_timewarp(
        mut self,
        timestamp: smb_dtyp::binrw_util::prelude::FileTime,
    ) -> Self {
        self.timewarp = Some(timestamp);
        self
    }
}

fn validate_durable_request(
    request: DurableOpenRequest,
    smb3: bool,
    persistent_handles: bool,
    continuous_availability: bool,
) -> crate::Result<()> {
    if !smb3 {
        return Err(Error::UnsupportedOperation(
            "Durable-v2 opens require an SMB3 dialect".into(),
        ));
    }
    if request.persistent && (!persistent_handles || !continuous_availability) {
        return Err(Error::UnsupportedOperation(
            "Persistent opens require negotiated persistent handles and a continuously available share"
                .into(),
        ));
    }
    Ok(())
}

fn requested_oplock_level(create_args: &FileCreateArgs) -> OplockLevel {
    if create_args.lease_request.is_some() {
        OplockLevel::Lease
    } else if create_args.durable_request.is_some() {
        OplockLevel::Batch
    } else {
        OplockLevel::None
    }
}

fn validate_create_parent_epoch(
    captured: crate::runtime::ObjectToken,
    current: crate::runtime::ObjectToken,
) -> crate::Result<()> {
    if captured == current {
        Ok(())
    } else {
        Err(Error::StaleObject)
    }
}

/// A resource opened by a create request.
pub enum Resource {
    File(File),
    Directory(Directory),
    Pipe(Pipe),
}

impl Resource {
    pub(crate) async fn create(
        name: &str,
        upstream: &Upstream,
        create_args: &FileCreateArgs,
        conn_info: &Arc<ConnectionInfo>,
        share_type: ShareType,
        is_dfs: bool,
    ) -> crate::Result<Resource> {
        let share_access = if share_type == ShareType::Disk {
            ShareAccessFlags::new()
                .with_read(true)
                .with_write(true)
                .with_delete(true)
        } else {
            ShareAccessFlags::new()
        };

        if share_type == ShareType::Print && create_args.disposition != CreateDisposition::Create {
            return Err(Error::InvalidArgument(
                "Printer can only accept CreateDisposition::Create.".to_string(),
            ));
        }

        if name.starts_with("\\") {
            return Err(Error::InvalidArgument(
                "Resource name cannot start with a backslash.".to_string(),
            ));
        }

        if let Some(request) = create_args.durable_request {
            validate_durable_request(
                request,
                conn_info.negotiation.dialect_rev.is_smb3(),
                conn_info.negotiation.caps.persistent_handles(),
                upstream.continuously_available()?,
            )?;
        }
        // 标准 create context 列表：MxAc + QFid 始终发送；lease (RqLs) 仅在调用方显式
        // 请求时附加，保持现有非-lease 调用方零行为变化。
        let mut contexts: Vec<CreateContextRequest> = vec![
            QueryMaximalAccessRequest::default().into(),
            QueryOnDiskIdReq.into(),
        ];
        if let Some(timestamp) = create_args.timewarp {
            contexts.push(TimewarpToken { timestamp }.into());
        }
        if let Some(lease_req) = create_args.lease_request.as_ref() {
            contexts.push(lease_req.clone().into());
        }
        if let Some(request) = create_args.durable_request {
            contexts.push(
                DurableHandleRequestV2::new(
                    request.timeout,
                    request.persistent,
                    request.create_guid,
                )
                .into(),
            );
        }

        // MS-SMB2 2.2.13: server 只在 RequestedOplockLevel = Lease (0xFF) 时把
        // `RqLs` context 当 lease 处理；任何其他值（含 None）都让 server 静默忽略。
        // 因此 lease 请求必须把 oplock level 同步切到 Lease。
        let requested_oplock_level = requested_oplock_level(create_args);

        let mut msg = CommandRequest::new(
            CreateRequest {
                requested_oplock_level,
                impersonation_level: ImpersonationLevel::Impersonation,
                desired_access: create_args.desired_access,
                file_attributes: create_args.attributes,
                share_access,
                create_disposition: create_args.disposition,
                create_options: create_args.options,
                name: name.into(),
                contexts: contexts.into(),
            }
            .into(),
        );
        // Make sure to set DFS if required.
        msg.message.header.flags.set_dfs_operation(is_dfs);

        let share = upstream.current_share_object().await?;
        let response = upstream
            .execute_for_with_replay(
                msg,
                ResponseOptions::new().with_allow_async(true),
                share,
                crate::runtime::ReplayPolicy::NeverReplay,
            )
            .await?
            .1;

        validate_create_parent_epoch(share, upstream.current_share_object().await?)?;

        let response = response.message.content.to_create()?;
        tracing::debug!("Created file '{}', ({:?})", name, response.file_id);

        let is_dir = response.file_attributes.directory();

        // Get maximal access
        let access = CreateContextResponseData::first_mxac(&response.create_contexts)
            .and_then(|r| r.maximal_access())
            .unwrap_or_else(|| {
                    tracing::debug!(
                        "No maximal access context found for file '{name}', using default (full access)."
                    );
                    FileAccessMask::from_bytes(u32::MAX.to_be_bytes())
                }
            );

        let durable_granted = if let Some(request) = create_args.durable_request {
            let response = CreateContextResponseData::first_dh2q(&response.create_contexts)
                .ok_or_else(|| {
                    Error::UnsupportedOperation(
                        "Server did not grant the requested durable-v2 open".into(),
                    )
                })?;
            let persistent = response.flags.persistent();
            if request.persistent && !persistent {
                return Err(Error::UnsupportedOperation(
                    "Server did not grant the requested persistent open".into(),
                ));
            }
            Some(DurableOpenGrant {
                timeout: response.timeout,
                persistent,
                create_guid: request.create_guid,
            })
        } else {
            None
        };

        // [`Resource::attach_lease_slot`] after this function returns.
        let object = upstream.create_resource_object_for(share).await?;
        let oplock_slot = if matches!(
            response.oplock_level,
            OplockLevel::II | OplockLevel::Exclusive | OplockLevel::Batch
        ) {
            let slot = Arc::new(OplockSlot::new(
                response.file_id,
                response.oplock_level,
                upstream.clone(),
                object,
            ));
            upstream.register_oplock_slot(&slot).await;
            Some(slot)
        } else {
            None
        };
        let opened = OpenedFacts {
            created: response.creation_time,
            accessed: response.last_access_time,
            written: response.last_write_time,
            changed: response.change_time,
            end_of_file: response.endof_file,
            attributes: response.file_attributes,
            reparse_point: response.flags.reparsepoint(),
            on_disk_id: CreateContextResponseData::first_qfid(&response.create_contexts)
                .map(|qfid| (qfid.file_id, qfid.volume_id)),
        };
        let handle = ResourceHandle {
            name: name.to_string(),
            context: upstream.clone(),
            generation: arc_swap::ArcSwap::from_pointee(ResourceGeneration {
                file_id: response.file_id,
                object,
                share,
            }),
            open: AtomicBool::new(true),
            recovery: tokio::sync::Mutex::new(()),
            access,
            durable_granted,
            oplock_slot,
            conn_info: conn_info.clone(),
            opened,
        };

        // Construct specific resource and return it.

        let resource = if is_dir {
            Resource::Directory(Directory::new(handle))
        } else {
            match share_type {
                ShareType::Disk => Resource::File(File::new(handle, response.endof_file)),
                ShareType::Pipe => Resource::Pipe(Pipe::new(handle)),
                ShareType::Print => {
                    return Err(Error::UnsupportedOperation(
                        "Printer resources are not yet implemented".to_string(),
                    ));
                }
            }
        };
        Ok(resource)
    }

    /// Borrow the underlying [`ResourceHandle`] regardless of resource
    /// kind. Convenience for callers that need handle-level metadata
    /// (`name`, `lease_granted`, `raw_file_id`) without first matching
    /// the variant. Returns `None` for variants that don't have a handle
    /// surface — currently none, but kept as `Option` for forward
    /// compatibility.
    pub fn handle(&self) -> Option<&ResourceHandle> {
        match self {
            Resource::File(f) => Some(f.handle()),
            Resource::Directory(d) => Some(d.handle()),
            Resource::Pipe(p) => Some(p.handle()),
        }
    }
}

/// Generates TryInto implementations for Resource enum variants.
macro_rules! make_resource_try_into {
    (
        $($t:ident,)+
    ) => {
        $(

impl TryInto<$t> for Resource {
    type Error = (crate::Error, Self);

    fn try_into(self) -> Result<$t, Self::Error> {
        match self {
            Resource::$t(f) => Ok(f),
            x => Err((Error::InvalidArgument(format!("Not a {}", stringify!($t))), x)),
        }
    }
}
        )+
    };
}

make_resource_try_into!(File, Directory, Pipe,);

/// Holds the common information for an opened SMB resource.
struct ResourceGeneration {
    file_id: FileId,
    object: crate::runtime::ObjectToken,
    share: crate::runtime::ObjectToken,
}

impl ResourceGeneration {
    fn belongs_to(&self, share: crate::runtime::ObjectToken) -> bool {
        self.share == share
    }
}

/// Facts the `CREATE` response already carried about the opened object.
///
/// Every open costs one round trip, and the server answers it with the same timestamps, sizes
/// and attributes a `FileBasicInformation` + `FileStandardInformation` pair would return — plus,
/// because this client always attaches a `QFid` create context, the on-disk file and volume
/// identifiers. Keeping that answer lets callers describe an object without any `QUERY_INFO`
/// round trip. The snapshot is taken at open time and is not refreshed by later writes; use
/// the query-based metadata when freshness after modification matters.
#[derive(Clone, Copy, Debug)]
pub struct OpenedFacts {
    created: FileTime,
    accessed: FileTime,
    written: FileTime,
    changed: FileTime,
    end_of_file: u64,
    attributes: FileAttributes,
    reparse_point: bool,
    /// `(file_id, volume_id)` from the `QFid` create context, when the server returned one.
    on_disk_id: Option<(u64, u64)>,
}

impl OpenedFacts {
    pub fn created(&self) -> FileTime {
        self.created
    }
    pub fn accessed(&self) -> FileTime {
        self.accessed
    }
    pub fn written(&self) -> FileTime {
        self.written
    }
    pub fn changed(&self) -> FileTime {
        self.changed
    }
    pub fn end_of_file(&self) -> u64 {
        self.end_of_file
    }
    pub fn attributes(&self) -> FileAttributes {
        self.attributes
    }
    /// Whether the last path component is a reparse point (`SMB2_CREATE_FLAG_REPARSEPOINT`).
    pub fn is_reparse_point(&self) -> bool {
        self.reparse_point
    }
    /// On-disk file identifier from the `QFid` create context.
    ///
    /// `None` when the server did not answer the context. Zero is also reported as `None`:
    /// back ends without a stable identifier answer zero rather than omitting the context.
    pub fn file_id(&self) -> Option<u64> {
        self.on_disk_id
            .map(|(file_id, _)| file_id)
            .filter(|file_id| *file_id != 0)
    }
    /// Volume identifier from the `QFid` create context, for telling apart identical file
    /// identifiers that come from different volumes behind one share.
    pub fn volume_id(&self) -> Option<u64> {
        self.on_disk_id.map(|(_, volume_id)| volume_id)
    }
}

pub struct ResourceHandle {
    name: String,
    context: Arc<TreeContext>,
    generation: arc_swap::ArcSwap<ResourceGeneration>,

    // Whether the resource is open or not.
    // TODO: Consider using RwLock here on FileId instead of AtomicBool+FileId.
    open: AtomicBool,
    recovery: tokio::sync::Mutex<()>,

    access: FileAccessMask,

    durable_granted: Option<DurableOpenGrant>,

    oplock_slot: Option<Arc<OplockSlot>>,

    conn_info: Arc<ConnectionInfo>,

    opened: OpenedFacts,
}

impl ResourceHandle {
    /// Returns the name of the resource.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Facts the `CREATE` response carried when this handle was opened.
    pub fn opened(&self) -> &OpenedFacts {
        &self.opened
    }

    /// Returns the server-granted durable-v2 properties for this Resource.
    pub fn durable_granted(&self) -> Option<DurableOpenGrant> {
        self.durable_granted
    }

    /// Returns the handle of the resource.
    // This is implemented to be "inhrited" by Deref impl of resources impls, to avoid boilerplate code.
    pub fn handle(&self) -> &ResourceHandle {
        self
    }

    /// (Internal)
    ///
    /// Returns the file ID of the resource, ensuring the resource is still open.
    async fn file_id(&self) -> crate::Result<FileId> {
        // The current design here allows the race condition over a close after this validation occurs.
        // therefore, this atomic load can be relaxed, and actual atomic compare and exchange are used
        // to avoid double close somehow.
        if !self.open.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(Error::InvalidState("Resource is closed".into()));
        }
        self.ensure_current().await?;
        Ok(self.generation.load().file_id)
    }

    async fn ensure_current(&self) -> crate::Result<()> {
        let share = self.context.current_share_object().await?;
        if self.generation.load().belongs_to(share) {
            return Ok(());
        }
        let grant = self.durable_granted.ok_or_else(|| {
            Error::InvalidState("Resource belongs to a stale share generation".into())
        })?;
        let _owner = self.recovery.lock().await;
        let policy = self.conn_info.config.auto_reconnect;
        let clock: Arc<dyn crate::clock::Clock> = Arc::new(crate::clock::TokioClock::new());
        let mut last_error = None;
        for attempt in 1..=policy.max_attempts {
            if attempt > 1 {
                let shift = attempt.saturating_sub(2).min(31);
                let delay = policy
                    .initial_backoff
                    .saturating_mul(1_u32 << shift)
                    .min(policy.maximum_backoff);
                clock.sleep_until(clock.now().saturating_add(delay)).await;
            }
            let previous = self.generation.load_full();
            let future = async {
                let share = self.context.current_share_object().await?;
                if previous.belongs_to(share) {
                    return crate::Result::Ok(None);
                }
                let contexts: Vec<CreateContextRequest> = vec![
                    DurableHandleReconnectV2::new(
                        previous.file_id,
                        grant.create_guid,
                        grant.persistent,
                    )
                    .into(),
                ];
                let response = self
                    .context
                    .execute_request(
                        CommandRequest::new(
                            CreateRequest {
                                requested_oplock_level: OplockLevel::None,
                                impersonation_level: ImpersonationLevel::Impersonation,
                                desired_access: FileAccessMask::new(),
                                file_attributes: FileAttributes::new(),
                                share_access: ShareAccessFlags::new(),
                                create_disposition: CreateDisposition::Open,
                                create_options: CreateOptions::new(),
                                name: "".into(),
                                contexts: contexts.into(),
                            }
                            .into(),
                        ),
                        ResponseOptions::new().with_allow_async(true),
                    )
                    .await?
                    .message
                    .content
                    .to_create()?;
                if self.context.current_share_object().await? != share {
                    return Err(Error::InvalidState(
                        "Share changed during durable reconnect".into(),
                    ));
                }
                let object = self.context.create_resource_object_for(share).await?;
                crate::Result::Ok(Some(ResourceGeneration {
                    file_id: response.file_id,
                    object,
                    share,
                }))
            };
            match crate::session::recovery_attempt::run_bounded_attempt(
                clock.clone(),
                policy.attempt_timeout,
                future,
            )
            .await
            {
                Ok(Ok(Some(candidate))) => {
                    if let Some(slot) = &self.oplock_slot {
                        slot.replace(candidate.file_id, candidate.object);
                        self.context.register_oplock_slot(slot).await;
                    }
                    self.generation.store(Arc::new(candidate));
                    return Ok(());
                }
                Ok(Ok(None)) => return Ok(()),
                Ok(Err(error)) => {
                    tracing::warn!(attempt, ?error, "durable reconnect attempt failed");
                    last_error = Some(error);
                }
                Err(_) => {
                    tracing::warn!(attempt, "durable reconnect attempt timed out");
                    last_error = Some(Error::ResourceRecoveryWaitTimedOut);
                }
            }
        }
        Err(last_error
            .unwrap_or_else(|| Error::InvalidState("Durable Resource recovery is disabled".into())))
    }

    /// (Internal)
    ///
    /// Calculates the transaction size to use for a request,
    /// considering both the requested size (if any), the max transaction size,
    /// and the default transaction size.
    ///
    /// Prints a warning if the requested size exceeds the max transaction size.
    fn calc_transact_size(&self, requested: Option<usize>) -> u32 {
        let max_transact_size = self.conn_info.negotiation.max_transact_size;
        match requested {
            Some(requested_length) if requested_length > max_transact_size as usize => {
                tracing::warn!(
                    "Requested transaction size (0x{requested_length:x}) exceeds max transaction size, clamping to 0x{max_transact_size:x}",
                );
                max_transact_size
            }
            Some(len) => len as u32,
            None => max_transact_size.min(self.conn_info.config.default_transaction_size()),
        }
    }

    /// (Internal)
    ///
    /// Sends a Query Information Request and parses the response.
    async fn query_common(
        &self,
        mut req: QueryInfoRequest,
        output_buffer_length: Option<usize>,
        data_type: &'static str,
    ) -> crate::Result<QueryInfoData> {
        let buffer_length = self.calc_transact_size(output_buffer_length);
        req.output_buffer_length = buffer_length;

        let info_type = req.info_type;
        let result = self
            .execute_content(
                req.into(),
                ResponseOptions::new().with_status(&[
                    Status::Success,
                    Status::BufferOverflow,
                    Status::BufferTooSmall,
                    Status::InfoLengthMismatch,
                ]),
            )
            .await;

        match result {
            Ok(response) => {
                let status: Status = response.message.header.status.try_into().map_err(|_| {
                    Error::InvalidMessage(format!(
                        "Unknown status code: 0x{:08x}",
                        response.message.header.status
                    ))
                })?;
                match status {
                    Status::Success => {
                        Ok(response.message.content.to_queryinfo()?.parse(info_type)?)
                    }
                    Status::BufferOverflow | Status::InfoLengthMismatch => {
                        let required_size = response
                            .message
                            .content
                            .as_error()
                            .ok()
                            .and_then(|e| e.find_context(ErrorId::Default))
                            .map(|ctx| match status {
                                Status::BufferOverflow => crate::Result::Ok(ctx.as_u32()? as usize),
                                Status::InfoLengthMismatch => {
                                    crate::Result::Ok(ctx.as_u64()? as usize)
                                }
                                _ => unreachable!(),
                            })
                            .transpose()?;
                        Err(Error::BufferTooSmall {
                            data_type,
                            required: required_size,
                            provided: buffer_length as usize,
                        })
                    }
                    Status::BufferTooSmall => Err(Error::BufferTooSmall {
                        data_type,
                        required: None,
                        provided: buffer_length as usize,
                    }),
                    _ => unreachable!(), // already filtered by execute_content
                }
            }
            Err(e) => Err(e),
        }
    }

    /// (Internal)
    ///
    /// Sends a Set Information Request and parses the response.
    async fn set_info_common<T>(
        &self,
        data: T,
        cls: SetInfoClass,
        additional_info: AdditionalInfo,
    ) -> crate::Result<()>
    where
        T: Into<SetInfoData>,
    {
        let data = data
            .into()
            .to_req(cls, self.file_id().await?, additional_info);
        let response = self.send_receive(data.into()).await?;
        response.message.content.to_setinfo()?;
        Ok(())
    }

    /// Queries the file for information.
    /// # Type Parameters
    /// * `T` - The type of information to query. Must implement the [QueryFileInfoValue] trait.
    /// # Returns
    /// A `Result` containing the requested information.
    /// # Notes
    /// * use [`ResourceHandle::query_full_ea_info`] to query extended attributes information.
    pub async fn query_info<T>(&self) -> crate::Result<T>
    where
        T: QueryFileInfoValue,
    {
        let flags = QueryInfoFlags::new()
            .with_restart_scan(true)
            .with_return_single_entry(true);

        self.query_info_with_options::<T>(flags, None).await
    }

    /// Queries the file for information with additional arguments.
    /// # Type Parameters
    /// * `T` - The type of information to query. Must implement the [QueryFileInfoValue] trait.
    /// # Arguments
    /// * `flags` - The [QueryInfoFlags] for the query request.
    /// * `output_buffer_length` - An optional maximum output buffer to use. This should be less
    ///   than or equal to the negotiated max transaction size. If `None`, the default transaction size
    ///   will be used (see [`ConnectionConfig::default_transaction_size`][crate::ConnectionConfig::default_transaction_size]).
    /// # Returns
    /// A `Result` containing the requested information.
    /// # Notes
    /// * use [ResourceHandle::query_full_ea_info] to query extended attributes information.
    pub async fn query_info_with_options<T: QueryFileInfoValue>(
        &self,
        flags: QueryInfoFlags,
        output_buffer_length: Option<usize>,
    ) -> crate::Result<T> {
        let result: T = self
            .query_common(
                QueryInfoRequest {
                    info_type: InfoType::File,
                    info_class: QueryInfoClass::File(T::CLASS_ID),
                    output_buffer_length: 0,
                    additional_info: AdditionalInfo::new(),
                    flags,
                    file_id: self.file_id().await?,
                    data: GetInfoRequestData::None(()),
                },
                output_buffer_length,
                std::any::type_name::<T>(),
            )
            .await?
            .as_file()?
            .parse(T::CLASS_ID)?
            .try_into()?;
        Ok(result)
    }

    /// Queries the file for it's security descriptor.
    /// # Arguments
    /// * `additional_info` - The information to request on the security descriptor.
    /// # Returns
    /// A `Result` containing the requested information, of type [`SecurityDescriptor`].
    pub async fn query_security_info(
        &self,
        additional_info: AdditionalInfo,
    ) -> crate::Result<SecurityDescriptor> {
        self.query_security_info_with_options(additional_info, None)
            .await
    }

    /// Queries the file for it's security descriptor.
    /// # Arguments
    /// * `additional_info` - The information to request on the security descriptor.
    /// * `output_buffer_length` - An optional maximum output buffer to use. This should be less
    ///   than or equal to the negotiated max transaction size. If `None`, the default transaction size
    ///   will be used (see [`ConnectionConfig::default_transaction_size`][crate::ConnectionConfig::default_transaction_size]).
    /// # Returns
    /// A `Result` containing the requested information, of type [`SecurityDescriptor`].
    pub async fn query_security_info_with_options(
        &self,
        additional_info: AdditionalInfo,
        output_buffer_length: Option<usize>,
    ) -> crate::Result<SecurityDescriptor> {
        Ok(self
            .query_common(
                QueryInfoRequest {
                    info_type: InfoType::Security,
                    info_class: Default::default(),
                    output_buffer_length: 0,
                    additional_info,
                    flags: QueryInfoFlags::new(),
                    file_id: self.file_id().await?,
                    data: GetInfoRequestData::None(()),
                },
                output_buffer_length,
                "SecurityDescriptor",
            )
            .await?
            .as_security()?)
    }

    /// Sends an FSCTL message for the current resource (file) with additional options.
    /// # Type Parameters
    /// * `T` - The type of the request to send. Must implement the [`FsctlRequest`] trait.
    /// # Arguments
    /// * `request` - The request to send, which has an associated FSCTL code and data.
    /// * `max_input_response` - The maximum input response size.
    /// * `max_output_response` - The maximum output response size.
    /// # Returns
    /// A `Result` containing the requested information, as bound to [`FsctlRequest::Response`].
    pub async fn fsctl_with_options<T: FsctlRequest>(
        &self,
        request: T,
        max_output_response: u32,
    ) -> crate::Result<T::Response> {
        self.fsctl_with_operation(
            request,
            max_output_response,
            file::FileOperationOptions::default(),
        )
        .await
    }

    pub(crate) async fn fsctl_with_operation<T: FsctlRequest>(
        &self,
        request: T,
        max_output_response: u32,
        operation: file::FileOperationOptions,
    ) -> crate::Result<T::Response> {
        const NO_INPUT_IN_RESPONSE: u32 = 0;
        let request = CommandRequest::new(RequestContent::Ioctl(IoctlRequest {
            ctl_code: T::FSCTL_CODE as u32,
            file_id: self.file_id().await?,
            max_input_response: NO_INPUT_IN_RESPONSE,
            max_output_response,
            flags: IoctlRequestFlags::new().with_is_fsctl(true),
            buffer: request.into(),
        }));
        let mut options = ResponseOptions::new().with_allow_async(true);
        if let Some(timeout) = operation.timeout {
            options = options.with_timeout(timeout);
        }
        if let Some(cancellation) = operation.cancellation {
            options = options.with_cancellation_token(cancellation);
        }
        let ioctl_result = self
            .execute_request_with_replay(request, options, operation.replay)
            .await?
            .message
            .content
            .to_ioctl()?
            .parse_fsctl::<T::Response>()?;
        Ok(ioctl_result)
    }

    /// (Internal)
    async fn _ioctl(
        &self,
        ctl_code: u32,
        req_data: IoctlReqData,
        max_in: u32,
        max_out: u32,
        flags: IoctlRequestFlags,
    ) -> crate::Result<IoctlResponse> {
        let result = self
            .context
            .execute_content(
                RequestContent::Ioctl(IoctlRequest {
                    ctl_code,
                    file_id: self.file_id().await?,
                    max_input_response: max_in,
                    max_output_response: max_out,
                    flags,
                    buffer: req_data,
                }),
                ResponseOptions::new().with_allow_async(true),
            )
            .await?
            .message
            .content
            .to_ioctl()?;
        Ok(result)
    }

    /// Sets the file information for the current file.
    /// # Type Parameters
    /// * `T` - The type of information to set. Must implement the [SetFileInfoValue] trait.
    pub async fn set_info<T>(&self, info: T) -> crate::Result<()>
    where
        T: SetFileInfoValue,
    {
        self.set_info_common(
            RawSetInfoData::from(info.into()),
            T::CLASS_ID.into(),
            Default::default(),
        )
        .await
    }

    /// Sets the file system information for the current file.
    /// # Arguments
    /// * `info` - The information to set - a [SecurityDescriptor].
    /// * `additional_info` - The information that is set on the security descriptor.
    pub async fn set_security_info(
        &self,
        info: SecurityDescriptor,
        additional_info: AdditionalInfo,
    ) -> crate::Result<()> {
        self.set_info_common(
            info,
            SetInfoClass::Security(Default::default()),
            additional_info,
        )
        .await
    }

    /// (Internal)
    ///
    /// Sends a close request to the server for the given file ID.
    /// This should be called properly after taking out the file id (handle) from the resource instance,
    /// to avoid Use-after-free errors.
    async fn send_close(
        file_id: FileId,
        context: &Arc<TreeContext>,
        object: crate::runtime::ObjectToken,
    ) -> crate::Result<()> {
        tracing::trace!("Send close to file with ID: {file_id:?}");
        let response = context
            .send_recv_for(CloseRequest { file_id }.into(), object)
            .await?;
        tracing::debug!("Close response received for file ID: {file_id:?}, {response:?}");
        Ok(())
    }

    /// Closes the resource.
    /// The resource may not be used after calling this method.
    ///
    /// # Returns
    /// A `Result` indicating success or failure.
    #[tracing::instrument(level = "debug", skip_all, fields(name = %self.name))]
    pub async fn close(&self) -> crate::Result<()> {
        self.ensure_current().await?;
        if !self.open.swap(false, std::sync::atomic::Ordering::Relaxed) {
            return Err(Error::InvalidState("Resource is already closed".into()));
        }

        let generation = self.generation.load_full();
        tracing::debug!(file_id = ?generation.file_id, "Closing handle");
        Self::send_close(generation.file_id, &self.context, generation.object).await?;

        tracing::debug!("Closed");

        Ok(())
    }

    #[inline]
    async fn send_receive(
        &self,
        msg: RequestContent,
    ) -> crate::Result<crate::command::CommandResponse> {
        self.ensure_current().await?;
        self.context
            .send_recv_for(msg, self.generation.load().object)
            .await
    }

    #[inline]
    async fn execute_content(
        &self,
        msg: RequestContent,
        options: ResponseOptions<'_>,
    ) -> crate::Result<CommandResponse> {
        self.ensure_current().await?;
        self.context
            .execute_for(
                CommandRequest::new(msg),
                options,
                self.generation.load().object,
            )
            .await
            .map(|(_, incoming)| incoming)
    }

    async fn execute_request_with_replay(
        &self,
        msg: CommandRequest,
        options: ResponseOptions<'_>,
        replay: crate::runtime::ReplayPolicy,
    ) -> crate::Result<CommandResponse> {
        self.ensure_current().await?;
        self.context
            .execute_for_with_replay(msg, options, self.generation.load().object, replay)
            .await
            .map(|(_, incoming)| incoming)
    }
}

impl Drop for ResourceHandle {
    fn drop(&mut self) {
        if !self.open.swap(false, std::sync::atomic::Ordering::Relaxed) {
            // already closed, no problem
            return;
        }

        tracing::debug!("Dropped an open resource; wire cleanup requires explicit async close");
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{DurableOpenRequest, FileCreateArgs, ResourceGeneration, validate_durable_request};
    use crate::runtime::{GenerationId, ObjectEffect, ObjectKind, ObjectRegistry};
    use smb_dtyp::Guid;

    #[test]
    fn file_create_args_default_has_no_lease() {
        let args = FileCreateArgs::default();
        assert!(
            args.lease_request.is_none(),
            "default must not request a lease"
        );
    }

    #[test]
    fn persistent_open_requires_negotiated_support_and_a_ca_share() {
        let request = DurableOpenRequest::persistent(
            30_000,
            Guid::parse_uuid("00000000-0000-0000-0000-000000000007").unwrap(),
        );
        assert!(validate_durable_request(request, true, true, true).is_ok());
        assert!(validate_durable_request(request, true, false, true).is_err());
        assert!(validate_durable_request(request, true, true, false).is_err());
        assert!(validate_durable_request(request, false, true, true).is_err());
    }

    #[test]
    fn resource_detects_share_epoch_replacement_within_same_connection_generation() {
        let mut objects = ObjectRegistry::new(GenerationId::new(7));
        let connection = objects.connection();
        let session = objects
            .create_child(connection, ObjectKind::Session)
            .unwrap();
        let share = objects.create_child(session, ObjectKind::Share).unwrap();
        let object = objects.create_child(share, ObjectKind::Resource).unwrap();
        let resource = ResourceGeneration {
            file_id: Default::default(),
            object,
            share,
        };

        objects.begin_recovery(session).unwrap();
        let ObjectEffect::ReplacementPublished {
            replacement: replacement_session,
            ..
        } = objects.publish_replacement(session).unwrap()
        else {
            panic!("expected replacement session")
        };
        let replacement_share = objects
            .create_child(replacement_session, ObjectKind::Share)
            .unwrap();
        assert_eq!(share.generation(), replacement_share.generation());
        assert!(!resource.belongs_to(replacement_share));
        assert!(super::validate_create_parent_epoch(share, replacement_share).is_err());
    }
}
