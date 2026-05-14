use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use maybe_async::*;
use smb_dtyp::SecurityDescriptor;
use smb_fscc::*;
use smb_msg::*;
use time::PrimitiveDateTime;

use crate::{
    Error,
    connection::connection_info::ConnectionInfo,
    lease::{LeaseSlot, ResourceProto, SlotReleaseAction},
    msg_handler::{
        AsyncMessageIds, HandlerReference, IncomingMessage, MessageHandler, OutgoingMessage,
        ReceiveOptions, SendMessageResult,
    },
    tree::TreeMessageHandler,
};

pub mod directory;
pub mod file;
pub mod file_util;
pub mod pipe;

pub use directory::*;
pub use file::*;
pub use file_util::*;
pub use pipe::*;

type Upstream = HandlerReference<TreeMessageHandler>;

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

    /// Returns arguments for creating a new file,
    /// with the default access set to Generic All.
    pub fn make_create_new(attributes: FileAttributes, options: CreateOptions) -> FileCreateArgs {
        FileCreateArgs {
            disposition: CreateDisposition::Create,
            attributes,
            options,
            desired_access: FileAccessMask::new().with_generic_all(true),
            ..Default::default()
        }
    }

    /// Returns arguments for creating a new file,
    /// with the default access set to Generic All.
    /// overwrites existing file, if it exists.
    pub fn make_overwrite(attributes: FileAttributes, options: CreateOptions) -> FileCreateArgs {
        FileCreateArgs {
            disposition: CreateDisposition::OverwriteIf,
            attributes,
            options,
            desired_access: FileAccessMask::new().with_generic_all(true),
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

    /// Attach a lease (`RqLs`) request to a create. Returns `self` for builder-style chaining.
    /// Caller must ensure the SMB connection negotiated the leasing capability;
    /// servers that don't support leasing will simply ignore the context.
    pub fn with_lease(mut self, lease: RequestLease) -> Self {
        self.lease_request = Some(lease);
        self
    }
}

/// A resource opened by a create request.
pub enum Resource {
    File(File),
    Directory(Directory),
    Pipe(Pipe),
}

impl Resource {
    #[maybe_async]
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

        // 标准 create context 列表：MxAc + QFid 始终发送；lease (RqLs) 仅在调用方显式
        // 请求时附加，保持现有非-lease 调用方零行为变化。
        let mut contexts: Vec<CreateContextRequest> = vec![
            QueryMaximalAccessRequest::default().into(),
            QueryOnDiskIdReq.into(),
        ];
        if let Some(lease_req) = create_args.lease_request.as_ref() {
            contexts.push(lease_req.clone().into());
        }

        // MS-SMB2 2.2.13: server 只在 RequestedOplockLevel = Lease (0xFF) 时把
        // `RqLs` context 当 lease 处理；任何其他值（含 None）都让 server 静默忽略。
        // 因此 lease 请求必须把 oplock level 同步切到 Lease。
        let requested_oplock_level = if create_args.lease_request.is_some() {
            OplockLevel::Lease
        } else {
            OplockLevel::None
        };

        let mut msg = OutgoingMessage::new(
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

        let response = upstream
            .sendo_recvo(msg, ReceiveOptions::new().with_allow_async(true))
            .await?;

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

        // 仅在 client 显式请求 lease 时才尝试解析 RqLs response context；server 未授予
        // (None) 与 client 未请求语义等价 —— 上层调用方都按"无 lease"处理。
        let lease_granted = if create_args.lease_request.is_some() {
            let grant = CreateContextResponseData::first_rqls(&response.create_contexts)
                .map(LeaseGrant::from_response);
            match &grant {
                Some(g) => tracing::debug!(
                    "Lease granted for '{}': key={:#034x}, state={:?}, epoch={}",
                    name, g.key, g.state, g.epoch
                ),
                None => tracing::debug!(
                    "Lease requested for '{}' but server did not grant one",
                    name
                ),
            }
            grant
        } else {
            None
        };

        // Common information is held in the handle object. `lease_slot`
        // defaults to None; if a lease was granted and the higher-level
        // client opts in, [`Client::_create_file`] will attach a slot via
        // [`Resource::attach_lease_slot`] after this function returns.
        let handle = ResourceHandle {
            name: name.to_string(),
            handler: ResourceMessageHandle::new(upstream),
            open: AtomicBool::new(true),
            _file_id: response.file_id,
            created: response.creation_time.date_time(),
            modified: response.last_write_time.date_time(),
            access,
            lease_granted,
            lease_slot: None,
            share_type,
            conn_info: conn_info.clone(),
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

    pub fn as_file(&self) -> Option<&File> {
        match self {
            Resource::File(f) => Some(f),
            _ => None,
        }
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

    /// Mutable counterpart to [`Resource::handle`]. Phase C uses this
    /// from [`Client::_create_file`] to attach a fresh lease slot to a
    /// resource that was just opened on the wire — once attached, the
    /// resource's `close()` and `Drop` participate in deferred-close.
    pub(crate) fn handle_mut(&mut self) -> Option<&mut ResourceHandle> {
        match self {
            Resource::File(f) => Some(&mut f.handle),
            Resource::Directory(d) => Some(&mut d.handle),
            Resource::Pipe(p) => Some(&mut p.handle),
        }
    }

    /// Phase C.3: install a lease slot on a freshly-created resource so
    /// its close/Drop will go through the deferred-close path. Called by
    /// [`Client::_create_file`] right after slot insertion in the
    /// connection's `lease_table`. Idempotent — overwriting an existing
    /// slot would be a logic bug (only the original Create attaches one),
    /// so we don't guard against it.
    pub(crate) fn attach_lease_slot(&mut self, slot: Arc<LeaseSlot>) {
        if let Some(h) = self.handle_mut() {
            h.lease_slot = Some(slot);
        }
    }

    /// Phase C.3: materialize a cache-hit resource from an existing
    /// `LeaseSlot`. Skips the wire `Create` entirely — the returned
    /// resource reuses the slot's `FileId`, handler chain, and creation
    /// metadata. The slot's refcount is *not* incremented here; the
    /// caller (`Client::_create_file`) must have already called
    /// [`LeaseSlot::try_acquire_for_reuse`] which performs the bump
    /// atomically with the eligibility check.
    pub(crate) fn reuse_from_slot(slot: Arc<LeaseSlot>) -> Resource {
        let proto = slot.proto.clone();
        let granted_state = slot
            .granted_state
            .read()
            .map(|s| *s)
            .unwrap_or_else(|p| *p.into_inner());

        let handle = ResourceHandle {
            name: slot.path.clone(),
            handler: proto.handler.clone(),
            open: AtomicBool::new(true),
            _file_id: slot.file_id,
            created: proto.created,
            modified: proto.modified,
            access: proto.access,
            lease_granted: Some(LeaseGrant {
                key: slot.lease_key,
                state: granted_state,
                epoch: proto.epoch_at_grant,
            }),
            lease_slot: Some(slot.clone()),
            share_type: proto.share_type,
            conn_info: proto.conn_info.clone(),
        };

        if proto.is_dir {
            Resource::Directory(Directory::new(handle))
        } else {
            match proto.share_type {
                ShareType::Disk => Resource::File(File::new(handle, proto.endof_file)),
                ShareType::Pipe => Resource::Pipe(Pipe::new(handle)),
                ShareType::Print => {
                    // Cache-hit on a Print share is impossible: print
                    // creates always use `CreateDisposition::Create`,
                    // which `try_acquire_for_reuse` rejects. Falling
                    // back to a File wrapper here keeps the type system
                    // happy without introducing a dead variant.
                    Resource::File(File::new(handle, proto.endof_file))
                }
            }
        }
    }

    /// Build a [`ResourceProto`] snapshot from a freshly-created resource
    /// and an `Upstream` reference. Phase C.1's slot-insert path now
    /// captures full reconstruction data here instead of the partial
    /// (file_id, lease_key, state) tuple it carried originally. Returns
    /// `None` only when the resource has no handle (shouldn't happen for
    /// successful creates today).
    ///
    /// `requested_access` must be the user-facing
    /// [`FileCreateArgs::desired_access`] from the originating Create
    /// (pre-server-expansion). Cache-hit eligibility compares the new
    /// caller's request against this, so passing the server-expanded
    /// mask here would cause spurious misses for `generic_*` requests.
    pub(crate) fn build_lease_proto(
        &self,
        upstream: &Upstream,
        requested_access: FileAccessMask,
    ) -> Option<Arc<ResourceProto>> {
        let h = self.handle()?;
        let endof_file = match self {
            Resource::File(f) => f.end_of_file(),
            _ => 0,
        };
        let is_dir = matches!(self, Resource::Directory(_));
        let epoch_at_grant = h.lease_granted.map(|g| g.epoch).unwrap_or(0);
        Some(Arc::new(ResourceProto {
            handler: ResourceMessageHandle::new(upstream),
            conn_info: h.conn_info.clone(),
            created: h.created,
            modified: h.modified,
            share_type: h.share_type,
            endof_file,
            is_dir,
            access: h.access,
            requested_access,
            epoch_at_grant,
        }))
    }

    pub fn as_dir(&self) -> Option<&Directory> {
        match self {
            Resource::Directory(d) => Some(d),
            _ => None,
        }
    }

    pub fn is_file(&self) -> bool {
        self.as_file().is_some()
    }

    pub fn is_dir(&self) -> bool {
        self.as_dir().is_some()
    }

    pub fn into_file(self) -> crate::Result<File> {
        match self {
            Resource::File(f) => Ok(f),
            _ => Err(Error::InvalidState("Resource is not a file".to_string())),
        }
    }

    pub fn into_dir(self) -> crate::Result<Directory> {
        match self {
            Resource::Directory(d) => Ok(d),
            _ => Err(Error::InvalidState(
                "Resource is not a directory".to_string(),
            )),
        }
    }

    #[deprecated(note = "Use into_file() which returns Result instead of panicking")]
    pub fn unwrap_file(self) -> File {
        match self {
            Resource::File(f) => f,
            other => panic!("Expected File, got {:?}", std::mem::discriminant(&other)),
        }
    }

    #[deprecated(note = "Use into_dir() which returns Result instead of panicking")]
    pub fn unwrap_dir(self) -> Directory {
        match self {
            Resource::Directory(d) => d,
            other => panic!(
                "Expected Directory, got {:?}",
                std::mem::discriminant(&other)
            ),
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

/// Information about a granted lease, extracted from the `RqLs` create-context
/// in a `CreateResponse`. Captures only the fields the client needs to track
/// the lease lifecycle; Phase B/C will key into [`ResourceHandle::lease_granted`]
/// when wiring break notifications and the lease_table cache.
///
/// `epoch == 0` is valid for either a v1 lease (no epoch field on the wire)
/// or a v2 lease whose server happens to start at epoch 0. Callers needing
/// to distinguish should compare against the `RequestLease` variant they sent.
#[derive(Debug, Clone, Copy)]
pub struct LeaseGrant {
    /// Client-generated key that identifies this lease.
    pub key: u128,
    /// The lease state actually granted by the server (may be a subset of
    /// what was requested).
    pub state: LeaseState,
    /// Epoch counter for state changes; `0` for v1 leases.
    pub epoch: u16,
}

impl LeaseGrant {
    /// Extract a [`LeaseGrant`] from a parsed `RqLs` response context.
    pub(crate) fn from_response(r: &RequestLease) -> Self {
        match r {
            RequestLease::RqLsReqv1(v1) => Self {
                key: v1.lease_key,
                state: v1.lease_state,
                epoch: 0,
            },
            RequestLease::RqLsReqv2(v2) => Self {
                key: v2.lease_key,
                state: v2.lease_state,
                epoch: v2.epoch,
            },
        }
    }
}

/// Holds the common information for an opened SMB resource.
pub struct ResourceHandle {
    name: String,
    handler: HandlerReference<ResourceMessageHandle>,

    // Whether the resource is open or not.
    // TODO: Consider using RwLock here on FileId instead of AtomicBool+FileId.
    open: AtomicBool,

    // Avoid accessing directly; use the `file_id()` getter,
    // that makes sure the resource is still open.
    _file_id: FileId,
    created: PrimitiveDateTime,
    modified: PrimitiveDateTime,
    share_type: ShareType,

    access: FileAccessMask,

    /// Granted lease for this open, when [`FileCreateArgs::lease_request`] was
    /// `Some` and the server replied with an `RqLs` response context.
    /// `None` when no lease was requested or the server didn't grant one.
    lease_granted: Option<LeaseGrant>,

    /// Phase C: when this handle is backed by a cached lease slot, close()
    /// and Drop release a refcount on the slot instead of sending a wire
    /// `Close`. The real `Close` is deferred until the slot is tombstoned
    /// *and* its refcount reaches zero. `None` for opens that didn't
    /// participate in the lease cache.
    lease_slot: Option<Arc<LeaseSlot>>,

    conn_info: Arc<ConnectionInfo>,
}

#[maybe_async(AFIT)]
impl ResourceHandle {
    /// Returns the name of the resource.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the creation time of the resource.
    pub fn created(&self) -> PrimitiveDateTime {
        self.created
    }

    /// Returns the last modified time of the resource.
    pub fn modified(&self) -> PrimitiveDateTime {
        self.modified
    }

    /// Returns the lease granted for this open, if any.
    ///
    /// Returns `None` when no lease was requested via
    /// [`FileCreateArgs::lease_request`], or when the server did not respond
    /// with an `RqLs` create context. Callers should treat `None` as
    /// "the open has no caching guarantees" and fall back to per-operation
    /// network round-trips.
    pub fn lease_granted(&self) -> Option<LeaseGrant> {
        self.lease_granted
    }

    /// Returns the server-assigned `FileId` for this open, *without* the
    /// "is-open" sanity check. Exposed for the lease-cache (Phase C):
    /// `Client::create_file` snapshots the FileId at Create time and
    /// installs it into the connection's `lease_table` so subsequent
    /// cache hits can reuse the same id. Callers should not use this
    /// FileId for direct I/O — go through the resource's typed methods.
    pub fn raw_file_id(&self) -> FileId {
        self._file_id
    }

    /// Returns the current share type of the resource. See [ShareType] for more details.
    pub fn share_type(&self) -> ShareType {
        self.share_type
    }

    /// Returns the handle of the resource.
    // This is implemented to be "inhrited" by Deref impl of resources impls, to avoid boilerplate code.
    pub fn handle(&self) -> &ResourceHandle {
        self
    }

    /// (Internal)
    ///
    /// Returns the file ID of the resource, ensuring the resource is still open.
    fn file_id(&self) -> crate::Result<FileId> {
        // The current design here allows the race condition over a close after this validation occurs.
        // therefore, this atomic load can be relaxed, and actual atomic compare and exchange are used
        // to avoid double close somehow.
        if !self.open.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(Error::InvalidState("Resource is closed".into()));
        }
        Ok(self._file_id)
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
    #[maybe_async]
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
            .send_recvo(
                req.into(),
                ReceiveOptions::new().with_status(&[
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
                    _ => unreachable!(), // already filtered by send_recvo
                }
            }
            Err(e) => Err(e),
        }
    }

    /// (Internal)
    ///
    /// Sends a Set Information Request and parses the response.
    #[maybe_async]
    async fn set_info_common<T>(
        &self,
        data: T,
        cls: SetInfoClass,
        additional_info: AdditionalInfo,
    ) -> crate::Result<()>
    where
        T: Into<SetInfoData>,
    {
        let data = data.into().to_req(cls, self.file_id()?, additional_info);
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

    /// Queries the file for extended attributes information.
    /// # Arguments
    /// * `names` - A list of extended attribute names to query.
    /// # Returns
    /// A `Result` containing the requested information, of type [QueryFileFullEaInformation].
    /// See [`ResourceHandle::query_info`] for more information.
    pub async fn query_full_ea_info(
        &self,
        names: Vec<&str>,
    ) -> crate::Result<QueryFileFullEaInformation> {
        self.query_full_ea_info_with_options(names, None).await
    }

    /// Queries the file for extended attributes information.
    ///
    /// The `output_buffer_length` should usually be the returned value from a prior
    /// [`FileEaInformation`] query, as it indicates the total size of all EAs.
    ///
    /// # Arguments
    /// * `names` - A list of extended attribute names to query.
    /// # Returns
    /// A `Result` containing the requested information, of type [QueryFileFullEaInformation].
    /// See [`ResourceHandle::query_info`] for more information.
    pub async fn query_full_ea_info_with_options(
        // TODO: Make this a nicer iterator (like Directory listing).
        &self,
        names: Vec<&str>,
        output_buffer_length: Option<usize>,
    ) -> crate::Result<QueryFileFullEaInformation> {
        let result = self
            .query_common(
                QueryInfoRequest {
                    info_type: InfoType::File,
                    info_class: QueryInfoClass::File(QueryFileInfoClass::FullEaInformation),
                    output_buffer_length: 0,
                    additional_info: AdditionalInfo::new(),
                    flags: QueryInfoFlags::new().with_restart_scan(true),
                    file_id: self.file_id()?,
                    data: GetInfoRequestData::EaInfo(GetEaInfoList {
                        values: names
                            .iter()
                            .map(|&s| FileGetEaInformation::new(s))
                            .collect(),
                    }),
                },
                output_buffer_length,
                std::any::type_name::<QueryFileFullEaInformation>(),
            )
            .await?
            .as_file()?
            .parse(QueryFileInfoClass::FullEaInformation)?
            .try_into()?;
        Ok(result)
    }

    /// Queries the file for information with additional arguments.
    /// # Type Parameters
    /// * `T` - The type of information to query. Must implement the [QueryFileInfoValue] trait.
    /// # Arguments
    /// * `flags` - The [QueryInfoFlags] for the query request.
    /// * `output_buffer_length` - An optional maximum output buffer to use. This should be less
    /// than or equal to the negotiated max transaction size. If `None`, the default transaction size
    /// will be used (see [`ConnectionConfig::default_transaction_size`][crate::ConnectionConfig::default_transaction_size]).
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
                    file_id: self.file_id()?,
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
    /// than or equal to the negotiated max transaction size. If `None`, the default transaction size
    /// will be used (see [`ConnectionConfig::default_transaction_size`][crate::ConnectionConfig::default_transaction_size]).
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
                    file_id: self.file_id()?,
                    data: GetInfoRequestData::None(()),
                },
                output_buffer_length,
                "SecurityDescriptor",
            )
            .await?
            .as_security()?)
    }

    /// Sends an FSCTL message for the current resource (file).
    /// # Type Parameters
    /// * `T` - The type of the request to send. Must implement the [`FsctlRequest`] trait.
    /// # Arguments
    /// * `request` - The request to send, which has an associated FSCTL code and data.
    /// # Returns
    /// A `Result` containing the requested information, as bound to [`FsctlRequest::Response`].
    pub async fn fsctl<T: FsctlRequest>(&self, request: T) -> crate::Result<T::Response> {
        const DEFAULT_RESPONSE_OUT_SIZE: u32 = 1024;
        self.fsctl_with_options(request, DEFAULT_RESPONSE_OUT_SIZE)
            .await
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
        const NO_INPUT_IN_RESPONSE: u32 = 0;
        let ioctl_result = self
            ._ioctl(
                T::FSCTL_CODE as u32,
                request.into(),
                NO_INPUT_IN_RESPONSE,
                max_output_response,
                IoctlRequestFlags::new().with_is_fsctl(true),
            )
            .await?
            .parse_fsctl::<T::Response>()?;
        Ok(ioctl_result)
    }

    /// Sends an IOCTL message for the current resource (file).
    /// # Arguments
    /// * `ctl_code` - The control code for the IOCTL request.
    /// * `request` - The request data to send.
    /// * `max_output_response` - The maximum output response size.
    /// # Returns
    /// A `Result` containing the response data as a vector of bytes.
    pub async fn ioctl(
        &self,
        ctl_code: u32,
        request: Vec<u8>,
        max_output_response: u32,
    ) -> crate::Result<Vec<u8>> {
        const NO_INPUT_IN_RESPONSE: u32 = 0;
        let response = self
            ._ioctl(
                ctl_code,
                IoctlReqData::Ioctl(request.into()),
                NO_INPUT_IN_RESPONSE,
                max_output_response,
                IoctlRequestFlags::new(),
            )
            .await?;
        Ok(response.out_buffer)
    }

    /// (Internal)
    #[maybe_async]
    async fn _ioctl(
        &self,
        ctl_code: u32,
        req_data: IoctlReqData,
        max_in: u32,
        max_out: u32,
        flags: IoctlRequestFlags,
    ) -> crate::Result<IoctlResponse> {
        let result = self
            .handler
            .send_recvo(
                RequestContent::Ioctl(IoctlRequest {
                    ctl_code,
                    file_id: self.file_id()?,
                    max_input_response: max_in,
                    max_output_response: max_out,
                    flags,
                    buffer: req_data,
                }),
                ReceiveOptions::new().with_allow_async(true),
            )
            .await?
            .message
            .content
            .to_ioctl()?;
        Ok(result)
    }

    /// Queries the file system information for the current file.
    /// # Type Parameters
    /// * `T` - The type of information to query. Must implement the [QueryFileSystemInfoValue] trait.
    /// # Returns
    /// A `Result` containing the requested information.
    pub async fn query_fs_info<T>(&self) -> crate::Result<T>
    where
        T: QueryFileSystemInfoValue,
    {
        self.query_fs_info_with_options(None).await
    }
    /// Queries the file system information for the current file.
    /// # Type Parameters
    /// * `T` - The type of information to query. Must implement the [QueryFileSystemInfoValue] trait.
    /// # Returns
    /// A `Result` containing the requested information.
    pub async fn query_fs_info_with_options<T>(
        &self,
        output_buffer_length: Option<usize>,
    ) -> crate::Result<T>
    where
        T: QueryFileSystemInfoValue,
    {
        if self.share_type != ShareType::Disk {
            return Err(crate::Error::InvalidState(
                "File system information is only available for disk files".into(),
            ));
        }
        let query_result: T = self
            .query_common(
                QueryInfoRequest {
                    info_type: InfoType::FileSystem,
                    info_class: QueryInfoClass::FileSystem(T::CLASS_ID),
                    output_buffer_length: 0,
                    additional_info: AdditionalInfo::new(),
                    flags: QueryInfoFlags::new()
                        .with_restart_scan(true)
                        .with_return_single_entry(true),
                    file_id: self.file_id()?,
                    data: GetInfoRequestData::None(()),
                },
                output_buffer_length,
                std::any::type_name::<T>(),
            )
            .await?
            .as_filesystem()?
            .parse(T::CLASS_ID)?
            .try_into()?;
        Ok(query_result)
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
    /// # Type Parameters
    /// * `T` - The type of information to set. Must implement the [SetFileSystemInfoValue] trait.
    pub async fn set_filesystem_info<T>(&self, info: T) -> crate::Result<()>
    where
        T: SetFileSystemInfoValue,
    {
        if self.share_type != ShareType::Disk {
            return Err(crate::Error::InvalidState(
                "File system information is only available for disk files".into(),
            ));
        }

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
    #[maybe_async]
    async fn send_close(
        file_id: FileId,
        handler: &HandlerReference<ResourceMessageHandle>,
    ) -> crate::Result<()> {
        tracing::trace!("Send close to file with ID: {file_id:?}");
        let response = handler.send_recv(CloseRequest { file_id }.into()).await?;
        tracing::debug!("Close response received for file ID: {file_id:?}, {response:?}");
        Ok(())
    }

    /// Phase C.5: pub(crate) entry point so the lease-eviction path in
    /// [`crate::Client::flush_eviction`] can send the deferred wire
    /// `Close` against a slot whose owning [`ResourceHandle`] is already
    /// gone (refcount was zero at evict time). The handler is pulled
    /// from `LeaseSlot::proto`, so the close goes through the same
    /// tree+session as the original Create.
    #[maybe_async]
    pub(crate) async fn send_close_external(
        file_id: FileId,
        handler: &HandlerReference<ResourceMessageHandle>,
    ) -> crate::Result<()> {
        Self::send_close(file_id, handler).await
    }

    /// Closes the resource.
    /// The resource may not be used after calling this method.
    ///
    /// # Phase C deferred-close
    ///
    /// When this handle is backed by a [`LeaseSlot`] (i.e. the original
    /// Create or a cache-hit reopen attached one), the wire `Close` is
    /// suppressed: we just flip `open = false` locally and release one
    /// refcount on the slot. The slot's FileId stays valid on the
    /// server, available for the next reopen on the same path.
    ///
    /// The real `Close` is sent only when [`LeaseSlot::release_one`]
    /// reports [`SlotReleaseAction::CloseAndEvict`] — i.e. *this* close
    /// dropped the refcount to zero *and* the slot has been tombstoned
    /// (server break or explicit eviction).
    ///
    /// # Returns
    /// A `Result` indicating success or failure.
    #[tracing::instrument(level = "debug", skip_all, fields(name = %self.name))]
    pub async fn close(&self) -> crate::Result<()> {
        if !self.open.swap(false, std::sync::atomic::Ordering::Relaxed) {
            return Err(Error::InvalidState("Resource is already closed".into()));
        }

        if let Some(slot) = self.lease_slot.as_ref() {
            match slot.release_one() {
                SlotReleaseAction::KeepCached => {
                    tracing::debug!(
                        path = %slot.path,
                        file_id = ?self._file_id,
                        "Deferred close: lease slot still cached",
                    );
                    return Ok(());
                }
                SlotReleaseAction::CloseAndEvict => {
                    tracing::debug!(
                        path = %slot.path,
                        file_id = ?self._file_id,
                        "Lease slot evicted; sending deferred Close on the wire",
                    );
                    // Fall through to the regular send_close path below.
                    // The connection-level lease_table cleanup happens on
                    // the next sweep (Phase C.5 flush_idle_leases) or on
                    // explicit Client::evict_lease — keeping the entry
                    // around briefly is harmless because tombstoned slots
                    // are not eligible for cache hits.
                }
            }
        }

        tracing::debug!(file_id = ?self._file_id, "Closing handle");
        Self::send_close(self._file_id, &self.handler).await?;

        tracing::debug!("Closed");

        Ok(())
    }

    #[maybe_async]
    #[inline]
    async fn send_receive(
        &self,
        msg: RequestContent,
    ) -> crate::Result<crate::msg_handler::IncomingMessage> {
        self.handler.send_recv(msg).await
    }

    #[maybe_async]
    #[inline]
    async fn send_recvo(
        &self,
        msg: RequestContent,
        options: ReceiveOptions<'_>,
    ) -> crate::Result<IncomingMessage> {
        self.handler
            .sendo_recvo(OutgoingMessage::new(msg), options)
            .await
    }

    #[maybe_async]
    #[inline]
    async fn sendo_recvo(
        &self,
        msg: OutgoingMessage,
        options: ReceiveOptions<'_>,
    ) -> crate::Result<IncomingMessage> {
        self.handler.sendo_recvo(msg, options).await
    }

    #[maybe_async]
    #[inline]
    pub async fn send_cancel(&self, msg_ids: &AsyncMessageIds) -> crate::Result<SendMessageResult> {
        let mut outgoing_message = OutgoingMessage::new(CancelRequest {}.into());
        outgoing_message.message.header.message_id = msg_ids.msg_id.load(Ordering::Relaxed);
        outgoing_message
            .message
            .header
            .to_async(msg_ids.async_id.load(Ordering::Relaxed));

        self.handler.sendo(outgoing_message).await
    }

    /// Returns whether current resource is opened from the same tree as the other resource.
    /// This is useful to check if two resources are opened from the same share instance.
    ///
    /// # Note
    /// * Even if a resource is positioned in the same tree, if the tree was accessed using different
    ///   share connections, this will return false!
    pub fn same_tree(&self, other: &Self) -> bool {
        Arc::ptr_eq(
            &self.handler.upstream.handler,
            &other.handler.upstream.handler,
        )
    }
}

// `pub(crate)` so [`crate::lease::ResourceProto`] can hold a `HandlerReference`
// to it across the cache-hit reconstruction path. The type itself remains
// invisible to external callers — they only interact through `Resource`.
pub(crate) struct ResourceMessageHandle {
    upstream: Upstream,
}

impl ResourceMessageHandle {
    pub(crate) fn new(upstream: &Upstream) -> HandlerReference<ResourceMessageHandle> {
        HandlerReference::new(ResourceMessageHandle {
            upstream: upstream.clone(),
        })
    }
}

impl MessageHandler for ResourceMessageHandle {
    #[maybe_async]
    #[inline]
    async fn sendo(
        &self,
        msg: crate::msg_handler::OutgoingMessage,
    ) -> crate::Result<crate::msg_handler::SendMessageResult> {
        self.upstream.sendo(msg).await
    }

    #[maybe_async]
    #[inline]
    async fn recvo(
        &self,
        options: crate::msg_handler::ReceiveOptions<'_>,
    ) -> crate::Result<crate::msg_handler::IncomingMessage> {
        self.upstream.recvo(options).await
    }
}

#[cfg(not(feature = "async"))]
impl Drop for ResourceHandle {
    fn drop(&mut self) {
        let file_id = self.file_id();
        if file_id.is_err() {
            return;
        }

        tracing::warn!(
            "ResourceHandle for '{}' ({}) is being dropped without closing it properly. This may lead to resource leaks.",
            self.name,
            self._file_id
        );
    }
}

#[cfg(feature = "async")]
impl Drop for ResourceHandle {
    fn drop(&mut self) {
        if !self.open.swap(false, std::sync::atomic::Ordering::Relaxed) {
            // already closed, no problem
            return;
        }

        // Phase C: if a lease slot is in play, decrement its refcount and
        // only send the wire `Close` when this drop made the slot
        // releasable (refcount=0 AND tombstoned). Otherwise the FileId
        // stays alive for the next cache hit.
        if let Some(slot) = self.lease_slot.as_ref() {
            match slot.release_one() {
                SlotReleaseAction::KeepCached => {
                    tracing::debug!(
                        path = %slot.path,
                        file_id = ?self._file_id,
                        "Drop: lease slot retained (not tombstoned or refs remain)",
                    );
                    return;
                }
                SlotReleaseAction::CloseAndEvict => {
                    tracing::debug!(
                        path = %slot.path,
                        file_id = ?self._file_id,
                        "Drop: lease slot evicted; scheduling wire Close",
                    );
                    // Fall through to the legacy spawn-Close branch below.
                }
            }
        }

        let file_id = self._file_id;
        let handler = self.handler.clone();
        tracing::debug!("Spawning task to close file with ID: {file_id:?}");
        tokio::task::spawn(async move {
            if file_id != FileId::EMPTY {
                if let Err(e) = Self::send_close(file_id, &handler).await {
                    tracing::error!("Error closing file: {e}");
                }
            }
        });
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    // `use maybe_async::*;` at the file top brings a `test` macro into our parent
    // scope, which conflicts with the standard `#[test]` attribute. Pull the
    // standard one in explicitly so attribute resolution is unambiguous.
    #[allow(unused_imports)]
    use core::prelude::v1::test;

    use super::{FileCreateArgs, LeaseGrant};
    use smb_fscc::FileAccessMask;
    use smb_msg::{LeaseFlags, LeaseState, RequestLease, RequestLeaseV1, RequestLeaseV2};

    fn make_state(read: bool, handle: bool, write: bool) -> LeaseState {
        LeaseState::new()
            .with_read_caching(read)
            .with_handle_caching(handle)
            .with_write_caching(write)
    }

    #[test]
    fn lease_grant_from_v1() {
        let v1 = RequestLeaseV1 {
            lease_key: 0x1122_3344_5566_7788_99AA_BBCC_DDEE_FF00_u128,
            lease_state: make_state(true, true, false),
        };
        let grant = LeaseGrant::from_response(&RequestLease::RqLsReqv1(v1));
        assert_eq!(grant.key, 0x1122_3344_5566_7788_99AA_BBCC_DDEE_FF00_u128);
        assert!(grant.state.read_caching());
        assert!(grant.state.handle_caching());
        assert!(!grant.state.write_caching());
        assert_eq!(grant.epoch, 0, "v1 lease has no epoch field");
    }

    #[test]
    fn lease_grant_from_v2() {
        let v2 = RequestLeaseV2 {
            lease_key: 0xDEAD_BEEF_CAFE_BABE_1234_5678_9ABC_DEF0_u128,
            lease_state: make_state(true, true, true),
            lease_flags: LeaseFlags::new().with_parent_lease_key_set(true),
            parent_lease_key: 0x0EDC_BA98_7654_3210_FEDC_BA98_7654_3210_u128,
            epoch: 0x1337,
        };
        let grant = LeaseGrant::from_response(&RequestLease::RqLsReqv2(v2));
        assert_eq!(grant.key, 0xDEAD_BEEF_CAFE_BABE_1234_5678_9ABC_DEF0_u128);
        assert!(grant.state.read_caching());
        assert!(grant.state.handle_caching());
        assert!(grant.state.write_caching());
        assert_eq!(grant.epoch, 0x1337);
    }

    #[test]
    fn file_create_args_with_lease_builder() {
        let args = FileCreateArgs::make_open_existing(FileAccessMask::new().with_generic_read(true))
            .with_lease(RequestLease::RqLsReqv2(RequestLeaseV2 {
                lease_key: 1,
                lease_state: make_state(true, true, false),
                lease_flags: LeaseFlags::new(),
                parent_lease_key: 0,
                epoch: 0,
            }));
        assert!(args.lease_request.is_some(), "with_lease should populate the field");
        assert!(matches!(
            args.lease_request.as_ref().unwrap(),
            RequestLease::RqLsReqv2(_)
        ));
    }

    #[test]
    fn file_create_args_default_has_no_lease() {
        let args = FileCreateArgs::default();
        assert!(args.lease_request.is_none(), "default must not request a lease");
    }
}
