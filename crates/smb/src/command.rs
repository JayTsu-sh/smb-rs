use bytes::Bytes;
use smb_msg::{Command, PlainRequest, PlainResponse, RequestContent, Status};
use std::sync::{Arc, atomic::AtomicU64};
use tokio_util::sync::CancellationToken;

#[derive(Debug)]
pub struct CommandRequest {
    pub message: PlainRequest,

    pub return_raw_data: bool,

    /// Zero-copy write data. Stored as `Bytes` for cheap clone without copying.
    pub additional_data: Option<Bytes>,

    /// Channel ID to use for this message, if any.
    pub channel_id: Option<u32>,

    /// Internal: explicit, sealed-at-construction safety policy.
    /// Producers stamp this directly (`tree.submit` for share-level
    /// encrypt_data; session-setup driver for `SnapshotKdfSign`); the
    /// channel layer fills in the default for any message that
    /// arrives with `None` based on session state. Once set, the
    /// wire pipeline dispatches purely on this enum without inspecting
    /// other mutable state — eliminating the class of bug where the
    /// state inference looked at `session.state` to decide and got it
    /// wrong (e.g. the Windows-DC unsigned-final-request regression).
    pub(crate) security: Option<Protection>,
}

/// Explicit security treatment for an [`CommandRequest`].
///
/// Sealed at construction by the caller (or, for legacy paths,
/// inferred by `ChannelContext::submit` from session state and
/// stamped into the message before it leaves the channel layer), so
/// the wire pipeline can dispatch purely on this enum without
/// inspecting other mutable state.
#[derive(Debug, Clone)]
pub enum Protection {
    /// No transport-layer protection. Used for Negotiate and the
    /// pre-channel SessionSetup exchanges where signing keys don't
    /// yet exist, plus anonymous / guest sessions where signing is
    /// allowed to be skipped.
    None,
    /// Sign this request with the channel's cached signer (the
    /// production wire-secured path). Looked up from
    /// `session_state.channel.signer` at sign time.
    SignWithChannel,
    /// Sign this request with a one-shot key derived from the given
    /// GSS-supplied SessionKey and the wire pipeline's currently
    /// finalized preauth hash (after the request's own plain bytes
    /// are ingested). Used exclusively for the final SessionSetup
    /// Request — see MS-SMB2 §3.3.5.5.3.
    SnapshotKdfSign {
        session_key: crate::crypto::KeyToDerive,
    },
    /// Encrypt this request with the session's cached encryptor.
    /// Mutually exclusive with the signing variants per MS-SMB2
    /// §3.1.4.1 (a transport-encrypted message carries its
    /// confidentiality MAC, no separate signature).
    Encrypt,
}

impl CommandRequest {
    pub fn new(content: RequestContent) -> CommandRequest {
        CommandRequest {
            message: PlainRequest::new(content),
            return_raw_data: false,
            additional_data: None,
            channel_id: None,
            security: None,
        }
    }

    pub fn with_additional_data(mut self, data: Bytes) -> Self {
        self.additional_data = Some(data);
        self
    }

    pub fn with_return_raw_data(mut self, return_raw_data: bool) -> Self {
        self.return_raw_data = return_raw_data;
        self
    }

    pub fn with_channel_id(mut self, channel_id: Option<u32>) -> Self {
        self.channel_id = channel_id;
        self
    }

    /// Internal: stamp `header.flags.signed = true` on a message that
    /// the session-setup driver is about to hand to
    /// [`ConnectionCore::dispatch_outgoing`] directly
    /// (bypassing [`ConnectionCore::submit`]). This is the
    /// final SessionSetup Request path, where the driver has manually
    /// run `prepare_outgoing` and installed a channel SigningKey via
    /// `make_channel`; the wire pipeline's signing path keys off
    /// `flags.signed`, so this flip is what makes the request
    /// wire-signed.
    #[doc(hidden)]
    pub fn into_signed(mut self) -> Self {
        self.message.header.flags.set_signed(true);
        self
    }
}

#[derive(Debug)]
pub struct CommandSubmission {
    // The message ID for the sent message.
    pub msg_id: u64,
    // If finalized, this is set.
    pub raw: Option<Bytes>,
}

impl CommandSubmission {
    pub fn new(msg_id: u64, raw: Option<Bytes>) -> CommandSubmission {
        CommandSubmission { msg_id, raw }
    }
}

#[derive(Debug)]
pub struct CommandResponse {
    pub message: PlainResponse,
    /// The raw message bytes received from the server, after applying transformations
    /// (e.g. decryption, decompression). Stored as `Bytes` for zero-copy slicing.
    pub raw: Bytes,

    // How did the message arrive?
    pub form: MessageForm,

    pub source_channel_id: Option<u32>,
}

impl CommandResponse {
    pub fn new(message: PlainResponse, raw: Bytes, form: MessageForm) -> CommandResponse {
        CommandResponse {
            message,
            raw,
            form,
            source_channel_id: None,
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct MessageForm {
    pub compressed: bool,
    pub encrypted: bool,
    pub signed: bool,
}

impl MessageForm {
    pub fn signed_or_encrypted(&self) -> bool {
        self.signed || self.encrypted
    }
}

#[derive(Debug)]
pub struct AsyncMessageIds {
    pub msg_id: AtomicU64,
    pub async_id: AtomicU64,
}

impl AsyncMessageIds {
    pub fn reset(&self) {
        self.set(u64::MAX, u64::MAX);
    }
    pub fn set(&self, msg_id: u64, async_id: u64) {
        self.msg_id
            .store(msg_id, std::sync::atomic::Ordering::Relaxed);
        self.async_id
            .store(async_id, std::sync::atomic::Ordering::Relaxed);
    }
}

impl Default for AsyncMessageIds {
    fn default() -> Self {
        Self {
            msg_id: AtomicU64::new(u64::MAX),
            async_id: AtomicU64::new(u64::MAX),
        }
    }
}

/// Options for receiving a message.
///
/// Use a builder pattern to set the options:
/// ```ignore
/// use smb_msg::*;
/// use smb::command::ResponseOptions;
///
/// let options = ResponseOptions::new()
///    .with_status(&[Status::Success])
///    .with_cmd(Some(Command::Negotiate));
/// ```
#[derive(Debug, Clone)]
pub struct ResponseOptions<'a> {
    /// The expected status(es) of the received message.
    /// If the received message has a different status, an error will be returned.
    pub status: &'a [Status],

    /// If set, this command will be checked against the received command.
    /// If not set, no check will be performed.
    pub cmd: Option<Command>,

    /// When receiving a message, only messages with this msg_id will be returned.
    /// This is mostly used for async message handling, where the client is waiting for a specific message.
    pub msg_id: u64,

    /// The channel ID to receive messages from, if any.
    pub channel_id: Option<u32>,

    /// Whether to allow (and wait for) async responses.
    /// If set to false, an async response from the server will trigger an error.
    /// If set to true, the handler will allow async messages to be received,
    /// and will make the caller wait until the final async response is received --
    /// the async response with status other than [`Status::Pending`].
    ///
    /// When using crate feature `async`, see [`async_cancel`][Self::async_cancel].
    pub allow_async: bool,

    /// An optional cancellation token to cancel the receive operation,
    /// if it's an async operation.
    pub async_cancel: Option<CancellationToken>,

    /// An optional atomic u64 to update with a message ID + async ID that is being
    /// waited for. This is useful for tracking the async message ID
    /// across multiple threads.
    pub async_msg_ids: Option<Arc<AsyncMessageIds>>,

    /// A timeout for the receive operation.
    /// If not set, the default timeout of the connection is used.
    pub timeout: Option<std::time::Duration>,
}

impl<'a> ResponseOptions<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_status(mut self, status: &'a [Status]) -> Self {
        self.status = status;
        self
    }

    pub fn with_cmd(mut self, cmd: Option<Command>) -> Self {
        self.cmd = cmd;
        self
    }

    pub fn with_msg_id_filter(mut self, msg_id: u64) -> Self {
        self.msg_id = msg_id;
        self
    }

    pub fn with_allow_async(mut self, allow_async: bool) -> Self {
        self.allow_async = allow_async;
        self
    }

    pub fn with_cancellation_token(mut self, token: CancellationToken) -> Self {
        self.async_cancel = Some(token);
        self
    }

    pub fn with_async_msg_ids(mut self, async_msg_ids: Arc<AsyncMessageIds>) -> Self {
        self.async_msg_ids = Some(async_msg_ids);
        self
    }

    pub fn with_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }
}

impl<'a> Default for ResponseOptions<'a> {
    fn default() -> Self {
        ResponseOptions {
            status: &[Status::Success],
            cmd: None,
            msg_id: 0,
            allow_async: false,
            channel_id: None,
            async_cancel: None,
            async_msg_ids: None,
            timeout: None,
        }
    }
}
