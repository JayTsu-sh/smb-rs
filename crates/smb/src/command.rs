use bytes::Bytes;
use smb_msg::{Command, PlainRequest, PlainResponse, RequestContent, Status};
use tokio_util::sync::CancellationToken;

#[derive(Debug)]
pub struct CommandRequest {
    pub message: PlainRequest,

    pub return_raw_data: bool,

    /// Zero-copy write data. Stored as `Bytes` for cheap clone without copying.
    pub additional_data: Option<Bytes>,

    /// Channel ID to use for this message, if any.
    pub channel_id: Option<u32>,

    /// Explicit policy that must be sealed before entering the wire module.
    /// Channel submission derives it from Session state; connection-level
    /// negotiation and setup requests stamp `Protection::None` directly.
    pub(crate) security: Option<Protection>,

    /// The connection owner observed another ready operation in this
    /// admission turn, so the portable CMAC path may coalesce this request.
    pub(crate) cmac_batch_eligible: bool,
}

/// Explicit security treatment for an [`CommandRequest`].
///
/// Sealed by the caller or inferred by `ChannelContext::submit` before the
/// request crosses the wire seam, so
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
            cmac_batch_eligible: false,
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

    pub(crate) fn with_protection(mut self, protection: Protection) -> Self {
        self.security = Some(protection);
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
}

impl CommandResponse {
    pub fn new(message: PlainResponse, raw: Bytes, form: MessageForm) -> CommandResponse {
        CommandResponse { message, raw, form }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct MessageForm {
    pub compressed: bool,
    pub encrypted: bool,
    pub signed: bool,
    /// The server reported that the signing session no longer exists, so the
    /// frame is usable only as an untrusted hint to start recovery.
    pub unauthenticated_recovery_hint: bool,
}

impl MessageForm {
    pub fn signed_or_encrypted(&self) -> bool {
        self.signed || self.encrypted
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
            timeout: None,
        }
    }
}
