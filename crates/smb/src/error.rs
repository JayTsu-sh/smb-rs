use std::{num::TryFromIntError, sync::PoisonError};

use smb_transport::TransportError;
use thiserror::Error;

use crate::{client::UncPath, connection::TransformError};
use smb_msg::{Command, ErrorResponse, Status};
use tokio::sync::AcquireError;

#[derive(Debug)]
pub enum TimedOutTask {
    ReceiveNextMessage,
    SessionReauthentication,
}

/// Fine-grained classification of session-setup failures.
///
/// These map the most common observable symptoms of an SMB SessionSetup
/// breaking down (timeout, unsigned response, etc.) onto the most
/// likely protocol-level root causes, so that users get an actionable
/// hint instead of a generic transport error.
#[derive(Error, Debug)]
pub enum SetupError {
    /// The server returned a final SessionSetup Response with no
    /// signature on a non-anonymous SMB 3.x session, in violation of
    /// MS-SMB2 §3.3.5.5.3. This is either a buggy server, or — more
    /// commonly — the connection-level preauth integrity hash
    /// diverged between client and server: each side then derives a
    /// different SigningKey and the server's response, while
    /// "correctly signed" by its computation, fails the client's
    /// verification, or vice versa.
    #[error(
        "Server returned an unsigned final SessionSetup Response on a non-anonymous \
         session. This is either a buggy server, or the preauth-integrity hash \
         diverged between client and server (each side would then derive a different \
         SigningKey)."
    )]
    UnsignedFinalResponse,

    /// SessionSetup phase timed out waiting for the server. The most
    /// likely root cause is a server-side silent drop of one of our
    /// requests: hardened servers (Windows AD DCs, Samba with
    /// `server signing = mandatory`, etc.) discard requests whose
    /// signing / preauth-hash policy doesn't match without ever
    /// replying. The timeout itself is indistinguishable from a real
    /// transport failure, but the surrounding setup state lets us
    /// surface this strong hint to the caller.
    #[error(
        "SessionSetup timed out after {elapsed:?} waiting for the server. Likely \
         cause: server silently dropped a SessionSetup Request — typical when (a) \
         the server enforces signing_required and the client failed to sign the \
         final SessionSetup Request, or (b) the connection-level preauth-integrity \
         hash diverged between client and server. Re-run with trace logging on \
         `smb::session::setup` to confirm which request the server stopped acknowledging."
    )]
    Timeout { elapsed: std::time::Duration },
}

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum Error {
    #[error("Unexpected Message, {0}")]
    InvalidMessage(String),
    #[error("IO Error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Binrw Error: {0}")]
    BinRWError(#[from] binrw::Error),
    #[error("Int parsing Error: {0}")]
    ParsingError(#[from] TryFromIntError),

    /// Indicates connection stopped - due to error or closed by user.
    /// See [`TransportError::NotConnected`] for transport-level disconnection.
    /// Usually, this is the actual error returned when trying to use a stopped connection, anyway.
    #[error("Client connection is stopped")]
    ConnectionStopped,

    #[error("Operation cancelled: {0}")]
    Cancelled(&'static str),

    #[error("Operation outcome is unknown because the request may have committed")]
    OutcomeUnknown,

    /// A transport failure or deadline ended a request whose effect may already have committed.
    #[error("Operation outcome is unknown after {0:?}")]
    NetworkOutcomeUnknown(NetworkFailure),

    #[error("The server invalidated the authenticated session")]
    SessionInvalidated,

    #[error("Operation admission is backpressured: {0}")]
    Backpressure(&'static str),

    #[error("The logical object is stale or revoked")]
    StaleObject,

    #[error("The request runtime terminated")]
    RuntimeTerminated,

    #[error("Session recovery wait queue is full")]
    SessionRecoveryQueueFull,

    #[error("Session recovery wait timed out")]
    SessionRecoveryWaitTimedOut,

    #[error("Share recovery wait queue is full")]
    ShareRecoveryQueueFull,

    #[error("Share recovery wait timed out")]
    ShareRecoveryWaitTimedOut,

    #[error("Resource recovery wait timed out")]
    ResourceRecoveryWaitTimedOut,

    #[error("{event} event queue exceeded its capacity of {capacity}")]
    EventQueueOverflow {
        event: &'static str,
        capacity: usize,
    },

    #[error("transfer failed at offset {offset} after {transferred} bytes: {source}")]
    TransferFailed {
        offset: u64,
        transferred: u64,
        source: Box<Error>,
    },

    #[error("Invalid state: {0}")]
    InvalidState(String),
    #[error("Unable to transform message: {0}")]
    TranformFailed(TransformError),
    #[error("Crypto error: {0}")]
    CryptoError(#[from] crate::crypto::CryptoError),

    /// Indicates that the negotiation phase of the SMB protocol failed.
    ///
    /// This might be due to incompatible protocol versions, unsupported features,
    /// or configuration issues between the client and server.
    #[error("Negotiation error: {0}")]
    NegotiationError(String),

    #[error("Signature verification failed!")]
    SignatureVerificationFailed,
    #[error("Unexpected message status: {}.", Status::try_display_as_status(*.0))]
    UnexpectedMessageStatus(u32),
    // TODO: This vs UnexpectedMessageStatus?!
    #[error("Server returned an error message with status: {}.", Status::try_display_as_status(*.0))]
    ReceivedErrorMessage(u32, ErrorResponse),
    #[error("Unexpected command: {0}")]
    UnexpectedMessageCommand(Command),
    #[error("Missing permissions to perform {0}")]
    MissingPermissions(String),

    /// Indicates an error sourced from the underlying authentication SSPI
    /// (Security Support Provider Interface) library.
    ///
    /// SSPI is used for handling authentication mechanisms like NTLM and Kerberos.
    ///
    /// For more references, see the [`sspi` crate documentation][sspi]
    #[error("Sspi error: {0}")]
    SspiError(#[from] sspi::Error),

    #[error("Provided buffer size too small to contain {data_type}")]
    BufferTooSmall {
        data_type: &'static str,
        required: Option<usize>,
        provided: usize,
    },

    #[error("Url parse error: {0}")]
    UrlParseError(#[from] url::ParseError),
    #[error("Unsupported authentication mechanism: {0}")]
    UnsupportedAuthenticationMechanism(String),
    #[error("Compression error: {0}")]
    CompressionError(#[from] crate::compression::CompressionError),
    #[error("Message processing failed. {0}")]
    MessageProcessingError(String),
    #[error("Operation timed out: {0:?}, took >{1:?}")]
    OperationTimeout(TimedOutTask, std::time::Duration),
    #[error("Lock error.")]
    LockError,
    #[error("Task join error.")]
    JoinError(#[from] tokio::task::JoinError),
    #[error("Acquire Error: {0}")]
    AcquireError(#[from] AcquireError),
    #[error("Unexpected message with ID {0} (exp {1}).")]
    UnexpectedMessageId(u64, u64),
    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),
    #[error("Invalid argument: {0}")]
    InvalidArgument(String),
    #[error("Unsupported operation: {0}")]
    UnsupportedOperation(String),
    #[error("Unable to perform DFS resolution: {0}")]
    DfsError(UncPath),
    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Channel {1} for session {0} not found.")]
    ChannelNotFound(u64, u32),

    #[error("RPC error: {0}")]
    RpcError(#[from] smb_rpc::SmbRpcError),
    #[error("SMB message error: {0}")]
    SmbMessageError(#[from] smb_msg::SmbMsgError),
    #[error("SMB FSCC error: {0}")]
    FsccError(#[from] smb_fscc::SmbFsccError),

    #[error("Transport error: {0}")]
    TransportError(#[from] TransportError),

    #[error("Other error: {0}")]
    Other(&'static str),

    /// Session-setup-phase failure with a protocol-level explanation.
    /// See [`SetupError`] for the recognised symptom → root-cause map.
    #[error(transparent)]
    Setup(#[from] SetupError),
}

impl<T> From<PoisonError<T>> for Error {
    fn from(_: PoisonError<T>) -> Self {
        Error::LockError
    }
}

/// Portable network failure categories for callers; protocol and permission errors remain distinct.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkFailure {
    ConnectionLost,
    TimedOut,
    SessionInvalidated,
}

impl Error {
    /// Classifies the structured error chain without inspecting server-controlled text.
    pub fn outcome_unknown(&self) -> bool {
        match self {
            Self::OutcomeUnknown | Self::NetworkOutcomeUnknown(_) => true,
            Self::TransferFailed { source, .. } => source.outcome_unknown(),
            _ => false,
        }
    }

    pub fn network_failure(&self) -> Option<NetworkFailure> {
        match self {
            Self::NetworkOutcomeUnknown(failure) => Some(*failure),
            Self::OperationTimeout(..)
            | Self::SessionRecoveryWaitTimedOut
            | Self::ShareRecoveryWaitTimedOut
            | Self::ResourceRecoveryWaitTimedOut
            | Self::Setup(SetupError::Timeout { .. }) => Some(NetworkFailure::TimedOut),
            Self::SessionInvalidated => Some(NetworkFailure::SessionInvalidated),
            Self::ConnectionStopped | Self::RuntimeTerminated => {
                Some(NetworkFailure::ConnectionLost)
            }
            Self::IoError(error) | Self::TransportError(TransportError::IoError(error)) => {
                match error.kind() {
                    std::io::ErrorKind::TimedOut => Some(NetworkFailure::TimedOut),
                    std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::UnexpectedEof
                    | std::io::ErrorKind::NotConnected
                    | std::io::ErrorKind::ConnectionRefused => Some(NetworkFailure::ConnectionLost),
                    _ => None,
                }
            }
            Self::TransportError(TransportError::Timeout(_)) => Some(NetworkFailure::TimedOut),
            Self::TransportError(TransportError::NotConnected | TransportError::WriteZero) => {
                Some(NetworkFailure::ConnectionLost)
            }
            Self::TransferFailed { source, .. } => source.network_failure(),
            _ => None,
        }
    }
}

#[cfg(test)]
mod network_failure_tests {
    use super::*;
    #[test]
    fn disconnect_and_timeout_are_distinct_and_protocol_errors_are_not_network_errors() {
        for kind in [
            std::io::ErrorKind::ConnectionReset,
            std::io::ErrorKind::UnexpectedEof,
            std::io::ErrorKind::BrokenPipe,
        ] {
            let error = Error::IoError(std::io::Error::new(kind, "redacted"));
            assert_eq!(
                error.network_failure(),
                Some(NetworkFailure::ConnectionLost)
            );
        }
        assert_eq!(
            Error::OperationTimeout(
                TimedOutTask::ReceiveNextMessage,
                std::time::Duration::from_secs(5)
            )
            .network_failure(),
            Some(NetworkFailure::TimedOut)
        );
        assert_eq!(
            Error::TransportError(TransportError::Timeout(std::time::Duration::from_secs(1)))
                .network_failure(),
            Some(NetworkFailure::TimedOut)
        );
        assert_eq!(
            Error::IoError(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "redacted"
            ))
            .network_failure(),
            Some(NetworkFailure::TimedOut)
        );
        assert_eq!(
            Error::SessionInvalidated.network_failure(),
            Some(NetworkFailure::SessionInvalidated)
        );
        assert_eq!(
            Error::InvalidMessage("redacted".into()).network_failure(),
            None
        );
        assert_eq!(
            Error::IoError(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
                .network_failure(),
            None
        );
    }
}
