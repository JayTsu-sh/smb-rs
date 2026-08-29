//! Typed domain-to-runtime operations for one connection generation.
//!
//! These types deliberately describe protocol intent rather than the old
//! send/receive pairing. Message identity, credit accounting, wire sealing,
//! response correlation, and terminal publication remain runtime concerns.

use crate::msg_handler::{IncomingMessage, OutgoingMessage};
use bytes::Bytes;
use smb_msg::{Command, Status};

use super::reducer::RequestKey;

/// Connection-bootstrap commands accepted by the first production runtime
/// cut-over. Tree and resource commands join the same seam in the next slice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BootstrapCommand {
    Negotiate,
    SessionSetup,
}

impl BootstrapCommand {
    pub(crate) const fn wire_command(self) -> Command {
        match self {
            Self::Negotiate => Command::Negotiate,
            Self::SessionSetup => Command::SessionSetup,
        }
    }

    pub(crate) const fn accepts_status(self, status: Status) -> bool {
        match self {
            Self::Negotiate => matches!(status, Status::Success),
            Self::SessionSetup => {
                matches!(status, Status::Success | Status::MoreProcessingRequired)
            }
        }
    }
}

/// An owned operation submitted by the domain layer. The runtime stamps its
/// owner-allocated MessageId before the wire pipeline seals the request.
#[derive(Debug)]
pub(crate) struct BootstrapOperation {
    command: BootstrapCommand,
    outgoing: OutgoingMessage,
}

impl BootstrapOperation {
    pub(crate) fn new(
        command: BootstrapCommand,
        outgoing: OutgoingMessage,
    ) -> Result<Self, OperationContractError> {
        let actual = outgoing.message.content.associated_cmd();
        let expected = command.wire_command();
        if actual != expected {
            return Err(OperationContractError::CommandMismatch { expected, actual });
        }
        Ok(Self { command, outgoing })
    }

    pub(crate) const fn command(&self) -> BootstrapCommand {
        self.command
    }

    pub(crate) fn payload_bytes(&self) -> u64 {
        self.outgoing
            .additional_data
            .as_ref()
            .map_or(0, |payload| payload.len() as u64)
    }

    pub(crate) fn into_outgoing(self) -> OutgoingMessage {
        self.outgoing
    }

    pub(crate) fn validate_response(
        &self,
        command: Command,
        status: Status,
    ) -> Result<(), OperationContractError> {
        let expected = self.command.wire_command();
        if command != expected {
            return Err(OperationContractError::CommandMismatch {
                expected,
                actual: command,
            });
        }
        if !self.command.accepts_status(status) {
            return Err(OperationContractError::UnexpectedStatus { command, status });
        }
        Ok(())
    }
}

/// Successful bootstrap exchange. Raw request bytes are retained only when
/// the operation asks for them (currently Negotiate preauth evidence).
#[derive(Debug)]
pub(crate) struct BootstrapResult {
    pub(crate) key: RequestKey,
    pub(crate) response: IncomingMessage,
    pub(crate) request_raw: Option<Bytes>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum OperationContractError {
    #[error("typed operation expected {expected:?}, got {actual:?}")]
    CommandMismatch { expected: Command, actual: Command },
    #[error("typed operation {command:?} rejected response status {status:?}")]
    UnexpectedStatus { command: Command, status: Status },
}

#[cfg(test)]
mod tests {
    use super::*;
    use smb_msg::{CancelRequest, RequestContent};

    #[test]
    fn constructor_rejects_a_command_mismatch() {
        let outgoing = OutgoingMessage::new(RequestContent::Cancel(CancelRequest::default()));
        let error = BootstrapOperation::new(BootstrapCommand::Negotiate, outgoing)
            .expect_err("mismatched command must be rejected before admission");
        assert_eq!(
            error,
            OperationContractError::CommandMismatch {
                expected: Command::Negotiate,
                actual: Command::Cancel,
            }
        );
    }

    #[test]
    fn negotiate_accepts_only_success() {
        assert_eq!(
            BootstrapCommand::Negotiate.wire_command(),
            Command::Negotiate
        );
        assert!(BootstrapCommand::Negotiate.accepts_status(Status::Success));
        assert!(!BootstrapCommand::Negotiate.accepts_status(Status::MoreProcessingRequired));
    }

    #[test]
    fn session_setup_accepts_intermediate_and_final_status() {
        assert_eq!(
            BootstrapCommand::SessionSetup.wire_command(),
            Command::SessionSetup
        );
        assert!(BootstrapCommand::SessionSetup.accepts_status(Status::MoreProcessingRequired));
        assert!(BootstrapCommand::SessionSetup.accepts_status(Status::Success));
        assert!(!BootstrapCommand::SessionSetup.accepts_status(Status::AccessDenied));
    }
}
