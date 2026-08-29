//! Typed domain-to-runtime operations for one connection generation.
//!
//! These types deliberately describe protocol intent rather than the old
//! send/receive pairing. Message identity, credit accounting, wire sealing,
//! response correlation, and terminal publication remain runtime concerns.

use crate::msg_handler::{IncomingMessage, OutgoingMessage};
use bytes::Bytes;
use smb_msg::{Command, Status};

use super::reducer::RequestKey;

/// Response contract sealed at operation construction. `AnyStatus` exists for
/// the temporary send/receive facade: the owner still validates command,
/// direction, framing, transforms, and correlation, while the facade applies
/// its caller-supplied status set when it awaits the result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResponsePolicy {
    command: Command,
    statuses: AcceptedStatuses,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum AcceptedStatuses {
    Any,
    OneOf(Box<[Status]>),
}

impl ResponsePolicy {
    pub(crate) fn one_of(
        command: Command,
        statuses: impl IntoIterator<Item = Status>,
    ) -> Result<Self, OperationContractError> {
        let statuses = statuses.into_iter().collect::<Box<[_]>>();
        if statuses.is_empty() {
            return Err(OperationContractError::EmptyStatusPolicy { command });
        }
        Ok(Self {
            command,
            statuses: AcceptedStatuses::OneOf(statuses),
        })
    }

    pub(crate) const fn any(command: Command) -> Self {
        Self {
            command,
            statuses: AcceptedStatuses::Any,
        }
    }

    pub(crate) const fn wire_command(&self) -> Command {
        self.command
    }

    pub(crate) fn accepts_status(&self, status: Status) -> bool {
        match &self.statuses {
            AcceptedStatuses::Any => true,
            AcceptedStatuses::OneOf(statuses) => statuses.contains(&status),
        }
    }
}

/// An owned operation submitted by the domain layer. The runtime stamps its
/// owner-allocated MessageId before the wire pipeline seals the request.
#[derive(Debug)]
pub(crate) struct TypedOperation {
    response: ResponsePolicy,
    outgoing: OutgoingMessage,
}

impl TypedOperation {
    pub(crate) fn new(
        outgoing: OutgoingMessage,
        response: ResponsePolicy,
    ) -> Result<Self, OperationContractError> {
        let actual = outgoing.message.content.associated_cmd();
        let expected = response.wire_command();
        if actual != expected {
            return Err(OperationContractError::CommandMismatch { expected, actual });
        }
        Ok(Self { response, outgoing })
    }

    pub(crate) fn any_status(outgoing: OutgoingMessage) -> Self {
        let command = outgoing.message.content.associated_cmd();
        Self {
            response: ResponsePolicy::any(command),
            outgoing,
        }
    }

    pub(crate) fn response_policy(&self) -> &ResponsePolicy {
        &self.response
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
        let expected = self.response.wire_command();
        if command != expected {
            return Err(OperationContractError::CommandMismatch {
                expected,
                actual: command,
            });
        }
        if !self.response.accepts_status(status) {
            return Err(OperationContractError::UnexpectedStatus { command, status });
        }
        Ok(())
    }
}

/// Successful typed exchange. Raw request bytes are retained only when the
/// operation asks for them (currently negotiation/preauth evidence).
#[derive(Debug)]
pub(crate) struct OperationResult {
    pub(crate) key: RequestKey,
    pub(crate) response: IncomingMessage,
    pub(crate) request_raw: Option<Bytes>,
}

impl OperationResult {
    pub(crate) fn into_incoming(self) -> IncomingMessage {
        self.response
    }
}

#[derive(Clone, Debug)]
pub(crate) struct OperationSubmission {
    pub(crate) key: RequestKey,
    pub(crate) request_raw: Option<Bytes>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum OperationContractError {
    #[error("typed operation expected {expected:?}, got {actual:?}")]
    CommandMismatch { expected: Command, actual: Command },
    #[error("typed operation {command:?} rejected response status {status:?}")]
    UnexpectedStatus { command: Command, status: Status },
    #[error("typed operation {command:?} requires at least one accepted status")]
    EmptyStatusPolicy { command: Command },
}

#[cfg(test)]
mod tests {
    use super::*;
    use smb_msg::{CancelRequest, RequestContent};

    #[test]
    fn constructor_rejects_a_command_mismatch() {
        let outgoing = OutgoingMessage::new(RequestContent::Cancel(CancelRequest::default()));
        let error = TypedOperation::new(
            outgoing,
            ResponsePolicy::one_of(Command::Negotiate, [Status::Success]).unwrap(),
        )
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
        let policy = ResponsePolicy::one_of(Command::Negotiate, [Status::Success]).unwrap();
        assert_eq!(policy.wire_command(), Command::Negotiate);
        assert!(policy.accepts_status(Status::Success));
        assert!(!policy.accepts_status(Status::MoreProcessingRequired));
    }

    #[test]
    fn session_setup_accepts_intermediate_and_final_status() {
        let policy = ResponsePolicy::one_of(
            Command::SessionSetup,
            [Status::MoreProcessingRequired, Status::Success],
        )
        .unwrap();
        assert_eq!(policy.wire_command(), Command::SessionSetup);
        assert!(policy.accepts_status(Status::MoreProcessingRequired));
        assert!(policy.accepts_status(Status::Success));
        assert!(!policy.accepts_status(Status::AccessDenied));
    }

    #[test]
    fn any_status_policy_supports_every_request_command_without_a_second_seam() {
        let operation = TypedOperation::any_status(OutgoingMessage::new(RequestContent::Cancel(
            CancelRequest::default(),
        )));
        assert_eq!(operation.response_policy().wire_command(), Command::Cancel);
        assert!(operation.response_policy().accepts_status(Status::Success));
        assert!(
            operation
                .response_policy()
                .accepts_status(Status::AccessDenied)
        );
    }
}
