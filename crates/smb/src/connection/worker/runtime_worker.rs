use crate::clock::{Clock, TokioClock};
use crate::connection::connection_info::ConnectionInfo;
use crate::connection::preauth_hash::PreauthHashValue;
use crate::error::TimedOutTask;
use crate::command::{CommandResponse, CommandRequest, ResponseOptions, CommandSubmission};
use crate::runtime::{
    GenerationExit, GenerationId, ObjectKind, ObjectToken, OperationResult, RequestKey,
    ResponsePolicy, RuntimeConfig, RuntimeError, RuntimeHandle, TerminalOutcome, TypedOperation,
    start_generation,
};
use crate::session::SessionAndChannel;
use crate::{Error, Result};
use smb_transport::SmbTransport;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

/// Temporary outer-shape facade over the W3 generation runtime.
///
/// It owns no transport, pending registry, credit ledger, MessageId counter,
/// or background task. All authoritative work is delegated to RuntimeHandle;
/// this type disappears when domain callers adopt typed operations directly.
pub(crate) struct RuntimeWorker {
    runtime: RuntimeHandle,
    clock: Arc<TokioClock>,
    generation: GenerationId,
    timeout: Duration,
}

impl RuntimeWorker {
    pub(crate) const fn connection_object(&self) -> ObjectToken {
        self.runtime.connection_object()
    }

    pub(crate) async fn create_object(
        &self,
        parent: ObjectToken,
        kind: ObjectKind,
    ) -> Result<ObjectToken> {
        self.runtime
            .create_object(parent, kind)
            .await
            .map_err(|error| self.map_runtime_error(error))
    }

    pub(crate) async fn start_generation_at(
        transport: Box<dyn SmbTransport>,
        timeout: Duration,
        initial_message_id: u64,
        target_credits: u32,
        generation: GenerationId,
    ) -> Result<Arc<Self>> {
        let clock = Arc::new(TokioClock::new());
        let config = RuntimeConfig::production(
            generation,
            initial_message_id,
            1,
            target_credits,
            timeout,
        );
        let (runtime, _events) = start_generation(transport, clock.clone(), config);
        Ok(Arc::new(Self {
            runtime,
            clock,
            generation,
            timeout,
        }))
    }

    pub(crate) fn runtime_handle(&self) -> RuntimeHandle {
        self.runtime.clone()
    }

    pub(crate) async fn exited(&self) -> GenerationExit {
        self.runtime.exited().await
    }

    pub(crate) async fn stop(&self) -> Result<()> {
        self.runtime
            .close(self.clock.now().saturating_add(self.timeout))
            .await
            .map(|_| ())
            .map_err(|error| self.map_runtime_error(error))
    }

    pub(crate) async fn send(&self, message: CommandRequest) -> Result<CommandSubmission> {
        self.send_for(message, self.connection_object()).await
    }

    pub(crate) async fn send_for(
        &self,
        message: CommandRequest,
        dependency: ObjectToken,
    ) -> Result<CommandSubmission> {
        let deadline = self.clock.now().saturating_add(self.timeout);
        let submission = self
            .runtime
            .submit_operation_detached(
                TypedOperation::any_status(message).with_dependency(dependency),
                Some(deadline),
            )
            .await
            .map_err(|error| self.map_runtime_error(error))?;
        Ok(CommandSubmission::new(
            submission.key.message_id,
            submission.request_raw,
        ))
    }

    pub(crate) async fn execute_for(
        &self,
        message: CommandRequest,
        options: &ResponseOptions<'_>,
        dependency: ObjectToken,
    ) -> Result<(CommandSubmission, CommandResponse)> {
        let command = options
            .cmd
            .unwrap_or_else(|| message.message.content.associated_cmd());
        let policy = ResponsePolicy::one_of(command, options.status.iter().copied())
            .map_err(|error| Error::InvalidArgument(error.to_string()))?;
        let operation = TypedOperation::new(message, policy)
            .map_err(|error| Error::InvalidArgument(error.to_string()))?
            .with_dependency(dependency);
        let timeout = options.timeout.unwrap_or(self.timeout);
        let deadline = self.clock.now().saturating_add(timeout);
        let ticket = self
            .runtime
            .submit_operation(operation, Some(deadline))
            .await
            .map_err(|error| self.map_runtime_error(error))?;
        let key = ticket.key;
        let completion = ticket.completion();
        tokio::pin!(completion);
        let result = if let Some(cancellation) = &options.async_cancel {
            tokio::select! {
                biased;
                _ = cancellation.cancelled() => {
                    self.runtime
                        .cancel(key, self.clock.now())
                        .map_err(|error| self.map_runtime_error(error))?;
                    return Err(Error::Cancelled("runtime operation"));
                }
                result = &mut completion => result,
            }
        } else {
            completion.await
        }
        .map_err(|error| self.map_runtime_error(error))?;
        Ok((
            CommandSubmission::new(result.key.message_id, result.request_raw),
            result.response,
        ))
    }

    pub(crate) async fn receive(&self, options: &ResponseOptions<'_>) -> Result<CommandResponse> {
        if options.msg_id == u64::MAX {
            return Err(Error::InvalidArgument(
                "Message ID -1 is not valid for receive()".to_string(),
            ));
        }
        let key = RequestKey::new(self.generation, options.msg_id);
        let wait = self.runtime.await_operation(key);
        tokio::pin!(wait);
        let result = if let Some(cancellation) = &options.async_cancel {
            tokio::select! {
                biased;
                _ = cancellation.cancelled() => {
                    self.runtime
                        .cancel(key, self.clock.now())
                        .map_err(|error| self.map_runtime_error(error))?;
                    return Err(Error::Cancelled("receive"));
                }
                result = &mut wait => result,
            }
        } else {
            wait.await
        };
        result
            .map(OperationResult::into_incoming)
            .map_err(|error| self.map_runtime_error(error))
    }

    pub(crate) async fn negotaite_complete(&self, info: &Arc<ConnectionInfo>) -> Result<()> {
        self.runtime
            .negotiated(info.clone())
            .await
            .map_err(|error| self.map_runtime_error(error))
    }

    pub(crate) async fn session_started(&self, info: &Arc<SessionAndChannel>) -> Result<()> {
        self.runtime
            .session_started(info.clone())
            .await
            .map_err(|error| self.map_runtime_error(error))
    }

    pub(crate) async fn session_ended(&self, info: &Arc<SessionAndChannel>) -> Result<()> {
        self.runtime
            .session_ended(info.clone())
            .await
            .map_err(|error| self.map_runtime_error(error))
    }

    pub(crate) async fn preauth_snapshot(&self) -> Result<Option<PreauthHashValue>> {
        self.runtime
            .preauth_snapshot()
            .await
            .map_err(|error| self.map_runtime_error(error))
    }

    pub(crate) fn start_notify_channel(
        self: &Arc<Self>,
        sender: tokio::sync::mpsc::Sender<CommandResponse>,
    ) -> Result<()> {
        self.runtime
            .install_notifications(sender)
            .map_err(|error| self.map_runtime_error(error))
    }

    pub(crate) async fn send_compound_for(
        self: &Arc<Self>,
        messages: Vec<CommandRequest>,
        dependency: ObjectToken,
    ) -> Result<Vec<CommandSubmission>> {
        let operations = messages
            .into_iter()
            .map(|message| {
                TypedOperation::any_status(message).with_dependency(dependency)
            })
            .collect();
        self.runtime
            .submit_compound_detached(
                operations,
                Some(self.clock.now().saturating_add(self.timeout)),
            )
            .await
            .map(|submissions| {
                submissions
                    .into_iter()
                    .map(|submission| {
                        CommandSubmission::new(submission.key.message_id, submission.request_raw)
                    })
                    .collect()
            })
            .map_err(|error| self.map_runtime_error(error))
    }

    fn map_runtime_error(&self, error: RuntimeError) -> Error {
        match error {
            RuntimeError::Terminal(TerminalOutcome::Cancelled) => {
                Error::Cancelled("runtime operation")
            }
            RuntimeError::Terminal(TerminalOutcome::TimedOut)
            | RuntimeError::Terminal(TerminalOutcome::OutcomeUnknown) => {
                Error::OperationTimeout(TimedOutTask::ReceiveNextMessage, self.timeout)
            }
            other => Error::InvalidState(other.to_string()),
        }
    }
}

impl fmt::Debug for RuntimeWorker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeWorker")
            .field("generation", &self.generation)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}
