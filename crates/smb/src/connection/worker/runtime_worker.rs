use crate::clock::{Clock, TokioClock};
use crate::connection::connection_info::ConnectionInfo;
use crate::connection::preauth_hash::PreauthHashValue;
use crate::error::TimedOutTask;
use crate::msg_handler::{IncomingMessage, OutgoingMessage, ReceiveOptions, SendMessageResult};
use crate::runtime::{
    GenerationId, OperationResult, RequestKey, RuntimeConfig, RuntimeError, RuntimeHandle,
    TerminalOutcome, TypedOperation, start_generation,
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
    pub(crate) async fn start_at(
        transport: Box<dyn SmbTransport>,
        timeout: Duration,
        initial_message_id: u64,
    ) -> Result<Arc<Self>> {
        let clock = Arc::new(TokioClock::new());
        let generation = GenerationId::new(1);
        let config = RuntimeConfig::production(generation, initial_message_id, 1, timeout);
        let (runtime, _events) = start_generation(transport, clock.clone(), config);
        Ok(Arc::new(Self {
            runtime,
            clock,
            generation,
            timeout,
        }))
    }

    pub(crate) async fn stop(&self) -> Result<()> {
        self.runtime
            .close(self.clock.now().saturating_add(self.timeout))
            .await
            .map(|_| ())
            .map_err(|error| self.map_runtime_error(error))
    }

    pub(crate) async fn send(&self, message: OutgoingMessage) -> Result<SendMessageResult> {
        let credit_charge = message.message.header.credit_charge.max(1);
        let deadline = self.clock.now().saturating_add(self.timeout);
        let submission = self
            .runtime
            .submit_operation_detached(
                TypedOperation::any_status(message),
                credit_charge,
                Some(deadline),
            )
            .await
            .map_err(|error| self.map_runtime_error(error))?;
        Ok(SendMessageResult::new(
            submission.key.message_id,
            submission.request_raw,
        ))
    }

    pub(crate) async fn receive(&self, options: &ReceiveOptions<'_>) -> Result<IncomingMessage> {
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
        sender: tokio::sync::mpsc::Sender<IncomingMessage>,
    ) -> Result<()> {
        self.runtime
            .install_notifications(sender)
            .map_err(|error| self.map_runtime_error(error))
    }

    pub(crate) async fn send_compound(
        self: &Arc<Self>,
        messages: Vec<OutgoingMessage>,
    ) -> Result<Vec<SendMessageResult>> {
        let operations = messages
            .into_iter()
            .map(|message| {
                let credit_charge = message.message.header.credit_charge.max(1);
                (TypedOperation::any_status(message), credit_charge)
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
                        SendMessageResult::new(submission.key.message_id, submission.request_raw)
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
