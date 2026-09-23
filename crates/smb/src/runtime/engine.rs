use super::crypto_executor::BoundedCryptoExecutor;
use super::object_state::{ObjectError, ObjectKind, ObjectRegistry, ObjectToken};
use super::operation::{
    OperationResult, OperationSubmission, ReplayPolicy, ResponsePolicy, TypedOperation,
};
use super::preparation_order::OrderedCompletionQueue;
use super::reducer::{CallerOutcome, GenerationId, ReduceEffect, RequestKey, TerminalOutcome};
use super::state::{
    AdmissionError, AdmissionLimits, GenerationState, OwnerEffect, OwnerEvent, RequestProgress,
};
use super::wire::WirePipeline;
use crate::clock::{Clock, MonotonicTime};
use crate::connection::connection_info::ConnectionInfo;
use crate::connection::preauth_hash::PreauthHashValue;
use crate::session::SessionAndChannel;
use futures_core::future::BoxFuture;
use futures_util::{FutureExt, StreamExt, stream::FuturesUnordered};
use smb_transport::{
    SendFrame, SmbTransport, SmbTransportRead, SmbTransportWrite, TransportError, TransportFrame,
};
use std::collections::{HashMap, VecDeque};
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::Notify;
use tokio::sync::{mpsc, oneshot, watch};
#[cfg(test)]
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

#[cfg(feature = "sign_cmac_rustcrypto")]
const READY_OPERATION_BATCH: usize = crate::crypto::PORTABLE_CMAC_LANES;
#[cfg(not(feature = "sign_cmac_rustcrypto"))]
const READY_OPERATION_BATCH: usize = 1;

#[derive(Clone, Copy, Debug)]
pub(crate) struct RuntimeConfig {
    pub(crate) generation: GenerationId,
    pub(crate) initial_message_id: u64,
    pub(crate) initial_credits: u32,
    pub(crate) target_credits: u32,
    pub(crate) admission_limits: AdmissionLimits,
    pub(crate) tombstone_drain_timeout: Duration,
    pub(crate) admission_capacity: usize,
    pub(crate) io_capacity: usize,
    pub(crate) control_capacity: usize,
    pub(crate) event_capacity: usize,
    pub(crate) control_batch: usize,
    pub(crate) maximum_frame_size: usize,
    pub(crate) emit_events: bool,
    pub(crate) decode_unsolicited: bool,
    pub(crate) crypto_parallelism: usize,
}

impl RuntimeConfig {
    pub(crate) fn production(
        generation: GenerationId,
        initial_message_id: u64,
        initial_credits: u32,
        target_credits: u32,
        timeout: Duration,
    ) -> Self {
        Self {
            generation,
            initial_message_id,
            initial_credits,
            target_credits,
            admission_limits: AdmissionLimits {
                max_operations: 1024,
                max_payload_bytes: 256 * 1024 * 1024,
            },
            tombstone_drain_timeout: timeout,
            admission_capacity: 1024,
            io_capacity: 1024,
            control_capacity: 256,
            event_capacity: 1,
            control_batch: 16,
            maximum_frame_size: smb_transport::DEFAULT_MAX_FRAME_SIZE,
            emit_events: false,
            decode_unsolicited: true,
            crypto_parallelism: BoundedCryptoExecutor::recommended_parallelism(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum RuntimeError {
    #[error("generation runtime is closed")]
    Closed,
    #[error("generation runtime owner terminated")]
    OwnerTerminated,
    #[error("generation runtime admission lane is full")]
    AdmissionBackpressure,
    #[error("generation runtime control lane is full")]
    ControlBackpressure,
    #[error("generation runtime admission failed: {0:?}")]
    Admission(AdmissionError),
    #[error("generation runtime transport failed: {0}")]
    Transport(&'static str),
    #[error("generation runtime event lane is full")]
    EventBackpressure,
    #[error("generation runtime wire pipeline failed: {0}")]
    Wire(&'static str),
    #[error("generation runtime request completed as {0:?}")]
    Terminal(TerminalOutcome),
    #[error("generation runtime does not own request {0}")]
    UnknownRequest(RequestKey),
    #[error("generation runtime request {0} already has a waiter")]
    AlreadyAwaited(RequestKey),
    #[error("generation object admission failed: {0:?}")]
    Object(ObjectError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeEvent {
    InboundFrame { bytes: usize },
    WriteProgress { key: RequestKey, bytes: usize },
    WriteComplete { key: RequestKey },
    PumpFailed { pump: PumpName, code: &'static str },
    PumpExited { pump: PumpName },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PumpName {
    Read,
    Write,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CloseReport {
    pub(crate) timed_out: bool,
    pub(crate) unresolved_requests: usize,
    pub(crate) joined_tasks: usize,
    pub(crate) failed_tasks: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum GenerationExitCause {
    ExplicitClose,
    Transport(RuntimeError),
    HandlesDropped,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GenerationExit {
    pub(crate) generation: GenerationId,
    pub(crate) cause: GenerationExitCause,
    pub(crate) report: CloseReport,
}

pub(crate) struct RequestTicket {
    pub(crate) key: RequestKey,
    completion: oneshot::Receiver<Result<TerminalOutcome, RuntimeError>>,
}

pub(crate) struct OperationTicket {
    pub(crate) key: RequestKey,
    completion: oneshot::Receiver<Result<OperationResult, RuntimeError>>,
}

impl OperationTicket {
    pub(crate) async fn completion(self) -> Result<OperationResult, RuntimeError> {
        self.completion
            .await
            .unwrap_or(Err(RuntimeError::OwnerTerminated))
    }
}

impl RequestTicket {
    pub(crate) async fn completion(self) -> Result<TerminalOutcome, RuntimeError> {
        self.completion
            .await
            .unwrap_or(Err(RuntimeError::OwnerTerminated))
    }
}

#[derive(Clone)]
pub(crate) struct RuntimeHandle {
    admission: mpsc::Sender<AdmissionCommand>,
    operations: mpsc::Sender<OperationAdmission>,
    compounds: mpsc::Sender<CompoundAdmission>,
    control: mpsc::Sender<ControlCommand>,
    owner_finished: CancellationToken,
    exit: watch::Receiver<Option<GenerationExit>>,
    connection_object: ObjectToken,
}

impl RuntimeHandle {
    pub(crate) const fn connection_object(&self) -> ObjectToken {
        self.connection_object
    }

    pub(crate) async fn create_object(
        &self,
        parent: ObjectToken,
        kind: ObjectKind,
    ) -> Result<ObjectToken, RuntimeError> {
        let (reply, result) = oneshot::channel();
        self.control
            .send(ControlCommand::CreateObject {
                parent,
                kind,
                reply,
            })
            .await
            .map_err(|_| RuntimeError::Closed)?;
        result.await.unwrap_or(Err(RuntimeError::OwnerTerminated))
    }

    pub(crate) async fn lose_object_generation(&self) -> Result<usize, RuntimeError> {
        let (reply, result) = oneshot::channel();
        self.control
            .send(ControlCommand::LoseObjectGeneration { reply })
            .await
            .map_err(|_| RuntimeError::Closed)?;
        result.await.unwrap_or(Err(RuntimeError::OwnerTerminated))
    }

    pub(crate) async fn begin_object_recovery(
        &self,
        object: ObjectToken,
    ) -> Result<(), RuntimeError> {
        let (reply, result) = oneshot::channel();
        self.control
            .send(ControlCommand::BeginObjectRecovery { object, reply })
            .await
            .map_err(|_| RuntimeError::Closed)?;
        result.await.unwrap_or(Err(RuntimeError::OwnerTerminated))
    }

    pub(crate) async fn publish_object_replacement(
        &self,
        object: ObjectToken,
    ) -> Result<ObjectToken, RuntimeError> {
        let (reply, result) = oneshot::channel();
        self.control
            .send(ControlCommand::PublishObjectReplacement { object, reply })
            .await
            .map_err(|_| RuntimeError::Closed)?;
        result.await.unwrap_or(Err(RuntimeError::OwnerTerminated))
    }

    pub(crate) async fn fail_object_recovery(
        &self,
        object: ObjectToken,
    ) -> Result<(), RuntimeError> {
        let (reply, result) = oneshot::channel();
        self.control
            .send(ControlCommand::FailObjectRecovery { object, reply })
            .await
            .map_err(|_| RuntimeError::Closed)?;
        result.await.unwrap_or(Err(RuntimeError::OwnerTerminated))
    }
    pub(crate) async fn negotiated(
        &self,
        connection: Arc<ConnectionInfo>,
    ) -> Result<(), RuntimeError> {
        let (reply, result) = oneshot::channel();
        self.control
            .send(ControlCommand::Negotiated { connection, reply })
            .await
            .map_err(|_| RuntimeError::Closed)?;
        result.await.unwrap_or(Err(RuntimeError::OwnerTerminated))
    }

    pub(crate) async fn session_started(
        &self,
        session: Arc<SessionAndChannel>,
    ) -> Result<(), RuntimeError> {
        let (reply, result) = oneshot::channel();
        self.control
            .send(ControlCommand::SessionStarted { session, reply })
            .await
            .map_err(|_| RuntimeError::Closed)?;
        result.await.unwrap_or(Err(RuntimeError::OwnerTerminated))
    }

    pub(crate) async fn session_ended(
        &self,
        session: Arc<SessionAndChannel>,
    ) -> Result<(), RuntimeError> {
        let (reply, result) = oneshot::channel();
        self.control
            .send(ControlCommand::SessionEnded { session, reply })
            .await
            .map_err(|_| RuntimeError::Closed)?;
        result.await.unwrap_or(Err(RuntimeError::OwnerTerminated))
    }

    pub(crate) async fn preauth_snapshot(&self) -> Result<Option<PreauthHashValue>, RuntimeError> {
        let (reply, result) = oneshot::channel();
        self.control
            .send(ControlCommand::PreauthSnapshot { reply })
            .await
            .map_err(|_| RuntimeError::Closed)?;
        result.await.unwrap_or(Err(RuntimeError::OwnerTerminated))
    }

    pub(crate) async fn reset_preauth_to_negotiate(&self) -> Result<(), RuntimeError> {
        let (reply, result) = oneshot::channel();
        self.control
            .send(ControlCommand::ResetPreauthToNegotiate { reply })
            .await
            .map_err(|_| RuntimeError::Closed)?;
        result.await.unwrap_or(Err(RuntimeError::OwnerTerminated))
    }

    pub(crate) fn install_notifications(
        &self,
        sender: mpsc::Sender<crate::command::CommandResponse>,
    ) -> Result<(), RuntimeError> {
        self.control
            .try_send(ControlCommand::InstallNotifications { sender })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => RuntimeError::ControlBackpressure,
                mpsc::error::TrySendError::Closed(_) => RuntimeError::Closed,
            })
    }

    pub(crate) async fn submit_operation(
        &self,
        operation: TypedOperation,
        deadline: Option<MonotonicTime>,
    ) -> Result<OperationTicket, RuntimeError> {
        let (acknowledge, acknowledged) = oneshot::channel();
        let (terminal, completion) = oneshot::channel();
        self.operations
            .try_send(OperationAdmission {
                operation,
                deadline,
                acknowledge,
                terminal: Some(terminal),
            })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => RuntimeError::AdmissionBackpressure,
                mpsc::error::TrySendError::Closed(_) => RuntimeError::Closed,
            })?;
        let submission = acknowledged
            .await
            .unwrap_or(Err(RuntimeError::OwnerTerminated))?;
        Ok(OperationTicket {
            key: submission.key,
            completion,
        })
    }

    pub(crate) async fn submit_operation_detached(
        &self,
        operation: TypedOperation,
        deadline: Option<MonotonicTime>,
    ) -> Result<OperationSubmission, RuntimeError> {
        let (acknowledge, acknowledged) = oneshot::channel();
        self.operations
            .try_send(OperationAdmission {
                operation,
                deadline,
                acknowledge,
                terminal: None,
            })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => RuntimeError::AdmissionBackpressure,
                mpsc::error::TrySendError::Closed(_) => RuntimeError::Closed,
            })?;
        acknowledged
            .await
            .unwrap_or(Err(RuntimeError::OwnerTerminated))
    }

    pub(crate) async fn await_operation(
        &self,
        key: RequestKey,
    ) -> Result<OperationResult, RuntimeError> {
        let (reply, result) = oneshot::channel();
        self.control
            .send(ControlCommand::AwaitOperation { key, reply })
            .await
            .map_err(|_| RuntimeError::Closed)?;
        result.await.unwrap_or(Err(RuntimeError::OwnerTerminated))
    }

    pub(crate) async fn submit_compound_detached(
        &self,
        operations: Vec<TypedOperation>,
        deadline: Option<MonotonicTime>,
    ) -> Result<Vec<OperationSubmission>, RuntimeError> {
        let (acknowledge, acknowledged) = oneshot::channel();
        self.compounds
            .try_send(CompoundAdmission {
                operations,
                deadline,
                acknowledge,
            })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => RuntimeError::AdmissionBackpressure,
                mpsc::error::TrySendError::Closed(_) => RuntimeError::Closed,
            })?;
        acknowledged
            .await
            .unwrap_or(Err(RuntimeError::OwnerTerminated))
    }

    pub(crate) async fn submit(
        &self,
        frame: SendFrame,
        payload_bytes: u64,
        credit_charge: u16,
        deadline: Option<MonotonicTime>,
    ) -> Result<RequestTicket, RuntimeError> {
        let (acknowledge, acknowledged) = oneshot::channel();
        let (terminal, completion) = oneshot::channel();
        self.admission
            .try_send(AdmissionCommand {
                frame,
                payload_bytes,
                credit_charge,
                deadline,
                acknowledge,
                terminal,
            })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => RuntimeError::AdmissionBackpressure,
                mpsc::error::TrySendError::Closed(_) => RuntimeError::Closed,
            })?;
        let key = acknowledged
            .await
            .unwrap_or(Err(RuntimeError::OwnerTerminated))?;
        Ok(RequestTicket { key, completion })
    }

    pub(crate) fn cancel(&self, key: RequestKey, now: MonotonicTime) -> Result<(), RuntimeError> {
        self.control
            .try_send(ControlCommand::Cancel { key, now })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => RuntimeError::ControlBackpressure,
                mpsc::error::TrySendError::Closed(_) => RuntimeError::Closed,
            })
    }

    pub(crate) async fn close(&self, deadline: MonotonicTime) -> Result<CloseReport, RuntimeError> {
        let (reply, report) = oneshot::channel();
        self.control
            .send(ControlCommand::Close { deadline, reply })
            .await
            .map_err(|_| RuntimeError::Closed)?;
        let report = report.await.unwrap_or(Err(RuntimeError::OwnerTerminated))?;
        self.owner_finished.cancelled().await;
        Ok(report)
    }

    pub(crate) async fn exited(&self) -> GenerationExit {
        let mut exit = self.exit.clone();
        loop {
            if let Some(exit) = exit.borrow().clone() {
                return exit;
            }
            if exit.changed().await.is_err() {
                return GenerationExit {
                    generation: self.connection_object.generation(),
                    cause: GenerationExitCause::Transport(RuntimeError::OwnerTerminated),
                    report: CloseReport {
                        timed_out: false,
                        unresolved_requests: 0,
                        joined_tasks: 0,
                        failed_tasks: 1,
                    },
                };
            }
        }
    }
}

pub(crate) struct RuntimeEvents {
    receiver: mpsc::Receiver<RuntimeEvent>,
}

impl RuntimeEvents {
    pub(crate) async fn recv(&mut self) -> Option<RuntimeEvent> {
        self.receiver.recv().await
    }
}

pub(crate) fn start_generation(
    transport: Box<dyn SmbTransport>,
    clock: Arc<dyn Clock>,
    config: RuntimeConfig,
) -> (RuntimeHandle, RuntimeEvents) {
    let (admission_tx, admission_rx) = mpsc::channel(config.admission_capacity.max(1));
    let (operation_tx, operation_rx) = mpsc::channel(config.admission_capacity.max(1));
    let (compound_tx, compound_rx) = mpsc::channel(config.admission_capacity.max(1));
    let (control_tx, control_rx) = mpsc::channel(config.control_capacity.max(1));
    let (event_tx, event_rx) = mpsc::channel(config.event_capacity.max(1));
    let owner_finished = CancellationToken::new();
    let (exit_tx, exit_rx) = watch::channel(None);
    let connection_object = ObjectRegistry::new(config.generation).connection();
    let handle = RuntimeHandle {
        admission: admission_tx,
        operations: operation_tx,
        compounds: compound_tx,
        control: control_tx,
        owner_finished: owner_finished.clone(),
        exit: exit_rx,
        connection_object,
    };
    tokio::spawn(async move {
        let exit = owner_task(
            transport,
            clock,
            config,
            admission_rx,
            operation_rx,
            compound_rx,
            control_rx,
            event_tx,
        )
        .await;
        let _ = exit_tx.send(Some(exit));
        owner_finished.cancel();
    });
    (handle, RuntimeEvents { receiver: event_rx })
}

struct AdmissionCommand {
    frame: SendFrame,
    payload_bytes: u64,
    credit_charge: u16,
    deadline: Option<MonotonicTime>,
    acknowledge: oneshot::Sender<Result<RequestKey, RuntimeError>>,
    terminal: oneshot::Sender<Result<TerminalOutcome, RuntimeError>>,
}

struct OperationAdmission {
    operation: TypedOperation,
    deadline: Option<MonotonicTime>,
    acknowledge: oneshot::Sender<Result<OperationSubmission, RuntimeError>>,
    terminal: Option<oneshot::Sender<Result<OperationResult, RuntimeError>>>,
}

struct CompoundAdmission {
    operations: Vec<TypedOperation>,
    deadline: Option<MonotonicTime>,
    acknowledge: oneshot::Sender<Result<Vec<OperationSubmission>, RuntimeError>>,
}

struct OperationPending {
    response: ResponsePolicy,
    replay: ReplayPolicy,
    request_raw: Option<bytes::Bytes>,
    terminal: Option<oneshot::Sender<Result<OperationResult, RuntimeError>>>,
    buffered: Option<Result<OperationResult, RuntimeError>>,
    draining: bool,
    caller_completed: bool,
}

struct RequestAuthority {
    state: GenerationState,
    objects: ObjectRegistry,
    terminals: HashMap<RequestKey, oneshot::Sender<Result<TerminalOutcome, RuntimeError>>>,
    operation_pending: HashMap<RequestKey, OperationPending>,
    early_responses: HashMap<RequestKey, crate::command::CommandResponse>,
    frame_members: HashMap<RequestKey, Arc<[RequestKey]>>,
    frame_cancellations: HashMap<RequestKey, CancellationToken>,
    deferred_cancellations: HashMap<RequestKey, MonotonicTime>,
    notifications: Option<mpsc::Sender<crate::command::CommandResponse>>,
    large_mtu: bool,
    target_credits: u32,
}

enum ControlCommand {
    CreateObject {
        parent: ObjectToken,
        kind: ObjectKind,
        reply: oneshot::Sender<Result<ObjectToken, RuntimeError>>,
    },
    LoseObjectGeneration {
        reply: oneshot::Sender<Result<usize, RuntimeError>>,
    },
    BeginObjectRecovery {
        object: ObjectToken,
        reply: oneshot::Sender<Result<(), RuntimeError>>,
    },
    PublishObjectReplacement {
        object: ObjectToken,
        reply: oneshot::Sender<Result<ObjectToken, RuntimeError>>,
    },
    FailObjectRecovery {
        object: ObjectToken,
        reply: oneshot::Sender<Result<(), RuntimeError>>,
    },
    InstallNotifications {
        sender: mpsc::Sender<crate::command::CommandResponse>,
    },
    PreauthSnapshot {
        reply: oneshot::Sender<Result<Option<PreauthHashValue>, RuntimeError>>,
    },
    ResetPreauthToNegotiate {
        reply: oneshot::Sender<Result<(), RuntimeError>>,
    },
    AwaitOperation {
        key: RequestKey,
        reply: oneshot::Sender<Result<OperationResult, RuntimeError>>,
    },
    Negotiated {
        connection: Arc<ConnectionInfo>,
        reply: oneshot::Sender<Result<(), RuntimeError>>,
    },
    SessionStarted {
        session: Arc<SessionAndChannel>,
        reply: oneshot::Sender<Result<(), RuntimeError>>,
    },
    SessionEnded {
        session: Arc<SessionAndChannel>,
        reply: oneshot::Sender<Result<(), RuntimeError>>,
    },
    Cancel {
        key: RequestKey,
        now: MonotonicTime,
    },
    Close {
        deadline: MonotonicTime,
        reply: oneshot::Sender<Result<CloseReport, RuntimeError>>,
    },
}

struct WriteCommand {
    key: RequestKey,
    members: Arc<[RequestKey]>,
    frame: SendFrame,
    cancel_before_write: CancellationToken,
}

struct PreparedOperation {
    key: RequestKey,
    result: crate::Result<SendFrame>,
    retain_raw: bool,
    acknowledge: oneshot::Sender<Result<OperationSubmission, RuntimeError>>,
}

struct PreparedInbound {
    sequence: u64,
    bytes: usize,
    result: crate::Result<Vec<crate::command::CommandResponse>>,
}

enum IoEvent {
    Inbound(TransportFrame),
    WriteCancelled(RequestKey),
    WriteProgress {
        key: RequestKey,
        bytes: usize,
    },
    WriteComplete(RequestKey),
    Failed {
        pump: PumpName,
        error: TransportError,
    },
    Exited(PumpName),
}

#[cfg(test)]
enum PumpExit {
    Read,
    Write,
}

struct ReadStep {
    transport: Box<dyn SmbTransportRead>,
    result: Result<TransportFrame, TransportError>,
}

type ReadStepFuture = BoxFuture<'static, std::thread::Result<ReadStep>>;

enum WriteStepResult {
    Cancelled,
    Sent {
        bytes: usize,
        result: Result<(), TransportError>,
    },
}

struct WriteStep {
    transport: Box<dyn SmbTransportWrite>,
    result: WriteStepResult,
}

type WriteStepFuture = BoxFuture<'static, std::thread::Result<WriteStep>>;

struct ActiveWrite {
    key: RequestKey,
    progressed: Arc<AtomicUsize>,
    progress_ready: Arc<Notify>,
    reported: usize,
    future: WriteStepFuture,
}

fn read_step(
    mut transport: Box<dyn SmbTransportRead>,
    maximum_frame_size: usize,
) -> ReadStepFuture {
    AssertUnwindSafe(async move {
        let result = transport.receive_with_limit(maximum_frame_size).await;
        ReadStep { transport, result }
    })
    .catch_unwind()
    .boxed()
}

fn write_step(mut transport: Box<dyn SmbTransportWrite>, command: WriteCommand) -> ActiveWrite {
    let key = command.key;
    let progressed = Arc::new(AtomicUsize::new(0));
    let progress_ready = Arc::new(Notify::new());
    let future_progressed = Arc::clone(&progressed);
    let future_progress_ready = Arc::clone(&progress_ready);
    let future = AssertUnwindSafe(async move {
        if command.cancel_before_write.is_cancelled() {
            return WriteStep {
                transport,
                result: WriteStepResult::Cancelled,
            };
        }

        let callback_progressed = Arc::clone(&future_progressed);
        let mut observe = move |bytes| {
            callback_progressed.fetch_add(bytes, Ordering::Relaxed);
        };
        let outcome = {
            let send = transport.send_with_progress(&command.frame, &mut observe);
            tokio::pin!(send);
            enum SendPoll {
                Progress,
                Complete(Result<(), TransportError>),
            }
            loop {
                let before = future_progressed.load(Ordering::Relaxed);
                let polled = std::future::poll_fn(|context| {
                    match std::future::Future::poll(send.as_mut(), context) {
                        std::task::Poll::Ready(result) => {
                            std::task::Poll::Ready(SendPoll::Complete(result))
                        }
                        std::task::Poll::Pending
                            if future_progressed.load(Ordering::Relaxed) > before =>
                        {
                            std::task::Poll::Ready(SendPoll::Progress)
                        }
                        std::task::Poll::Pending => std::task::Poll::Pending,
                    }
                });
                enum SendControl {
                    Cancelled,
                    Polled(SendPoll),
                }
                let control = tokio::select! {
                    biased;
                    _ = command.cancel_before_write.cancelled() => SendControl::Cancelled,
                    result = polled => SendControl::Polled(result),
                };
                match control {
                    SendControl::Cancelled => {
                        if future_progressed.load(Ordering::Relaxed) == 0 {
                            break None;
                        }
                        future_progress_ready.notify_one();
                        break Some(send.await);
                    }
                    SendControl::Polled(SendPoll::Progress) => {
                        future_progress_ready.notify_one();
                    }
                    SendControl::Polled(SendPoll::Complete(result)) => break Some(result),
                }
            }
        };
        let result = match outcome {
            Some(result) => WriteStepResult::Sent {
                bytes: future_progressed.load(Ordering::Relaxed),
                result,
            },
            None => WriteStepResult::Cancelled,
        };
        WriteStep { transport, result }
    })
    .catch_unwind()
    .boxed();
    ActiveWrite {
        key,
        progressed,
        progress_ready,
        reported: 0,
        future,
    }
}

#[allow(clippy::too_many_arguments)]
async fn owner_task(
    transport: Box<dyn SmbTransport>,
    clock: Arc<dyn Clock>,
    config: RuntimeConfig,
    mut admission_rx: mpsc::Receiver<AdmissionCommand>,
    mut operation_rx: mpsc::Receiver<OperationAdmission>,
    mut compound_rx: mpsc::Receiver<CompoundAdmission>,
    mut control_rx: mpsc::Receiver<ControlCommand>,
    event_tx: mpsc::Sender<RuntimeEvent>,
) -> GenerationExit {
    let wire = Arc::new(WirePipeline::with_crypto_parallelism(
        config.crypto_parallelism,
    ));
    let Ok((read, write)) = transport.split() else {
        fail_waiting_admissions(&mut admission_rx, RuntimeError::Transport("split")).await;
        fail_waiting_operations(&mut operation_rx, RuntimeError::Transport("split")).await;
        fail_waiting_compounds(&mut compound_rx, RuntimeError::Transport("split")).await;
        return GenerationExit {
            generation: config.generation,
            cause: GenerationExitCause::Transport(RuntimeError::Transport("split")),
            report: CloseReport {
                timed_out: false,
                unresolved_requests: 0,
                joined_tasks: 0,
                failed_tasks: 0,
            },
        };
    };
    // Read and write remain independent, cancellation-safe futures, but they
    // are polled by the owner task itself. This keeps full-duplex transport
    // progress without crossing Tokio worker queues for every I/O event.
    let mut read = read_step(read, config.maximum_frame_size);
    let mut write = Some(write);
    let mut active_write: Option<ActiveWrite> = None;
    let mut read_panicked = false;
    let mut write_panicked = false;

    let mut authority = RequestAuthority {
        state: GenerationState::new(
            config.generation,
            config.initial_message_id,
            config.initial_credits,
            1,
            config.admission_limits,
            config.tombstone_drain_timeout,
        ),
        objects: ObjectRegistry::new(config.generation),
        terminals: HashMap::new(),
        operation_pending: HashMap::new(),
        early_responses: HashMap::new(),
        frame_members: HashMap::new(),
        frame_cancellations: HashMap::new(),
        deferred_cancellations: HashMap::new(),
        notifications: None,
        large_mtu: false,
        target_credits: config.target_credits,
    };
    let mut send_queue = VecDeque::new();
    let mut received_frames = VecDeque::new();
    let mut preparations = FuturesUnordered::<BoxFuture<'static, PreparedOperation>>::new();
    let mut preparation_order = OrderedCompletionQueue::default();
    let mut inbound_preparations = FuturesUnordered::<BoxFuture<'static, PreparedInbound>>::new();
    let mut inbound_order = OrderedCompletionQueue::default();
    let mut next_inbound_sequence = 0_u64;
    let mut waiting_operation = None;
    let mut waiting_compound = None;
    let mut close_request = None;
    let mut fatal = None;

    loop {
        // Drain only transport reads that are already ready. This gives the
        // transform stage up to one portable CMAC lane set without waiting
        // for another frame or adding a coalescing timer.
        for _ in 0..config.crypto_parallelism.max(1) {
            // A scripted or very fast server can make a response readable in
            // the same turn that its typed operation reaches the owner. When
            // unsolicited decoding is disabled, admit that operation first
            // so the response is not intentionally treated as opaque input.
            if !config.decode_unsolicited
                && authority.operation_pending.is_empty()
                && (!operation_rx.is_empty() || !compound_rx.is_empty())
            {
                break;
            }
            if received_frames.len() >= config.io_capacity.max(1) {
                break;
            }
            let Some(completion) = read.as_mut().now_or_never() else {
                break;
            };
            match completion {
                Ok(step) => match step.result {
                    Ok(frame) => {
                        read = read_step(step.transport, config.maximum_frame_size);
                        received_frames.push_back(frame);
                    }
                    Err(error) => {
                        process_io(
                            IoEvent::Failed {
                                pump: PumpName::Read,
                                error,
                            },
                            &mut authority,
                            &event_tx,
                            config.emit_events,
                            &mut fatal,
                        )
                        .await;
                        break;
                    }
                },
                Err(_) => {
                    read_panicked = true;
                    fatal = Some(RuntimeError::Transport("pump-panicked"));
                    break;
                }
            }
        }
        while inbound_preparations.len() < config.crypto_parallelism.max(1) {
            let Some(frame) = received_frames.pop_front() else {
                break;
            };
            if process_or_enqueue_io(
                IoEvent::Inbound(frame),
                &wire,
                &mut authority,
                &event_tx,
                config.emit_events,
                config.decode_unsolicited,
                &mut fatal,
                &mut inbound_preparations,
                &mut inbound_order,
                &mut next_inbound_sequence,
            )
            .await
            {
                admission_rx.close();
                operation_rx.close();
                compound_rx.close();
                break;
            }
        }
        if let Some(Some(prepared)) = preparations.next().now_or_never() {
            for ready in preparation_order.complete(prepared.key, prepared) {
                finish_prepared_operation(ready, &mut authority, &mut send_queue, &mut fatal);
            }
        }
        if let Some(Some(inbound)) = inbound_preparations.next().now_or_never() {
            for ready in inbound_order.complete(inbound.sequence, inbound) {
                finish_prepared_inbound(
                    ready,
                    &mut authority,
                    &event_tx,
                    config.emit_events,
                    &mut fatal,
                );
            }
        }
        if let Some(command) = waiting_operation.take() {
            waiting_operation = process_operation_admission(
                command,
                false,
                &wire,
                &mut authority,
                &mut send_queue,
                &mut fatal,
                &mut preparations,
                &mut preparation_order,
            )
            .await;
        }
        if preparation_order.is_empty()
            && let Some(command) = waiting_compound.take()
        {
            waiting_compound = process_compound_admission(
                command,
                &wire,
                &mut authority,
                &mut send_queue,
                &mut fatal,
            )
            .await;
        }
        for _ in 0..config.control_batch.max(1) {
            match control_rx.try_recv() {
                Ok(command) => {
                    if handle_control(
                        command,
                        &wire,
                        &mut authority,
                        &mut send_queue,
                        &mut close_request,
                    )
                    .await
                    {
                        admission_rx.close();
                        operation_rx.close();
                        compound_rx.close();
                    }
                }
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => break,
            }
        }

        if let Ok(command) = admission_rx.try_recv() {
            process_admission(
                command,
                &mut authority.state,
                &mut authority.terminals,
                &mut send_queue,
            );
        }
        for _ in 0..READY_OPERATION_BATCH {
            if waiting_operation.is_some() || waiting_compound.is_some() {
                break;
            }
            let Ok(command) = operation_rx.try_recv() else {
                break;
            };
            let cmac_batch_eligible = !preparations.is_empty() || !operation_rx.is_empty();
            waiting_operation = process_operation_admission(
                command,
                cmac_batch_eligible,
                &wire,
                &mut authority,
                &mut send_queue,
                &mut fatal,
                &mut preparations,
                &mut preparation_order,
            )
            .await;
        }
        if waiting_compound.is_none()
            && waiting_operation.is_none()
            && preparation_order.is_empty()
            && let Ok(command) = compound_rx.try_recv()
        {
            waiting_compound = process_compound_admission(
                command,
                &wire,
                &mut authority,
                &mut send_queue,
                &mut fatal,
            )
            .await;
        }
        dispatch_next(
            &mut write,
            &mut active_write,
            &mut authority,
            &mut send_queue,
        );

        if close_request.is_some() || fatal.is_some() {
            break;
        }

        let deadline = authority.state.next_deadline();
        let deadline_sleep = async {
            match deadline {
                Some(deadline) => clock.sleep_until(deadline).await,
                None => futures_util::future::pending().await,
            }
        };
        tokio::pin!(deadline_sleep);
        let write_progress_ready = active_write
            .as_ref()
            .map(|active| Arc::clone(&active.progress_ready));

        tokio::select! {
            biased;
            command = control_rx.recv() => match command {
                Some(command) => {
                    let close = handle_control(command, &wire, &mut authority, &mut send_queue, &mut close_request).await;
                    close_admission_if(close, &mut admission_rx);
                    if close {
                        operation_rx.close();
                        compound_rx.close();
                    }
                }
                None if admission_rx.is_closed() => break,
                None => {}
            },
            inbound = inbound_preparations.next(), if !inbound_preparations.is_empty() => {
                if let Some(inbound) = inbound {
                    for ready in inbound_order.complete(inbound.sequence, inbound) {
                        if finish_prepared_inbound(
                            ready,
                            &mut authority,
                            &event_tx,
                            config.emit_events,
                            &mut fatal,
                        ) {
                            admission_rx.close();
                            operation_rx.close();
                            compound_rx.close();
                        }
                    }
                }
            }
            completion = read.as_mut(), if received_frames.len() < config.io_capacity.max(1)
                && (config.decode_unsolicited
                    || !authority.operation_pending.is_empty()
                    || (operation_rx.is_empty() && compound_rx.is_empty())) => {
                match completion {
                    Ok(step) => match step.result {
                        Ok(frame) => {
                            read = read_step(step.transport, config.maximum_frame_size);
                            received_frames.push_back(frame);
                        }
                        Err(error) => {
                            process_io(
                                IoEvent::Failed { pump: PumpName::Read, error },
                                &mut authority,
                                &event_tx,
                                config.emit_events,
                                &mut fatal,
                            ).await;
                        }
                    },
                    Err(_) => {
                        read_panicked = true;
                        fatal = Some(RuntimeError::Transport("pump-panicked"));
                    }
                }
                if fatal.is_some() {
                    admission_rx.close();
                    operation_rx.close();
                    compound_rx.close();
                }
            }
            completion = async {
                active_write
                    .as_mut()
                    .expect("guarded active write must exist")
                    .future
                    .as_mut()
                    .await
            }, if active_write.is_some() => {
                let active = active_write
                    .take()
                    .expect("completed active write must exist");
                let key = active.key;
                let unreported = active
                    .progressed
                    .load(Ordering::Relaxed)
                    .saturating_sub(active.reported);
                if unreported > 0 {
                    process_io(
                        IoEvent::WriteProgress { key, bytes: unreported },
                        &mut authority,
                        &event_tx,
                        config.emit_events,
                        &mut fatal,
                    ).await;
                }
                match completion {
                    Ok(step) => {
                        write = Some(step.transport);
                        match step.result {
                            WriteStepResult::Cancelled => {
                                process_io(
                                    IoEvent::WriteCancelled(key),
                                    &mut authority,
                                    &event_tx,
                                    config.emit_events,
                                    &mut fatal,
                                ).await;
                            }
                            WriteStepResult::Sent { bytes, result } => {
                                debug_assert_eq!(bytes, active.reported + unreported);
                                match result {
                                    Ok(()) => {
                                        process_io(
                                            IoEvent::WriteComplete(key),
                                            &mut authority,
                                            &event_tx,
                                            config.emit_events,
                                            &mut fatal,
                                        ).await;
                                    }
                                    Err(error) => {
                                        process_io(
                                            IoEvent::Failed { pump: PumpName::Write, error },
                                            &mut authority,
                                            &event_tx,
                                            config.emit_events,
                                            &mut fatal,
                                        ).await;
                                    }
                                }
                            }
                        }
                    }
                    Err(_) => {
                        write_panicked = true;
                        fatal = Some(RuntimeError::Transport("pump-panicked"));
                    }
                }
                if fatal.is_some() {
                    admission_rx.close();
                    operation_rx.close();
                    compound_rx.close();
                }
            }
            _ = async {
                write_progress_ready
                    .as_ref()
                    .expect("guarded write progress notifier must exist")
                    .notified()
                    .await
            }, if write_progress_ready.is_some() => {
                let active = active_write
                    .as_mut()
                    .expect("notified active write must exist");
                let progressed = active.progressed.load(Ordering::Relaxed);
                let bytes = progressed.saturating_sub(active.reported);
                active.reported = progressed;
                if bytes > 0
                    && process_io(
                        IoEvent::WriteProgress { key: active.key, bytes },
                        &mut authority,
                        &event_tx,
                        config.emit_events,
                        &mut fatal,
                    ).await
                {
                    admission_rx.close();
                    operation_rx.close();
                    compound_rx.close();
                }
            }
            command = admission_rx.recv(), if !admission_rx.is_closed() => {
                if let Some(command) = command {
                    process_admission(command, &mut authority.state, &mut authority.terminals, &mut send_queue);
                }
            },
            command = operation_rx.recv(), if !operation_rx.is_closed() && waiting_operation.is_none() && waiting_compound.is_none() => {
                if let Some(command) = command {
                    let cmac_batch_eligible = !operation_rx.is_empty();
                    waiting_operation = process_operation_admission(
                        command,
                        cmac_batch_eligible,
                        &wire,
                        &mut authority,
                        &mut send_queue,
                        &mut fatal,
                        &mut preparations,
                        &mut preparation_order,
                    ).await;
                }
            },
            prepared = preparations.next(), if !preparations.is_empty() => {
                if let Some(prepared) = prepared {
                    for ready in preparation_order.complete(prepared.key, prepared) {
                        finish_prepared_operation(ready, &mut authority, &mut send_queue, &mut fatal);
                    }
                }
            }
            command = compound_rx.recv(), if !compound_rx.is_closed() && waiting_compound.is_none() && waiting_operation.is_none() && preparation_order.is_empty() => {
                if let Some(command) = command {
                    waiting_compound = process_compound_admission(command, &wire, &mut authority, &mut send_queue, &mut fatal).await;
                }
            },
            _ = &mut deadline_sleep => {
                let effects = authority.state.reduce(OwnerEvent::AdvanceTime { now: clock.now() });
                apply_operation_effects(&effects, &mut authority.operation_pending);
                apply_owner_effects(effects, &mut authority.terminals);
                if authority.state.is_unhealthy() {
                    fatal = Some(RuntimeError::Transport("generation-unhealthy"));
                    admission_rx.close();
                    operation_rx.close();
                    compound_rx.close();
                }
            }
        }
    }

    admission_rx.close();
    operation_rx.close();
    compound_rx.close();
    fail_waiting_admissions(
        &mut admission_rx,
        fatal.clone().unwrap_or(RuntimeError::Closed),
    )
    .await;
    fail_waiting_compounds(
        &mut compound_rx,
        fatal.clone().unwrap_or(RuntimeError::Closed),
    )
    .await;
    fail_waiting_operations(
        &mut operation_rx,
        fatal.clone().unwrap_or(RuntimeError::Closed),
    )
    .await;
    let terminal_error = fatal.clone().unwrap_or(RuntimeError::Closed);
    if let Some(command) = waiting_operation {
        if let Some(terminal) = command.terminal {
            let _ = terminal.send(Err(terminal_error.clone()));
        }
        let _ = command.acknowledge.send(Err(terminal_error.clone()));
    }
    if let Some(command) = waiting_compound {
        let _ = command.acknowledge.send(Err(terminal_error));
    }
    for queued in send_queue {
        queued.cancel_before_write.cancel();
    }
    for cancellation in authority.frame_cancellations.values() {
        cancellation.cancel();
    }
    // The owner is the sole authority for both request and domain-object
    // lifetimes. Revoke the complete hierarchy before publishing disconnect
    // effects so no token from this generation can survive transport loss.
    authority.objects.lose_generation();
    let effects = authority.state.reduce(OwnerEvent::Disconnect);
    apply_operation_effects(&effects, &mut authority.operation_pending);
    apply_owner_effects(effects, &mut authority.terminals);
    for (_, terminal) in authority.terminals.drain() {
        let _ = terminal.send(Err(fatal.clone().unwrap_or(RuntimeError::Closed)));
    }
    for (_, pending) in authority.operation_pending.drain() {
        if let Some(terminal) = pending.terminal {
            let _ = terminal.send(Err(fatal.clone().unwrap_or(RuntimeError::Closed)));
        }
    }

    let close_deadline = close_request
        .as_ref()
        .map(|request: &CloseRequest| request.deadline);
    let (write_joined, write_failed, timed_out) = if write_panicked {
        (0, 1, false)
    } else {
        finish_active_write(active_write.take(), clock.as_ref(), close_deadline).await
    };
    let report = CloseReport {
        timed_out,
        unresolved_requests: authority.state.unresolved_callers(),
        joined_tasks: usize::from(!read_panicked) + write_joined,
        failed_tasks: usize::from(read_panicked) + write_failed,
    };
    let cause = if close_request.is_some() {
        GenerationExitCause::ExplicitClose
    } else if let Some(error) = fatal {
        // The one place every fatal path converges; without this line a transport-class exit
        // is invisible to the caller, who only sees the next operation fail in recovery.
        tracing::warn!(
            generation = ?config.generation,
            ?error,
            unresolved_requests = report.unresolved_requests,
            "SMB connection generation exited on a transport fault"
        );
        GenerationExitCause::Transport(error)
    } else {
        GenerationExitCause::HandlesDropped
    };
    if let Some(request) = close_request {
        let _ = request.reply.send(Ok(report));
    }
    GenerationExit {
        generation: config.generation,
        cause,
        report,
    }
}

async fn finish_active_write(
    active_write: Option<ActiveWrite>,
    clock: &dyn Clock,
    deadline: Option<MonotonicTime>,
) -> (usize, usize, bool) {
    let Some(mut active_write) = active_write else {
        return (1, 0, false);
    };
    let sleep = async {
        match deadline {
            Some(deadline) => clock.sleep_until(deadline).await,
            None => futures_util::future::pending().await,
        }
    };
    tokio::pin!(sleep);
    tokio::select! {
        result = &mut active_write.future => {
            if result.is_ok() { (1, 0, false) } else { (0, 1, false) }
        }
        _ = &mut sleep => (0, 1, true),
    }
}

#[allow(clippy::too_many_arguments)]
async fn process_operation_admission(
    command: OperationAdmission,
    cmac_batch_eligible: bool,
    wire: &Arc<WirePipeline>,
    authority: &mut RequestAuthority,
    send_queue: &mut VecDeque<WriteCommand>,
    fatal: &mut Option<RuntimeError>,
    preparations: &mut FuturesUnordered<BoxFuture<'static, PreparedOperation>>,
    preparation_order: &mut OrderedCompletionQueue<RequestKey, PreparedOperation>,
) -> Option<OperationAdmission> {
    if let Some(dependency) = command.operation.dependency()
        && let Err(error) = authority.objects.validate_active(dependency)
    {
        let error = RuntimeError::Object(error);
        if let Some(terminal) = command.terminal {
            let _ = terminal.send(Err(error.clone()));
        }
        let _ = command.acknowledge.send(Err(error));
        return None;
    }
    if authority.operation_pending.len() >= authority.state.operation_limit() {
        let error = RuntimeError::Admission(AdmissionError::OperationsExhausted);
        if let Some(terminal) = command.terminal {
            let _ = terminal.send(Err(error.clone()));
        }
        let _ = command.acknowledge.send(Err(error));
        return None;
    }
    let payload_bytes = command.operation.payload_bytes();
    let credit_charge = match command.operation.credit_charge(authority.large_mtu) {
        Ok(charge) => charge,
        Err(_) => {
            let error = RuntimeError::Wire("credit-charge");
            if let Some(terminal) = command.terminal {
                let _ = terminal.send(Err(error.clone()));
            }
            let _ = command.acknowledge.send(Err(error));
            return None;
        }
    };
    if u32::from(credit_charge) > authority.state.available_credits() {
        return Some(command);
    }
    let effects = authority.state.reduce(OwnerEvent::Admit {
        payload_bytes,
        credit_charge,
        caller_deadline: command.deadline,
    });
    let Some(OwnerEffect::Admitted(plan)) = effects.first() else {
        let error = match effects.first() {
            Some(OwnerEffect::AdmissionRejected(error)) => RuntimeError::Admission(*error),
            _ => RuntimeError::OwnerTerminated,
        };
        if let Some(terminal) = command.terminal {
            let _ = terminal.send(Err(error.clone()));
        }
        let _ = command.acknowledge.send(Err(error));
        return None;
    };

    let key = plan.key;
    let response = command.operation.response_policy().clone();
    let replay = command.operation.replay_policy();
    let mut outgoing = command.operation.into_outgoing();
    outgoing.cmac_batch_eligible = cmac_batch_eligible;
    outgoing.message.header.message_id = key.message_id;
    outgoing.message.header.credit_charge = plan.credit_charge;
    outgoing.message.header.credit_request = plan.credit_request;
    let retain_raw = outgoing.return_raw_data;
    if !wire.should_prepare_concurrently(&outgoing) {
        let frame = match wire.transform_outgoing(outgoing).await {
            Ok(frame) => frame,
            Err(_) => {
                authority.state.reduce(OwnerEvent::PrepareFailed { key });
                let error = RuntimeError::Wire("prepare-outgoing");
                if let Some(terminal) = command.terminal {
                    let _ = terminal.send(Err(error.clone()));
                }
                let _ = command.acknowledge.send(Err(error));
                return None;
            }
        };
        let request_raw = retain_raw
            .then(|| frame.segments().first().cloned())
            .flatten();
        authority.operation_pending.insert(
            key,
            OperationPending {
                response,
                replay,
                request_raw: request_raw.clone(),
                terminal: command.terminal,
                buffered: None,
                draining: false,
                caller_completed: false,
            },
        );
        send_queue.push_back(WriteCommand {
            key,
            members: Arc::from([key]),
            frame,
            cancel_before_write: CancellationToken::new(),
        });
        let _ = command
            .acknowledge
            .send(Ok(OperationSubmission { key, request_raw }));
        if let Some(message) = authority.early_responses.remove(&key) {
            process_decoded_response(message, authority, fatal);
        }
        return None;
    }
    authority.operation_pending.insert(
        key,
        OperationPending {
            response,
            replay,
            request_raw: None,
            terminal: command.terminal,
            buffered: None,
            draining: false,
            caller_completed: false,
        },
    );
    preparation_order.reserve(key);
    let wire = wire.clone();
    preparations.push(
        async move {
            let result = wire.transform_outgoing(outgoing).await;
            PreparedOperation {
                key,
                result,
                retain_raw,
                acknowledge: command.acknowledge,
            }
        }
        .boxed(),
    );
    None
}

fn finish_prepared_operation(
    prepared: PreparedOperation,
    authority: &mut RequestAuthority,
    send_queue: &mut VecDeque<WriteCommand>,
    fatal: &mut Option<RuntimeError>,
) {
    let key = prepared.key;
    let Some(caller) = authority.state.request(key).map(|request| request.caller()) else {
        // A preparation-stage request can disappear only when its caller
        // deadline rolls back the still-uncommitted reservation. The caller
        // cannot explicitly cancel yet because acknowledgement (and thus the
        // request key) is published only after preparation completes.
        authority.operation_pending.remove(&key);
        let _ = prepared
            .acknowledge
            .send(Err(RuntimeError::Terminal(TerminalOutcome::TimedOut)));
        return;
    };
    if let CallerOutcome::Terminal(outcome) = caller {
        authority.operation_pending.remove(&key);
        let _ = prepared
            .acknowledge
            .send(Err(RuntimeError::Terminal(outcome)));
        return;
    }

    let frame = match prepared.result {
        Ok(frame) => frame,
        Err(_) => {
            authority.state.reduce(OwnerEvent::PrepareFailed { key });
            let error = RuntimeError::Wire("prepare-outgoing");
            if let Some(mut pending) = authority.operation_pending.remove(&key)
                && let Some(terminal) = pending.terminal.take()
            {
                let _ = terminal.send(Err(error.clone()));
            }
            let _ = prepared.acknowledge.send(Err(error));
            return;
        }
    };
    let request_raw = prepared
        .retain_raw
        .then(|| frame.segments().first().cloned())
        .flatten();
    let Some(pending) = authority.operation_pending.get_mut(&key) else {
        let error = RuntimeError::Wire("prepared-operation-missing");
        let _ = prepared.acknowledge.send(Err(error.clone()));
        *fatal = Some(error);
        return;
    };
    pending.request_raw = request_raw.clone();
    send_queue.push_back(WriteCommand {
        key,
        members: Arc::from([key]),
        frame,
        cancel_before_write: CancellationToken::new(),
    });
    let _ = prepared
        .acknowledge
        .send(Ok(OperationSubmission { key, request_raw }));
    if let Some(message) = authority.early_responses.remove(&key) {
        process_decoded_response(message, authority, fatal);
    }
}

async fn process_compound_admission(
    command: CompoundAdmission,
    wire: &WirePipeline,
    authority: &mut RequestAuthority,
    send_queue: &mut VecDeque<WriteCommand>,
    fatal: &mut Option<RuntimeError>,
) -> Option<CompoundAdmission> {
    if command.operations.is_empty() {
        let _ = command
            .acknowledge
            .send(Err(RuntimeError::Wire("empty-compound")));
        return None;
    }
    if let Some(error) = command
        .operations
        .iter()
        .filter_map(TypedOperation::dependency)
        .find_map(|dependency| authority.objects.validate_active(dependency).err())
    {
        let _ = command.acknowledge.send(Err(RuntimeError::Object(error)));
        return None;
    }
    if authority
        .operation_pending
        .len()
        .saturating_add(command.operations.len())
        > authority.state.operation_limit()
    {
        let _ = command.acknowledge.send(Err(RuntimeError::Admission(
            AdmissionError::OperationsExhausted,
        )));
        return None;
    }

    let required_credits = match command
        .operations
        .iter()
        .map(|operation| operation.credit_charge(authority.large_mtu))
        .try_fold(0u32, |total, charge| {
            total.checked_add(u32::from(charge?)).ok_or(
                super::operation::OperationContractError::CreditChargeOverflow {
                    command: smb_msg::Command::Cancel,
                },
            )
        }) {
        Ok(total) => total,
        Err(_) => {
            let _ = command
                .acknowledge
                .send(Err(RuntimeError::Wire("credit-charge")));
            return None;
        }
    };
    if required_credits > authority.state.available_credits() {
        return Some(command);
    }

    let mut admitted = Vec::with_capacity(command.operations.len());
    let mut outgoing_messages = Vec::with_capacity(command.operations.len());
    for operation in command.operations {
        let payload_bytes = operation.payload_bytes();
        let credit_charge = match operation.credit_charge(authority.large_mtu) {
            Ok(charge) => charge,
            Err(_) => {
                for (key, _, _) in &admitted {
                    authority
                        .state
                        .reduce(OwnerEvent::PrepareFailed { key: *key });
                }
                let _ = command
                    .acknowledge
                    .send(Err(RuntimeError::Wire("credit-charge")));
                return None;
            }
        };
        let effects = authority.state.reduce(OwnerEvent::Admit {
            payload_bytes,
            credit_charge,
            caller_deadline: command.deadline,
        });
        let Some(OwnerEffect::Admitted(plan)) = effects.first() else {
            for (key, _, _) in &admitted {
                authority
                    .state
                    .reduce(OwnerEvent::PrepareFailed { key: *key });
            }
            let error = match effects.first() {
                Some(OwnerEffect::AdmissionRejected(error)) => RuntimeError::Admission(*error),
                _ => RuntimeError::OwnerTerminated,
            };
            let _ = command.acknowledge.send(Err(error));
            return None;
        };
        let key = plan.key;
        let response = operation.response_policy().clone();
        let replay = operation.replay_policy();
        let mut outgoing = operation.into_outgoing();
        outgoing.message.header.message_id = key.message_id;
        outgoing.message.header.credit_charge = plan.credit_charge;
        outgoing.message.header.credit_request = plan.credit_request;
        admitted.push((key, response, replay));
        outgoing_messages.push(outgoing);
    }

    let frame = match wire.transform_outgoing_compound(outgoing_messages).await {
        Ok(frame) => frame,
        Err(_) => {
            for (key, _, _) in &admitted {
                authority
                    .state
                    .reduce(OwnerEvent::PrepareFailed { key: *key });
            }
            let _ = command
                .acknowledge
                .send(Err(RuntimeError::Wire("prepare-compound")));
            return None;
        }
    };

    let keys = admitted
        .iter()
        .map(|(key, _, _)| *key)
        .collect::<Arc<[_]>>();
    let submissions = keys
        .iter()
        .copied()
        .map(|key| OperationSubmission {
            key,
            request_raw: None,
        })
        .collect();
    for (key, response, replay) in admitted {
        authority.operation_pending.insert(
            key,
            OperationPending {
                response,
                replay,
                request_raw: None,
                terminal: None,
                buffered: None,
                draining: false,
                caller_completed: false,
            },
        );
        if let Some(message) = authority.early_responses.remove(&key) {
            process_decoded_response(message, authority, fatal);
        }
    }
    send_queue.push_back(WriteCommand {
        key: keys[0],
        members: keys,
        frame,
        cancel_before_write: CancellationToken::new(),
    });
    let _ = command.acknowledge.send(Ok(submissions));
    None
}

struct CloseRequest {
    deadline: MonotonicTime,
    reply: oneshot::Sender<Result<CloseReport, RuntimeError>>,
}

fn close_admission_if(close: bool, admission: &mut mpsc::Receiver<AdmissionCommand>) {
    if close {
        admission.close();
    }
}

fn process_admission(
    command: AdmissionCommand,
    state: &mut GenerationState,
    terminals: &mut HashMap<RequestKey, oneshot::Sender<Result<TerminalOutcome, RuntimeError>>>,
    send_queue: &mut VecDeque<WriteCommand>,
) {
    let effects = state.reduce(OwnerEvent::Admit {
        payload_bytes: command.payload_bytes,
        credit_charge: command.credit_charge,
        caller_deadline: command.deadline,
    });
    match effects.first() {
        Some(OwnerEffect::Admitted(plan)) => {
            let key = plan.key;
            terminals.insert(key, command.terminal);
            send_queue.push_back(WriteCommand {
                key,
                members: Arc::from([key]),
                frame: command.frame,
                cancel_before_write: CancellationToken::new(),
            });
            let _ = command.acknowledge.send(Ok(key));
        }
        Some(OwnerEffect::AdmissionRejected(error)) => {
            let error = RuntimeError::Admission(*error);
            let _ = command.terminal.send(Err(error.clone()));
            let _ = command.acknowledge.send(Err(error));
        }
        _ => {
            let _ = command.terminal.send(Err(RuntimeError::OwnerTerminated));
            let _ = command.acknowledge.send(Err(RuntimeError::OwnerTerminated));
        }
    }
}

async fn handle_control(
    command: ControlCommand,
    wire: &WirePipeline,
    authority: &mut RequestAuthority,
    send_queue: &mut VecDeque<WriteCommand>,
    close_request: &mut Option<CloseRequest>,
) -> bool {
    match command {
        ControlCommand::CreateObject {
            parent,
            kind,
            reply,
        } => {
            let result = authority
                .objects
                .create_child(parent, kind)
                .map_err(RuntimeError::Object);
            let _ = reply.send(result);
            false
        }
        ControlCommand::LoseObjectGeneration { reply } => {
            let revoked = authority.objects.lose_generation().len();
            let _ = reply.send(Ok(revoked));
            false
        }
        ControlCommand::BeginObjectRecovery { object, reply } => {
            let result = authority
                .objects
                .begin_recovery(object)
                .map_err(RuntimeError::Object);
            let _ = reply.send(result);
            false
        }
        ControlCommand::PublishObjectReplacement { object, reply } => {
            let result = authority
                .objects
                .publish_replacement_revoking_descendants(object)
                .map_err(RuntimeError::Object)
                .and_then(|(effect, _revoked)| match effect {
                    super::object_state::ObjectEffect::ReplacementPublished {
                        replacement, ..
                    } => Ok(replacement),
                    super::object_state::ObjectEffect::Revoked(_) => {
                        Err(RuntimeError::Object(ObjectError::Stale))
                    }
                });
            let _ = reply.send(result);
            false
        }
        ControlCommand::FailObjectRecovery { object, reply } => {
            let result = authority
                .objects
                .fail_recovery(object)
                .map(|_| ())
                .map_err(RuntimeError::Object);
            let _ = reply.send(result);
            false
        }
        ControlCommand::InstallNotifications { sender } => {
            authority.notifications = Some(sender);
            false
        }
        ControlCommand::PreauthSnapshot { reply } => {
            let result = wire
                .snapshot_preauth_finalized()
                .await
                .map_err(|_| RuntimeError::Wire("preauth-snapshot"));
            let _ = reply.send(result);
            false
        }
        ControlCommand::ResetPreauthToNegotiate { reply } => {
            let result = wire
                .reset_preauth_to_negotiate()
                .await
                .map_err(|_| RuntimeError::Wire("preauth-reset"));
            let _ = reply.send(result);
            false
        }
        ControlCommand::AwaitOperation { key, reply } => {
            let Some(pending) = authority.operation_pending.get_mut(&key) else {
                let _ = reply.send(Err(RuntimeError::UnknownRequest(key)));
                return false;
            };
            if let Some(result) = pending.buffered.take() {
                pending.caller_completed = true;
                if !pending.draining {
                    authority.operation_pending.remove(&key);
                }
                let _ = reply.send(result);
            } else if pending.terminal.is_some() || pending.caller_completed {
                let _ = reply.send(Err(RuntimeError::AlreadyAwaited(key)));
            } else {
                pending.terminal = Some(reply);
            }
            false
        }
        ControlCommand::Negotiated { connection, reply } => {
            authority.large_mtu = connection.negotiation.caps.large_mtu();
            authority.state.set_target_credits(if authority.large_mtu {
                authority.target_credits
            } else {
                1
            });
            let result = wire
                .negotiated(&connection)
                .await
                .map_err(|_| RuntimeError::Wire("negotiated-policy"));
            let _ = reply.send(result);
            false
        }
        ControlCommand::SessionStarted { session, reply } => {
            let result = wire
                .session_started(&session)
                .await
                .map_err(|_| RuntimeError::Wire("session-started-policy"));
            let _ = reply.send(result);
            false
        }
        ControlCommand::SessionEnded { session, reply } => {
            let result = wire
                .session_ended(&session)
                .await
                .map_err(|_| RuntimeError::Wire("session-ended-policy"));
            let _ = reply.send(result);
            false
        }
        ControlCommand::Cancel { key, now } => {
            let removed_before_dispatch = if let Some(position) =
                send_queue.iter().position(|command| command.key == key)
                && let Some(command) = send_queue.remove(position)
            {
                command.cancel_before_write.cancel();
                true
            } else {
                false
            };
            if let Some(cancellation) = authority.frame_cancellations.get(&key) {
                cancellation.cancel();
            }
            let committed = authority
                .state
                .request(key)
                .is_some_and(|request| request.wire_committed());
            if removed_before_dispatch
                || committed
                || !authority.frame_cancellations.contains_key(&key)
            {
                let effects = authority.state.reduce(OwnerEvent::Cancel { key, now });
                apply_operation_effects(&effects, &mut authority.operation_pending);
                apply_owner_effects(effects, &mut authority.terminals);
            } else {
                authority.deferred_cancellations.entry(key).or_insert(now);
            }
            false
        }
        ControlCommand::Close { deadline, reply } => {
            if close_request.is_none() {
                *close_request = Some(CloseRequest { deadline, reply });
            } else {
                let _ = reply.send(Err(RuntimeError::Closed));
            }
            true
        }
    }
}

fn dispatch_next(
    write: &mut Option<Box<dyn SmbTransportWrite>>,
    active_write: &mut Option<ActiveWrite>,
    authority: &mut RequestAuthority,
    send_queue: &mut VecDeque<WriteCommand>,
) {
    if active_write.is_some() {
        return;
    }
    let Some(command) = send_queue.pop_front() else {
        return;
    };
    let key = command.key;
    let members = command.members.clone();
    let cancellation = command.cancel_before_write.clone();
    for member in members.iter().copied() {
        authority.state.reduce(OwnerEvent::Request {
            key: member,
            event: RequestProgress::Queued,
        });
    }
    authority.frame_members.insert(key, members);
    authority.frame_cancellations.insert(key, cancellation);
    let transport = write
        .take()
        .expect("an idle connection driver must own its write transport");
    *active_write = Some(write_step(transport, command));
}

#[allow(clippy::too_many_arguments)]
async fn process_or_enqueue_io(
    event: IoEvent,
    wire: &Arc<WirePipeline>,
    authority: &mut RequestAuthority,
    event_tx: &mpsc::Sender<RuntimeEvent>,
    emit_events: bool,
    decode_unsolicited: bool,
    fatal: &mut Option<RuntimeError>,
    inbound_preparations: &mut FuturesUnordered<BoxFuture<'static, PreparedInbound>>,
    inbound_order: &mut OrderedCompletionQueue<u64, PreparedInbound>,
    next_inbound_sequence: &mut u64,
) -> bool {
    let IoEvent::Inbound(frame) = event else {
        return process_io(event, authority, event_tx, emit_events, fatal).await;
    };
    let sequence = *next_inbound_sequence;
    let Some(next) = sequence.checked_add(1) else {
        *fatal = Some(RuntimeError::Wire("inbound-sequence-exhausted"));
        return true;
    };
    *next_inbound_sequence = next;
    let bytes = frame.len();
    let should_decode = decode_unsolicited || !authority.operation_pending.is_empty();
    let wire = wire.clone();
    inbound_order.reserve(sequence);
    inbound_preparations.push(
        async move {
            let result = if should_decode {
                wire.transform_incoming_all(frame.into_bytes()).await
            } else {
                Ok(Vec::new())
            };
            PreparedInbound {
                sequence,
                bytes,
                result,
            }
        }
        .boxed(),
    );
    false
}

fn finish_prepared_inbound(
    inbound: PreparedInbound,
    authority: &mut RequestAuthority,
    event_tx: &mpsc::Sender<RuntimeEvent>,
    emit_events: bool,
    fatal: &mut Option<RuntimeError>,
) -> bool {
    let messages = match inbound.result {
        Ok(messages) => messages,
        Err(error) => {
            tracing::warn!(?error, "failed to decode incoming SMB frame");
            *fatal = Some(RuntimeError::Wire("decode-incoming"));
            Vec::new()
        }
    };
    for message in messages {
        let key = RequestKey::new(
            authority.state.generation(),
            message.message.header.message_id,
        );
        if authority.operation_pending.contains_key(&key) {
            process_decoded_response(message, authority, fatal);
        } else if key.message_id == u64::MAX {
            if let Some(notifications) = &authority.notifications
                && notifications.try_send(message).is_err()
            {
                *fatal = Some(RuntimeError::EventBackpressure);
            }
        } else if authority.early_responses.len() >= authority.state.operation_limit()
            || authority.early_responses.insert(key, message).is_some()
        {
            *fatal = Some(RuntimeError::Wire("early-response-overflow-or-duplicate"));
        }
    }
    if emit_events
        && event_tx
            .try_send(RuntimeEvent::InboundFrame {
                bytes: inbound.bytes,
            })
            .is_err()
    {
        *fatal = Some(RuntimeError::EventBackpressure);
    }
    fatal.is_some()
}

async fn process_io(
    event: IoEvent,
    authority: &mut RequestAuthority,
    event_tx: &mpsc::Sender<RuntimeEvent>,
    emit_events: bool,
    fatal: &mut Option<RuntimeError>,
) -> bool {
    let runtime_event = match event {
        IoEvent::Inbound(_) => unreachable!("inbound frames are prepared before owner processing"),
        IoEvent::WriteCancelled(key) => {
            let now = authority
                .deferred_cancellations
                .remove(&key)
                .unwrap_or(MonotonicTime::ZERO);
            let members = authority
                .frame_members
                .remove(&key)
                .unwrap_or_else(|| Arc::from([key]));
            for member in members.iter().copied() {
                let effects = authority
                    .state
                    .reduce(OwnerEvent::Cancel { key: member, now });
                apply_operation_effects(&effects, &mut authority.operation_pending);
                apply_owner_effects(effects, &mut authority.terminals);
            }
            authority.frame_cancellations.remove(&key);
            None
        }
        IoEvent::WriteProgress { key, bytes } => {
            let members = authority
                .frame_members
                .get(&key)
                .cloned()
                .unwrap_or_else(|| Arc::from([key]));
            for member in members.iter().copied() {
                authority.state.reduce(OwnerEvent::Request {
                    key: member,
                    event: RequestProgress::WriteProgress { bytes },
                });
            }
            if let Some(now) = authority.deferred_cancellations.remove(&key) {
                let effects = authority.state.reduce(OwnerEvent::Cancel { key, now });
                apply_operation_effects(&effects, &mut authority.operation_pending);
                apply_owner_effects(effects, &mut authority.terminals);
            }
            Some(RuntimeEvent::WriteProgress { key, bytes })
        }
        IoEvent::WriteComplete(key) => {
            let members = authority
                .frame_members
                .remove(&key)
                .unwrap_or_else(|| Arc::from([key]));
            for member in members.iter().copied() {
                authority.state.reduce(OwnerEvent::Request {
                    key: member,
                    event: RequestProgress::WriteComplete,
                });
            }
            if let Some(now) = authority.deferred_cancellations.remove(&key) {
                let effects = authority.state.reduce(OwnerEvent::Cancel { key, now });
                apply_operation_effects(&effects, &mut authority.operation_pending);
                apply_owner_effects(effects, &mut authority.terminals);
            }
            authority.frame_cancellations.remove(&key);
            Some(RuntimeEvent::WriteComplete { key })
        }
        IoEvent::Failed { pump, error } => {
            *fatal = Some(RuntimeError::Transport(transport_error_code(&error)));
            Some(RuntimeEvent::PumpFailed {
                pump,
                code: transport_error_code(&error),
            })
        }
        IoEvent::Exited(pump) => Some(RuntimeEvent::PumpExited { pump }),
    };
    if emit_events
        && let Some(event) = runtime_event
        && event_tx.try_send(event).is_err()
    {
        *fatal = Some(RuntimeError::EventBackpressure);
    }
    fatal.is_some()
}

fn apply_owner_effects(
    effects: Vec<OwnerEffect>,
    terminals: &mut HashMap<RequestKey, oneshot::Sender<Result<TerminalOutcome, RuntimeError>>>,
) {
    for effect in effects {
        if let OwnerEffect::Request {
            key,
            effect: ReduceEffect::Publish(outcome),
        } = effect
            && let Some(terminal) = terminals.remove(&key)
        {
            let _ = terminal.send(Ok(outcome));
        }
    }
}

fn process_decoded_response(
    message: crate::command::CommandResponse,
    authority: &mut RequestAuthority,
    fatal: &mut Option<RuntimeError>,
) {
    let key = RequestKey::new(
        authority.state.generation(),
        message.message.header.message_id,
    );
    // An NTSTATUS the enum does not model is not a wire fault: the server may answer with any
    // status, and a late `STATUS_FILE_CLOSED` for a cancelled QUERY_DIRECTORY used to take the
    // whole connection down (issue #75). `ResponsePolicy::accepts_wire_status` admits it under
    // an `Any` policy, and the caller sees the raw status on the response.
    let status = smb_msg::Status::try_from(message.message.header.status).ok();
    let Some(pending) = authority.operation_pending.get(&key) else {
        *fatal = Some(RuntimeError::Wire("response-without-operation"));
        return;
    };
    if matches!(status, Some(smb_msg::Status::Pending)) {
        let Some(async_id) = message.message.header.async_id else {
            *fatal = Some(RuntimeError::Wire("pending-without-async-id"));
            return;
        };
        authority.state.reduce(OwnerEvent::Response {
            key,
            event: super::state::ResponseEvent::Pending { async_id },
            credit_grant: message.message.header.credit_request,
        });
        return;
    }
    let session_invalidated = matches!(
        status,
        Some(smb_msg::Status::UserSessionDeleted | smb_msg::Status::NetworkSessionExpired)
    );
    if message.form.unauthenticated_recovery_hint && !session_invalidated {
        *fatal = Some(RuntimeError::Wire("invalid-recovery-hint"));
        return;
    }
    if message.form.unauthenticated_recovery_hint {
        let effects = authority.state.reduce(OwnerEvent::RecoveryHint { key });
        apply_owner_effects(effects, &mut authority.terminals);
        complete_operation(
            &mut authority.operation_pending,
            key,
            Err(RuntimeError::Terminal(TerminalOutcome::SessionInvalidated)),
        );
        return;
    }
    // A draining operation has no caller left to hold the server to a status contract: whatever
    // the late answer says, it only settles the tombstone. The command must still match.
    let response_is_accepted = pending.draining
        || response_status_is_admissible(
            &pending.response,
            status,
            matches!(message.message.content, smb_msg::ResponseContent::Error(_)),
        );
    if message.message.header.command != pending.response.wire_command()
        || (!session_invalidated && !response_is_accepted)
    {
        *fatal = Some(RuntimeError::Wire("operation-response-contract"));
        return;
    }
    let effects = authority.state.reduce(OwnerEvent::Response {
        key,
        event: super::state::ResponseEvent::Final,
        // An invalidated server session cannot authenticate this response.
        // It may trigger recovery, but none of its mutable accounting fields
        // are trusted.
        credit_grant: message.message.header.credit_request,
    });
    let publishes_response = effects.iter().any(|effect| {
        matches!(
            effect,
            OwnerEffect::Request {
                key: found,
                effect: ReduceEffect::Publish(TerminalOutcome::Response),
            } if *found == key
        )
    });
    apply_owner_effects(effects, &mut authority.terminals);
    if publishes_response {
        complete_operation(
            &mut authority.operation_pending,
            key,
            Ok(OperationResult {
                key,
                response: message,
                request_raw: None,
            }),
        );
    } else if authority
        .operation_pending
        .get(&key)
        .is_some_and(|pending| pending.draining)
    {
        authority.operation_pending.remove(&key);
    }
}

fn response_status_is_admissible(
    policy: &ResponsePolicy,
    status: Option<smb_msg::Status>,
    is_server_error: bool,
) -> bool {
    policy.accepts_wire_status(status) || is_server_error
}

fn apply_operation_effects(
    effects: &[OwnerEffect],
    pending: &mut HashMap<RequestKey, OperationPending>,
) {
    for key in effects.iter().filter_map(|effect| match effect {
        OwnerEffect::BestEffortWireCancel(key) => Some(*key),
        _ => None,
    }) {
        if let Some(entry) = pending.get_mut(&key) {
            entry.draining = true;
            entry.request_raw = None;
        }
    }
    for effect in effects {
        if let OwnerEffect::Request {
            key,
            effect: ReduceEffect::Publish(outcome),
        } = effect
            && *outcome != TerminalOutcome::Response
        {
            if pending.get(key).is_some_and(|entry| entry.draining) {
                let entry = pending.get_mut(key).expect("draining entry must exist");
                let result = Err(RuntimeError::Terminal(*outcome));
                if let Some(terminal) = entry.terminal.take() {
                    let _ = terminal.send(result);
                    entry.caller_completed = true;
                } else {
                    entry.buffered = Some(result);
                }
            } else {
                complete_operation(pending, *key, Err(RuntimeError::Terminal(*outcome)));
            }
        }
    }
}

fn complete_operation(
    pending: &mut HashMap<RequestKey, OperationPending>,
    key: RequestKey,
    mut result: Result<OperationResult, RuntimeError>,
) {
    let Some(mut entry) = pending.remove(&key) else {
        return;
    };
    if let Ok(completed) = &mut result
        && completed.request_raw.is_none()
    {
        completed.request_raw = entry.request_raw.take();
    }
    if let Some(terminal) = entry.terminal.take() {
        let _ = terminal.send(result);
    } else {
        entry.buffered = Some(result);
        pending.insert(key, entry);
    }
}

#[cfg(test)]
async fn read_pump(
    mut read: Box<dyn SmbTransportRead>,
    io: mpsc::Sender<IoEvent>,
    shutdown: CancellationToken,
    maximum_frame_size: usize,
) -> PumpExit {
    loop {
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => break,
            result = read.receive_with_limit(maximum_frame_size) => match result {
                Ok(frame) => {
                    if io.send(IoEvent::Inbound(frame)).await.is_err() {
                        break;
                    }
                }
                Err(error) => {
                    let _ = io.send(IoEvent::Failed { pump: PumpName::Read, error }).await;
                    break;
                }
            }
        }
    }
    let _ = io.send(IoEvent::Exited(PumpName::Read)).await;
    PumpExit::Read
}

#[cfg(test)]
async fn write_pump(
    mut write: Box<dyn SmbTransportWrite>,
    mut commands: mpsc::Receiver<WriteCommand>,
    io: mpsc::Sender<IoEvent>,
    shutdown: CancellationToken,
) -> PumpExit {
    loop {
        let command = tokio::select! {
            biased;
            _ = shutdown.cancelled() => break,
            command = commands.recv() => match command {
                Some(command) => command,
                None => break,
            }
        };
        if command.cancel_before_write.is_cancelled() {
            if io.send(IoEvent::WriteCancelled(command.key)).await.is_err() {
                break;
            }
            continue;
        }
        let progress_permit = tokio::select! {
            biased;
            _ = command.cancel_before_write.cancelled() => {
                if io.send(IoEvent::WriteCancelled(command.key)).await.is_err() {
                    break;
                }
                continue;
            }
            permit = io.clone().reserve_owned() => match permit {
                Ok(permit) => permit,
                Err(_) => break,
            },
        };
        let progressed = Arc::new(AtomicUsize::new(0));
        let reported = Arc::new(AtomicUsize::new(0));
        let callback_progress = Arc::clone(&progressed);
        let callback_reported = Arc::clone(&reported);
        let mut first_progress = Some(progress_permit);
        let key = command.key;
        let mut observe = move |bytes| {
            callback_progress.fetch_add(bytes, Ordering::Relaxed);
            if bytes > 0
                && let Some(permit) = first_progress.take()
            {
                callback_reported.fetch_add(bytes, Ordering::Relaxed);
                permit.send(IoEvent::WriteProgress { key, bytes });
            }
        };
        let send = write.send_with_progress(&command.frame, &mut observe);
        tokio::pin!(send);
        let result = tokio::select! {
            biased;
            _ = command.cancel_before_write.cancelled() => {
                if progressed.load(Ordering::Relaxed) == 0 {
                    if io.send(IoEvent::WriteCancelled(command.key)).await.is_err() {
                        return PumpExit::Write;
                    }
                    continue;
                }
                send.await
            }
            result = &mut send => result,
        };
        let bytes = progressed
            .load(Ordering::Relaxed)
            .saturating_sub(reported.load(Ordering::Relaxed));
        if bytes > 0
            && io
                .send(IoEvent::WriteProgress {
                    key: command.key,
                    bytes,
                })
                .await
                .is_err()
        {
            return PumpExit::Write;
        }
        match result {
            Ok(()) => {
                if io.send(IoEvent::WriteComplete(command.key)).await.is_err() {
                    break;
                }
            }
            Err(error) => {
                let _ = io
                    .send(IoEvent::Failed {
                        pump: PumpName::Write,
                        error,
                    })
                    .await;
                break;
            }
        }
    }
    let _ = io.send(IoEvent::Exited(PumpName::Write)).await;
    PumpExit::Write
}

async fn fail_waiting_admissions(
    admissions: &mut mpsc::Receiver<AdmissionCommand>,
    error: RuntimeError,
) {
    while let Some(command) = admissions.recv().await {
        let _ = command.terminal.send(Err(error.clone()));
        let _ = command.acknowledge.send(Err(error.clone()));
    }
}

async fn fail_waiting_operations(
    admissions: &mut mpsc::Receiver<OperationAdmission>,
    error: RuntimeError,
) {
    while let Some(command) = admissions.recv().await {
        if let Some(terminal) = command.terminal {
            let _ = terminal.send(Err(error.clone()));
        }
        let _ = command.acknowledge.send(Err(error.clone()));
    }
}

async fn fail_waiting_compounds(
    admissions: &mut mpsc::Receiver<CompoundAdmission>,
    error: RuntimeError,
) {
    while let Some(command) = admissions.recv().await {
        let _ = command.acknowledge.send(Err(error.clone()));
    }
}

#[cfg(test)]
async fn join_pumps(
    pumps: &mut JoinSet<PumpExit>,
    clock: &dyn Clock,
    deadline: Option<MonotonicTime>,
) -> (usize, usize, bool) {
    let mut joined = 0;
    let mut failed = 0;
    let sleep = async {
        match deadline {
            Some(deadline) => clock.sleep_until(deadline).await,
            None => futures_util::future::pending().await,
        }
    };
    tokio::pin!(sleep);
    while !pumps.is_empty() {
        tokio::select! {
            result = pumps.join_next() => match result {
                Some(Ok(_)) => joined += 1,
                Some(Err(_)) => failed += 1,
                None => break,
            },
            _ = &mut sleep => {
                pumps.abort_all();
                while let Some(result) = pumps.join_next().await {
                    if result.is_ok() { joined += 1; } else { failed += 1; }
                }
                return (joined, failed, true);
            }
        }
    }
    (joined, failed, false)
}

fn transport_error_code(error: &TransportError) -> &'static str {
    match error {
        TransportError::AlreadyConnected => "already-connected",
        TransportError::InvalidMessage => "invalid-message",
        TransportError::FrameTooLarge { .. } => "frame-too-large",
        TransportError::SegmentLimitExceeded { .. } => "segment-limit",
        TransportError::CursorAdvanceOutOfBounds { .. } => "cursor-bounds",
        TransportError::WriteZero => "write-zero",
        TransportError::ParseError(_) => "parse",
        TransportError::NotConnected => "not-connected",
        TransportError::AlreadySplit => "already-split",
        TransportError::Timeout(_) => "timeout",
        TransportError::InvalidAddress(_) => "invalid-address",
        TransportError::IoError(_) => "io",
    }
}

#[cfg(all(test, feature = "test-support"))]
mod tests {
    use super::*;
    use crate::clock::ManualClock;
    use crate::command::{CommandRequest, Protection};
    use binrw::{BinRead, BinWrite};
    use bytes::Bytes;
    use futures_core::future::BoxFuture;
    use futures_util::FutureExt;
    use smb_transport::test_support::{ScriptedTransport, ScriptedTransportControl};
    use std::io::Cursor;
    use std::io::ErrorKind;
    use std::net::SocketAddr;
    use std::ops::Range;
    use tokio::sync::Notify;

    const SMB2_HEADER_SIZE: usize = 64;
    const SMB2_STATUS_RANGE: Range<usize> = 8..12;
    const SMB2_COMMAND_RANGE: Range<usize> = 12..14;
    const SMB2_EMPTY_ERROR_RESPONSE: [u8; 9] = [9, 0, 0, 0, 0, 0, 0, 0, 0];

    #[derive(Clone)]
    struct GateControl {
        began: Arc<Notify>,
        progressed: Arc<Notify>,
        release: Arc<Notify>,
    }

    impl GateControl {
        fn new() -> Self {
            Self {
                began: Arc::new(Notify::new()),
                progressed: Arc::new(Notify::new()),
                release: Arc::new(Notify::new()),
            }
        }
    }

    struct PendingRead;

    impl SmbTransportRead for PendingRead {
        fn receive_exact<'a>(
            &'a mut self,
            _out: &'a mut [u8],
        ) -> BoxFuture<'a, smb_transport::error::Result<()>> {
            futures_util::future::pending().boxed()
        }
    }

    struct OneFrameRead {
        framed: Bytes,
        offset: usize,
    }

    impl OneFrameRead {
        fn new(payload: &'static [u8]) -> Self {
            let mut framed = Vec::with_capacity(4 + payload.len());
            framed.extend_from_slice(&(payload.len() as u32).to_be_bytes());
            framed.extend_from_slice(payload);
            Self {
                framed: Bytes::from(framed),
                offset: 0,
            }
        }
    }

    impl SmbTransportRead for OneFrameRead {
        fn receive_exact<'a>(
            &'a mut self,
            out: &'a mut [u8],
        ) -> BoxFuture<'a, smb_transport::error::Result<()>> {
            async move {
                if self.offset == self.framed.len() {
                    futures_util::future::pending::<()>().await;
                }
                let end = self.offset.saturating_add(out.len());
                if end > self.framed.len() {
                    return Err(TransportError::IoError(std::io::Error::new(
                        ErrorKind::UnexpectedEof,
                        "one-frame test read exhausted",
                    )));
                }
                out.copy_from_slice(&self.framed[self.offset..end]);
                self.offset = end;
                Ok(())
            }
            .boxed()
        }
    }

    struct GatedWrite {
        control: GateControl,
        progress_before_release: bool,
    }

    impl SmbTransportWrite for GatedWrite {
        fn send_raw<'a>(
            &'a mut self,
            _bytes: &'a [u8],
        ) -> BoxFuture<'a, smb_transport::error::Result<()>> {
            futures_util::future::pending().boxed()
        }

        fn send_with_progress<'a>(
            &'a mut self,
            _frame: &'a SendFrame,
            progress: &'a mut (dyn FnMut(usize) + Send),
        ) -> BoxFuture<'a, smb_transport::error::Result<()>> {
            async move {
                self.control.began.notify_one();
                if self.progress_before_release {
                    progress(1);
                    self.control.progressed.notify_one();
                }
                self.control.release.notified().await;
                Ok(())
            }
            .boxed()
        }
    }

    struct GatedTransport {
        control: GateControl,
        progress_before_release: bool,
    }

    struct EarlyInboundTransport {
        control: GateControl,
    }

    impl SmbTransportRead for EarlyInboundTransport {
        fn receive_exact<'a>(
            &'a mut self,
            _out: &'a mut [u8],
        ) -> BoxFuture<'a, smb_transport::error::Result<()>> {
            futures_util::future::pending().boxed()
        }
    }

    impl SmbTransportWrite for EarlyInboundTransport {
        fn send_raw<'a>(
            &'a mut self,
            _bytes: &'a [u8],
        ) -> BoxFuture<'a, smb_transport::error::Result<()>> {
            futures_util::future::pending().boxed()
        }
    }

    impl SmbTransport for EarlyInboundTransport {
        fn connect<'a>(
            &'a mut self,
            _server_name: &'a str,
            _address: SocketAddr,
        ) -> BoxFuture<'a, smb_transport::error::Result<()>> {
            async { Ok(()) }.boxed()
        }

        fn default_port(&self) -> u16 {
            445
        }

        fn split(
            self: Box<Self>,
        ) -> smb_transport::error::Result<(Box<dyn SmbTransportRead>, Box<dyn SmbTransportWrite>)>
        {
            Ok((
                Box::new(OneFrameRead::new(b"early-response")),
                Box::new(GatedWrite {
                    control: self.control,
                    progress_before_release: true,
                }),
            ))
        }

        fn remote_address(&self) -> smb_transport::error::Result<SocketAddr> {
            Ok(SocketAddr::from(([127, 0, 0, 1], 445)))
        }
    }

    impl SmbTransportRead for GatedTransport {
        fn receive_exact<'a>(
            &'a mut self,
            _out: &'a mut [u8],
        ) -> BoxFuture<'a, smb_transport::error::Result<()>> {
            futures_util::future::pending().boxed()
        }
    }

    impl SmbTransportWrite for GatedTransport {
        fn send_raw<'a>(
            &'a mut self,
            _bytes: &'a [u8],
        ) -> BoxFuture<'a, smb_transport::error::Result<()>> {
            futures_util::future::pending().boxed()
        }
    }

    impl SmbTransport for GatedTransport {
        fn connect<'a>(
            &'a mut self,
            _server_name: &'a str,
            _address: SocketAddr,
        ) -> BoxFuture<'a, smb_transport::error::Result<()>> {
            async { Ok(()) }.boxed()
        }

        fn default_port(&self) -> u16 {
            445
        }

        fn split(
            self: Box<Self>,
        ) -> smb_transport::error::Result<(Box<dyn SmbTransportRead>, Box<dyn SmbTransportWrite>)>
        {
            Ok((
                Box::new(PendingRead),
                Box::new(GatedWrite {
                    control: self.control,
                    progress_before_release: self.progress_before_release,
                }),
            ))
        }

        fn remote_address(&self) -> smb_transport::error::Result<SocketAddr> {
            Ok(SocketAddr::from(([127, 0, 0, 1], 445)))
        }
    }

    struct PanicRead {
        trigger: Arc<Notify>,
    }

    impl SmbTransportRead for PanicRead {
        fn receive_exact<'a>(
            &'a mut self,
            _out: &'a mut [u8],
        ) -> BoxFuture<'a, smb_transport::error::Result<()>> {
            async move {
                self.trigger.notified().await;
                panic!("injected read pump panic");
            }
            .boxed()
        }
    }

    struct NoopWrite;

    impl SmbTransportWrite for NoopWrite {
        fn send_raw<'a>(
            &'a mut self,
            _bytes: &'a [u8],
        ) -> BoxFuture<'a, smb_transport::error::Result<()>> {
            async { Ok(()) }.boxed()
        }
    }

    struct PanicTransport {
        trigger: Arc<Notify>,
    }

    impl SmbTransportRead for PanicTransport {
        fn receive_exact<'a>(
            &'a mut self,
            _out: &'a mut [u8],
        ) -> BoxFuture<'a, smb_transport::error::Result<()>> {
            futures_util::future::pending().boxed()
        }
    }

    impl SmbTransportWrite for PanicTransport {
        fn send_raw<'a>(
            &'a mut self,
            _bytes: &'a [u8],
        ) -> BoxFuture<'a, smb_transport::error::Result<()>> {
            async { Ok(()) }.boxed()
        }
    }

    impl SmbTransport for PanicTransport {
        fn connect<'a>(
            &'a mut self,
            _server_name: &'a str,
            _address: SocketAddr,
        ) -> BoxFuture<'a, smb_transport::error::Result<()>> {
            async { Ok(()) }.boxed()
        }

        fn default_port(&self) -> u16 {
            445
        }

        fn split(
            self: Box<Self>,
        ) -> smb_transport::error::Result<(Box<dyn SmbTransportRead>, Box<dyn SmbTransportWrite>)>
        {
            Ok((
                Box::new(PanicRead {
                    trigger: self.trigger,
                }),
                Box::new(NoopWrite),
            ))
        }

        fn remote_address(&self) -> smb_transport::error::Result<SocketAddr> {
            Ok(SocketAddr::from(([127, 0, 0, 1], 445)))
        }
    }

    fn config() -> RuntimeConfig {
        RuntimeConfig {
            generation: GenerationId::new(1),
            initial_message_id: 10,
            initial_credits: 32,
            target_credits: 32,
            admission_limits: AdmissionLimits {
                max_operations: 32,
                max_payload_bytes: 1024 * 1024,
            },
            tombstone_drain_timeout: Duration::from_secs(5),
            admission_capacity: 32,
            io_capacity: 64,
            control_capacity: 32,
            event_capacity: 128,
            control_batch: 2,
            maximum_frame_size: 1024 * 1024,
            emit_events: true,
            decode_unsolicited: false,
            crypto_parallelism: 2,
        }
    }

    fn frame() -> SendFrame {
        SendFrame::from_segments(
            vec![Bytes::from_static(b"meta"), Bytes::from_static(b"payload")],
            2,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn completed_preparation_is_discarded_after_deadline_rollback() {
        let config = config();
        let mut authority = RequestAuthority {
            state: GenerationState::new(
                config.generation,
                config.initial_message_id,
                config.initial_credits,
                1,
                config.admission_limits,
                config.tombstone_drain_timeout,
            ),
            objects: ObjectRegistry::new(config.generation),
            terminals: HashMap::new(),
            operation_pending: HashMap::new(),
            early_responses: HashMap::new(),
            frame_members: HashMap::new(),
            frame_cancellations: HashMap::new(),
            deferred_cancellations: HashMap::new(),
            notifications: None,
            large_mtu: false,
            target_credits: config.target_credits,
        };
        let (acknowledge, acknowledged) = oneshot::channel();
        let prepared = PreparedOperation {
            key: RequestKey::new(config.generation, config.initial_message_id),
            result: Ok(frame()),
            retain_raw: false,
            acknowledge,
        };
        let mut send_queue = VecDeque::new();
        let mut fatal = None;

        finish_prepared_operation(prepared, &mut authority, &mut send_queue, &mut fatal);

        assert!(matches!(
            acknowledged.await.unwrap(),
            Err(RuntimeError::Terminal(TerminalOutcome::TimedOut))
        ));
        assert!(send_queue.is_empty());
        assert!(fatal.is_none());
    }

    #[tokio::test]
    async fn owner_publishes_typed_transport_exit_after_pumps_join() {
        let (transport, control) = ScriptedTransport::new();
        control.fail_read_on(1, std::io::ErrorKind::ConnectionReset);
        let clock = Arc::new(ManualClock::new());
        let (handle, _events) = start_generation(transport, clock, config());

        let exit = tokio::time::timeout(Duration::from_secs(1), handle.exited())
            .await
            .expect("transport loss must publish generation exit");
        assert_eq!(exit.generation, GenerationId::new(1));
        assert!(matches!(exit.cause, GenerationExitCause::Transport(_)));
        assert_eq!(exit.report.joined_tasks + exit.report.failed_tasks, 2);
    }

    #[tokio::test]
    async fn explicit_close_is_not_reported_as_recoverable_transport_loss() {
        let (transport, _) = ScriptedTransport::new();
        let clock = Arc::new(ManualClock::new());
        let (handle, _events) = start_generation(transport, clock.clone(), config());
        let observer = handle.clone();
        handle
            .close(clock.now().saturating_add(Duration::from_secs(1)))
            .await
            .unwrap();

        let exit = observer.exited().await;
        assert_eq!(exit.cause, GenerationExitCause::ExplicitClose);
        assert_eq!(exit.report.joined_tasks, 2);
    }

    fn session_setup_operation(return_raw: bool) -> TypedOperation {
        session_setup_operation_accepting(
            return_raw,
            &[
                smb_msg::Status::MoreProcessingRequired,
                smb_msg::Status::Success,
            ],
        )
    }

    fn session_setup_operation_accepting(
        return_raw: bool,
        statuses: &[smb_msg::Status],
    ) -> TypedOperation {
        let mut outgoing = CommandRequest::new(smb_msg::RequestContent::SessionSetup(
            smb_msg::SessionSetupRequest::new(
                vec![9, 8, 7],
                smb_msg::SessionSecurityMode::new(),
                smb_msg::SetupRequestFlags::new(),
                smb_msg::NegotiateCapabilities::new(),
            ),
        ))
        .with_return_raw_data(return_raw);
        outgoing.security = Some(Protection::None);
        TypedOperation::new(
            outgoing,
            ResponsePolicy::one_of(smb_msg::Command::SessionSetup, statuses.iter().copied())
                .unwrap(),
        )
        .unwrap()
    }

    fn session_setup_response(message_id: u64) -> Bytes {
        let mut response = smb_msg::PlainResponse::new(smb_msg::ResponseContent::SessionSetup(
            smb_msg::SessionSetupResponse {
                session_flags: smb_msg::SessionFlags::new(),
                buffer: vec![1, 2, 3],
            },
        ));
        response.header.status = smb_msg::Status::MoreProcessingRequired as u32;
        response.header.credit_request = 1;
        response.header.flags.set_server_to_redir(true);
        response.header.message_id = message_id;
        let mut encoded = Vec::new();
        response.write(&mut Cursor::new(&mut encoded)).unwrap();
        Bytes::from(encoded)
    }

    #[tokio::test]
    async fn same_command_server_error_is_returned_and_generation_remains_usable() {
        let (control, clock, handle, mut events) = test_runtime();

        let denied = handle
            .submit_operation(create_operation(), None)
            .await
            .unwrap();
        wait_for_write(&mut events, denied.key).await;
        control.push_server_frame(create_error_response(denied.key.message_id));
        let denied_result = denied.completion().await.unwrap();
        assert_eq!(
            denied_result.response.message.header.status().unwrap(),
            smb_msg::Status::AccessDenied
        );
        assert!(matches!(
            denied_result.response.message.content,
            smb_msg::ResponseContent::Error(_)
        ));

        let follow_up = handle
            .submit_operation(echo_operation(), None)
            .await
            .unwrap();
        let follow_up_key = follow_up.key;
        wait_for_write(&mut events, follow_up_key).await;
        control.push_server_frame(echo_response(follow_up_key.message_id));
        assert_eq!(follow_up.completion().await.unwrap().key, follow_up_key);
        handle
            .close(clock.now().saturating_add(Duration::from_secs(1)))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn wrong_command_server_error_remains_fatal() {
        let (control, _clock, handle, mut events) = test_runtime();
        let ticket = handle
            .submit_operation(create_operation(), None)
            .await
            .unwrap();
        wait_for_write(&mut events, ticket.key).await;
        let mut response = create_error_response(ticket.key.message_id).to_vec();
        set_wire_command(&mut response, smb_msg::Command::TreeConnect);
        control.push_server_frame(Bytes::from(response));

        assert!(ticket.completion().await.is_err());
        assert!(matches!(
            handle.exited().await.cause,
            GenerationExitCause::Transport(RuntimeError::Wire("operation-response-contract"))
        ));
    }

    #[tokio::test]
    async fn same_command_non_error_unexpected_status_remains_fatal() {
        let (control, _clock, handle, mut events) = test_runtime();
        let operation = session_setup_operation_accepting(false, &[smb_msg::Status::Success]);
        let ticket = handle.submit_operation(operation, None).await.unwrap();
        wait_for_write(&mut events, ticket.key).await;
        control.push_server_frame(session_setup_response(ticket.key.message_id));

        assert!(ticket.completion().await.is_err());
        assert!(matches!(
            handle.exited().await.cause,
            GenerationExitCause::Transport(RuntimeError::Wire("operation-response-contract"))
        ));
    }

    /// `STATUS_FILE_CORRUPT_ERROR`, which `smb_msg::Status` does not model. The live case was
    /// `STATUS_FILE_CLOSED` (a QUERY_DIRECTORY that lost the race against its handle's CLOSE);
    /// that one is modelled now, so the test needs another gap in the enum.
    const UNMODELLED_STATUS: u32 = 0xC000_0102;

    fn error_response_with_raw_status(message_id: u64, status: u32) -> Bytes {
        let mut encoded = create_error_response(message_id).to_vec();
        encoded[SMB2_STATUS_RANGE].copy_from_slice(&status.to_le_bytes());
        Bytes::from(encoded)
    }

    async fn assert_generation_still_serves(
        control: &ScriptedTransportControl,
        handle: &RuntimeHandle,
        events: &mut RuntimeEvents,
    ) {
        let follow_up = handle
            .submit_operation(echo_operation(), None)
            .await
            .unwrap();
        let follow_up_key = follow_up.key;
        wait_for_write(events, follow_up_key).await;
        control.push_server_frame(echo_response(follow_up_key.message_id));
        assert_eq!(follow_up.completion().await.unwrap().key, follow_up_key);
    }

    #[tokio::test]
    async fn unmodelled_error_status_reaches_the_caller_and_generation_remains_usable() {
        let (control, clock, handle, mut events) = test_runtime();
        assert!(smb_msg::Status::try_from(UNMODELLED_STATUS).is_err());

        let ticket = handle
            .submit_operation(create_operation(), None)
            .await
            .unwrap();
        wait_for_write(&mut events, ticket.key).await;
        control.push_server_frame(error_response_with_raw_status(
            ticket.key.message_id,
            UNMODELLED_STATUS,
        ));
        let result = ticket.completion().await.unwrap();
        assert_eq!(result.response.message.header.status, UNMODELLED_STATUS);
        assert!(matches!(
            result.response.message.content,
            smb_msg::ResponseContent::Error(_)
        ));

        assert_generation_still_serves(&control, &handle, &mut events).await;
        handle
            .close(clock.now().saturating_add(Duration::from_secs(1)))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn late_unmodelled_status_for_a_cancelled_operation_is_discarded() {
        let (control, clock, handle, mut events) = test_runtime();
        let ticket = handle
            .submit_operation(create_operation(), None)
            .await
            .unwrap();
        let key = ticket.key;
        wait_for_write(&mut events, key).await;
        handle.cancel(key, clock.now()).unwrap();
        assert!(ticket.completion().await.is_err());

        control.push_server_frame(error_response_with_raw_status(
            key.message_id,
            UNMODELLED_STATUS,
        ));
        assert_generation_still_serves(&control, &handle, &mut events).await;
        let report = handle
            .close(clock.now().saturating_add(Duration::from_secs(1)))
            .await
            .unwrap();
        assert_eq!(report.unresolved_requests, 0);
    }

    #[tokio::test]
    async fn late_off_policy_status_for_a_cancelled_operation_is_not_fatal() {
        let (control, clock, handle, mut events) = test_runtime();
        let operation = session_setup_operation_accepting(false, &[smb_msg::Status::Success]);
        let ticket = handle.submit_operation(operation, None).await.unwrap();
        let key = ticket.key;
        wait_for_write(&mut events, key).await;
        handle.cancel(key, clock.now()).unwrap();
        assert!(ticket.completion().await.is_err());

        // Same frame that is fatal for a live operation in
        // `same_command_non_error_unexpected_status_remains_fatal`.
        control.push_server_frame(session_setup_response(key.message_id));
        assert_generation_still_serves(&control, &handle, &mut events).await;
        handle
            .close(clock.now().saturating_add(Duration::from_secs(1)))
            .await
            .unwrap();
    }

    async fn wait_for_write(events: &mut RuntimeEvents, expected: RequestKey) {
        loop {
            if matches!(
                events.recv().await,
                Some(RuntimeEvent::WriteComplete { key }) if key == expected
            ) {
                return;
            }
        }
    }

    fn test_runtime() -> (
        ScriptedTransportControl,
        Arc<ManualClock>,
        RuntimeHandle,
        RuntimeEvents,
    ) {
        let (transport, control) = ScriptedTransport::new();
        let clock = Arc::new(ManualClock::new());
        let (handle, events) = start_generation(transport, clock.clone(), config());
        (control, clock, handle, events)
    }

    fn create_operation() -> TypedOperation {
        let mut outgoing = CommandRequest::new(
            smb_msg::CreateRequest {
                requested_oplock_level: smb_msg::OplockLevel::None,
                impersonation_level: smb_msg::ImpersonationLevel::Impersonation,
                desired_access: smb_fscc::FileAccessMask::new().with_generic_read(true),
                file_attributes: smb_fscc::FileAttributes::new(),
                share_access: smb_msg::ShareAccessFlags::new().with_read(true),
                create_disposition: smb_msg::CreateDisposition::Open,
                create_options: smb_msg::CreateOptions::new(),
                name: "denied.bin".into(),
                contexts: Vec::<smb_msg::CreateContextRequest>::new().into(),
            }
            .into(),
        );
        outgoing.security = Some(Protection::None);
        TypedOperation::new(
            outgoing,
            ResponsePolicy::one_of(smb_msg::Command::Create, [smb_msg::Status::Success]).unwrap(),
        )
        .unwrap()
    }

    fn create_error_response(message_id: u64) -> Bytes {
        let mut encoded = session_setup_response(message_id).to_vec();
        encoded.truncate(SMB2_HEADER_SIZE);
        encoded[SMB2_STATUS_RANGE]
            .copy_from_slice(&(smb_msg::Status::AccessDenied as u32).to_le_bytes());
        set_wire_command(&mut encoded, smb_msg::Command::Create);
        encoded.extend_from_slice(&SMB2_EMPTY_ERROR_RESPONSE);
        Bytes::from(encoded)
    }

    fn set_wire_command(encoded: &mut [u8], command: smb_msg::Command) {
        encoded[SMB2_COMMAND_RANGE].copy_from_slice(&(command as u16).to_le_bytes());
    }

    fn echo_operation() -> TypedOperation {
        let mut outgoing =
            CommandRequest::new(smb_msg::RequestContent::Echo(smb_msg::EchoRequest {}));
        outgoing.security = Some(Protection::None);
        TypedOperation::new(
            outgoing,
            ResponsePolicy::one_of(smb_msg::Command::Echo, [smb_msg::Status::Success]).unwrap(),
        )
        .unwrap()
    }

    fn echo_response(message_id: u64) -> Bytes {
        let mut response =
            smb_msg::PlainResponse::new(smb_msg::ResponseContent::Echo(smb_msg::EchoResponse {}));
        response.header.credit_request = 1;
        response.header.flags.set_server_to_redir(true);
        response.header.message_id = message_id;
        let mut encoded = Vec::new();
        response.write(&mut Cursor::new(&mut encoded)).unwrap();
        Bytes::from(encoded)
    }

    fn pending_session_setup_response(message_id: u64, async_id: u64) -> Bytes {
        let mut response = smb_msg::PlainResponse::new(smb_msg::ResponseContent::SessionSetup(
            smb_msg::SessionSetupResponse {
                session_flags: smb_msg::SessionFlags::new(),
                buffer: Vec::new(),
            },
        ));
        response.header.status = smb_msg::Status::Pending as u32;
        response.header.credit_request = 1;
        response.header.flags.set_server_to_redir(true);
        response.header.message_id = message_id;
        response.header.to_async(async_id);
        let mut encoded = Vec::new();
        response.write(&mut Cursor::new(&mut encoded)).unwrap();
        Bytes::from(encoded)
    }

    #[tokio::test]
    async fn runtime_owns_short_write_progress_and_joins_both_pumps_on_close() {
        let (transport, control) = ScriptedTransport::new();
        control.set_maximum_write(2);
        let clock = Arc::new(ManualClock::new());
        let (handle, mut events) = start_generation(transport, clock.clone(), config());
        let ticket = handle.submit(frame(), 7, 1, None).await.unwrap();
        let mut progress = Vec::new();
        loop {
            match events.recv().await {
                Some(RuntimeEvent::WriteProgress { key, bytes }) if key == ticket.key => {
                    progress.push(bytes);
                }
                Some(RuntimeEvent::WriteComplete { key }) if key == ticket.key => break,
                Some(_) => {}
                None => panic!("runtime events closed before write completion"),
            }
        }
        assert!(progress.iter().all(|bytes| *bytes > 0));
        assert_eq!(progress.iter().sum::<usize>(), 4 + frame().total_len());
        assert_eq!(
            control.captured_client_frames(),
            vec![Bytes::from_static(b"metapayload")]
        );

        let report = handle
            .close(clock.now().saturating_add(Duration::from_secs(1)))
            .await
            .unwrap();
        assert!(!report.timed_out);
        assert_eq!(report.joined_tasks, 2);
        assert_eq!(report.failed_tasks, 0);
        assert_eq!(
            ticket.completion().await,
            Ok(TerminalOutcome::OutcomeUnknown)
        );
    }

    #[tokio::test]
    async fn pre_cancelled_write_never_touches_transport() {
        let (transport, control) = ScriptedTransport::new();
        let (_, write) = transport.split().unwrap();
        let (command_tx, command_rx) = mpsc::channel(1);
        let (io_tx, mut io_rx) = mpsc::channel(8);
        let shutdown = CancellationToken::new();
        let pump = tokio::spawn(write_pump(write, command_rx, io_tx, shutdown.child_token()));
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let key = RequestKey::new(GenerationId::new(1), 1);
        command_tx
            .send(WriteCommand {
                key,
                members: Arc::from([key]),
                frame: frame(),
                cancel_before_write: cancellation,
            })
            .await
            .unwrap();
        assert!(matches!(io_rx.recv().await, Some(IoEvent::WriteCancelled(found)) if found == key));
        assert!(control.captured_client_frames().is_empty());
        shutdown.cancel();
        drop(command_tx);
        assert!(matches!(pump.await, Ok(PumpExit::Write)));
    }

    #[tokio::test]
    async fn write_zero_and_fault_report_typed_pump_failure_after_exact_progress() {
        for (maximum, fault) in [(0, None), (2, Some((3, ErrorKind::BrokenPipe)))] {
            let (transport, control) = ScriptedTransport::new();
            control.set_maximum_write(maximum);
            if let Some((operation, kind)) = fault {
                control.fail_write_on(operation, kind);
            }
            let (_, write) = transport.split().unwrap();
            let (command_tx, command_rx) = mpsc::channel(1);
            let (io_tx, mut io_rx) = mpsc::channel(16);
            let shutdown = CancellationToken::new();
            let pump = tokio::spawn(write_pump(write, command_rx, io_tx, shutdown.child_token()));
            let key = RequestKey::new(GenerationId::new(1), 1);
            command_tx
                .send(WriteCommand {
                    key,
                    members: Arc::from([key]),
                    frame: frame(),
                    cancel_before_write: CancellationToken::new(),
                })
                .await
                .unwrap();
            let mut progressed = 0;
            loop {
                match io_rx.recv().await {
                    Some(IoEvent::WriteProgress { bytes, .. }) => progressed += bytes,
                    Some(IoEvent::Failed {
                        pump: PumpName::Write,
                        ..
                    }) => break,
                    Some(_) => {}
                    None => panic!("write pump closed without failure"),
                }
            }
            if maximum == 0 {
                assert_eq!(progressed, 0);
            } else {
                assert!(progressed > 0);
            }
            shutdown.cancel();
            drop(command_tx);
            assert!(matches!(pump.await, Ok(PumpExit::Write)));
        }
    }

    #[tokio::test]
    async fn read_pump_reports_frame_then_injected_fault_without_registry_access() {
        let (transport, control) = ScriptedTransport::new();
        control.push_server_frame(Bytes::from_static(b"response"));
        control.fail_read_on(3, ErrorKind::ConnectionReset);
        let (read, _) = transport.split().unwrap();
        let (io_tx, mut io_rx) = mpsc::channel(8);
        let shutdown = CancellationToken::new();
        let pump = tokio::spawn(read_pump(read, io_tx, shutdown.child_token(), 1024));
        assert!(
            matches!(io_rx.recv().await, Some(IoEvent::Inbound(frame)) if frame.as_ref() == b"response")
        );
        assert!(matches!(
            io_rx.recv().await,
            Some(IoEvent::Failed {
                pump: PumpName::Read,
                ..
            })
        ));
        shutdown.cancel();
        assert!(matches!(pump.await, Ok(PumpExit::Read)));
    }

    #[tokio::test]
    async fn single_clock_deadline_completes_committed_caller_without_timer_task() {
        let (transport, _) = ScriptedTransport::new();
        let clock = Arc::new(ManualClock::new());
        let deadline = MonotonicTime::ZERO.saturating_add(Duration::from_millis(10));
        let (handle, mut events) = start_generation(transport, clock.clone(), config());
        let ticket = handle.submit(frame(), 7, 1, Some(deadline)).await.unwrap();
        loop {
            if matches!(events.recv().await, Some(RuntimeEvent::WriteComplete { key }) if key == ticket.key)
            {
                break;
            }
        }
        tokio::task::yield_now().await;
        clock.advance_to(deadline).await.unwrap();
        assert_eq!(
            ticket.completion().await,
            Ok(TerminalOutcome::OutcomeUnknown)
        );
        let report = handle
            .close(deadline.saturating_add(Duration::from_secs(1)))
            .await
            .unwrap();
        assert_eq!(report.joined_tasks, 2);
    }

    #[tokio::test]
    async fn bounded_control_flood_cannot_starve_admission_lane() {
        let (transport, _) = ScriptedTransport::new();
        let clock = Arc::new(ManualClock::new());
        let (handle, _events) = start_generation(transport, clock.clone(), config());
        for message_id in 100..132 {
            let _ = handle.cancel(
                RequestKey::new(GenerationId::new(1), message_id),
                MonotonicTime::ZERO,
            );
        }
        let ticket =
            tokio::time::timeout(Duration::from_secs(1), handle.submit(frame(), 0, 1, None))
                .await
                .expect("admission must not starve")
                .unwrap();
        assert_eq!(ticket.key.message_id, 10);
        let report = handle
            .close(clock.now().saturating_add(Duration::from_secs(1)))
            .await
            .unwrap();
        assert_eq!(report.joined_tasks, 2);
    }

    #[tokio::test]
    async fn cancellation_before_first_progress_is_provably_zero_byte() {
        let control = GateControl::new();
        let (command_tx, command_rx) = mpsc::channel(1);
        let (io_tx, mut io_rx) = mpsc::channel(8);
        let shutdown = CancellationToken::new();
        let pump = tokio::spawn(write_pump(
            Box::new(GatedWrite {
                control: control.clone(),
                progress_before_release: false,
            }),
            command_rx,
            io_tx,
            shutdown.child_token(),
        ));
        let cancellation = CancellationToken::new();
        let key = RequestKey::new(GenerationId::new(1), 1);
        command_tx
            .send(WriteCommand {
                key,
                members: Arc::from([key]),
                frame: frame(),
                cancel_before_write: cancellation.clone(),
            })
            .await
            .unwrap();
        control.began.notified().await;
        cancellation.cancel();
        assert!(matches!(io_rx.recv().await, Some(IoEvent::WriteCancelled(found)) if found == key));
        shutdown.cancel();
        drop(command_tx);
        assert!(matches!(pump.await, Ok(PumpExit::Write)));
    }

    #[tokio::test]
    async fn cancellation_after_first_progress_finishes_active_frame() {
        let control = GateControl::new();
        let (command_tx, command_rx) = mpsc::channel(1);
        let (io_tx, mut io_rx) = mpsc::channel(8);
        let shutdown = CancellationToken::new();
        let pump = tokio::spawn(write_pump(
            Box::new(GatedWrite {
                control: control.clone(),
                progress_before_release: true,
            }),
            command_rx,
            io_tx,
            shutdown.child_token(),
        ));
        let cancellation = CancellationToken::new();
        let key = RequestKey::new(GenerationId::new(1), 1);
        command_tx
            .send(WriteCommand {
                key,
                members: Arc::from([key]),
                frame: frame(),
                cancel_before_write: cancellation.clone(),
            })
            .await
            .unwrap();
        control.progressed.notified().await;
        cancellation.cancel();
        control.release.notify_one();
        assert!(
            matches!(io_rx.recv().await, Some(IoEvent::WriteProgress { key: found, bytes: 1 }) if found == key)
        );
        assert!(matches!(io_rx.recv().await, Some(IoEvent::WriteComplete(found)) if found == key));
        shutdown.cancel();
        drop(command_tx);
        assert!(matches!(pump.await, Ok(PumpExit::Write)));
    }

    #[tokio::test]
    async fn close_deadline_aborts_and_joins_a_stuck_active_write() {
        let control = GateControl::new();
        let transport = Box::new(GatedTransport {
            control: control.clone(),
            progress_before_release: true,
        });
        let clock = Arc::new(ManualClock::new());
        let (handle, mut events) = start_generation(transport, clock.clone(), config());
        let ticket = handle.submit(frame(), 7, 1, None).await.unwrap();
        loop {
            if matches!(events.recv().await, Some(RuntimeEvent::WriteProgress { key, .. }) if key == ticket.key)
            {
                break;
            }
        }
        let deadline = MonotonicTime::ZERO.saturating_add(Duration::from_millis(10));
        let close = tokio::spawn({
            let handle = handle.clone();
            async move { handle.close(deadline).await }
        });
        tokio::task::yield_now().await;
        clock.advance_to(deadline).await.unwrap();
        let report = close.await.unwrap().unwrap();
        assert!(report.timed_out);
        assert_eq!(report.joined_tasks + report.failed_tasks, 2);
        assert_eq!(
            ticket.completion().await,
            Ok(TerminalOutcome::OutcomeUnknown)
        );
    }

    #[tokio::test]
    async fn pump_panic_terminates_generation_and_joins_the_sibling() {
        let trigger = Arc::new(Notify::new());
        let transport = Box::new(PanicTransport {
            trigger: Arc::clone(&trigger),
        });
        let clock = Arc::new(ManualClock::new());
        let (handle, mut events) = start_generation(transport, clock, config());
        let ticket = handle.submit(frame(), 0, 1, None).await.unwrap();
        loop {
            if matches!(events.recv().await, Some(RuntimeEvent::WriteComplete { key }) if key == ticket.key)
            {
                break;
            }
        }
        trigger.notify_one();
        assert_eq!(
            ticket.completion().await,
            Ok(TerminalOutcome::OutcomeUnknown)
        );
        while tokio::time::timeout(Duration::from_secs(1), events.recv())
            .await
            .expect("owner must terminate after pump panic")
            .is_some()
        {}
        assert!(matches!(
            handle.submit(frame(), 0, 1, None).await,
            Err(RuntimeError::Closed)
        ));
    }

    #[tokio::test]
    async fn dropping_all_handles_closes_channels_and_reclaims_owner_and_pumps() {
        let (transport, _) = ScriptedTransport::new();
        let clock = Arc::new(ManualClock::new());
        let (handle, mut events) = start_generation(transport, clock, config());
        let ticket = handle.submit(frame(), 0, 1, None).await.unwrap();
        loop {
            if matches!(events.recv().await, Some(RuntimeEvent::WriteComplete { key }) if key == ticket.key)
            {
                break;
            }
        }
        drop(handle);
        assert_eq!(
            ticket.completion().await,
            Ok(TerminalOutcome::OutcomeUnknown)
        );
        while tokio::time::timeout(Duration::from_secs(1), events.recv())
            .await
            .expect("channel closure must stop runtime")
            .is_some()
        {}
    }

    #[tokio::test]
    async fn inbound_frame_can_arrive_before_write_completion_without_losing_request() {
        let control = GateControl::new();
        let transport = Box::new(EarlyInboundTransport {
            control: control.clone(),
        });
        let clock = Arc::new(ManualClock::new());
        let (handle, mut events) = start_generation(transport, clock.clone(), config());
        let ticket = handle.submit(frame(), 0, 1, None).await.unwrap();
        loop {
            if matches!(
                events.recv().await,
                Some(RuntimeEvent::InboundFrame { bytes: 14 })
            ) {
                break;
            }
        }
        control.release.notify_one();
        loop {
            if matches!(events.recv().await, Some(RuntimeEvent::WriteComplete { key }) if key == ticket.key)
            {
                break;
            }
        }
        let report = handle
            .close(clock.now().saturating_add(Duration::from_secs(1)))
            .await
            .unwrap();
        assert_eq!(report.joined_tasks, 2);
    }

    #[tokio::test]
    async fn typed_session_setup_is_stamped_correlated_and_completed_by_owner() {
        let (transport, control) = ScriptedTransport::new();
        control.push_server_frame(session_setup_response(10));

        let clock = Arc::new(ManualClock::new());
        let (handle, _events) = start_generation(transport, clock.clone(), config());
        let ticket = handle
            .submit_operation(session_setup_operation(true), None)
            .await
            .unwrap();
        assert_eq!(ticket.key.message_id, 10);
        let key = ticket.key;
        let result = tokio::time::timeout(Duration::from_secs(1), ticket.completion())
            .await
            .expect("typed response must complete")
            .unwrap();
        assert_eq!(result.key, key);
        assert_eq!(
            result.response.message.header.status().unwrap(),
            smb_msg::Status::MoreProcessingRequired
        );
        assert!(result.request_raw.is_some());

        let captured = control.captured_client_frames();
        let request = smb_msg::PlainRequest::read(&mut Cursor::new(captured[0].as_ref())).unwrap();
        assert_eq!(request.header.message_id, 10);
        assert_eq!(request.header.command, smb_msg::Command::SessionSetup);

        let report = handle
            .close(clock.now().saturating_add(Duration::from_secs(1)))
            .await
            .unwrap();
        assert_eq!(report.joined_tasks, 2);
    }

    #[tokio::test]
    async fn committed_cancel_retains_response_policy_until_async_final_drains() {
        let (transport, control) = ScriptedTransport::new();
        let clock = Arc::new(ManualClock::new());
        let (handle, mut events) = start_generation(transport, clock.clone(), config());
        let ticket = handle
            .submit_operation(session_setup_operation(false), None)
            .await
            .unwrap();
        let cancelled_key = ticket.key;
        loop {
            if matches!(events.recv().await, Some(RuntimeEvent::WriteComplete { key }) if key == ticket.key)
            {
                break;
            }
        }

        handle.cancel(cancelled_key, clock.now()).unwrap();
        assert!(matches!(
            ticket.completion().await,
            Err(RuntimeError::Terminal(TerminalOutcome::OutcomeUnknown))
        ));
        control.push_server_frame(pending_session_setup_response(cancelled_key.message_id, 77));
        control.push_server_frame(session_setup_response(cancelled_key.message_id));
        loop {
            if matches!(events.recv().await, Some(RuntimeEvent::InboundFrame { .. })) {
                break;
            }
        }
        tokio::task::yield_now().await;

        let next = handle
            .submit_operation(session_setup_operation(false), None)
            .await
            .unwrap();
        control.push_server_frame(session_setup_response(next.key.message_id));
        next.completion().await.unwrap();
        let report = handle
            .close(clock.now().saturating_add(Duration::from_secs(1)))
            .await
            .unwrap();
        assert_eq!(report.unresolved_requests, 0);
    }

    #[tokio::test]
    async fn typed_admission_waits_inside_owner_until_response_returns_credit() {
        let (transport, control) = ScriptedTransport::new();
        let clock = Arc::new(ManualClock::new());
        let mut runtime_config = config();
        runtime_config.initial_credits = 1;
        let (handle, mut events) = start_generation(transport, clock.clone(), runtime_config);

        let first = handle
            .submit_operation(session_setup_operation(false), None)
            .await
            .unwrap();
        let first_key = first.key;
        loop {
            if matches!(events.recv().await, Some(RuntimeEvent::WriteComplete { key }) if key == first.key)
            {
                break;
            }
        }

        let second_submit = tokio::spawn({
            let handle = handle.clone();
            async move {
                handle
                    .submit_operation(session_setup_operation(false), None)
                    .await
            }
        });
        tokio::task::yield_now().await;
        assert!(!second_submit.is_finished());

        control.push_server_frame(session_setup_response(first_key.message_id));
        first.completion().await.unwrap();
        let second = tokio::time::timeout(Duration::from_secs(1), second_submit)
            .await
            .expect("credit grant must wake owner admission")
            .unwrap()
            .unwrap();
        assert_eq!(second.key.message_id, first_key.message_id + 1);
        control.push_server_frame(session_setup_response(second.key.message_id));
        second.completion().await.unwrap();

        let report = handle
            .close(clock.now().saturating_add(Duration::from_secs(1)))
            .await
            .unwrap();
        assert_eq!(report.unresolved_requests, 0);
    }

    #[tokio::test]
    async fn stale_object_chain_is_rejected_before_wire_admission() {
        let (transport, control) = ScriptedTransport::new();
        let clock = Arc::new(ManualClock::new());
        let (handle, _events) = start_generation(transport, clock.clone(), config());
        let session = handle
            .create_object(handle.connection_object(), ObjectKind::Session)
            .await
            .unwrap();
        let share = handle
            .create_object(session, ObjectKind::Share)
            .await
            .unwrap();
        let resource = handle
            .create_object(share, ObjectKind::Resource)
            .await
            .unwrap();
        assert_eq!(handle.lose_object_generation().await.unwrap(), 4);

        let operation = session_setup_operation(false).with_dependency(resource);
        assert!(matches!(
            handle.submit_operation(operation, None).await,
            Err(RuntimeError::Object(ObjectError::ParentNotActive))
        ));
        assert!(control.captured_client_frames().is_empty());

        handle
            .close(clock.now().saturating_add(Duration::from_secs(1)))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn typed_cancel_before_first_progress_proves_cancelled() {
        let control = GateControl::new();
        let transport = Box::new(GatedTransport {
            control: control.clone(),
            progress_before_release: false,
        });
        let clock = Arc::new(ManualClock::new());
        let (handle, _events) = start_generation(transport, clock.clone(), config());
        let ticket = handle
            .submit_operation(session_setup_operation(false), None)
            .await
            .unwrap();
        let key = ticket.key;
        control.began.notified().await;
        handle.cancel(key, clock.now()).unwrap();
        assert!(matches!(
            ticket.completion().await,
            Err(RuntimeError::Terminal(TerminalOutcome::Cancelled))
        ));
        let report = handle
            .close(clock.now().saturating_add(Duration::from_secs(1)))
            .await
            .unwrap();
        assert_eq!(report.joined_tasks, 2);
    }

    #[tokio::test]
    async fn typed_deadline_after_write_commit_reports_outcome_unknown() {
        let (transport, _) = ScriptedTransport::new();
        let clock = Arc::new(ManualClock::new());
        let (handle, mut events) = start_generation(transport, clock.clone(), config());
        let deadline = clock.now().saturating_add(Duration::from_secs(1));
        let ticket = handle
            .submit_operation(session_setup_operation(false), Some(deadline))
            .await
            .unwrap();
        let key = ticket.key;
        loop {
            if matches!(events.recv().await, Some(RuntimeEvent::WriteComplete { key: found }) if found == key)
            {
                break;
            }
        }
        clock.advance(Duration::from_secs(1)).await.unwrap();
        assert!(matches!(
            ticket.completion().await,
            Err(RuntimeError::Terminal(TerminalOutcome::OutcomeUnknown))
        ));
        let report = handle
            .close(clock.now().saturating_add(Duration::from_secs(1)))
            .await
            .unwrap();
        assert_eq!(report.unresolved_requests, 0);
    }

    #[tokio::test]
    async fn detached_response_is_buffered_only_by_owner_until_awaited() {
        let (transport, control) = ScriptedTransport::new();
        control.push_server_frame(session_setup_response(10));
        let clock = Arc::new(ManualClock::new());
        let (handle, mut events) = start_generation(transport, clock.clone(), config());
        let submission = handle
            .submit_operation_detached(session_setup_operation(true), None)
            .await
            .unwrap();
        let key = submission.key;
        assert!(submission.request_raw.is_some());
        loop {
            if matches!(events.recv().await, Some(RuntimeEvent::InboundFrame { .. })) {
                break;
            }
        }
        let result = handle.await_operation(key).await.unwrap();
        assert_eq!(result.key, key);
        assert!(result.request_raw.is_some());
        assert!(matches!(
            handle.await_operation(key).await,
            Err(RuntimeError::UnknownRequest(found)) if found == key
        ));
        let report = handle
            .close(clock.now().saturating_add(Duration::from_secs(1)))
            .await
            .unwrap();
        assert_eq!(report.unresolved_requests, 0);
    }

    #[tokio::test]
    async fn response_before_admission_is_bounded_and_replayed_through_reducer() {
        let (transport, control) = ScriptedTransport::new();
        control.push_server_frame(session_setup_response(10));
        let clock = Arc::new(ManualClock::new());
        let mut runtime_config = config();
        runtime_config.decode_unsolicited = true;
        let (handle, mut events) = start_generation(transport, clock.clone(), runtime_config);
        loop {
            if matches!(events.recv().await, Some(RuntimeEvent::InboundFrame { .. })) {
                break;
            }
        }
        let ticket = handle
            .submit_operation(session_setup_operation(false), None)
            .await
            .unwrap();
        let result = ticket.completion().await.unwrap();
        assert_eq!(result.key.message_id, 10);
        assert_eq!(
            result.response.message.header.status().unwrap(),
            smb_msg::Status::MoreProcessingRequired
        );
        let report = handle
            .close(clock.now().saturating_add(Duration::from_secs(1)))
            .await
            .unwrap();
        assert_eq!(report.unresolved_requests, 0);
    }

    #[tokio::test]
    async fn unawaited_detached_results_remain_admission_bounded() {
        let (transport, control) = ScriptedTransport::new();
        control.push_server_frame(session_setup_response(10));
        let clock = Arc::new(ManualClock::new());
        let mut runtime_config = config();
        runtime_config.admission_limits.max_operations = 1;
        let (handle, mut events) = start_generation(transport, clock.clone(), runtime_config);
        let first = handle
            .submit_operation_detached(session_setup_operation(false), None)
            .await
            .unwrap()
            .key;
        loop {
            if matches!(events.recv().await, Some(RuntimeEvent::InboundFrame { .. })) {
                break;
            }
        }
        assert!(matches!(
            handle
                .submit_operation_detached(session_setup_operation(false), None)
                .await,
            Err(RuntimeError::Admission(AdmissionError::OperationsExhausted))
        ));
        handle.await_operation(first).await.unwrap();
        let second = handle
            .submit_operation_detached(session_setup_operation(false), None)
            .await
            .unwrap()
            .key;
        assert_eq!(second.message_id, 11);
        let report = handle
            .close(clock.now().saturating_add(Duration::from_secs(1)))
            .await
            .unwrap();
        assert_eq!(report.unresolved_requests, 0);
    }

    #[tokio::test]
    async fn compound_admission_seals_one_frame_and_assigns_every_member() {
        let (transport, control) = ScriptedTransport::new();
        let clock = Arc::new(ManualClock::new());
        let (handle, mut events) = start_generation(transport, clock.clone(), config());
        let submissions = handle
            .submit_compound_detached(
                vec![
                    session_setup_operation(false),
                    session_setup_operation(false),
                ],
                None,
            )
            .await
            .unwrap();
        assert_eq!(
            submissions
                .iter()
                .map(|submission| submission.key.message_id)
                .collect::<Vec<_>>(),
            vec![10, 11]
        );
        loop {
            if matches!(events.recv().await, Some(RuntimeEvent::WriteComplete { key }) if key == submissions[0].key)
            {
                break;
            }
        }
        let captured = control.captured_client_frames();
        assert_eq!(captured.len(), 1);
        let first = smb_msg::PlainRequest::read(&mut Cursor::new(captured[0].as_ref())).unwrap();
        assert_eq!(first.header.message_id, 10);
        assert!(first.header.next_command > 0);
        let second = smb_msg::PlainRequest::read(&mut Cursor::new(
            &captured[0][first.header.next_command as usize..],
        ))
        .unwrap();
        assert_eq!(second.header.message_id, 11);
        assert_eq!(second.header.next_command, 0);
        let report = handle
            .close(clock.now().saturating_add(Duration::from_secs(1)))
            .await
            .unwrap();
        assert_eq!(report.unresolved_requests, 0);
    }
}
