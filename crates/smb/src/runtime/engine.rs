use super::operation::{BootstrapCommand, BootstrapOperation, BootstrapResult};
use super::reducer::{GenerationId, ReduceEffect, RequestKey, TerminalOutcome};
use super::state::{
    AdmissionError, AdmissionLimits, GenerationState, OwnerEffect, OwnerEvent, RequestProgress,
};
use super::wire::WirePipeline;
use crate::clock::{Clock, MonotonicTime};
use crate::connection::connection_info::ConnectionInfo;
use crate::session::SessionAndChannel;
use smb_transport::{
    SendFrame, SmbTransport, SmbTransportRead, SmbTransportWrite, TransportError, TransportFrame,
};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy, Debug)]
pub(crate) struct RuntimeConfig {
    pub(crate) generation: GenerationId,
    pub(crate) initial_message_id: u64,
    pub(crate) initial_credits: u32,
    pub(crate) admission_limits: AdmissionLimits,
    pub(crate) tombstone_drain_timeout: Duration,
    pub(crate) admission_capacity: usize,
    pub(crate) io_capacity: usize,
    pub(crate) control_capacity: usize,
    pub(crate) event_capacity: usize,
    pub(crate) control_batch: usize,
    pub(crate) maximum_frame_size: usize,
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

pub(crate) struct RequestTicket {
    pub(crate) key: RequestKey,
    completion: oneshot::Receiver<Result<TerminalOutcome, RuntimeError>>,
}

pub(crate) struct BootstrapTicket {
    pub(crate) key: RequestKey,
    completion: oneshot::Receiver<Result<BootstrapResult, RuntimeError>>,
}

impl BootstrapTicket {
    pub(crate) async fn completion(self) -> Result<BootstrapResult, RuntimeError> {
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
    bootstrap: mpsc::Sender<BootstrapAdmission>,
    control: mpsc::Sender<ControlCommand>,
    owner_finished: CancellationToken,
}

impl RuntimeHandle {
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

    pub(crate) async fn submit_bootstrap(
        &self,
        operation: BootstrapOperation,
        credit_charge: u16,
        deadline: Option<MonotonicTime>,
    ) -> Result<BootstrapTicket, RuntimeError> {
        let (acknowledge, acknowledged) = oneshot::channel();
        let (terminal, completion) = oneshot::channel();
        self.bootstrap
            .try_send(BootstrapAdmission {
                operation,
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
        Ok(BootstrapTicket { key, completion })
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
    let (bootstrap_tx, bootstrap_rx) = mpsc::channel(config.admission_capacity.max(1));
    let (control_tx, control_rx) = mpsc::channel(config.control_capacity.max(1));
    let (event_tx, event_rx) = mpsc::channel(config.event_capacity.max(1));
    let owner_finished = CancellationToken::new();
    let handle = RuntimeHandle {
        admission: admission_tx,
        bootstrap: bootstrap_tx,
        control: control_tx,
        owner_finished: owner_finished.clone(),
    };
    tokio::spawn(async move {
        owner_task(
            transport,
            clock,
            config,
            admission_rx,
            bootstrap_rx,
            control_rx,
            event_tx,
        )
        .await;
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

struct BootstrapAdmission {
    operation: BootstrapOperation,
    credit_charge: u16,
    deadline: Option<MonotonicTime>,
    acknowledge: oneshot::Sender<Result<RequestKey, RuntimeError>>,
    terminal: oneshot::Sender<Result<BootstrapResult, RuntimeError>>,
}

struct BootstrapPending {
    command: BootstrapCommand,
    request_raw: Option<bytes::Bytes>,
    terminal: oneshot::Sender<Result<BootstrapResult, RuntimeError>>,
}

struct RequestAuthority {
    state: GenerationState,
    terminals: HashMap<RequestKey, oneshot::Sender<Result<TerminalOutcome, RuntimeError>>>,
    bootstrap_pending: HashMap<RequestKey, BootstrapPending>,
}

enum ControlCommand {
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
    frame: SendFrame,
    cancel_before_write: CancellationToken,
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

enum PumpExit {
    Read,
    Write,
}

#[allow(clippy::too_many_arguments)]
async fn owner_task(
    transport: Box<dyn SmbTransport>,
    clock: Arc<dyn Clock>,
    config: RuntimeConfig,
    mut admission_rx: mpsc::Receiver<AdmissionCommand>,
    mut bootstrap_rx: mpsc::Receiver<BootstrapAdmission>,
    mut control_rx: mpsc::Receiver<ControlCommand>,
    event_tx: mpsc::Sender<RuntimeEvent>,
) {
    let wire = WirePipeline::default();
    let Ok((read, write)) = transport.split() else {
        fail_waiting_admissions(&mut admission_rx, RuntimeError::Transport("split")).await;
        fail_waiting_bootstrap(&mut bootstrap_rx, RuntimeError::Transport("split")).await;
        return;
    };
    let (write_tx, write_rx) = mpsc::channel(1);
    let (io_tx, mut io_rx) = mpsc::channel(config.io_capacity.max(1));
    let shutdown = CancellationToken::new();
    let mut pumps = JoinSet::new();
    pumps.spawn(read_pump(
        read,
        io_tx.clone(),
        shutdown.child_token(),
        config.maximum_frame_size,
    ));
    pumps.spawn(write_pump(write, write_rx, io_tx, shutdown.child_token()));

    let mut authority = RequestAuthority {
        state: GenerationState::new(
            config.generation,
            config.initial_message_id,
            config.initial_credits,
            config.admission_limits,
            config.tombstone_drain_timeout,
        ),
        terminals: HashMap::new(),
        bootstrap_pending: HashMap::new(),
    };
    let mut frame_cancellations = HashMap::new();
    let mut deferred_cancellations = HashMap::new();
    let mut send_queue = VecDeque::new();
    let mut close_request = None;
    let mut fatal = None;

    loop {
        for _ in 0..config.control_batch.max(1) {
            match control_rx.try_recv() {
                Ok(command) => {
                    if handle_control(
                        command,
                        &wire,
                        &mut authority,
                        &mut frame_cancellations,
                        &mut deferred_cancellations,
                        &mut send_queue,
                        &mut close_request,
                    )
                    .await
                    {
                        admission_rx.close();
                        bootstrap_rx.close();
                    }
                }
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => break,
            }
        }

        if let Ok(event) = io_rx.try_recv()
            && process_io(
                event,
                &wire,
                &mut authority,
                &mut frame_cancellations,
                &mut deferred_cancellations,
                &event_tx,
                &mut fatal,
            )
            .await
        {
            admission_rx.close();
            bootstrap_rx.close();
        }
        if let Ok(command) = admission_rx.try_recv() {
            process_admission(
                command,
                &mut authority.state,
                &mut authority.terminals,
                &mut send_queue,
            );
        }
        if let Ok(command) = bootstrap_rx.try_recv() {
            process_bootstrap_admission(
                command,
                &wire,
                &mut authority.state,
                &mut authority.bootstrap_pending,
                &mut send_queue,
            )
            .await;
        }
        dispatch_next(
            &write_tx,
            &mut authority.state,
            &mut send_queue,
            &mut frame_cancellations,
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

        tokio::select! {
            biased;
            command = control_rx.recv() => match command {
                Some(command) => {
                    let close = handle_control(command, &wire, &mut authority, &mut frame_cancellations, &mut deferred_cancellations, &mut send_queue, &mut close_request).await;
                    close_admission_if(close, &mut admission_rx);
                    if close {
                        bootstrap_rx.close();
                    }
                }
                None if admission_rx.is_closed() => break,
                None => {}
            },
            event = io_rx.recv() => match event {
                Some(event) => {
                    if process_io(event, &wire, &mut authority, &mut frame_cancellations, &mut deferred_cancellations, &event_tx, &mut fatal).await {
                        admission_rx.close();
                        bootstrap_rx.close();
                    }
                }
                None => {
                    fatal = Some(RuntimeError::Transport("io-channel-closed"));
                    admission_rx.close();
                    bootstrap_rx.close();
                }
            },
            command = admission_rx.recv(), if !admission_rx.is_closed() => {
                if let Some(command) = command {
                    process_admission(command, &mut authority.state, &mut authority.terminals, &mut send_queue);
                }
            },
            command = bootstrap_rx.recv(), if !bootstrap_rx.is_closed() => {
                if let Some(command) = command {
                    process_bootstrap_admission(
                        command,
                        &wire,
                        &mut authority.state,
                        &mut authority.bootstrap_pending,
                        &mut send_queue,
                    ).await;
                }
            },
            _ = &mut deadline_sleep => {
                let effects = authority.state.reduce(OwnerEvent::AdvanceTime { now: clock.now() });
                apply_bootstrap_effects(&effects, &mut authority.bootstrap_pending);
                apply_owner_effects(effects, &mut authority.terminals);
                if authority.state.is_unhealthy() {
                    fatal = Some(RuntimeError::Transport("generation-unhealthy"));
                    admission_rx.close();
                    bootstrap_rx.close();
                }
            }
            completion = pumps.join_next() => {
                match completion {
                    Some(Ok(PumpExit::Read)) => fatal = Some(RuntimeError::Transport("read-pump-exited")),
                    Some(Ok(PumpExit::Write)) => fatal = Some(RuntimeError::Transport("write-pump-exited")),
                    Some(Err(_)) => fatal = Some(RuntimeError::Transport("pump-panicked")),
                    None => fatal = Some(RuntimeError::Transport("pumps-exited")),
                }
                admission_rx.close();
                bootstrap_rx.close();
            }
        }
    }

    admission_rx.close();
    bootstrap_rx.close();
    fail_waiting_admissions(
        &mut admission_rx,
        fatal.clone().unwrap_or(RuntimeError::Closed),
    )
    .await;
    fail_waiting_bootstrap(
        &mut bootstrap_rx,
        fatal.clone().unwrap_or(RuntimeError::Closed),
    )
    .await;
    for queued in send_queue {
        queued.cancel_before_write.cancel();
    }
    for cancellation in frame_cancellations.values() {
        cancellation.cancel();
    }
    drop(write_tx);
    shutdown.cancel();
    let effects = authority.state.reduce(OwnerEvent::Disconnect);
    apply_bootstrap_effects(&effects, &mut authority.bootstrap_pending);
    apply_owner_effects(effects, &mut authority.terminals);
    for (_, terminal) in authority.terminals.drain() {
        let _ = terminal.send(Err(fatal.clone().unwrap_or(RuntimeError::Closed)));
    }
    for (_, pending) in authority.bootstrap_pending.drain() {
        let _ = pending
            .terminal
            .send(Err(fatal.clone().unwrap_or(RuntimeError::Closed)));
    }

    let close_deadline = close_request
        .as_ref()
        .map(|request: &CloseRequest| request.deadline);
    let (joined_tasks, failed_tasks, timed_out) =
        join_pumps(&mut pumps, clock.as_ref(), close_deadline).await;
    if let Some(request) = close_request {
        let _ = request.reply.send(Ok(CloseReport {
            timed_out,
            unresolved_requests: authority.state.unresolved_callers(),
            joined_tasks,
            failed_tasks,
        }));
    }
}

async fn process_bootstrap_admission(
    command: BootstrapAdmission,
    wire: &WirePipeline,
    state: &mut GenerationState,
    pending: &mut HashMap<RequestKey, BootstrapPending>,
    send_queue: &mut VecDeque<WriteCommand>,
) {
    let payload_bytes = command.operation.payload_bytes();
    let effects = state.reduce(OwnerEvent::Admit {
        payload_bytes,
        credit_charge: command.credit_charge,
        caller_deadline: command.deadline,
    });
    let Some(OwnerEffect::Admitted(plan)) = effects.first() else {
        let error = match effects.first() {
            Some(OwnerEffect::AdmissionRejected(error)) => RuntimeError::Admission(*error),
            _ => RuntimeError::OwnerTerminated,
        };
        let _ = command.terminal.send(Err(error.clone()));
        let _ = command.acknowledge.send(Err(error));
        return;
    };

    let key = plan.key;
    let operation_command = command.operation.command();
    let mut outgoing = command.operation.into_outgoing();
    outgoing.message.header.message_id = key.message_id;
    let retain_raw = outgoing.return_raw_data;
    let frame = match wire.transform_outgoing(outgoing).await {
        Ok(frame) => frame,
        Err(_) => {
            state.reduce(OwnerEvent::PrepareFailed { key });
            let error = RuntimeError::Wire("prepare-outgoing");
            let _ = command.terminal.send(Err(error.clone()));
            let _ = command.acknowledge.send(Err(error));
            return;
        }
    };
    let request_raw = retain_raw
        .then(|| frame.segments().first().cloned())
        .flatten();
    pending.insert(
        key,
        BootstrapPending {
            command: operation_command,
            request_raw,
            terminal: command.terminal,
        },
    );
    send_queue.push_back(WriteCommand {
        key,
        frame,
        cancel_before_write: CancellationToken::new(),
    });
    let _ = command.acknowledge.send(Ok(key));
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
    frame_cancellations: &mut HashMap<RequestKey, CancellationToken>,
    deferred_cancellations: &mut HashMap<RequestKey, MonotonicTime>,
    send_queue: &mut VecDeque<WriteCommand>,
    close_request: &mut Option<CloseRequest>,
) -> bool {
    match command {
        ControlCommand::Negotiated { connection, reply } => {
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
            if let Some(cancellation) = frame_cancellations.get(&key) {
                cancellation.cancel();
            }
            let committed = authority
                .state
                .request(key)
                .is_some_and(|request| request.wire_committed());
            if removed_before_dispatch || committed || !frame_cancellations.contains_key(&key) {
                let effects = authority.state.reduce(OwnerEvent::Cancel { key, now });
                apply_bootstrap_effects(&effects, &mut authority.bootstrap_pending);
                apply_owner_effects(effects, &mut authority.terminals);
            } else {
                deferred_cancellations.entry(key).or_insert(now);
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
    write_tx: &mpsc::Sender<WriteCommand>,
    state: &mut GenerationState,
    send_queue: &mut VecDeque<WriteCommand>,
    frame_cancellations: &mut HashMap<RequestKey, CancellationToken>,
) {
    let Some(command) = send_queue.pop_front() else {
        return;
    };
    let key = command.key;
    let cancellation = command.cancel_before_write.clone();
    match write_tx.try_send(command) {
        Ok(()) => {
            state.reduce(OwnerEvent::Request {
                key,
                event: RequestProgress::Queued,
            });
            frame_cancellations.insert(key, cancellation);
        }
        Err(mpsc::error::TrySendError::Full(command)) => send_queue.push_front(command),
        Err(mpsc::error::TrySendError::Closed(command)) => {
            command.cancel_before_write.cancel();
            state.reduce(OwnerEvent::PrepareFailed { key });
        }
    }
}

async fn process_io(
    event: IoEvent,
    wire: &WirePipeline,
    authority: &mut RequestAuthority,
    frame_cancellations: &mut HashMap<RequestKey, CancellationToken>,
    deferred_cancellations: &mut HashMap<RequestKey, MonotonicTime>,
    event_tx: &mpsc::Sender<RuntimeEvent>,
    fatal: &mut Option<RuntimeError>,
) -> bool {
    let runtime_event = match event {
        IoEvent::Inbound(frame) => {
            let bytes = frame.len();
            if !authority.bootstrap_pending.is_empty() {
                let messages = match wire.transform_incoming_all(frame.into_bytes()).await {
                    Ok(messages) => messages,
                    Err(_) => {
                        *fatal = Some(RuntimeError::Wire("decode-incoming"));
                        Vec::new()
                    }
                };
                for message in messages {
                    let key = RequestKey::new(
                        authority.state.generation(),
                        message.message.header.message_id,
                    );
                    let status = match message.message.header.status() {
                        Ok(status) => status,
                        Err(_) => {
                            *fatal = Some(RuntimeError::Wire("invalid-status"));
                            break;
                        }
                    };
                    if status == smb_msg::Status::Pending {
                        let Some(async_id) = message.message.header.async_id else {
                            *fatal = Some(RuntimeError::Wire("pending-without-async-id"));
                            break;
                        };
                        authority.state.reduce(OwnerEvent::Response {
                            key,
                            event: super::state::ResponseEvent::Pending { async_id },
                            credit_grant: message.message.header.credit_request,
                        });
                        continue;
                    }
                    let Some(pending) = authority.bootstrap_pending.get(&key) else {
                        continue;
                    };
                    if message.message.header.command != pending.command.wire_command()
                        || !pending.command.accepts_status(status)
                    {
                        *fatal = Some(RuntimeError::Wire("bootstrap-response-contract"));
                        break;
                    }
                    let effects = authority.state.reduce(OwnerEvent::Response {
                        key,
                        event: super::state::ResponseEvent::Final,
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
                    if publishes_response
                        && let Some(pending) = authority.bootstrap_pending.remove(&key)
                    {
                        let _ = pending.terminal.send(Ok(BootstrapResult {
                            key,
                            response: message,
                            request_raw: pending.request_raw,
                        }));
                    }
                }
            }
            Some(RuntimeEvent::InboundFrame { bytes })
        }
        IoEvent::WriteCancelled(key) => {
            let now = deferred_cancellations
                .remove(&key)
                .unwrap_or(MonotonicTime::ZERO);
            let effects = authority.state.reduce(OwnerEvent::Cancel { key, now });
            apply_bootstrap_effects(&effects, &mut authority.bootstrap_pending);
            apply_owner_effects(effects, &mut authority.terminals);
            frame_cancellations.remove(&key);
            None
        }
        IoEvent::WriteProgress { key, bytes } => {
            authority.state.reduce(OwnerEvent::Request {
                key,
                event: RequestProgress::WriteProgress { bytes },
            });
            if let Some(now) = deferred_cancellations.remove(&key) {
                let effects = authority.state.reduce(OwnerEvent::Cancel { key, now });
                apply_bootstrap_effects(&effects, &mut authority.bootstrap_pending);
                apply_owner_effects(effects, &mut authority.terminals);
            }
            Some(RuntimeEvent::WriteProgress { key, bytes })
        }
        IoEvent::WriteComplete(key) => {
            authority.state.reduce(OwnerEvent::Request {
                key,
                event: RequestProgress::WriteComplete,
            });
            if let Some(now) = deferred_cancellations.remove(&key) {
                let effects = authority.state.reduce(OwnerEvent::Cancel { key, now });
                apply_bootstrap_effects(&effects, &mut authority.bootstrap_pending);
                apply_owner_effects(effects, &mut authority.terminals);
            }
            frame_cancellations.remove(&key);
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
    if let Some(event) = runtime_event
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

fn apply_bootstrap_effects(
    effects: &[OwnerEffect],
    pending: &mut HashMap<RequestKey, BootstrapPending>,
) {
    for effect in effects {
        if let OwnerEffect::Request {
            key,
            effect: ReduceEffect::Publish(outcome),
        } = effect
            && *outcome != TerminalOutcome::Response
            && let Some(pending) = pending.remove(key)
        {
            let _ = pending.terminal.send(Err(RuntimeError::Terminal(*outcome)));
        }
    }
}

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
        let progressed = Arc::new(AtomicUsize::new(0));
        let callback_progress = Arc::clone(&progressed);
        let mut observe = move |bytes| {
            callback_progress.fetch_add(bytes, Ordering::Relaxed);
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
        let bytes = progressed.load(Ordering::Relaxed);
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

async fn fail_waiting_bootstrap(
    admissions: &mut mpsc::Receiver<BootstrapAdmission>,
    error: RuntimeError,
) {
    while let Some(command) = admissions.recv().await {
        let _ = command.terminal.send(Err(error.clone()));
        let _ = command.acknowledge.send(Err(error.clone()));
    }
}

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
        #[cfg(feature = "quic")]
        TransportError::QuicError(_) => "quic",
        #[cfg(feature = "rdma")]
        TransportError::RdmaError(_) => "rdma",
    }
}

#[cfg(all(test, feature = "test-support"))]
mod tests {
    use super::*;
    use crate::clock::ManualClock;
    use binrw::{BinRead, BinWrite};
    use bytes::Bytes;
    use futures_core::future::BoxFuture;
    use futures_util::FutureExt;
    use smb_transport::test_support::ScriptedTransport;
    use std::io::Cursor;
    use std::io::ErrorKind;
    use std::net::SocketAddr;
    use tokio::sync::Notify;

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
        }
    }

    fn frame() -> SendFrame {
        SendFrame::from_segments(
            vec![Bytes::from_static(b"meta"), Bytes::from_static(b"payload")],
            2,
        )
        .unwrap()
    }

    fn session_setup_operation(return_raw: bool) -> BootstrapOperation {
        let mut outgoing = crate::msg_handler::OutgoingMessage::new(
            smb_msg::RequestContent::SessionSetup(smb_msg::SessionSetupRequest::new(
                vec![9, 8, 7],
                smb_msg::SessionSecurityMode::new(),
                smb_msg::SetupRequestFlags::new(),
                smb_msg::NegotiateCapabilities::new(),
            )),
        )
        .with_return_raw_data(return_raw);
        outgoing.security = Some(crate::msg_handler::Protection::None);
        BootstrapOperation::new(BootstrapCommand::SessionSetup, outgoing).unwrap()
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
            Ok(TerminalOutcome::GenerationLost)
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
        let (handle, _events) = start_generation(transport, clock.clone(), config());
        let ticket = handle.submit(frame(), 7, 1, None).await.unwrap();
        control.progressed.notified().await;
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
            Ok(TerminalOutcome::GenerationLost)
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
        trigger.notify_one();
        assert_eq!(
            ticket.completion().await,
            Ok(TerminalOutcome::GenerationLost)
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
        drop(handle);
        assert_eq!(
            ticket.completion().await,
            Ok(TerminalOutcome::GenerationLost)
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
        let mut response = smb_msg::PlainResponse::new(smb_msg::ResponseContent::SessionSetup(
            smb_msg::SessionSetupResponse {
                session_flags: smb_msg::SessionFlags::new(),
                buffer: vec![1, 2, 3],
            },
        ));
        response.header.status = smb_msg::Status::MoreProcessingRequired as u32;
        response.header.credit_request = 1;
        response.header.flags.set_server_to_redir(true);
        response.header.message_id = 10;
        let mut encoded = Vec::new();
        response.write(&mut Cursor::new(&mut encoded)).unwrap();
        control.push_server_frame(Bytes::from(encoded));

        let clock = Arc::new(ManualClock::new());
        let (handle, _events) = start_generation(transport, clock.clone(), config());
        let ticket = handle
            .submit_bootstrap(session_setup_operation(true), 1, None)
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
    async fn typed_cancel_before_first_progress_proves_cancelled() {
        let control = GateControl::new();
        let transport = Box::new(GatedTransport {
            control: control.clone(),
            progress_before_release: false,
        });
        let clock = Arc::new(ManualClock::new());
        let (handle, _events) = start_generation(transport, clock.clone(), config());
        let ticket = handle
            .submit_bootstrap(session_setup_operation(false), 1, None)
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
            .submit_bootstrap(session_setup_operation(false), 1, Some(deadline))
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
}
