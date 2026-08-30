use crate::clock::{Clock, ManualClock, MonotonicTime};
use futures_util::FutureExt;
use serde::Serialize;
use smb_transport::test_support::{ScriptedTransport, ScriptedTransportControl};
use std::collections::BTreeSet;
use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::sync::{Arc, Mutex};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum ScenarioEvent {
    TaskStarted { name: String },
    TaskSucceeded { name: String },
    TaskFailed { name: String, code: String },
    TaskPanicked { name: String },
    TaskCancelled { name: String },
    ShutdownStarted,
    ShutdownCompleted { timed_out: bool },
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct ScenarioReport {
    pub events: Vec<ScenarioEvent>,
    pub timed_out: bool,
    pub remaining_tasks: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalOutcome {
    Response,
    Cancelled,
    TimedOut,
    Failed,
    OutcomeUnknown,
}

#[derive(Clone, Debug, Default)]
pub struct TerminalProbe {
    outcome: Arc<Mutex<Option<TerminalOutcome>>>,
}

impl TerminalProbe {
    pub fn try_commit(&self, outcome: TerminalOutcome) -> bool {
        let Ok(mut current) = self.outcome.lock() else {
            return false;
        };
        if current.is_some() {
            return false;
        }
        *current = Some(outcome);
        true
    }

    pub fn outcome(&self) -> Option<TerminalOutcome> {
        self.outcome.lock().ok().and_then(|outcome| *outcome)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ScenarioError {
    #[error("scenario transport has already been taken")]
    TransportTaken,
    #[error("scenario task name must not be empty")]
    EmptyTaskName,
    #[error("scenario task name must be a stable identifier")]
    InvalidTaskName,
    #[error("scenario task name is already active: {0}")]
    DuplicateTaskName(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScenarioTaskError {
    kind: ScenarioTaskErrorKind,
    code: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ScenarioTaskErrorKind {
    Failed,
    Cancelled,
}

impl ScenarioTaskError {
    pub fn failed(code: impl Into<String>) -> Self {
        let code = code.into();
        Self {
            kind: ScenarioTaskErrorKind::Failed,
            code: if is_stable_identifier(&code) {
                code
            } else {
                "invalid-failure-code".to_string()
            },
        }
    }

    pub fn cancelled() -> Self {
        Self {
            kind: ScenarioTaskErrorKind::Cancelled,
            code: "cancelled".to_string(),
        }
    }
}

impl From<smb_transport::TransportError> for ScenarioTaskError {
    fn from(error: smb_transport::TransportError) -> Self {
        let code = match error {
            smb_transport::TransportError::AlreadyConnected => "transport-already-connected",
            smb_transport::TransportError::InvalidMessage => "transport-invalid-message",
            smb_transport::TransportError::FrameTooLarge { .. } => "transport-frame-too-large",
            smb_transport::TransportError::SegmentLimitExceeded { .. } => "transport-segment-limit",
            smb_transport::TransportError::CursorAdvanceOutOfBounds { .. } => {
                "transport-cursor-bounds"
            }
            smb_transport::TransportError::WriteZero => "transport-write-zero",
            smb_transport::TransportError::ParseError(_) => "transport-parse",
            smb_transport::TransportError::NotConnected => "transport-not-connected",
            smb_transport::TransportError::AlreadySplit => "transport-already-split",
            smb_transport::TransportError::Timeout(_) => "transport-timeout",
            smb_transport::TransportError::InvalidAddress(_) => "transport-invalid-address",
            smb_transport::TransportError::IoError(_) => "transport-io",
        };
        Self::failed(code)
    }
}

pub struct LifecycleScenario {
    clock: ManualClock,
    transport: Option<Box<ScriptedTransport>>,
    transport_control: ScriptedTransportControl,
    cancellation: CancellationToken,
    tasks: JoinSet<String>,
    active_tasks: BTreeSet<String>,
    events: Arc<Mutex<Vec<ScenarioEvent>>>,
}

impl LifecycleScenario {
    pub fn new() -> Self {
        let (transport, transport_control) = ScriptedTransport::new();
        Self {
            clock: ManualClock::new(),
            transport: Some(transport),
            transport_control,
            cancellation: CancellationToken::new(),
            tasks: JoinSet::new(),
            active_tasks: BTreeSet::new(),
            events: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn clock(&self) -> ManualClock {
        self.clock.clone()
    }

    pub fn transport_control(&self) -> ScriptedTransportControl {
        self.transport_control.clone()
    }

    pub fn take_transport(&mut self) -> Result<Box<ScriptedTransport>, ScenarioError> {
        self.transport.take().ok_or(ScenarioError::TransportTaken)
    }

    pub fn spawn<F, Fut>(&mut self, name: impl Into<String>, task: F) -> Result<(), ScenarioError>
    where
        F: FnOnce(CancellationToken) -> Fut + Send + 'static,
        Fut: Future<Output = Result<(), ScenarioTaskError>> + Send + 'static,
    {
        let name = name.into();
        if name.is_empty() {
            return Err(ScenarioError::EmptyTaskName);
        }
        if !is_stable_identifier(&name) {
            return Err(ScenarioError::InvalidTaskName);
        }
        if !self.active_tasks.insert(name.clone()) {
            return Err(ScenarioError::DuplicateTaskName(name));
        }
        push_event(
            &self.events,
            ScenarioEvent::TaskStarted { name: name.clone() },
        );
        let cancellation = self.cancellation.child_token();
        let events = Arc::clone(&self.events);
        self.tasks.spawn(async move {
            let outcome = AssertUnwindSafe(task(cancellation)).catch_unwind().await;
            let event = match outcome {
                Ok(Ok(())) => ScenarioEvent::TaskSucceeded { name: name.clone() },
                Ok(Err(error)) if error.kind == ScenarioTaskErrorKind::Cancelled => {
                    ScenarioEvent::TaskCancelled { name: name.clone() }
                }
                Ok(Err(error)) => ScenarioEvent::TaskFailed {
                    name: name.clone(),
                    code: error.code,
                },
                Err(_) => ScenarioEvent::TaskPanicked { name: name.clone() },
            };
            push_event(&events, event);
            name
        });
        Ok(())
    }

    pub async fn shutdown(&mut self, deadline: MonotonicTime) -> ScenarioReport {
        push_event(&self.events, ScenarioEvent::ShutdownStarted);
        self.cancellation.cancel();
        let deadline_sleep = self.clock.sleep_until(deadline);
        tokio::pin!(deadline_sleep);
        let mut timed_out = false;

        while !self.tasks.is_empty() {
            tokio::select! {
                biased;
                completion = self.tasks.join_next() => {
                    if let Some(Ok(name)) = completion {
                        self.active_tasks.remove(&name);
                    }
                }
                _ = &mut deadline_sleep => {
                    timed_out = true;
                    break;
                }
            }
        }

        if timed_out {
            while let Some(completion) = self.tasks.try_join_next() {
                if let Ok(name) = completion {
                    self.active_tasks.remove(&name);
                }
            }
            for name in &self.active_tasks {
                push_event(
                    &self.events,
                    ScenarioEvent::TaskCancelled { name: name.clone() },
                );
            }
            self.tasks.abort_all();
            while self.tasks.join_next().await.is_some() {}
            self.active_tasks.clear();
        }

        push_event(&self.events, ScenarioEvent::ShutdownCompleted { timed_out });
        ScenarioReport {
            events: snapshot_events(&self.events),
            timed_out,
            remaining_tasks: self.active_tasks.len(),
        }
    }
}

impl Default for LifecycleScenario {
    fn default() -> Self {
        Self::new()
    }
}

fn push_event(events: &Arc<Mutex<Vec<ScenarioEvent>>>, event: ScenarioEvent) {
    if let Ok(mut events) = events.lock() {
        events.push(event);
    }
}

fn snapshot_events(events: &Arc<Mutex<Vec<ScenarioEvent>>>) -> Vec<ScenarioEvent> {
    events
        .lock()
        .map(|events| events.clone())
        .unwrap_or_default()
}

fn is_stable_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}
