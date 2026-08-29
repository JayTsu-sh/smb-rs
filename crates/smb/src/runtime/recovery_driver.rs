//! Async coordinator that applies the pure recovery reducer.

use super::engine::{GenerationExit, GenerationExitCause, RuntimeError, RuntimeHandle};
use super::recovery::{
    RecoveryCoordinator, RecoveryEffect, RecoveryEvent, RecoveryPolicy, RecoveryState,
};
use super::GenerationId;
use crate::clock::{Clock, MonotonicTime};
use futures_core::future::BoxFuture;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

pub(crate) trait GenerationBootstrap: Send + Sync + 'static {
    /// Establishes transport, negotiates Connection state, and starts exactly
    /// one fresh generation. Session recovery is intentionally a later stage.
    fn bootstrap(
        &self,
        generation: GenerationId,
        deadline: MonotonicTime,
    ) -> BoxFuture<'static, Result<RuntimeHandle, RuntimeError>>;
}

pub(crate) trait RecoveryJitter: Send + Sync + 'static {
    fn next(&self, failed_attempt: u32) -> Duration;
}

#[derive(Debug, Default)]
pub(crate) struct NoRecoveryJitter;

impl RecoveryJitter for NoRecoveryJitter {
    fn next(&self, _failed_attempt: u32) -> Duration {
        Duration::ZERO
    }
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum RecoveryError {
    #[error("generation exit is not recoverable")]
    NotRecoverable,
    #[error("connection recovery was explicitly closed")]
    Closed,
    #[error("connection recovery attempts were exhausted")]
    AttemptsExhausted,
    #[error("generation identity space is exhausted")]
    GenerationExhausted,
    #[error("bootstrap published a mismatched generation")]
    MismatchedGeneration,
}

pub(crate) struct RecoveryDriver {
    coordinator: Mutex<RecoveryCoordinator>,
    clock: Arc<dyn Clock>,
    bootstrap: Arc<dyn GenerationBootstrap>,
    jitter: Arc<dyn RecoveryJitter>,
    closed: CancellationToken,
}

impl RecoveryDriver {
    pub(crate) fn new(
        generation: GenerationId,
        policy: RecoveryPolicy,
        clock: Arc<dyn Clock>,
        bootstrap: Arc<dyn GenerationBootstrap>,
        jitter: Arc<dyn RecoveryJitter>,
    ) -> Self {
        Self {
            coordinator: Mutex::new(RecoveryCoordinator::new(generation, policy)),
            clock,
            bootstrap,
            jitter,
            closed: CancellationToken::new(),
        }
    }

    pub(crate) async fn recover(
        &self,
        exit: GenerationExit,
    ) -> Result<RuntimeHandle, RecoveryError> {
        if !matches!(exit.cause, GenerationExitCause::Transport(_)) {
            return Err(RecoveryError::NotRecoverable);
        }
        let next_generation = exit
            .generation
            .checked_next()
            .ok_or(RecoveryError::GenerationExhausted)?;
        let mut effect = self
            .reduce(RecoveryEvent::TransportLost {
                generation: exit.generation,
                now: self.clock.now(),
            })
            .await;

        loop {
            effect = match effect {
                Some(RecoveryEffect::ScheduleAttempt { at, .. }) => {
                    tokio::select! {
                        biased;
                        _ = self.closed.cancelled() => return Err(RecoveryError::Closed),
                        _ = self.clock.sleep_until(at) => {}
                    }
                    self.reduce(RecoveryEvent::Wake {
                        now: self.clock.now(),
                    })
                    .await
                }
                Some(RecoveryEffect::StartAttempt { attempt, deadline }) => {
                    let result = tokio::select! {
                        biased;
                        _ = self.closed.cancelled() => return Err(RecoveryError::Closed),
                        _ = self.clock.sleep_until(deadline) => Err(RuntimeError::Transport("recovery-attempt-timeout")),
                        result = self.bootstrap.bootstrap(next_generation, deadline) => result,
                    };
                    match result {
                        Ok(runtime)
                            if runtime.connection_object().generation() == next_generation =>
                        {
                            let published = self
                                .reduce(RecoveryEvent::AttemptSucceeded {
                                    generation: next_generation,
                                })
                                .await;
                            if published
                                == Some(RecoveryEffect::PublishGeneration(next_generation))
                            {
                                return Ok(runtime);
                            }
                            return Err(RecoveryError::Closed);
                        }
                        Ok(runtime) => {
                            let _ = runtime.close(self.clock.now()).await;
                            return Err(RecoveryError::MismatchedGeneration);
                        }
                        Err(_) => {
                            self.reduce(RecoveryEvent::AttemptFailed {
                                now: self.clock.now(),
                                jitter: self.jitter.next(attempt),
                            })
                            .await
                        }
                    }
                }
                Some(RecoveryEffect::RecoveryFailed) => {
                    return Err(RecoveryError::AttemptsExhausted);
                }
                Some(RecoveryEffect::Closed) | None => return Err(RecoveryError::Closed),
                Some(RecoveryEffect::PublishGeneration(_)) => {
                    return Err(RecoveryError::Closed);
                }
            };
        }
    }

    pub(crate) async fn close(&self) {
        self.closed.cancel();
        let _ = self.reduce(RecoveryEvent::Close).await;
    }

    pub(crate) async fn state(&self) -> RecoveryState {
        self.coordinator.lock().await.state()
    }

    async fn reduce(&self, event: RecoveryEvent) -> Option<RecoveryEffect> {
        self.coordinator.lock().await.reduce(event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::ManualClock;
    use crate::runtime::engine::{RuntimeConfig, start_generation};
    use crate::runtime::state::AdmissionLimits;
    use futures_util::FutureExt;
    use smb_transport::test_support::ScriptedTransport;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct ScriptedBootstrap {
        outcomes: std::sync::Mutex<VecDeque<bool>>,
        calls: AtomicUsize,
        clock: Arc<ManualClock>,
    }

    impl GenerationBootstrap for ScriptedBootstrap {
        fn bootstrap(
            &self,
            generation: GenerationId,
            _deadline: MonotonicTime,
        ) -> BoxFuture<'static, Result<RuntimeHandle, RuntimeError>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let succeeds = self.outcomes.lock().unwrap().pop_front().unwrap_or(false);
            let clock = self.clock.clone();
            async move {
                if !succeeds {
                    return Err(RuntimeError::Transport("scripted-bootstrap"));
                }
                let (transport, _) = ScriptedTransport::new();
                let (runtime, _) = start_generation(transport, clock, config(generation));
                Ok(runtime)
            }
            .boxed()
        }
    }

    fn config(generation: GenerationId) -> RuntimeConfig {
        RuntimeConfig {
            generation,
            initial_message_id: 0,
            initial_credits: 1,
            target_credits: 32,
            admission_limits: AdmissionLimits {
                max_operations: 8,
                max_payload_bytes: 1024,
            },
            tombstone_drain_timeout: Duration::from_secs(1),
            admission_capacity: 8,
            io_capacity: 8,
            control_capacity: 8,
            event_capacity: 8,
            control_batch: 2,
            maximum_frame_size: 1024,
            emit_events: false,
            decode_unsolicited: false,
        }
    }

    fn policy() -> RecoveryPolicy {
        RecoveryPolicy {
            max_attempts: 3,
            attempt_timeout: Duration::from_secs(2),
            total_timeout: Duration::from_secs(10),
            initial_backoff: Duration::from_secs(1),
            maximum_backoff: Duration::from_secs(4),
            maximum_jitter: Duration::ZERO,
        }
    }

    async fn transport_exit(clock: Arc<ManualClock>) -> GenerationExit {
        let (transport, control) = ScriptedTransport::new();
        control.fail_read_on(1, std::io::ErrorKind::ConnectionReset);
        let (runtime, _) = start_generation(transport, clock, config(GenerationId::new(1)));
        runtime.exited().await
    }

    #[tokio::test]
    async fn starts_new_generation_only_after_old_owner_joined() {
        let clock = Arc::new(ManualClock::new());
        let exit = transport_exit(clock.clone()).await;
        assert_eq!(exit.report.joined_tasks + exit.report.failed_tasks, 2);
        let bootstrap = Arc::new(ScriptedBootstrap {
            outcomes: std::sync::Mutex::new(VecDeque::from([true])),
            calls: AtomicUsize::new(0),
            clock: clock.clone(),
        });
        let driver = RecoveryDriver::new(
            GenerationId::new(1),
            policy(),
            clock.clone(),
            bootstrap.clone(),
            Arc::new(NoRecoveryJitter),
        );

        let recovered = driver.recover(exit).await.unwrap();
        assert_eq!(recovered.connection_object().generation(), GenerationId::new(2));
        assert_eq!(bootstrap.calls.load(Ordering::SeqCst), 1);
        assert_eq!(driver.state().await, RecoveryState::Connected(GenerationId::new(2)));
        recovered.close(clock.now()).await.unwrap();
    }

    #[tokio::test]
    async fn retries_with_manual_clock_and_close_cancels_wait() {
        let clock = Arc::new(ManualClock::new());
        let exit = transport_exit(clock.clone()).await;
        let bootstrap = Arc::new(ScriptedBootstrap {
            outcomes: std::sync::Mutex::new(VecDeque::from([false, true])),
            calls: AtomicUsize::new(0),
            clock: clock.clone(),
        });
        let driver = Arc::new(RecoveryDriver::new(
            GenerationId::new(1),
            policy(),
            clock.clone(),
            bootstrap.clone(),
            Arc::new(NoRecoveryJitter),
        ));
        let recovery = tokio::spawn({
            let driver = driver.clone();
            async move { driver.recover(exit).await }
        });
        tokio::task::yield_now().await;
        assert_eq!(bootstrap.calls.load(Ordering::SeqCst), 1);
        assert_eq!(clock.pending_sleepers(), 1);
        clock.advance(Duration::from_secs(1)).await.unwrap();
        let recovered = recovery.await.unwrap().unwrap();
        assert_eq!(bootstrap.calls.load(Ordering::SeqCst), 2);
        recovered.close(clock.now()).await.unwrap();

        let exit = transport_exit(clock.clone()).await;
        let closing_driver = Arc::new(RecoveryDriver::new(
            GenerationId::new(1),
            policy(),
            clock.clone(),
            Arc::new(ScriptedBootstrap {
                outcomes: std::sync::Mutex::new(VecDeque::from([false])),
                calls: AtomicUsize::new(0),
                clock: clock.clone(),
            }),
            Arc::new(NoRecoveryJitter),
        ));
        let waiting = tokio::spawn({
            let closing_driver = closing_driver.clone();
            async move { closing_driver.recover(exit).await }
        });
        tokio::task::yield_now().await;
        closing_driver.close().await;
        assert!(matches!(
            waiting.await.unwrap(),
            Err(RecoveryError::Closed)
        ));
    }
}
