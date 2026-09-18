//! Async coordinator that applies the pure recovery reducer.

use super::GenerationId;
use super::engine::{GenerationExit, GenerationExitCause, RuntimeError, RuntimeHandle};
use super::object_state::{
    ObjectEffect, ObjectToken, RecoveryQueue, RecoveryQueueError, RecoveryWaitId,
    RecoveryWaitOutcome,
};
use super::recovery::{
    RecoveryCoordinator, RecoveryEffect, RecoveryEvent, RecoveryPolicy, RecoveryState,
};
use crate::clock::{Clock, MonotonicTime};
use futures_core::future::BoxFuture;
use rand::Rng;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, oneshot};
use tokio_util::sync::CancellationToken;

pub(crate) trait GenerationBootstrap: Send + Sync + 'static {
    /// Establishes transport, negotiates Connection state, and starts exactly
    /// one fresh generation. Session recovery is intentionally a later stage.
    fn bootstrap(
        &self,
        generation: GenerationId,
        deadline: MonotonicTime,
    ) -> BoxFuture<'static, Result<PreparedGeneration, RuntimeError>>;
}

pub(crate) trait GenerationPublication: Send + 'static {
    fn publish(self: Box<Self>);
}

pub(crate) struct PreparedGeneration {
    runtime: RuntimeHandle,
    publication: Box<dyn GenerationPublication>,
}

impl PreparedGeneration {
    pub(crate) fn new(runtime: RuntimeHandle, publication: Box<dyn GenerationPublication>) -> Self {
        Self {
            runtime,
            publication,
        }
    }
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

#[derive(Debug)]
pub(crate) struct RandomRecoveryJitter {
    maximum: Duration,
}

impl RandomRecoveryJitter {
    pub(crate) const fn new(maximum: Duration) -> Self {
        Self { maximum }
    }
}

impl RecoveryJitter for RandomRecoveryJitter {
    fn next(&self, _failed_attempt: u32) -> Duration {
        let maximum = u64::try_from(self.maximum.as_nanos()).unwrap_or(u64::MAX);
        if maximum == 0 {
            Duration::ZERO
        } else {
            Duration::from_nanos(rand::thread_rng().gen_range(0..=maximum))
        }
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
    #[error("generation exit does not match the active generation")]
    StaleGeneration,
    #[error("generation identity space is exhausted")]
    GenerationExhausted,
    #[error("bootstrap published a mismatched generation")]
    MismatchedGeneration,
    #[error("connection recovery wait queue is full")]
    QueueFull,
    #[error("only the Connection dependency may wait in this recovery stage")]
    DependencyNotConnection,
    #[error("connection recovery wait reached its deadline")]
    WaitTimedOut,
    #[error("connection recovery wait was cancelled")]
    WaitCancelled,
    #[error("connection recovery failed while waiting")]
    WaitFailed,
}

struct RecoveryAdmissions {
    active_connection: ObjectToken,
    recovering: bool,
    queue: RecoveryQueue,
    completions: HashMap<RecoveryWaitId, oneshot::Sender<Result<ObjectToken, RecoveryError>>>,
}

pub(crate) struct RecoveryDriver {
    coordinator: Mutex<RecoveryCoordinator>,
    admissions: Mutex<RecoveryAdmissions>,
    /// Upper bound for a dependency wait whose caller passed no deadline: the policy's total
    /// recovery budget. A wait must never outlive the recovery it is waiting for.
    default_wait: Duration,
    clock: Arc<dyn Clock>,
    bootstrap: Arc<dyn GenerationBootstrap>,
    jitter: Arc<dyn RecoveryJitter>,
    closed: CancellationToken,
}

impl RecoveryDriver {
    pub(crate) fn new(
        connection: ObjectToken,
        policy: RecoveryPolicy,
        clock: Arc<dyn Clock>,
        bootstrap: Arc<dyn GenerationBootstrap>,
        jitter: Arc<dyn RecoveryJitter>,
    ) -> Self {
        Self {
            coordinator: Mutex::new(RecoveryCoordinator::new(connection.generation(), policy)),
            admissions: Mutex::new(RecoveryAdmissions {
                active_connection: connection,
                recovering: false,
                queue: RecoveryQueue::new(policy.max_waiting_operations),
                completions: HashMap::new(),
            }),
            default_wait: policy.total_timeout,
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
        if self.closed.is_cancelled() {
            return Err(RecoveryError::Closed);
        }
        let next_generation = exit
            .generation
            .checked_next()
            .ok_or(RecoveryError::GenerationExhausted)?;
        let effect = {
            let mut coordinator = self.coordinator.lock().await;
            if coordinator.state() != RecoveryState::Connected(exit.generation) {
                return Err(RecoveryError::StaleGeneration);
            }
            coordinator.reduce(RecoveryEvent::TransportLost {
                generation: exit.generation,
                now: self.clock.now(),
            })
        };
        self.begin_recovery(exit.generation).await?;
        tracing::warn!(
            generation = ?exit.generation,
            cause = ?exit.cause,
            "SMB connection lost its transport; recovery started"
        );

        // Every exit from the attempt loop other than a published replacement must release the
        // operations queued behind the recovery; otherwise `recovering` stays set with nobody
        // driving it, and every later Connection-dependency wait hangs.
        let outcome = self.drive_attempts(next_generation, effect).await;
        match &outcome {
            Ok(runtime) => tracing::info!(
                generation = ?runtime.connection_object().generation(),
                "SMB connection recovered"
            ),
            Err(error) => {
                tracing::warn!(
                    ?error,
                    "SMB connection recovery ended without a replacement"
                );
                self.fail_waiters().await;
            }
        }
        outcome
    }

    async fn drive_attempts(
        &self,
        next_generation: GenerationId,
        mut effect: Option<RecoveryEffect>,
    ) -> Result<RuntimeHandle, RecoveryError> {
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
                        Ok(candidate)
                            if candidate.runtime.connection_object().generation()
                                == next_generation =>
                        {
                            let published = self
                                .reduce(RecoveryEvent::AttemptSucceeded {
                                    generation: next_generation,
                                })
                                .await;
                            if published == Some(RecoveryEffect::PublishGeneration(next_generation))
                            {
                                candidate.publication.publish();
                                self.finish_recovery(candidate.runtime.connection_object())
                                    .await;
                                return Ok(candidate.runtime);
                            }
                            return Err(RecoveryError::Closed);
                        }
                        Ok(candidate) => {
                            let _ = candidate.runtime.close(self.clock.now()).await;
                            return Err(RecoveryError::MismatchedGeneration);
                        }
                        // The bootstrap found its connection gone (issue #77). No later
                        // attempt can succeed, so end recovery now instead of burning the
                        // backoff budget and reporting `AttemptsExhausted` for a server that
                        // was never asked.
                        Err(RuntimeError::Closed) => return Err(RecoveryError::Closed),
                        Err(error) => {
                            tracing::debug!(
                                ?error,
                                attempt,
                                "SMB connection recovery attempt failed"
                            );
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
                Some(RecoveryEffect::Closed) | None => {
                    return Err(RecoveryError::Closed);
                }
                Some(RecoveryEffect::PublishGeneration(_)) => {
                    return Err(RecoveryError::Closed);
                }
            };
        }
    }

    pub(crate) async fn close(&self) {
        self.closed.cancel();
        let _ = self.reduce(RecoveryEvent::Close).await;
        self.fail_waiters().await;
    }

    /// Synchronous half of [`close`](Self::close), for a `Drop` that cannot await: trips the
    /// close token so a running or future `recover` returns `Closed` and releases its waiters
    /// on the way out.
    pub(crate) fn abandon(&self) {
        self.closed.cancel();
    }

    pub(crate) async fn state(&self) -> RecoveryState {
        self.coordinator.lock().await.state()
    }

    pub(crate) fn deadline_after(&self, duration: Duration) -> MonotonicTime {
        self.clock.now().saturating_add(duration)
    }

    async fn reduce(&self, event: RecoveryEvent) -> Option<RecoveryEffect> {
        self.coordinator.lock().await.reduce(event)
    }

    pub(crate) async fn resolve_dependency(
        &self,
        dependency: ObjectToken,
        deadline: Option<MonotonicTime>,
        cancellation: Option<CancellationToken>,
    ) -> Result<ObjectToken, RecoveryError> {
        let (id, completion, deadline) =
            {
                let mut admissions = self.admissions.lock().await;
                if !admissions.recovering {
                    return Ok(dependency);
                }
                if dependency != admissions.active_connection {
                    return Err(RecoveryError::DependencyNotConnection);
                }
                let deadline = Some(
                    deadline.unwrap_or_else(|| self.clock.now().saturating_add(self.default_wait)),
                );
                let id = admissions.queue.enqueue(dependency, deadline).map_err(
                    |error| match error {
                        RecoveryQueueError::Full => RecoveryError::QueueFull,
                        RecoveryQueueError::IdExhausted => RecoveryError::WaitFailed,
                    },
                )?;
                let (reply, completion) = oneshot::channel();
                admissions.completions.insert(id, reply);
                (id, completion, deadline)
            };

        let deadline_wait = async {
            match deadline {
                Some(deadline) => self.clock.sleep_until(deadline).await,
                None => futures_util::future::pending().await,
            }
        };
        let cancel_wait = async {
            match cancellation {
                Some(cancellation) => cancellation.cancelled().await,
                None => futures_util::future::pending().await,
            }
        };
        tokio::pin!(deadline_wait);
        tokio::pin!(cancel_wait);
        tokio::select! {
            result = completion => result.unwrap_or(Err(RecoveryError::WaitFailed)),
            _ = &mut deadline_wait => {
                self.remove_wait(id).await;
                Err(RecoveryError::WaitTimedOut)
            }
            _ = &mut cancel_wait => {
                self.remove_wait(id).await;
                Err(RecoveryError::WaitCancelled)
            }
        }
    }

    async fn begin_recovery(&self, generation: GenerationId) -> Result<(), RecoveryError> {
        let mut admissions = self.admissions.lock().await;
        if admissions.active_connection.generation() != generation || admissions.recovering {
            return Err(RecoveryError::StaleGeneration);
        }
        admissions.recovering = true;
        Ok(())
    }

    async fn finish_recovery(&self, replacement: ObjectToken) {
        let mut admissions = self.admissions.lock().await;
        let previous = admissions.active_connection;
        admissions
            .queue
            .publish_replacement(ObjectEffect::ReplacementPublished {
                previous,
                replacement,
            });
        admissions.active_connection = replacement;
        admissions.recovering = false;
        let outcomes = admissions.queue.release_dependency(replacement);
        Self::complete_waits(&mut admissions, outcomes, Some(replacement));
    }

    async fn fail_waiters(&self) {
        let mut admissions = self.admissions.lock().await;
        admissions.recovering = false;
        let outcomes = admissions.queue.fail_all();
        Self::complete_waits(&mut admissions, outcomes, None);
    }

    async fn remove_wait(&self, id: RecoveryWaitId) {
        let mut admissions = self.admissions.lock().await;
        let _ = admissions.queue.cancel(id);
        admissions.completions.remove(&id);
    }

    fn complete_waits(
        admissions: &mut RecoveryAdmissions,
        outcomes: Vec<RecoveryWaitOutcome>,
        replacement: Option<ObjectToken>,
    ) {
        for outcome in outcomes {
            let id = match outcome {
                RecoveryWaitOutcome::Ready(id)
                | RecoveryWaitOutcome::Cancelled(id)
                | RecoveryWaitOutcome::TimedOut(id)
                | RecoveryWaitOutcome::AncestorFailed(id) => id,
            };
            if let Some(completion) = admissions.completions.remove(&id) {
                let result = match (outcome, replacement) {
                    (RecoveryWaitOutcome::Ready(_), Some(replacement)) => Ok(replacement),
                    _ => Err(RecoveryError::WaitFailed),
                };
                let _ = completion.send(result);
            }
        }
    }
}

#[cfg(all(test, feature = "test-support"))]
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

    struct PendingBootstrap;

    impl GenerationBootstrap for PendingBootstrap {
        fn bootstrap(
            &self,
            _generation: GenerationId,
            _deadline: MonotonicTime,
        ) -> BoxFuture<'static, Result<PreparedGeneration, RuntimeError>> {
            futures_util::future::pending().boxed()
        }
    }

    struct GatedBootstrap {
        release: Arc<tokio::sync::Notify>,
        clock: Arc<ManualClock>,
    }

    impl GenerationBootstrap for GatedBootstrap {
        fn bootstrap(
            &self,
            generation: GenerationId,
            _deadline: MonotonicTime,
        ) -> BoxFuture<'static, Result<PreparedGeneration, RuntimeError>> {
            let release = self.release.clone();
            let clock = self.clock.clone();
            async move {
                release.notified().await;
                let (transport, _) = ScriptedTransport::new();
                let (runtime, _) = start_generation(transport, clock, config(generation));
                Ok(PreparedGeneration::new(runtime, Box::new(NoopPublication)))
            }
            .boxed()
        }
    }

    struct NoopPublication;

    impl GenerationPublication for NoopPublication {
        fn publish(self: Box<Self>) {}
    }

    impl GenerationBootstrap for ScriptedBootstrap {
        fn bootstrap(
            &self,
            generation: GenerationId,
            _deadline: MonotonicTime,
        ) -> BoxFuture<'static, Result<PreparedGeneration, RuntimeError>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let succeeds = self.outcomes.lock().unwrap().pop_front().unwrap_or(false);
            let clock = self.clock.clone();
            async move {
                if !succeeds {
                    return Err(RuntimeError::Transport("scripted-bootstrap"));
                }
                let (transport, _) = ScriptedTransport::new();
                let (runtime, _) = start_generation(transport, clock, config(generation));
                Ok(PreparedGeneration::new(runtime, Box::new(NoopPublication)))
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
            max_waiting_operations: 8,
        }
    }

    async fn transport_exit(clock: Arc<ManualClock>) -> (GenerationExit, ObjectToken) {
        let (transport, control) = ScriptedTransport::new();
        control.fail_read_on(1, std::io::ErrorKind::ConnectionReset);
        let (runtime, _) = start_generation(transport, clock, config(GenerationId::new(1)));
        let connection = runtime.connection_object();
        (runtime.exited().await, connection)
    }

    #[tokio::test]
    async fn starts_new_generation_only_after_old_owner_joined() {
        let clock = Arc::new(ManualClock::new());
        let (exit, connection) = transport_exit(clock.clone()).await;
        assert_eq!(exit.report.joined_tasks + exit.report.failed_tasks, 2);
        let bootstrap = Arc::new(ScriptedBootstrap {
            outcomes: std::sync::Mutex::new(VecDeque::from([true])),
            calls: AtomicUsize::new(0),
            clock: clock.clone(),
        });
        let driver = RecoveryDriver::new(
            connection,
            policy(),
            clock.clone(),
            bootstrap.clone(),
            Arc::new(NoRecoveryJitter),
        );

        let recovered = driver.recover(exit).await.unwrap();
        assert_eq!(
            recovered.connection_object().generation(),
            GenerationId::new(2)
        );
        assert_eq!(bootstrap.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            driver.state().await,
            RecoveryState::Connected(GenerationId::new(2))
        );
        recovered.close(clock.now()).await.unwrap();
    }

    #[tokio::test]
    async fn retries_with_manual_clock_and_close_cancels_wait() {
        let clock = Arc::new(ManualClock::new());
        let (exit, connection) = transport_exit(clock.clone()).await;
        let bootstrap = Arc::new(ScriptedBootstrap {
            outcomes: std::sync::Mutex::new(VecDeque::from([false, true])),
            calls: AtomicUsize::new(0),
            clock: clock.clone(),
        });
        let driver = Arc::new(RecoveryDriver::new(
            connection,
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

        let (exit, connection) = transport_exit(clock.clone()).await;
        let closing_driver = Arc::new(RecoveryDriver::new(
            connection,
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
        assert!(matches!(waiting.await.unwrap(), Err(RecoveryError::Closed)));
    }

    #[tokio::test]
    async fn explicit_close_wins_transport_exit_recovery_race() {
        let clock = Arc::new(ManualClock::new());
        let (exit, connection) = transport_exit(clock.clone()).await;
        let bootstrap = Arc::new(ScriptedBootstrap {
            outcomes: std::sync::Mutex::new(VecDeque::from([true])),
            calls: AtomicUsize::new(0),
            clock: clock.clone(),
        });
        let driver = RecoveryDriver::new(
            connection,
            policy(),
            clock,
            bootstrap,
            Arc::new(NoRecoveryJitter),
        );

        driver.close().await;

        assert!(matches!(
            driver.recover(exit).await,
            Err(RecoveryError::Closed)
        ));
    }

    #[tokio::test]
    async fn attempt_deadline_stops_pending_bootstrap_and_stale_exit_is_rejected() {
        let clock = Arc::new(ManualClock::new());
        let (exit, connection) = transport_exit(clock.clone()).await;
        let driver = Arc::new(RecoveryDriver::new(
            connection,
            RecoveryPolicy {
                max_attempts: 1,
                ..policy()
            },
            clock.clone(),
            Arc::new(PendingBootstrap),
            Arc::new(NoRecoveryJitter),
        ));
        let recovery = tokio::spawn({
            let driver = driver.clone();
            let exit = exit.clone();
            async move { driver.recover(exit).await }
        });
        tokio::task::yield_now().await;
        clock.advance(Duration::from_secs(2)).await.unwrap();
        assert!(matches!(
            recovery.await.unwrap(),
            Err(RecoveryError::AttemptsExhausted)
        ));
        assert_eq!(
            driver.recover(exit).await.err(),
            Some(RecoveryError::StaleGeneration)
        );
    }

    #[tokio::test]
    async fn connection_waits_are_bounded_fifo_and_receive_replacement_token() {
        let clock = Arc::new(ManualClock::new());
        let (exit, connection) = transport_exit(clock.clone()).await;
        let release = Arc::new(tokio::sync::Notify::new());
        let driver = Arc::new(RecoveryDriver::new(
            connection,
            RecoveryPolicy {
                max_waiting_operations: 2,
                ..policy()
            },
            clock.clone(),
            Arc::new(GatedBootstrap {
                release: release.clone(),
                clock: clock.clone(),
            }),
            Arc::new(NoRecoveryJitter),
        ));
        let recovery = tokio::spawn({
            let driver = driver.clone();
            async move { driver.recover(exit).await }
        });
        tokio::task::yield_now().await;

        let first = tokio::spawn({
            let driver = driver.clone();
            async move { driver.resolve_dependency(connection, None, None).await }
        });
        let second = tokio::spawn({
            let driver = driver.clone();
            async move { driver.resolve_dependency(connection, None, None).await }
        });
        tokio::task::yield_now().await;
        assert!(!first.is_finished());
        assert!(!second.is_finished());
        assert_eq!(
            driver.resolve_dependency(connection, None, None).await,
            Err(RecoveryError::QueueFull)
        );

        release.notify_one();
        let recovered = recovery.await.unwrap().unwrap();
        let replacement = recovered.connection_object();
        assert_eq!(first.await.unwrap().unwrap(), replacement);
        assert_eq!(second.await.unwrap().unwrap(), replacement);
        recovered.close(clock.now()).await.unwrap();
    }

    /// Publishes a runtime for the wrong generation, once released, so a waiter can be
    /// queued before the mismatch is discovered.
    struct MismatchedBootstrap {
        release: Arc<tokio::sync::Notify>,
        clock: Arc<ManualClock>,
    }

    impl GenerationBootstrap for MismatchedBootstrap {
        fn bootstrap(
            &self,
            _generation: GenerationId,
            _deadline: MonotonicTime,
        ) -> BoxFuture<'static, Result<PreparedGeneration, RuntimeError>> {
            let release = self.release.clone();
            let clock = self.clock.clone();
            async move {
                release.notified().await;
                let (transport, _) = ScriptedTransport::new();
                let (runtime, _) = start_generation(transport, clock, config(GenerationId::new(9)));
                Ok(PreparedGeneration::new(runtime, Box::new(NoopPublication)))
            }
            .boxed()
        }
    }

    #[tokio::test]
    async fn connection_wait_without_deadline_is_bounded_by_the_recovery_budget() {
        let clock = Arc::new(ManualClock::new());
        let (exit, connection) = transport_exit(clock.clone()).await;
        let driver = Arc::new(RecoveryDriver::new(
            connection,
            policy(),
            clock.clone(),
            Arc::new(PendingBootstrap),
            Arc::new(NoRecoveryJitter),
        ));
        let recovery = tokio::spawn({
            let driver = driver.clone();
            async move { driver.recover(exit).await }
        });
        tokio::task::yield_now().await;
        let attempt_sleepers = clock.pending_sleepers();

        let waiter = tokio::spawn({
            let driver = driver.clone();
            async move { driver.resolve_dependency(connection, None, None).await }
        });
        tokio::task::yield_now().await;
        // The wait registered its own deadline sleeper even though the caller passed none.
        assert_eq!(clock.pending_sleepers(), attempt_sleepers + 1);

        driver.close().await;
        assert_eq!(waiter.await.unwrap(), Err(RecoveryError::WaitFailed));
        assert!(matches!(
            recovery.await.unwrap(),
            Err(RecoveryError::Closed)
        ));
    }

    #[tokio::test]
    async fn mismatched_replacement_generation_releases_waiters() {
        let clock = Arc::new(ManualClock::new());
        let (exit, connection) = transport_exit(clock.clone()).await;
        let release = Arc::new(tokio::sync::Notify::new());
        let driver = Arc::new(RecoveryDriver::new(
            connection,
            policy(),
            clock.clone(),
            Arc::new(MismatchedBootstrap {
                release: release.clone(),
                clock: clock.clone(),
            }),
            Arc::new(NoRecoveryJitter),
        ));
        let recovery = tokio::spawn({
            let driver = driver.clone();
            async move { driver.recover(exit).await }
        });
        tokio::task::yield_now().await;
        let waiter = tokio::spawn({
            let driver = driver.clone();
            async move { driver.resolve_dependency(connection, None, None).await }
        });
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());

        release.notify_one();
        assert!(matches!(
            recovery.await.unwrap(),
            Err(RecoveryError::MismatchedGeneration)
        ));
        assert_eq!(waiter.await.unwrap(), Err(RecoveryError::WaitFailed));
        // Nobody is recovering any more, so a fresh wait must not queue behind a ghost.
        assert_eq!(
            driver.resolve_dependency(connection, None, None).await,
            Ok(connection)
        );
    }

    struct ClosedBootstrap {
        calls: AtomicUsize,
    }

    impl GenerationBootstrap for ClosedBootstrap {
        fn bootstrap(
            &self,
            _generation: GenerationId,
            _deadline: MonotonicTime,
        ) -> BoxFuture<'static, Result<PreparedGeneration, RuntimeError>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            async { Err(RuntimeError::Closed) }.boxed()
        }
    }

    #[tokio::test]
    async fn bootstrap_reporting_a_dropped_connection_ends_recovery_at_once() {
        let clock = Arc::new(ManualClock::new());
        let (exit, connection) = transport_exit(clock.clone()).await;
        let bootstrap = Arc::new(ClosedBootstrap {
            calls: AtomicUsize::new(0),
        });
        let driver = Arc::new(RecoveryDriver::new(
            connection,
            policy(),
            clock.clone(),
            bootstrap.clone(),
            Arc::new(NoRecoveryJitter),
        ));
        let waiter = tokio::spawn({
            let driver = driver.clone();
            async move {
                // Queue behind the recovery before it starts; `recovering` flips inside
                // `recover`, so poll until the wait is actually parked.
                driver.resolve_dependency(connection, None, None).await
            }
        });
        tokio::task::yield_now().await;

        assert!(matches!(
            driver.recover(exit).await,
            Err(RecoveryError::Closed)
        ));
        assert_eq!(bootstrap.calls.load(Ordering::SeqCst), 1);
        // No backoff was scheduled: the loop ended on the first `Closed`.
        assert_eq!(clock.pending_sleepers(), 0);
        let waited = waiter.await.unwrap();
        assert!(
            matches!(waited, Ok(_) | Err(RecoveryError::WaitFailed)),
            "waiter must be released, got {waited:?}"
        );
        assert_eq!(
            driver.resolve_dependency(connection, None, None).await,
            Ok(connection)
        );
    }

    #[tokio::test]
    async fn abandon_from_a_drop_ends_a_parked_recovery_and_releases_waiters() {
        let clock = Arc::new(ManualClock::new());
        let (exit, connection) = transport_exit(clock.clone()).await;
        let driver = Arc::new(RecoveryDriver::new(
            connection,
            policy(),
            clock.clone(),
            Arc::new(PendingBootstrap),
            Arc::new(NoRecoveryJitter),
        ));
        let recovery = tokio::spawn({
            let driver = driver.clone();
            async move { driver.recover(exit).await }
        });
        tokio::task::yield_now().await;
        let waiter = tokio::spawn({
            let driver = driver.clone();
            async move { driver.resolve_dependency(connection, None, None).await }
        });
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());

        driver.abandon();
        assert!(matches!(
            recovery.await.unwrap(),
            Err(RecoveryError::Closed)
        ));
        assert_eq!(waiter.await.unwrap(), Err(RecoveryError::WaitFailed));
    }

    #[tokio::test]
    async fn connection_wait_deadline_and_cancel_remove_exact_entries() {
        let clock = Arc::new(ManualClock::new());
        let (exit, connection) = transport_exit(clock.clone()).await;
        let driver = Arc::new(RecoveryDriver::new(
            connection,
            policy(),
            clock.clone(),
            Arc::new(PendingBootstrap),
            Arc::new(NoRecoveryJitter),
        ));
        let recovery = tokio::spawn({
            let driver = driver.clone();
            async move { driver.recover(exit).await }
        });
        tokio::task::yield_now().await;

        let cancellation = CancellationToken::new();
        let cancelled = tokio::spawn({
            let driver = driver.clone();
            let cancellation = cancellation.clone();
            async move {
                driver
                    .resolve_dependency(connection, None, Some(cancellation))
                    .await
            }
        });
        let timed = tokio::spawn({
            let driver = driver.clone();
            let deadline = clock.now().saturating_add(Duration::from_secs(1));
            async move {
                driver
                    .resolve_dependency(connection, Some(deadline), None)
                    .await
            }
        });
        tokio::task::yield_now().await;
        cancellation.cancel();
        assert_eq!(cancelled.await.unwrap(), Err(RecoveryError::WaitCancelled));
        clock.advance(Duration::from_secs(1)).await.unwrap();
        assert_eq!(timed.await.unwrap(), Err(RecoveryError::WaitTimedOut));
        driver.close().await;
        assert!(matches!(
            recovery.await.unwrap(),
            Err(RecoveryError::Closed)
        ));
    }
}
