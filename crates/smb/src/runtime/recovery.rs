//! Deterministic cross-generation connection recovery policy.
//!
//! This reducer owns retry timing and generation publication decisions. It
//! never owns a transport or generation runtime; the coordinator applies its
//! effects only after the previous generation has completely joined.

use super::GenerationId;
use crate::clock::MonotonicTime;
use std::time::Duration;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RecoveryPolicy {
    pub(crate) max_attempts: u32,
    pub(crate) attempt_timeout: Duration,
    pub(crate) total_timeout: Duration,
    pub(crate) initial_backoff: Duration,
    pub(crate) maximum_backoff: Duration,
    pub(crate) maximum_jitter: Duration,
    pub(crate) max_waiting_operations: usize,
}

impl RecoveryPolicy {
    pub(crate) const fn disabled() -> Self {
        Self {
            max_attempts: 0,
            attempt_timeout: Duration::ZERO,
            total_timeout: Duration::ZERO,
            initial_backoff: Duration::ZERO,
            maximum_backoff: Duration::ZERO,
            maximum_jitter: Duration::ZERO,
            max_waiting_operations: 0,
        }
    }

    fn backoff(self, failed_attempt: u32) -> Duration {
        if failed_attempt == 0 {
            return Duration::ZERO;
        }
        let shift = failed_attempt.saturating_sub(1).min(31);
        self.initial_backoff
            .saturating_mul(1_u32 << shift)
            .min(self.maximum_backoff)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RecoveryState {
    Connected(GenerationId),
    Waiting {
        attempt: u32,
        wake_at: MonotonicTime,
        total_deadline: MonotonicTime,
    },
    Connecting {
        attempt: u32,
        attempt_deadline: MonotonicTime,
        total_deadline: MonotonicTime,
    },
    Failed,
    Closed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RecoveryEvent {
    TransportLost {
        generation: GenerationId,
        now: MonotonicTime,
    },
    Wake { now: MonotonicTime },
    AttemptSucceeded { generation: GenerationId },
    AttemptFailed {
        now: MonotonicTime,
        jitter: Duration,
    },
    Close,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RecoveryEffect {
    ScheduleAttempt { attempt: u32, at: MonotonicTime },
    StartAttempt { attempt: u32, deadline: MonotonicTime },
    PublishGeneration(GenerationId),
    RecoveryFailed,
    Closed,
}

pub(crate) struct RecoveryCoordinator {
    policy: RecoveryPolicy,
    state: RecoveryState,
}

impl RecoveryCoordinator {
    pub(crate) const fn new(generation: GenerationId, policy: RecoveryPolicy) -> Self {
        Self {
            policy,
            state: RecoveryState::Connected(generation),
        }
    }

    pub(crate) const fn state(&self) -> RecoveryState {
        self.state
    }

    pub(crate) fn reduce(&mut self, event: RecoveryEvent) -> Option<RecoveryEffect> {
        match (self.state, event) {
            (RecoveryState::Closed, _) | (RecoveryState::Failed, _) => None,
            (_, RecoveryEvent::Close) => {
                self.state = RecoveryState::Closed;
                Some(RecoveryEffect::Closed)
            }
            (
                RecoveryState::Connected(active),
                RecoveryEvent::TransportLost { generation, now },
            ) if active == generation => {
                if self.policy.max_attempts == 0 {
                    self.state = RecoveryState::Failed;
                    return Some(RecoveryEffect::RecoveryFailed);
                }
                let total_deadline = now.saturating_add(self.policy.total_timeout);
                self.schedule(1, now, total_deadline)
            }
            (
                RecoveryState::Waiting {
                    attempt,
                    wake_at,
                    total_deadline,
                },
                RecoveryEvent::Wake { now },
            ) if now >= wake_at => {
                if now >= total_deadline {
                    self.fail()
                } else {
                    let deadline = now
                        .saturating_add(self.policy.attempt_timeout)
                        .min(total_deadline);
                    self.state = RecoveryState::Connecting {
                        attempt,
                        attempt_deadline: deadline,
                        total_deadline,
                    };
                    Some(RecoveryEffect::StartAttempt { attempt, deadline })
                }
            }
            (
                RecoveryState::Connecting { .. },
                RecoveryEvent::AttemptSucceeded { generation },
            ) => {
                self.state = RecoveryState::Connected(generation);
                Some(RecoveryEffect::PublishGeneration(generation))
            }
            (
                RecoveryState::Connecting {
                    attempt,
                    total_deadline,
                    ..
                },
                RecoveryEvent::AttemptFailed { now, jitter },
            ) => {
                if attempt >= self.policy.max_attempts || now >= total_deadline {
                    self.fail()
                } else {
                    self.schedule(
                        attempt + 1,
                        now.saturating_add(jitter.min(self.policy.maximum_jitter)),
                        total_deadline,
                    )
                }
            }
            _ => None,
        }
    }

    fn schedule(
        &mut self,
        attempt: u32,
        now: MonotonicTime,
        total_deadline: MonotonicTime,
    ) -> Option<RecoveryEffect> {
        let at = now
            .saturating_add(self.policy.backoff(attempt.saturating_sub(1)))
            .min(total_deadline);
        self.state = RecoveryState::Waiting {
            attempt,
            wake_at: at,
            total_deadline,
        };
        Some(RecoveryEffect::ScheduleAttempt { attempt, at })
    }

    fn fail(&mut self) -> Option<RecoveryEffect> {
        self.state = RecoveryState::Failed;
        Some(RecoveryEffect::RecoveryFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECOND: Duration = Duration::from_secs(1);

    fn policy() -> RecoveryPolicy {
        RecoveryPolicy {
            max_attempts: 3,
            attempt_timeout: SECOND,
            total_timeout: Duration::from_secs(10),
            initial_backoff: SECOND,
            maximum_backoff: Duration::from_secs(4),
            maximum_jitter: Duration::from_millis(250),
            max_waiting_operations: 8,
        }
    }

    fn at(seconds: u64) -> MonotonicTime {
        MonotonicTime::ZERO.saturating_add(Duration::from_secs(seconds))
    }

    #[test]
    fn retries_are_bounded_and_publish_one_new_generation() {
        let mut recovery = RecoveryCoordinator::new(GenerationId::new(1), policy());
        assert_eq!(
            recovery.reduce(RecoveryEvent::TransportLost {
                generation: GenerationId::new(1),
                now: at(0),
            }),
            Some(RecoveryEffect::ScheduleAttempt { attempt: 1, at: at(0) })
        );
        assert_eq!(
            recovery.reduce(RecoveryEvent::Wake { now: at(0) }),
            Some(RecoveryEffect::StartAttempt { attempt: 1, deadline: at(1) })
        );
        assert_eq!(
            recovery.reduce(RecoveryEvent::AttemptFailed {
                now: at(1),
                jitter: Duration::ZERO,
            }),
            Some(RecoveryEffect::ScheduleAttempt { attempt: 2, at: at(2) })
        );
        assert_eq!(
            recovery.reduce(RecoveryEvent::Wake { now: at(2) }),
            Some(RecoveryEffect::StartAttempt { attempt: 2, deadline: at(3) })
        );
        assert_eq!(
            recovery.reduce(RecoveryEvent::AttemptSucceeded {
                generation: GenerationId::new(2),
            }),
            Some(RecoveryEffect::PublishGeneration(GenerationId::new(2)))
        );
        assert!(recovery
            .reduce(RecoveryEvent::AttemptSucceeded {
                generation: GenerationId::new(3),
            })
            .is_none());
    }

    #[test]
    fn total_deadline_and_attempt_limit_are_terminal() {
        let mut deadline = RecoveryCoordinator::new(GenerationId::new(1), RecoveryPolicy {
            total_timeout: SECOND,
            ..policy()
        });
        deadline.reduce(RecoveryEvent::TransportLost {
            generation: GenerationId::new(1),
            now: at(0),
        });
        assert_eq!(
            deadline.reduce(RecoveryEvent::Wake { now: at(1) }),
            Some(RecoveryEffect::RecoveryFailed)
        );

        let mut attempts = RecoveryCoordinator::new(GenerationId::new(1), RecoveryPolicy {
            max_attempts: 1,
            ..policy()
        });
        attempts.reduce(RecoveryEvent::TransportLost {
            generation: GenerationId::new(1),
            now: at(0),
        });
        attempts.reduce(RecoveryEvent::Wake { now: at(0) });
        assert_eq!(
            attempts.reduce(RecoveryEvent::AttemptFailed {
                now: at(1),
                jitter: Duration::ZERO,
            }),
            Some(RecoveryEffect::RecoveryFailed)
        );
    }

    #[test]
    fn duplicate_fatal_and_close_never_start_another_recovery() {
        let mut recovery = RecoveryCoordinator::new(GenerationId::new(1), policy());
        recovery.reduce(RecoveryEvent::TransportLost {
            generation: GenerationId::new(1),
            now: at(0),
        });
        assert!(recovery
            .reduce(RecoveryEvent::TransportLost {
                generation: GenerationId::new(1),
                now: at(0),
            })
            .is_none());
        assert_eq!(recovery.reduce(RecoveryEvent::Close), Some(RecoveryEffect::Closed));
        assert!(recovery.reduce(RecoveryEvent::Wake { now: at(10) }).is_none());

        let mut disabled = RecoveryCoordinator::new(
            GenerationId::new(1),
            RecoveryPolicy::disabled(),
        );
        assert_eq!(
            disabled.reduce(RecoveryEvent::TransportLost {
                generation: GenerationId::new(1),
                now: at(0),
            }),
            Some(RecoveryEffect::RecoveryFailed)
        );
    }
}
