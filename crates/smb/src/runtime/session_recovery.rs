//! Deterministic Session reauthentication authority.
//!
//! The reducer owns only lifecycle decisions. Credential acquisition and
//! SessionSetup I/O are effects executed by one async coordinator.

use super::ObjectToken;
use crate::clock::MonotonicTime;
use std::collections::VecDeque;
use std::time::Duration;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct SessionWaitId(u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SessionWaitError {
    Full,
    DependencyNotSession,
    IdExhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SessionWaitOutcome {
    Ready {
        id: SessionWaitId,
        session: ObjectToken,
    },
    Cancelled(SessionWaitId),
    TimedOut(SessionWaitId),
    RecoveryFailed(SessionWaitId),
}

#[derive(Clone, Copy, Debug)]
struct SessionWait {
    id: SessionWaitId,
    dependency: ObjectToken,
    deadline: Option<MonotonicTime>,
}

pub(crate) struct SessionWaitQueue {
    session: ObjectToken,
    capacity: usize,
    next_id: Option<u64>,
    waits: VecDeque<SessionWait>,
}

impl SessionWaitQueue {
    pub(crate) fn new(session: ObjectToken, capacity: usize) -> Self {
        Self {
            session,
            capacity,
            next_id: Some(0),
            waits: VecDeque::with_capacity(capacity),
        }
    }

    pub(crate) fn enqueue(
        &mut self,
        dependency: ObjectToken,
        deadline: Option<MonotonicTime>,
    ) -> Result<SessionWaitId, SessionWaitError> {
        if dependency != self.session {
            return Err(SessionWaitError::DependencyNotSession);
        }
        if self.waits.len() >= self.capacity {
            return Err(SessionWaitError::Full);
        }
        let id = SessionWaitId(self.next_id.ok_or(SessionWaitError::IdExhausted)?);
        self.next_id = id.0.checked_add(1);
        self.waits.push_back(SessionWait {
            id,
            dependency,
            deadline,
        });
        Ok(id)
    }

    pub(crate) fn cancel(&mut self, id: SessionWaitId) -> Option<SessionWaitOutcome> {
        let index = self.waits.iter().position(|wait| wait.id == id)?;
        self.waits.remove(index)?;
        Some(SessionWaitOutcome::Cancelled(id))
    }

    pub(crate) fn advance_time(&mut self, now: MonotonicTime) -> Vec<SessionWaitOutcome> {
        let mut outcomes = Vec::new();
        self.waits.retain(|wait| {
            if wait.deadline.is_some_and(|deadline| deadline <= now) {
                outcomes.push(SessionWaitOutcome::TimedOut(wait.id));
                false
            } else {
                true
            }
        });
        outcomes
    }

    pub(crate) fn publish(&mut self, replacement: ObjectToken) -> Vec<SessionWaitOutcome> {
        let previous = self.session;
        self.session = replacement;
        self.waits
            .drain(..)
            .filter(|wait| wait.dependency == previous)
            .map(|wait| SessionWaitOutcome::Ready {
                id: wait.id,
                session: replacement,
            })
            .collect()
    }

    pub(crate) fn fail(&mut self) -> Vec<SessionWaitOutcome> {
        self.waits
            .drain(..)
            .map(|wait| SessionWaitOutcome::RecoveryFailed(wait.id))
            .collect()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SessionRecoveryPolicy {
    pub(crate) max_attempts: u32,
    pub(crate) attempt_timeout: Duration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SessionRecoveryState {
    Active(ObjectToken),
    Authenticating {
        previous: ObjectToken,
        connection: ObjectToken,
        attempt: u32,
        deadline: MonotonicTime,
    },
    Revoked(ObjectToken),
    Closed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SessionRecoveryEvent {
    SessionLost {
        session: ObjectToken,
        connection: ObjectToken,
        now: MonotonicTime,
    },
    ConnectionReplaced {
        connection: ObjectToken,
        now: MonotonicTime,
    },
    AttemptFailed {
        connection: ObjectToken,
        now: MonotonicTime,
    },
    AttemptSucceeded {
        connection: ObjectToken,
        session: ObjectToken,
    },
    Close,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SessionRecoveryEffect {
    StartAuthentication {
        connection: ObjectToken,
        attempt: u32,
        deadline: MonotonicTime,
    },
    PublishSession {
        previous: ObjectToken,
        replacement: ObjectToken,
    },
    RevokeSession(ObjectToken),
    Closed,
}

pub(crate) struct SessionRecoveryCoordinator {
    policy: SessionRecoveryPolicy,
    state: SessionRecoveryState,
}

impl SessionRecoveryCoordinator {
    pub(crate) const fn new(session: ObjectToken, policy: SessionRecoveryPolicy) -> Self {
        Self {
            policy,
            state: SessionRecoveryState::Active(session),
        }
    }

    pub(crate) const fn state(&self) -> SessionRecoveryState {
        self.state
    }

    pub(crate) fn reduce(
        &mut self,
        event: SessionRecoveryEvent,
    ) -> Option<SessionRecoveryEffect> {
        match (self.state, event) {
            (SessionRecoveryState::Closed | SessionRecoveryState::Revoked(_), _) => None,
            (_, SessionRecoveryEvent::Close) => {
                self.state = SessionRecoveryState::Closed;
                Some(SessionRecoveryEffect::Closed)
            }
            (
                SessionRecoveryState::Active(previous),
                SessionRecoveryEvent::SessionLost {
                    session,
                    connection,
                    now,
                },
            ) if session == previous => self.start(previous, connection, 1, now),
            (
                SessionRecoveryState::Active(previous),
                SessionRecoveryEvent::ConnectionReplaced { connection, now },
            ) if connection.generation() != previous.generation() => {
                self.start(previous, connection, 1, now)
            }
            (
                SessionRecoveryState::Authenticating {
                    previous,
                    connection: current,
                    ..
                },
                SessionRecoveryEvent::ConnectionReplaced { connection, now },
            ) if connection.generation() != current.generation() => {
                self.start(previous, connection, 1, now)
            }
            (
                SessionRecoveryState::Authenticating {
                    previous,
                    connection: current,
                    attempt,
                    ..
                },
                SessionRecoveryEvent::AttemptFailed { connection, now },
            ) if connection == current => {
                if attempt >= self.policy.max_attempts {
                    self.state = SessionRecoveryState::Revoked(previous);
                    Some(SessionRecoveryEffect::RevokeSession(previous))
                } else {
                    self.start(previous, connection, attempt + 1, now)
                }
            }
            (
                SessionRecoveryState::Authenticating {
                    previous,
                    connection: current,
                    ..
                },
                SessionRecoveryEvent::AttemptSucceeded {
                    connection,
                    session,
                },
            ) if connection == current && session.generation() == connection.generation() => {
                self.state = SessionRecoveryState::Active(session);
                Some(SessionRecoveryEffect::PublishSession {
                    previous,
                    replacement: session,
                })
            }
            _ => None,
        }
    }

    fn start(
        &mut self,
        previous: ObjectToken,
        connection: ObjectToken,
        attempt: u32,
        now: MonotonicTime,
    ) -> Option<SessionRecoveryEffect> {
        if self.policy.max_attempts == 0 {
            self.state = SessionRecoveryState::Revoked(previous);
            return Some(SessionRecoveryEffect::RevokeSession(previous));
        }
        let deadline = now.saturating_add(self.policy.attempt_timeout);
        self.state = SessionRecoveryState::Authenticating {
            previous,
            connection,
            attempt,
            deadline,
        };
        Some(SessionRecoveryEffect::StartAuthentication {
            connection,
            attempt,
            deadline,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::object_state::{ObjectKind, ObjectRegistry};
    use crate::runtime::GenerationId;

    fn objects(generation: u64) -> (ObjectToken, ObjectToken) {
        let mut objects = ObjectRegistry::new(GenerationId::new(generation));
        let connection = objects.connection();
        let session = objects
            .create_child(connection, ObjectKind::Session)
            .unwrap();
        (connection, session)
    }

    fn policy() -> SessionRecoveryPolicy {
        SessionRecoveryPolicy {
            max_attempts: 2,
            attempt_timeout: Duration::from_secs(3),
        }
    }

    #[test]
    fn publishes_only_a_session_from_the_target_connection_generation() {
        let (_, previous) = objects(1);
        let (connection, replacement) = objects(2);
        let mut recovery = SessionRecoveryCoordinator::new(previous, policy());

        assert!(matches!(
            recovery.reduce(SessionRecoveryEvent::ConnectionReplaced {
                connection,
                now: MonotonicTime::ZERO,
            }),
            Some(SessionRecoveryEffect::StartAuthentication { attempt: 1, .. })
        ));
        assert!(recovery
            .reduce(SessionRecoveryEvent::AttemptSucceeded {
                connection,
                session: previous,
            })
            .is_none());
        assert_eq!(
            recovery.reduce(SessionRecoveryEvent::AttemptSucceeded {
                connection,
                session: replacement,
            }),
            Some(SessionRecoveryEffect::PublishSession {
                previous,
                replacement,
            })
        );
        assert_eq!(recovery.state(), SessionRecoveryState::Active(replacement));
    }

    #[test]
    fn duplicate_and_stale_events_do_not_create_a_second_owner() {
        let (_, previous) = objects(1);
        let (connection, _) = objects(2);
        let (stale_connection, _) = objects(3);
        let mut recovery = SessionRecoveryCoordinator::new(previous, policy());
        recovery.reduce(SessionRecoveryEvent::ConnectionReplaced {
            connection,
            now: MonotonicTime::ZERO,
        });

        assert!(recovery
            .reduce(SessionRecoveryEvent::ConnectionReplaced {
                connection,
                now: MonotonicTime::ZERO,
            })
            .is_none());
        assert!(recovery
            .reduce(SessionRecoveryEvent::AttemptFailed {
                connection: stale_connection,
                now: MonotonicTime::ZERO,
            })
            .is_none());
    }

    #[test]
    fn newest_connection_restarts_authentication_and_old_completion_is_ignored() {
        let (_, previous) = objects(1);
        let (second, second_session) = objects(2);
        let (third, third_session) = objects(3);
        let mut recovery = SessionRecoveryCoordinator::new(previous, policy());
        recovery.reduce(SessionRecoveryEvent::ConnectionReplaced {
            connection: second,
            now: MonotonicTime::ZERO,
        });

        assert!(matches!(
            recovery.reduce(SessionRecoveryEvent::ConnectionReplaced {
                connection: third,
                now: MonotonicTime::ZERO,
            }),
            Some(SessionRecoveryEffect::StartAuthentication {
                connection,
                attempt: 1,
                ..
            }) if connection == third
        ));
        assert!(recovery
            .reduce(SessionRecoveryEvent::AttemptSucceeded {
                connection: second,
                session: second_session,
            })
            .is_none());
        assert!(matches!(
            recovery.reduce(SessionRecoveryEvent::AttemptSucceeded {
                connection: third,
                session: third_session,
            }),
            Some(SessionRecoveryEffect::PublishSession { .. })
        ));
    }

    #[test]
    fn attempts_are_bounded_and_close_is_first_terminal() {
        let (_, previous) = objects(1);
        let (connection, _) = objects(2);
        let mut exhausted = SessionRecoveryCoordinator::new(previous, policy());
        exhausted.reduce(SessionRecoveryEvent::ConnectionReplaced {
            connection,
            now: MonotonicTime::ZERO,
        });
        assert!(matches!(
            exhausted.reduce(SessionRecoveryEvent::AttemptFailed {
                connection,
                now: MonotonicTime::ZERO,
            }),
            Some(SessionRecoveryEffect::StartAuthentication { attempt: 2, .. })
        ));
        assert_eq!(
            exhausted.reduce(SessionRecoveryEvent::AttemptFailed {
                connection,
                now: MonotonicTime::ZERO,
            }),
            Some(SessionRecoveryEffect::RevokeSession(previous))
        );

        let mut closed = SessionRecoveryCoordinator::new(previous, policy());
        assert_eq!(
            closed.reduce(SessionRecoveryEvent::Close),
            Some(SessionRecoveryEffect::Closed)
        );
        assert!(closed
            .reduce(SessionRecoveryEvent::ConnectionReplaced {
                connection,
                now: MonotonicTime::ZERO,
            })
            .is_none());
    }

    #[test]
    fn session_loss_can_reauthenticate_without_a_connection_generation_change() {
        let (connection, previous) = objects(1);
        let mut recovery = SessionRecoveryCoordinator::new(previous, policy());

        assert!(matches!(
            recovery.reduce(SessionRecoveryEvent::SessionLost {
                session: previous,
                connection,
                now: MonotonicTime::ZERO,
            }),
            Some(SessionRecoveryEffect::StartAuthentication {
                connection: target,
                attempt: 1,
                ..
            }) if target == connection
        ));
        assert!(recovery
            .reduce(SessionRecoveryEvent::SessionLost {
                session: previous,
                connection,
                now: MonotonicTime::ZERO,
            })
            .is_none());
    }

    #[test]
    fn session_waits_are_bounded_fifo_and_reject_deeper_dependencies() {
        let (_, session) = objects(1);
        let mut registry = ObjectRegistry::new(GenerationId::new(1));
        let connection = registry.connection();
        let another_session = registry
            .create_child(connection, ObjectKind::Session)
            .unwrap();
        let share = registry
            .create_child(another_session, ObjectKind::Share)
            .unwrap();
        let mut queue = SessionWaitQueue::new(session, 2);
        let first = queue.enqueue(session, None).unwrap();
        let second = queue.enqueue(session, None).unwrap();

        assert_eq!(queue.enqueue(session, None), Err(SessionWaitError::Full));
        assert_eq!(
            queue.enqueue(share, None),
            Err(SessionWaitError::DependencyNotSession)
        );

        let (_, replacement) = objects(2);
        assert_eq!(
            queue.publish(replacement),
            vec![
                SessionWaitOutcome::Ready {
                    id: first,
                    session: replacement,
                },
                SessionWaitOutcome::Ready {
                    id: second,
                    session: replacement,
                },
            ]
        );
    }

    #[test]
    fn session_wait_cancel_deadline_and_failure_remove_exact_entries() {
        let (_, session) = objects(1);
        let mut queue = SessionWaitQueue::new(session, 3);
        let cancelled = queue.enqueue(session, None).unwrap();
        let timed = queue.enqueue(session, Some(MonotonicTime::ZERO)).unwrap();
        let failed = queue.enqueue(session, None).unwrap();

        assert_eq!(
            queue.cancel(cancelled),
            Some(SessionWaitOutcome::Cancelled(cancelled))
        );
        assert_eq!(
            queue.advance_time(MonotonicTime::ZERO),
            vec![SessionWaitOutcome::TimedOut(timed)]
        );
        assert_eq!(
            queue.fail(),
            vec![SessionWaitOutcome::RecoveryFailed(failed)]
        );
        assert!(queue.cancel(cancelled).is_none());
    }
}
