//! Deterministic Session reauthentication authority.
//!
//! The reducer owns only lifecycle decisions. Credential acquisition and
//! SessionSetup I/O are effects executed by one async coordinator.

use super::ObjectToken;
use crate::clock::MonotonicTime;
use std::time::Duration;

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
}
