//! Deterministic Share TreeConnect replay authority.

use super::ObjectToken;
use crate::clock::MonotonicTime;
use std::collections::VecDeque;
use std::time::Duration;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ShareRecoveryPolicy {
    pub(crate) max_attempts: u32,
    pub(crate) attempt_timeout: Duration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ShareRecoveryState {
    Active(ObjectToken),
    Replaying {
        previous: ObjectToken,
        session: ObjectToken,
        attempt: u32,
        deadline: MonotonicTime,
    },
    Revoked(ObjectToken),
    Closed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ShareRecoveryEvent {
    SessionReplaced {
        session: ObjectToken,
        now: MonotonicTime,
    },
    AttemptFailed {
        session: ObjectToken,
        now: MonotonicTime,
    },
    AttemptSucceeded {
        session: ObjectToken,
        share: ObjectToken,
    },
    Close,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ShareRecoveryEffect {
    StartTreeConnect {
        session: ObjectToken,
        attempt: u32,
        deadline: MonotonicTime,
    },
    PublishShare {
        previous: ObjectToken,
        replacement: ObjectToken,
    },
    RevokeShare(ObjectToken),
    Closed,
}

pub(crate) struct ShareRecoveryCoordinator {
    policy: ShareRecoveryPolicy,
    state: ShareRecoveryState,
}

impl ShareRecoveryCoordinator {
    pub(crate) const fn new(share: ObjectToken, policy: ShareRecoveryPolicy) -> Self {
        Self {
            policy,
            state: ShareRecoveryState::Active(share),
        }
    }

    pub(crate) fn reduce(&mut self, event: ShareRecoveryEvent) -> Option<ShareRecoveryEffect> {
        match (self.state, event) {
            (ShareRecoveryState::Closed | ShareRecoveryState::Revoked(_), _) => None,
            (_, ShareRecoveryEvent::Close) => {
                self.state = ShareRecoveryState::Closed;
                Some(ShareRecoveryEffect::Closed)
            }
            (
                ShareRecoveryState::Active(previous),
                ShareRecoveryEvent::SessionReplaced { session, now },
            ) => self.start(previous, session, 1, now),
            (
                ShareRecoveryState::Replaying {
                    previous,
                    session: current,
                    ..
                },
                ShareRecoveryEvent::SessionReplaced { session, now },
            ) if session != current => self.start(previous, session, 1, now),
            (
                ShareRecoveryState::Replaying {
                    previous,
                    session: current,
                    attempt,
                    ..
                },
                ShareRecoveryEvent::AttemptFailed { session, now },
            ) if session == current => {
                if attempt >= self.policy.max_attempts {
                    self.state = ShareRecoveryState::Revoked(previous);
                    Some(ShareRecoveryEffect::RevokeShare(previous))
                } else {
                    self.start(previous, session, attempt + 1, now)
                }
            }
            (
                ShareRecoveryState::Replaying {
                    previous,
                    session: current,
                    ..
                },
                ShareRecoveryEvent::AttemptSucceeded { session, share },
            ) if session == current && share.generation() == session.generation() => {
                self.state = ShareRecoveryState::Active(share);
                Some(ShareRecoveryEffect::PublishShare {
                    previous,
                    replacement: share,
                })
            }
            _ => None,
        }
    }

    fn start(
        &mut self,
        previous: ObjectToken,
        session: ObjectToken,
        attempt: u32,
        now: MonotonicTime,
    ) -> Option<ShareRecoveryEffect> {
        if self.policy.max_attempts == 0 {
            self.state = ShareRecoveryState::Revoked(previous);
            return Some(ShareRecoveryEffect::RevokeShare(previous));
        }
        let deadline = now.saturating_add(self.policy.attempt_timeout);
        self.state = ShareRecoveryState::Replaying {
            previous,
            session,
            attempt,
            deadline,
        };
        Some(ShareRecoveryEffect::StartTreeConnect {
            session,
            attempt,
            deadline,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct ShareWaitId(u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ShareWaitError {
    Full,
    DependencyNotShare,
    IdExhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ShareWaitOutcome {
    Ready { id: ShareWaitId, share: ObjectToken },
    Cancelled(ShareWaitId),
    TimedOut(ShareWaitId),
    RecoveryFailed(ShareWaitId),
}

#[derive(Clone, Copy, Debug)]
struct ShareWait {
    id: ShareWaitId,
    dependency: ObjectToken,
    deadline: Option<MonotonicTime>,
}

pub(crate) struct ShareWaitQueue {
    share: ObjectToken,
    capacity: usize,
    next_id: Option<u64>,
    waits: VecDeque<ShareWait>,
}

impl ShareWaitQueue {
    pub(crate) fn new(share: ObjectToken, capacity: usize) -> Self {
        Self {
            share,
            capacity,
            next_id: Some(0),
            waits: VecDeque::with_capacity(capacity),
        }
    }

    pub(crate) fn enqueue(
        &mut self,
        dependency: ObjectToken,
        deadline: Option<MonotonicTime>,
    ) -> Result<ShareWaitId, ShareWaitError> {
        if dependency != self.share {
            return Err(ShareWaitError::DependencyNotShare);
        }
        if self.waits.len() >= self.capacity {
            return Err(ShareWaitError::Full);
        }
        let id = ShareWaitId(self.next_id.ok_or(ShareWaitError::IdExhausted)?);
        self.next_id = id.0.checked_add(1);
        self.waits.push_back(ShareWait {
            id,
            dependency,
            deadline,
        });
        Ok(id)
    }

    pub(crate) fn cancel(&mut self, id: ShareWaitId) -> Option<ShareWaitOutcome> {
        let index = self.waits.iter().position(|wait| wait.id == id)?;
        self.waits.remove(index)?;
        Some(ShareWaitOutcome::Cancelled(id))
    }

    pub(crate) fn advance_time(&mut self, now: MonotonicTime) -> Vec<ShareWaitOutcome> {
        let mut outcomes = Vec::new();
        self.waits.retain(|wait| {
            if wait.deadline.is_some_and(|deadline| deadline <= now) {
                outcomes.push(ShareWaitOutcome::TimedOut(wait.id));
                false
            } else {
                true
            }
        });
        outcomes
    }

    pub(crate) fn publish(&mut self, replacement: ObjectToken) -> Vec<ShareWaitOutcome> {
        let previous = self.share;
        self.share = replacement;
        self.waits
            .drain(..)
            .filter(|wait| wait.dependency == previous)
            .map(|wait| ShareWaitOutcome::Ready {
                id: wait.id,
                share: replacement,
            })
            .collect()
    }

    pub(crate) fn fail(&mut self) -> Vec<ShareWaitOutcome> {
        self.waits
            .drain(..)
            .map(|wait| ShareWaitOutcome::RecoveryFailed(wait.id))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::object_state::{ObjectKind, ObjectRegistry};
    use crate::runtime::GenerationId;

    fn objects(generation: u64) -> (ObjectToken, ObjectToken, ObjectToken) {
        let mut objects = ObjectRegistry::new(GenerationId::new(generation));
        let connection = objects.connection();
        let session = objects.create_child(connection, ObjectKind::Session).unwrap();
        let share = objects.create_child(session, ObjectKind::Share).unwrap();
        (session, share, objects.create_child(share, ObjectKind::Resource).unwrap())
    }

    fn policy() -> ShareRecoveryPolicy {
        ShareRecoveryPolicy {
            max_attempts: 2,
            attempt_timeout: Duration::from_secs(3),
        }
    }

    #[test]
    fn replay_publishes_only_for_the_target_session() {
        let (_, previous, _) = objects(1);
        let (session, replacement, _) = objects(2);
        let mut recovery = ShareRecoveryCoordinator::new(previous, policy());
        assert!(matches!(
            recovery.reduce(ShareRecoveryEvent::SessionReplaced {
                session,
                now: MonotonicTime::ZERO,
            }),
            Some(ShareRecoveryEffect::StartTreeConnect { attempt: 1, .. })
        ));
        assert_eq!(
            recovery.reduce(ShareRecoveryEvent::AttemptSucceeded {
                session,
                share: replacement,
            }),
            Some(ShareRecoveryEffect::PublishShare {
                previous,
                replacement,
            })
        );
    }

    #[test]
    fn duplicate_stale_and_consecutive_session_events_have_one_owner() {
        let (_, previous, _) = objects(1);
        let (second, second_share, _) = objects(2);
        let (third, third_share, _) = objects(3);
        let mut recovery = ShareRecoveryCoordinator::new(previous, policy());
        recovery.reduce(ShareRecoveryEvent::SessionReplaced {
            session: second,
            now: MonotonicTime::ZERO,
        });
        assert!(recovery
            .reduce(ShareRecoveryEvent::SessionReplaced {
                session: second,
                now: MonotonicTime::ZERO,
            })
            .is_none());
        assert!(matches!(
            recovery.reduce(ShareRecoveryEvent::SessionReplaced {
                session: third,
                now: MonotonicTime::ZERO,
            }),
            Some(ShareRecoveryEffect::StartTreeConnect {
                session,
                attempt: 1,
                ..
            }) if session == third
        ));
        assert!(recovery
            .reduce(ShareRecoveryEvent::AttemptSucceeded {
                session: second,
                share: second_share,
            })
            .is_none());
        assert!(matches!(
            recovery.reduce(ShareRecoveryEvent::AttemptSucceeded {
                session: third,
                share: third_share,
            }),
            Some(ShareRecoveryEffect::PublishShare { .. })
        ));
    }

    #[test]
    fn retry_exhaustion_and_close_are_terminal() {
        let (_, previous, _) = objects(1);
        let (session, _, _) = objects(2);
        let mut recovery = ShareRecoveryCoordinator::new(previous, policy());
        recovery.reduce(ShareRecoveryEvent::SessionReplaced {
            session,
            now: MonotonicTime::ZERO,
        });
        assert!(matches!(
            recovery.reduce(ShareRecoveryEvent::AttemptFailed {
                session,
                now: MonotonicTime::ZERO,
            }),
            Some(ShareRecoveryEffect::StartTreeConnect { attempt: 2, .. })
        ));
        assert_eq!(
            recovery.reduce(ShareRecoveryEvent::AttemptFailed {
                session,
                now: MonotonicTime::ZERO,
            }),
            Some(ShareRecoveryEffect::RevokeShare(previous))
        );
        let mut closed = ShareRecoveryCoordinator::new(previous, policy());
        assert_eq!(
            closed.reduce(ShareRecoveryEvent::Close),
            Some(ShareRecoveryEffect::Closed)
        );
        assert!(closed
            .reduce(ShareRecoveryEvent::SessionReplaced {
                session,
                now: MonotonicTime::ZERO,
            })
            .is_none());
    }

    #[test]
    fn waits_are_bounded_fifo_and_resources_never_enter() {
        let (_, share, resource) = objects(1);
        let mut queue = ShareWaitQueue::new(share, 2);
        let first = queue.enqueue(share, None).unwrap();
        let second = queue.enqueue(share, None).unwrap();
        assert_eq!(queue.enqueue(share, None), Err(ShareWaitError::Full));
        assert_eq!(
            queue.enqueue(resource, None),
            Err(ShareWaitError::DependencyNotShare)
        );
        let (_, replacement, _) = objects(2);
        assert_eq!(
            queue.publish(replacement),
            vec![
                ShareWaitOutcome::Ready {
                    id: first,
                    share: replacement,
                },
                ShareWaitOutcome::Ready {
                    id: second,
                    share: replacement,
                },
            ]
        );
    }

    #[test]
    fn cancellation_deadline_and_failure_remove_exact_waits() {
        let (_, share, _) = objects(1);
        let mut queue = ShareWaitQueue::new(share, 3);
        let cancelled = queue.enqueue(share, None).unwrap();
        let timed = queue.enqueue(share, Some(MonotonicTime::ZERO)).unwrap();
        let failed = queue.enqueue(share, None).unwrap();
        assert_eq!(
            queue.cancel(cancelled),
            Some(ShareWaitOutcome::Cancelled(cancelled))
        );
        assert_eq!(
            queue.advance_time(MonotonicTime::ZERO),
            vec![ShareWaitOutcome::TimedOut(timed)]
        );
        assert_eq!(
            queue.fail(),
            vec![ShareWaitOutcome::RecoveryFailed(failed)]
        );
    }
}
