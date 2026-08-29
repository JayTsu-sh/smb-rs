//! Deterministic durable/persistent Resource reconnect authority.

use super::ObjectToken;
use crate::clock::MonotonicTime;
use smb_dtyp::Guid;
use smb_msg::FileId;
use std::time::Duration;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DurableIdentity {
    pub(crate) file_id: FileId,
    pub(crate) create_guid: Guid,
    pub(crate) persistent: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DurableRecoveryPolicy {
    pub(crate) max_attempts: u32,
    pub(crate) attempt_timeout: Duration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DurableRecoveryState {
    Active {
        resource: ObjectToken,
        identity: DurableIdentity,
    },
    Reconnecting {
        previous: ObjectToken,
        identity: DurableIdentity,
        share: ObjectToken,
        attempt: u32,
        deadline: MonotonicTime,
    },
    Revoked(ObjectToken),
    Closed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DurableRecoveryEvent {
    ShareReplaced {
        share: ObjectToken,
        now: MonotonicTime,
    },
    AttemptFailed {
        share: ObjectToken,
        now: MonotonicTime,
    },
    AttemptSucceeded {
        share: ObjectToken,
        resource: ObjectToken,
        identity: DurableIdentity,
    },
    Close,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DurableRecoveryEffect {
    StartReconnect {
        share: ObjectToken,
        identity: DurableIdentity,
        attempt: u32,
        deadline: MonotonicTime,
    },
    PublishResource {
        previous: ObjectToken,
        replacement: ObjectToken,
        identity: DurableIdentity,
    },
    RevokeResource(ObjectToken),
    Closed,
}

pub(crate) struct DurableRecoveryCoordinator {
    policy: DurableRecoveryPolicy,
    state: DurableRecoveryState,
}

impl DurableRecoveryCoordinator {
    pub(crate) const fn new(
        resource: ObjectToken,
        identity: DurableIdentity,
        policy: DurableRecoveryPolicy,
    ) -> Self {
        Self {
            policy,
            state: DurableRecoveryState::Active { resource, identity },
        }
    }

    pub(crate) fn reduce(
        &mut self,
        event: DurableRecoveryEvent,
    ) -> Option<DurableRecoveryEffect> {
        match (self.state, event) {
            (DurableRecoveryState::Closed | DurableRecoveryState::Revoked(_), _) => None,
            (_, DurableRecoveryEvent::Close) => {
                self.state = DurableRecoveryState::Closed;
                Some(DurableRecoveryEffect::Closed)
            }
            (
                DurableRecoveryState::Active { resource, identity },
                DurableRecoveryEvent::ShareReplaced { share, now },
            ) => self.start(resource, identity, share, 1, now),
            (
                DurableRecoveryState::Reconnecting {
                    previous,
                    identity,
                    share: current,
                    ..
                },
                DurableRecoveryEvent::ShareReplaced { share, now },
            ) if share != current => self.start(previous, identity, share, 1, now),
            (
                DurableRecoveryState::Reconnecting {
                    previous,
                    identity,
                    share: current,
                    attempt,
                    ..
                },
                DurableRecoveryEvent::AttemptFailed { share, now },
            ) if share == current => {
                if attempt >= self.policy.max_attempts {
                    self.state = DurableRecoveryState::Revoked(previous);
                    Some(DurableRecoveryEffect::RevokeResource(previous))
                } else {
                    self.start(previous, identity, share, attempt + 1, now)
                }
            }
            (
                DurableRecoveryState::Reconnecting {
                    previous,
                    identity,
                    share: current,
                    ..
                },
                DurableRecoveryEvent::AttemptSucceeded {
                    share,
                    resource,
                    identity: candidate,
                },
            ) if share == current
                && resource.generation() == share.generation()
                && candidate.create_guid == identity.create_guid
                && candidate.persistent == identity.persistent =>
            {
                self.state = DurableRecoveryState::Active {
                    resource,
                    identity: candidate,
                };
                Some(DurableRecoveryEffect::PublishResource {
                    previous,
                    replacement: resource,
                    identity: candidate,
                })
            }
            _ => None,
        }
    }

    fn start(
        &mut self,
        previous: ObjectToken,
        identity: DurableIdentity,
        share: ObjectToken,
        attempt: u32,
        now: MonotonicTime,
    ) -> Option<DurableRecoveryEffect> {
        if self.policy.max_attempts == 0 {
            self.state = DurableRecoveryState::Revoked(previous);
            return Some(DurableRecoveryEffect::RevokeResource(previous));
        }
        let deadline = now.saturating_add(self.policy.attempt_timeout);
        self.state = DurableRecoveryState::Reconnecting {
            previous,
            identity,
            share,
            attempt,
            deadline,
        };
        Some(DurableRecoveryEffect::StartReconnect {
            share,
            identity,
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
        let session = objects.create_child(connection, ObjectKind::Session).unwrap();
        let share = objects.create_child(session, ObjectKind::Share).unwrap();
        let resource = objects.create_child(share, ObjectKind::Resource).unwrap();
        (share, resource)
    }

    fn identity(file: u64) -> DurableIdentity {
        DurableIdentity {
            file_id: FileId {
                persistent: file,
                volatile: file + 1,
            },
            create_guid: Guid::from_u128(7),
            persistent: false,
        }
    }

    fn policy() -> DurableRecoveryPolicy {
        DurableRecoveryPolicy {
            max_attempts: 2,
            attempt_timeout: Duration::from_secs(3),
        }
    }

    #[test]
    fn validated_identity_publishes_a_resource_in_the_target_generation() {
        let (_, previous) = objects(1);
        let (share, replacement) = objects(2);
        let mut recovery = DurableRecoveryCoordinator::new(previous, identity(10), policy());
        assert!(matches!(
            recovery.reduce(DurableRecoveryEvent::ShareReplaced {
                share,
                now: MonotonicTime::ZERO,
            }),
            Some(DurableRecoveryEffect::StartReconnect { attempt: 1, .. })
        ));
        let candidate = identity(20);
        assert!(matches!(
            recovery.reduce(DurableRecoveryEvent::AttemptSucceeded {
                share,
                resource: replacement,
                identity: candidate,
            }),
            Some(DurableRecoveryEffect::PublishResource {
                replacement: found,
                identity: found_identity,
                ..
            }) if found == replacement && found_identity == candidate
        ));
    }

    #[test]
    fn mismatched_guid_persistence_and_generation_are_rejected() {
        let (_, previous) = objects(1);
        let (share, replacement) = objects(2);
        let (_, foreign) = objects(3);
        let mut recovery = DurableRecoveryCoordinator::new(previous, identity(10), policy());
        recovery.reduce(DurableRecoveryEvent::ShareReplaced {
            share,
            now: MonotonicTime::ZERO,
        });
        let mut wrong_guid = identity(20);
        wrong_guid.create_guid = Guid::from_u128(8);
        assert!(recovery
            .reduce(DurableRecoveryEvent::AttemptSucceeded {
                share,
                resource: replacement,
                identity: wrong_guid,
            })
            .is_none());
        let mut wrong_persistence = identity(20);
        wrong_persistence.persistent = true;
        assert!(recovery
            .reduce(DurableRecoveryEvent::AttemptSucceeded {
                share,
                resource: replacement,
                identity: wrong_persistence,
            })
            .is_none());
        assert!(recovery
            .reduce(DurableRecoveryEvent::AttemptSucceeded {
                share,
                resource: foreign,
                identity: identity(20),
            })
            .is_none());
    }

    #[test]
    fn retry_consecutive_parent_replacement_and_close_are_first_wins() {
        let (_, previous) = objects(1);
        let (second, _) = objects(2);
        let (third, _) = objects(3);
        let mut recovery = DurableRecoveryCoordinator::new(previous, identity(10), policy());
        recovery.reduce(DurableRecoveryEvent::ShareReplaced {
            share: second,
            now: MonotonicTime::ZERO,
        });
        assert!(matches!(
            recovery.reduce(DurableRecoveryEvent::AttemptFailed {
                share: second,
                now: MonotonicTime::ZERO,
            }),
            Some(DurableRecoveryEffect::StartReconnect { attempt: 2, .. })
        ));
        assert!(matches!(
            recovery.reduce(DurableRecoveryEvent::ShareReplaced {
                share: third,
                now: MonotonicTime::ZERO,
            }),
            Some(DurableRecoveryEffect::StartReconnect {
                share,
                attempt: 1,
                ..
            }) if share == third
        ));
        assert_eq!(
            recovery.reduce(DurableRecoveryEvent::Close),
            Some(DurableRecoveryEffect::Closed)
        );
        assert!(recovery
            .reduce(DurableRecoveryEvent::AttemptFailed {
                share: third,
                now: MonotonicTime::ZERO,
            })
            .is_none());
    }
}
