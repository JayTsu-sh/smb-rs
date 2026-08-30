//! Deterministic authority for server-initiated lease/oplock events.

use super::GenerationId;
use crate::clock::MonotonicTime;
use std::collections::BTreeMap;
use std::time::Duration;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct BreakKey {
    pub(crate) generation: GenerationId,
    pub(crate) lease_key: u128,
    pub(crate) epoch: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EventPolicy {
    pub(crate) capacity: usize,
    pub(crate) ack_timeout: Duration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AckOutcome {
    NotRequired,
    Accepted,
    Failed,
    TimedOut,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BreakState {
    Received { ack_required: bool },
    AckPending { deadline: MonotonicTime },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EventInput {
    Receive { key: BreakKey, ack_required: bool },
    Invalidated { key: BreakKey, now: MonotonicTime },
    AckCompleted { key: BreakKey, accepted: bool },
    AckDeadline { key: BreakKey, now: MonotonicTime },
    ReplaceGeneration(GenerationId),
    Close,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EventEffect {
    Invalidate(BreakKey),
    SendAck {
        key: BreakKey,
        deadline: MonotonicTime,
    },
    Publish {
        key: BreakKey,
        ack: AckOutcome,
    },
    QueueFull(BreakKey),
    IgnoreStale(BreakKey),
    Closed,
}

pub(crate) struct EventAuthority {
    generation: GenerationId,
    policy: EventPolicy,
    pending: BTreeMap<BreakKey, BreakState>,
    closed: bool,
}

impl EventAuthority {
    pub(crate) const fn new(generation: GenerationId, policy: EventPolicy) -> Self {
        Self {
            generation,
            policy,
            pending: BTreeMap::new(),
            closed: false,
        }
    }

    pub(crate) fn reduce(&mut self, input: EventInput) -> Vec<EventEffect> {
        if self.closed {
            return Vec::new();
        }
        match input {
            EventInput::Receive { key, ack_required } => {
                if key.generation != self.generation {
                    return vec![EventEffect::IgnoreStale(key)];
                }
                if self.pending.contains_key(&key) {
                    return Vec::new();
                }
                if self.pending.len() >= self.policy.capacity {
                    return vec![EventEffect::QueueFull(key)];
                }
                self.pending
                    .insert(key, BreakState::Received { ack_required });
                vec![EventEffect::Invalidate(key)]
            }
            EventInput::Invalidated { key, now } => {
                let Some(BreakState::Received { ack_required }) = self.pending.get(&key).copied()
                else {
                    return Vec::new();
                };
                if ack_required {
                    let deadline = now.saturating_add(self.policy.ack_timeout);
                    self.pending
                        .insert(key, BreakState::AckPending { deadline });
                    vec![EventEffect::SendAck { key, deadline }]
                } else {
                    self.pending.remove(&key);
                    vec![EventEffect::Publish {
                        key,
                        ack: AckOutcome::NotRequired,
                    }]
                }
            }
            EventInput::AckCompleted { key, accepted } => {
                if !matches!(self.pending.get(&key), Some(BreakState::AckPending { .. })) {
                    return Vec::new();
                }
                self.pending.remove(&key);
                vec![EventEffect::Publish {
                    key,
                    ack: if accepted {
                        AckOutcome::Accepted
                    } else {
                        AckOutcome::Failed
                    },
                }]
            }
            EventInput::AckDeadline { key, now } => {
                let Some(BreakState::AckPending { deadline }) = self.pending.get(&key).copied()
                else {
                    return Vec::new();
                };
                if now < deadline {
                    return Vec::new();
                }
                self.pending.remove(&key);
                vec![EventEffect::Publish {
                    key,
                    ack: AckOutcome::TimedOut,
                }]
            }
            EventInput::ReplaceGeneration(generation) => {
                self.generation = generation;
                self.pending.retain(|key, _| key.generation == generation);
                Vec::new()
            }
            EventInput::Close => {
                self.pending.clear();
                self.closed = true;
                vec![EventEffect::Closed]
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIRST: GenerationId = GenerationId::new(1);
    const SECOND: GenerationId = GenerationId::new(2);

    fn key(generation: GenerationId, lease_key: u128) -> BreakKey {
        BreakKey {
            generation,
            lease_key,
            epoch: 7,
        }
    }

    fn authority(capacity: usize) -> EventAuthority {
        EventAuthority::new(
            FIRST,
            EventPolicy {
                capacity,
                ack_timeout: Duration::from_secs(3),
            },
        )
    }

    #[test]
    fn invalidation_precedes_bounded_ack_and_publication() {
        let mut events = authority(2);
        let key = key(FIRST, 11);
        assert_eq!(
            events.reduce(EventInput::Receive {
                key,
                ack_required: true,
            }),
            vec![EventEffect::Invalidate(key)]
        );
        assert!(matches!(
            events.reduce(EventInput::Invalidated {
                key,
                now: MonotonicTime::ZERO,
            })[..],
            [EventEffect::SendAck { key: found, .. }] if found == key
        ));
        assert_eq!(
            events.reduce(EventInput::AckCompleted {
                key,
                accepted: true,
            }),
            vec![EventEffect::Publish {
                key,
                ack: AckOutcome::Accepted,
            }]
        );
    }

    #[test]
    fn duplicate_stale_and_over_capacity_events_are_explicit() {
        let mut events = authority(1);
        let first = key(FIRST, 11);
        let second = key(FIRST, 12);
        let stale = key(SECOND, 13);
        events.reduce(EventInput::Receive {
            key: first,
            ack_required: true,
        });
        assert!(
            events
                .reduce(EventInput::Receive {
                    key: first,
                    ack_required: true,
                })
                .is_empty()
        );
        assert_eq!(
            events.reduce(EventInput::Receive {
                key: second,
                ack_required: false,
            }),
            vec![EventEffect::QueueFull(second)]
        );
        assert_eq!(
            events.reduce(EventInput::Receive {
                key: stale,
                ack_required: false,
            }),
            vec![EventEffect::IgnoreStale(stale)]
        );
    }

    #[test]
    fn deadline_generation_replacement_and_close_are_terminal() {
        let mut events = authority(2);
        let old = key(FIRST, 11);
        events.reduce(EventInput::Receive {
            key: old,
            ack_required: true,
        });
        events.reduce(EventInput::Invalidated {
            key: old,
            now: MonotonicTime::ZERO,
        });
        assert!(
            events
                .reduce(EventInput::AckDeadline {
                    key: old,
                    now: MonotonicTime::ZERO.saturating_add(Duration::from_secs(2)),
                })
                .is_empty()
        );
        assert_eq!(
            events.reduce(EventInput::AckDeadline {
                key: old,
                now: MonotonicTime::ZERO.saturating_add(Duration::from_secs(3)),
            }),
            vec![EventEffect::Publish {
                key: old,
                ack: AckOutcome::TimedOut,
            }]
        );
        events.reduce(EventInput::ReplaceGeneration(SECOND));
        let current = key(SECOND, 12);
        assert_eq!(
            events.reduce(EventInput::Receive {
                key: current,
                ack_required: false,
            }),
            vec![EventEffect::Invalidate(current)]
        );
        assert_eq!(events.reduce(EventInput::Close), vec![EventEffect::Closed]);
        assert!(
            events
                .reduce(EventInput::Receive {
                    key: current,
                    ack_required: false,
                })
                .is_empty()
        );
    }
}
