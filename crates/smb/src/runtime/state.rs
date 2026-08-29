use super::reducer::{
    GenerationId, ReduceEffect, RequestEvent, RequestKey, RequestRecord, TerminalOutcome,
};
use std::collections::HashMap;

/// Typed input lane for the sole state owner of one connection generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OwnerEvent {
    Admit {
        message_id: u64,
    },
    Request {
        key: RequestKey,
        event: RequestEvent,
    },
    Disconnect,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OwnerEffect {
    Admitted(RequestKey),
    Request {
        key: RequestKey,
        effect: ReduceEffect,
    },
    UnknownRequest(RequestKey),
}

/// All mutable request authority for exactly one physical generation.
pub(crate) struct GenerationState {
    generation: GenerationId,
    requests: HashMap<RequestKey, RequestRecord>,
}

impl GenerationState {
    pub(crate) fn new(generation: GenerationId) -> Self {
        Self {
            generation,
            requests: HashMap::new(),
        }
    }

    pub(crate) fn reduce(&mut self, event: OwnerEvent) -> Vec<OwnerEffect> {
        match event {
            OwnerEvent::Admit { message_id } => {
                let key = RequestKey::new(self.generation, message_id);
                self.requests
                    .entry(key)
                    .or_insert_with(|| RequestRecord::new(key));
                vec![OwnerEffect::Admitted(key)]
            }
            OwnerEvent::Request { key, event } => {
                if key.generation != self.generation {
                    return vec![OwnerEffect::Request {
                        key,
                        effect: ReduceEffect::IgnoredForeignGeneration,
                    }];
                }
                let Some(request) = self.requests.get_mut(&key) else {
                    return vec![OwnerEffect::UnknownRequest(key)];
                };
                vec![OwnerEffect::Request {
                    key,
                    effect: request.reduce(event),
                }]
            }
            OwnerEvent::Disconnect => self
                .requests
                .iter_mut()
                .map(|(key, request)| OwnerEffect::Request {
                    key: *key,
                    effect: request.reduce(RequestEvent::Disconnect),
                })
                .collect(),
        }
    }

    pub(crate) fn request(&self, key: RequestKey) -> Option<&RequestRecord> {
        self.requests.get(&key)
    }

    pub(crate) fn unresolved_callers(&self) -> usize {
        self.requests
            .values()
            .filter(|request| request.caller() == super::reducer::CallerOutcome::Open)
            .count()
    }

    pub(crate) fn terminal_outcome(&self, key: RequestKey) -> Option<TerminalOutcome> {
        match self.requests.get(&key)?.caller() {
            super::reducer::CallerOutcome::Open => None,
            super::reducer::CallerOutcome::Terminal(outcome) => Some(outcome),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GENERATION: GenerationId = GenerationId::new(3);

    #[test]
    fn owner_rejects_foreign_generation_before_registry_lookup() {
        let mut state = GenerationState::new(GENERATION);
        let foreign = RequestKey::new(GenerationId::new(4), 1);
        assert_eq!(
            state.reduce(OwnerEvent::Request {
                key: foreign,
                event: RequestEvent::FinalResponse { key: foreign },
            }),
            vec![OwnerEffect::Request {
                key: foreign,
                effect: ReduceEffect::IgnoredForeignGeneration,
            }]
        );
    }

    #[test]
    fn unknown_late_response_does_not_create_a_request() {
        let mut state = GenerationState::new(GENERATION);
        let unknown = RequestKey::new(GENERATION, 9);
        assert_eq!(
            state.reduce(OwnerEvent::Request {
                key: unknown,
                event: RequestEvent::FinalResponse { key: unknown },
            }),
            vec![OwnerEffect::UnknownRequest(unknown)]
        );
        assert!(state.request(unknown).is_none());
    }

    #[test]
    fn disconnect_terminally_completes_every_open_caller_once() {
        let mut state = GenerationState::new(GENERATION);
        let first = RequestKey::new(GENERATION, 1);
        let second = RequestKey::new(GENERATION, 2);
        state.reduce(OwnerEvent::Admit { message_id: 1 });
        state.reduce(OwnerEvent::Admit { message_id: 2 });
        state.reduce(OwnerEvent::Request {
            key: first,
            event: RequestEvent::FinalResponse { key: first },
        });

        let effects = state.reduce(OwnerEvent::Disconnect);
        assert_eq!(
            effects
                .iter()
                .filter(|effect| matches!(
                    effect,
                    OwnerEffect::Request {
                        effect: ReduceEffect::Publish(_),
                        ..
                    }
                ))
                .count(),
            1
        );
        assert_eq!(state.unresolved_callers(), 0);
        assert_eq!(
            state.terminal_outcome(first),
            Some(TerminalOutcome::Response)
        );
        assert_eq!(
            state.terminal_outcome(second),
            Some(TerminalOutcome::GenerationLost)
        );
    }
}
