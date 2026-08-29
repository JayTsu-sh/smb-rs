use super::reducer::{
    CallerOutcome, GenerationId, ReduceEffect, RequestEvent, RequestKey, RequestRecord,
    ResponseProgress, TerminalOutcome,
};
use std::collections::HashMap;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AdmissionLimits {
    pub(crate) max_operations: usize,
    pub(crate) max_payload_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AdmissionError {
    OperationsExhausted,
    PayloadBytesExhausted,
    CreditsExhausted { available: u32, requested: u16 },
    MessageIdExhausted,
    InvalidCreditCharge,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PreparationPlan {
    pub(crate) key: RequestKey,
    pub(crate) payload_bytes: u64,
    pub(crate) credit_charge: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResponseEvent {
    Pending { async_id: u64 },
    Final,
}

/// Typed input lane for the sole state owner of one connection generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OwnerEvent {
    Admit {
        payload_bytes: u64,
        credit_charge: u16,
    },
    Request {
        key: RequestKey,
        event: RequestEvent,
    },
    PrepareFailed {
        key: RequestKey,
    },
    Response {
        key: RequestKey,
        event: ResponseEvent,
        credit_grant: u16,
    },
    Disconnect,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OwnerEffect {
    Admitted(PreparationPlan),
    AdmissionRejected(AdmissionError),
    Request {
        key: RequestKey,
        effect: ReduceEffect,
    },
    ReservationRolledBack(RequestKey),
    CreditGrantApplied {
        key: RequestKey,
        grant: u16,
        available: u32,
    },
    DuplicateResponse(RequestKey),
    CreditLedgerOverflow {
        key: RequestKey,
        available: u32,
        grant: u16,
    },
    UnknownRequest(RequestKey),
}

struct OwnedRequest {
    lifecycle: RequestRecord,
    payload_bytes: u64,
    credit_charge: u16,
    admission_held: bool,
    credit_obligation: bool,
}

/// All mutable request authority for exactly one physical generation.
pub(crate) struct GenerationState {
    generation: GenerationId,
    limits: AdmissionLimits,
    next_message_id: Option<u64>,
    available_credits: u32,
    admitted_operations: usize,
    retained_payload_bytes: u64,
    requests: HashMap<RequestKey, OwnedRequest>,
}

impl GenerationState {
    pub(crate) fn new(
        generation: GenerationId,
        initial_message_id: u64,
        initial_credits: u32,
        limits: AdmissionLimits,
    ) -> Self {
        Self {
            generation,
            limits,
            next_message_id: Some(initial_message_id),
            available_credits: initial_credits,
            admitted_operations: 0,
            retained_payload_bytes: 0,
            requests: HashMap::new(),
        }
    }

    pub(crate) fn reduce(&mut self, event: OwnerEvent) -> Vec<OwnerEffect> {
        match event {
            OwnerEvent::Admit {
                payload_bytes,
                credit_charge,
            } => vec![self.admit(payload_bytes, credit_charge)],
            OwnerEvent::Request { key, event } => self.request_event(key, event),
            OwnerEvent::PrepareFailed { key } => self.prepare_failed(key),
            OwnerEvent::Response {
                key,
                event,
                credit_grant,
            } => self.response(key, event, credit_grant),
            OwnerEvent::Disconnect => self.disconnect(),
        }
    }

    fn admit(&mut self, payload_bytes: u64, credit_charge: u16) -> OwnerEffect {
        let rejection = if credit_charge == 0 {
            Some(AdmissionError::InvalidCreditCharge)
        } else if self.admitted_operations >= self.limits.max_operations {
            Some(AdmissionError::OperationsExhausted)
        } else if self
            .retained_payload_bytes
            .checked_add(payload_bytes)
            .is_none_or(|total| total > self.limits.max_payload_bytes)
        {
            Some(AdmissionError::PayloadBytesExhausted)
        } else if u32::from(credit_charge) > self.available_credits {
            Some(AdmissionError::CreditsExhausted {
                available: self.available_credits,
                requested: credit_charge,
            })
        } else if self.next_message_id.is_none() {
            Some(AdmissionError::MessageIdExhausted)
        } else {
            None
        };
        if let Some(error) = rejection {
            return OwnerEffect::AdmissionRejected(error);
        }

        let Some(message_id) = self.next_message_id else {
            return OwnerEffect::AdmissionRejected(AdmissionError::MessageIdExhausted);
        };
        self.next_message_id = message_id.checked_add(1);
        let key = RequestKey::new(self.generation, message_id);
        let plan = PreparationPlan {
            key,
            payload_bytes,
            credit_charge,
        };
        self.available_credits -= u32::from(credit_charge);
        self.admitted_operations += 1;
        self.retained_payload_bytes += payload_bytes;
        self.requests.insert(
            key,
            OwnedRequest {
                lifecycle: RequestRecord::new(key),
                payload_bytes,
                credit_charge,
                admission_held: true,
                credit_obligation: true,
            },
        );
        OwnerEffect::Admitted(plan)
    }

    fn request_event(&mut self, key: RequestKey, event: RequestEvent) -> Vec<OwnerEffect> {
        if key.generation != self.generation {
            return vec![OwnerEffect::Request {
                key,
                effect: ReduceEffect::IgnoredForeignGeneration,
            }];
        }
        let Some(request) = self.requests.get_mut(&key) else {
            return vec![OwnerEffect::UnknownRequest(key)];
        };
        let effect = request.lifecycle.reduce(event);
        let should_rollback = matches!(event, RequestEvent::Cancel | RequestEvent::Deadline)
            && !request.lifecycle.wire_committed();
        let mut effects = vec![OwnerEffect::Request { key, effect }];
        if should_rollback && self.rollback(key) {
            effects.push(OwnerEffect::ReservationRolledBack(key));
        }
        effects
    }

    fn prepare_failed(&mut self, key: RequestKey) -> Vec<OwnerEffect> {
        if key.generation != self.generation {
            return vec![OwnerEffect::Request {
                key,
                effect: ReduceEffect::IgnoredForeignGeneration,
            }];
        }
        let Some(request) = self.requests.get_mut(&key) else {
            return vec![OwnerEffect::UnknownRequest(key)];
        };
        if request.lifecycle.wire_committed() {
            return vec![OwnerEffect::Request {
                key,
                effect: ReduceEffect::BookkeepingOnly,
            }];
        }
        let effect = request
            .lifecycle
            .publish_terminal(TerminalOutcome::PreparationFailed);
        let mut effects = vec![OwnerEffect::Request { key, effect }];
        if self.rollback(key) {
            effects.push(OwnerEffect::ReservationRolledBack(key));
        }
        effects
    }

    fn response(
        &mut self,
        key: RequestKey,
        event: ResponseEvent,
        credit_grant: u16,
    ) -> Vec<OwnerEffect> {
        if key.generation != self.generation {
            return vec![OwnerEffect::Request {
                key,
                effect: ReduceEffect::IgnoredForeignGeneration,
            }];
        }
        let Some(request) = self.requests.get_mut(&key) else {
            return vec![OwnerEffect::UnknownRequest(key)];
        };
        let duplicate = match event {
            ResponseEvent::Pending { async_id } => {
                matches!(
                    request.lifecycle.response(),
                    ResponseProgress::AsyncPending { async_id: current } if current == async_id
                ) || request.lifecycle.response() == ResponseProgress::Final
            }
            ResponseEvent::Final => request.lifecycle.response() == ResponseProgress::Final,
        };
        if duplicate {
            return vec![OwnerEffect::DuplicateResponse(key)];
        }

        // Protocol bookkeeping deliberately precedes caller completion.
        request.lifecycle.observe_response_commitment();
        let Some(available) = self.available_credits.checked_add(u32::from(credit_grant)) else {
            return vec![OwnerEffect::CreditLedgerOverflow {
                key,
                available: self.available_credits,
                grant: credit_grant,
            }];
        };
        self.available_credits = available;
        let mut effects = vec![OwnerEffect::CreditGrantApplied {
            key,
            grant: credit_grant,
            available: self.available_credits,
        }];
        let lifecycle_event = match event {
            ResponseEvent::Pending { async_id } => RequestEvent::AsyncPending { key, async_id },
            ResponseEvent::Final => RequestEvent::FinalResponse { key },
        };
        let effect = request.lifecycle.reduce(lifecycle_event);
        effects.push(OwnerEffect::Request { key, effect });
        if event == ResponseEvent::Final {
            request.credit_obligation = false;
            self.release_admission(key);
        }
        effects
    }

    fn rollback(&mut self, key: RequestKey) -> bool {
        let Some(request) = self.requests.get_mut(&key) else {
            return false;
        };
        if !request.credit_obligation && !request.admission_held {
            return false;
        }
        if request.credit_obligation {
            let Some(available) = self
                .available_credits
                .checked_add(u32::from(request.credit_charge))
            else {
                return false;
            };
            self.available_credits = available;
            request.credit_obligation = false;
        }
        self.release_admission(key);
        true
    }

    fn release_admission(&mut self, key: RequestKey) {
        let Some(request) = self.requests.get_mut(&key) else {
            return;
        };
        if request.admission_held {
            self.admitted_operations -= 1;
            self.retained_payload_bytes -= request.payload_bytes;
            request.admission_held = false;
        }
    }

    fn disconnect(&mut self) -> Vec<OwnerEffect> {
        let keys = self.requests.keys().copied().collect::<Vec<_>>();
        let mut effects = Vec::with_capacity(keys.len() * 2);
        for key in keys {
            if let Some(request) = self.requests.get_mut(&key) {
                let effect = request.lifecycle.reduce(RequestEvent::Disconnect);
                effects.push(OwnerEffect::Request { key, effect });
            }
            self.release_admission(key);
        }
        effects
    }

    pub(crate) fn request(&self, key: RequestKey) -> Option<&RequestRecord> {
        self.requests.get(&key).map(|request| &request.lifecycle)
    }

    pub(crate) const fn available_credits(&self) -> u32 {
        self.available_credits
    }

    pub(crate) const fn admitted_operations(&self) -> usize {
        self.admitted_operations
    }

    pub(crate) const fn retained_payload_bytes(&self) -> u64 {
        self.retained_payload_bytes
    }

    pub(crate) fn unresolved_callers(&self) -> usize {
        self.requests
            .values()
            .filter(|request| request.lifecycle.caller() == CallerOutcome::Open)
            .count()
    }

    pub(crate) fn terminal_outcome(&self, key: RequestKey) -> Option<TerminalOutcome> {
        match self.requests.get(&key)?.lifecycle.caller() {
            CallerOutcome::Open => None,
            CallerOutcome::Terminal(outcome) => Some(outcome),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GENERATION: GenerationId = GenerationId::new(3);
    const LIMITS: AdmissionLimits = AdmissionLimits {
        max_operations: 2,
        max_payload_bytes: 1024,
    };

    fn state() -> GenerationState {
        GenerationState::new(GENERATION, 40, 4, LIMITS)
    }

    fn admit(state: &mut GenerationState, payload_bytes: u64, charge: u16) -> RequestKey {
        match state.reduce(OwnerEvent::Admit {
            payload_bytes,
            credit_charge: charge,
        })[..]
        {
            [OwnerEffect::Admitted(plan)] => plan.key,
            ref effects => panic!("expected admission, got {effects:?}"),
        }
    }

    #[test]
    fn admission_atomically_reserves_identity_credits_and_both_limits() {
        let mut state = state();
        let key = admit(&mut state, 512, 2);
        assert_eq!(key, RequestKey::new(GENERATION, 40));
        assert_eq!(state.available_credits(), 2);
        assert_eq!(state.admitted_operations(), 1);
        assert_eq!(state.retained_payload_bytes(), 512);
        assert!(state.request(key).is_some());
    }

    #[test]
    fn every_rejection_leaves_all_owner_counters_unchanged() {
        let cases = [
            (0, 0, AdmissionError::InvalidCreditCharge),
            (
                0,
                5,
                AdmissionError::CreditsExhausted {
                    available: 4,
                    requested: 5,
                },
            ),
            (1025, 1, AdmissionError::PayloadBytesExhausted),
        ];
        for (bytes, charge, expected) in cases {
            let mut state = state();
            assert_eq!(
                state.reduce(OwnerEvent::Admit {
                    payload_bytes: bytes,
                    credit_charge: charge,
                }),
                vec![OwnerEffect::AdmissionRejected(expected)]
            );
            assert_eq!(
                (state.available_credits(), state.admitted_operations()),
                (4, 0)
            );
            assert_eq!(state.retained_payload_bytes(), 0);
        }
    }

    #[test]
    fn operation_limit_rejects_without_consuming_next_message_id() {
        let mut state = GenerationState::new(
            GENERATION,
            9,
            3,
            AdmissionLimits {
                max_operations: 1,
                max_payload_bytes: 10,
            },
        );
        let first = admit(&mut state, 1, 1);
        assert_eq!(
            state.reduce(OwnerEvent::Admit {
                payload_bytes: 1,
                credit_charge: 1,
            }),
            vec![OwnerEffect::AdmissionRejected(
                AdmissionError::OperationsExhausted
            )]
        );
        state.reduce(OwnerEvent::Request {
            key: first,
            event: RequestEvent::Cancel,
        });
        assert_eq!(admit(&mut state, 1, 1).message_id, 10);
    }

    #[test]
    fn message_id_max_is_allocated_once_and_never_wraps() {
        let mut state = GenerationState::new(GENERATION, u64::MAX, 2, LIMITS);
        let key = admit(&mut state, 0, 1);
        assert_eq!(key.message_id, u64::MAX);
        state.reduce(OwnerEvent::Request {
            key,
            event: RequestEvent::Cancel,
        });
        assert_eq!(
            state.reduce(OwnerEvent::Admit {
                payload_bytes: 0,
                credit_charge: 1,
            }),
            vec![OwnerEffect::AdmissionRejected(
                AdmissionError::MessageIdExhausted
            )]
        );
    }

    #[test]
    fn serialized_concurrent_submissions_receive_unique_monotonic_ids() {
        let mut state = GenerationState::new(
            GENERATION,
            100,
            64,
            AdmissionLimits {
                max_operations: 64,
                max_payload_bytes: 64,
            },
        );
        let keys = (0..64).map(|_| admit(&mut state, 1, 1)).collect::<Vec<_>>();
        assert_eq!(
            keys.iter().map(|key| key.message_id).collect::<Vec<_>>(),
            (100..164).collect::<Vec<_>>()
        );
    }

    #[test]
    fn zero_byte_cancel_and_prepare_failure_roll_back_exactly_once() {
        for event in [
            OwnerEvent::Request {
                key: RequestKey::new(GENERATION, 40),
                event: RequestEvent::Cancel,
            },
            OwnerEvent::PrepareFailed {
                key: RequestKey::new(GENERATION, 40),
            },
        ] {
            let mut state = state();
            let key = admit(&mut state, 600, 3);
            assert_eq!(key.message_id, 40);
            let first = state.reduce(event);
            assert!(first.contains(&OwnerEffect::ReservationRolledBack(key)));
            assert_eq!(
                (state.available_credits(), state.admitted_operations()),
                (4, 0)
            );
            assert_eq!(state.retained_payload_bytes(), 0);
            let second = state.reduce(event);
            assert!(!second.contains(&OwnerEffect::ReservationRolledBack(key)));
            assert_eq!(
                (state.available_credits(), state.admitted_operations()),
                (4, 0)
            );
        }
    }

    #[test]
    fn first_write_byte_forbids_local_credit_rollback() {
        let mut state = state();
        let key = admit(&mut state, 100, 2);
        state.reduce(OwnerEvent::Request {
            key,
            event: RequestEvent::WriteProgress { bytes: 1 },
        });
        let effects = state.reduce(OwnerEvent::Request {
            key,
            event: RequestEvent::Deadline,
        });
        assert!(!effects.contains(&OwnerEffect::ReservationRolledBack(key)));
        assert_eq!(state.available_credits(), 2);
        assert_eq!(state.admitted_operations(), 1);
    }

    #[test]
    fn pending_and_late_final_apply_grants_before_terminal_bookkeeping() {
        let mut state = state();
        let key = admit(&mut state, 100, 2);
        state.reduce(OwnerEvent::Request {
            key,
            event: RequestEvent::WriteComplete,
        });
        state.reduce(OwnerEvent::Request {
            key,
            event: RequestEvent::Deadline,
        });
        let pending = state.reduce(OwnerEvent::Response {
            key,
            event: ResponseEvent::Pending { async_id: 7 },
            credit_grant: 1,
        });
        assert!(matches!(
            pending.as_slice(),
            [
                OwnerEffect::CreditGrantApplied { available: 3, .. },
                OwnerEffect::Request { .. }
            ]
        ));
        let final_response = state.reduce(OwnerEvent::Response {
            key,
            event: ResponseEvent::Final,
            credit_grant: 2,
        });
        assert!(matches!(
            final_response.as_slice(),
            [
                OwnerEffect::CreditGrantApplied { available: 5, .. },
                OwnerEffect::Request {
                    effect: ReduceEffect::BookkeepingOnly,
                    ..
                }
            ]
        ));
        assert_eq!(state.admitted_operations(), 0);
        assert_eq!(state.retained_payload_bytes(), 0);
        assert_eq!(
            state.terminal_outcome(key),
            Some(TerminalOutcome::OutcomeUnknown)
        );
    }

    #[test]
    fn duplicate_responses_never_double_grant_credits() {
        let mut state = state();
        let key = admit(&mut state, 0, 1);
        let event = OwnerEvent::Response {
            key,
            event: ResponseEvent::Final,
            credit_grant: 4,
        };
        state.reduce(event);
        assert_eq!(state.available_credits(), 7);
        assert_eq!(
            state.reduce(event),
            vec![OwnerEffect::DuplicateResponse(key)]
        );
        assert_eq!(state.available_credits(), 7);
    }

    #[test]
    fn early_response_proves_commitment_before_write_pump_completion_arrives() {
        let mut state = state();
        let key = admit(&mut state, 100, 2);
        state.reduce(OwnerEvent::Response {
            key,
            event: ResponseEvent::Pending { async_id: 9 },
            credit_grant: 1,
        });
        let effects = state.reduce(OwnerEvent::Request {
            key,
            event: RequestEvent::Cancel,
        });
        assert!(!effects.contains(&OwnerEffect::ReservationRolledBack(key)));
        assert_eq!(state.available_credits(), 3);
        assert_eq!(state.admitted_operations(), 1);
        assert_eq!(
            state.terminal_outcome(key),
            Some(TerminalOutcome::OutcomeUnknown)
        );
    }

    #[test]
    fn credit_overflow_is_typed_and_does_not_advance_response_state() {
        let mut state = GenerationState::new(GENERATION, 1, u32::MAX, LIMITS);
        let key = admit(&mut state, 0, 1);
        assert_eq!(
            state.reduce(OwnerEvent::Response {
                key,
                event: ResponseEvent::Final,
                credit_grant: 2,
            }),
            vec![OwnerEffect::CreditLedgerOverflow {
                key,
                available: u32::MAX - 1,
                grant: 2,
            }]
        );
        assert_eq!(
            state.request(key).map(RequestRecord::response),
            Some(ResponseProgress::None)
        );
        assert_eq!(state.admitted_operations(), 1);
    }

    #[test]
    fn foreign_and_unknown_responses_cannot_mutate_credit_pool() {
        let mut state = state();
        let foreign = RequestKey::new(GenerationId::new(4), 40);
        let unknown = RequestKey::new(GENERATION, 99);
        for key in [foreign, unknown] {
            state.reduce(OwnerEvent::Response {
                key,
                event: ResponseEvent::Final,
                credit_grant: u16::MAX,
            });
            assert_eq!(state.available_credits(), 4);
        }
    }

    #[test]
    fn disconnect_completes_open_callers_and_releases_admission() {
        let mut state = state();
        let first = admit(&mut state, 400, 1);
        let second = admit(&mut state, 500, 1);
        state.reduce(OwnerEvent::Response {
            key: first,
            event: ResponseEvent::Final,
            credit_grant: 1,
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
        assert_eq!(state.admitted_operations(), 0);
        assert_eq!(state.retained_payload_bytes(), 0);
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
