use super::reducer::{
    CallerOutcome, GenerationId, ReduceEffect, RequestEvent, RequestKey, RequestRecord,
    ResponseProgress, TerminalOutcome,
};
use crate::clock::MonotonicTime;
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::time::Duration;

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
    pub(crate) credit_request: u16,
    pub(crate) caller_deadline: Option<MonotonicTime>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResponseEvent {
    Pending { async_id: u64 },
    Final,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RequestProgress {
    Queued,
    WriteProgress { bytes: usize },
    WriteComplete,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum DeadlineKind {
    Caller,
    Tombstone,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct DeadlineEntry {
    at: MonotonicTime,
    sequence: u64,
    key: RequestKey,
    kind: DeadlineKind,
    version: u64,
}

/// Typed input lane for the sole state owner of one connection generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OwnerEvent {
    Admit {
        payload_bytes: u64,
        credit_charge: u16,
        caller_deadline: Option<MonotonicTime>,
    },
    Request {
        key: RequestKey,
        event: RequestProgress,
    },
    PrepareFailed {
        key: RequestKey,
    },
    Cancel {
        key: RequestKey,
        now: MonotonicTime,
    },
    Response {
        key: RequestKey,
        event: ResponseEvent,
        credit_grant: u16,
    },
    AdvanceTime {
        now: MonotonicTime,
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
    CancelControlQueued(RequestKey),
    DuplicateCancel(RequestKey),
    BestEffortWireCancel(RequestKey),
    StaleDeadlineIgnored(RequestKey),
    GenerationUnhealthy {
        key: RequestKey,
    },
    AsyncIdConflict {
        async_id: u64,
        existing: RequestKey,
        incoming: RequestKey,
    },
    AsyncIdChanged {
        key: RequestKey,
        existing: u64,
        incoming: u64,
    },
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
    requested_extra_credits: u32,
    credit_response_seen: bool,
    admission_held: bool,
    payload_held: bool,
    credit_obligation: bool,
    cancel_seen: bool,
    deadline_version: u64,
}

/// All mutable request authority for exactly one physical generation.
pub(crate) struct GenerationState {
    generation: GenerationId,
    limits: AdmissionLimits,
    next_message_id: Option<u64>,
    available_credits: u32,
    total_credits: u32,
    pending_extra_credits: u32,
    target_credits: u32,
    admitted_operations: usize,
    retained_payload_bytes: u64,
    requests: HashMap<RequestKey, OwnedRequest>,
    async_index: HashMap<u64, RequestKey>,
    deadlines: BinaryHeap<Reverse<DeadlineEntry>>,
    next_deadline_sequence: u64,
    tombstone_drain_timeout: Duration,
    unhealthy: bool,
}

impl GenerationState {
    pub(crate) const fn generation(&self) -> GenerationId {
        self.generation
    }

    pub(crate) const fn operation_limit(&self) -> usize {
        self.limits.max_operations
    }

    pub(crate) fn set_target_credits(&mut self, target: u32) {
        self.target_credits = target.max(1);
    }

    pub(crate) fn new(
        generation: GenerationId,
        initial_message_id: u64,
        initial_credits: u32,
        target_credits: u32,
        limits: AdmissionLimits,
        tombstone_drain_timeout: Duration,
    ) -> Self {
        Self {
            generation,
            limits,
            next_message_id: Some(initial_message_id),
            available_credits: initial_credits,
            total_credits: initial_credits,
            pending_extra_credits: 0,
            target_credits,
            admitted_operations: 0,
            retained_payload_bytes: 0,
            requests: HashMap::new(),
            async_index: HashMap::new(),
            deadlines: BinaryHeap::new(),
            next_deadline_sequence: 0,
            tombstone_drain_timeout,
            unhealthy: false,
        }
    }

    pub(crate) fn reduce(&mut self, event: OwnerEvent) -> Vec<OwnerEffect> {
        match event {
            OwnerEvent::Admit {
                payload_bytes,
                credit_charge,
                caller_deadline,
            } => vec![self.admit(payload_bytes, credit_charge, caller_deadline)],
            OwnerEvent::Request { key, event } => self.request_event(key, event),
            OwnerEvent::PrepareFailed { key } => self.prepare_failed(key),
            OwnerEvent::Cancel { key, now } => self.cancel(key, now),
            OwnerEvent::Response {
                key,
                event,
                credit_grant,
            } => self.response(key, event, credit_grant),
            OwnerEvent::AdvanceTime { now } => self.advance_time(now),
            OwnerEvent::Disconnect => self.disconnect(),
        }
    }

    fn admit(
        &mut self,
        payload_bytes: u64,
        credit_charge: u16,
        caller_deadline: Option<MonotonicTime>,
    ) -> OwnerEffect {
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
        self.next_message_id = message_id.checked_add(u64::from(credit_charge));
        let projected_total = self
            .total_credits
            .saturating_add(self.pending_extra_credits);
        let requested_extra_credits = self.target_credits.saturating_sub(projected_total);
        let credit_request = u32::from(credit_charge)
            .saturating_add(requested_extra_credits)
            .min(u32::from(u16::MAX)) as u16;
        let requested_extra_credits = u32::from(credit_request) - u32::from(credit_charge);
        let key = RequestKey::new(self.generation, message_id);
        let plan = PreparationPlan {
            key,
            payload_bytes,
            credit_charge,
            credit_request,
            caller_deadline,
        };
        self.available_credits -= u32::from(credit_charge);
        self.pending_extra_credits = self
            .pending_extra_credits
            .saturating_add(requested_extra_credits);
        self.admitted_operations += 1;
        self.retained_payload_bytes += payload_bytes;
        self.requests.insert(
            key,
            OwnedRequest {
                lifecycle: RequestRecord::new(key),
                payload_bytes,
                credit_charge,
                requested_extra_credits,
                credit_response_seen: false,
                admission_held: true,
                payload_held: true,
                credit_obligation: true,
                cancel_seen: false,
                deadline_version: 0,
            },
        );
        if let Some(deadline) = caller_deadline {
            let _ = self.schedule_deadline(key, deadline, DeadlineKind::Caller);
        }
        OwnerEffect::Admitted(plan)
    }

    fn request_event(&mut self, key: RequestKey, event: RequestProgress) -> Vec<OwnerEffect> {
        if key.generation != self.generation {
            return vec![OwnerEffect::Request {
                key,
                effect: ReduceEffect::IgnoredForeignGeneration,
            }];
        }
        let Some(request) = self.requests.get_mut(&key) else {
            return vec![OwnerEffect::UnknownRequest(key)];
        };
        let lifecycle_event = match event {
            RequestProgress::Queued => RequestEvent::Queued,
            RequestProgress::WriteProgress { bytes } => RequestEvent::WriteProgress { bytes },
            RequestProgress::WriteComplete => RequestEvent::WriteComplete,
        };
        let effect = request.lifecycle.reduce(lifecycle_event);
        let write_completed = matches!(event, RequestProgress::WriteComplete);
        let effects = vec![OwnerEffect::Request { key, effect }];
        if write_completed {
            self.release_payload(key);
        }
        effects
    }

    fn cancel(&mut self, key: RequestKey, now: MonotonicTime) -> Vec<OwnerEffect> {
        if key.generation != self.generation {
            return vec![OwnerEffect::Request {
                key,
                effect: ReduceEffect::IgnoredForeignGeneration,
            }];
        }
        let Some(request) = self.requests.get_mut(&key) else {
            return vec![OwnerEffect::UnknownRequest(key)];
        };
        if request.cancel_seen {
            return vec![OwnerEffect::DuplicateCancel(key)];
        }
        if !request.lifecycle.caller_is_open() {
            request.cancel_seen = true;
            return vec![OwnerEffect::DuplicateCancel(key)];
        }
        request.cancel_seen = true;
        let committed = request.lifecycle.wire_committed();
        let effect = request.lifecycle.reduce(RequestEvent::Cancel);
        let mut effects = vec![
            OwnerEffect::CancelControlQueued(key),
            OwnerEffect::Request { key, effect },
        ];
        if committed {
            effects.push(OwnerEffect::BestEffortWireCancel(key));
            if !self.schedule_deadline(
                key,
                now.saturating_add(self.tombstone_drain_timeout),
                DeadlineKind::Tombstone,
            ) {
                effects.push(OwnerEffect::GenerationUnhealthy { key });
            }
        } else if self.rollback(key) {
            effects.push(OwnerEffect::ReservationRolledBack(key));
        }
        effects
    }

    fn schedule_deadline(
        &mut self,
        key: RequestKey,
        at: MonotonicTime,
        kind: DeadlineKind,
    ) -> bool {
        let Some(request) = self.requests.get_mut(&key) else {
            return false;
        };
        let Some(version) = request.deadline_version.checked_add(1) else {
            self.unhealthy = true;
            return false;
        };
        request.deadline_version = version;
        let sequence = self.next_deadline_sequence;
        self.next_deadline_sequence = self.next_deadline_sequence.saturating_add(1);
        self.deadlines.push(Reverse(DeadlineEntry {
            at,
            sequence,
            key,
            kind,
            version,
        }));
        true
    }

    fn advance_time(&mut self, now: MonotonicTime) -> Vec<OwnerEffect> {
        let mut effects = Vec::new();
        while self.deadlines.peek().is_some_and(|entry| entry.0.at <= now) {
            let Some(Reverse(entry)) = self.deadlines.pop() else {
                break;
            };
            let Some(request) = self.requests.get_mut(&entry.key) else {
                effects.push(OwnerEffect::StaleDeadlineIgnored(entry.key));
                continue;
            };
            if request.deadline_version != entry.version {
                effects.push(OwnerEffect::StaleDeadlineIgnored(entry.key));
                continue;
            }
            match entry.kind {
                DeadlineKind::Caller => {
                    if !request.lifecycle.caller_is_open() {
                        effects.push(OwnerEffect::StaleDeadlineIgnored(entry.key));
                        continue;
                    }
                    let committed = request.lifecycle.wire_committed();
                    let effect = request.lifecycle.reduce(RequestEvent::Deadline);
                    effects.push(OwnerEffect::Request {
                        key: entry.key,
                        effect,
                    });
                    if committed {
                        effects.push(OwnerEffect::BestEffortWireCancel(entry.key));
                        if !self.schedule_deadline(
                            entry.key,
                            now.saturating_add(self.tombstone_drain_timeout),
                            DeadlineKind::Tombstone,
                        ) {
                            effects.push(OwnerEffect::GenerationUnhealthy { key: entry.key });
                        }
                    } else if self.rollback(entry.key) {
                        effects.push(OwnerEffect::ReservationRolledBack(entry.key));
                    }
                }
                DeadlineKind::Tombstone => {
                    if request.lifecycle.is_tombstone()
                        && request.lifecycle.response() != ResponseProgress::Final
                    {
                        self.unhealthy = true;
                        effects.push(OwnerEffect::GenerationUnhealthy { key: entry.key });
                    } else {
                        effects.push(OwnerEffect::StaleDeadlineIgnored(entry.key));
                    }
                }
            }
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
        if let ResponseEvent::Pending { async_id } = event
            && let Some(existing) = self.async_index.get(&async_id).copied()
            && existing != key
        {
            self.unhealthy = true;
            return vec![
                OwnerEffect::AsyncIdConflict {
                    async_id,
                    existing,
                    incoming: key,
                },
                OwnerEffect::GenerationUnhealthy { key },
            ];
        }
        let Some(request) = self.requests.get_mut(&key) else {
            return vec![OwnerEffect::UnknownRequest(key)];
        };
        if let ResponseEvent::Pending { async_id } = event
            && let ResponseProgress::AsyncPending { async_id: existing } =
                request.lifecycle.response()
            && existing != async_id
        {
            self.unhealthy = true;
            return vec![
                OwnerEffect::AsyncIdChanged {
                    key,
                    existing,
                    incoming: async_id,
                },
                OwnerEffect::GenerationUnhealthy { key },
            ];
        }
        let duplicate = match event {
            ResponseEvent::Pending { .. } => {
                request.lifecycle.response() == ResponseProgress::Final
            }
            ResponseEvent::Final => request.lifecycle.response() == ResponseProgress::Final,
        };
        if duplicate {
            return vec![OwnerEffect::DuplicateResponse(key)];
        }
        let previous_response = request.lifecycle.response();

        if !request.credit_response_seen {
            self.pending_extra_credits = self
                .pending_extra_credits
                .saturating_sub(request.requested_extra_credits);
            self.total_credits = self
                .total_credits
                .saturating_sub(u32::from(request.credit_charge))
                .saturating_add(u32::from(credit_grant));
            request.credit_response_seen = true;
        } else {
            self.total_credits = self.total_credits.saturating_add(u32::from(credit_grant));
        }

        // Protocol bookkeeping deliberately precedes caller completion.
        request.lifecycle.observe_response_commitment();
        if request.payload_held {
            self.retained_payload_bytes -= request.payload_bytes;
            request.payload_held = false;
        }
        let Some(available) = self.available_credits.checked_add(u32::from(credit_grant)) else {
            self.unhealthy = true;
            return vec![
                OwnerEffect::CreditLedgerOverflow {
                    key,
                    available: self.available_credits,
                    grant: credit_grant,
                },
                OwnerEffect::GenerationUnhealthy { key },
            ];
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
        match event {
            ResponseEvent::Pending { async_id } => {
                self.async_index.insert(async_id, key);
            }
            ResponseEvent::Final => {
                if let ResponseProgress::AsyncPending { async_id } = previous_response {
                    self.async_index.remove(&async_id);
                }
                request.credit_obligation = false;
                if let Some(version) = request.deadline_version.checked_add(1) {
                    request.deadline_version = version;
                } else {
                    self.unhealthy = true;
                    effects.push(OwnerEffect::GenerationUnhealthy { key });
                }
                self.release_request_ownership(key);
            }
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
            self.pending_extra_credits = self
                .pending_extra_credits
                .saturating_sub(request.requested_extra_credits);
            request.credit_obligation = false;
        }
        self.release_request_ownership(key);
        true
    }

    fn release_payload(&mut self, key: RequestKey) {
        let Some(request) = self.requests.get_mut(&key) else {
            return;
        };
        if request.payload_held {
            self.retained_payload_bytes -= request.payload_bytes;
            request.payload_held = false;
        }
    }

    fn release_request_ownership(&mut self, key: RequestKey) {
        self.release_payload(key);
        let Some(request) = self.requests.get_mut(&key) else {
            return;
        };
        if request.admission_held {
            self.admitted_operations -= 1;
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
            self.release_request_ownership(key);
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

    pub(crate) fn request_for_async_id(&self, async_id: u64) -> Option<RequestKey> {
        self.async_index.get(&async_id).copied()
    }

    pub(crate) fn next_deadline(&self) -> Option<MonotonicTime> {
        self.deadlines.peek().map(|entry| entry.0.at)
    }

    pub(crate) const fn is_unhealthy(&self) -> bool {
        self.unhealthy
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
    const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

    fn state() -> GenerationState {
        GenerationState::new(GENERATION, 40, 4, 4, LIMITS, DRAIN_TIMEOUT)
    }

    fn admit(state: &mut GenerationState, payload_bytes: u64, charge: u16) -> RequestKey {
        admit_with_deadline(state, payload_bytes, charge, None)
    }

    fn admit_with_deadline(
        state: &mut GenerationState,
        payload_bytes: u64,
        charge: u16,
        caller_deadline: Option<MonotonicTime>,
    ) -> RequestKey {
        match state.reduce(OwnerEvent::Admit {
            payload_bytes,
            credit_charge: charge,
            caller_deadline,
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
    fn multi_credit_admission_consumes_the_full_message_id_sequence_window() {
        let mut state = GenerationState::new(GENERATION, 40, 32, 32, LIMITS, DRAIN_TIMEOUT);
        let first = admit(&mut state, 0, 16);
        let second = admit(&mut state, 0, 1);
        assert_eq!(first.message_id, 40);
        assert_eq!(second.message_id, 56);
    }

    #[test]
    fn owner_requests_target_credit_window_once_while_grant_is_pending() {
        let mut state = GenerationState::new(GENERATION, 0, 4, 128, LIMITS, DRAIN_TIMEOUT);
        let first = state.reduce(OwnerEvent::Admit {
            payload_bytes: 0,
            credit_charge: 2,
            caller_deadline: None,
        });
        let second = state.reduce(OwnerEvent::Admit {
            payload_bytes: 0,
            credit_charge: 1,
            caller_deadline: None,
        });
        assert!(matches!(
            first.as_slice(),
            [OwnerEffect::Admitted(PreparationPlan {
                credit_charge: 2,
                credit_request: 126,
                ..
            })]
        ));
        assert!(matches!(
            second.as_slice(),
            [OwnerEffect::Admitted(PreparationPlan {
                credit_charge: 1,
                credit_request: 1,
                ..
            })]
        ));
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
                    caller_deadline: None,
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
            3,
            AdmissionLimits {
                max_operations: 1,
                max_payload_bytes: 10,
            },
            DRAIN_TIMEOUT,
        );
        let first = admit(&mut state, 1, 1);
        assert_eq!(
            state.reduce(OwnerEvent::Admit {
                payload_bytes: 1,
                credit_charge: 1,
                caller_deadline: None,
            }),
            vec![OwnerEffect::AdmissionRejected(
                AdmissionError::OperationsExhausted
            )]
        );
        state.reduce(OwnerEvent::Cancel {
            key: first,
            now: MonotonicTime::ZERO,
        });
        assert_eq!(admit(&mut state, 1, 1).message_id, 10);
    }

    #[test]
    fn message_id_max_is_allocated_once_and_never_wraps() {
        let mut state = GenerationState::new(GENERATION, u64::MAX, 2, 2, LIMITS, DRAIN_TIMEOUT);
        let key = admit(&mut state, 0, 1);
        assert_eq!(key.message_id, u64::MAX);
        state.reduce(OwnerEvent::Cancel {
            key,
            now: MonotonicTime::ZERO,
        });
        assert_eq!(
            state.reduce(OwnerEvent::Admit {
                payload_bytes: 0,
                credit_charge: 1,
                caller_deadline: None,
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
            64,
            AdmissionLimits {
                max_operations: 64,
                max_payload_bytes: 64,
            },
            DRAIN_TIMEOUT,
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
            OwnerEvent::Cancel {
                key: RequestKey::new(GENERATION, 40),
                now: MonotonicTime::ZERO,
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
            event: RequestProgress::WriteProgress { bytes: 1 },
        });
        let effects = state.reduce(OwnerEvent::Cancel {
            key,
            now: MonotonicTime::ZERO,
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
            event: RequestProgress::WriteComplete,
        });
        state.reduce(OwnerEvent::Cancel {
            key,
            now: MonotonicTime::ZERO,
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
        let effects = state.reduce(OwnerEvent::Cancel {
            key,
            now: MonotonicTime::ZERO,
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
        let mut state =
            GenerationState::new(GENERATION, 1, u32::MAX, u32::MAX, LIMITS, DRAIN_TIMEOUT);
        let key = admit(&mut state, 0, 1);
        assert_eq!(
            state.reduce(OwnerEvent::Response {
                key,
                event: ResponseEvent::Final,
                credit_grant: 2,
            }),
            vec![
                OwnerEffect::CreditLedgerOverflow {
                    key,
                    available: u32::MAX - 1,
                    grant: 2,
                },
                OwnerEffect::GenerationUnhealthy { key },
            ]
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
    fn async_id_index_is_unique_stable_and_removed_by_final_response() {
        let mut state = state();
        let first = admit(&mut state, 10, 1);
        let second = admit(&mut state, 10, 1);
        state.reduce(OwnerEvent::Response {
            key: first,
            event: ResponseEvent::Pending { async_id: 70 },
            credit_grant: 1,
        });
        assert_eq!(state.request_for_async_id(70), Some(first));
        assert_eq!(
            state.reduce(OwnerEvent::Response {
                key: second,
                event: ResponseEvent::Pending { async_id: 70 },
                credit_grant: 1,
            }),
            vec![
                OwnerEffect::AsyncIdConflict {
                    async_id: 70,
                    existing: first,
                    incoming: second,
                },
                OwnerEffect::GenerationUnhealthy { key: second },
            ]
        );
        assert_eq!(
            state.reduce(OwnerEvent::Response {
                key: first,
                event: ResponseEvent::Pending { async_id: 71 },
                credit_grant: 1,
            }),
            vec![
                OwnerEffect::AsyncIdChanged {
                    key: first,
                    existing: 70,
                    incoming: 71,
                },
                OwnerEffect::GenerationUnhealthy { key: first },
            ]
        );
        state.reduce(OwnerEvent::Response {
            key: first,
            event: ResponseEvent::Final,
            credit_grant: 1,
        });
        assert_eq!(state.request_for_async_id(70), None);
    }

    #[test]
    fn repeated_pending_responses_keep_one_index_but_apply_each_credit_grant() {
        let mut state = state();
        let key = admit(&mut state, 0, 2);
        for expected in [3, 4] {
            let effects = state.reduce(OwnerEvent::Response {
                key,
                event: ResponseEvent::Pending { async_id: 70 },
                credit_grant: 1,
            });
            assert!(matches!(
                effects.first(),
                Some(OwnerEffect::CreditGrantApplied { available, .. }) if *available == expected
            ));
            assert_eq!(state.request_for_async_id(70), Some(key));
        }
    }

    #[test]
    fn owner_deadline_heap_rolls_back_uncommitted_request_once() {
        let mut state = state();
        let deadline = MonotonicTime::ZERO.saturating_add(Duration::from_millis(10));
        let key = admit_with_deadline(&mut state, 200, 2, Some(deadline));
        assert_eq!(state.next_deadline(), Some(deadline));
        assert!(
            state
                .reduce(OwnerEvent::AdvanceTime {
                    now: MonotonicTime::ZERO.saturating_add(Duration::from_millis(9)),
                })
                .is_empty()
        );
        let effects = state.reduce(OwnerEvent::AdvanceTime { now: deadline });
        assert!(effects.contains(&OwnerEffect::Request {
            key,
            effect: ReduceEffect::Publish(TerminalOutcome::TimedOut),
        }));
        assert!(effects.contains(&OwnerEffect::ReservationRolledBack(key)));
        assert_eq!(state.available_credits(), 4);
        assert_eq!(state.retained_payload_bytes(), 0);
    }

    #[test]
    fn committed_deadline_creates_payload_free_tombstone_and_drain_expiry_is_fatal() {
        let mut state = state();
        let deadline = MonotonicTime::ZERO.saturating_add(Duration::from_millis(10));
        let key = admit_with_deadline(&mut state, 200, 2, Some(deadline));
        state.reduce(OwnerEvent::Request {
            key,
            event: RequestProgress::WriteComplete,
        });
        let effects = state.reduce(OwnerEvent::AdvanceTime { now: deadline });
        assert!(effects.contains(&OwnerEffect::BestEffortWireCancel(key)));
        assert_eq!(state.retained_payload_bytes(), 0);
        assert!(state.request(key).is_some_and(RequestRecord::is_tombstone));
        let drain = deadline.saturating_add(DRAIN_TIMEOUT);
        assert_eq!(state.next_deadline(), Some(drain));
        let effects = state.reduce(OwnerEvent::AdvanceTime { now: drain });
        assert_eq!(effects, vec![OwnerEffect::GenerationUnhealthy { key }]);
        assert!(state.is_unhealthy());
    }

    #[test]
    fn late_final_settles_tombstone_and_makes_drain_entry_stale() {
        let mut state = state();
        let deadline = MonotonicTime::ZERO.saturating_add(Duration::from_millis(10));
        let key = admit_with_deadline(&mut state, 10, 1, Some(deadline));
        state.reduce(OwnerEvent::Request {
            key,
            event: RequestProgress::WriteComplete,
        });
        state.reduce(OwnerEvent::AdvanceTime { now: deadline });
        state.reduce(OwnerEvent::Response {
            key,
            event: ResponseEvent::Final,
            credit_grant: 1,
        });
        let effects = state.reduce(OwnerEvent::AdvanceTime {
            now: deadline.saturating_add(DRAIN_TIMEOUT),
        });
        assert_eq!(effects, vec![OwnerEffect::StaleDeadlineIgnored(key)]);
        assert!(!state.is_unhealthy());
        assert!(!state.request(key).is_some_and(RequestRecord::is_tombstone));
    }

    #[test]
    fn cancel_control_is_deduplicated_and_committed_cancel_gets_one_wire_obligation() {
        let mut state = state();
        let key = admit(&mut state, 10, 1);
        state.reduce(OwnerEvent::Request {
            key,
            event: RequestProgress::WriteProgress { bytes: 1 },
        });
        let first = state.reduce(OwnerEvent::Cancel {
            key,
            now: MonotonicTime::ZERO,
        });
        assert_eq!(
            first
                .iter()
                .filter(|effect| **effect == OwnerEffect::BestEffortWireCancel(key))
                .count(),
            1
        );
        assert_eq!(
            state.reduce(OwnerEvent::Cancel {
                key,
                now: MonotonicTime::ZERO,
            }),
            vec![OwnerEffect::DuplicateCancel(key)]
        );
    }

    #[test]
    fn pending_response_releases_outbound_payload_before_tombstone() {
        let mut state = state();
        let key = admit(&mut state, 512, 1);
        state.reduce(OwnerEvent::Response {
            key,
            event: ResponseEvent::Pending { async_id: 8 },
            credit_grant: 1,
        });
        assert_eq!(state.retained_payload_bytes(), 0);
        state.reduce(OwnerEvent::Cancel {
            key,
            now: MonotonicTime::ZERO,
        });
        assert!(state.request(key).is_some_and(RequestRecord::is_tombstone));
        assert_eq!(state.retained_payload_bytes(), 0);
    }

    #[test]
    fn response_cancel_and_deadline_orders_publish_once_and_settle_final_once() {
        #[derive(Clone, Copy)]
        enum RaceEvent {
            Final,
            Cancel,
            Deadline,
        }
        let orders = [
            [RaceEvent::Final, RaceEvent::Cancel, RaceEvent::Deadline],
            [RaceEvent::Final, RaceEvent::Deadline, RaceEvent::Cancel],
            [RaceEvent::Cancel, RaceEvent::Final, RaceEvent::Deadline],
            [RaceEvent::Cancel, RaceEvent::Deadline, RaceEvent::Final],
            [RaceEvent::Deadline, RaceEvent::Final, RaceEvent::Cancel],
            [RaceEvent::Deadline, RaceEvent::Cancel, RaceEvent::Final],
        ];
        for order in orders {
            let mut state = state();
            let key = admit_with_deadline(&mut state, 0, 1, Some(MonotonicTime::ZERO));
            state.reduce(OwnerEvent::Request {
                key,
                event: RequestProgress::WriteComplete,
            });
            let mut effects = Vec::new();
            for event in order {
                effects.extend(match event {
                    RaceEvent::Final => state.reduce(OwnerEvent::Response {
                        key,
                        event: ResponseEvent::Final,
                        credit_grant: 1,
                    }),
                    RaceEvent::Cancel => state.reduce(OwnerEvent::Cancel {
                        key,
                        now: MonotonicTime::ZERO,
                    }),
                    RaceEvent::Deadline => state.reduce(OwnerEvent::AdvanceTime {
                        now: MonotonicTime::ZERO,
                    }),
                });
            }
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
            assert_eq!(
                effects
                    .iter()
                    .filter(|effect| matches!(effect, OwnerEffect::CreditGrantApplied { .. }))
                    .count(),
                1
            );
            assert_eq!(state.admitted_operations(), 0);
            assert!(!state.request(key).is_some_and(RequestRecord::is_tombstone));
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
