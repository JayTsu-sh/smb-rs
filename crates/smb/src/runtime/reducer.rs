use std::fmt;

/// Identity of one physical connection generation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct GenerationId(u64);

impl GenerationId {
    pub(crate) const fn new(value: u64) -> Self {
        Self(value)
    }
}

/// Request identity is never meaningful without its generation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct RequestKey {
    pub(crate) generation: GenerationId,
    pub(crate) message_id: u64,
}

impl RequestKey {
    pub(crate) const fn new(generation: GenerationId, message_id: u64) -> Self {
        Self {
            generation,
            message_id,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SendProgress {
    NotQueued,
    Queued,
    Partial { bytes: usize },
    Complete,
}

impl SendProgress {
    const fn committed(self) -> bool {
        matches!(self, Self::Partial { .. } | Self::Complete)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResponseProgress {
    None,
    AsyncPending { async_id: u64 },
    Final,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TerminalOutcome {
    Response,
    Cancelled,
    TimedOut,
    OutcomeUnknown,
    GenerationLost,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CallerOutcome {
    Open,
    Terminal(TerminalOutcome),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RequestEvent {
    Queued,
    WriteProgress { bytes: usize },
    WriteComplete,
    AsyncPending { key: RequestKey, async_id: u64 },
    FinalResponse { key: RequestKey },
    Cancel,
    Deadline,
    Disconnect,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReduceEffect {
    None,
    Publish(TerminalOutcome),
    BookkeepingOnly,
    IgnoredForeignGeneration,
}

/// Orthogonal request facts owned and mutated only by the generation reducer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RequestRecord {
    key: RequestKey,
    caller: CallerOutcome,
    send: SendProgress,
    response: ResponseProgress,
    tombstone: bool,
}

impl RequestRecord {
    pub(crate) const fn new(key: RequestKey) -> Self {
        Self {
            key,
            caller: CallerOutcome::Open,
            send: SendProgress::NotQueued,
            response: ResponseProgress::None,
            tombstone: false,
        }
    }

    pub(crate) const fn key(&self) -> RequestKey {
        self.key
    }

    pub(crate) const fn caller(&self) -> CallerOutcome {
        self.caller
    }

    pub(crate) const fn send(&self) -> SendProgress {
        self.send
    }

    pub(crate) const fn response(&self) -> ResponseProgress {
        self.response
    }

    pub(crate) const fn is_tombstone(&self) -> bool {
        self.tombstone
    }

    pub(crate) fn reduce(&mut self, event: RequestEvent) -> ReduceEffect {
        match event {
            RequestEvent::Queued => {
                if self.send == SendProgress::NotQueued {
                    self.send = SendProgress::Queued;
                }
                ReduceEffect::None
            }
            RequestEvent::WriteProgress { bytes } => {
                if bytes > 0 && !matches!(self.send, SendProgress::Complete) {
                    let previous = match self.send {
                        SendProgress::Partial { bytes } => bytes,
                        _ => 0,
                    };
                    self.send = SendProgress::Partial {
                        bytes: previous.saturating_add(bytes),
                    };
                }
                ReduceEffect::None
            }
            RequestEvent::WriteComplete => {
                self.send = SendProgress::Complete;
                ReduceEffect::None
            }
            RequestEvent::AsyncPending { key, async_id } => {
                if key.generation != self.key.generation {
                    return ReduceEffect::IgnoredForeignGeneration;
                }
                if key != self.key || self.response == ResponseProgress::Final {
                    return ReduceEffect::BookkeepingOnly;
                }
                self.response = ResponseProgress::AsyncPending { async_id };
                ReduceEffect::BookkeepingOnly
            }
            RequestEvent::FinalResponse { key } => {
                if key.generation != self.key.generation {
                    return ReduceEffect::IgnoredForeignGeneration;
                }
                if key != self.key {
                    return ReduceEffect::BookkeepingOnly;
                }
                self.response = ResponseProgress::Final;
                self.tombstone = false;
                self.publish_once(TerminalOutcome::Response)
            }
            RequestEvent::Cancel => self.finish_without_response(TerminalOutcome::Cancelled),
            RequestEvent::Deadline => self.finish_without_response(TerminalOutcome::TimedOut),
            RequestEvent::Disconnect => {
                self.tombstone = false;
                self.publish_once(TerminalOutcome::GenerationLost)
            }
        }
    }

    fn finish_without_response(&mut self, uncommitted: TerminalOutcome) -> ReduceEffect {
        let outcome = if self.send.committed() {
            self.tombstone = self.response != ResponseProgress::Final;
            TerminalOutcome::OutcomeUnknown
        } else {
            uncommitted
        };
        self.publish_once(outcome)
    }

    fn publish_once(&mut self, outcome: TerminalOutcome) -> ReduceEffect {
        if self.caller != CallerOutcome::Open {
            return ReduceEffect::BookkeepingOnly;
        }
        self.caller = CallerOutcome::Terminal(outcome);
        ReduceEffect::Publish(outcome)
    }
}

impl fmt::Display for RequestKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "generation {:?}, message {}",
            self.generation, self.message_id
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GENERATION: GenerationId = GenerationId::new(7);
    const KEY: RequestKey = RequestKey::new(GENERATION, 41);

    #[test]
    fn response_cancel_deadline_and_disconnect_publish_at_most_once_in_every_order() {
        let terminals = [
            RequestEvent::FinalResponse { key: KEY },
            RequestEvent::Cancel,
            RequestEvent::Deadline,
            RequestEvent::Disconnect,
        ];
        for ordering in permutations(&terminals) {
            let mut request = RequestRecord::new(KEY);
            request.reduce(RequestEvent::Queued);
            request.reduce(RequestEvent::WriteComplete);
            let effects = ordering
                .into_iter()
                .map(|event| request.reduce(event))
                .collect::<Vec<_>>();
            assert_eq!(
                effects
                    .iter()
                    .filter(|effect| matches!(effect, ReduceEffect::Publish(_)))
                    .count(),
                1,
                "ordering: {ordering:?}"
            );
            assert_eq!(request.response(), ResponseProgress::Final);
            assert!(!request.is_tombstone());
        }
    }

    #[test]
    fn cancellation_before_commit_is_known_and_needs_no_tombstone() {
        let mut request = RequestRecord::new(KEY);
        assert_eq!(
            request.reduce(RequestEvent::Cancel),
            ReduceEffect::Publish(TerminalOutcome::Cancelled)
        );
        assert!(!request.is_tombstone());
    }

    #[test]
    fn deadline_after_first_byte_is_unknown_until_late_response_settles_wire() {
        let mut request = RequestRecord::new(KEY);
        request.reduce(RequestEvent::WriteProgress { bytes: 1 });
        assert_eq!(
            request.reduce(RequestEvent::Deadline),
            ReduceEffect::Publish(TerminalOutcome::OutcomeUnknown)
        );
        assert!(request.is_tombstone());
        assert_eq!(
            request.reduce(RequestEvent::FinalResponse { key: KEY }),
            ReduceEffect::BookkeepingOnly
        );
        assert!(!request.is_tombstone());
        assert_eq!(
            request.caller(),
            CallerOutcome::Terminal(TerminalOutcome::OutcomeUnknown)
        );
    }

    #[test]
    fn duplicate_terminal_events_are_bookkeeping_only() {
        let mut request = RequestRecord::new(KEY);
        assert_eq!(
            request.reduce(RequestEvent::FinalResponse { key: KEY }),
            ReduceEffect::Publish(TerminalOutcome::Response)
        );
        assert_eq!(
            request.reduce(RequestEvent::FinalResponse { key: KEY }),
            ReduceEffect::BookkeepingOnly
        );
        assert_eq!(
            request.reduce(RequestEvent::Cancel),
            ReduceEffect::BookkeepingOnly
        );
    }

    #[test]
    fn async_pending_is_scoped_to_exact_request_and_generation() {
        let mut request = RequestRecord::new(KEY);
        let foreign = RequestKey::new(GenerationId::new(8), KEY.message_id);
        assert_eq!(
            request.reduce(RequestEvent::AsyncPending {
                key: foreign,
                async_id: 99,
            }),
            ReduceEffect::IgnoredForeignGeneration
        );
        assert_eq!(request.response(), ResponseProgress::None);

        let unknown = RequestKey::new(GENERATION, KEY.message_id + 1);
        assert_eq!(
            request.reduce(RequestEvent::AsyncPending {
                key: unknown,
                async_id: 99,
            }),
            ReduceEffect::BookkeepingOnly
        );
        assert_eq!(request.response(), ResponseProgress::None);

        request.reduce(RequestEvent::AsyncPending {
            key: KEY,
            async_id: 99,
        });
        assert_eq!(
            request.response(),
            ResponseProgress::AsyncPending { async_id: 99 }
        );
    }

    #[test]
    fn write_progress_saturates_and_complete_is_monotonic() {
        let mut request = RequestRecord::new(KEY);
        request.reduce(RequestEvent::WriteProgress { bytes: usize::MAX });
        request.reduce(RequestEvent::WriteProgress { bytes: 1 });
        assert_eq!(request.send(), SendProgress::Partial { bytes: usize::MAX });
        request.reduce(RequestEvent::WriteComplete);
        request.reduce(RequestEvent::WriteProgress { bytes: 1 });
        assert_eq!(request.send(), SendProgress::Complete);
    }

    fn permutations<T: Copy, const N: usize>(items: &[T; N]) -> Vec<[T; N]> {
        fn visit<T: Copy, const N: usize>(
            items: &mut [T; N],
            index: usize,
            output: &mut Vec<[T; N]>,
        ) {
            if index == N {
                output.push(*items);
                return;
            }
            for candidate in index..N {
                items.swap(index, candidate);
                visit(items, index + 1, output);
                items.swap(index, candidate);
            }
        }

        let mut items = *items;
        let mut output = Vec::new();
        visit(&mut items, 0, &mut output);
        output
    }
}
