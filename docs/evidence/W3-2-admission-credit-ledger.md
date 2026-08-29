# W3-2 admission, identity, and credit ledger

## Scope

- Ticket: #46
- Wave: W3 — Replace the single-generation request runtime
- Depends on: W3-1 evidence `4f7a2a7`
- Tested implementation: `7bf9f2f`
- Validation date: 2026-08-29

This ticket makes `GenerationState` the sole destination for operation
admission, request identity allocation, and SMB credit bookkeeping. Admission
atomically reserves the operation slot, retained payload bytes, credit charge,
generation-tagged MessageId, and request record before emitting an immutable
`PreparationPlan`. A rejected admission changes none of those facts.

## Invariants and tests

- Operation count and retained payload bytes have explicit hard limits and
  typed rejection outcomes.
- Credit charge must be non-zero and available before admission commits.
- MessageIds are generation-scoped, unique, monotonic, and checked; `u64::MAX`
  can be allocated once and the next admission returns typed exhaustion.
- Zero-byte cancellation, deadline, and preparation failure release admission
  and restore reserved credits exactly once.
- After any positive write progress, credits are never restored locally.
- A validated response itself proves wire commitment when it races ahead of
  the write-pump completion event.
- Pending and final responses apply a validated credit grant before caller
  completion or late-response bookkeeping.
- Duplicate, unknown, and foreign-generation responses cannot grant credits.
- Credit representation overflow is a typed owner effect and does not advance
  response state.
- Disconnect completes only open callers and releases all admission ownership.

The runtime suite contains 22 focused reducer/owner tests, including table
boundaries, 64 serialized concurrent submissions, terminal orderings, repeated
rollback/settlement, early and late responses, identity exhaustion, and
generation isolation. The owner state uses no task, mutex, semaphore, atomic,
or peer registry.

## Validation

| Gate | Result |
| --- | --- |
| runtime reducer and owner ledger | Passed: 22 |
| default workspace tests and documentation tests | Passed in full; 3 authorized-device cases ignored by default |
| strict workspace production clippy | Passed with warnings denied |
| architecture checker | Passed: runtime activated, 0 violations |
| permanent W2 wire copy/allocation budget | Passed: 3 |
| changed-diff and consolidation scans | Passed |
| credential and endpoint scan | Passed: no repository matches |

No production data-path callsite changed in this ticket, so a new appliance
resource run would add no behavioral evidence. W3-1 remains the latest
hash-bound real-server proof for the runtime namespace and wire pipeline.

## Boundary and rollback

The ledger is an internal owner seam; the legacy handler path still supplies
production credits and MessageIds until subsequent W3 vertical migrations.
It must not gain new authority. W3-3 extends these records with async-id,
tombstone, deadline, and cancellation ownership.

Rollback starts with dependent W3 tickets, then reverts this evidence and
`7bf9f2f`. No appliance rollback is required.
