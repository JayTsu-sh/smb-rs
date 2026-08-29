# W3-3 pending, deadline, cancellation, and tombstone ownership

## Scope

- Ticket: #47
- Wave: W3 — Replace the single-generation request runtime
- Depends on: W3-2 evidence `0256fe5`
- Tested implementation: `16c14bb`
- Validation date: 2026-08-29

This ticket extends the sole `GenerationState` authority with the complete
pending-control model. It owns the generation-scoped AsyncId index, one ordered
deadline heap, cancellation deduplication, caller/wire obligation separation,
and tombstone drain health decision. No per-request timer or control task is
created.

## Invariants and behavior

- `(generation, MessageId)` remains the primary registry key. A pending
  response atomically installs one `AsyncId -> RequestKey` index; final response
  removes it.
- Reusing one AsyncId for another request, or changing a request's AsyncId,
  produces a typed protocol conflict and marks the generation unhealthy.
- Multiple legitimate pending responses with the same AsyncId retain one index
  and apply every validated credit grant.
- Request progress accepts only queued/write-progress/write-complete events.
  Cancel and deadline cannot bypass their dedicated owner lanes.
- Each request accepts one cancel control event. A committed cancel emits one
  best-effort wire-CANCEL obligation; an uncommitted cancel rolls back once.
- Caller and tombstone deadlines share one heap. Versioned entries make stale
  caller/drain deadlines harmless without deleting current state.
- A response racing ahead of write completion proves commitment and releases
  outbound payload accounting before any tombstone can be created.
- A late final response settles credits and AsyncId state, clears the
  tombstone, invalidates its drain entry, and never publishes a second caller
  outcome.
- Tombstone drain expiry marks the generation unhealthy. It neither silently
  drops the obligation nor restores unobserved credits.
- Credit ledger overflow is typed and generation-fatal rather than a panic.

## Validation

| Gate | Result |
| --- | --- |
| runtime reducer/owner suite | Passed: 30 |
| terminal ordering matrix | Passed: all 6 response/cancel/deadline orders publish once and settle final once |
| default workspace tests and documentation tests | Passed in full; 3 authorized-device cases ignored by default |
| strict workspace production clippy | Passed with warnings denied |
| architecture checker | Passed: runtime activated, 0 violations |
| permanent W2 wire copy/allocation budget | Passed: 3 |
| changed-diff and consolidation scans | Passed |
| credential and endpoint scan | Passed: no repository matches |

The owner state imports no async runtime primitive and creates no task, mutex,
semaphore, atomic, or peer registry. The existing `Clock` remains the sole time
source; W3-4 will drive only the heap's nearest deadline from the owner task.

No production wire callsite changed, so a new appliance run would add no
behavioral evidence. W3-1 remains the current hash-bound runtime/wire proof.

## Boundary and rollback

The best-effort SMB CANCEL is currently an owner effect, not yet a frame; W3-4
connects effects to the write pump. Legacy worker pending maps remain only on
the old production route and must be deleted during later W3 migration.

Rollback starts with dependent W3 tickets, then reverts this evidence and
`16c14bb`. No appliance rollback is required.
