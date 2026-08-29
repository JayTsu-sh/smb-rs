# W3-1 generation owner spine

## Scope

- Ticket: #45
- Wave: W3 — Replace the single-generation request runtime
- Depends on: W2 checkpoint `83d357c`
- Tested implementation: `460db01`
- Validation date: 2026-08-29

This ticket activates the W3 runtime root and establishes its sole-authority
state seam. `GenerationState` owns the request registry for one physical
generation. `RequestRecord` keeps caller outcome, send progress, response
progress, and tombstone state orthogonal, while one pure reducer arbitrates all
terminal events with first-terminal-wins behavior.

The W2 transformer adapter reached its W3 removal boundary. Its wire codec,
protection, preauthentication, and session-security behavior moved unchanged
into the runtime-internal `WirePipeline`; workers now borrow that pipeline from
the runtime namespace. The old adapter path and ledger entry are deleted.

## Reducer invariants

- A request key always includes generation and message ID.
- Foreign-generation traffic is rejected before registry lookup.
- Unknown or late traffic cannot create a request record.
- Response, cancellation, deadline, and disconnect publish at most one caller
  terminal result under every tested ordering.
- Cancellation/deadline before wire commitment is known; after the first byte
  it yields `OutcomeUnknown` and retains a tombstone until final response or
  generation loss.
- A late response performs bookkeeping and clears its tombstone without waking
  the caller twice.
- Disconnect completes only callers that remain open.

## Local validation

| Gate | Result |
| --- | --- |
| reducer and generation-owner tests | Passed: 12 |
| default workspace tests | Passed in full; 3 device cases ignored by default |
| strict workspace production clippy | Passed with warnings denied |
| architecture checker | Passed: runtime activated, 0 violations |
| W2 wire/transform tests and budgets | Passed as part of workspace suite |
| changed-diff and consolidation scans | Passed |
| credential and endpoint scan | Passed: no repository matches |

## Isolated real-server validation

The manifest was bound to `460db01` and an anonymized target identity. Runtime
inputs used one-shot descriptors and are absent from stored artifacts.

| Gate | Result |
| --- | --- |
| plain 1 MiB immutable write/read | Passed |
| encryption-required 1 MiB immutable write/read | Passed |
| plain signed compound Create/SetInfo/Close | Passed |
| encrypted whole-chain compound Create/SetInfo/Close | Passed |
| plain 4-stream 1 MiB | Passed: write 12.782 MiB/s, read 16.058 MiB/s |
| encrypted 4-stream 1 MiB | Passed: write 4.455 MiB/s, read 4.406 MiB/s |

The isolated plain share, encrypted share, and volume all reached `Deleted` in
the exact manifest inventory. Retained-resource count is zero.

## Boundary and rollback

W3 is activated, but this ticket does not claim that legacy worker and handler
authorities have been eliminated. Subsequent W3 tickets route admission,
message IDs, credits, pending completion, pumps, and shutdown through this
runtime spine before deleting those paths.

Rollback starts with dependent W3 tickets, then reverts this evidence and
`460db01`. No appliance rollback is required.
