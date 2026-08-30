# W3-4 state owner and I/O pumps

## Scope

- Ticket: #48
- Wave: W3 — Replace the single-generation request runtime
- Depends on: W3-3 evidence `6e66cc5`
- Tested implementation: `b2a81af`
- Validation date: 2026-08-29

This ticket connects the W3 reducer to one asynchronous state-owner task and
two owner-created transport pumps. The transport is split once: the read pump
owns its receive half, the write pump owns its send half, and only the owner
mutates generation state, schedules frames, accounts credits, or completes
callers.

## Task and lane invariants

- Admission, I/O, control, event, and one-frame write lanes are explicitly
  bounded. The admitted-operation limit bounds the owner send queue.
- Each owner turn drains a bounded control batch, then services ready I/O and
  admission before waiting again; a control flood cannot starve submission.
- The write pump holds one active sealed `SendFrame`. It reports positive
  progress, completion, cancellation-before-write, or a typed transport
  failure, and owns no request registry.
- A cancellation racing the first write is resolved inside the pump's select:
  cancellation before observed progress proves zero bytes; after positive
  progress the active frame is driven to completion. The owner defers credit
  rollback until that proof arrives.
- TCP exposes `send_with_progress` using the existing immutable segment cursor.
  The ordinary transport `send` behavior remains unchanged.
- The read pump returns only hard-cap-validated `TransportFrame` owners and
  typed failures. It has no session, pending, credit, or caller access.
- Only the owner drives the nearest deadline through the shared `Clock`; no
  per-request timer task exists.
- Close stops admission, classifies callers, cancels both pumps, finishes or
  deadline-aborts an active write, joins both pump tasks, then waits for the
  owner task itself to exit before returning.
- Pump panic, I/O channel closure, or last-handle channel closure terminates
  the generation and reclaims the sibling pump. No runtime task is silently
  restarted or left detached.

## Deterministic validation

| Gate | Result |
| --- | --- |
| runtime reducer and topology tests with test support | Passed: 42, including 12 owner/pump cases |
| transport unit and scripted integration tests | Passed: 18 unit and 10 integration tests |
| partial-write cursor classes | Passed: maximum progress 1 through 15 |
| zero progress and injected write fault | Passed with typed failures and exact preceding progress |
| read frame and injected read fault | Passed |
| early inbound before write completion | Passed without losing the request |
| pre-progress cancel / post-progress cancel | Passed: zero-byte branch / finish-active branch |
| control-flood fairness and admission | Passed |
| single ManualClock deadline wake | Passed |
| pump panic and channel closure | Passed with typed terminal and sibling reclamation |
| close deadline with stuck active write | Passed: timed out, aborted, and joined both tasks |
| default workspace and documentation tests | Passed in full; 3 authorized-device cases ignored by default |
| lifecycle Scenario suite | Passed: 7 |
| strict workspace production clippy | Passed with warnings denied |
| architecture checker | Passed: runtime activated, 0 violations |
| permanent W2 copy/allocation budget | Passed: 3 |
| changed-diff, consolidation, credential, and endpoint scans | Passed |

## Isolated real-server validation

The manifest was bound to `b2a81af` and an anonymized target identity. Runtime
inputs used one-shot descriptors and are absent from stored artifacts.

| Gate | Result |
| --- | --- |
| plain 1 MiB immutable write/read | Passed |
| encryption-required 1 MiB immutable write/read | Passed |
| plain signed compound Create/SetInfo/Close | Passed |
| encrypted whole-chain compound Create/SetInfo/Close | Passed |
| plain 4-stream 1 MiB | Passed: write 11.022 MiB/s, read 17.548 MiB/s |
| encrypted 4-stream 1 MiB | Passed: write 5.015 MiB/s, read 7.767 MiB/s |

The run validates that the new production TCP progress seam preserves the
existing device path. The new owner is not yet the public command route; that
migration is W3-5 and is not claimed here. The isolated plain share, encrypted
share, and volume all reached `Deleted`; retained-resource count is zero.

## Boundary and rollback

W3-5 must route typed commands and decoded responses through this topology,
then remove the old Worker/Backend/MessageHandler request authorities. It may
not introduce another owner or bypass the progress/cancellation proof.

Rollback starts with dependent W3 tickets, then reverts this evidence and
`b2a81af`. No appliance rollback is required.
