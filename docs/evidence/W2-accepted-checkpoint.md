# W2 accepted checkpoint

## Scope

- Wave: W2 — Replace the wire data plane
- Depends on: W1 checkpoint and W2-1 through W2-4
- Tested implementation: `0b38a27`
- Accepted checkpoint: the commit containing this evidence record
- Validation date: 2026-08-29

W2 establishes one immutable ownership spine from validated receive frames to
sealed outbound segments, protection transforms, and partial transport writes.
It does not claim the W3 single-generation request runtime, W4 recovery model,
or W5 public Interface.

## Commit and rollback record

| Evidence | Implementation scope |
| --- | --- |
| `df5a816` | W2-1 immutable receive frames and validated wire ranges |
| `1dbfa87` | W2-2 codec-owned outbound builder and sealed segments |
| `944e749` | W2-3 segmented signing and partial-write cursor |
| `9af5631` | W2-4 consume-and-replace compression/encryption transforms |
| `99fbc17` | activate W2 dependency gates and record the W3 adapter deadline |
| `0b38a27` | keep the default workspace gate deterministic while explicitly gating real-server targets |

Rollback starts with dependent W3 work, then reverts this checkpoint and the
W2 evidence and implementation commits in reverse order. The validation run
retained no appliance resources, so rollback has no server-side step.

## Architecture audit

- Receive bodies have one immutable `TransportFrame(Bytes)` owner; decoded
  variable regions are checked `WireRange` values into that owner.
- Ordinary and compound requests use the same codec-owned builder and sealed
  `WireMessage`; payload segments remain immutable and ordered.
- Signing traverses segments and patches only validated signature fields.
- Transport consumes `SendFrame` with an explicit cursor and vectored
  short-write loop; it neither mutates nor consolidates the message.
- Compression and encryption consume the sealed owner and return one immutable
  `TransformFrame`; encryption operates in place and compression writes into
  its final serialized arena.
- The active async transformer/backend path contains no `IoVec`, and production
  code contains no `consolidate` call.
- The only recorded compatibility seam is the W3-owned transformer adapter,
  with removal required during W3.

## Local validation

| Category | Result |
| --- | --- |
| default workspace test suite | Passed in full with external targets disabled by default |
| message codec | Passed: 133 unit and 1 documentation test |
| transport with deterministic test support | Passed: 18 unit and 8 integration tests |
| SMB lifecycle scenarios | Passed: 7 |
| offline SMB conformance | Passed: 6 |
| wire/transform copy-budget gate | Passed |
| all real-server test targets compile | Passed with explicit test and real-server features |
| strict production clippy | Passed with warnings denied |
| architecture dependency checker | Passed: 0 violations |
| changed-diff, consolidation, and credential/endpoint scans | Passed |

The permanent plain signed 1 MiB budget records zero payload copies, zero
payload-sized allocations, and stable payload ownership. Transform tests reject
a second output buffer and validate size, nonce, authentication, and compound
boundary invariants.

## Isolated real-server validation

The fresh plan was hash-bound to `0b38a27`, an anonymized target identity, the
preflight state, test identity, and exact isolated inventory. Runtime inputs
were provided only through one-shot descriptors.

| Gate | Result |
| --- | --- |
| plain 1 MiB immutable write/read | Passed |
| encryption-required 1 MiB immutable write/read | Passed |
| plain signed compound Create/SetInfo/Close | Passed |
| encrypted whole-chain compound Create/SetInfo/Close | Passed |
| plain 4-stream 64 KiB | Passed: write 9.045 MiB/s, read 16.456 MiB/s |
| plain 4-stream 1 MiB | Passed: write 14.622 MiB/s, read 16.084 MiB/s |
| encrypted 4-stream 64 KiB | Passed: write 4.662 MiB/s, read 4.573 MiB/s |
| encrypted 4-stream 1 MiB | Passed: write 4.956 MiB/s, read 4.775 MiB/s |

## Cleanup and gate ledger

- The manifest-owned plain share, encrypted share, and dedicated volume all
  reached `Deleted`; retained-resource count is zero.
- W2 gates are active in the architecture ledger: immutable receive ownership,
  validated ranges, sealed outbound ownership, segmented protection and send,
  copy/allocation budgets, and consume-and-replace transforms.
- W3 remains next: one generation owner, request reducer, deadlines,
  cancellation, backpressure, first-terminal-wins completion, and bounded
  shutdown. Its implementation must remove the recorded transformer adapter.

W2 is accepted. The next authorized ticket is W3-1, which begins the
single-generation request runtime.
