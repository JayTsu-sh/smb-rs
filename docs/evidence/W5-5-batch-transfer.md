# W5-5 typed Batch and concurrent Transfer acceptance

## Accepted implementation

The accepted implementation ends at `9c53251`. The Batch and Transfer slice
starts at `9927efc` and includes the deterministic contract, cancellation,
negotiated-I/O-limit, ordered-write, exact-partial-failure, architecture, and
test-scope corrections through the accepted commit.

`Batch` accepts only explicitly batch-compatible domain commands and returns
typed per-member outcomes. Invalid cross-batch or forward dependencies reject
the submission before execution; a member failure skips only its direct or
transitive dependants. The domain implementation uses split execution, while
the existing runtime compound admission and sealing invariants remain behind
the same domain boundary.

`Transfer` is a lazy future with a bounded progress stream. It schedules at
most the configured number of concurrent positioned reads, retains at most
that many chunks, and commits writes in offset order. The common read path
returns its immutable `Bytes` owner directly, and write slicing respects the
negotiated maximum without copying payload bytes. Cancellation, deadline,
short I/O, progress lag, unsupported strategy, and partial failure are typed.

The CLI copy consumer now uses the domain facade and no longer selects legacy
channels or invokes the old parallel-copy helper.

## Deterministic and local gates

| Gate | Result |
| --- | --- |
| typed heterogeneous Batch results and dependency-local failure | Passed |
| invalid Batch submission before member side effects | Passed |
| cancellation before first poll | Passed |
| concurrent-read bound and ordered writes | Passed |
| short I/O, cancellation, deadline, progress overflow, and exact partial failure | Passed |
| negotiated positioned read/write limits and `Bytes` copy budget | Passed |
| CLI copy domain-facade migration | Passed |
| workspace all-target tests | Passed |
| strict workspace production clippy | Passed with warnings denied |
| architecture checker | Passed: 9/9, zero violations |
| credential, endpoint, and diagnostic-marker scan | Passed |
| clean accepted implementation worktree | Passed |

## Isolated real-server validation

The final manifest was bound to `9c53251` and plan hash
`d5ec7775727cb6633478fbc90b1aed733e6b4ab16938f1255d8e8b0f5f12e0c4`.
Runtime inputs used one-shot descriptors; no endpoint, account, credential, or
exact resource name is stored here.

| Gate | Result |
| --- | --- |
| plain Share single-concurrency Transfer and full-content comparison | Passed |
| plain Share four-way concurrent-read Transfer and full-content comparison | Passed |
| encryption-required Share single-concurrency Transfer and full-content comparison | Passed |
| encryption-required Share four-way concurrent-read Transfer and full-content comparison | Passed |
| typed Batch write/read outcomes on both Shares | Passed |
| bounded progress, pre-cancel, and expired-deadline behavior on both Shares | Passed |
| cleanup | Passed: volume and both Shares Deleted; retained-resource count 0 |

## Boundary and rollback

W5-5 owns typed Batch and Transfer policy, scheduling, progress, and partial
failure reporting. It does not expose runtime workers, channels, credits,
message identifiers, or compound packets. Explicit server-side copy remains a
typed unsupported strategy until a later ticket supplies and verifies that
capability.

The remaining legacy public modules are not a compatibility commitment. Their
workspace-wide consumer migration and atomic deletion remain a hard W5 cutover
gate. Rollback requires reverting dependent W5 work first, then this evidence
and the W5-5 implementation commits in reverse order; W5-1 through W5-4 and
the W4 runtime/event authority remain the rollback floor.
