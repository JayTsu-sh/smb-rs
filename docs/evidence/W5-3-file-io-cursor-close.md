# W5-3 File I/O, cursor, and typed close acceptance

## Accepted implementation

The accepted implementation is `2ec55fa`, with prerequisite commits
`f7becf9`, `bb58cea`, `efe0d6e`, `f7675bd`, and `032c1d8`.

File exposes ownership-specific positioned I/O. `Bytes` write preserves the
shared payload owner through the sealed ordinary path; slice write performs its
single copy at the caller boundary on first poll. Bytes read remains a slice of
the immutable response owner, while read-into copies only into the caller's
buffer. `read_exact_at` and `write_all_at` handle short operations without
resetting the Operation's absolute deadline or cancellation budget. Zero
progress, offset overflow, and responses larger than the requested/submitted
range are typed failures.

Each borrowed `FileCursor` owns an independent offset and implements Tokio
AsyncRead, AsyncWrite, and AsyncSeek. It delegates work to positioned File
operations and introduces no File-wide cursor mutex. Checked relative and
end-relative seeks reject underflow and overflow.

File close returns `CloseOutcome::{Confirmed, AlreadyClosed, OutcomeUnknown}`.
One internal authority serializes only close state publication; concurrent
callers invoke the wire-close closure once and observe the same first terminal
state. An uncertain outcome is sticky and is never retried as a new Close.
RuntimeSession now registers child Shares and disconnects every live child
before Logoff, eliminating the previously observed Drop-after-parent duplicate
TreeDisconnect warning.

## Deterministic and local gates

| Gate | Result |
| --- | --- |
| short I/O complete-operation loop and zero-progress guards | Passed |
| checked cursor seek in both directions | Passed |
| two independent cursor and positioned-operation API contract | Passed |
| concurrent close first-terminal authority | Passed: two callers, one closure invocation |
| sticky OutcomeUnknown close | Passed: no retry |
| lazy deadline/cancellation/replay regression | Passed |
| Bytes write copy budget | Passed: zero payload copies after API ownership transfer |
| slice write copy budget | Passed: one caller-boundary payload copy |
| Bytes read owner identity | Passed by immutable-frame range tests and real I/O |
| workspace all-target tests | Passed |
| strict workspace production clippy | Passed with warnings denied |
| architecture checker | Passed: 9/9, zero violations |
| credential and endpoint scan | Passed |

## Isolated real-server validation

The accepted manifest was bound to `2ec55fa` and plan hash
`fa64fdd3221f8104e2daa720dc5c89648b821afad16836e1aae63f8ee7e841c5`.
Runtime inputs used one-shot descriptors; no endpoint, account, credential, or
exact resource name is stored here.

| Gate | Result |
| --- | --- |
| plain Share Bytes and slice positioned I/O | Passed |
| encryption-required Share Bytes and slice positioned I/O | Passed |
| read_exact_at/write_all_at content verification | Passed on both Shares |
| two independent cursors reading the same File | Passed on both Shares |
| concurrent typed close | Passed: Confirmed plus AlreadyClosed |
| child Share disconnect before Session Logoff | Passed on both Shares |
| teardown log scan | Passed: duplicate disconnect/runtime-terminated warnings 0 |
| cleanup | Passed: volume and both Shares Deleted; retained-resource count 0 |

## Boundary and rollback

W5-3 owns File positioned/cursor ownership contracts and typed File close.
W5-4 may add Directory, Pipe, streams, batches, and transfer helpers on the
accepted Operation/lifecycle seams. Rollback requires reverting dependent W5
work first, then this evidence and the implementation commits in reverse order.
W5-1 handles, W5-2 Operation, and W4 runtime authority remain the rollback
floor.
