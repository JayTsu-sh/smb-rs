# W4-4 Share recovery acceptance

## Accepted implementation

The accepted implementation is `0c6c6d0`, with prerequisite commits `6395461`,
`bfde2c1`, and `ad18dab`.

Each Share now exposes one atomic generation snapshot containing TreeId,
validated TreeConnectInfo, parent Session token, and Share object token. After
Session replacement, SessionContext snapshots its live Share weak registry and
replays independent TreeConnect operations concurrently. Each Share has one
FIFO recovery mutex, so duplicate callers share a single authoritative replay
and cannot publish partial candidates.

TreeConnect response capabilities, share flags, encryption requirements, and
TreeId are validated before a new Share object is created and published. Direct
Share operations use a hard-capacity recovery gate with typed timeout,
cancellation, and full outcomes. Caller cancellation detaches only that waiter;
the owned replay continues. Resource-dependent operations never enter the
Share gate, and old Resource/FileId tokens remain revoked after Session
replacement.

## Local gates

| Gate | Result |
| --- | --- |
| Share replay reducer/wait tests | Passed: 5 |
| default workspace tests and doctests | Passed |
| strict workspace production-library clippy | Passed with warnings denied |
| architecture checker | Passed: runtime activated, 0 violations |
| credential and endpoint scan | Passed |

Deterministic coverage includes successful publication, stale completion,
duplicate and consecutive Session replacement, bounded retry, close and
failure terminal states, hard queue capacity, FIFO release, Resource rejection,
and exact cancellation/deadline/failure removal. Existing ManualClock bounded
attempt coverage is reused by both SessionSetup and TreeConnect replay.

## Isolated real-server validation

The final manifest was bound to `0c6c6d0` and plan hash
`315f32c21cb69bdad86f7d1886dbe5cddc89ca55addcdfb465b857f757410231`.
Runtime inputs used one-shot descriptors; no endpoint, account, credential, or
exact resource name is stored here.

| Gate | Result |
| --- | --- |
| transparent-proxy transport loss | Passed: replacement Connection and SessionSetup |
| exact appliance CIFS-session disruption | Passed: exactly one run-owned session closed |
| original Session handle recovery | Passed: replacement SessionId published |
| original Share handle recovery | Passed: TreeConnect replay, new TreeId/token, create and write |
| stale Resource boundary | Passed: old Resource rejected without reopen |
| plain 1 MiB immutable write/read | Passed: write 9.356 MiB/s, read 8.623 MiB/s |
| plain 4-stream 1 MiB | Passed: write 19.153 MiB/s, read 19.420 MiB/s |
| encryption-required 1 MiB immutable write/read | Passed: write 4.467 MiB/s, read 2.380 MiB/s |
| encrypted 4-stream 1 MiB | Passed: write 6.520 MiB/s, read 4.648 MiB/s |

The isolated volume, plain share, and encryption-required share all reached
`Deleted`; retained-resource count is zero and cleanup restored the bound
preflight state.

## Boundary and rollback

W4-4 never reconnects or replays an ordinary Resource. A recovered Share may
create a new Resource, but a pre-loss FileId remains stale. W4-5 owns explicit
replay categories, OutcomeUnknown, and protocol-supported durable/persistent
Resource recovery; unsupported ordinary handles must continue to fail closed.

Rollback starts with dependent W4 work, then reverts this evidence and the
accepted implementation commits above in reverse order. No appliance rollback
is required because all manifest-owned resources were deleted.
