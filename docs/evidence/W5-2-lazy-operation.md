# W5-2 lazy Operation acceptance

## Accepted implementation

The accepted implementation is `2827bb2`, with prerequisite commits
`03f1ebe`, `fe17e09`, `7caf6ed`, and `3e7935b`.

The public data path now returns one lazy `Operation<T>` from Share file open
and positioned File read/write. Construction and drop before the first poll do
not admit protocol work. A timeout derives an absolute deadline; deadline,
cancellation, and replay configuration then travel through the domain/runtime
boundary into the generation owner. Ordinary operations default to
`ReplayPolicy::Never`.

The public replay vocabulary maps exactly to Never, IfUncommitted, Idempotent,
and DurableReconnectOnly runtime policies. File open currently rejects a
non-Never replay request explicitly instead of silently weakening it. Runtime
timeout, cancellation, admission/control/event backpressure, stale generation,
runtime termination, and uncertain post-commit outcome remain typed at the
public boundary. MessageId, AsyncId, credit, SMB CANCEL, and runtime object
tokens remain internal.

## Deterministic and local gates

| Gate | Result |
| --- | --- |
| unpolled/drop-before-poll side effects | Passed: zero starts |
| explicit pre-poll cancellation | Passed: typed cancellation, zero admission |
| drop after first poll | Passed: admitted cancellation token fired |
| absolute deadline and timeout derivation | Passed with paused Tokio time |
| simultaneous cancellation/deadline race | Passed: deterministic cancellation bias |
| four public replay mappings | Passed exactly |
| typed runtime outcome mapping | Passed |
| workspace all-target tests | Passed |
| strict workspace production clippy | Passed with warnings denied |
| real-server feature matrix compile | Passed |
| architecture checker | Passed: 9/9, zero violations |
| credential and endpoint scan | Passed |

The repository's broader `clippy --workspace --all-targets -D warnings` command
still reports pre-existing test-only lints outside the W5-2 change set. The
production workspace gate and the changed smb library gate both pass with
warnings denied; W5-2 introduced no remaining lint finding.

## Isolated real-server validation

The final manifest was bound to `2827bb2` and plan hash
`338381eccf4a5ae5d25b765ab63b1731b6d259d46b954c7e797011ddc50c6084`.
Runtime inputs used one-shot descriptors; no endpoint, account, credential, or
exact resource name is stored here.

| Gate | Result |
| --- | --- |
| cancelled file open before admission | Passed on plain and encrypted Shares |
| already-expired absolute deadline | Passed on plain and encrypted Shares |
| timeout-bounded file open | Passed on plain and encrypted Shares |
| immutable Bytes positioned write, Never replay | Passed on both Shares |
| zero-copy Bytes positioned read, Idempotent replay | Passed on both Shares |
| delete and explicit File/Share/Session/Client close | Passed |
| cleanup | Passed: volume and both Shares Deleted; retained-resource count 0 |

After successful explicit close, legacy bridge drop emitted a non-fatal warning
because a retained Share attempted a second disconnect after its Session was
already invalid. This did not change the typed result or leave resources. It is
recorded for the later W5 lifecycle/bridge-removal work rather than hidden by a
compatibility workaround.

## Boundary and rollback

W5-2 owns the public lazy operation contract and its policy propagation. W5-3
may build cursor, transfer, or remaining typed-resource operations on this one
seam. Rollback requires reverting dependent W5 work first, then this evidence
and the implementation commits in reverse order. W5-1 logical handles and the
accepted W4 runtime authority remain the rollback floor.
