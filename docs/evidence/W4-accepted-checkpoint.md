# W4 accepted checkpoint

## Accepted boundary

W4 accepts the implementation through `9e621a0` and the W4-6 evidence through
`c336823`. The ticket chain is W4-1 through W4-6, with evidence records:

- `W4-1-generation-object-authority.md`;
- `W4-2-connection-generation-recovery.md`;
- `W4-3-session-reauthentication.md`;
- `W4-4-share-recovery.md`;
- `W4-5-resource-recovery.md`;
- `W4-6-event-policy.md`.

The permanent object spine is Connection → Session → Share → Resource. Every
object carries generation-scoped runtime authority; parent loss atomically
revokes descendants, and only a fully validated replacement may publish a new
token. Connection, Session, and Share recovery have one bounded owner each.
Ordinary Resources fail closed. Explicitly granted durable-v2 Resources may
reconnect with DH2C, but neither recovery nor server events widen an
operation's replay policy.

Lease/oplock breaks invalidate local authority before a bounded ACK and public
event publication. Change-notify uses a single owner, hard queue capacity,
typed overflow, and drop cancellation. Public consumer lag is outside the
correctness-critical cache invalidation path.

## Local gates

| Gate | Result |
| --- | --- |
| W4-1..W4-6 issue/evidence/commit audit | Passed |
| workspace all-target tests | Passed |
| lifecycle, recovery, event, copy/allocation tests | Passed |
| strict workspace production clippy | Passed with warnings denied |
| architecture checker | Passed: runtime activated, 0 violations |
| credential and endpoint scan | Passed |

No old generation authority, ordinary-Resource blind replay, or
correctness-critical subscriber path remains. `domain` and `facade` remain the
two declared not-yet-activated architecture modules for W5.

## Isolated real-server checkpoint

The final checkpoint manifest was bound to `c336823` and plan hash
`4391ca78cb70510dd58f43f6a8ece207b13b24635b1c915ecbb0ce4022808653`.
Runtime inputs used one-shot descriptors; no endpoint, account, credential, or
exact resource name is stored here.

| Gate | Result |
| --- | --- |
| plain 1 MiB immutable roundtrip | Passed: write 8.869 MiB/s, read 8.136 MiB/s |
| plain 4-stream 1 MiB | Passed: write 33.642 MiB/s, read 20.635 MiB/s |
| encryption-required 1 MiB immutable roundtrip | Passed: write 4.426 MiB/s, read 2.358 MiB/s |
| encrypted 4-stream 1 MiB | Passed: write 5.890 MiB/s, read 4.758 MiB/s |
| byte-for-byte plain and encrypted data path | Passed |
| lease break, oplock break/ACK, change-notify/cancel | Passed |
| ten independent transport-loss recovery cycles | Passed: 10/10 ordinary stale and durable reconnect |
| per-cycle cleanup | Passed: 10/10 retained-resource count 0 |
| final checkpoint cleanup | Passed: volume and both Shares Deleted; retained-resource count 0 |
| persistent handle on CA Share | NotApplicable: isolated Shares did not advertise continuous availability |

The ten-cycle stress created a new hash-bound manifest and isolated
volume/plain/encrypted Share set for every cycle, triggered a transport loss,
required Connection generation replacement, rejected the ordinary Resource,
reconnected the durable Resource, and restored the exact preflight state
before the next cycle.

## Permanent gates and W5 handoff

W5 may replace the public interface without preserving compatibility, but it
must route through this accepted runtime. The following are permanent gates:

- one generation/object authority and one recovery owner per layer;
- bounded queues, attempts, deadlines, cancellation, task join, and cleanup;
- explicit replay policy and `OutcomeUnknown` after ambiguous commitment;
- stale-generation rejection and ordinary Resource fail-closed behavior;
- invalidate → ACK → publish server-event ordering;
- zero retained isolation resources and secret-free evidence.

Rollback requires reverting W5+ first, then W4-6 through W4-1 in reverse
dependency order. W3's single-generation runtime remains the rollback floor.
