# W3-6 domain-to-runtime cutover acceptance

## Accepted implementation

The accepted implementation is `947e853`, with prerequisite commits
`e8906cf`, `cb2e5ee`, and `600a829`.

The generation runtime is now the only request sequencing authority:

- credit charge is derived from typed command shape and negotiated Large MTU
  policy inside the runtime path;
- MessageId, credit request, response grant, pending correlation, deadlines,
  cancellation, and caller completion are owned by the reducer/owner;
- credit-starved typed admissions wait inside the bounded owner path and resume
  after a response grant, without a connection-layer semaphore or peer ledger;
- the old connection credit semaphore, MessageId atomic, credit-pool atomic,
  and outgoing/incoming sequence functions are deleted;
- the `ConnectionActor` task and mailbox are deleted. Lease/session domain
  bookkeeping uses a short-critical-section registry that owns no transport,
  request, credit, or lifecycle state and is always released before wire I/O;
- the `MessageHandler`/`MessageHandlerExt` chain and `msg_handler` module are
  deleted. Connection, channel, session, and tree contexts seal domain policy
  before one typed runtime execution;
- normal domain execution submits a `ResponsePolicy` containing the expected
  command and statuses. The owner validates it before publishing the result.

Standalone submit/await operations remain only for protocol flows that require
an intermediate state transition, such as multi-round SessionSetup and SMB
Cancel. They use the same runtime admission and correlation authority; they are
not a second transport or pending seam.

## Local gates

| Gate | Result |
| --- | --- |
| default workspace tests and doctests | Passed |
| runtime tests with test support | Passed: 57 |
| owner credit-wait wake test | Passed |
| strict workspace production-library clippy | Passed with warnings denied |
| architecture checker | Passed: runtime activated, 0 violations |
| lifecycle, transport, copy/allocation, and documentation coverage | Passed as part of workspace gates |
| changed-diff, credential, and endpoint scans | Passed |

The new deterministic credit-wait test proves that a second typed command is
not rejected or assigned an identity while the only credit is outstanding. A
response grant wakes owner admission and assigns the next unique MessageId.
Existing runtime coverage continues to cover early responses, short and zero
progress writes, transport/decode faults, cancellation before and after
progress, deadline, disconnect, pump panic, and bounded close/join.

## Isolated real-server validation

The manifest was bound to `947e853` and plan hash
`ebd0a3f829135ca6fccf24be70adcb48b2aeee95b7d89ed126b2137ee147111d`.
Runtime inputs used one-shot descriptors; no endpoint, account, credential, or
exact resource name is stored here.

| Gate | Result |
| --- | --- |
| plain 1 MiB immutable write/read | Passed: write 9.145 MiB/s, read 9.000 MiB/s |
| encryption-required 1 MiB immutable write/read | Passed: write 4.498 MiB/s, read 2.406 MiB/s |
| plain 4-stream 1 MiB | Passed: write 20.652 MiB/s, read 21.488 MiB/s |
| encrypted 4-stream 1 MiB | Passed: write 6.633 MiB/s, read 4.927 MiB/s |
| plain signed compound Create/SetInfo/Close | Passed |
| encrypted whole-chain compound Create/SetInfo/Close | Passed |
| lease-break notification fan-out and ACK path | Passed |
| lease cache tombstone on unsolicited break | Passed |

The isolated volume and both shares reached `Deleted`; retained-resource count
is zero.

## Boundary and rollback

W3 now has one accepted single-generation request runtime. Cross-generation
reconnect, replay classification, recoverable object reconstruction, and the
final event model begin in W4; this ticket does not claim them.

Rollback starts with dependent W3 checkpoint/W4 work, then reverts this
evidence and `947e853`, `600a829`, `cb2e5ee`, and `e8906cf` in reverse order.
Rollback must not restore concurrent transport, pending, MessageId, or credit
authorities. No appliance rollback is required.
