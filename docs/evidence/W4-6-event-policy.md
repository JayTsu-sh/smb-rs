# W4-6 event policy acceptance

## Accepted implementation

The accepted implementation is `9e621a0`, with prerequisite commits `75b76a1`,
`d9c67e7`, `22fcb4f`, `835571a`, `765f4ab`, and `70b2745`.

Lease and oplock breaks now follow one explicit order: invalidate the local
authority, complete a bounded protocol acknowledgment when required, then
publish the terminal event. Duplicate and stale-generation events cannot
modify the replacement generation. ACKs use the normal typed runtime path and
there is no event-specific transport or signing bypass.

Change-notify has one owner task, a hard-capacity queue, typed overflow, and
drop-driven cancellation. Consumer lag can no longer delay internal lease
invalidation. The deterministic event reducer covers queue admission,
invalidation, ACK deadlines, publication, generation replacement, and close.

Real-server diagnosis also found and fixed a pre-existing codec defect: the
SMB2 oplock-break notification is a 24-byte structure, but it had been declared
as 12 bytes. A wire-format regression test now fixes that protocol boundary.
The granted oplock level is exposed as authoritative Resource state and is
updated before the ACK is sent.

## Local gates

| Gate | Result |
| --- | --- |
| event reducer scenarios | Passed: ordering, duplicate/stale, capacity, ACK timeout, replacement, close |
| lease/oplock and change-notify unit tests | Passed |
| default workspace all-target tests | Passed |
| strict workspace production clippy | Passed with warnings denied |
| architecture checker | Passed: runtime activated, 0 violations |
| credential and endpoint scan | Passed |

The retained W4 plain/encrypted, one/four-stream data-path checkpoint remains
accepted. This ticket changes event ownership and oplock codec/state handling;
it does not change the immutable payload, transform, scatter/gather, or pump
copy paths.

## Isolated real-server validation

The final manifest was bound to `9e621a0` and plan hash
`329f6e48933a6a39de747427a4e389fd9b3378d277fc38bf389c0e3be3068903`.
Runtime inputs used one-shot descriptors; no endpoint, account, credential, or
exact resource name is stored here.

| Gate | Result |
| --- | --- |
| two-client lease conflict | Passed: cache invalidated before required ACK; ACK accepted |
| two-client Batch oplock conflict | Passed: 24-byte notification decoded, level downgraded before ACK, ACK accepted |
| change-notify create/rename/delete | Passed: ordered old/new rename actions observed |
| change-notify cancellation | Passed: owner task terminated within the bounded deadline |
| local overflow and consumer-lag policy | Passed: typed overflow and cache correctness independent of subscribers |
| cleanup | Passed: volume and both Shares Deleted; retained-resource count 0 |

Before the accepted gate run, an operator command selected a nonexistent
manifest field and therefore supplied an invalid share name. All three tests
failed immediately at TreeConnect without exercising their event assertions.
The field was corrected to the schema-defined `plain_share`; the same bound,
non-drifted manifest then passed all three gates. No implementation change was
made between those attempts.

## Boundary and rollback

Break handling narrows caching authority but never broadens replay authority.
Ordinary Resources remain stale after parent replacement, while durable
Resources retain only the reconnect rights accepted in W4-5. Public event
delivery is diagnostic/application-facing and is not part of the correctness
critical invalidation path.

Rollback starts with dependent W5+ work, then reverts this evidence and the
accepted implementation commits above in reverse order. W4-5 replay and
durable Resource semantics remain intact.
