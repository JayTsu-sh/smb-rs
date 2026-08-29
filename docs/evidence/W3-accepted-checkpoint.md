# W3 single-generation runtime accepted checkpoint

## Accepted chain

W3 is accepted as the cumulative chain below:

| Slice | Evidence | Accepted result |
| --- | --- | --- |
| W3-1 generation reducer | `4f7a2a7` | one request-lifecycle state authority; Transformer adapter removed |
| W3-2 admission and credit ledger | `0256fe5` | atomic admission, MessageId, payload, and credit reservation |
| W3-3 pending and terminal races | `6e66cc5` | pending/AsyncId/tombstone/deadline/cancel unified in reducer |
| W3-4 owner and pumps | `2a5dbb1` | one owner plus bounded read/write progress tasks |
| W3-5 typed production path | `492a55f` | production transport I/O cut over; old Worker/backend removed |
| W3-6 domain cutover | `39c297d` | handler/actor peers removed; domain commands directly use typed runtime |

The final implementation under device validation is `947e853`. The checkpoint
adds no runtime behavior beyond that accepted implementation.

## Frozen authority boundary

For one physical connection generation, the runtime owner is the sole authority
for admission, MessageId allocation, credit charge/request/grant accounting,
pending and AsyncId correlation, early and late responses, caller deadline and
cancellation, wire progress, terminal publication, and shutdown. Read and write
pumps report facts to the owner; they do not decide lifecycle outcomes.

The source audit found none of the removed peer authorities in production:
`MessageHandler`, `MessageHandlerExt`, `ConnectionActor`, Transformer,
parallel/single Worker, multi-worker backend, legacy credit semaphore/MessageId
atomic, or outgoing/incoming sequence accounting. The remaining connection
registry is domain bookkeeping behind short critical sections; it owns no task,
transport, request, credit, or lifecycle state.

The accepted mainline is:

`domain context → CommandRequest + ResponsePolicy → RuntimeHandle → owner reducer → WirePipeline → read/write pumps`

## Permanent local gates

| Gate | Result |
| --- | --- |
| W3-1 through W3-6 evidence chain | Present and audited |
| default workspace tests and doctests | Passed |
| runtime tests with test support | Passed: 57 |
| scripted transport tests | Passed: 18 unit and 10 integration |
| lifecycle Scenario suite | Passed: 7 |
| permanent wire copy/allocation budget | Passed: 3 |
| strict workspace production-library clippy | Passed with warnings denied |
| architecture checker | Passed: runtime activated, 0 violations |
| removed-authority consolidation scan | Passed |
| changed-diff, credential, and endpoint scans | Passed |

These W3 gates are permanent for W4 and later. Later work may extend owner state
and typed operations but may not introduce another transport task owner,
pending registry, credit/MessageId ledger, or compatibility adapter.

## Final isolated real-server matrix

The final W3 run was bound to implementation `947e853` and an immutable plan
hash. One-shot descriptors supplied runtime inputs; persisted evidence contains
no endpoint, account, credential, or exact resource name.

| Gate | Result |
| --- | --- |
| plain 1 MiB immutable write/read | Passed: write 9.145 MiB/s, read 9.000 MiB/s |
| encryption-required 1 MiB immutable write/read | Passed: write 4.498 MiB/s, read 2.406 MiB/s |
| plain 4-stream 1 MiB | Passed: write 20.652 MiB/s, read 21.488 MiB/s |
| encrypted 4-stream 1 MiB | Passed: write 6.633 MiB/s, read 4.927 MiB/s |
| plain and encrypted compound | Passed |
| unsolicited lease-break fan-out, ACK, and tombstone | Passed |

The isolated volume, plain share, and encrypted share all reached `Deleted`;
retained-resource count is zero.

## W4 entry contract and rollback

W4 may add generation identity, reconnect policy, typed retry classification,
recoverable object descriptors, event delivery, and bounded reconstruction. It
must express all of them as owner state/events/effects or typed domain policy on
top of this checkpoint. It may not infer replay safety, reuse identifiers across
generations, retain credentials in persisted state, or restore a peer actor.

Rollback starts with all W4+ work, then this checkpoint, followed by W3-6
through W3-1 evidence and implementation in reverse dependency order. No
appliance rollback is required.
