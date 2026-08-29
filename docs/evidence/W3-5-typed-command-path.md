# W3-5 typed command path acceptance

## Accepted implementation

The final isolated validation was bound to `786faf3`. The production cutover is
implemented by `4910dfa`; `786faf3` fixes the multi-credit MessageId advance
exposed by the appliance run. Supporting commits are `f93e3d2`, `11411e2`,
`e5625f2`, `39b54ec`, `cae2865`, and `4910dfa`.

The runtime now exposes typed operations, owns bootstrap wire policy, supports
owner-bounded detached waits, buffers early responses, and admits compound
requests atomically. `RuntimeWorker` is a facade over the unique runtime owner:
all production single and compound request transport I/O goes through the owner
and its pumps. The former Worker trait, parallel/single workers, multi-worker
backend, async/threading backends, and duplicate single-message inbound
transform path were removed.

MessageId allocation advances by the request credit charge. A deterministic
state test covers a charge of 16 advancing MessageId 40 to 56; this prevents a
large request from overlapping the MessageId range reserved by an earlier
multi-credit request.

## Local gates

| Gate | Result |
| --- | --- |
| default workspace tests | Passed |
| runtime tests with test support | Passed: 54 |
| strict workspace production clippy | Passed with warnings denied |
| architecture checker | Passed: runtime activated, 0 violations |
| lifecycle, transport, copy/allocation, and documentation coverage | Passed as part of the workspace gates |
| changed-diff, consolidation, credential, and endpoint scans | Passed |

The runtime suite covers early response buffering, short writes with progress
1 through 15, zero progress, transport/decode faults, cancellation before and
after progress, deadline, disconnect, pump panic, and bounded close/join. State
and integration coverage also verify unique correlation, payload/credit
reclamation, and compound admission.

## Isolated real-server validation

The final manifest was bound to `786faf3` and plan hash
`a9642fcc44c31599151aa04521bdaa41bf71b9236dca641f1bdd1954eaf509bb`.
Runtime inputs used one-shot descriptors and no endpoint, account, credential,
or exact resource name is stored here.

| Gate | Result |
| --- | --- |
| plain 1 MiB immutable write/read | Passed: write 8.321 MiB/s, read 7.910 MiB/s |
| encryption-required 1 MiB immutable write/read | Passed: write 4.195 MiB/s, read 2.323 MiB/s |
| plain signed compound Create/SetInfo/Close | Passed |
| encrypted whole-chain compound Create/SetInfo/Close | Passed |
| plain 4-stream 1 MiB | Passed: write 17.045 MiB/s, read 19.427 MiB/s |
| encrypted 4-stream 1 MiB | Passed: write 6.218 MiB/s, read 4.813 MiB/s |

An earlier diagnostic run found that fixed one-step MessageId allocation caused
a reset on a 1 MiB multi-credit request while a 4 KiB request succeeded. That
run was not accepted as evidence and its resources were cleaned. After
`786faf3`, the 1 MiB path and the full final matrix passed. The final isolated
plain share, encrypted share, and volume all reached `Deleted`; retained-resource
count is zero.

## Boundary and rollback

This ticket establishes the typed runtime seam and removes the old worker and
backend transport authorities. `ConnectionMessageHandler` and sequence-policy
fields still remain as a facade around parts of outgoing preparation. W3-6 must
remove that handler chain, its legacy credit semaphore/atomics, and any
remaining `ConnectionActor` peer authority while moving domain calls directly
onto typed operations. This evidence does not claim that cleanup early.

Rollback starts with dependent W3 tickets, then reverts this evidence, the
MessageId fix, and the typed-operation cutover in reverse order. It must not
restore two concurrent transport authorities. No appliance rollback is needed.
