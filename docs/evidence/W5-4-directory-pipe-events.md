# W5-4 Directory, Pipe, and typed event stream acceptance

## Accepted implementation

The accepted implementation is `51ca095`, with prerequisite commits
`53a3da9`, `ee7de65`, `d0e0cdb`, `ef89732`, `6ef2161`, `72e8b3f`,
`910d1e4`, and `e2ac5b5`.

`Share::open_directory` and `Share::open_pipe` now return lazy typed domain
operations. Directory pagination is exposed as a cancellable lazy stream;
collection is an explicit convenience. Directory watches use a bounded typed
event stream, pair rename-old/rename-new records, and cancel their owned wire
operation when the stream is dropped. Pipe read, write, and transact accept or
return `Bytes`, and transact propagates the operation deadline and cancellation
policy to the runtime.

Directory and Pipe close reuse the first-terminal close authority. The domain
surface does not expose FileId, MessageId, IOCTL packets, raw ChangeNotify
records, RPC fragments, Tree, or runtime tokens.

The final ONTAP diagnosis also tightened the shared runtime boundary. A
committed cancellation now completes the caller while retaining only the
response policy needed to drain async pending/final responses. The first
transport write progress is published to the owner while a frame is still in
flight, so disconnect outcome classification reflects actual wire commitment.
ONTAP's standard `STATUS_DELETE_PENDING` ChangeNotify cleanup result and empty
directory terminal statuses are explicitly typed rather than treated as wire
pipeline failures.

## Deterministic and local gates

| Gate | Result |
| --- | --- |
| lazy Directory pagination and stream-drop cancellation | Passed |
| bounded watch overflow and owner-task cancellation | Passed |
| rename old/new pairing | Passed |
| Pipe Bytes operations and operation-policy propagation | Passed |
| committed cancel plus async pending/final drain | Passed |
| first-byte write commitment during a stuck frame | Passed |
| concurrent typed close authority | Passed |
| workspace all-target tests | Passed |
| strict workspace production clippy | Passed with warnings denied |
| architecture checker | Passed: 9/9, zero violations |
| credential, endpoint, and diagnostic-marker scan | Passed |

## Isolated real-server validation

The final manifest was bound to `51ca095` and plan hash
`9908ed816eb05991c242c3cede442ea8dcacbe6a0865c5f036e834fed2b9ed69`.
Runtime inputs used one-shot descriptors; no endpoint, account, credential, or
exact resource name is stored here.

| Gate | Result |
| --- | --- |
| plain Share Directory create/list/rename/delete/watch | Passed |
| encryption-required Share Directory create/list/rename/delete/watch | Passed |
| watch cancellation and late response drain | Passed |
| plain diagnostic repetition | Passed: 5 consecutive complete runs |
| standard IPC service Pipe open/cancel/close | Passed |
| typed close and parent teardown | Passed |
| cleanup | Passed: volume and both Shares Deleted; retained-resource count 0 |

## Boundary and rollback

W5-4 owns typed Directory/Pipe operations, typed Directory event streams, and
their cancellation/drain behavior. The old workspace-wide API modules are not
a compatibility commitment: their atomic consumer migration and deletion
remain a hard W5 cutover gate after transfer/batch consumers have moved. No
alias from the new domain types to those legacy types was introduced.

Rollback requires reverting dependent W5 work first, then this evidence and
the implementation commits in reverse order. W5-1 through W5-3 and the W4
runtime/event authority remain the rollback floor.
