# FAS2750 acceptance matrix and resource guardrails

## Status and scope

Accepted first-phase real-server protocol for the async architecture rewrite.
It is normative for milestone acceptance. Runtime endpoints, user names, and
credentials are secret inputs and never appear in this document, manifests,
tracker comments, or ordinary logs.

The authorized mutation scope is limited to resources created by the current
Validation run under the designated existing domain-joined SVM. Existing
shares, SVM-wide signing/encryption/Multichannel settings, AD, data LIFs,
network topology, aggregate policy, and cluster HA operations are read-only.

## Run identity and inventory

Every run generates a random 128-bit ID and uses names of the form
`smbrs_<run-id>_<role>`. The same ID is stored in volume/share comments,
Snapshot and test-object names, and a local manifest. The Resource inventory is
the only cleanup authority.

An object may be mutated or deleted only when all of the following match the
manifest:

- exact name and object type;
- run ID and ownership comment;
- target SVM;
- expected parent/dependency;
- creation record and current lifecycle state.

A prefix, glob, discovery result, or partially matching comment never grants
cleanup authority.

## Resource topology

One run may create three independent groups:

| Role | Volume | Shares | Purpose |
| --- | --- | --- | --- |
| functional | 2 GiB thin, UNIX security style | plain and encrypted | protocol/function, lease/oplock, notify, Snapshot/Previous Versions |
| performance | 16 GiB thin, UNIX security style | plain and encrypted | uncontaminated throughput/RSS matrix |
| CA | 2 GiB thin, NTFS security style | continuously available | conditional persistent-handle gate |

Volumes disable autosize and automatic Snapshot policy for the run. Capacity
may be reduced only when the complete assigned matrix still fits; otherwise the
run is `Blocked`. The CA group is created only when preflight proves that the
platform, aggregate, volume, and share prerequisites are available within the
authorized scope.

Creation removes the default Everyone share ACL and grants only the SMB test
identity the required access. Functional/performance UNIX roots receive the
minimum mode and ownership needed by that identity. CA NTFS permissions are
applied and verified before use. A resource is not `Ready` until share,
junction, security style, ACL, share properties, capacity, and ownership comment
all match the plan.

## Preflight and plan

Preflight is read-only and verifies:

- cluster and SVM identity match the configured target;
- CIFS service is healthy and domain joined;
- aggregate is online and has sufficient headroom;
- run ID is absent from active objects and the recovery queue;
- runner management and SMB data paths are reachable;
- required share-scoped encryption, Snapshot, and conditional CA properties are
  supported and authorized;
- time/toolchain/runner facts needed by the evidence protocol are available;
- no unfinished manifest requires cleanup or an explicit retained decision.

The tool defaults to dry-run and prints exact resources, permissions, space,
property changes, and the cleanup dependency graph. Execution requires an
explicit apply flag bound to the generated plan hash. Any drift from the
preflight snapshot invalidates the plan before mutation.

Performance and fault-injection runs acquire an exclusive target lease.
Functional runs may coexist if their inventories and capacity are independent.
The lease is represented locally and by a run-owned ONTAP marker/comment. It may
be taken over only after its TTL expires and the owner process is proven absent.

## Transactional provisioning

Each successful creation or mutation is appended to the manifest atomically and
fsynced before the next step. The manifest contains no credentials. Failure
triggers best-effort reverse dependency cleanup from the recorded inventory.
Tests cannot begin until the entire required group reaches `Ready` after a
read-only verification pass.

On process restart, unfinished manifests are handled before a new run:

- ownership-verified cleanup may resume;
- an explicitly retained run may remain until its TTL;
- ambiguity becomes `Blocked` for manual review.

Orphaned resources are never ignored or adopted through name discovery.

## Core acceptance matrix

### Protocol and authentication

Hard gates:

- SMB 3.1.1 over TCP negotiation;
- NTLMv2 success and wrong-credential failure;
- requested/negotiated signing and protected request/response traffic;
- SessionSetup, Share connect, Logoff, and disconnect;
- typed failure for unsupported algorithms or invalid downgrade;
- no SMB1 or silent unsigned fallback.

SMB 3.0.2 and 2.1 remain compatibility regressions and do not replace the
3.1.1 gate.

### File and directory lifecycle

Hard gates cover create, open, overwrite, short and exact I/O, chunked I/O,
sparse offsets, set length, flush, metadata, security and filesystem queries,
paginated/pattern directory enumeration, rename, delete-on-close, typed close,
and parent-close cascade. Payloads include empty, 4 KiB, 64 KiB, 1 MiB, and the
configured large-file shape, with byte-for-byte verification.

Concurrent positioned reads/writes must work without a shared client cursor.
An open-time EOF snapshot must not suppress a valid write-followed-by-read.
Before infrastructure cleanup, the run enumerates and accounts for every test
file and directory in its inventory.

### Lease, oplock, and change notification

Two independent Client/Session identities create conflicts that require a lease
or oplock break. Acceptance requires receipt, deadline-bounded ACK, invalidation
of stale cache/open state, and successful progress by the competing client.
Change notification covers create, rename, delete, and cancellation.

Queue overflow and lag policy is tested deterministically locally; ONTAP is the
hard gate for normal event/ACK behavior. Missing ACK or continued use of invalid
cached state fails the run.

### Integrity fault injection

A test-only loopback TCP proxy flips a protected byte in one signed direction
and an authentication-tag byte in one encrypted frame. Client or server must
reject/close the exchange and the operation must receive a typed integrity
failure. The proxy records only direction, frame ordinal, mutation type, and
outcome; it never stores payloads or secrets. Production code exposes no raw
send interface for this test.

### Share-scoped encryption

The encrypted functional share proves negotiated cipher, encryption after wire
TreeConnect, complete create/write/read/query/close behavior, round-trip bytes,
and rejection of plaintext or invalid tags. The plain share proves that no
unauthorized SVM-wide encryption requirement leaked into the run. Encrypted
throughput and RSS are reported separately from the plain zero-copy budget.

### Snapshot and Previous Versions

The deterministic sequence is:

1. write version A, flush, and close;
2. create a run-owned Snapshot;
3. overwrite the active file with version B;
4. enumerate Previous Versions through SMB;
5. open the Snapshot version and verify A byte-for-byte;
6. verify B through the active path;
7. delete the Snapshot and verify the old version no longer opens.

Seeing the Snapshot only through the management interface is insufficient.

### Automatic recovery

After exact matching of run-owned client session, SVM, and isolated share, the
management path may close only that CIFS session. It may not restart CIFS,
modify LIFs, or trigger takeover/giveback. Acceptance requires a new generation
for Session/Share, revocation of an ordinary resource, policy-correct durable or
persistent handling, a typed result or `OutcomeUnknown` for sent side effects,
and deadline-bounded release of pending records, credits, payload, and tasks.

### Conditional continuously available gate

When preflight permits creation of a compliant NTFS continuously-available
share, persistent create context, disconnect/reconnect behavior, and data
integrity are hard gates for that run. If the prerequisites objectively do not
apply, the case is `NotApplicable` with a machine-readable reason. Closing one
test CIFS session does not prove nondisruptive cluster failover. Real
takeover/giveback remains outside first-phase authorization.

## Concurrency and lifecycle stress

Hard stress shapes include one connection with 16 in-flight requests, four
connections with 16 each, full-window randomized cancellation/timeout,
simultaneous read/write progress, close racing new admission, exact test-session
termination and recovery, and ten consecutive cycles without growth in pending
records, retained payload bytes, tasks, or server sessions.

Local deterministic tests cover event overflow, every partial-write cursor,
deadline ordering, and task panic. The real appliance gate covers full-duplex
load, cancel/timeout behavior visible to ONTAP, resource closure, and recovery.

## Performance gates

ADR-0001 defines payload, concurrency, build, statistic, throughput, and RSS
rules; the #29 baseline provides the comparison. Ordinary CI runs local copy,
allocation, and window-memory gates. Every architecture wave runs the ONTAP
functional matrix. Performance-affecting waves and milestone acceptance run the
complete plain and encrypted matrix: one discarded warm-up and at least five
measured samples, median and nearest-rank p95, and rejection when coefficient of
variation exceeds 10%.

Nightly reduced-payload trends are informational and cannot replace the
milestone hard gate. Plain 1 GiB throughput must remain at least 90% of baseline
and peak RSS at most 110%; transform paths report their separate budgets.

## Credentials and privilege separation

Secrets enter through an inherited file descriptor, interactive hidden input,
or CI secret provider and move immediately into a zeroizing container. An
environment variable is a controlled fallback only: it is removed after read
and not inherited by child processes. Command-line secrets, repository config,
manifests, issue text, packet captures, and ordinary traces are forbidden.

Management credentials are used only for preflight, provisioning, exact
test-session fault injection, and cleanup. The SMB data path uses the restricted
test identity. Management and data connections are independently timed,
audited, and closed.

## Result and evidence model

Case results are `Passed`, `Failed`, `NotApplicable`, or `Blocked` with stable
reason codes. A first-phase hard gate cannot be skipped: absence is Failed or
Blocked and the overall run does not pass. Only the conditional CA gate may be
NotApplicable after preflight evidence. Temporary infrastructure failure is
Blocked, never Passed.

Every run writes a secret-free JSON manifest and Markdown summary containing:

- run ID, code commit, toolchain, runner and test versions;
- anonymized target identity, ONTAP version, and read-only capabilities;
- inventory lifecycle transitions and plan hash;
- case timestamps, results, typed errors, and reason codes;
- negotiated dialect, signing algorithm, cipher, and authentication mechanism;
- performance samples, median, p95, CV, throughput, and RSS;
- cleanup result and exact retained objects;
- command category and status, not secret-bearing full commands or payloads.

## Cleanup and retention

Default behavior cleans up on success and failure. Retention is allowed only
when declared before execution with an owner identifier and expiry, for at most
24 hours. Retained inventory is marked `RetainedUntil`; the report supplies
exact ownership-checked cleanup instructions without credentials.

Cleanup first closes run-owned SMB handles and sessions, joins the loopback
proxy and every local task/process, deletes files/Snapshots/shares, unmounts and
deletes volumes in reverse dependency order, then verifies:

- no run-owned active Snapshot, share, junction, or volume remains;
- every inventory item is `Deleted` or explicitly `RetainedUntil`;
- pre-existing read-only state hashes match preflight;
- the recovery queue contains at most this run's deleted volumes.

Volume deletion may use ONTAP's normal recovery queue; default cleanup does not
purge it. A janitor operates only from a validated manifest and rechecks run ID,
comment, SVM, creation time, and TTL per object. It never accepts prefix/glob
targets or discovers resources. Missing or inconsistent evidence is `Blocked`,
not permission to delete.

Cleanup continues best-effort after individual errors, but ownership mismatch
stops deletion of that object and its parents. Any cleanup error fails the run
and produces the smallest exact manual cleanup inventory. The tool never tries
to restore or “fix” an unexpected change to pre-existing infrastructure.
