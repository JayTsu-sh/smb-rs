# SMB object and request lifecycle invariants

## Status

Accepted lifecycle decision for the async architecture redesign. This document
defines normative states, transitions, concurrency rules, automatic
reconnection, and typed terminal outcomes for Connection, Session, Share,
Resource, and Request.

Exact Rust enum/type names may change during API prototyping, but an
implementation must preserve these observable semantics and invariants. The
single-owner implementation model is fixed in `async-request-engine.md`.

## Universal rules

1. Every mutable lifecycle is represented by an explicit enum. Boolean flags,
   optional fields, sentinel IDs, map membership, and sender lifetime may be
   implementation details but are never the authoritative state definition.
2. The connection runtime registry is the only authority for connection-bound
   mutable state.
3. Every domain handle carries an opaque `(identity, generation)` token. A
   numeric SMB identifier without its generation is insufficient authority.
4. Every transition is validated. Illegal transitions return a typed error and
   do not partially mutate state.
5. A terminal state is monotonic. `Closed`, `Revoked`, and terminal `Failed`
   objects never return to `Active`.
6. Each request publishes exactly one terminal result to its caller.
7. Each reservation, credit obligation, pending entry, payload owner, and
   waiter is released or transferred exactly once.
8. State commits are short and serialized by the runtime owner. Network waits,
   encoding, signing, encryption, compression, and caller work execute
   concurrently outside the state commit.
9. Parent state changes invalidate descendants in one authoritative runtime
   transaction; cleanup does not depend on `Arc` or `Drop` order.
10. User-visible request completion and connection-level protocol bookkeeping
    are separate facts. A terminal user result never permits the runtime to
    skip validation or credit processing for a later wire response.

## Object hierarchy

```text
Connection generation
  └─ Session generation
       └─ Share generation
            └─ Resource generation
```

A token is valid only when its complete ancestor chain is valid. Reconnection
may publish replacement tokens for recovered objects; it never mutates an old
token into authority for a different generation.

## Connection lifecycle

```text
New
  → Connecting
  → Negotiating
  → Active
  → Closing
  → Closed

Active      → Reconnecting → Active(new generation)
Connecting  → Failed
Negotiating → Failed
Active      → Failed
Reconnecting→ Failed
```

### Connection rules

- `New`, `Connecting`, and `Negotiating` do not accept domain operations.
- `Active` accepts operations subject to backpressure and descendant validity.
- An unplanned transport loss from `Active` enters `Reconnecting` when the
  configured recovery policy permits it; otherwise it enters `Failed`.
- `Reconnecting` is not terminal. It creates a new physical connection and a
  new generation under bounded attempts, exponential backoff, and a total
  deadline.
- Exhausted recovery, non-recoverable negotiation/authentication failure, or
  missing credentials enters terminal `Failed` and preserves the root cause.
- Explicit close from any non-terminal state enters `Closing`; it cancels
  reconnection and never initiates a new one.
- `Closing` closes admission, drains already-sent work within a close deadline,
  terminates remaining work, performs teardown, and joins all connection-owned
  tasks before publishing `Closed`.
- `Closed` and terminal `Failed` reject every new operation deterministically.

## Session lifecycle

```text
Establishing → Active → LoggingOff → Closed
       ↘ Failed   ↘ Reestablishing → Active(new token)
                       ↘ Revoked
```

### Session rules

- A public usable Session handle is published only after authentication and
  security context establishment complete.
- Session cryptographic state and its channel bindings belong to the same
  authoritative generation record.
- On parent reconnection, an active Session enters `Reestablishing`. It becomes
  active only after authentication and channel security are fully established
  on the new connection generation.
- Reauthentication failure revokes the Session and its entire Share/Resource
  subtree. It does not leave a partially usable session.
- Explicit logoff closes admission to the complete subtree before sending the
  wire logoff.
- A server session-closed notification revokes the Session subtree after the
  runtime completes mandatory protocol validation/bookkeeping.

## Share lifecycle

```text
Connecting → Active → Disconnecting → Closed
      ↘ Failed  ↘ Reconnecting → Active(new token)
                         ↘ Revoked
```

### Share rules

- Share capabilities and security requirements are immutable snapshots
  attached to the active token.
- A Share is published only after successful wire TreeConnect validation.
- During parent recovery, the Share becomes `Reconnecting` after its Session is
  reestablished. It becomes active only after a validated TreeConnect on the
  new generation.
- Failed Share recovery revokes that Share and all of its Resources without
  revoking unrelated trees on the Session.
- Share disconnect closes admission to every descendant Resource before the
  wire disconnect is attempted.

## Resource lifecycle

```text
Opening → Active → Closing → Closed
    ↘ Failed  ↘ Recovering → Active(new token)   # durable/persistent only
                     ↘ Revoked
```

### Resource rules

- A Resource handle is published only after a validated Create response and
  registry commit.
- Ordinary resources become `Revoked` when their connection generation is
  lost. Reusing a coincidentally identical FileId is forbidden.
- A durable/persistent resource may enter `Recovering`. It becomes active only
  after the protocol reconnect context is accepted and a replacement token is
  atomically published.
- Recovery failure revokes only that Resource unless the error proves an
  ancestor is invalid.
- `Closing` rejects new I/O. Concurrent close calls share the same close result.
- The local state becomes `Closed` even if the wire Close response is lost; the
  close future returns `OutcomeUnknown(Close)` and parent teardown owns remote
  reclamation.

## Parent cascade matrix

| Parent transition | Descendant effect |
|---|---|
| Connection → Reconnecting | Sessions/Shares wait for ordered recovery; durable Resources recover; ordinary Resources are revoked. |
| Connection → Failed | All Sessions, Shares, and Resources are revoked with the connection cause. |
| Connection → Closing | Descendant admission closes; outstanding work follows close-deadline policy. |
| Session → LoggingOff/Closed/Revoked | All Shares and Resources below it are revoked or closed. |
| Share → Disconnecting/Closed/Revoked | All Resources below it are revoked or closed. |
| Resource → Closed/Revoked | Only that Resource and its requests are affected. |

Cascade publication is atomic from the perspective of new operation
admission: no child accepts a request after its parent has committed the
invalidating transition.

## Request lifecycle

```text
Created
  → WaitingForConnection
  → WaitingForCredits
  → Preparing
  → Queued
  → Sent
  → AsyncPending
  → Completed

any non-terminal state
  → Cancelled
  → TimedOut
  → Failed
  → OutcomeUnknown
```

Stages may be skipped when unnecessary, but may not be reordered. For example,
an already-active connection skips `WaitingForConnection`; a command with no
async interim response goes directly from `Sent` to `Completed`.

### Request admission

- An operation submitted during `Reconnecting`/`Recovering` waits for recovery
  within its own deadline by default; a caller that supplies no deadline is
  bounded by the recovery policy's total budget instead. A deliberate fail-fast
  option may return immediately.
- Every non-success exit of the recovery driver releases the queued waiters
  with a typed failure. `recovering` is never left set without a driver.
- Dropping a connection without `close()` still ends its recovery: the drop
  trips the driver's close token, and a bootstrap that finds its connection
  gone ends recovery with `Closed` on the first attempt instead of spending
  the retry budget.
- Waiting operations never enter an old generation's send queue.
- The recovery wait queue is bounded simultaneously by operation count, total
  retained payload bytes, and individual deadlines.
- Exceeding a queue bound returns a typed backpressure error without partially
  admitting the operation.
- Explicit close and cancellation bypass recovery waiting and take effect
  immediately.

### Concurrent execution model

Many operation futures may prepare data and remain outstanding concurrently.
The runtime serializes only short state commits:

```text
concurrent operation futures
  → concurrent prepare/transform where dependency-safe
  → reserve/commit in runtime state owner
  → asynchronous send/receive progress
  → complete/bookkeep in runtime state owner
  → wake callers independently
```

The initial design does not shard authoritative state. Sharding is permitted
only if a benchmark demonstrates that short serialized commits are a material
bottleneck and the replacement preserves every invariant here.

## Cancellation and timeout

### Before `Sent`

- Cancellation yields `Cancelled`; deadline expiry yields
  `TimedOut { stage }`.
- Queue membership, memory accounting, reservations, and any credits/message
  identity already reserved but not committed to the wire are rolled back
  exactly once.
- No SMB CANCEL is sent for a request that was never sent.

### After `Sent`

- The runtime sends a best-effort SMB CANCEL when the command supports it.
- A read-only/no-side-effect operation may return `Cancelled` or
  `TimedOut { stage }` without claiming a server-side mutation.
- A side-effecting operation without an observed terminal response returns
  `OutcomeUnknown { operation }`.
- Cancellation or timeout never silently retries a non-idempotent operation.
- A lightweight tombstone remains in the old generation for late-response
  bookkeeping.

### Tombstone drain deadline

The runtime cannot invent credits that the server has not granted. If a sent
request reaches its user terminal state but no terminal response arrives, the
runtime waits for a bounded internal drain deadline while retaining its
tombstone and credit obligation. After that deadline the old connection
generation is unhealthy and enters reconnection (or terminal failure if
recovery is disabled/exhausted).

## Response handling and first-terminal-wins

Response, cancellation, timeout, explicit close, and transport failure events
race through the serialized runtime owner. The first valid terminal transition
wins the user result. Later events cannot replace or publish a second result.

Every wire response—including `STATUS_PENDING`, a final response, or a late
response after user completion—first undergoes the applicable:

1. framing and codec validation;
2. generation check;
3. signature/encryption validation;
4. credit and connection bookkeeping;
5. request/tombstone state update.

Only then does the runtime decide whether a user waiter should be completed.
A late response can clear an old tombstone and settle old-generation credits,
but never wakes the caller twice. A tombstone's late response is accepted
whatever its status says: status contracts belong to live callers, and the
server answers a cancelled request with whatever it likes (`STATUS_CANCELLED`,
`STATUS_FILE_CLOSED`, or the real result). The command must still match.

An NTSTATUS outside the modelled `Status` enum is not a wire fault. It never
satisfies a response policy, so a live caller receives it as a raw-status error
response; it does not terminate the generation.

Data belonging to a retired generation cannot mutate the new generation's
credit pool, session state, tree state, resource state, or pending table.

## Automatic reconnection

Reconnection is a bounded hierarchy recovery, not blind transport replacement:

```text
connect transport
  → negotiate new Connection generation
  → authenticate Session
  → connect Share (wire TreeConnect)
  → reconnect required durable/persistent Resource
  → atomically publish replacement token(s)
  → release eligible waiting operations
```

- Connection, Session, and Share recovery is automatic when policy and
  credentials allow it.
- A waiting operation is released only when its complete dependency chain is
  active.
- Independent Shares/Resources may recover or fail independently after their
  common Session is active.
- Ordinary Resource handles are revoked rather than silently reopened.
- Explicit close or user cancellation never causes reconnection.

### Replay policy

Every internal operation declares one non-user-forgeable replay category:

- `NeverReplay` — default; never automatically resubmitted after possible send;
- `Idempotent` — safe to resubmit under the documented operation semantics;
- `ProtocolReplayable` — resubmission is permitted only with the SMB replay
  mechanism and evidence required by the protocol recovery path.

The runtime cannot infer replay safety from HTTP-like intuition or allow a
caller to mark arbitrary writes as safe. A sent operation without sufficient
replay proof ends as `OutcomeUnknown` rather than being guessed safe.

## Credential lifecycle during recovery

The connection runtime does not retain a plaintext password `String` for the
life of a Session. A recoverable Session references a controlled credential
provider or secret handle. Recovery obtains authentication material on demand,
limits its scope to authentication, and clears temporary secret buffers after
use.

If the provider is unavailable, rejects access, or supplies invalid material,
Session recovery stops with typed `AuthenticationFailed` and revokes its
descendants. Credential failure is not retried indefinitely as a transport
error.

## Explicit close and Drop

### Explicit close

- The first concurrent `close()` atomically owns protocol close work.
- Later close calls await the same shared result.
- Entering `Closing` rejects new ordinary operations.
- Already-sent work may finish within the close deadline; remaining work is
  terminally completed according to cancellation/outcome-unknown rules.
- `close().await` returns only after protocol work, authoritative state commit,
  descendant handling, and owned task joining complete.
- Loss of a close response produces local `Closed` plus
  `OutcomeUnknown { operation: Close }`.

### Drop

`Drop` never blocks, creates a Tokio task, or triggers automatic reconnection.
It may attempt one non-blocking best-effort release command only when its
runtime is still active. Failure to enqueue is ignored; ancestor teardown is
the final remote-resource reclamation mechanism.

Callers that require deterministic wire cleanup must use explicit
`close().await`. Drop is not an implicit async interface and makes no completion
guarantee.

## Typed public error semantics

The public error model must make at least these cases programmatically
distinguishable:

- `Closed { object }`
- `Revoked { object, cause }`
- `Cancelled { operation }`
- `TimedOut { operation, stage }`
- `OutcomeUnknown { operation, source }`
- `ConnectionLost { source }`
- `ReconnectExhausted { attempts, source }`
- `Backpressure { limit }`
- `ProtocolViolation { detail }`
- `AuthenticationFailed { source }`
- `ServerStatus { status, context }`

Concrete enum nesting is deferred, but these cases cannot be collapsed into
`InvalidState(String)`, `Other`, or stringified lower-level errors. Root causes
remain available through typed fields and error sources.

## Required verification properties

The eventual implementation must support deterministic tests proving:

- every legal and illegal state transition;
- concurrent close shares one result and sends at most one wire close;
- parent invalidation rejects all descendant admission atomically;
- stale generation tokens cannot address recovered objects;
- cancellation/timeout before send rolls back every reservation once;
- cancellation/timeout after send publishes one result and retains required
  bookkeeping;
- late responses never complete a caller twice or mutate a new generation;
- every interim/final/late response performs credit bookkeeping exactly once;
- drain deadline retires an unhealthy generation rather than inventing credits;
- only durable/persistent resources recover;
- replay policy prevents non-idempotent blind retries;
- reconnect queues enforce count, byte, and deadline bounds;
- explicit close joins tasks; Drop works without an active Tokio runtime.
