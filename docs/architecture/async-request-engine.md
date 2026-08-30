# Async request engine

## Status and purpose

Accepted design for the connection runtime's request engine. It implements the
lifecycle invariants, wire ownership model, and copy/allocation budgets while
replacing the current handler chain, worker/backend abstraction, and split
pending registries with one deep module.

## External interface

The domain-facing interface is conceptually:

```text
submit(typed operation) → RequestFuture<typed result>
close(deadline) → CloseReport
events() → typed unsolicited-event stream
```

Normal callers do not see message IDs, credits, async IDs, pending receivers,
manual send/receive pairing, channel selection, workers, transport handles, or
SMB CANCEL. Tests use this same interface. Internal adapters exist only for
deterministic I/O, clocks, and transform execution.

## Task topology

One physical connection generation owns exactly three long-lived tasks:

```text
State owner
  ├─ Read pump
  └─ Write pump
```

The state owner creates and joins both pumps. It exclusively owns connection
state, generation identity, admission accounting, credit balance, message and
async IDs, request records, deadlines, tombstones, send scheduling, and caller
completion. It never waits on network I/O or performs payload-sized CPU work.

The read pump owns the transport read half. It performs framing, codec decode,
and protection validation using an immutable generation security plan, then
reports a typed response, notification, or failure event. Ordered mutable
security phases such as negotiation and preauthentication are driven by an
explicit plan from the owner, never by registry lookup in the pump.

The write pump owns the transport write half and at most one active sealed
frame. It advances the transport-private `SendCursor` and reports
`CancelledBeforeWrite`, positive-byte progress, completion, or failure. It
does not schedule requests, mutate credits, or complete callers.

The root owner task holds pump handles. Pump exit is an owner event. If the
owner terminates unexpectedly, channel closure stops both pumps, drops the
registry and payload owners, and closes terminal senders. `RequestFuture` maps
that closure to typed `RuntimeTerminated`; pumps are never silently restarted.

## Request record

One linear state enum cannot express a caller that has timed out while a late
wire response may still settle credits. A request record therefore stores
orthogonal facts:

```text
RequestKey = (generation, message_id)
caller outcome     Open | Terminal(result)
send progress      NotQueued | Queued | Partial(bytes) | Complete
response progress  None | AsyncPending | Final
credit obligation  reserved charge and observed grants
payload owner       admission / preparation / owner queue / write pump / released
tombstone           absent | drain deadline
operation facts     side-effect class, cancellation support, dependency token
```

Each record owns at most one terminal sender. Only the state-owner reducer may
consume it. Later events perform protocol bookkeeping but cannot publish a
second result.

The primary registry key always includes generation and message ID. A validated
`STATUS_PENDING` atomically adds an `AsyncId → RequestKey` index scoped to the
same generation. No data from a retired generation can modify a new credit pool
or pending registry.

## Admission and preparation

Before taking payload ownership, submission acquires configured permits for
operation count and retained payload bytes. Exceeding either limit returns
typed backpressure without partially admitting the operation. Once its complete
dependency chain is active, the owner atomically reserves generation, message
ID, and credits and emits an immutable `PreparationPlan`.

Encoding, signing, encryption, and compression execute outside the owner as
short-lived owned tasks. Synchronous payload-sized transforms use
`spawn_blocking` behind a global bounded semaphore; every SMB chunk is bounded
by the negotiated maximum. Tasks are tracked in the owner's `JoinSet`, check
cancellation before and after work, and report only `Prepared` or
`PrepareFailed`. No preparation task is detached.

A preparation or queue failure before any byte is written rolls back every
permit, identifier reservation, credit reservation, and payload owner exactly
once through the reducer.

## Event lanes and fairness

The owner consumes three internal lanes:

- control: cancellation, deadline, explicit close, shutdown;
- I/O completion: read/write pump events;
- admission/preparation: new operations and preparation results.

External submitters cannot write directly to internal lanes. Admission permits
bound data-bearing work. Each admitted request can enqueue at most one
cancellation event, guarded by an atomic/token, so the private unbounded control
lane is logically bounded by admitted request count and remains usable from
`Drop`.

Scheduling handles a bounded control batch, then ready I/O completions, then
admission/preparation while capacity remains, before checking control again.
Shutdown closes admission immediately but does not starve I/O needed to drain
wire obligations.

Normal send scheduling uses bounded FIFO with credit-aware aging. A queue head
whose credit charge cannot currently be satisfied may be skipped only a limited
number of times; its age eventually blocks further overtaking. Mandatory ACK
and control frames have explicit priority without bypassing batch fairness.

Configured hard limits cover admitted operations, retained payload bytes,
preparation jobs, send queue items and bytes, outstanding credits, and each
notification-family queue. After negotiation the effective values are the
minimum of configuration and server capability. Channel capacities are
implementation details, never hidden backpressure policies.

## Send commitment and response races

The owner registers the complete request record and credit obligation before a
frame can reach the write pump. A valid response may therefore arrive before
the owner observes `WriteComplete` and still resolves the correct record.

The owner retains all not-yet-dispatched frames in its removable send queue.
The write pump receives only one active frame with a one-shot cancellation
token. Before its first transport write it reports one provable branch:

- `CancelledBeforeWrite`: zero bytes reached transport and all reservations
  can be rolled back;
- `WriteProgress(bytes > 0)` or `WriteComplete`: wire commitment exists.

After complete send, the write pump returns outbound payload ownership for
immediate release. Waiting for a response retains request metadata and credit
obligations, not sent file payload.

For a compound frame, member requests have independent keys, caller outcomes,
credits, async IDs, and tombstones while sharing one send-progress record.
Before dispatch, cancellation removes a member and re-finalizes compound
metadata without copying other payload. After dispatch begins, the frame cannot
be retracted; each member is classified independently.

## Credits, cancellation, and deadlines

Credits reserved for a request with zero bytes written are rolled back locally.
Once any byte is written, credits are not invented locally: the obligation
remains until a valid response grants credits or generation teardown closes the
old ledger. Every response, including `STATUS_PENDING` and late final response,
undergoes validation and credit bookkeeping before caller completion logic.

Explicit cancellation, future drop, deadline expiry, response, close, and
transport failure are reducer events. Before wire commitment, cancellation and
timeout remove queued work and roll back all ownership. After commitment, the
engine sends a best-effort high-priority SMB CANCEL when supported. The CANCEL
is a protected control frame referencing the target MessageId/AsyncId; it does
not create another pending request or caller future.

Read-only operations may publish cancelled/timed-out results according to the
lifecycle contract. A side-effecting operation without an observed final
response publishes `OutcomeUnknown`. In either case a tombstone may retain the
wire obligation without retaining outbound payload.

The owner maintains one deadline heap/wheel and one timer for the nearest
deadline. It does not create per-request timer tasks. Each tombstone has its own
drain deadline in that heap. Expiry means credit correctness is no longer
provable, so the complete old generation becomes unhealthy; the engine never
silently deletes the tombstone and continues.

`RequestFuture::cancel().await` waits for owner acknowledgement. Dropping the
future emits the deduplicated cancellation event but cannot promise synchronous
cleanup. The runtime continues draining its wire obligation independently.

## Notifications

The read pump reports validated unsolicited traffic through the I/O lane. The
owner performs mandatory authoritative updates and timely ACK work before
publishing a typed domain event. Domain streams are bounded per event family.
Recoverability determines overflow behavior: explicitly coalescible events may
merge, while loss of a correctness-critical event invalidates the relevant
object. A universal log-and-drop policy is forbidden.

## Failure, reconnection, and shutdown

Transport loss or any pump/preparation panic is a typed owner event. The engine
does not restart pumps, migrate registries, replay operations, or reconnect. It
classifies every request, terminates the current generation, joins its tasks,
and publishes generation loss to the runtime recovery policy. Only that higher
policy may submit a proven-safe operation into a new generation.

Explicit `close(deadline)` closes admission, rolls back undispatched work,
attempts to finish an active partial frame, and drains sent requests and
tombstones until the deadline. It then terminates transport if necessary,
cancels and joins preparation and pump tasks, and only then publishes `Closed`.
Its structured `CloseReport` includes final state, completed/cancelled/unknown
counts, unresolved wire obligations, task join results, and the first teardown
cause.

Rust `Drop` is not a reliable protocol operation. Dropping the last handle
triggers best-effort admission closure and shutdown, and request futures still
receive typed termination, but only `close().await` guarantees teardown and
protocol attempts are complete.

## Verification contract

Replacement of the old worker requires:

- pure reducer property tests over arbitrary response, cancel, timeout, close,
  and failure orderings;
- invariant checks that caller completion is at most once and every credit,
  permit, payload owner, tombstone, and sender is released exactly once;
- deterministic clock plus fake read/write pump adapters;
- cancellation and failure injection at every partial-write cursor position;
- early-response-before-write-completion and late-response cases;
- independent compound-member outcomes;
- deadline heap and generation failure on tombstone expiry;
- pump, owner, and preparation panic with bounded shutdown;
- loom models for channel closure, future Drop, terminal sender, and task exit;
- copy/allocation and in-flight-memory budgets from ADR-0001;
- FAS2750 concurrency, cancellation, disconnect, and automatic-recovery UAT.

Tests cross the runtime interface rather than inspecting or mutating owner
maps. The reducer and fake adapters are internal seams, not peer public modules.
