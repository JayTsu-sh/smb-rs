# Preparation-stage cancellation and crypto-permit deadlines

Date: 2026-09-23 (Asia/Shanghai)  
Scope: the P2 review finding concerning a request that expires while its
outgoing transform is waiting for a crypto permit, before `spawn_blocking`
starts. This is a source-and-primary-document review; no production code was
changed.

## Decision

The cancellation/deadline concern is **valid**, but it is a resource and
latency correctness gap rather than a wire, credit-accounting, or double-result
bug. A deadline rolls the uncommitted request back correctly; its transform
future nevertheless remains in `FuturesUnordered`, may later acquire a permit,
and will run payload signing before its result is discarded. The implementation
therefore fails the accepted architecture's explicit “checks cancellation before
and after execution” requirement.

Implement an owner-created, per-preparation `CancellationToken`, pass it to a
cancellation-aware crypto executor, and cancel/remove it whenever the reducer
rolls back an uncommitted preparation. Do **not** manufacture an
`INHERITED_ACE`-style result or otherwise turn a cancelled transform into a
successful wire frame. A blocking job that has already begun cannot be forcibly
stopped; the contract must distinguish that race and discard its result.

There is a separate architecture discrepancy to resolve in the same design:
the normal generation path is currently **not global** even though both the
architecture and `BoundedCryptoExecutor::default` say it is. `owner_task`
constructs `WirePipeline::with_crypto_parallelism`, and that constructor creates
a fresh semaphore. Thus every active connection gets up to its own configured
parallelism. The present P2 exists with either pool topology, but the claimed
process-wide CPU bound is not currently true.

## Observed lifecycle

1. `GenerationRuntime::execute_for_with_replay` calculates an absolute caller
   deadline and calls `RuntimeHandle::submit_operation`
   (`crates/smb/src/connection/generation_runtime.rs:147-185`). The latter waits
   for an acknowledgement before returning an `OperationTicket`
   (`crates/smb/src/runtime/engine.rs:321-345`). Consequently a domain caller
   cannot issue the existing key-based explicit cancellation while preparation
   is pending; deadline expiry is the practical preparation-stage terminal path.
2. The owner reserves credits, message ID, admission, and payload ownership,
   and schedules the deadline in `GenerationState::admit`
   (`crates/smb/src/runtime/state.rs:228-302`). A signed, sufficiently large
   operation is placed in `preparations` and calls
   `WirePipeline::transform_outgoing` asynchronously
   (`crates/smb/src/runtime/engine.rs:1428-1521`).
3. That transform delegates payload-sized signing to
   `BoundedCryptoExecutor::execute` (`crates/smb/src/runtime/wire.rs:517-663`).
   For work at least 64 KiB, it awaits `acquire_owned()` and only then invokes
   `spawn_blocking` (`crates/smb/src/runtime/crypto_executor.rs:43-65`). There
   is no cancellation argument or check on either side of the acquire.
4. Independently, the owner `select!` wakes at the deadline and calls
   `AdvanceTime` (`crates/smb/src/runtime/engine.rs:1258-1267`). For an
   uncommitted request the reducer publishes `TimedOut` and rolls back all
   reservations (`crates/smb/src/runtime/state.rs:394-445`).
5. The queued transform remains live. Once it completes,
   `finish_prepared_operation` sees that the request record was removed,
   returns `TimedOut` to the acknowledgement, and does not enqueue a frame
   (`crates/smb/src/runtime/engine.rs:1525-1549`). The existing unit test
   `completed_preparation_is_discarded_after_deadline_rollback`
   (`crates/smb/src/runtime/engine.rs:2892-2933`) tests only this *post-work*
   discard.

So accounting and no-send behavior are sound. The unaddressed interval is:

```text
admit → async prepare → wait semaphore → deadline rolls back
      → semaphore becomes available → spawn_blocking(sign payload) → discard
```

Tokio documents that `Semaphore::acquire_owned` is cancellation-safe (the
cancelled waiter loses its fair-queue position), making this wait safely
interruptible. [Tokio Semaphore: `acquire_owned`](https://docs.rs/tokio/latest/tokio/sync/struct.Semaphore.html#method.acquire_owned)
also documents FIFO fairness. Tokio separately documents that a started
`spawn_blocking` closure cannot be aborted; only a not-yet-started blocking task
may be prevented from starting. [Tokio `spawn_blocking`](https://docs.rs/tokio/latest/tokio/task/fn.spawn_blocking.html)
This is why the fix must prevent work *before* dispatch and tolerate completion
after it has started.

## Pool topology finding

`GLOBAL_CRYPTO_PERMITS` is a `LazyLock<Arc<Semaphore>>`, and `Default` borrows
it (`crates/smb/src/runtime/crypto_executor.rs:7-26`). However,
`WirePipeline::with_crypto_parallelism` calls `BoundedCryptoExecutor::new`,
which creates a separate semaphore (`crates/smb/src/runtime/wire.rs:84-89`;
`crates/smb/src/runtime/crypto_executor.rs:37-41`). The production owner calls
that constructor for every generation (`crates/smb/src/runtime/engine.rs:793-805`).

Therefore the review wording “global semaphore” is inaccurate for the current
production path. It should be corrected while fixing P2: production should use
the global executor, while a private/test injection seam supplies a local
one-permit executor for deterministic tests. `RuntimeConfig::crypto_parallelism`
can remain an inbound/preparation-capacity setting only if its meaning is
renamed/documented; it must not silently describe a global CPU cap.

## Recommended data flow

Keep cancellation ownership in the single connection owner; do not expose it
through the public domain API or make `WirePipeline` decide lifecycle state.

```text
owner admits key
  ├─ creates PreparationControl { cancellation: CancellationToken }
  ├─ stores it by RequestKey in RequestAuthority
  └─ passes a clone with the outgoing preparation to WirePipeline
        └─ BoundedCryptoExecutor::execute_cancellable(..., token, job)

owner processes Cancel / AdvanceTime / close
  └─ reducer emits uncommitted ReservationRolledBack(key)
        └─ remove + cancel PreparationControl(key)
              └─ acquire waiter returns without spawn_blocking
```

The executor should have an internal, typed `CancelledBeforeExecution` result;
it must not collapse this into a wire/cryptographic failure. Its required
sequence is:

1. check `token.is_cancelled()` before inline work or permit acquisition;
2. for offloaded work, `select! { biased; token.cancelled() => cancelled;
   permit = acquire_owned() => ... }`;
3. after acquisition, check again, drop the permit, and return cancellation;
4. capture a clone in the blocking closure and check immediately before calling
   `job`; after await, check again and return cancellation rather than a frame.

`CancellationToken::cancelled()` completes immediately when already cancelled
and is cancellation-safe; its docs also warn that cancellation itself is not
globally atomic. [Tokio-util `CancellationToken`](https://docs.rs/tokio-util/latest/tokio_util/sync/struct.CancellationToken.html)
Thus the linearization rule should be explicit: **if the owner processes the
terminal event before the executor's final pre-job check, the closure must not
call `job`; if the job has passed that check, it may finish, but its result is
never queued or acknowledged as successful.** No implementation can promise to
kill a CPU closure already running in `spawn_blocking`.

When `finish_prepared_operation` receives either a normal result or the typed
cancellation result, it removes the token-map entry. On close/fatal exit the
owner must cancel all remaining preparation tokens before dropping futures.
Dropping an awaited semaphore acquire removes the waiter safely, but dropping a
`JoinHandle` does not stop a started task ([Tokio `JoinHandle` cancellation
safety](https://docs.rs/tokio/latest/tokio/task/struct.JoinHandle.html)). The
current shutdown path drops `preparations` without joining them, so the broader
architecture promise “No preparation work is detached”
(`docs/architecture/async-request-engine.md:97-103`) also needs a deliberate
close policy: settle async waiters, and report/bound already-started CPU work
rather than claiming it was cancelled.

## Alternatives rejected

| Alternative | Why not recommended |
| --- | --- |
| Only discard in `finish_prepared_operation` | Current behavior; preserves protocol correctness but still executes expired payload crypto and delays live work in the semaphore's fair queue. |
| Abort the future / `spawn_blocking` handle | Cannot stop a started CPU closure according to Tokio; can incorrectly imply resource release. |
| Make the executor read `GenerationState` | Breaks single-owner state authority and couples a generic crypto facility to request records. |
| Check only before `acquire_owned` | Misses cancellation while queued, the exact P2 interval. |
| Treat cancellation as generic `PrepareFailed` | Loses terminal cause and risks publishing a preparation failure instead of the reducer's already-published timeout/cancel outcome. |

## Deterministic regression tests

Add a test-only executor hook/observer immediately before waiting for a permit;
avoid sleep-based timing. Use `BoundedCryptoExecutor::new(1)` and a blocking
first job held by a `Condvar`/`Notify`, as the existing permit-retention test
does (`crates/smb/src/runtime/crypto_executor.rs:152-197`).

1. **Cancelled while waiting:** wait until job A owns the sole permit and job B
   has reached the executor's acquire hook. Cancel B, await its typed cancelled
   result, release A, and assert B's closure-start counter is zero. Also assert
   that the permit is available after A finishes.
2. **Deadline end-to-end:** inject that one-permit wire executor into an owner
   test, submit a signed >=64 KiB operation, hold the first transform, advance
   `ManualClock` past B's deadline, and verify B's acknowledge is `TimedOut`,
   no B frame reaches scripted transport, B's closure never starts after A is
   released, and a following request can use rolled-back credits/admission.
3. **Post-start race:** let the executor announce that B entered its blocking
   closure, then cancel/deadline B before releasing its CPU gate. Verify the
   closure is allowed to finish, no frame is queued, and its permit remains held
   until completion. This documents the non-preemptible boundary rather than
   leaving it accidental.
4. **Close:** with B waiting on the permit, invoke close and verify B never
   starts. With B already started, verify the selected close report/timeout
   policy and that no result is sent after closure.

The current `ManualClock` already provides deterministic deadline advancement
(`crates/smb/src/clock.rs:74-126`); the missing seam is only controlled wire
executor construction for the owner test.

## Scope and priority

This is a legitimate P2: no SMB request is committed after the deadline, and
the reducer rolls back credits and payload accounting exactly once. Under
concurrent large signed traffic, however, expired transforms can consume CPU
and fair-queue capacity after the caller is terminal, producing avoidable
tail-latency and weakening the documented bounded-work/cancellation contract.
Fix the cancellation flow and the global-pool discrepancy together; then
separately decide the shutdown settlement/reporting contract for already-started
blocking work.
