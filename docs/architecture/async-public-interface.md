# Async public interface

## Status and objective

Accepted public-interface design for the async-only client. Exact Rust spelling
may be adjusted during implementation, but the capability hierarchy, ownership
semantics, copy contracts, lazy operation behavior, lifecycle outcomes, and
absence of request-engine details are fixed.

The interface is a deep facade over the SMB domain and connection runtime:

```text
Client → Session → Share → File | Directory | Pipe
```

`Tree`, `TreeId`, physical `Connection`, credits, message/async IDs, channel
selection, workers, protection stages, and manual send/receive pairing do not
appear in normal public use.

## Connecting and authentication

Common use connects directly to a share:

```rust,ignore
let client = Client::new();
let share = client.connect_share(target, credentials).await?;
```

Callers that intentionally reuse one authenticated identity may make Session
explicit:

```rust,ignore
let session = client.authenticate(server, credentials).await?;
let share = session.connect_share(name).await?;
```

Both paths return the same `Share` type and use the same single-flight cache and
runtime. The cache identity includes server identity, authentication identity,
transport/security policy, and share. Objects with different identities or
policies are never accidentally reused.

`Credentials` is an explicit variant for anonymous, NTLM, Kerberos, and future
methods. Secrets use a non-`Debug`, zeroizing container. A Session configured
for recovery owns one `CredentialProvider`, either static secret storage or an
async refresh provider, until close. Credentials are not copied into Share or
resource handles and never appear in errors, tracing, events, or diagnostics.

## Targets and paths

Connection accepts a validated `ShareTarget` containing server and share
identity. Once connected, resource methods accept only normalized,
share-relative `SharePath`. A SharePath cannot smuggle another server/share or
escape its root. DFS normalization and referral traversal remain Share/domain
behavior rather than caller string concatenation.

## Handle ownership

`Client`, `Session`, and `Share` are cheap `Clone` handles to one logical
identity. Closing any clone closes that identity and its descendant admission;
callers needing independent lifecycle create an independent Client or Session.

`File`, `Directory`, and `Pipe` do not implement `Clone`. Their positioned
methods take `&self` and are safe to call concurrently; callers make aliasing
explicit with `Arc` when needed. Resource state remains generation-aware, so a
parent close atomically stops descendant admission regardless of outstanding
Rust references.

Session and Share are stable logical handles that may atomically publish a new
active generation after automatic recovery. Ordinary resources remain bound to
their open generation and become `Revoked` after loss. Durable or persistent
files recover only through explicit open/replay policy; no ordinary resource is
silently reopened.

Public introspection returns immutable, redacted `SessionInfo`, `ShareInfo`, and
`OpenInfo` snapshots. Raw SessionId, TreeId, FileId, generation internals, and
channel IDs are gated diagnostics, never operation authority.

## Typed open operations

Normal open methods return the requested resource directly:

```text
Share::open_file(path, FileOpenOptions) → File
Share::open_dir(path, DirectoryOpenOptions) → Directory
Share::open_pipe(name, PipeOpenOptions) → Pipe
```

The option types prevent contradictory combinations and provide common presets.
Rare SMB flags live in an explicit advanced substructure. A restricted generic
open may exist for extension modules but is not in the normal prelude and does
not return an enum that every common caller must downcast.

`OpenInfo` records the server response at open time. It is not perpetual
authority for file size or metadata. `file.metadata().await` queries current
server state; positioned reads do not return local EOF solely because the open
snapshot is stale. Successful writes and set-length operations may update an
advisory snapshot without replacing server authority.

## Positioned and streaming I/O

The ownership-specific positioned methods are:

```text
read_at(offset, max_len)             → Operation<Bytes>
read_at_into(offset, &mut [u8])      → Operation<usize>
write_at(offset, Bytes)              → Operation<usize>
write_at_from(offset, &[u8])         → Operation<usize>
```

The `Bytes` variants carry the zero-copy contracts from ADR-0001; the slice
variants each allow one caller-boundary payload copy. Type, not a `zc` suffix,
communicates ownership. Like ordinary I/O, these methods may return short
results. `read_exact_at` and `write_all_at` provide complete-operation helpers.
Large zero-copy reads use `read_chunks(range) → Stream<Result<Bytes>>`; the
library never joins multiple receive frames into one payload allocation merely
to return a contiguous value.

`File` has no implicit mutable cursor. `file.cursor()` creates an independent
borrowed `FileCursor` implementing Tokio `AsyncRead`, `AsyncWrite`, and
`AsyncSeek` with `&mut self`. A caller needing a `'static` cursor explicitly
uses an `Arc<File>`-backed owned cursor. Positioned operations remain freely
concurrent and are not serialized through a client mutex; server/SMB semantics
determine conflicts.

## Lazy operations, deadlines, and cancellation

Every async domain method returns `Operation<T>`, a lazy future with no side
effect until first poll:

```rust,ignore
let bytes = file
    .read_at(offset, length)
    .deadline(deadline)
    .cancellation(token)
    .replay(policy)
    .await?;
```

Direct `.await` uses inherited defaults. An operation dropped before first poll
does nothing; after admission, Drop emits the request engine's deduplicated
cancellation event. Explicit `cancel().await` can wait for acknowledgement.
Caller code never sends SMB CANCEL or handles message IDs.

The core time limit is an absolute monotonic `Deadline` covering recovery wait,
admission, preparation, send, and response. `.timeout(duration)` is only a
convenience for deriving a deadline. Client defaults may be overridden by
Session, Share, and individual Operation without restarting the budget at each
layer.

Operations submitted during recovery and not bound to an old generation wait
within their deadline by default. Work already sent is never automatically
replayed. Unsent idempotent work may continue in the new generation. Durable
resource replay requires explicit `ReplayPolicy`; non-idempotent operations
default to no replay.

## Errors and outcomes

One non-exhaustive public `Error` exposes stable typed categories for
configuration/path, authentication, protocol/status, transport,
timeout/cancellation/backpressure, stale or revoked generation,
`OutcomeUnknown`, shutdown, and runtime termination. Codec, transform, request
engine, Tokio, SSPI, and transport implementation errors remain sources and do
not leak internal module names into the stable interface.

File, Directory, and Pipe close return `CloseOutcome`, distinguishing confirmed,
already closed, and outcome unknown. Session, Share, and Client close return an
aggregate `CloseReport` with descendant counts and the first teardown cause.
Concurrent close calls are idempotent and share one result.

Only `close().await` guarantees logical admission closure and awaited teardown.
Drop triggers best-effort shutdown without blocking, panicking, or promising a
wire Close/Logoff/TreeDisconnect. Closing a parent atomically closes descendant
admission before teardown; existing child `Arc`s cannot keep the logical subtree
active.

## Directories, events, batching, and transfer

`Directory::entries(query)` returns a cancellable
`Stream<Result<DirectoryEntry>>` and hides SMB pagination/resume keys. A collect
helper is available when callers intentionally want all entries in memory.

Client, Session, Share, and relevant resources expose typed event streams.
Events carry logical identity, generation, and typed cause, not raw handlers.
Lag is observable as `Lagged` or `StateResyncRequired`; correctness-critical
events are never silently dropped.

Public callers do not construct compound headers. A typed `Batch` accepts only
domain operations declared compound-compatible and uses typed references for
related results. Runtime may send a compound or split it. `BatchResult` reports
one outcome per input member; a dependent operation not executed after a prior
failure receives `DependencyFailed`. Only failure to encode or submit the batch
is an overall error.

Bulk copy uses `TransferOptions { concurrency, chunk_size, deadline,
cancellation, strategy }` and a Transfer future/progress stream. Callers express
performance intent, not channel IDs or worker maps. The scheduler selects
connections/channels, and server-side copy is an explicit or automatically
negotiated strategy behind the same transfer interface.

## Extension and export policy

There is no raw `send(Request)` public backdoor. FSCTL, IOCTL, security info,
RPC pipe, DFS, and similar expert features use narrow extension traits or
modules that still submit typed operations and obey lifecycle, protection,
cancellation, and copy budgets.

The crate root exports only facade/domain essentials:

```text
Client, Credentials, CredentialProvider,
ShareTarget, SharePath, Session, Share,
File, Directory, Pipe, typed open options,
Operation, Error, Result, Deadline, CancelToken,
core event, batch, and transfer types
```

Protocol values/messages, transport adapters, diagnostics, and extension traits
are accessed through explicit modules. The crate root no longer glob-reexports
whole protocol crates.

Handles are `Send + Sync`; operations and event/directory streams are `Send`.
Borrowed cursors remain tied to their File lifetime while owned cursors can cross
Tokio worker tasks.

No compatibility wrapper preserves the old public Connection, handler/channel,
manual cancellation, `ReadAtChannel`, or overlapping high/low-level paths. The
new facade replaces them in one intentional breaking architecture change.

## Verification

Public-interface tests compile and execute only through the exported facade.
They cover common and explicit-Session connection, typed opens, positioned and
cursor I/O, copy budgets, lazy unpolled operations, Drop cancellation, deadline
inheritance, concurrent close, stale/recovered generations, event lag, batch
partial outcomes, transfer cancellation, and Send/Sync assertions. Real ONTAP
UAT uses the same interface without diagnostic or raw-protocol escape hatches.
