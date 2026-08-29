# Current architecture, lifecycle, and byte-flow audit

## Scope

This document records the current implementation before the async architecture
redesign. It is an evidence snapshot, not the target design. It follows a normal
file read/write from the public interface through the transport, then inventories
ownership, background tasks, synchronization, lifecycle behavior, and byte
copies. The terminology “module”, “interface”, “seam”, “adapter”, “depth”, and
“locality” follows the repository's codebase-design discipline.

Audit baseline:

- `cargo check --workspace` passes on 2026-08-29.
- The inspected production trees contain about 24,700 Rust lines across
  `smb`, `smb-msg`, and `smb-transport`.
- The largest relevant files are `connection.rs` (1,490 lines),
  `client/smb_client.rs` (1,366), `resource.rs` (1,328),
  `connection/transformer.rs` (978), and `resource/directory.rs` (665).
- No allocation or throughput benchmark existed or was run for this audit;
  performance statements below identify code paths, not measured costs.

## Workspace modules and seams

| Module | Current interface | Implementation responsibility | Depth/locality observation |
|---|---|---|---|
| `smb` public client | `Client`, `Connection`, `Session`, `Tree`, `Resource`, `File`, `Directory`, read/write traits | Discovery, connection/session/tree caches, SMB lifecycle, leases, DFS, RPC pipes, I/O | Broad interface. High-level and low-level entry points expose overlapping capabilities and allow callers to bypass `Client`. |
| Domain handler chain | `MessageHandler::{sendo, recvo, notify}` plus eight composition helpers | Adds tree/session/channel fields and validates responses while forwarding each call | A shallow repeated interface: four concrete handlers mostly decorate and forward the same message. Policy is local to each layer, but request lifecycle is spread across all of them. |
| Connection request machinery | `ConnectionMessageHandler`, `Worker`, `MultiWorkerBackend`, `Transformer`, `ConnectionActor` | Credits/message IDs, pending response dispatch, transforms, notification fan-out, session/lease registries | Multiple overlapping seams survive from different migrations. Callers need knowledge from several modules, reducing locality. |
| `smb-msg` codec | `binrw` request/response structures and top-level `Request`/`Response` enums | Wire layouts and validation | Strong locality for fixed metadata. Variable payload ownership is inconsistent: some messages keep `Vec<u8>`, while file read/write have special offset/tail paths. |
| `smb-transport` | three object-safe traits returning `BoxFuture`, plus `IoVec` | TCP, NetBIOS, QUIC, RDMA adapters; framing and exact reads/writes | A real seam because several adapters exist. It also carries an SMB-TCP header assumption in the shared default methods, and heap-boxes each transport future. |

The workspace dependency direction is mostly `smb` → `smb-msg` and
`smb-transport`, but the runtime request behavior does not follow a comparably
simple module direction inside `smb`.

## Actual request flow

### Outgoing file write

```text
File::write_block_zc(Bytes)
  → ResourceHandle::sendo_recvo
  → TreeMessageHandler::sendo        (tree_id, share encryption)
  → SessionMessageHandler::sendo     (choose channel)
  → ChannelMessageHandler::sendo     (session_id, signing/encryption policy)
  → ConnectionMessageHandler::sendo  (credits, message_id)
  → ParallelWorker::send
  → Transformer::transform_outgoing  (encode, sign/compress/encrypt)
  → bounded mpsc<IoVec>
  → AsyncBackend send task
  → TcpTransport::send
  → HeaderAndIoVec / write_all_buf
```

The response returns through the receive task, `Transformer`, the worker's
`awaiting`/`pending` maps, and then the same handler chain in reverse for
connection-, channel-, and tree-level validation.

### Incoming file read

```text
TcpStream::read_exact
  → BytesMut::zeroed(frame_len)
  → freeze() as Bytes
  → Response::try_from(&[u8])
  → Transformer::transform_incoming_all
  → Bytes slices per compound member
  → worker dispatch by message_id
  → IncomingMessage { parsed response, raw: Bytes }
  → File::read_block_bytes returns raw.slice(payload range)
```

`File::read_block` deliberately adds one final copy into a caller-provided
`&mut [u8]`; `File::read_block_bytes` retains the network allocation and returns
a zero-copy `Bytes` slice.

### Where protocol policy is applied

Protocol policy is not concentrated behind one deep interface:

- `TreeMessageHandler` stamps `tree_id` and share-level encryption.
- `ChannelMessageHandler` derives protection from session state, stamps
  `session_id`, and verifies signed/encrypted responses.
- `ConnectionMessageHandler` reserves/returns credits, assigns message IDs,
  validates status/direction/command, and routes notifications.
- `Transformer` encodes, hashes pre-auth messages, signs, compresses, encrypts,
  parses, decrypts, decompresses, and verifies signatures.
- `ParallelWorker` owns pending-response routing and compound dispatch.

The deletion test shows that the tree and channel decorators contain real
protocol policy, but the uniform three-method `MessageHandler` interface does
not hide request lifecycle complexity: special paths call
`prepare_outgoing`, `dispatch_outgoing`, `send_compound`, `send_cancel`, or
`recvo_internal` directly.

## Ownership graph

```text
Client
  ├─ RwLock<HashMap<IP, ClientConnectionInfo>>
  │    ├─ Arc<Connection>
  │    └─ HashMap<session_id, Arc<Session> + alternate Arc<Connection>s>
  └─ Mutex<HashMap<UNC, ClientConnectedTree>>
       ├─ Arc<Session>
       └─ Arc<Tree>

Connection
  └─ Arc<ConnectionMessageHandler>
       ├─ OnceCell<Arc<ParallelWorker<AsyncBackend>>>
       ├─ ConnectionActorHandle
       └─ credits / negotiation / notification state

Session
  ├─ Channel → Arc<ChannelMessageHandler> → Arc<ConnectionMessageHandler>
  ├─ alternate Channel map
  └─ Arc<SessionMessageHandler> → channel-handler map

Tree
  └─ Arc<TreeMessageHandler> → Arc<SessionMessageHandler>

ResourceHandle
  └─ Arc<TreeMessageHandler>
```

This chain intentionally lets a resource keep its connection/session/tree
alive after `Client` is dropped. It also means lifecycle ownership and cleanup
ownership differ: the public object holding an `Arc` is not necessarily the
module that owns the background task or sends the protocol close.

Two registries contain session knowledge: `ClientConnectionInfo.sessions`
owns public `Session` objects, while `ConnectionActor.sessions` stores weak
`ChannelMessageHandler` references for notification routing. Transformer keeps
a third `sessions` map for cryptographic state. Each has a distinct purpose,
but their ordering contract spans modules rather than living behind one
interface.

## Existing state models

The session is the only lifecycle represented by an explicit enum:

```text
Initial → SettingUp → Ready → Invalid
```

`SessionInfo` validates several transitions, and `ChannelInfo` has a separate
`valid` flag. Other lifecycles use sentinel combinations:

- connection: `worker: OnceCell<Option>` plus worker `stopped: AtomicBool`;
- tree: `tree_id == u32::MAX` means disconnected;
- resource: `open: AtomicBool` guards an immutable `FileId`;
- request: membership in `awaiting` or `pending`, plus caller-held receive
  future and optional `AsyncMessageIds` atomics;
- notification tasks: shared cancellation token without stored task handles;
- actor: existence of sender clones determines shutdown.

Because these representations are independent, there is no single connection
state transition that atomically closes admission, fails pending requests,
stops notification/lease tasks, stops I/O, invalidates sessions/trees/resources,
and joins every task.

## Tasks, channels, and locks

### Long-lived connection tasks

A normal TCP connection can create:

1. `ConnectionActor::run`, with a bounded command mailbox of 64;
2. the async backend receive task;
3. the async backend send task, with a bounded data mailbox of 100;
4. the unsolicited-notification task, with a bounded mailbox of 10;
5. the lease-break listener using a broadcast channel of 64.

Only the backend stores `JoinHandle`s. The actor and notification/lease tasks
exit through sender lifetime or cancellation but are not joined by their
owner. Directory watch and copy helpers create further per-operation tasks.

### Shared mutable state

- `Client` serializes share-cache access with one `Mutex` and connection-cache
  access with one `RwLock`; several methods perform async work around these
  caches, so lock scope must be checked per call.
- `ConnectionMessageHandler` uses atomics/semaphore for message IDs and credits,
  `OnceCell` for negotiated/worker state, and an actor for lease/session maps.
- `ParallelWorker` puts both `awaiting` and `pending` maps behind one async
  `Mutex`, shared by receive dispatch and every waiter registration.
- `Transformer` has its own session `RwLock<HashMap>`, config `RwLock`, and
  pre-auth-hash `Mutex`.
- `Session` has separate channel registries in `Session` and
  `SessionMessageHandler`; cryptographic session state uses another `RwLock`.

The connection actor deepens lease-table mutations, but it does not own the
request lifecycle, credit state, worker, transformer sessions, or task group.
It therefore adds a mailbox and oneshot per lease/session registry operation
without becoming the connection's single lifecycle owner.

## Cancellation, timeout, and shutdown observations

These are current behavior/risk observations for later state-machine design,
not fixes made by this audit:

1. `Worker::receive` calls the first `receive_next` without the cancellation
   wrapper. The optional cancellation token is observed only after an initial
   `STATUS_PENDING` response. A request waiting for its first response is not
   cancellable through that option.
2. A receive timeout drops the oneshot receiver but leaves its sender in the
   worker's `awaiting` map until a response arrives or the receive loop exits.
   There is no timeout/cancel removal transaction keyed by message ID.
3. Cancellation ends the local wait but does not automatically send an SMB
   CANCEL; callers must separately retain `AsyncMessageIds` and call
   `ResourceHandle::send_cancel`.
4. Credits are reserved before transform and enqueue. Credits are returned only
   in `ConnectionMessageHandler::process_sequence_incoming`; transform, enqueue,
   timeout, or cancellation failure paths do not visibly roll the reservation
   back at the same seam.
5. The receive loop drains `awaiting` with `ConnectionStopped` on exit, but
   stored `pending` responses are not explicitly cleared there.
6. send-loop and receive-loop errors are mostly logged and retried. Only selected
   transport disconnect errors cancel the shared backend token, so terminal vs
   recoverable error classification is distributed.
7. `Drop` for connection, session, tree, and resource uses `tokio::spawn` for
   best-effort wire cleanup. Dropping outside an active Tokio runtime can panic;
   shutdown completion is not observable, and cleanup can race a stopped worker.
8. `ConnectionActor` starts in `ConnectionMessageHandler::new`, before transport
   connect succeeds, and has no explicit stop/join interface.

## Byte ownership and copy inventory

### Plain TCP write using `File::write_block_zc`

| Stage | Allocation/copy behavior |
|---|---|
| Caller to `Bytes` | No payload copy when caller already owns `Bytes`. `write_block(&[u8])` performs one `Bytes::copy_from_slice`. |
| Encode metadata | One growable owned `Vec<u8>` for SMB header/body. |
| Attach payload | `Bytes` is appended as a shared `IoVec` segment; clones are refcount-only. |
| Signing | Hashes metadata and payload segments; patches header in owned segment without consolidating payload. |
| Worker mailbox | Moves `IoVec`; no payload clone on the normal path. |
| TCP adapter | Stack-allocates four-byte framing header and uses `write_all_buf` with vectored chunks. No user-space payload consolidation in this path. |

This is already a credible zero-copy payload path from caller-owned `Bytes` to
the kernel boundary for plain or signed single-message TCP writes.

### Plain TCP read using `File::read_block_bytes`

| Stage | Allocation/copy behavior |
|---|---|
| TCP receive | Allocates and zero-initializes one `BytesMut` sized to the frame, then `read_exact` fills it. |
| Parse | `Response::try_from(&[u8])` parses metadata; message fields containing owned `Vec` may allocate, but file `ReadResponse` stores only offset/length. |
| Dispatch | `Bytes` moves through transformer/worker; compound members use refcounted slices. |
| Public result | `read_block_bytes` returns a `Bytes::slice` of the frame allocation. `read_block` adds one copy into the caller buffer. |

The read payload has one network receive allocation and no subsequent payload
copy on the `Bytes` interface. It is not kernel-to-caller zero-copy: Tokio reads
socket bytes into a newly allocated user buffer.

### Known consolidation or transform paths

- `return_raw_data` creates a contiguous copy of the entire outgoing `IoVec` for
  pre-auth consumers.
- compression consolidates all segments, then produces another encoded buffer.
- encryption is in-place over mutable/owned segments where supported, but adds
  an encryption header and necessarily transforms payload bytes.
- decryption and decompression return new `Vec<u8>` allocations which are then
  wrapped as `Bytes`.
- compound requests allocate one `Vec` per member, rewrite headers, pad, and
  exclude `additional_data`, compression, and encryption in the current path.
- many non-file variable wire fields remain `Vec<u8>` in `smb-msg`; zero-copy is
  a targeted exception rather than a codec-wide ownership model.
- `IoVecBuf` implements `DerefMut` but panics for `Shared(Bytes)`, making a
  variant-dependent runtime precondition part of its interface.

## Scattered or overlapping abstractions

1. **Async-only implementation behind generic historical seams.**
   `worker.rs` always aliases `ParallelWorker<AsyncBackend>`, while
   `MultiWorkerBackend` abstracts a second execution model that is no longer
   selected by Cargo features. `single_worker.rs`, `threading_backend.rs`, and
   `connection/README.md` describe obsolete sync/multi-threaded variants.
2. **Handler chain plus direct escape hatches.** The same request can travel
   through the generic handler interface or bypass portions via compound,
   setup, cancel, and internal receive paths. The effective interface is much
   larger than the three trait methods imply.
3. **Actor beside worker rather than instead of shared ownership.** The actor
   owns registry maps, the worker owns request maps, the transformer owns crypto
   session maps, and the connection handler owns credits and task cancellation.
4. **Duplicated lifecycle registries.** Client, session handler, connection
   actor, and transformer each retain a different view of sessions/channels.
   Their consistency is enforced by call ordering across modules.
5. **Public domain objects expose transport scheduling concepts.** Channel IDs,
   `ReceiveOptions`, `AsyncMessageIds`, explicit cancel messages, and compound
   preparation leak request-engine knowledge upward.
6. **Drop is an implicit async interface.** Four types promise best-effort wire
   cleanup through spawned tasks, even though Rust `Drop` cannot report or await
   completion.
7. **Documentation and configuration disagree.** Repository guidance and the
   connection README still advertise three threading models, but current Cargo
   features and compiled aliases implement Tokio async only.

## Modules that already provide useful depth

- `File::read_block_bytes` and `File::write_block_zc` hide wire offsets and
  scatter/gather details behind small payload-oriented interfaces.
- `TcpTransport::send` hides partial vectored-write retry behavior behind the
  transport seam.
- `SessionInfo` concentrates the one explicit lifecycle and cryptographic
  transition validation currently present.
- `ConnectionActor` gives lease mutations a typed serialized interface and
  removes lock ordering from its callers, even though its scope is narrower
  than the overall connection lifecycle.
- `Protection` seals the sign/encrypt decision before transformation and removes
  some mutable-state inference from the transformer.

These are preservation candidates for later design decisions; this audit does
not require retaining their current types or placement.

## Facts the next decision tickets can rely on

- The code is already compiled as Tokio async-only; removing historical worker
  generality is not a compatibility migration between active implementations.
- Plain single-message TCP file payloads already avoid payload copies when the
  caller uses `Bytes`; the larger zero-copy problem is interface consistency,
  codec ownership, transformed/compound paths, and measurement.
- The primary rigor gap is not absence of all state validation. It is the lack
  of one owner and one transition model for request admission, credits, pending
  responses, cancellation, timeout, connection shutdown, and task joining.
- The current handler interface offers limited depth because important callers
  must understand and bypass its ordering rules.
- Performance work must distinguish payload copies from metadata allocations
  and mandatory cryptographic/compression transforms.
- Subsequent architecture work needs an explicit answer for whether cleanup is
  guaranteed by awaited close, best-effort on drop, or both with clearly
  different contracts.

## Primary code references

- [`client/smb_client.rs`](../../crates/smb/src/client/smb_client.rs)
- [`connection.rs`](../../crates/smb/src/connection.rs)
- [`connection/actor.rs`](../../crates/smb/src/connection/actor.rs)
- [`connection/transformer.rs`](../../crates/smb/src/connection/transformer.rs)
- [`connection/worker/parallel/base.rs`](../../crates/smb/src/connection/worker/parallel/base.rs)
- [`connection/worker/parallel/async_backend.rs`](../../crates/smb/src/connection/worker/parallel/async_backend.rs)
- [`session.rs`](../../crates/smb/src/session.rs)
- [`session/channel.rs`](../../crates/smb/src/session/channel.rs)
- [`session/state.rs`](../../crates/smb/src/session/state.rs)
- [`tree.rs`](../../crates/smb/src/tree.rs)
- [`resource.rs`](../../crates/smb/src/resource.rs)
- [`resource/file.rs`](../../crates/smb/src/resource/file.rs)
- [`msg_handler.rs`](../../crates/smb/src/msg_handler.rs)
- [`smb-msg/file.rs`](../../crates/smb-msg/src/file.rs)
- [`smb-transport/traits.rs`](../../crates/smb-transport/src/traits.rs)
- [`smb-transport/iovec.rs`](../../crates/smb-transport/src/iovec.rs)
- [`smb-transport/tcp/transport.rs`](../../crates/smb-transport/src/tcp/transport.rs)
