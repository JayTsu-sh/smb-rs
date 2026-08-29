# Target module boundaries and dependency rules

## Status

Accepted architecture decision for the `smb-rs` async redesign. This document
fixes module responsibilities, seams, ownership, and dependency direction. The
concrete byte ownership states are refined in `wire-buffer-ownership.md`; final
public method signatures remain a separate decision.

## Design objective

The target is a small number of deep modules with strict one-way dependencies.
Each module hides its implementation behind one interface that callers and
tests share. Runtime scheduling concepts must not leak into the public facade
or SMB domain objects.

```text
public facade
    ↓
SMB domain
    ↓
connection runtime
    ↓
wire codec
    ↓
async transport
```

An arrow means “may depend on”. Reverse dependencies and skipped-layer access
are forbidden. Shared protocol value crates may be imported where their value
types are part of the relevant interface, but they may not create a callback or
dependency in the opposite direction.

## Module map

### Public facade

The public facade is the sole stable external interface of the client library.
Its accepted domain-first shape is specified in `async-public-interface.md`.

Responsibilities:

- configure and create a client;
- establish authenticated share access;
- expose domain handles and high-level operations;
- make explicit close/shutdown available and awaitable;
- translate internal failures into the public typed error model;
- expose expert capabilities only through deliberate, narrow interfaces.

It does not expose or accept message IDs, credits, channel IDs,
`ReceiveOptions`, `AsyncMessageIds`, `Protection`, raw workers, transformers,
encoded wire messages, or transport objects in normal usage.

The facade may orchestrate connection/session/tree reuse, but cache mutation
must not hold a lock across network I/O. It does not become a second source of
truth for runtime lifecycle state.

### SMB domain

The SMB domain module expresses Connection, Session, Share, Resource, File,
Directory, Pipe, leases, and SMB operations in domain language.

Responsibilities:

- hold stable identities and immutable negotiated/share/open capability
  snapshots;
- enforce operation-level domain rules before submission;
- construct typed operations with their domain context and payload ownership;
- turn typed runtime responses into File/Directory/Pipe results;
- own optional domain policies such as lease-cache reuse;
- consume typed server events without blocking network progress.

Domain handles reference authoritative runtime state through opaque,
generation-aware tokens. They do not duplicate mutable validity state in
independent handler, transformer, and client registries.

The domain interface to the runtime is a typed operation, conceptually:

```text
Operation {
    command
    context token
    typed request metadata
    owned/shared payload
    deadline and cancellation
}
```

This is a conceptual shape, not the final Rust type. The public-interface and
request-engine prototype tickets will decide exact signatures.

### Connection runtime

The connection runtime is the single deep module responsible for asynchronous
progress and the complete request lifecycle of one physical SMB connection.

It owns:

- connection admission and shutdown state;
- negotiated connection state;
- SMB credit reservation and return;
- message-ID and async-ID bookkeeping;
- pending requests and terminal completion;
- timeout and cancellation coordination;
- response and unsolicited-notification dispatch;
- session/tree/open registry entries required for wire correctness;
- security transform selection and execution;
- transport send/receive tasks and every connection-scoped background task;
- deterministic failure of pending work and joining of owned tasks.

Its external interface accepts typed operations and returns one terminal typed
result. It hides send/receive pairing, worker channels, oneshots, sequencing,
transform ordering, and protocol CANCEL mechanics.

Internally the runtime may contain a state owner, scheduler, task group, and
wire transformation pipeline. These are internal seams for implementation
tests, not peer modules exposed to domain callers.

One physical transport connection has one connection runtime. A Session may
later associate with multiple runtime handles. Channel selection belongs to an
internal scheduler seam within the runtime module; the initial implementation
has only a primary-channel adapter and must not build a speculative full
Multichannel framework. The runtime's concrete single-owner task and request
model is fixed in `async-request-engine.md`.

### Wire transformation pipeline

Signing, pre-auth hashing, encryption, compression, and their inverses are an
internal part of the connection runtime implementation.

The pipeline:

- consumes codec output plus an already resolved protection policy;
- operates on owned/shared segments according to the operation's copy budget;
- calls crypto/compression algorithms through internal interfaces;
- never looks up mutable domain objects;
- never schedules I/O or completes requests;
- returns wire segments or a typed transform error to the runtime owner.

This placement preserves the useful property of the current `Protection`
decision—security treatment is sealed before transformation—without exposing
`Protection` as a public scheduling concept.

### Wire codec

The wire codec is synchronous, deterministic, and independent of runtime
state.

Responsibilities:

- encode typed SMB metadata into provided owned/shared output segments;
- parse framing payloads into strictly validated typed metadata plus ranges or
  slices for variable data;
- validate offsets, lengths, alignment, discriminants, compound chains, and
  dialect-specific wire constraints supplied explicitly as inputs;
- return typed codec errors.

The codec performs no I/O, locking, async work, session lookup, credit
accounting, cancellation, signing, encryption, compression, or task spawning.
It may use protocol value crates, but does not depend on the domain or runtime.

Codec parsing must not require a registry or callback into higher layers. Any
needed dialect/capability fact is an explicit immutable input.

### Async transport

The async transport module is a real seam because TCP, NetBIOS, QUIC, and RDMA
are distinct adapters.

Responsibilities:

- connect a configured endpoint;
- own transport-specific framing and handshake behavior;
- receive a complete framed payload into an owned buffer;
- send owned/shared byte segments with correct partial-write handling;
- report typed transport errors and endpoint information;
- split or otherwise support concurrent send/receive according to its adapter.

It does not understand SMB sessions, trees, resources, credits, message IDs,
signatures, encryption policy, or request completion. SMB-over-TCP/NetBIOS,
QUIC, and RDMA framing differences live in their adapters rather than a shared
default method that assumes the four-byte TCP header.

The transport interface remains async and may use enum dispatch or trait
objects internally; the exact dispatch mechanism is an implementation choice
unless copy/allocation measurement shows it affects the agreed budget.

## Domain event seam

Unsolicited server traffic crosses from runtime to domain as typed events.

The runtime must first perform protocol-mandatory work that cannot wait for a
consumer, including validation, authoritative registry updates, and timely ACK
when required. It then publishes a typed event such as lease break, oplock
break, or session closure.

Domain consumers cannot run on or block the receive loop. Queue capacity and
overflow behavior are defined per event family because not all notifications
have the same recoverability. A single “log and drop” policy is forbidden.

## Lease cache placement

Lease reuse, eligibility, tombstoning, eviction, and cache policy form a domain
module behind a narrow lease-cache interface. The module is used by Client and
Resource operations and consumes typed lease-break events.

The connection runtime owns only the open/session registry facts needed for
wire correctness and publishes protocol events. It does not own user-facing
cache policy. Coordination between cache invalidation and runtime open state is
explicit through typed commands/events, not shared HashMaps or cross-module
lock ordering.

## Extension modules

RPC pipes, DFS, security helpers, and similar facilities are upper-layer
extensions. They depend only on the public facade or SMB domain interface.
They may not directly access connection-runtime, codec, or transport
implementation details.

If an extension cannot be expressed through the domain interface, the missing
capability must be added at the appropriate seam. A special-case backdoor is
not an accepted substitute.

## Crate placement

The intended crate-level shape is:

```text
smb                  public facade + SMB domain + connection runtime
smb-msg              pure SMB wire codec
smb-transport        async byte transport adapters
smb-dtyp / smb-fscc  protocol value types
smb-rpc              upper-layer RPC abstractions
```

The public facade, domain, and runtime remain modules within `smb`; splitting
Worker, actor, transformer, or handler concepts into additional crates would
make internal seams public without creating caller leverage.

`smb-rpc` must use a public/domain pipe interface. `smb` may re-export or
provide convenience integration, but the architectural dependency may not
form a cycle or grant RPC access to runtime internals.

## Existing structure disposition

| Existing structure | Decision |
|---|---|
| `Client`, `Session`, `Share`, `File`, `Directory`, `Pipe` concepts | Preserve as domain vocabulary; the wire-level Tree terminology remains internal. |
| `File::read_block_bytes` / `write_block_zc` behavior | Preserve the payload-ownership leverage; names and placement may change. |
| `SessionInfo` state validation | Preserve the rigor; move lifecycle authority into the target runtime/domain state model. |
| `Protection` sealing | Preserve as an internal runtime-pipeline concept. |
| `smb-msg` and `smb-transport` crates | Preserve and narrow to their target responsibilities. |
| `MessageHandler` forwarding chain | Delete; replace with one typed domain-to-runtime operation seam. |
| `Worker` and `MultiWorkerBackend` | Delete; async request progress is the connection runtime implementation. |
| `SingleWorker`, threading backend, threading-model feature documentation | Delete as inactive historical structure. |
| `ConnectionActor` as a peer abstraction | Merge its authoritative state-owner behavior into the connection runtime; no separate peer actor seam. |
| `Transformer` as a registry-owning peer | Split/merge transformation behavior into the runtime's internal wire pipeline; remove its independent session registry. |
| public `ReceiveOptions`, `AsyncMessageIds`, channel selection, manual send/receive pairing | Remove from normal public interface; re-express only through deliberate expert operations if justified. |
| transport-wide default SMB-TCP framing | Move into the relevant TCP/NetBIOS adapters. |

## Enforceable dependency rules

1. Public facade code may import domain interfaces, not runtime implementation
   types.
2. Domain code may submit typed operations and receive typed results/events; it
   may not access wire buffers, transport adapters, credits, pending maps, or
   task handles.
3. Runtime code may call codec and transport interfaces; it may not call back
   into a domain handle to discover mutable state.
4. Codec and transport crates may share byte/value dependencies but may not
   depend on `smb`.
5. Transport adapters own framing; codec begins at an SMB message payload.
6. Only the runtime owner creates connection-scoped tasks. Every created task
   has an explicit shutdown condition and join path.
7. A mutable lifecycle fact has exactly one authoritative owner. Cached
   snapshots are immutable and generation-tagged.
8. Tests cross the same external seam as callers. Internal seams exist only
   where the runtime implementation genuinely varies or deterministic testing
   requires an adapter.

These rules should be enforced with Rust visibility and crate dependencies
first. Architectural tests or lint checks may supplement them where visibility
alone cannot express the constraint.

## Deliberately deferred decisions

- exact connection/session/tree/resource state enums and transition tables;
- transport enum dispatch versus object-safe traits;
- Multichannel scheduling policy beyond preserving the one-session-to-many-
  runtimes relationship;
- migration/implementation wave order.

Those decisions must respect the module direction and ownership fixed here.
