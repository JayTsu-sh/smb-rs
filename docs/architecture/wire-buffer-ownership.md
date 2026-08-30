# Wire buffer ownership model

## Status and scope

Accepted design for the codec/runtime/transport byte seam. It refines the module
direction in `target-module-boundaries.md` and implements the budgets in
ADR-0001. Exact Rust names may change, but the ownership states, allowed
mutations, copy limits, and dependency direction are fixed.

## Ownership spine

```text
typed wire request
  → WireBuilder { metadata: BytesMut, payloads: Bytes segments }
  → offsets/padding/signature finalized
  → WireMessage { metadata: Bytes, payloads: Bytes segments }
  → optional TransformFrame(Bytes)
  → transport-private SendCursor

transport adapter
  → TransportFrame(Bytes)
  → optional TransformFrame(Bytes)
  → DecodedFrame { owned metadata, validated WireRange values, frame owner }
  → typed domain result + Bytes payload slices
```

There is one authoritative byte owner at every state. A successful transform
replaces its source representation. A view never owns a second payload, and an
outbound request does not retain file payload after its frame has been sent.

## Outbound types and states

`WireBuilder` is runtime-internal mutable construction state. It owns one
metadata arena and immutable shared payload segments. Its interface permits
codec writes and narrowly scoped header patches; it does not implement general
mutable dereference and does not expose consolidation.

For a single message, the arena contains its header and encoded body metadata.
A compound uses one arena for every member's metadata, `NextCommand` fields,
and 8-byte alignment padding. Each member records ranges into that arena and
references its own payload segments. Padding is part of the signed member range
and never receives a separate heap segment.

The allowed pipeline is:

```text
Encoded
  → OffsetsFinalized
  → Signed | Unsigned
  → Compressed | Plain
  → Encrypted | Plain
  → Framed
```

The runtime owns these transitions. Callers cannot assemble arbitrary boolean
combinations or reorder protection stages. Signing and preauthentication hash
consume the same chunk iterator later used by transport, so they observe exact
wire bytes. They may patch only the independently owned header range and may
not re-encode or consolidate the message.

Sealing freezes the metadata arena and returns `WireMessage`, whose segments
are immutable `Bytes`. A transport adapter receives only this sealed form. It
tracks partial vectored writes with a private, short-lived `SendCursor` holding
segment index and byte offset; advancing a send never mutates the message.

The runtime compares the segment count with an immutable transport capability
before admission. If a compound would exceed the adapter's vectored-write
limit, the scheduler splits it into multiple protocol-valid compounds. Copying
payload into a contiguous buffer is not a fallback.

## Transform ownership

Encryption and compression consume `WireMessage` and produce one continuous,
immutable `TransformFrame(Bytes)`, matching the one-transform-buffer allowance.
Their conceptual result is:

```text
Applied(TransformFrame)
Bypassed(WireMessage)
Err(TransformError)
```

`Applied` releases the original segments. `Bypassed` first releases an
unprofitable temporary result and returns the original message. `Err` terminates
the operation and releases both input and scratch state. No result may expose
the source and candidate transform simultaneously.

## Inbound frame and views

The transport adapter validates its framing length against a configured hard
maximum before allocation and receives one complete frame into `Bytes`. The
runtime then applies negotiated limits, credit/window policy, and transform
envelope validation before codec decode.

Plain input follows:

```text
TransportFrame → DecodedFrame
```

Transformed input follows:

```text
TransportFrame → envelope validation → one transform buffer → DecodedFrame
```

`DecodedFrame<T>` owns the immutable frame, decoded fixed-size values, and
`WireRange` values for variable input. `WireRange` has a codec-private
constructor and is created only after checked offset-plus-length arithmetic,
member/frame containment, SMB-relative offset conversion, alignment, minimum
structure length, and compound-boundary validation.

Potentially large or server-controlled byte, string, security, directory, and
file-data fields remain ranges. Fixed scalars and small bounded protocol values
become owned typed metadata. Decode is atomic: failure returns a typed codec
error containing field, offset, and reason, never a partial message or retained
payload.

Compound members share the frame owner and carry member-relative validated
ranges. Runtime delivery may create `Bytes::slice` values for individual
results; retaining a small zero-copy slice can therefore retain its negotiated-
size frame. That is an explicit zero-copy interface cost. Slice-based domain
operations copy into the caller buffer and do not retain the frame. Background
caches may not retain arbitrary wire views.

## Module interfaces

The codec exposes the conceptual operations:

```text
encode(typed_wire_value, immutable_context) → WireBuilder
decode(TransportFrame, immutable_context) → DecodedFrame<T>
```

The immutable context supplies dialect, capability, and decode limits. The
codec performs no registry lookup, I/O, locking, async work, signing,
encryption, compression, credit accounting, cancellation, or transport
framing. The domain receives typed metadata and `Bytes` payloads, not arenas,
ranges, segment indices, framing limits, or transport capabilities.

The runtime attaches payload only through constraints emitted by encoding; it
cannot manually patch arbitrary offsets. This keeps the codec a deep module:
offset and layout correctness remains local while callers learn only typed
encode/decode and immutable byte ownership.

## Cancellation and payload lifetime

The connection runtime is the sole outbound payload owner after submission:

- cancellation before transport admission drops the message immediately;
- cancellation before any byte is written safely releases the message;
- after a partial write, the adapter completes the frame or terminates the
  connection and reports `Outcome unknown`;
- after a complete send, outbound file payload is released immediately;
- pending response state retains request metadata, not the sent payload.

Payload memory is bounded by the admitted window and negotiated chunk size,
not total file length. Input length is checked before allocation at transport,
runtime, and codec layers.

## Safety and verification

The initial production ownership path contains no unsafe code. `Bytes` is the
single shared byte representation because it provides real integration leverage
across codec, runtime, and Tokio transport; a generic buffer seam has no second
adapter and is rejected.

Verification includes:

- property and fuzz tests over offsets, lengths, padding, and compound chains;
- golden-wire comparisons after logically concatenating encoded segments;
- ADR-0001 payload-copy and allocation counters;
- an adapter that exercises every partial vectored-write position;
- cancellation at every send-cursor position;
- retained-frame and in-flight-window memory bounds;
- Miri checks for builder sealing, slicing, and range handling;
- tests through codec/runtime interfaces rather than internal fields.

Future unsafe optimization requires a separate ADR, quantified evidence that
this model cannot meet a hard budget, and dedicated Miri, loom, and fuzz proof.
