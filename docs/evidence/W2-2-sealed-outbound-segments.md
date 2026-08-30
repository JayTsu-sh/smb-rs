# W2-2 sealed outbound metadata and payload segments

## Scope

- Ticket: #41
- Wave: W2 — Replace the wire data plane
- Depends on: W2-1 evidence `df5a816`
- Implementation: `df9f5b4`
- Permanent real-target gate: `704d04f`
- Validation date: 2026-08-29

This ticket replaces the two independent ordinary/compound serializers with
one codec-owned `WireBuilder`. It encodes member-relative offsets into a single
`BytesMut` metadata arena, patches compound `NextCommand`, includes eight-byte
padding in member ranges, attaches only immutable `Bytes` payload segments, and
permits sealing only after offset finalization.

`WireMessage` exposes immutable ordered segment traversal, total length,
segment count, and validated compound member ranges. It exposes neither mutable
deref nor consolidation. The W2 compatibility adapter consumes the sealed
message, thaws only the small metadata segment for the legacy signer, and moves
payload `Bytes` unchanged into the existing connection path. W2-3 removes that
metadata thaw and moves signing/partial writes to the sealed segment Interface.

## Functional and budget evidence

- Ordinary Write and compound Create/SetInfo/Close use the same builder.
- Compound signing traverses and patches only each validated member slice in
  the one metadata arena.
- A 1 MiB `Bytes` write records zero payload copies, zero payload-sized
  allocations, no payload pointer change, and at most four net metadata
  allocations after measurement-harness normalization.
- The slice-write shape records exactly one copy and the exact copied byte
  count at the API boundary.
- Golden logical concatenation matches the established codec bytes.
- Tests cover empty payload, multiple payload order/identity, segment limit,
  exact compound alignment, and invalid builder transitions.

## Local validation

| Category | Result |
| --- | --- |
| workspace compile | Passed |
| message codec | Passed: 129 unit, 1 documentation test |
| transport with test support | Passed: 15 unit, 7 integration tests |
| SMB library | Passed: 19 |
| offline SMB conformance | Passed: 6 |
| validation and budget infrastructure | Passed: 48 executed tests; 3 authorized-device cases ignored by default |
| all SMB test targets compile | Passed |
| strict clippy on changed libraries/tests | Passed with warnings denied |
| architecture dependency checker | Passed: 0 violations |
| changed-diff and secret scan | Passed |

## Isolated real-target validation

The hash-bound run targeted the permanent gate commit. Runtime inputs used
one-shot descriptors. Results:

| Gate | Result |
| --- | --- |
| plain 1 MiB `Bytes` write and zero-copy read, byte-for-byte verified | Passed |
| encryption-required SMB 3.1.1 1 MiB `Bytes` roundtrip | Passed |
| signed three-member compound Create/SetInfo/Close and metadata verification | Passed |
| plain 4-stream verified 64 KiB and 1 MiB data paths | Passed |
| encrypted 4-stream verified 64 KiB and 1 MiB data paths | Passed |

Both isolated shares and their volume were deleted through the manifest-owned
cleanup. Retained-resource count is zero and the post-cleanup pre-existing-state
hash is unchanged.

## Rollback

Revert this evidence commit, `704d04f`, then `df9f5b4`. No appliance rollback
is required. W2-1 and W1 remain independent accepted checkpoints. W2-3 may
proceed only with this unique sealed-message Interface or an equivalent that
preserves the same copy and ownership evidence.
