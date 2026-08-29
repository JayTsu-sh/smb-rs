# W2-3 sealed signing and partial-write cursor

## Scope

- Ticket: #42
- Wave: W2 — Replace the wire data plane
- Depends on: W2-2 evidence `1dbfa87`
- Implementation: `18c96a1`
- Validation date: 2026-08-29

This ticket makes outbound protection and transport consume immutable segment
owners. `WireBuilder` now enforces `Encoded -> OffsetsFinalized -> Protected ->
sealed`, where protection is completed explicitly as signed or unsigned.
Signing traverses metadata and payload chunks directly and the builder permits
only ordered 16-byte SMB header signature patches. Ordinary signed writes no
longer thaw metadata for the legacy `IoVec` signer.

Transport accepts only an immutable `SendFrame`. Its private `SendCursor`
tracks the four-byte framing header, segment index, and intra-segment offset
without mutating or consolidating the message. TCP drives `write_vectored` in
an explicit async short-write loop and returns typed errors for zero progress,
cursor bounds, and segment-capability overflow.

## Functional and budget evidence

- State tests reject sealing before protection, incomplete signing, skipped or
  duplicate signature patches, and conversion of a partially signed message
  to unsigned.
- Signature tests prove segmented and contiguous algorithms produce the same
  signature and that only header bytes 48 through 63 change.
- A signed `Bytes` payload retains its owner and pointer through sealing; the
  existing 1 MiB copy-budget gate still records zero payload copies and zero
  payload-sized allocations.
- Cursor tests cover every byte position across framing, empty segments,
  segment boundaries, and segment interiors. Scripted writes cover maximum
  progress sizes 1 through 15, zero writes, and faults after partial frames.
- Plain signed paths cannot reach `IoVec::consolidate`. Compression and
  encryption consume-and-replace consolidation remains explicitly assigned to
  W2-4.

## Local validation

| Category | Result |
| --- | --- |
| workspace compile | Passed |
| message codec | Passed: 131 unit, 1 documentation test |
| sealed builder state tests | Passed: 8 |
| transport with test support | Passed: 18 unit, 8 integration tests |
| SMB library | Passed: 19 |
| lifecycle scenarios | Passed: 7 |
| offline SMB conformance | Passed: 6 |
| validation and budget infrastructure | Passed |
| all SMB test targets compile with test support | Passed |
| strict clippy on production libraries | Passed with warnings denied |
| architecture dependency checker | Passed: 0 violations |
| changed-diff and secret scan | Passed |

The full test-target clippy command additionally reports pre-existing warnings
in legacy codec test fixtures; production libraries are clean under
`-D warnings`, and no new test warning originates from this ticket.

## Isolated real-target validation

The manifest was bound to implementation commit `18c96a1`. Runtime credentials
used one-shot descriptors and are absent from the manifest and repository.

| Gate | Result |
| --- | --- |
| plain 1 MiB immutable write/read, byte-for-byte verified | Passed |
| encryption-required 1 MiB immutable write/read | Passed |
| plain signed three-member compound Create/SetInfo/Close | Passed |
| plain 4-stream verified 64 KiB path | Passed: write 10.235 MiB/s, read 16.348 MiB/s |
| plain 4-stream verified 1 MiB path | Passed: write 10.410 MiB/s, read 18.584 MiB/s |
| encrypted 4-stream verified 64 KiB path | Passed: write 5.918 MiB/s, read 7.850 MiB/s |
| encrypted 4-stream verified 1 MiB path | Passed: write 6.045 MiB/s, read 4.476 MiB/s |

An exploratory compound request on the encryption-required share returned a
typed access denial. It is outside W2-3's plain signed compound gate and is
carried into W2-4 as a transform-composition regression case.

The isolated plain share, encrypted share, and volume were deleted through the
exact manifest inventory. All three resources are `Deleted`; retained-resource
count is zero and the post-cleanup pre-existing-state hash is unchanged.

## Rollback

Revert this evidence commit and then `18c96a1`. No appliance rollback is
required. W2-2 remains an independent accepted checkpoint. W2-4 must preserve
the sealed signing and cursor invariants while replacing transform
consolidation with consume-and-replace ownership.
