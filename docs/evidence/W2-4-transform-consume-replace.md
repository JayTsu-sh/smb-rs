# W2-4 transform consume-and-replace

## Scope

- Ticket: #43
- Wave: W2 — Replace the wire data plane
- Depends on: W2-3 evidence `944e749`
- Transform implementation: `f016534`
- Share-encryption correction: `4c72c14`
- Validation date: 2026-08-29

This ticket completes the outbound ownership spine. `WireMessage` remains the
sole immutable owner for plain segmented traffic. Compression and encryption
consume that owner and return one immutable contiguous `TransformFrame`.
Transformer, worker/backend channels, and transport now exchange immutable
`SendFrame` values; the active async path no longer exposes or accepts an
`IoVec`, and the repository contains no call to `consolidate`.

The common protection pipeline is shared by ordinary and compound requests:
preauthentication and signing observe sealed plain segments, compression
writes directly into the final transform arena, encryption operates in place
after a reserved transform header, and transport framing is applied last.
Preauth raw bytes use `Bytes`; a single segment clones only its owner.

## Copy, allocation, and validation evidence

- Plain signed `Bytes` retains its payload pointer with zero payload copy and
  zero payload-sized allocation.
- The transition from segmented wire data to a transform input makes exactly
  one contiguous arena allocation with no reallocation.
- LZ4 writes directly into its final serialized transform owner, including a
  reserved encryption prefix. The 1 MiB gate observes no reallocation and
  less than two payload-sized allocations, rejecting a second transform
  output buffer.
- AES-GCM encrypts the final payload region in place; tampering fails
  authentication.
- Encrypted envelopes reject mismatched `OriginalMessageSize` and non-zero
  unused nonce bytes before plaintext parsing.
- Compressed envelopes reject oversized declared output before allocation,
  validate exact output sizes, and use typed errors instead of production
  panics.
- Unit tests prove compound member boundaries survive whole-chain encryption
  and compression is serialized inside encryption rather than outside it.

## Debugging finding and regression

The first device run showed that encrypted ordinary I/O passed while encrypted
compound returned `AccessDenied`. A minimal repeatable device loop reproduced
the same first-member failure twice. The cause was protection-policy loss:
ordinary requests pass through `TreeMessageHandler`, which applies the share's
`encrypt_data` flag, while the direct compound helper inspected only the
session policy. Encryption-required shares do not necessarily force the whole
session to encrypt.

The helper now composes `share_requires_encryption OR
session_requires_encryption` before considering signing. A focused local test
locks this precedence, and the original device loop plus the final hash-bound
matrix both pass. No temporary debug instrumentation remains.

## Local validation

| Category | Result |
| --- | --- |
| workspace compile | Passed |
| message codec | Passed: 133 unit, 1 documentation test |
| SMB library after regression fix | Passed: 25 |
| transport with test support | Passed: 18 unit, 8 integration tests |
| lifecycle scenarios | Passed: 7 |
| offline SMB conformance | Passed: 6 |
| wire/transform copy-budget tests | Passed: 4 |
| all SMB test targets compile with test support | Passed |
| strict clippy on production libraries | Passed with warnings denied |
| architecture dependency checker | Passed: 0 violations |
| changed-diff, temporary-debug, consolidation, and secret scans | Passed |

## Isolated real-target validation

The accepted manifest is bound to correction commit `4c72c14`. Runtime inputs
used one-shot descriptors and are absent from stored artifacts.

| Gate | Result |
| --- | --- |
| plain 1 MiB immutable write/read | Passed |
| encryption-required 1 MiB immutable write/read | Passed |
| plain signed compound Create/SetInfo/Close | Passed |
| encrypted whole-chain compound Create/SetInfo/Close | Passed |
| plain 4-stream 64 KiB | Passed: write 8.892 MiB/s, read 16.536 MiB/s |
| plain 4-stream 1 MiB | Passed: write 14.118 MiB/s, read 11.984 MiB/s |
| encrypted 4-stream 64 KiB | Passed: write 4.751 MiB/s, read 4.686 MiB/s |
| encrypted 4-stream 1 MiB | Passed: write 6.451 MiB/s, read 4.750 MiB/s |

The diagnostic run and final accepted run were independently cleaned. In the
accepted manifest the isolated volume, plain share, and encrypted share are all
`Deleted`; retained-resource count is zero and the pre-existing-state hash is
unchanged.

## Rollback

Revert this evidence commit, `4c72c14`, and then `f016534`. No appliance
rollback is required. W2-3 remains an independent checkpoint. The W2 accepted
checkpoint must retain the immutable ownership spine and all W2-1 through W2-4
gates before W3 changes request authority.
