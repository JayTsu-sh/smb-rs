# W2-1 immutable receive frames and validated ranges

## Scope

- Ticket: #40
- Wave: W2 — Replace the wire data plane
- Depends on: W1 checkpoint `070fb3d`
- Tested implementation: `f737978`
- Validation date: 2026-08-29

This ticket establishes the receive-side ownership seam without introducing W3
runtime authority. Direct TCP reads validate the announced length before body
allocation and freeze the body into one `TransportFrame(Bytes)`. Codec decode
retains an immutable owner in `DecodedFrame<T>` and constructs `WireRange` only
after checked containment, minimum-offset, and alignment validation.

## Migrated production path

`ReadResponse` no longer exposes its server-controlled offset and length.
File slice reads, caller-buffer reads, and pipe reads request a validated range
from the codec. `Bytes` reads slice the immutable owner without copying; slice
reads perform only the API-required copy into the caller buffer. Plain and
decrypted/decompressed responses enter through the same atomic frame decode.

The current connection worker converts `TransportFrame` to its underlying
immutable `Bytes` through a stateless compatibility seam. It does not copy or
register the payload. Outbound builders, signing, send cursors, and remaining
variable response fields belong to later W2 tickets; request lifecycle remains
W3 and is not claimed here.

## Validation

| Category | Result |
| --- | --- |
| message codec | Passed: 123 unit, 1 documentation test |
| transport with test support | Passed: 15 unit, 7 scripted integration tests |
| SMB library | Passed: 18 |
| offline SMB conformance | Passed: 6 |
| strict library clippy for changed crates | Passed |
| architecture dependency checker | Passed: 0 violations |
| range property/table space | Passed: checked arithmetic, exact end, empty, overflow, minimum offset, alignment, and member escape |
| pre-allocation frame cap | Passed: oversized announced frame rejected before body read |
| secret and endpoint scan | Passed: no matches |

Workspace-wide all-target clippy is not used as this ticket's gate because it
reports pre-existing redundant-static-lifetime warnings in unrelated historical
test constants. All changed library targets and all new tests pass with warnings
denied where applicable.

## Real-target evidence and cleanup

The tested commit passed full create/write/verified-read/metadata/delete
lifecycle on an isolated plain share and on an isolated encryption-required SMB
3.1.1 share. Runtime inputs used one-shot descriptors. Both shares and their
dedicated volume were then removed by the hash-bound manifest cleanup; retained
resource count is zero and the pre-existing-state hash is unchanged.

An earlier attempt against the pre-existing shared fixture authenticated but
was denied share access. It is not reported as a product failure or a passed
gate; the authorized isolated run is the acceptance evidence.

## Rollback

Revert the evidence commit, then `f737978`. No appliance rollback is required.
W1 remains valid. W2-2 may proceed only while this receive ownership seam or an
equivalent validated immutable-frame Interface remains present.
