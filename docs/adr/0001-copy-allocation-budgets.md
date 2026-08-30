---
status: accepted
---

# Define zero-copy through operation-specific budgets

The client uses operation-specific payload-copy, transform-buffer, and
allocation budgets instead of describing the whole implementation as
“zero-copy”. This makes ownership claims testable while recognizing that
kernel receive, slice adapters, encryption, and compression necessarily create
different memory behavior.

## Budgets

For plain signed SMB over TCP, the hot-path limits are:

| Operation | Payload copies | Payload-sized allocations | Metadata allocations |
| --- | ---: | ---: | ---: |
| `Bytes` write | 0 | 0 | at most 4 |
| slice write | 1 | 1 | at most 4 |
| `Bytes` read | 0 | 1 receive frame | at most 4 |
| slice read | 1 | 1 receive frame | at most 4 |

Signing must traverse scatter/gather segments and may modify an independently
owned header segment; it may not consolidate file payload. A compound request
may allocate one metadata arena, but its payloads remain shared segments or
ranges. A compound response may allocate one receive frame whose members are
views into that frame.

Each encryption, decryption, compression, or decompression step may allocate at
most one necessary transform buffer. A compression attempt that falls back to
plain data must release its unsuccessful output before dispatch and may not
retain two complete payload representations. Chained compression may not copy
the original payload per member.

Authentication is measured separately from file I/O because SSPI behavior may
change independently. Project-owned token canonicalization may allocate at most
one output buffer per round, and simultaneously retained token storage may not
exceed twice the negotiated token limit. Authentication records allocations,
allocated bytes, and peak memory, but its third-party allocation count is not a
cross-version hard limit.

## Measurement protocol

The fixed payload set is 0 B, 4 KiB, 64 KiB, 1 MiB, and 1 GiB. The concurrency
shapes are one connection with one request, one connection with 16 in-flight
requests, four connections with 16 in-flight requests each, and a full window
subjected to cancellation or timeout. Payload memory must remain
`O(window × negotiated chunk size)`, never `O(file size)`.

A test-only counting allocator attributes allocations from request-engine entry
until payload ownership returns to the caller. Runtime startup, connection
setup, logging, and the test framework are outside that scope; whole-process
peak RSS remains a second guard against moving allocations outside the tag.
Payload copies and payload-sized allocations are hard gates from the first
implementation wave. Metadata allocations must be recorded and monotonically
non-increasing for two waves, then become a hard limit of four per operation.

Hard acceptance uses a release build, pinned Rust toolchain and lockfile, and
disabled test logging. Every report records host CPU and memory, kernel, NIC,
ONTAP version, negotiated dialect, cipher, signing algorithm, and maximum SMB
read/write sizes. Each shape gets one discarded warm-up and at least five
measured runs. Reports use the median and nearest-rank p95; a coefficient of
variation above 10% invalidates the sample set rather than relaxing a gate.
Every run verifies all returned bytes and cleans up its files.

Plain signed TCP runs the full payload and concurrency matrix. Encryption runs
64 KiB, 1 MiB, and 1 GiB with one stream and 16 in-flight requests. Compression
runs compressible and incompressible 1 MiB and 1 GiB payloads with those same
windows. Compound tests use 4 KiB and 64 KiB members in groups of 2, 8, and 32.
Authentication runs independently for 20 repetitions.

Continuous integration enforces function, copy, allocation, and window-memory
budgets. Milestone validation on the FAS2750 enforces interoperability,
cancellation and disconnect cleanup, throughput, and RSS. The 1 GiB throughput
must remain at least 90% of the frozen baseline, and peak RSS must remain at
most 110%. Both environments must pass before an architecture wave is accepted.

## Consequences

Only a concrete operation may be called zero-copy, for example “plain signed
TCP `Bytes` write: zero payload copies.” The client as a whole, slice APIs, and
transform paths must not receive that label.

Budget exceptions require a separate time-bounded ADR recording the triggering
condition, additional byte and allocation limits, performance evidence,
affected paths, removal condition, and expiry milestone. Unknown or unbounded
copying cannot receive an exception.
