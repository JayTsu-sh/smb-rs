# W4-2 Connection generation recovery acceptance

## Accepted implementation

The accepted implementation is `9e3167f`, built from the prerequisite commits
`5653f32`, `31b0dcd`, `db27a07`, `9551d9b`, `3df2580`, `945eb95`, `e2b7868`,
`2d697b8`, `1dea3f5`, `685ed46`, `febe326`, and `db21168`.

Connection recovery now has one async owner. A pure reducer controls bounded
attempts, per-attempt and total deadlines, exponential backoff, injected
jitter, and first-wins close/fatal transitions. The old generation publishes a
typed exit only after both transport pumps have joined. A replacement is
negotiated completely and then publishes its worker and connection information
as one atomic snapshot, so no caller can observe a half-published generation.

Only operations depending directly on the lost Connection may enter the
bounded recovery queue. The queue has stable FIFO release, exact deadline and
cancellation removal, replacement-token publication, and failure draining.
Session, Share, and Resource dependencies remain generation-bound and cannot be
silently correlated or replayed across generations. Explicit close wins a
transport-exit race and Connection close remains idempotent after the owner has
terminated.

## Local gates

| Gate | Result |
| --- | --- |
| recovery reducer/driver tests with test support | Passed: 9 |
| default workspace tests and doctests | Passed |
| strict workspace production-library clippy | Passed with warnings denied |
| architecture checker | Passed: runtime activated, 0 violations |
| credential and endpoint scan | Passed |

Deterministic coverage uses scripted transports and a manual clock. It covers
successful replacement, bounded retry, attempt and total timeout, backoff,
close cancellation, stale exit rejection, one recovery owner, bounded FIFO
admission, deadline/cancellation removal, queue failure, replacement tokens,
and the explicit-close/transport-exit race.

## Isolated real-server validation

The final manifest was bound to `9e3167f` and plan hash
`d9050cd9ca60a42c901a1852369c37c8d6057a62b112b35756e64e677d6473ab`.
Runtime inputs used one-shot descriptors; no endpoint, account, credential, or
exact resource name is stored here.

| Gate | Result |
| --- | --- |
| transparent-proxy transport loss | Passed: early EOF and negotiated generation replacement |
| stale Resource after replacement | Passed: rejected before ordinary reuse |
| exact appliance CIFS-session disruption | Passed: exactly one session selected and closed |
| W4-2 Session boundary | Passed: typed signature-verification failure, no blind Resource reopen |
| plain 1 MiB immutable write/read | Passed: write 8.825 MiB/s, read 8.783 MiB/s |
| plain 4-stream 1 MiB | Passed: write 18.420 MiB/s, read 15.789 MiB/s |
| encryption-required 1 MiB immutable write/read | Passed: write 4.452 MiB/s, read 2.233 MiB/s |
| encrypted 4-stream 1 MiB | Passed: write 5.941 MiB/s, read 4.701 MiB/s |

The isolated volume, plain share, and encryption-required share all reached
`Deleted`; retained-resource count is zero and the pre-existing appliance state
hash was restored.

## Boundary and rollback

An appliance CIFS-session close may preserve the TCP connection. W4-2 treats
that as a typed Session-level boundary rather than fabricating a transport
failure. Session credential retention and reauthentication belong to W4-3;
TreeConnect recovery and Resource policy remain later W4 tickets.

Rollback starts with dependent W4 work, then reverts this evidence and the
accepted implementation commits above in reverse order. No appliance rollback
is required because all manifest-owned resources were deleted.
