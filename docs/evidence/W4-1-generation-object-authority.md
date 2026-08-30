# W4-1 generation-aware object authority acceptance

## Accepted implementation

The accepted implementation is `74e1d20`, with prerequisite commits `e00efe6`
and `a54ef9a`.

The runtime now owns an opaque, generation-aware hierarchy of Connection,
Session, Share, and Resource identities. Domain operations carry the narrowest
applicable dependency token, and owner admission validates the complete parent
chain before assigning MessageId, consuming credit, retaining payload, or
writing a frame.

The object reducer provides deterministic Active, Recovering, Revoked, Closing,
and Closed transitions. Parent loss cascades atomically, explicit close is
first-close-wins and idempotent, replacement publication advances the opaque
epoch in one commit, and runtime termination revokes the entire generation.

A bounded recovery wait reducer establishes the W4-2 seam. It has a hard
capacity, stable FIFO release, exact cancellation and deadline removal,
replacement-token publication, and ancestor-scoped failure draining. It stores
only wait identity and object dependencies; reconnect command payloads remain a
W4-2 responsibility.

## Local gates

| Gate | Result |
| --- | --- |
| object hierarchy/recovery reducer tests | Passed: 8 |
| runtime owner tests with test support | Passed: 21 |
| default workspace tests and doctests | Passed |
| strict workspace production-library clippy | Passed with warnings denied |
| architecture checker | Passed: runtime activated, 0 violations |
| credential and endpoint scan | Passed |

Deterministic coverage includes strict hierarchy construction, parent cascade,
concurrent/idempotent close decisions, stale and foreign-generation rejection,
atomic replacement, no-wire stale admission, bounded FIFO recovery waits,
deadline, cancellation, and ancestor-subtree draining.

## Isolated real-server validation

The manifest was bound to `74e1d20` and plan hash
`1a09fdd54cd19a7fb29c91a8d7cc28c1c62df9f3788023bd77f861d92127afa4`.
Runtime inputs used one-shot descriptors; no endpoint, account, credential, or
exact resource name is stored here.

| Gate | Result |
| --- | --- |
| plain 1 MiB immutable write/read | Passed: write 7.306 MiB/s, read 7.668 MiB/s |
| plain 4-stream 1 MiB | Passed: write 17.701 MiB/s, read 17.890 MiB/s |
| encryption-required 1 MiB immutable write/read | Passed: write 4.454 MiB/s, read 2.314 MiB/s |
| encrypted 4-stream 1 MiB | Passed: write 6.056 MiB/s, read 4.673 MiB/s |

The isolated volume, plain share, and encryption-required share all reached
`Deleted`; retained-resource count is zero.

## Boundary and rollback

W4-1 does not claim transport reconnect, Session reauthentication, TreeConnect
replay, durable/persistent resource recovery, or final event policy. W4-2 may
place payload-bearing operations behind the accepted recovery queue and publish
replacement generations, without adding a second object or request authority.

Rollback starts with dependent W4 work, then reverts this evidence and
`74e1d20`, `a54ef9a`, and `e00efe6` in reverse order. It must not restore domain
construction of object identity or allow stale handles to reach wire admission.
