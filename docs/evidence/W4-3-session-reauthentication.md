# W4-3 Session reauthentication acceptance

## Accepted implementation

The accepted implementation is `5155c93`, with prerequisite commits
`a22529e`, `e4dc067`, `0d4fa81`, `6a378ba`, `ef786af`, `2a4b950`, `f01ad8b`,
and `9f656a5`.

An authenticated Session now retains a controlled asynchronous credential
capability rather than placing credentials in a recovery command or queue. A
single recovery mutex owns SessionSetup attempts. Each attempt is bounded, the
attempt count is finite, and caller timeout/cancellation detaches only that
waiter while the owned recovery task continues to a terminal result.

The candidate SessionId, preauthentication transcript, signing/encryption
keys, channel state, ConnectionInfo, and Session object token remain private
until SessionSetup completes. They are then exposed through one atomic Session
generation snapshot. Same-Connection recovery advances the Session object
epoch and revokes Share/Resource descendants; cross-Connection recovery creates
a Session token in the replacement runtime. Old key state is invalidated after
publication and key or preauthentication material is never traced.

Only directly Session-dependent operations may use the bounded recovery gate.
The gate has a hard capacity, FIFO recovery ownership, exact timeout and
cancellation outcomes, and detached recovery ownership. Share and Resource
dependencies are not migrated or released; their old tokens remain stale for
W4-4 and later policy.

## Local gates

| Gate | Result |
| --- | --- |
| Session recovery reducer/wait tests | Passed: 7 |
| ManualClock bounded-attempt tests | Passed: 2 |
| default workspace tests and doctests | Passed |
| strict workspace production-library clippy | Passed with warnings denied |
| architecture checker | Passed: runtime activated, 0 violations |
| credential, endpoint, and key-log scans | Passed |

Coverage includes same- and cross-generation recovery, duplicate owner
suppression, stale completion rejection, consecutive Connection replacement,
bounded attempts, first-terminal-wins close, hard queue capacity, FIFO
publication, deeper-dependency rejection, exact cancellation/deadline/failure
draining, attempt-future cancellation, and descendant revocation.

## Isolated real-server validation

The final manifest was bound to `5155c93` and plan hash
`68055a7f5d4ab35a2a1ed787daf445beef2b016a9b9cd676960e422f5e1d66be`.
Runtime inputs used one-shot descriptors; no endpoint, account, credential, or
exact resource name is stored here.

| Gate | Result |
| --- | --- |
| transparent-proxy transport loss | Passed: new Connection generation and SessionSetup observed |
| exact appliance CIFS-session disruption | Passed: exactly one run-owned session selected and closed |
| Session replacement | Passed: new SessionId, new TreeConnect, and verified write |
| stale child boundary | Passed: old Resource rejected and not reopened |
| plain 1 MiB immutable write/read | Passed: write 8.886 MiB/s, read 7.911 MiB/s |
| plain 4-stream 1 MiB | Passed: write 19.449 MiB/s, read 19.372 MiB/s |
| encryption-required 1 MiB immutable write/read | Passed: write 4.509 MiB/s, read 2.334 MiB/s |
| encrypted 4-stream 1 MiB | Passed: write 6.190 MiB/s, read 4.742 MiB/s |

The isolated volume, plain share, and encryption-required share all reached
`Deleted`; retained-resource count is zero and cleanup restored the bound
preflight state.

## Boundary and rollback

W4-3 deliberately does not replay TreeConnect or migrate ordinary Resources.
The recovered Session is usable for a new TreeConnect, while existing Share and
Resource handles remain stale. W4-4 owns Share identity, TreeConnect replay,
replacement publication, and its direct-Share waiting policy.

Rollback starts with dependent W4 work, then reverts this evidence and the
accepted implementation commits above in reverse order. No appliance rollback
is required because all manifest-owned resources were deleted.
