# W4-5 Resource recovery acceptance

## Accepted implementation

The accepted implementation is `e16eb17`, with prerequisite commits `0a0f0dd`,
`20a1831`, `1e751fd`, `9b65283`, `2946a4b`, `8f272a6`, `67f9693`,
`d3d054d`, and `68068d8`.

Operations now carry one of four explicit replay policies: never replay,
replay only before wire commitment, idempotent replay, or durable reconnect
only. A partial or complete write followed by deadline, cancellation, or
generation disconnect is reported as outcome unknown. An operation that never
committed to the wire retains a known failure result.

Ordinary Resource handles remain bound to their original generation and fail
closed after Connection, Session, or Share replacement. An explicitly granted
SMB3 durable-v2 Resource instead retains only its FileId, CreateGuid, persistent
flag, and atomic Resource token. Its unique recovery owner issues DH2C with
bounded attempts and backoff. A replacement `{FileId, Resource token}` snapshot
is published only after the reconnect response and its current parent Share
have both been validated.

Persistent opens are rejected before wire admission unless SMB3 persistent
handles were negotiated and the Share advertises continuous availability. A
server that omits DH2Q, or does not grant the requested persistent flag, is a
typed unsupported result rather than a false success.

## Local gates

| Gate | Result |
| --- | --- |
| replay-policy and OutcomeUnknown tests | Passed |
| durable recovery reducer tests | Passed: success, mismatch, retry, consecutive parent replacement, close race |
| `smb` library tests | Passed: 93 |
| default workspace tests and doctests | Passed |
| strict workspace production-library clippy | Passed with warnings denied |
| architecture checker | Passed: runtime activated, 0 violations |
| credential and endpoint scan | Passed |

Deterministic request-lifecycle coverage includes pre-commit failure, partial
write, complete write, deadline, cancellation, disconnect, late response,
single terminal publication, and complete pending/credit/task cleanup. The
durable coordinator covers identity and generation mismatch, bounded retry,
consecutive Share replacement, close ordering, and terminal revocation.

## Isolated real-server validation

The accepted manifest was bound to `e16eb17` and plan hash
`f83672afaee77654d11addec1f54067d1f1af4ed5091e98a5044c6ac886aecd9`.
Runtime inputs used one-shot descriptors; no endpoint, account, credential, or
exact resource name is stored here.

| Gate | Result |
| --- | --- |
| SMB3 durable-v2 create with DH2Q grant | Passed |
| transparent-proxy transport loss | Passed: replacement Connection generation |
| ordinary Resource after loss | Passed: rejected without CREATE/write replay |
| original durable Resource after loss | Passed: DH2C reconnect and subsequent write |
| persistent/CA capability | Not activated: the isolated plain Share did not advertise continuous availability |
| W4-4 plain/encrypted 1/4-stream regression baseline | Retained accepted checkpoint; no copy-path implementation changed |
| cleanup | Passed: volume and both Shares Deleted; retained-resource count 0 |

The durable fault seam is an unplanned transport loss. Exact management-path
CIFS-session close remains the Session/Share recovery seam from W4-3/W4-4; it
is not substituted for transport-loss durable semantics. No takeover,
giveback, LIF mutation, CIFS restart, or SVM-wide setting change was performed.

## Next seam and rollback

W4-6 owns lease/oplock break delivery, ACK deadlines, cache invalidation, and
change-notify overflow, lag, cancellation, and event-delivery policy. Those
events may revoke or constrain a durable Resource, but they do not widen the
replay policy defined here.

Rollback starts with dependent W4 work, then reverts this evidence and the
accepted implementation commits above in reverse order. W4-4 Share recovery is
retained, and ordinary Resource blind replay must never be restored.
