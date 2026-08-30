# W5-1 domain-first public spine acceptance

## Accepted implementation

The accepted implementation is `855bd3e`, with prerequisite commits `6611d56`,
`7acd892`, `50bd2b6`, `6c877bd`, and `a1d4ec8`.

The normal crate-root path is now `Client → Session → Share → Resource`.
`Tree` and physical `Connection` are no longer root exports. Wire and protocol
values, including raw object identities, live under the explicit `protocol`
extension namespace instead of being glob-reexported into ordinary use.

Facade code depends only on domain code; domain code depends only on the
runtime interface. The W5 bridge is a declared temporary internal adapter over
the accepted W4 implementation. It owns no lifecycle authority and expires at
W6. The architecture checker now activates facade, domain, and runtime together.

Client, Session, and Share are cheap Clone, Send, and Sync logical handles.
File is Send and Sync but deliberately not Clone. Share retains its parent
Session, and explicit close delegates to the accepted W4 parent-cascade
authority. ShareTarget separates server/share identity, while SharePath rejects
absolute paths, empty components, and parent traversal.

Credentials are non-Debug and zeroizing. The facade maintains only a weak,
credential-digest session reuse index; it is not lifecycle authority and holds
no lock across authentication I/O. This prevents duplicate SessionSetup when
common and explicit-Session paths use the same logical identity.

## Local gates

| Gate | Result |
| --- | --- |
| crate-root API compile test | Passed: common and explicit Session paths |
| handle Send/Sync and Clone contract | Passed |
| ShareTarget/SharePath validation | Passed |
| workspace all-target tests | Passed |
| real-server feature matrix compile | Passed |
| strict workspace production clippy | Passed with warnings denied |
| architecture checker | Passed: facade/domain/runtime activated, 0 violations |
| credential and endpoint scan | Passed |

Existing low-level conformance and W4 recovery tests now use explicit internal
module paths. They no longer define the normal crate-root vocabulary. The
runtime bridge is tracked in `dependency-rules.json` and cannot survive W6.

## Isolated real-server validation

The final manifest was bound to `855bd3e` and plan hash
`3814f24c97de62f9b4a17921285b18d18d0beee987f534643b1a85d87733826c`.
Runtime inputs used one-shot descriptors; no endpoint, account, credential, or
exact resource name is stored here.

| Gate | Result |
| --- | --- |
| plain Share common `Client::connect_share` path | Passed |
| plain Share explicit `Client::authenticate` path | Passed |
| encryption-required Share common path | Passed |
| encryption-required Share explicit Session path | Passed |
| create, immutable Bytes write, close, reopen, zero-copy Bytes read, delete | Passed on both Shares |
| explicit Share/Session/Client close | Passed |
| cleanup | Passed: volume and both Shares Deleted; retained-resource count 0 |

The first device run exposed a duplicate-SessionSetup defect in the temporary
bridge: common connect succeeded, but a following explicit authentication on
the same Client bypassed session reuse and failed signature verification. The
facade was corrected to reuse a live Session by server and credential digest,
without adding lifecycle authority. Both paths then passed on plain and
encrypted Shares. That diagnostic run was cleaned with retained count zero;
the accepted run above was newly provisioned and bound to the fix commit.

## Boundary and rollback

This ticket establishes naming, ownership, target/path validation, explicit
authentication, typed file open, positioned Bytes I/O, and close delegation.
W5-2 owns lazy `Operation`, deadline, cancellation, replay configuration, and
typed public outcomes. Later W5 tickets migrate Directory/Pipe/extensions and
delete the temporary runtime bridge plus remaining old public module seams.

Rollback requires reverting dependent W5 work first, then this evidence and
the implementation commits above in reverse order. W4 runtime recovery and
event authority remain the rollback floor.
