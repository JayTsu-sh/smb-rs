# W5-6 atomic domain cutover acceptance

## Accepted implementation

The accepted implementation ends at `2233e27`. Production consumers now use
only the domain facade and its explicit extensions. The public mainline is
`Client → Session → Share → File / Directory / Pipe`; protocol mechanics and
the former client, connection, session, tree, command, and resource modules
are crate-private implementation details.

The runtime boundary is permanently named `runtime::port`. The temporary
`domain_bridge` path, legacy root exports, CLI transport/path surface, and old
parallel-copy helpers are removed. Historical real-server tests that called
the deleted surface were retired in favor of the domain integration suite.
Protocol transcript diagnostics use the explicitly unstable `test_support`
namespace and do not form a second production API.

## Deterministic and local gates

| Gate | Result |
| --- | --- |
| SMB library unit tests | Passed: 121/121 with default features |
| full test-support and real-server-feature build | Passed: 153 library tests plus integration suites |
| SMB strict all-target clippy | Passed with warnings denied |
| RPC and CLI tests | Passed: 44/44 and 1/1 |
| workspace all-target tests | Passed |
| rustdoc | Passed with warnings denied |
| architecture checker | Passed: 9/9, zero violations, zero temporary adapters |
| production-consumer legacy API scan | Passed |
| credential and endpoint scan | Passed |

The workspace-wide all-target clippy invocation additionally reports existing
test-only lints in protocol crates outside the W5-6 change set. The production
and SMB all-target warning-denied gates pass; those unrelated lint findings do
not weaken the cutover boundary.

## Isolated real-server validation

The final manifest was bound to `2233e27`. Runtime inputs used one-shot file
descriptors; no endpoint, account, credential, or exact resource name is
stored here.

| Gate | Result |
| --- | --- |
| plain Share domain regression | Passed: 6/6 |
| encryption-required Share domain regression | Passed: 6/6 |
| concurrent Transfer and typed Batch | Passed on both Shares |
| directory query/watch and paired rename events | Passed on both Shares |
| metadata and security descriptor extension | Passed on both Shares |
| named-pipe lifecycle, cancellation, and typed RPC capability | Passed |
| cleanup | Passed: manifest-owned volume and both Shares deleted; retained-resource count 0 |

The target returns its existing nonzero DCE/RPC remote fault for the current
NDR64 SRVSVC request. The public pipe path preserves that rejection as a typed
`RemoteFault`; successful share enumeration is not claimed.

## Boundary and rollback

There is deliberately no compatibility layer. Reintroducing a legacy public
module, root export, CLI transport switch, or caller-owned channel would
recreate a second architectural mainline and violates this checkpoint.
Rollback therefore means reverting the W5-6 commits as one dependent stack,
not restoring individual aliases.
