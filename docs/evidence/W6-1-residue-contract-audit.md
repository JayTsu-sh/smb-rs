# W6-1 residue removal and architecture-contract audit

## Accepted implementation

The accepted implementation ends at `a182126` and depends on the W5-6
checkpoint. The activation ledger is now at W6 with no temporary adapters.

The obsolete worker-shaped generation wrapper was renamed and deepened as the
crate-private `GenerationRuntime` capability. Worker vocabulary, dead CLI and
test features, the obsolete worker module path, and the pre-redesign
implementation-coupled architecture snapshot were removed. The stable public
mainline remains `Client → Session → Share → File / Directory / Pipe`.

## Executable contract audit

| Gate | Result |
| --- | --- |
| workspace all-target tests | Passed |
| SMB all-target tests with test-support, real-server declarations, and typed RPC enabled | Passed: 153 library tests and all local integration tests |
| strict SMB, CLI, and test-tool all-target clippy | Passed with warnings denied |
| architecture dependency checker | Passed: 9/9, zero violations |
| W6 residue regression gate | Passed: 3/3 |
| allocation accounting | Passed: 8/8 |
| wire copy budgets | Passed: 3/3 |
| rustdoc for SMB, RPC, and transport | Passed with warnings denied |
| credential and endpoint scan | Passed |

The residue gate prevents restoration of the six legacy public modules, the
temporary domain bridge, worker-shaped adapter paths, deleted dead features,
and the obsolete implementation audit. It also requires W6 activation and an
empty temporary-adapter ledger.

Real-server tests are explicit ignored gates in local runs. This prevents an
all-target build from accidentally connecting to localhost while preserving
their deliberate execution in isolated appliance validation.

## Boundary and rollback

No protocol behavior or public compatibility alias was added. The generation
runtime remains a narrow internal capability over the single-owner runtime;
it does not own lifecycle state or create a second request authority.

Rollback requires reverting this W6-1 stack in reverse order. Restoring a
worker/handler/actor peer abstraction or the legacy public spine is not an
accepted partial rollback.
