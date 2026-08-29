# W1-4 deterministic lifecycle Scenario harness

## Scope

- Ticket: #37
- Wave: W1 — Build verification infrastructure
- Depends on: W1-3 checkpoint `fdc62c4`

This ticket combines the deterministic transport and monotonic clock Adapters
with one managed task group. It supplies a black-box Scenario Interface for
later runtime tests without becoming the SMB lifecycle authority itself.

## Scenario contract

`LifecycleScenario` owns exactly one ScriptedTransport, one shared ManualClock,
one cancellation tree, and one JoinSet. Tests take the transport once, script
server/client behavior through its control Interface, spawn uniquely named
tasks, explicitly advance time, and finish through deadline-bounded shutdown.

Shutdown first closes the Scenario cancellation tree. Cooperative tasks finish
and are joined. At the manual deadline, non-cooperative tasks receive stable
cancel events, are aborted, and are still joined before the report is returned.
No Scenario task is detached.

The report records only stable events and identifiers:

- task started, succeeded, failed, panicked, or cancelled;
- shutdown started and completed;
- whether shutdown reached its deadline and the final remaining-task count.

Task names and failure codes accept only 1–64 ASCII alphanumeric, dash,
underscore, or dot characters. Payload-like/free-form strings are rejected or
replaced with `invalid-failure-code`, preventing protocol payloads and runtime
secrets from entering JSON evidence. Panics are caught as task outcomes; panic
text is not stored.

`TerminalProbe` is a test oracle for first-terminal-wins scenarios. It accepts
exactly one typed terminal outcome and ignores later candidates without
exposing a runtime pending map or channel.

## Covered reusable scenarios

- scripted receive followed by scatter/gather send in an owned task;
- successful, failed, panicked, and cooperatively cancelled tasks;
- cancellation before send, proving no client frame is emitted;
- equal-time response versus timeout, proving one terminal outcome;
- partial-write failure and close-like read failure;
- deadline abort and join of a non-cooperative task;
- stable JSON report fields and secret-safe identifiers.

## Validation

| Command | Result |
| --- | --- |
| `cargo test -p smb --features test-support --test lifecycle_scenario` | Passed: 7 |
| `cargo test -p smb --features test-support --test clock` | Passed: 5 |
| four existing conformance binaries | Passed: 6 |
| `cargo test -p smb --lib` | Passed: 18 |
| `cargo clippy -p smb --features test-support --test lifecycle_scenario -- -D warnings` | Passed |
| `cargo clippy -p smb --lib -- -D warnings` | Passed |
| `cargo check --workspace` | Passed |
| `git diff --check` | Passed |
| credential and endpoint scan | Passed: no matches |

No FAS2750 resources were required or created. W3 will run the same Scenario
Interface against the real single-owner runtime and activate its lifecycle
gates.

## Rollback

This ticket may be rolled back with an ordinary revert of the commit containing
this record. W1-1 transport, W1-2 memory measurement, and W1-3 clock remain
independent and valid.
