# W6-2 local fault, lifecycle, concurrency, and task-ownership gates

## Accepted implementation

The accepted implementation ends at `886650d` and depends on the accepted
W6-1 checkpoint. Connection-level recovery and notification support tasks are
owned by `ConnectionCore` and joined during explicit asynchronous close.
`Drop` performs synchronous invalidation only; it cannot create detached
cleanup work.

The public architecture remains the single mainline
`Client → Session → Share → File / Directory / Pipe`. The single-owner runtime
is the only request authority, while operation futures carry typed
cancellation, deadline, and replay policy.

## Executable local gates

| Gate | Result |
| --- | --- |
| workspace all-target tests | Passed |
| function, fault, lifecycle, cancellation, deadline, and replay | Passed |
| concurrency, admission, credit, partial-write, panic, and owner/pump join | Passed |
| allocation accounting | Passed: 8/8 |
| wire copy budgets | Passed: 3/3 |
| architecture dependency checker | Passed: 9/9, zero violations |
| W6 residue and task-ownership gate | Passed: 4/4 |
| strict SMB, CLI, and test-tool all-target clippy | Passed with warnings denied |
| rustdoc for SMB, RPC, and transport | Passed with warnings denied |
| credential and endpoint scan | Passed |

The copy contract admits `Bytes` payloads without a payload copy, records the
single required copy at the slice API boundary, and permits exactly one final
contiguous arena when protection transforms require one. Allocation scopes
prove that retained payload accounting settles exactly once.

The lifecycle contract forbids spawning from every `Drop` implementation.
Long-lived connection support tasks are stored, cancelled, and joined by their
owner. Operation-scoped recovery waits remain locally owned by the awaiting
future. Closing a connection drains request authority before its task owners
return.

## Validation boundary

This checkpoint is deliberately local and deterministic. Real-server tests
remain explicit isolated gates and were not used to accept W6-2. W6-3 must
bind a fresh manifest to this exact accepted implementation and independently
validate appliance behavior, performance, recovery, capability-dependent
features, and zero-retained cleanup.

Rollback requires reverting the W6-2 lifecycle stack in reverse order. A
rollback that restores detached cleanup or an unjoined long-lived support task
is not accepted.
