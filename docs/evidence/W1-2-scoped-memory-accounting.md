# W1-2 scoped memory and payload accounting

## Scope

- Ticket: #35
- Wave: W1 — Build verification infrastructure
- Depends on: W1-1 checkpoint `9df2418`

This ticket provides the test/benchmark measurement Interface required before
operation-specific copy and allocation budgets can be activated. It does not
instrument the current legacy worker or claim that any W2/W3 budget passes.

## Measurement contract

`measure_memory(future)` attributes events only while the supplied future is
being polled. Tokio task-local scope, rather than thread-local state, keeps
concurrent and nested async measurements separate when tasks move or futures
interleave. Child tasks must open their own explicit measurement scope; scope
is not silently inherited.

The stable `MemoryReport` fields cover:

- payload-copy count and copied bytes;
- allocation/reallocation count and byte traffic;
- current and peak live allocated bytes;
- current and peak retained payload bytes.

`RetainedPayload` is an owned guard. Moving it does not duplicate accounting,
and Drop releases its bytes exactly once. Deallocation/reallocation use
saturating live-byte subtraction so freeing memory allocated outside the scope
cannot wrap counters. The report derives `serde::Serialize` for the later JSON
evidence pipeline.

## Safety and build placement

`TrackingAllocator<A>` implements Rust's unsafe `GlobalAlloc` Interface in the
test-utility crate only. Each allocator operation delegates unchanged to `A`;
the wrapper observes successful results with non-allocating atomics and does
not alter pointers, layouts, or production data paths. A test binary opts in by
declaring the wrapper as its global allocator. Production crates do not enable
or install it.

## Validation

| Command | Result |
| --- | --- |
| `cargo test -p smb-tests` | Passed: 8 measurement tests; 3 existing doc tests ignored |
| `cargo clippy -p smb-tests --all-targets -- -D warnings` | Passed |
| `cargo check --workspace` | Passed |
| `git diff --check` | Passed |
| credential and endpoint scan | Passed: no matches |

The tests cover allocation/release, reallocation, live-byte saturation,
payload-copy events, guard move/drop, nested scopes, concurrent scopes, and
stable serialized field names. No FAS2750 resources were required or created.

## Activation and rollback

W1-2 activates the measurement facility itself. Concrete operation budgets
remain NotYetActivated until W2/W3 connect named paths to this Interface.
The ticket may be rolled back with an ordinary revert of the commit containing
this record; W1-1 is unaffected.
