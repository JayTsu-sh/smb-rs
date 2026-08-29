# W1-3 controllable monotonic clock

## Scope

- Ticket: #36
- Wave: W1 — Build verification infrastructure
- Depends on: W1-2 checkpoint `2f8fce8`

This ticket introduces the internal Clock Interface shared by production
deadline code and deterministic lifecycle tests. The Interface exposes only a
monotonic `now` and `sleep_until`; callers do not learn Tokio timer handles or
the ManualClock implementation.

## Adapters and behavior

- `TokioClock` is the production Adapter. The existing async worker waiter
  timeout now uses it without changing timeout results or duration reporting.
- `ManualClock` is exported only through `smb/test-support`. Tests explicitly
  advance its shared timeline and never wait for wall-clock time.
- Manual sleepers are keyed by deadline and registration sequence. One advance
  wakes them in that order, yielding between notifications so equal-deadline
  ordering is observable and deterministic.
- Dropping a sleep future removes it from the queue; Clock creates no task.
- Backward movement returns a typed error. Duration overflow saturates at the
  maximum monotonic value rather than wrapping.
- A poisoned ManualClock state returns a typed control error or conservative
  terminal value; production TokioClock contains no mutex.

## Validation

| Command | Result |
| --- | --- |
| `cargo test -p smb --features test-support --test clock` | Passed: 5 |
| equal-deadline ordering test repeated 20 times | Passed: 20/20 |
| `cargo clippy -p smb --features test-support --test clock -- -D warnings` | Passed |
| `cargo clippy -p smb --lib -- -D warnings` | Passed |
| `cargo test -p smb --lib` | Passed: 18 |
| `cargo check --workspace` | Passed |
| `git diff --check` | Passed |
| credential and endpoint scan | Passed: no matches |

No FAS2750 resources were required or created. W1-3 activates deterministic
time control; request deadline-heap and lifecycle gates remain owned by W3.

## Rollback

This ticket may be rolled back with an ordinary revert of the commit containing
this record. The legacy async worker then returns to direct Tokio sleep, while
W1-1 and W1-2 remain valid.
