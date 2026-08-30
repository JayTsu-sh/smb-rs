# W1-1 deterministic transport Adapter

## Scope

- Ticket: #34
- Wave: W1 — Build verification infrastructure
- Depends on: W0 checkpoint `2695ed3`

This ticket establishes one reusable test-only Adapter at the existing
`SmbTransport` Interface. It replaces the conformance suite's private mock and
does not alter any production transport or request lifecycle behavior.

## Observable contract

- tests enqueue raw server frames and receive them through the production read
  Interface;
- scatter/gather client writes are captured as one raw frame without payload
  consolidation in the control Interface;
- exact reads may consume one framed input through arbitrary caller buffer
  sizes;
- tests can inject a typed I/O failure at an exact one-based `receive_exact` or
  `send_raw` operation;
- a failed read does not consume its queued frame, and a failed write does not
  remove frames captured before it;
- frame waits are notification-driven and bounded by a caller deadline.

The Adapter and its control Interface exist only behind the
`smb-transport/test-support` feature. The `smb/test-support` feature enables it
for conformance tests. No test-only Interface is enabled by default.

## Replacement evidence

The former `crates/smb/tests/conformance/mock_transport.rs` implementation was
deleted. All four deterministic SMB conformance binaries now consume
`ScriptedTransport` from `smb-transport`; there is one transport scripting
authority and no compatibility alias.

## Validation

| Command | Result |
| --- | --- |
| `cargo test -p smb-transport --features test-support` | Passed: 14 existing + 6 Adapter tests |
| `cargo clippy -p smb-transport --features test-support --tests -- -D warnings` | Passed |
| four `smb` conformance test binaries with `test-support` | Passed: 6 |
| `cargo test -p smb --lib` | Passed: 18 |
| `cargo check --workspace` | Passed |
| `git diff --check` | Passed |
| credential and endpoint scan | Passed: no matches |

No FAS2750 resources were required or created because this ticket changes only
the deterministic local test Adapter. Clock control, allocation accounting,
dependency checks, and lifecycle scenarios remain subsequent W1 tickets.

## Rollback

This ticket is one commit on top of W0 and may be rolled back with an ordinary
revert of the commit containing this record. Reverting restores the private
conformance mock and removes the `test-support` Adapter feature as one unit.
