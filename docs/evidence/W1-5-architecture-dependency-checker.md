# W1-5 architecture dependency checker

## Scope

- Ticket: #38
- Wave: W1 — Build verification infrastructure
- Depends on: W1-4 checkpoint `892b17b`

This ticket converts the accepted dependency direction and wave activation
rules into a read-only executable gate. The checker does not create target
module directories or report future architecture as implemented.

## Checker contract

The single command reads three authoritative inputs:

1. Cargo metadata for actual workspace package dependencies;
2. `docs/architecture/dependency-rules.json` for wave ownership, allowed module
   direction, allowed shared prefixes, and temporary Adapter expiry;
3. parsed Rust syntax for crate-local `use`, expression, and type paths.

Output is a stable JSON `ArchitectureReport` containing activated and
NotYetActivated crates/modules plus sorted violations. The checker never edits
source or rule files.

Rules reject:

- forbidden crate dependencies;
- reverse and skipped-layer module imports;
- crate-local imports that bypass all classified modules/prefixes;
- unknown allowed-module names and duplicate module rules;
- absolute, parent-relative, or symlink-resolved workspace escapes;
- activated roots that are missing, overdue roots that remain absent, and
  future-wave roots introduced before their merge wave;
- temporary Adapters present at or after their `remove_by` wave, including
  invalid lifetimes where removal is not later than creation.

Module status is evidence-based. A NotYetActivated root is reported as such
only while it is absent and belongs to a later wave. When the directory appears
in its owning wave, source checks activate automatically. Appearing earlier is
a violation, preserving strict W0→W6 merge order.

## Current repository result

Activated crate gates:

- `smb-msg` does not depend on `smb` or `smb-transport`;
- `smb-transport` does not depend on `smb`;
- `smb-rpc` does not depend on `smb`, preserving the current acyclic graph.

The target `runtime`, `domain`, and `facade` roots are explicitly
NotYetActivated with owners W3, W5, and W5. There are no registered temporary
Adapters at W1.

## Validation

| Command | Result |
| --- | --- |
| `cargo test -p smb-tests` | Passed: 9 architecture + 8 memory tests |
| `cargo run -p smb-tests --bin architecture-check -- docs/architecture/dependency-rules.json` | Passed: 3 activated crates, 3 NotYetActivated modules, 0 violations |
| `cargo clippy -p smb-tests --all-targets -- -D warnings` | Passed |
| `cargo check --workspace` | Passed |
| `git diff --check` | Passed |
| credential and endpoint scan | Passed: no matches |

Fixture coverage proves accepted direction, reverse dependency, skipped layer,
unknown module, unclassified import, path escape, early/overdue activation,
expired Adapter, forbidden crate dependency, and real-repository execution.
No FAS2750 resources were required or created.

## Rollback

This ticket may be rolled back with an ordinary revert of the commit containing
this record. W1-1 through W1-4 remain independent; later waves must not proceed
without restoring an equivalent executable dependency gate.
