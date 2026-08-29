# W0 accepted checkpoint

## Scope

- Wave: W0 — Freeze the pre-rewrite baseline
- Depends on: repository checkpoint `c3ecf00`
- Accepted checkpoint: the commit containing this evidence record
- Validation date: 2026-08-29

W0 contains no target-architecture implementation. It freezes the repaired
FAS2750 interoperability behavior, the reproducible baseline harness, and the
accepted architecture/validation contracts as separate commit groups.

## Commit and rollback record

| Commit | Scope |
| --- | --- |
| `2d0537c` | ONTAP negotiate, NTLM SessionSetup, preauth transcript, setup signer, and integration-fixture fixes |
| `ec20c6d` | ignored ONTAP data-path harness and secret-free baseline record |
| `0dd8db5` | domain glossary, ADRs, architecture contracts, research, and FAS2750 acceptance contract |

W0 is the latest wave and may be rolled back by first reverting the commit that
contains this evidence record, then running
`git revert 0dd8db5 ec20c6d 2d0537c`. No server-side rollback is required: the
historical Validation runs cleaned their isolated resources, and W0 checkpoint
validation created no appliance resources.

## Local validation

| Command | Result |
| --- | --- |
| `cargo check --workspace` | Passed |
| `cargo test -p smb --lib` | Passed: 18 |
| `cargo test -p smb-msg` | Passed: 118 unit, 1 doc |
| `cargo test -p smb-transport` | Passed: 14 unit |
| `cargo test -p smb --features test-support --test conformance_smoke --test conformance_smb302 --test conformance_windows_dc_ntlm --test conformance_anonymous` | Passed: 6 |
| `cargo test -p smb --test ontap_baseline --no-run` | Passed |
| `git diff --check` | Passed |
| repository/issue credential and endpoint scan | Passed: no matches |

Workspace-wide `cargo fmt --check` is not an activated W0 gate. It reports
pre-existing formatting differences in files outside the W0 change set; W0
does not mix those unrelated mechanical changes into its commits. All modified
Rust files and all staged diffs were checked before commit.

## Real-server evidence

The isolated real-server validation and performance observations are frozen in
`docs/baselines/pre-refactor-baseline.md`. They cover SMB 3.1.1 NTLM setup,
signed final authentication, share/file lifecycle, metadata queries, verified
data I/O, single-stream and four-stream throughput, RSS, and resource cleanup.
W0 did not repeat those destructive tests because it introduced no code after
the interoperability commit and the evidence already identifies the tested
code and environment without storing runtime secrets.

## Gate ledger

- Activated at W0: existing local regressions, frozen interoperability
  behavior, baseline reproducibility, secret-free artifacts, atomic commit
  separation.
- NotYetActivated (W1): deterministic lifecycle/fault harness, allocation and
  retained-memory instrumentation, automated dependency checks.
- NotYetActivated (W2): wire ownership and payload copy/allocation budgets.
- NotYetActivated (W3): single-generation runtime lifecycle and concurrency.
- NotYetActivated (W4): automatic recovery, server events, and conditional CA.
- NotYetActivated (W5): domain-first public Interface.
- NotYetActivated (W6): complete milestone acceptance.

No temporary adapter or dual-authority path was introduced by W0.
