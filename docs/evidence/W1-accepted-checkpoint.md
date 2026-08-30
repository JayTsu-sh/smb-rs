# W1 accepted checkpoint

## Scope

- Wave: W1 — Build verification infrastructure
- Depends on: W0 accepted checkpoint and W1-1 through W1-5
- Tested implementation: `1e9d098`
- Accepted checkpoint: the commit containing this evidence record
- Validation date: 2026-08-29

W1 establishes the reusable measurement, deterministic lifecycle, architecture,
and isolated ONTAP validation facilities required by later implementation waves.
It does not claim that the W2 wire ownership, W3 runtime, W4 recovery, or W5
public Interface has been implemented.

## Commit and rollback record

| Commit range | Scope |
| --- | --- |
| `9df2418` through `f02188b` | deterministic transport, scoped memory, clock, lifecycle Scenario, and dependency gates |
| `c122e74` | secret-free machine-readable evidence schema |
| `307e40e` through `1cc2d53` | hash-bound ONTAP plan, atomic inventory, cleanup recovery, guarded SSH runner, trace metadata, and dual-share provisioning |
| `1e9d098` | route lease-break acknowledgement through the owning tree and consume its response |

Rollback starts with later dependent waves in reverse order, then reverts the W1
checkpoint and the ranges above. The validation run retained no appliance
resources, so rollback has no server-side step.

## Local validation

| Category | Result |
| --- | --- |
| workspace compile | Passed |
| SMB library tests | Passed: 18 |
| SMB offline protocol conformance | Passed: 6 |
| message codec tests | Passed: 118 unit and 1 documentation test |
| transport with deterministic test support | Passed: 14 unit and 6 scripted integration tests |
| W1 validation infrastructure | Passed: 46 executed tests; 3 device baselines intentionally ignored outside an authorized run |
| W1 validation clippy | Passed with warnings denied |
| architecture dependency checker | Passed: 3 activated crates, 3 future modules, 0 violations |
| changed-diff whitespace check | Passed |
| repository credential and endpoint scan | Passed: no matches |

The generic SMB integration suite is environment-driven and is therefore not
used as an unconfigured localhost gate. Its activated device cases were run
explicitly against the isolated target as recorded below.

## Isolated real-server validation

The plan was bound to the tested commit, anonymized target identity, preflight
state hash, test-identity digest, and an exact inventory. Runtime credentials
were supplied only through one-shot file descriptors.

| Gate | Result |
| --- | --- |
| plain-share SMB lifecycle and verified data I/O | Passed |
| typed wrong-password rejection | Passed |
| exact SMB 2.1, SMB 3.0, and SMB 3.1.1 lifecycle | Passed |
| SMB 3.1.1 encrypted-share lifecycle with encryption required | Passed |
| signed authenticated request path | Passed |
| lease grant | Passed |
| lease break notification, exact-tree acknowledgement, and fan-out | Passed |
| plain data path, 4 concurrent streams at 4 KiB, 64 KiB, and 1 MiB | Passed |
| encrypted data path, 4 concurrent streams at 4 KiB, 64 KiB, and 1 MiB | Passed |

Exact SMB 3.0.2 remains covered by the offline conformance suite. The appliance
rejected exact 3.0.2 negotiation while accepting 2.1, 3.0, and 3.1.1; 3.0.2 is
not a W1 real-target hard gate and is not reported as passed on that target.

The lease-break repair was diagnosed from a repeated real-target timeout: the
acknowledgement was signed but carried TreeId zero because it used an arbitrary
session. The repaired path resolves the lease owner, sends through its retained
tree handler, and waits for the matching response. The previously failing case
then completed successfully on the target.

## Cleanup evidence

- Both isolated shares and their dedicated volume were removed through the
  manifest-owned cleanup path.
- Final retained-resource count: zero.
- The post-cleanup preflight hash matched the plan's pre-existing-state hash.
- No existing share, volume, SVM, identity, network, or cluster policy changed.

## Gate ledger

- Activated at W1: deterministic transport/fault scripting, scoped allocation
  and payload accounting, controllable deadlines, lifecycle Scenario coverage,
  dependency-direction enforcement, secret-free evidence validation, and
  recoverable isolated ONTAP provisioning/cleanup.
- NotYetActivated (W2): immutable receive frames, validated wire views, sealed
  scatter/gather sends, and operation copy/allocation budgets.
- NotYetActivated (W3): sole generation runtime, request reducer, bounded
  shutdown, and runtime concurrency ownership.
- NotYetActivated (W4): automatic reconnect/recovery and server event model.
- NotYetActivated (W5): domain-first async public Interface.
- NotYetActivated (W6): complete milestone acceptance.

W1 is accepted and the next authorized implementation ticket is W2 wire data
plane.
