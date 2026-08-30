# W6 accepted checkpoint

## Accepted boundary

W6 accepts the runtime implementation through `eb7236f`, the final isolated
appliance evidence in this checkpoint, and the complete W0-W6 architecture map.
The W6 evidence chain is:

- `W6-1-residue-contract-audit.md`;
- `W6-2-local-total-gates.md`;
- `W6-3-fas2750-total-matrix.md`.

The shipped public mainline is `Client -> Session -> Share -> File / Directory
/ Pipe`. Tokio async is the only execution model. The generation runtime is the
single lifecycle authority; codec and transport remain below it with one-way
dependencies. No compatibility facade, legacy worker/backend authority, or
public request-engine vocabulary remains.

`smb-rs` exposes negotiated maximum read and write chunk sizes. The upper layer
owns its actual chunk size, connection count, in-flight window, and bounded
memory policy. Ordinary payloads retain shared `Bytes` ownership through the
wire path; signing preserves segments, and encryption/compression each consume
their input into one final transform arena rather than claiming literal
zero-copy.

## Permanent local gates

| Gate | Result |
| --- | --- |
| complete workspace all-target tests | Passed |
| all-feature tests | Passed: 138 |
| strict workspace Clippy | Passed with warnings denied |
| architecture dependency and activation rules | Passed: 0 violations |
| evidence schema and residue contract | Passed |
| wire copy/allocation budgets | Passed |
| lifecycle, cancellation, recovery, and task teardown | Passed |
| credential and endpoint scan | Passed |

These gates permanently enforce one owner per lifecycle, first-terminal-wins,
typed cancellation/deadline/recovery outcomes, bounded queues and retry, stale
generation rejection, child-before-parent teardown, and zero retained test
resources.

## Isolated appliance acceptance

The final fresh manifest was cryptographically bound to the accepted runtime,
anonymous appliance preflight, and one unique validation run. Runtime inputs
used one-shot descriptors. No endpoint, account, credential, manifest, run
identifier, or generated appliance object name is retained in the repository.

| Gate | Result |
| --- | --- |
| plain and encrypted domain matrices | Passed: 6/6 each |
| typed RPC / named-pipe capability | Passed |
| CA persistent-handle grant and I/O | Passed |
| exact session-close recovery and generation replacement | Passed: 10/10 |
| stale ordinary Resource rejection and new Resource I/O | Passed: 10/10 |
| Previous Versions create/read/delete lifecycle | Passed |
| plain 1 GiB release matrix | Passed: 1x1, 1x16, 4x16 |
| encrypted 64 KiB / 1 MiB / 1 GiB matrix | Passed: 1x1 and 1x16 |
| reverse cleanup and pre-existing-state preservation | Passed: zero retained objects |

Every connection negotiated 1 MiB maximum read and write chunks. At 1 GiB,
single-connection 16-in-flight execution improved encrypted median write/read
throughput by 32.6%/32.5% over serial execution. Plain four-connection
throughput approached the practical limit of the shared 1 GbE management path.
The detailed medians, p95, CV, RSS, failed-sample transparency, recovery model,
and cleanup evidence are recorded in `W6-3-fas2750-total-matrix.md`.

## Milestone closure and later work

The architecture map is accepted. QUIC, RDMA, Kerberos, Multichannel, and real
takeover/giveback remain later roadmap work and do not weaken this checkpoint.
Administrative session deletion is not represented as a transport-loss proxy;
durable-v2 transport recovery remains covered by the accepted W4-5 fault gate.

A later observability enhancement may expose secret-free negotiated dialect,
signing-algorithm, and cipher metadata. It is not a correctness or acceptance
blocker because the encrypted transform behavior and protocol gates are already
measured.
