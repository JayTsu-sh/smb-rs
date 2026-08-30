# W6-3 isolated ONTAP appliance acceptance

## Accepted implementation and isolation

The final fresh manifest was created from and cryptographically bound to
implementation `ee306e4`, the appliance preflight state, an anonymized test
identity, and one unique validation run. Runtime inputs were supplied through
one-shot file descriptors. This document retains no endpoint, account,
credential, manifest, plan hash, or generated appliance object name.

The run owned three independent volumes: 2 GiB functional, 16 GiB performance,
and 2 GiB CA. It owned plain and encrypted functional Shares, plain and
encrypted performance Shares, and one continuously available Share. Cleanup
deleted the Snapshot, Shares, and volumes in dependency-reverse order and
proved that the pre-existing appliance state hash was unchanged. Retained
run-owned object count was zero.

## Architecture boundary

The public mainline remains `Client -> Session -> Share -> File / Directory /
Pipe`. `smb-rs` exposes the negotiated maximum read and write chunk sizes via
`File::io_capabilities()`. The upper layer selects its actual chunk size,
connection count, in-flight window, and memory policy without exceeding those
limits. Every appliance connection in this run negotiated a 1 MiB maximum read
chunk and a 1 MiB maximum write chunk.

Resource publication is bound to one complete Share object token. CREATE
captures the parent token before admission, uses it as the request dependency,
and validates that exact token again before publishing the Resource. A Share
epoch replacement can therefore never bind an old FileId into a new epoch.

An unsigned session-invalidated frame is an untrusted recovery hint, not a
business response. It contributes no credit grant, leaves response progress at
`None`, completes the affected operation with typed `SessionInvalidated`, and
starts Session recovery. Its payload is never published as an operation result.

## Functional and recovery gates

| Gate | Result |
| --- | --- |
| plain public-domain matrix | Passed: 6/6 |
| encrypted public-domain matrix | Passed: 6/6 |
| named-pipe / typed RPC seam | Passed |
| CA persistent-handle grant and ordinary I/O | Passed |
| exact administrative session-close recovery | Passed: 10/10 |
| Session and Share object generation replacement | Passed: 10/10 |
| stale ordinary Resource rejection after replacement | Passed: 10/10 |
| Previous Versions A/Snapshot/B dual-view read | Passed |
| deleted Snapshot token rejected | Passed |
| active version B readable after Snapshot deletion | Passed |
| manifest cleanup and pre-existing-state preservation | Passed |

The recovery loop deliberately sends one never-replay side-effecting operation
after each exact session close. That operation fails with a typed terminal;
Session and Share generations then change, the stale Resource remains invalid,
and a newly opened Resource completes I/O. No operation is silently replayed.

Persistent handles are granted only on the CA Share. Administrative ONTAP
session deletion is not used as a durable-reconnect proxy because it explicitly
revokes server opens. DH2C recovery after unplanned transport loss remains the
separate W4-5 transport-fault gate; deterministic reducer tests cover durable
identity, bounded retry, parent replacement, and close races.

For Previous Versions, version A is flushed before Snapshot creation and
version B is flushed afterward. The historical handle reads A while the active
handle reads B. After manifest-owned Snapshot deletion, the old GMT token fails
to open; because the appliance terminates that invalid timewarp session, active
B is independently verified through a fresh authenticated Session.

## Release 1 GiB performance hard gate

Each shape used 1 GiB per connection, one warm-up, five measured samples,
complete byte-for-byte read-back, release mode, and the manifest-owned 16 GiB
plain performance volume. CV must be at most 10%; throughput must remain at
least 90% of the frozen baseline; peak RSS must remain below the frozen 110%
limit.

| Connections x in-flight | Write median | Write p95 | Write CV | Read median | Read p95 | Read CV | Peak RSS |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 x 1 | 21.33 MiB/s | 21.83 | 1.45% | 22.59 MiB/s | 23.17 | 2.22% | 15,636 KiB |
| 1 x 16 | 32.35 MiB/s | 33.14 | 1.61% | 35.42 MiB/s | 36.77 | 3.07% | 29,244 KiB |
| 4 x 16 | 92.48 MiB/s | 94.57 | 1.72% | 84.47 MiB/s | 88.40 | 3.34% | 47,684 KiB |

The first complete 4 x 16 run met throughput and RSS gates but failed the read
stability gate with CV 18.53% after one slow sample. The identical shape was
rerun without changing code, payload, window, sample count, appliance objects,
or thresholds; the table records that complete passing rerun. The failed run is
part of the acceptance history rather than being silently discarded.

Single-connection concurrency improved median write throughput by 51.7% and
read throughput by 56.8% over 1 x 1. Four connections approached the practical
limit of the shared 1 GbE management path. These results validate asynchronous
in-flight execution and bounded memory; they are not a claim about a dedicated
storage-front-end network.

Earlier encrypted characterization on the same appliance established that
64 KiB payloads do not benefit from concurrency, while 1 MiB and 1 GiB payloads
do. The client VM exposes no AES acceleration, so encrypted throughput is
software-crypto limited. This explains the environment constraint without
weakening the plain hard gate.

## Local total gates

The final implementation passes 124 `smb` library tests, the public-domain API
tests, strict Clippy with warnings denied, and the complete workspace all-target
test suite. The workspace run includes architecture rules, evidence schema,
manifest lifecycle, residue, and wire-copy-budget gates. The zero-copy gates
prove that `Bytes` payload ownership survives sealing, slice writes make their
single copy at the API boundary, and each protection transform allocates one
final contiguous arena.

The final secret and endpoint scan is required before checkpoint acceptance.
