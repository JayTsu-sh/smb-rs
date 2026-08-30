# W6-3 isolated ONTAP appliance acceptance

## Accepted implementation and isolation

The final fresh manifest was created from and cryptographically bound to
implementation `eb7236f`, the appliance preflight state, an anonymized test
identity, and one unique validation run. Binding identifiers are deliberately
not retained in the repository.
Runtime inputs were supplied through one-shot file descriptors. This document
retains no endpoint, account, credential, manifest, run identifier, or
generated appliance object name.

The final encrypted matrix ran from 2026-08-30T09:12:02Z through
2026-08-30T09:30:51Z with rustc 1.95.0 (59807616e 2026-04-14). Appliance
preflight identified ONTAP 9.19.1. Authentication traces identify NTLM and the
encrypted Share exercises the SMB transform path. The current public evidence
seam does not emit the negotiated dialect, signing algorithm, or cipher, so
those values are deliberately not inferred here.

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
| 1 x 1 | 22.50 MiB/s | 22.67 | 0.79% | 22.85 MiB/s | 23.25 | 1.22% | 16,540 KiB |
| 1 x 16 | 32.12 MiB/s | 32.95 | 1.40% | 33.78 MiB/s | 34.91 | 7.52% | 27,388 KiB |
| 4 x 16 | 93.64 MiB/s | 94.74 | 0.55% | 68.01 MiB/s | 71.52 | 2.24% | 47,344 KiB |

The first complete 4 x 16 run met throughput and RSS gates but failed the read
stability gate with CV 15.57% after one slow sample. The identical shape was
rerun without changing code, payload, window, sample count, appliance objects,
or thresholds; the table records that complete passing rerun. The failed run is
part of the acceptance history rather than being silently discarded.

Single-connection concurrency improved median write throughput by 51.7% and
read throughput by 56.8% over 1 x 1. Four connections approached the practical
limit of the shared 1 GbE management path. These results validate asynchronous
in-flight execution and bounded memory; they are not a claim about a dedicated
storage-front-end network.

## Fresh encrypted performance matrix

The final isolated manifest also ran every encrypted payload/window pair in
release mode. Each row used one warm-up, five measured samples, complete
byte-for-byte read-back, and a 10% CV hard limit. Small logical payloads were
repeated to transfer at least 16 MiB per sample. Every row negotiated a 1 MiB
maximum read chunk and a 1 MiB maximum write chunk.

| Payload | In-flight | Write median | Write p95 | Write CV | Read median | Read p95 | Read CV | Peak RSS |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 64 KiB | 1 | 15.65 MiB/s | 15.74 | 0.57% | 16.95 MiB/s | 17.41 | 8.72% | 9,776 KiB |
| 64 KiB | 16 | 15.96 MiB/s | 16.29 | 4.75% | 16.73 MiB/s | 17.74 | 4.96% | 18,120 KiB |
| 1 MiB | 1 | 20.20 MiB/s | 20.89 | 1.50% | 20.15 MiB/s | 20.30 | 4.98% | 18,616 KiB |
| 1 MiB | 16 | 23.37 MiB/s | 24.23 | 3.03% | 27.25 MiB/s | 28.24 | 2.23% | 12,508 KiB |
| 1 GiB | 1 | 20.06 MiB/s | 20.26 | 0.86% | 19.30 MiB/s | 19.56 | 1.33% | 17,972 KiB |
| 1 GiB | 16 | 26.59 MiB/s | 26.74 | 0.79% | 25.56 MiB/s | 25.91 | 3.69% | 51,048 KiB |

Concurrency is neutral at 64 KiB but materially helps larger transfers. At
1 GiB, 16 in-flight operations improve median write throughput by 32.6% and
read throughput by 32.5%. The client VM exposes no AES acceleration, so the
encrypted figures are software-crypto limited.

## Local total gates

The final implementation passes 138 all-feature tests, the public-domain API
tests, strict Clippy with warnings denied, and the complete workspace all-target
test suite. The workspace run includes architecture rules, evidence schema,
manifest lifecycle, residue, and wire-copy-budget gates. The zero-copy gates
prove that `Bytes` payload ownership survives sealing, slice writes make their
single copy at the API boundary, and each protection transform allocates one
final contiguous arena.

The final secret and endpoint scan passed with no matches. Manifest cleanup
passed, the pre-existing appliance state hash was unchanged, and retained
run-owned inventory was zero.
