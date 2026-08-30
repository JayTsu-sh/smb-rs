# W6-3 isolated ONTAP appliance acceptance

## Accepted implementation and isolation

The final fresh manifest was created from and cryptographically bound to
implementation `ee306e4`, the appliance preflight state, an anonymized test
identity, and one unique validation run. The plan hash was
`b3b5607e5f5d8602a784dafdabf4f209dbc0a48920b23cb48915734915dc1a4e` and the
anonymous target identity was
`afd7d49a973e4271b2cdcc61b7ff430435bab6b5ff04e1b6dd0a0cbb4da9fc89`.
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

## Fresh encrypted performance matrix

The final isolated manifest also ran every encrypted payload/window pair in
release mode. Each row used one warm-up, five measured samples, complete
byte-for-byte read-back, and a 10% CV hard limit. Small logical payloads were
repeated to transfer at least 16 MiB per sample. Every row negotiated a 1 MiB
maximum read chunk and a 1 MiB maximum write chunk.

| Payload | In-flight | Write median | Write p95 | Write CV | Read median | Read p95 | Read CV | Peak RSS |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 64 KiB | 1 | 16.44 MiB/s | 16.75 | 4.52% | 15.61 MiB/s | 17.09 | 6.80% | 11,044 KiB |
| 64 KiB | 16 | 15.74 MiB/s | 16.10 | 2.58% | 17.00 MiB/s | 17.93 | 8.98% | 17,556 KiB |
| 1 MiB | 1 | 20.16 MiB/s | 20.44 | 0.99% | 19.86 MiB/s | 20.07 | 2.04% | 20,272 KiB |
| 1 MiB | 16 | 23.32 MiB/s | 23.64 | 2.38% | 26.16 MiB/s | 27.45 | 2.19% | 13,884 KiB |
| 1 GiB | 1 | 19.96 MiB/s | 20.13 | 0.53% | 19.44 MiB/s | 19.65 | 0.63% | 20,004 KiB |
| 1 GiB | 16 | 27.06 MiB/s | 27.79 | 1.49% | 26.70 MiB/s | 27.11 | 2.94% | 52,732 KiB |

Concurrency is neutral at 64 KiB but materially helps larger transfers. At
1 GiB, 16 in-flight operations improve median write throughput by 35.6% and
read throughput by 37.3%. The client VM exposes no AES acceleration, so the
encrypted figures are software-crypto limited.

## Local total gates

The final implementation passes 124 `smb` library tests, the public-domain API
tests, strict Clippy with warnings denied, and the complete workspace all-target
test suite. The workspace run includes architecture rules, evidence schema,
manifest lifecycle, residue, and wire-copy-budget gates. The zero-copy gates
prove that `Bytes` payload ownership survives sealing, slice writes make their
single copy at the API boundary, and each protection transform allocates one
final contiguous arena.

The final secret and endpoint scan passed with no matches. Manifest cleanup
passed, the pre-existing appliance state hash was unchanged, and retained
run-owned inventory was zero.
