# Pre-refactor baseline

Captured on 2026-08-29 before the architecture rewrite, at repository commit
`c3ecf0007a5477cfd954d4e6dda65c7abd765e71`.

This document is a reproducibility boundary, not a performance claim. Runtime
credentials and endpoint addresses are deliberately omitted. The ONTAP tests
used secrets supplied through a hidden process input; no secret was written to
the repository or a test configuration file.

## Measurement host

- Linux x86_64, kernel 6.8.0-124-generic
- 24 logical CPUs, 31 GiB RAM, no swap
- rustc 1.95.0 (59807616e 2026-04-14), LLVM 22.1.2
- cargo 1.95.0 (f2d3ce0bd 2026-03-21)
- Real-server target: NetApp FAS2750, ONTAP 9.19.1, SMB over TCP, NTLMv2

Elapsed time and maximum resident set size were collected with GNU
`/usr/bin/time -v`. Cold measurements include compilation and therefore must
not be compared with warm test execution as if they measured the same thing.

## Deterministic local baseline

| Command | Result | Elapsed | Maximum RSS |
| --- | --- | ---: | ---: |
| `cargo check --workspace` | pass | not retained | not retained |
| `cargo test -p smb --lib` (cold) | 16 pass | 26.92 s | 1,194,728 KiB |
| `cargo test -p smb --lib` (warm) | 16 pass | 0.23 s | 82,124 KiB |
| `cargo test -p smb-msg` | 118 unit and 1 doc pass | 24.69 s | 628,716 KiB |
| `cargo test -p smb-transport` | 14 pass | 3.95 s | 386,796 KiB |

Conformance tests compile only when the `test-support` feature is explicit:

| Command suffix after `cargo test -p smb` | Result | Elapsed | Maximum RSS |
| --- | --- | ---: | ---: |
| `--features test-support --test conformance_smoke` | 3 pass | 13.35 s | 643,772 KiB |
| `--features test-support --test conformance_smb302` | 1 pass | 2.06 s | 541,200 KiB |
| `--features test-support --test conformance_windows_dc_ntlm` | 1 pass | 2.11 s | 540,340 KiB |
| `--features test-support --test conformance_anonymous` | 1 pass | 2.13 s | 540,740 KiB |

Without that feature these integration-test targets fail to compile because
`smb::test_support` is configuration-gated. The default `smb-cli` feature set
also fails to compile: four non-exhaustive-match errors originate in
`crates/smb/src/crypto/signing.rs` because no signing algorithm variant is
enabled. These are frozen pre-existing build-surface failures; they are not
silently repaired as part of the architecture baseline.

The Docker Samba environment could not be started because the container image
manifest request to GHCR ended with EOF. No container was created. This is an
external environment failure and is kept separate from product failures.

## Real ONTAP red baseline

The minimal existing integration path reached the server over TCP and completed
SMB negotiation. The second NTLM `InitializeSecurityContext` call then failed
deterministically with an SSPI `InternalError` caused by `UnexpectedEof` while
reading the challenge token. Three runs failed at the same point before tree
connect or file creation. The first measured run took 3.15 s with 637,952 KiB
maximum RSS; that figure includes compilation and is not a data-path benchmark.

Forced-dialect probes reveal two additional, earlier protocol failures:

- SMB 3.0.2 with encryption disabled receives status `0xc00000bb`
  (`STATUS_NOT_SUPPORTED`) immediately after connection/negotiate.
- SMB 3.1.1 with encryption disabled cannot decode the server's negotiate
  contexts. Parsing reports an invalid encryption-capability cipher value at
  the context boundary and the receive operation times out after 10 seconds.

The default-dialect authentication failure and forced-dialect negotiation
failures are separate observations. The evidence does not yet justify assigning
them one root cause.

## Performance baseline status

Real-server file throughput, allocation count, payload-copy count, concurrency
scaling, reconnect recovery time, and peak in-flight memory are **not
available**: the current client fails before a file handle can be opened.
Inventing zero values or benchmarking a different server would destroy the
purpose of this baseline.

Once interoperability is repaired, measurements must use a fixed payload set
(4 KiB, 64 KiB, 1 MiB, and 1 GiB), report warm single-stream and concurrent
results separately, verify read-back bytes, include cleanup, and record median,
p95, throughput, allocations, payload copies, and peak in-flight bytes. Signing
and encryption runs are separate budgets because their transforms can require
owned output buffers.

## Interoperability remediation validation

The red baseline above was subsequently resolved without changing its status
as the historical pre-refactor observation. Validation against an isolated,
write-enabled share on the same ONTAP appliance passed the SMB 3.1.1 path for:

- NTLM session setup and signed final authentication exchange;
- tree connect, create, write, read, close, and delete-on-close;
- owner security-information query, directory enumeration, file-information
  query, and filesystem-size query.

The original shared volume remained unchanged. Its root directory is UNIX
mode `0755`, which explains the independent create-access denial observed there.
The isolated share and volume used for validation were deleted after the run.
Local verification after the remediation passed 18 library tests, the NTLM
conformance test, `cargo check -p smb`, and `git diff --check`.

### Reproducible real-server data-path baseline

`crates/smb/tests/ontap_baseline.rs` is an ignored, explicitly invoked harness.
It creates one file per stream on a caller-provisioned writable share, performs
fixed-size sequential I/O in 1 MiB application chunks, reopens the file between
write and read, verifies every returned byte, and requests delete-on-close.
Endpoint, user, password, and share remain runtime-only inputs.

The measurements below are one warm run per shape on the same host and appliance.
They are frozen observations, not statistically stable median/p95 claims. A
future threshold ticket must repeat each shape under controlled appliance load;
reporting p95 from one run would be false precision.

| Payload per stream | Streams | Write throughput | Read throughput | Wall time | Maximum RSS |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 4 KiB | 1 | 2.757 MiB/s | 3.596 MiB/s | included in 0.51 s calibration run | 81,672 KiB (shared run) |
| 64 KiB | 1 | 7.227 MiB/s | 7.797 MiB/s | included in 0.51 s calibration run | 81,672 KiB (shared run) |
| 1 MiB | 1 | 8.916 MiB/s | 8.330 MiB/s | included in 0.51 s calibration run | 81,672 KiB (shared run) |
| 1 GiB | 1 | 9.083 MiB/s | 8.676 MiB/s | 230.78 s | 81,864 KiB |
| 1 GiB | 4 | 10.608 MiB/s aggregate | 35.409 MiB/s aggregate | 503.96 s | 81,092 KiB |

Four concurrent connections scale reads to about 4.08 times the single-stream
rate, while writes improve only about 1.17 times. This is evidence that async
concurrency is viable but that the current write path has a shared or CPU-side
bottleneck; it is not evidence that one connection currently pipelines file
requests.

The application-buffer APIs used by this harness add one payload copy on write
(`&[u8]` into `Bytes`) and one on read (`Bytes` into `&mut [u8]`). The existing
`write_block_zc(Bytes)` and `read_block_bytes` paths avoid those application
copies for plain signed TCP traffic, as inventoried in the architecture audit.
No allocation profiler is installed on the measurement host, so exact dynamic
allocation counts remain explicitly unavailable. Peak RSS is retained as the
measured memory boundary; static copy counts and dynamic allocations must not be
conflated.

The harness also freezes a current semantic constraint: a `File` created at EOF
zero retains that cached length after writes, so correct immediate verification
requires close and reopen before using the slice-based read API.

## Frozen regression boundary

The rewrite must preserve all passing local tests unless a semantic change is
explicitly approved. It must also turn each real ONTAP red baseline into a
named regression test before performance thresholds are selected. This ticket
therefore freezes both the historical red state and the subsequent real-server
green data-path baseline. Statistical percentile and allocation thresholds
remain follow-up decisions rather than invented baseline facts.
