# smb-rs API versus kernel CIFS mount performance

Date: 2026-09-02 (Asia/Shanghai)
Targets: FAS2750 and DXN CIFS shares
Result: both complete matrices passed data verification and cleanup

## Scope and method

This comparison measures two client data paths from the same Linux host to the
same share on each target:

- the public smb-rs `File::write_all_at`, `File::read_exact_at`, and `flush`
  operations;
- ordinary `write`, `read`, and `fsync` calls through the Linux kernel CIFS
  mount.

“Local mount” means a locally mounted remote CIFS filesystem, not local-disk
I/O. Both mounts used SMB 3.1.1, `cache=none`, and `actimeo=0`. This prevents
Linux page-cache hits from being counted as remote read throughput. Server-side
caching can still affect both paths.

The payload labels use binary units: 4 KiB, 40 MiB, and 1 GiB. Tests ran in
release mode with one warm-up and three measured samples. Writes include a
remote flush/fsync, and every read is byte-for-byte verified. smb-rs uses one
connection and up to 16 in-flight requests bounded by the negotiated chunk
size. The mount path uses sequential POSIX I/O with application buffers capped
by the smb-rs negotiated chunk; the kernel can split those calls according to
its own `rsize`/`wsize` (4 MiB was observed on DXN). The execution order
alternates between the two paths to reduce order bias.

For statistically meaningful 4 KiB results, each sample performs 4,096
complete 4 KiB transfers (16 MiB total). The 40 MiB and 1 GiB rows perform one
complete transfer per sample.

## Median throughput

All values are MiB/s. “API/mount” is the smb-rs median divided by the kernel
mount median; 100% would be parity.

| Target | Payload | smb-rs write | Mount write | API/mount | smb-rs read | Mount read | API/mount |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| DXN | 4 KiB | 6.50 | 9.00 | 72.3% | 6.56 | 9.42 | 69.7% |
| DXN | 40 MiB | 26.67 | 87.81 | 30.4% | 32.17 | 102.46 | 31.4% |
| DXN | 1 GiB | 28.31 | 107.90 | 26.2% | 33.06 | 100.96 | 32.7% |
| FAS2750 | 4 KiB | 3.92 | 5.74 | 68.3% | 4.25 | 5.41 | 78.5% |
| FAS2750 | 40 MiB | 30.38 | 70.65 | 43.0% | 30.22 | 76.65 | 39.4% |
| FAS2750 | 1 GiB | 32.60 | 69.50 | 46.9% | 34.98 | 75.32 | 46.4% |

## 4 KiB request latency

The repeated-transfer medians correspond to these average per-transfer
latencies:

| Target | smb-rs write | Mount write | smb-rs read | Mount read |
| --- | ---: | ---: | ---: | ---: |
| DXN | 0.601 ms | 0.434 ms | 0.595 ms | 0.415 ms |
| FAS2750 | 0.997 ms | 0.681 ms | 0.920 ms | 0.722 ms |

## Stability and rerun

DXN coefficients of variation ranged from 0.16% to 3.77%. FAS2750 was below
7.04% except for the kernel-mount 40 MiB read result, whose first complete run
had CV 14.90%. That exact payload was rerun without changing code, mount
options, concurrency, sample count, or target. The rerun produced 76.65 MiB/s
median read throughput with CV 8.33%; the table uses this stable rerun.

The first FAS2750 40 MiB result is retained here for transparency: smb-rs
write/read 30.88/33.69 MiB/s, mount write/read 73.05/76.46 MiB/s. Its medians
are consistent with the rerun despite the slow mount-read sample.

## Interpretation

The kernel client is faster in every measured cell. The gap is moderate for
4 KiB requests (smb-rs reaches 68%–79% of mount throughput), but much larger
for streaming data. At 1 GiB, smb-rs reaches 26%–33% of DXN mount throughput
and about 46%–47% of FAS2750 mount throughput.

The target comparison also separates request latency from streaming capacity:

- DXN has lower 4 KiB latency on both client paths.
- FAS2750 gives smb-rs slightly higher 1 GiB throughput than DXN.
- DXN kernel-mount streaming is substantially faster, reaching roughly
  101–108 MiB/s at 1 GiB, close to the practical payload ceiling of a 1 GbE
  path.

The likely smb-rs optimization area is therefore not file creation or fixed
per-request latency alone. Large-transfer results point to request scheduling,
credit/window utilization, and per-chunk processing in the user-space data
path. Profiling those components against the kernel client's approximately
70–108 MiB/s target-specific ceiling is the next useful step.

## Root-cause investigation

Follow-up experiments on the DXN 40 MiB case isolated the principal bottleneck.

### Explicit signing changes kernel-path performance

The ordinary kernel mount reported SMB 3.1.1 with server security mode `0x1`:
signing is supported but the server does not require it during negotiation.
That value alone does not prove whether the established kernel session signed
each data request. Packet capture was not performed, so the ordinary mount's
per-message signing state remains unconfirmed. smb-rs signed its normal data
messages in this run.

Forcing the kernel mount to use signing reduced its write/read medians from
87.81/102.46 MiB/s to 69.05/67.95 MiB/s. Signing-policy mismatch is therefore a
plausible explanation for a material part of the original comparison,
especially on reads, but the ordinary path cannot be labelled unsigned without
wire evidence. It also does not explain the remaining 2.1–2.5x signed-path gap.

### Client-required signing policy validation

The public connection policy now separates signing support from the client's
requirement bit. `ClientConfig::default().signing_required` is `false`, while
setting it to `true` sets `SMB2_NEGOTIATE_SIGNING_REQUIRED`. Both modes continue
to advertise signing support, and `false` does not disable signing required by
the server or established session.

Protocol-transcript tests verified the exact outgoing NEGOTIATE bits for both
values. A real DXN experiment also showed why an optional requirement cannot be
implemented as “never sign”: after authentication, an actually unsigned
TREE_CONNECT was rejected with `STATUS_ACCESS_DENIED` even though the server's
NEGOTIATE response did not set its signing-required bit.

The public configuration path was then exercised with 40 MiB, 1-connection,
16-inflight write/read/verify/cleanup runs on both targets:

| Target | Client requires signing | Write median | Read median | Result |
| --- | ---: | ---: | ---: | --- |
| DXN | false | 89.01 MiB/s | 92.40 MiB/s | pass |
| DXN | true | 88.10 MiB/s | 91.79 MiB/s | pass |
| FAS2750 | false | 75.48 MiB/s | 77.01 MiB/s | pass |
| FAS2750 | true | 85.39 MiB/s | 84.27 MiB/s | pass |

These focused runs establish interoperability, not a performance difference
between the two values; the default path can still sign established-session
traffic, and the separate samples are subject to normal target variance.

### Unsigned comparison attempt

A subsequent round attempted to establish genuinely unsigned sessions rather
than treating `signing_required=false` as unsigned. Packet capture of the
kernel client with `sec=ntlmssp` showed that both DXN and FAS2750 TREE_CONNECT
requests still carried SMB2 Flags `0x00000008` and non-zero signatures. Those
mounts therefore could not serve as unsigned baselines.

A one-shot smb-rs probe then disabled the signing bits in NEGOTIATE and
SESSION_SETUP and sent the authenticated TREE_CONNECT without a signature.
DXN rejected it with `STATUS_ACCESS_DENIED` (`0xC0000022`); FAS2750 reset the
TCP connection and the client reported `OutcomeUnknown`. The probe-only code
was removed immediately after the run.

Read-only ONTAP inspection mapped `data_mover_e2e` to SVM `lizy` and reported
`is-signing-required=false`. Nevertheless, that concrete authenticated session
did not accept unsigned application traffic. Consequently neither target
reached file I/O, so no valid unsigned throughput result exists for this round.
An unsigned performance comparison requires a separately provisioned test SMB
server that both negotiates and accepts unsigned authenticated traffic.

### Software AES-CMAC is the dominant smb-rs CPU cost

A `perf` CPU-clock profile of the smb-rs-only 40 MiB path collected about 6,000
samples with zero lost samples. 95.5% of sampled CPU call chains were beneath
`MessageSigner::signature_for_segments` or `MessageSigner::verify_signature`,
through `Cmac128Signer::update` into RustCrypto's software fixslice AES-128
backend. Outgoing signing and incoming verification accounted for roughly
equal halves.

The test VM exposes a generic 2 GHz KVM CPU without the AES-NI CPU flag. The
smb-rs AES crate consequently uses `aes::backends::soft::fixslice` instead of
hardware AES. This produces a repeatable throughput plateau of roughly
28–35 MiB/s on both storage targets, regardless of their higher backend/network
ceiling.

The negotiated algorithm is not replaceable by merely reordering the compiled
algorithms on these appliances. Builds offering only HMAC-SHA256 or only
AES-GMAC failed during session setup on both DXN and FAS2750 because the server
selected `AesCmac`; a CMAC-only build completed normally. On DXN, the CMAC-only
40 MiB, one-in-flight run measured 28.83 MiB/s write and 28.71 MiB/s read.

The signed kernel path is CPU-bound in the same logical operation, but not at
the same cost. A separate `perf` capture of a 40 MiB signed, uncached DXN mount
write collected 893 samples with zero loss; 76.82% landed in
`crypto_aes_encrypt` below `crypto_cmac_digest_update`, `smb3_calc_signature`,
and `smb2_sign_rqst`. Thus the kernel is not faster because it avoids signing.
On this CPU it uses its generic AES implementation, whereas RustCrypto uses a
constant-time fixslice implementation. CMAC is a serial chaining construction,
and the RustCrypto CMAC loop calls single-block AES for every 16-byte block, so
the portable fixslice cost becomes the limiting per-byte cost. This also
explains why syscall savings in user space do not appear in the leading profile.

### Credits and serialization are secondary constraints

DXN negotiated 8 MiB maximum read/write chunks. Each 8 MiB SMB operation costs
128 SMB credits, exactly the current smb-rs default target, so only one such
operation can be admitted at a time even when the caller requests 16 in-flight
operations. The Linux CIFS session had 389 credits available.

A controlled 40 MiB smb-rs-only run changed from one to sixteen requested
in-flight operations. A fresh 1x16 control run used below measured
31.50/33.89 MiB/s; the earlier matrix values are retained here to show the
original experiment:

| Window | Write | Read |
| ---: | ---: | ---: |
| 1 | 28.64 MiB/s | 27.34 MiB/s |
| 16 | 31.55 MiB/s | 34.52 MiB/s |

The modest 10% write and 26% read improvement shows that concurrency helps,
but it cannot overcome synchronous CMAC work. Raising the default credit target
from 128 to 512, with all other inputs fixed at 1x16, did not help:

| Requested credit target | Write | Read |
| ---: | ---: | ---: |
| 128 | 31.50 MiB/s | 33.89 MiB/s |
| 512 | 30.42 MiB/s | 33.95 MiB/s |

The 512 result was therefore not retained as a production default. It may mean
that the appliance did not grant a materially larger usable window, or simply
that CMAC was already the ceiling; either way, higher requested credits alone
are not an evidence-backed fix.

Smaller chunks produce a direction-specific tradeoff. All of these DXN runs
used 128 requested credits, 16 requested in-flight operations, 40 MiB, five
measured samples, and had CV below 2%:

| Chunk limit | Write | Read |
| ---: | ---: | ---: |
| 2.5 MiB (uncapped control) | 31.50 MiB/s | 33.89 MiB/s |
| 1 MiB | 29.84 MiB/s | 34.81 MiB/s |
| 512 KiB | 29.54 MiB/s | 38.10 MiB/s |
| 256 KiB | 27.95 MiB/s | 36.16 MiB/s |

The 512 KiB limit improved read by 12.4% but reduced write by 6.2%; 256 KiB
then lost more throughput to per-message overhead. Consequently a single global
chunk reduction is not safe. The public migration transfer primitive already
defaults to 1 MiB chunks with four in flight, while the lower-level positioned
read/write APIs intentionally leave scheduling to their caller.

### Why user space is not automatically faster

Both implementations still use kernel TCP sockets; smb-rs does not bypass the
kernel networking stack. Avoiding a few syscall transitions cannot compensate
for software AES over every payload byte. Kernel CIFS also has mature credit
autotuning, request batching, parallel workqueues, optimized crypto plumbing,
scatter/gather I/O, and decades of data-path tuning. In this run, transition
overhead was not visible as a leading CPU cost; AES-CMAC was.

## Optimization order

The evidence supports this order rather than starting with generic async or
allocation changes:

1. Run on a CPU/VM exposing AES-NI, and benchmark an accelerated CMAC backend.
2. Separate “signing supported” from “signing required” in client policy, while
   preserving server/session-required signing and comparing only equivalent
   security modes. **Implemented: `ConnectionConfig::signing_required` defaults
   to `false`; this does not disable signing.**
3. Move per-message signing and verification out of the single runtime owner
   into a bounded parallel crypto stage without weakening wire ordering.
   **Implemented and real-target validated in this follow-up.**
4. Autotune read and write chunk sizes separately and observe actual granted
   credits, rather than merely raising the requested credit target. Keep this
   policy inside smb-rs so migration logic does not depend on SMB mechanics.
5. Evaluate AES-GMAC preference only after replacing its current whole-message
   buffering with a streaming implementation; otherwise it trades one hotspot
   for an additional payload copy/allocation.

Copy/allocation and syscall optimization should be measured again after the
crypto ceiling is removed. The current profile gives them too little CPU share
to justify treating them as the first fix.

## Bounded parallel CMAC implementation

The follow-up implementation removes signing and verification from the single
runtime-owner critical path while keeping all SMB protocol state in that owner.
It has these constraints:

- each connection owns a semaphore-bounded crypto executor; its default width
  is the smaller of the host's available parallelism and four, with a minimum
  of one;
- signed payloads below 64 KiB execute inline, avoiding a blocking-pool and
  asynchronous-preparation penalty for latency-sensitive requests;
- large signed writes are prepared concurrently, but completed frames are
  released to the transport in reservation order;
- incoming frames are transformed concurrently with the same bound and are
  delivered back to the owner in receive order;
- semaphore permits live inside the actual blocking jobs, so cancelling an
  awaiting future cannot make the executor start more work than its bound;
- payload ownership is moved through `Bytes` and sealed frame segments; the
  parallel stage does not introduce a full-payload copy.

Compounds wait for earlier independently prepared requests before admission.
Credit accounting, message-ID allocation, response correlation, deadlines,
cancellation, and session/preauthentication state remain exclusively owned by
the runtime owner.

### Real-target result after optimization

The same public `Client`/`Share`/`File` path was rerun in release mode with five
measured samples. The large-transfer case uses 40 MiB and 16 requested in-flight
operations on one connection. The baseline is the controlled pre-optimization
1x16 DXN run above and the original FAS2750 matrix row. Sample counts differ
(five after optimization versus three in the original FAS matrix), so the
ratios should be treated as engineering comparisons rather than formal
cross-run confidence intervals.

| Target | Path | Before | After | Ratio |
| --- | --- | ---: | ---: | ---: |
| DXN | Write | 31.50 MiB/s | 88.99 MiB/s | 2.83x |
| DXN | Read | 33.89 MiB/s | 92.70 MiB/s | 2.74x |
| FAS2750 | Write | 30.38 MiB/s | 79.05 MiB/s | 2.60x |
| FAS2750 | Read | 30.22 MiB/s | 84.19 MiB/s | 2.79x |

All stable runs passed byte-for-byte verification, remote flush, cleanup, and
the benchmark's 10% coefficient-of-variation threshold. DXN's final write/read
CV was 0.71%/0.60%; FAS2750's was 3.09%/1.77%.

The first FAS2750 post-optimization run is retained for transparency. It
reported 83.42/83.24 MiB/s write/read, but write CV was 11.68%, so the benchmark
failed only its statistical threshold. An unchanged rerun produced the stable
result in the table.

The 64 KiB inline threshold was separately validated with repeated 4 KiB
transfers:

| Target | Write | Read | Write/read CV |
| --- | ---: | ---: | ---: |
| DXN | 6.14 MiB/s | 6.47 MiB/s | 9.93% / 1.12% |
| FAS2750 | 4.00 MiB/s | 4.06 MiB/s | 9.46% / 4.00% |

These results are close to the original 4 KiB medians (DXN 6.50/6.56 MiB/s;
FAS2750 3.92/4.25 MiB/s), so the large-transfer gain did not create a material
small-request regression. One earlier DXN run reported 6.07/6.57 MiB/s but
failed the CV threshold at 12.10% on writes; the unchanged stable rerun is shown
above.

Unit coverage additionally proves the executor bound, inline fast path,
cancellation-safe permit lifetime, ordered release after out-of-order worker
completion, and rejection of a tampered AES-CMAC payload.

### Paired comparison with a signed kernel mount

A final comparison reran smb-rs and the kernel mount alternately in the same
test process and time window. Both paths targeted the same share, used one
warm-up plus three measured samples, flushed writes, and verified every byte.
The mount used SMB 3.1.1, `cache=none`, `actimeo=0`, and `sec=ntlmsspi`, so its
data traffic was signed like smb-rs. “API/mount” is the median smb-rs throughput
divided by the median signed-mount throughput.

| Target | Payload | smb-rs write | Signed mount write | API/mount | smb-rs read | Signed mount read | API/mount |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| DXN | 4 KiB | 5.47 | 7.90 | 69.3% | 8.37 | 8.81 | 95.1% |
| DXN | 40 MiB | 60.92 | 70.20 | 86.8% | 67.26 | 67.12 | 100.2% |
| DXN | 1 GiB | 86.78 | 79.30 | 109.4% | 87.21 | 74.51 | 117.0% |
| FAS2750 | 4 KiB | 3.79 | 5.36 | 70.8% | 4.43 | 4.55 | 97.3% |
| FAS2750 | 40 MiB | 85.36 | 41.83 | 204.0% | 81.93 | 42.89 | 191.0% |
| FAS2750 | 1 GiB | 87.87 | 40.88 | 214.9% | 83.42 | 42.60 | 195.8% |

All values are MiB/s. Every coefficient of variation was below 10%; the largest
was 9.26% for the FAS2750 signed-mount 4 KiB read. Both target runs passed and
removed their SMB and mount-path test files. Their temporary mounts and mount
directories were also removed.

This paired result changes the earlier conclusion that the kernel path is
always faster. Small requests still favor the kernel because fixed request and
scheduling costs dominate. With equivalent signing enabled, smb-rs reaches
near parity by 40 MiB on DXN and exceeds the signed kernel path at 1 GiB; on
FAS2750 it is roughly twice as fast for both large payloads. The ordinary-mount
table at the start of this report remains useful as an observed
default-configuration comparison, but its exact signing behavior was not
packet-confirmed and it must not be presented as an equal-security result.

The paired harness uses the negotiated maximum request size: 8 MiB on DXN and
1 MiB on FAS2750. That explains why its DXN 40 MiB smb-rs result is lower than
the 2.5 MiB-chunk, 1x16 result above: the shorter five-request transfer has less
opportunity to fill the parallel pipeline and each 8 MiB request consumes a
larger credit window. At 1 GiB the steady-state pipeline reaches 86–87 MiB/s.

### Second paired explicit-signing run

After the signing protocol audit and fixes, the complete paired matrix was run
again. This rerun made the mount policy independently observable before the
benchmark: the mount command included `sign`, and the kernel reported
`sec=ntlmsspi`, SMB 3.1.1, `cache=none`, and `actimeo=0`. This matters because
`sec=ntlmssp` selects the authentication mechanism but, without the trailing
`i` or the separate `sign` option, does not by itself force packet signing.

The test otherwise kept the same controls: one warm-up, three measured
samples, alternating path order, 16 requested smb-rs operations in flight,
write flush/fsync, byte-for-byte read verification, and cleanup. The FAS2750
4 KiB row was rerun with five measured samples because the first three-sample
mount-read CV was 13.19%; the table uses that rerun.

| Target | Payload | smb-rs write | Signed mount write | API/mount | smb-rs read | Signed mount read | API/mount |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| DXN | 4 KiB | 6.34 | 9.31 | 68.1% | 6.45 | 8.75 | 73.7% |
| DXN | 40 MiB | 60.13 | 69.78 | 86.2% | 65.54 | 68.15 | 96.2% |
| DXN | 1 GiB | 86.40 | 79.42 | 108.8% | 87.27 | 75.47 | 115.6% |
| FAS2750 | 4 KiB | 4.45 | 4.93 | 90.1% | 4.10 | 5.07 | 80.7% |
| FAS2750 | 40 MiB | 81.28 | 39.99 | 203.3% | 79.40 | 41.62 | 190.8% |
| FAS2750 | 1 GiB | 85.90 | 40.03 | 214.6% | 81.91 | 41.91 | 195.4% |

All values are median MiB/s. Every large-transfer CV was below 5.6%. In the
five-sample FAS2750 4 KiB rerun, smb-rs write/read CV was 8.01%/10.17% and the
signed mount was 2.86%/4.28%; the smb-rs read result is therefore marked as
slightly unstable rather than silently selecting another run.

The large-transfer results reproduce the previous paired run closely. At 40
MiB, smb-rs is within 14% of signed-mount writes and within 4% of signed-mount
reads on DXN, while it is about 1.9–2.0x the FAS2750 signed mount. At 1 GiB,
smb-rs is about 1.09–1.16x the DXN signed mount and about 1.95–2.15x the
FAS2750 signed mount. Every run passed content verification and removed both
test files; the temporary mounts were unmounted.

For comparison only, an initial DXN control mount used `sec=ntlmssp` without
the explicit `sign` option and reached 108.13 MiB/s write and 101.82 MiB/s read
at 1 GiB. It is not labelled an unsigned result: an option that does not force
signing is not proof that each data packet was unsigned. It is excluded from
the equal-security table above.

## Cooperative connection-driver follow-up (2026-09-03)

The runtime previously used one state-owner task plus separate read and write
pump tasks. Every transport result therefore crossed a Tokio task wakeup and an
MPSC channel before the owner could reduce it. The implementation now keeps one
long-lived connection-driver task and polls independent read and active-write
futures directly. Read and write remain full duplex; protocol state still has a
single owner, and partial-write cancellation still waits for the transport send
to finish or for the explicit close deadline.

A local in-memory request/response benchmark reduced median fixed round-trip
overhead from 58.1 us to 36.7 us per operation (about 37%). This isolates the
removed scheduling path but is not a network throughput result.

The signed DXN runs used the public API, 4 KiB SMB operations, one warm-up and
five measured samples:

| Shape | Files | Write | Read | Write/read CV | Result |
| --- | ---: | ---: | ---: | ---: | --- |
| 1 connection x 1 in flight | 1 | 5.63-5.77 MiB/s | 6.61-6.77 MiB/s | up to 12.91% / 12.46% | statistically unstable |
| 1 connection x 16 in flight | 1 | 22.34 MiB/s | 25.00 MiB/s | 2.41% / 1.61% | passed |
| 1 connection x 16 in flight | 16 | 22.06 MiB/s | 24.53 MiB/s | 1.96% / 2.35% | passed |

The same-day pre-change 1x1 control was 6.32 MiB/s write and 6.62 MiB/s read.
The post-change 1x1 read median is comparable, while the write samples are both
lower and too variable to establish an improvement. Consequently the real
target data does not support claiming a single-request throughput gain even
though the isolated scheduler latency fell. At 16 operations in flight, using
16 different files instead of one changes write/read throughput by only
-1.3%/-1.9%, which is within run variance and shows no file-count-specific
penalty from the single connection driver.

Every DXN run verified returned bytes and removed its remote files. The
multi-file case is retained as the ignored release test
`signed_4k_multi_file_single_connection`.

### Paired rerun after connection-driver optimization

The complete public-API versus kernel-mount matrix was rerun on both targets
after the cooperative connection-driver change. Both paths accessed the same
share on each target. The mount was forced to SMB 3.1.1 with signing,
`cache=none`, and `actimeo=0`; smb-rs used one connection and up to 16 in-flight
requests. Each case used one warm-up and three measured samples, included
flush/fsync in write time, and verified every byte read.

| Target | Payload | smb-rs write | Signed mount write | API/mount | smb-rs read | Signed mount read | API/mount |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| DXN | 4 KiB | 5.95 | 9.31 | 63.9% | 6.84 | 8.70 | 78.7% |
| DXN | 40 MiB | 61.47 | 71.25 | 86.3% | 66.50 | 67.71 | 98.2% |
| DXN | 1 GiB | 87.13 | 78.91 | 110.4% | 87.73 | 76.53 | 114.6% |
| FAS2750 | 4 KiB | 3.68 | 5.51 | 66.7% | 4.40 | 5.13 | 85.7% |
| FAS2750 | 40 MiB | 85.27 | 40.49 | 210.6% | 81.69 | 43.17 | 189.2% |
| FAS2750 | 1 GiB | 85.80 | 40.54 | 211.6% | 85.10 | 43.33 | 196.4% |

All throughput values are median MiB/s. Every coefficient of variation was
below 5.8%. Both target tests passed, deleted their two remote test files, and
unmounted their temporary CIFS mounts successfully.

The result separates latency-bound and pipeline-bound behavior. A serialized
4 KiB operation still favors the kernel client. DXN reaches near read parity at
40 MiB and smb-rs is 10-15% faster at 1 GiB. On FAS2750, smb-rs is about
1.9-2.1x the signed mount for both large sizes. These large-transfer medians are
close to the preceding explicit-signing run, so removing the per-event pump
hop reduced isolated scheduling latency without materially changing the
steady-state server/network ceiling.

## Reproduction interface

The ignored release benchmark is
`crates/smb/tests/cifs_mount_performance.rs`. Runtime-only inputs select the SMB
server/share credentials, target label, and mount path. Optional controls are:

- `SMB_RUST_PERF_SAMPLES` (default `3`);
- `SMB_RUST_PERF_INFLIGHT` (default `16`);
- `SMB_RUST_PERF_MINIMUM_TRANSFER_BYTES` (default `16777216`);
- `SMB_RUST_PERF_PAYLOAD_BYTES` to select one of `4096`, `41943040`, or
  `1073741824` for a focused rerun.

The existing `crates/smb/tests/ontap_performance.rs` benchmark was also used for
the controlled follow-up. `SMB_RUST_PERF_SHAPE` selects `1x1` or `1x16`, and the
new optional `SMB_RUST_PERF_CHUNK_BYTES` imposes a reproducible chunk-size cap
without changing production behavior. `SMB_RUST_PERF_SIGNING_REQUIRED=true`
exercises the public client-required-signing policy; when absent it uses the
default optional policy.

Both full runs and the focused rerun removed their test files. The temporary
CIFS mounts were unmounted and their mount directories removed.

## Historical OpenSSL AES-CMAC comparison (2026-09-03)

This section records an intermediate experiment. The OpenSSL implementation,
Cargo feature, and dependency were subsequently removed; the production
implementation is the four-lane RustCrypto backend in the following section.

The signed 4 KiB CPU profile identified RustCrypto's software AES-CMAC as the
dominant client-side cost on this VM, which does not expose AES-NI. An
intermediate build compared OpenSSL 0.10.81 with the scalar RustCrypto
implementation. Both used the same internal segmented-signing seam, so the SMB
header and file payload were streamed without being joined or copied.

The release-mode 4160-byte CMAC probe measured the complete per-message signer
initialization, segmented update, and finalization path:

| Backend | Time per CMAC | Throughput | Relative |
| --- | ---: | ---: | ---: |
| OpenSSL | 40.9 us | 96.9 MiB/s | 2.57x |
| RustCrypto fallback | 105.1 us | 37.8 MiB/s | 1.00x |

RFC 4493 known-answer tests, segmented input tests, and signed-message tamper
rejection passed with both backends. Real-server runs required signing, used
one warm-up plus five measured samples, verified all returned data, and removed
their run-owned files.

| Target | Shape | Backend | Write MiB/s | Read MiB/s | Write/read CV |
| --- | --- | --- | ---: | ---: | ---: |
| DXN | 1 connection, 1 x 4 KiB in flight | OpenSSL | 6.82-6.99 | 7.26-7.30 | 7.4-9.6% / 10.3-13.7% |
| DXN | 1 connection, 1 x 4 KiB in flight | RustCrypto | 6.27 | 6.54 | 11.2% / 11.2% |
| FAS2750 | 1 connection, 1 x 4 KiB in flight | OpenSSL | 4.30 | 4.63 | 5.9% / 4.7% |
| FAS2750 | 1 connection, 1 x 4 KiB in flight | RustCrypto | 4.32 | 4.07 | 2.2% / 9.0% |
| DXN | 1 connection, 16 x 4 KiB in flight | OpenSSL | 30.92 | 35.06 | 2.2% / 1.9% |
| DXN | 1 connection, 16 x 4 KiB in flight | RustCrypto | 21.32 | 24.12 | 0.8% / 1.0% |
| FAS2750 | 1 connection, 16 x 4 KiB in flight | OpenSSL | 27.73 | 28.28 | 10.9% / 1.5% |
| FAS2750 | 1 connection, 16 x 4 KiB in flight | RustCrypto | 18.75 | 20.08 | 1.7% / 11.0% |

The stable DXN 16-request comparison improved write by 45.0% and read by
45.4%. FAS2750 showed the same direction, improving the corresponding medians
by 47.9% and 40.8%, although one direction in each FAS backend run narrowly
exceeded the 10% CV gate. Serialized operations remain substantially
RTT-bound: the faster signer improves DXN by roughly 9-12% and FAS reads by
13.5%, but the paired FAS write medians were effectively unchanged.

## Four-lane portable RustCrypto CMAC follow-up (2026-09-03)

Production is assumed not to expose AES-NI or VAES. The default `sign_cmac`
feature therefore returned to RustCrypto and now advances four independent
CMAC chains through one complete 64-bit fixslice AES state. Batching is internal
to the connection runtime: callers still submit atomic operations, payload
owners remain shared `Bytes`, and no timer waits for a partially filled batch.
Only operations already ready in the same owner turn are coalesced. Serialized
outgoing operations keep the scalar path.

The implementation groups work by the identity of the immutable expanded key,
not merely by SessionId, preventing different channel keys from sharing an AES
operation. Incoming processing first drains up to four transport frames that
are already ready and then starts ordered verification work. Preauthentication
and setup-phase signing remain outside the batching path.

Release-mode CPU probes on the generic 2 GHz KVM CPU (no AES-NI/AVX) measured:

| Probe | Time per 4160-byte message | Aggregate throughput |
| --- | ---: | ---: |
| Previous scalar RustCrypto rerun | 97.8 us | 40.56 MiB/s |
| Four-lane CMAC core | 25.9 us | 153.26 MiB/s |
| Runtime batch coordinator | 26.6 us | 149.28 MiB/s |

RFC 4493 empty and 16-byte vectors passed. Differential tests against the
standard RustCrypto `cmac` crate covered 0, 1, 15, 16, 17, 31, 32, 63, 64,
4095, and 4160-byte messages, split across segment boundaries and refilled over
more than four inputs. Runtime tests proved one four-lane group for four ready
4 KiB writes and four ready 4 KiB responses; payload storage was not copied.

Real-server tests required signing, used one warm-up plus five measured samples,
verified every read, and removed all sixteen run-owned files:

| Target | Shape | Backend | Write MiB/s | Read MiB/s | Write/read CV |
| --- | --- | --- | ---: | ---: | ---: |
| DXN | 1 connection, 1 x 4 KiB in flight | four-lane RustCrypto | 6.32 | 6.50 | 3.5% / 9.7% |
| DXN | 1 connection, 16 x 4 KiB in flight | four-lane RustCrypto | 35.85 | 41.23 | 2.5% / 1.3% |
| FAS2750 | 1 connection, 1 x 4 KiB in flight | four-lane RustCrypto | 4.24 | 3.87 | 3.9% / 8.2% |
| FAS2750 | 1 connection, 16 x 4 KiB in flight | four-lane RustCrypto | 29.45 | 32.11 | 0.5% / 7.8% |

Against the previous scalar RustCrypto 1x16 medians, DXN improved by 68.2% for
write and 70.9% for read; FAS2750 improved by 57.1% and 59.9%. Against the
previous OpenSSL medians, the four-lane backend improved DXN by 15.9% and
17.6%, and FAS2750 by 6.2% and 13.5%. Serialized results remained within about
5% of the previous RustCrypto measurements, confirming that the batching
policy did not trade ordinary request latency for concurrent throughput.

## Current RustCrypto API versus mount rerun (2026-09-03)

The complete comparison was rerun after removing the OpenSSL implementation
and dependency. The tested working tree was based on commit `d8291b3a3157`.
The client host used Linux 6.8.0 on a generic 2 GHz KVM CPU without AES-NI.

Both kernel paths used SMB 3.1.1, `sec=ntlmssp`, `cache=none`, `actimeo=0`, and
`nosharesock`. DXN negotiated 4 MiB mount `rsize`/`wsize`; FAS2750 negotiated
1 MiB. The smb-rs side used one connection and up to 16 in-flight chunks.
Writes include `flush`/`fsync`, every read was byte-for-byte verified, and the
two paths alternated execution order.

Each result is the median of three samples after one warm-up. To make each
sample long enough to suppress sub-second appliance variance, the 4 KiB case
transferred 16 MiB per DXN sample and 64 MiB per FAS2750 sample. The 40 MiB
case repeated the complete 40 MiB transfer ten times per sample (400 MiB per
direction). The 1 GiB case performed one complete transfer per sample.

| Target | Payload | smb-rs write | Mount write | API/mount | smb-rs read | Mount read | API/mount |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| DXN | 4 KiB | 6.08 | 8.80 | 69.1% | 6.46 | 9.55 | 67.6% |
| DXN | 40 MiB | 64.73 | 107.18 | 60.4% | 65.85 | 102.10 | 64.5% |
| DXN | 1 GiB | 86.59 | 107.88 | 80.3% | 87.33 | 101.09 | 86.4% |
| FAS2750 | 4 KiB | 3.90 | 5.51 | 70.8% | 4.08 | 5.35 | 76.2% |
| FAS2750 | 40 MiB | 80.75 | 59.29 | 136.2% | 77.56 | 77.00 | 100.7% |
| FAS2750 | 1 GiB | 87.86 | 68.76 | 127.8% | 82.42 | 75.33 | 109.4% |

All throughput values are MiB/s. The final coefficients of variation were at
most 6.9%: DXN 4 KiB 1.8-6.9%, DXN 40 MiB 0.1-1.4%, DXN 1 GiB 0.3-1.0%,
FAS2750 4 KiB 1.2-5.9%, FAS2750 40 MiB 1.7-6.2%, and FAS2750 1 GiB 0.3-6.1%.

The repeated 4 KiB case is intentionally serialized because each complete
payload contains only one SMB request; its median per-operation latencies were
0.642/0.605 ms for smb-rs DXN write/read versus 0.444/0.409 ms for mount, and
1.001/0.959 ms for smb-rs FAS2750 versus 0.709/0.731 ms for mount. The earlier
16-file test remains the measurement of four-lane small-request concurrency.

DXN continues to favor the kernel mount in every cell, but the current smb-rs
implementation reaches 80-86% of mount throughput at 1 GiB, rather than the
26-33% recorded before the bounded crypto and driver changes. On FAS2750,
smb-rs reaches parity on 40 MiB reads and exceeds the mount for 40 MiB writes
and both 1 GiB directions. This is target-specific: the FAS mount is limited to
1 MiB I/O and its write path showed greater appliance variance, while smb-rs
can maintain a deeper asynchronous request pipeline.

The first FAS2750 40 MiB single-transfer run and its immediate short rerun were
not used because their coefficients of variation reached 14.9% and 36.8%.
Increasing the sample duration produced the stable confirmation above; no
individual favorable sample was selected.

## Default credit target 1024 trial (2026-09-03)

The connection's default target was increased from 128 to 1024 credits and
compared with a freshly rebuilt 128-credit control. Each run transferred 40
MiB through one connection with a caller window of 16 operations, one warm-up,
and five measured samples. No chunk override was supplied. DXN therefore used
2.5 MiB chunks under its negotiated 8 MiB maximum; FAS2750 used its negotiated
1 MiB maximum. All reads were verified and all run-owned files were removed.

| Target | Credit target | Write MiB/s | Read MiB/s | Write/read CV |
| --- | ---: | ---: | ---: | ---: |
| DXN | 128 | 90.04 | 93.39 | 2.54% / 0.75% |
| DXN | 1024 | 93.13 | 93.51 | 3.73% / 0.36% |
| FAS2750 | 128 | 82.57 | 77.99 | 5.17% / 4.34% |
| FAS2750 | 1024 | 85.18 | 84.77 | 1.65% / 2.94% |

The 1024 target produced no regression in this trial. Relative to 128, DXN
changed by +3.4% write and +0.1% read; FAS2750 changed by +3.2% write and +8.7%
read. These modest deltas show that a larger requested window can remove part
of the credit constraint, but is not by itself the dominant throughput fix.
The benchmark observes end-to-end throughput rather than the server's internal
credit ceiling, so these results do not assert that either server granted the
entire requested target.

## 1024-credit API versus mount comparison (2026-09-03)

The complete public-API versus kernel-mount matrix was rerun after changing
`ConnectionConfig::DEFAULT_CREDITS_BACKLOG` to 1024. The release build was
based on commit `d8291b3a3157` plus the working-tree changes described in this
report, on Linux 6.8.0 and a generic 2 GHz KVM CPU without AES-NI.

Both mount paths used SMB 3.1.1, `sec=ntlmssp`, `cache=none`, `actimeo=0`, and
`nosharesock`. The smb-rs path used one connection and a caller window of 16
operations. The benchmark alternated path order, included SMB `flush` and
mount `sync_all` in write timings, and verified every byte read. Each result is
the median of three samples after one warm-up.

The 4 KiB samples transferred 16 MiB per DXN sample and 64 MiB per FAS2750
sample. The 40 MiB workload repeated ten times per sample (400 MiB per
direction), and the 1 GiB workload ran once per sample. This kept every
coefficient of variation at or below 5.6%.

| Target | Payload | smb-rs write | Mount write | API/mount | smb-rs read | Mount read | API/mount |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| DXN | 4 KiB | 6.24 | 11.11 | 56.1% | 6.23 | 9.42 | 66.1% |
| DXN | 40 MiB | 64.80 | 107.07 | 60.5% | 65.01 | 101.79 | 63.9% |
| DXN | 1 GiB | 86.71 | 108.40 | 80.0% | 87.36 | 101.05 | 86.4% |
| FAS2750 | 4 KiB | 3.89 | 5.33 | 72.9% | 4.10 | 5.01 | 81.8% |
| FAS2750 | 40 MiB | 82.34 | 67.40 | 122.2% | 81.63 | 77.31 | 105.6% |
| FAS2750 | 1 GiB | 85.45 | 68.28 | 125.2% | 82.92 | 74.71 | 111.0% |

All throughput values are MiB/s. DXN continues to favor the kernel client: the
smb-rs ratio rises from roughly 60-64% at 40 MiB to 80-86% at 1 GiB. On
FAS2750, smb-rs remains slower for serialized 4 KiB operations but exceeds the
mount for both directions at 40 MiB and 1 GiB.

Compared with the immediately preceding 128-credit full matrix, the 1024-credit
results are broadly unchanged. This confirms that increasing the requested
credit target is safe on both tested appliances but is not sufficient to close
the DXN gap while the comparator uses negotiated-maximum 8 MiB smb-rs chunks.
The separate chunk-shape experiment remains the evidence that DXN performs
better with a deeper window of smaller requests.

Every file owned by this run was deleted and both temporary mounts were
removed. A pre-existing DXN pair named with PID `4133448`, dated 2026-09-02,
was confirmed not to belong to this run and was preserved.
