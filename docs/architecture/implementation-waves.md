# Reversible architecture implementation waves

## Status and objective

Accepted execution plan for replacing the current SMB client architecture with
the domain-first async design. It converts ADR-0001 through ADR-0006 and the
FAS2750 acceptance contract into dependency-ordered changes that keep the main
branch at an Accepted checkpoint after every merge.

An Implementation wave is both a delivery boundary and a rollback boundary.
It is not a time box and may contain several bisectable commits, but it cannot
depend on an unmerged later wave or leave a known hard-gate failure for that
later wave to repair.

## Global execution rules

1. Merge order is strictly W0 through W6. Parallel investigation and branch
   work are allowed, but a later wave rebases onto the latest Accepted
   checkpoint and reruns every affected gate before merge.
2. Behavior fixes are separate from architecture changes. A newly discovered
   defect is fixed and verified in its own commit, and when practical its own
   pre-wave change, before structural work resumes.
3. A wave may contain separate mechanical-move, behavior, test, and evidence
   commits. The complete wave must be revertible with one ordinary revert of
   its merge commit or an explicitly recorded reverse-order commit list.
4. The latest wave may be reverted alone. Reverting an older wave requires
   reverting all dependent waves in reverse order. Every evidence record names
   `depends_on` and the exact rollback command or commit sequence.
5. A migrated path has one authoritative implementation at the checkpoint.
   Branch-local dual paths are permitted only while assembling a wave; no
   dual-write registry, lifecycle state, wire representation, or long-lived
   compatibility feature may merge.
6. Every temporary adapter records its owning wave and `remove_by` wave. An
   expired adapter is a hard failure, not cleanup debt.
7. Tests use the same external Interface as callers. Tests coupled to deleted
   handler maps, worker channels, or task layout are replaced by equal or
   stronger observable-behavior tests and removed with their implementation.
8. Production data-path `unsafe` is forbidden unless a separate accepted ADR
   and proof tests justify it. Production paths add no implicit `unwrap` or
   `expect` panic. Every runtime task has one owner, shutdown condition, and
   join path.

## Gate activation

Every wave reports the complete matrix. A requirement owned by a later wave has
the planning status `NotYetActivated`, with its owner wave; it is not executed
as a Validation run case and is never reported as Passed, NotApplicable, or
silently skipped. This planning status is separate from the four case results
defined by the FAS2750 acceptance contract. When its owner wave merges, the
requirement becomes an Activation gate and remains a hard gate for every later
checkpoint.

Existing behavior frozen by W0 may not regress in any wave. Each architecture
wave runs local workspace tests, activated copy/allocation and lifecycle gates,
and the applicable isolated FAS2750 functional matrix. A wave that changes the
data path, concurrency model, or performance-sensitive public I/O runs the
complete plain and encrypted performance matrix. W6 always runs the complete
milestone matrix.

A failing local or appliance hard gate blocks the merge. The failure is
classified as implementation defect, performance regression, or validation
infrastructure defect and resolved inside the wave. If it cannot be resolved,
the branch is abandoned or the wave is redesigned; the previous Accepted
checkpoint remains main.

## Wave plan

### W0 — Freeze the pre-rewrite baseline

Purpose: preserve already demonstrated behavior and evidence without mixing it
with target-architecture implementation.

Deliverables are split into at least three atomic commit groups:

1. FAS2750 negotiation, authentication, signing interoperability fixes and
   their regression tests;
2. the ONTAP baseline harness and secret-free baseline record;
3. architecture ADRs, specifications, research, validation contract, and
   domain glossary.

The checkpoint must pass the current workspace suite and the frozen real-server
functional and performance baseline. W0 introduces no target runtime, wire, or
public-interface implementation.

### W1 — Build verification infrastructure

Purpose: make later structural changes measurable before changing authority.

Deliverables:

- a deterministic transport Adapter, controllable clock, fault injection, and
  lifecycle scenario harness behind internal test seams;
- copy/allocation attribution, retained-payload/window accounting, task and
  pending-record leak checks, and benchmark reporting required by ADR-0001;
- automated dependency-direction checks for facade → domain → runtime → codec
  → transport;
- reusable black-box state, cancellation, timeout, partial-write, shutdown,
  and first-terminal-wins scenarios;
- the secret-free evidence record schema used by later waves.

Production retains only low-cost, payload-free structured observation points.
The counting allocator, deterministic clock, fault transport, and internal
state snapshots are test/benchmark-only and are not public Interfaces.

### W2 — Replace the wire data plane

Purpose: establish the sole byte-ownership model before the concurrency core
depends on it.

Deliverables:

- immutable Transport frames and validated Wire views for receive;
- mutable metadata builders that seal into immutable shared segments;
- scatter/gather signing and sends without payload consolidation;
- transform-consume-and-replace behavior for encryption and compression;
- transport-owned partial-write cursor and adapter-owned framing;
- codec range, alignment, compound, malformed-frame, and transform tests.

The existing connection path calls the new unique wire Interface through a
thin stateless adapter marked `remove_by: W3`. There is no second codec, buffer
registry, or payload owner. W2 activates the plain signed TCP payload-copy and
payload-allocation gates and runs the full plain/encrypted performance matrix.

### W3 — Replace the single-generation request runtime

Purpose: make one deep module the only authority for request progress within a
physical connection generation.

Deliverables:

- one state-owner task plus read and write pumps;
- admission, message IDs, credits, pending records, tombstones, deadlines,
  cancellation, backpressure, and first-terminal-wins;
- deterministic connection close, pending failure, payload release, task
  shutdown, and join;
- migration of every existing SMB command through the typed operation/result
  Interface;
- removal of MessageHandler, Worker/MultiWorkerBackend, peer ConnectionActor
  authority, registry-owning Transformer behavior, and the W2 adapter.

W3 owns the complete lifecycle within one generation. Cross-generation
recovery and unsolicited server event policy remain W4 and are explicitly
NotYetActivated. The accepted checkpoint contains no old authoritative request
path. W3 runs the complete concurrency and performance matrix.

### W4 — Add recovery and server-event lifecycles

Purpose: extend the runtime from one generation to the complete object
hierarchy without weakening its single-owner model.

Deliverables:

- generation-aware Connection, Session, Share, and Resource authority;
- atomic parent cascade, revocation, bounded recovery queues, and replacement
  token publication;
- automatic connection, session, and share recovery and protocol-supported
  durable/persistent Resource recovery;
- explicit replay categories and OutcomeUnknown handling;
- lease/oplock break validation and ACK, cache invalidation, change-notify
  delivery, cancellation, overflow, and lag policy;
- exact-session disruption and ten-cycle cleanup/recovery stress.

W4 activates automatic recovery, cross-generation stale-handle rejection,
lease/oplock/change-notify, and conditional CA persistent-handle gates. It runs
the complete FAS2750 functional matrix and the performance matrix because it
changes concurrency and retained-memory behavior.

### W5 — Cut over the domain-first public interface

Purpose: expose the target architecture as one deep caller Interface without a
compatibility surface.

Deliverables:

- `Client → Session → Share → Resource` handles and lazy configurable
  operations;
- positioned and cursor I/O, owned/shared payload contracts, typed close,
  cancellation, batching, event streams, and transfer helpers;
- removal of public Tree terminology, raw request pairing, message IDs,
  credits, worker/channel selection, and runtime implementation types;
- atomic migration of `smb-rpc`, CLI, workspace tests, examples, and docs;
- deletion of deprecated aliases, compatibility facade, and temporary call-site
  adapters before merge.

Because compatibility is explicitly out of scope, the old public Interface is
removed rather than deprecated. W5 activates all public ownership, error,
close, cancellation, and extension-module gates and runs the complete
functional and performance matrices.

### W6 — Remove residue and accept the milestone

Purpose: prove the shipped structure and behavior match the accepted design,
not merely that the new happy path works.

Deliverables:

- removal of expired adapters, dead features, old threading documentation,
  reverse dependencies, duplicated registries, and implementation-coupled
  tests;
- source and documentation audit against every accepted ADR and architecture
  contract;
- complete local function, fault, lifecycle, concurrency, copy/allocation,
  dependency, panic, task-ownership, and leak gates;
- complete isolated FAS2750 functional, plain/encrypted performance,
  automatic-recovery, Previous Versions, and conditional CA matrix;
- verified cleanup of the Validation run Resource inventory and final
  secret-free evidence package.

The architecture map may close only after W6 passes. QUIC, RDMA, Kerberos,
Multichannel, and real takeover/giveback remain later roadmap work and cannot
be used to defer a first-phase hard gate.

## Evidence record

Each wave adds a Markdown record containing:

- wave ID, branch/commit range, `depends_on`, and rollback instructions;
- changed module Interfaces and deleted authority paths;
- activated and NotYetActivated gates;
- local commands and results;
- copy/allocation and retained-memory results;
- anonymized FAS2750 case results and performance summary when required;
- known out-of-scope work and confirmation that no expired adapter remains.

The machine-readable Validation run manifest is retained as a CI artifact, not
committed. It contains no credentials or raw target details. A documentation-
only claim cannot substitute for the measured gate owned by a wave.
