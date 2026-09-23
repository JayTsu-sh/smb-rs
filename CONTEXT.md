# Domain glossary

## Async core

The single asynchronous execution model that owns SMB connection lifecycle,
request scheduling, cancellation, and I/O progress. Synchronous interfaces, if
offered, are adapters and are not separate protocol implementations.

## Directory authentication

**AD-authenticated CIFS access**:
An SMB session in which an Active Directory domain user is authenticated by a
domain-joined CIFS server and authorized to access a named share.
_Avoid_: AD domain function, domain API

**Samba CIFS gateway**:
The Samba service that exports an SMB share and owns Active Directory
authentication, Kerberos, and SMB signing behavior above its storage backend.
_Avoid_: CephFS server, storage backend

**Validation principal**:
A dedicated least-privilege Active Directory user whose share access is used
to prove AD-authenticated CIFS access.
_Avoid_: Administrator account, test credential

**Dual-target CIFS acceptance**:
A repeatable acceptance profile that proves the same SMB client behavior
against a DXN Samba share authenticated by Active Directory and an FAS ONTAP
share authenticated by a local CIFS user. It does not imply that both targets
use the same identity provider.
_Avoid_: universal AD validation

**CIFS acceptance profile**:
A named, reproducible binding of one validation target endpoint, one share,
one identity kind, and runtime-only credentials. A profile rejects a target,
share, or identity-kind mismatch rather than silently testing another share.
_Avoid_: generic real-server configuration

**Identity kind**:
The declared source of a validation identity: either an Active Directory
principal or a local CIFS principal. It is part of the acceptance profile and
must not be inferred from a successful login.
_Avoid_: username format, authenticated user

**Run-owned temporary file**:
A uniquely named file whose ownership is established only after this validation
run successfully creates it with create-new semantics and records its Run ID.
Cleanup authority covers only that recorded file, never a matching prefix or
pre-existing name.
_Avoid_: temporary file, test prefix

**Acceptance evidence**:
A secret-free record of a validation run's profile, Run ID, phase outcomes,
cleanup outcome, and any run-owned residual object. It is not a packet trace
or command transcript.
_Avoid_: test log, raw trace

**Acceptance failure category**:
A portable classification of a failed validation phase: authentication
rejection, share access denial, I/O failure, cleanup failure, or target
unavailability. It preserves the underlying diagnostic without using raw
server text as the acceptance result.
_Avoid_: generic failure, server error string

**Acceptance execution**:
A manually authorized real-device run on a controlled, secret-enabled runner.
A profile may run alone for diagnosis, while merge or release acceptance
requires the DXN and FAS profiles to pass against the same commit.
_Avoid_: ordinary CI run, device smoke test

**Blocked acceptance run**:
A real-device validation run whose target is unavailable at preflight. It
records target unavailability and evidence but cannot pass or be treated as a
code failure.
_Avoid_: skipped acceptance, successful retry

**Acceptance artifact**:
A controlled CI-retained, secret-free evidence package for a validation run.
It is not repository history; only an accepted checkpoint Markdown summary is
committed.
_Avoid_: permanent raw logs, committed test output

**Dual-target acceptance runner**:
Two dedicated operator-invoked integration tests, one for `dxn-ad` and one for
`fas-local`. Each receives runtime credentials only through descriptors, uses
the public SMB client API, and produces acceptance artifacts. The shared
evidence helpers have no storage-management authority.
_Avoid_: production binary, ONTAP provisioning runner

**Profile invocation**:
One execution of the dedicated integration test for exactly one named profile.
The test name fixes the identity kind; endpoint, share, username, and password
are explicit descriptor inputs with no defaults. It writes one required
secret-free evidence artifact.
_Avoid_: generic test environment, inferred identity kind

**Owned-path conflict**:
A `create_new` collision for the exact run-owned temporary path. It blocks the
run without overwrite, retry-by-renaming, or deletion authority over the
existing object.
_Avoid_: retryable test failure, stale temporary file

**Credential-rejection probe**:
One explicitly authorized SessionSetup attempt using a separately supplied,
known-wrong password for one profile. It passes only when authentication is
rejected before any Session, Share, Guest, or Anonymous success; a missing
account-lockout authorization blocks the probe before network I/O.
_Avoid_: failed login smoke test, authentication timeout

**CIFS acceptance evidence**:
A versioned, secret-free JSON record for exactly one profile invocation. It
contains profile, commit, Run ID, stable phase outcomes, classifications, and
cleanup state; it contains neither connection details nor raw diagnostics. A
separate verifier accepts the combined result only for one passing `dxn-ad`
record and one passing `fas-local` record from the same commit.
_Avoid_: architecture-wave evidence, raw test log

**Controlled acceptance wrapper**:
A repository-owned test invocation contract that validates and forwards
explicit descriptor numbers to the two profile tests and their evidence
verifier. The external controlled runner, not ordinary CI or the test code,
obtains secrets and retains secret-free artifacts.
_Avoid_: secret-aware CI workflow, credential bootstrap script

## Data path

The path file payload bytes take between a caller-owned buffer and the network
transport. Protocol metadata, authentication tokens, signing, encryption, and
compression are distinguished from file payload bytes when evaluating copies.

## Copy budget

The measurable upper bound on payload copies, transform buffers, and metadata
allocations for a named operation and payload size. “Zero-copy” is reserved for
operations whose payload-copy budget is zero; it does not describe metadata.

## Payload copy

A full or partial duplication of file-content bytes between user-space memory
regions. Reference-count changes, ranges, and scatter/gather views are not
payload copies.
_Avoid_: Buffer move, allocation

## Transform buffer

A destination buffer necessarily containing the result of encryption,
decryption, compression, or decompression. It is budgeted separately from
payload copies because transformed bytes cannot alias their original form.
_Avoid_: Zero-copy buffer

## Transport frame

One complete immutable byte sequence received from, or ready for, a transport
adapter. A transformed frame replaces its source representation rather than
coexisting with it as another authoritative payload.
_Avoid_: Packet, raw message

## Wire message

A sealed SMB message represented by independently owned metadata and immutable
shared payload segments. It is ready for protection and transport but is not a
domain object.
_Avoid_: I/O vector, outgoing message

## Wire view

A validated range into one immutable transport frame. A wire view carries no
independent payload ownership and cannot outlive its frame owner.
_Avoid_: Borrowed response, payload buffer

## Validation target

The real SMB server and share against which interoperability and performance
acceptance are demonstrated. Validation credentials are runtime secrets and
are not part of the project domain or its stored artifacts.

## Validation run

One isolated, uniquely identified execution against a validation target,
including preflight, provisioning, tests, evidence, and cleanup. It is the
smallest unit that may own or retain validation resources.
_Avoid_: Test session, test environment

## Resource inventory

The exact set of isolated server objects created and ownership-verified by one
validation run. Cleanup authority never extends beyond this set.
_Avoid_: Resource prefix, cleanup list

## Functional acceptance path

The end-to-end sequence covering negotiation, authentication, share connection,
directory enumeration, file creation, chunked write, verified read, metadata
query, close, and cleanup.

## Connection

A negotiated SMB transport relationship with one server endpoint. It owns the
wire-level request sequence, credit window, and the sessions established over
that transport relationship.

## Session

An authenticated SMB security context established on a connection. A session
may use one primary channel and additional channels, and supplies the signing
or encryption context for its requests.

## Share

A session's active connection to one SMB share, including its immutable
capabilities and generation-aware authority to open resources. Tree and TreeId
are wire-protocol terms, not public handle names.
_Avoid_: Tree, connected tree

## Resource

An open file, directory, pipe, or print object within a share, identified by a
server-issued file identifier until it is closed or invalidated.

## Implementation wave

One dependency-ordered, independently verified architecture change that leaves
the main branch at an accepted checkpoint and can be reverted as a unit.
_Avoid_: Phase, mixed refactor

## Accepted checkpoint

A main-branch state whose currently activated gates pass and from which the
next implementation wave may start.
_Avoid_: Green enough, intermediate main

## Activation gate

An acceptance requirement that becomes permanently mandatory when its owning
implementation wave is merged. Before that wave it is reported explicitly as
not yet activated, never as passed or skipped.
_Avoid_: Optional test, deferred failure

## Request lifecycle

The period from reserving SMB credits and assigning a message identifier until
the request receives a terminal response or deterministically ends through
cancellation, timeout, or connection shutdown.

## Wire obligation

Protocol bookkeeping that can outlive a request's caller-visible terminal
result, including outstanding credits, a tombstone, or completion of a partially
sent frame. Settling it must never publish a second caller result.
_Avoid_: Pending request, background cleanup

## Generation

A monotonically changing identity for one established instance of a connection
or a dependent SMB object. A handle from an older generation never refers to a
new object merely because the server reuses the same numeric identifier.

## Reconnection

The bounded process of creating a new connection generation and reestablishing
its sessions and shares after an unplanned transport loss. Only resources with
protocol-supported durable or persistent recovery can become active again.

## Revoked

A terminal handle state caused by a parent failure, server action, or failed
recovery. A revoked handle cannot accept new operations or become active again.

## Outcome unknown

The result of an operation that may have reached the server but whose terminal
response was not observed. It does not assert that the operation succeeded or
failed and must not be silently converted into either claim.
