# SMB 2/3 message signing: specification and smb-rs validation

Date: 2026-09-02 (Asia/Shanghai)
Scope: SMB 2.0.2 through SMB 3.1.1 message signing, negotiation policy,
key derivation, preauthentication integrity, and packet-capture validation.

## Executive result

smb-rs has the essential signing machinery and its real-environment evidence
shows successful signed SMB 3.1.1 file I/O. The implementation correctly
computes and verifies 16-byte signatures, derives SMB 3.x signing keys, signs
ordinary non-guest traffic, treats encryption as an alternative integrity
envelope, and rejects an unsigned final non-guest `SESSION_SETUP` response.

The audit found three concrete protocol-conformance defects, all of which were
closed in the same worktree before this report was finalized:

1. `SESSION_SETUP.SecurityMode` did not propagate the public
   `signing_required=true` policy into `SIGNING_REQUIRED`; it now does.
2. The SMB 3.1.1 offer used HMAC-SHA256, AES-CMAC, AES-GMAC even though the
   field is a preference list; it now uses the project's intended
   AES-GMAC, AES-CMAC, HMAC-SHA256 order.
3. SMB 3.1.1 response validation accepted a missing preauthentication context
   and did not enforce the selected-algorithm cardinalities; it now rejects
   the invalid forms.

Test coverage has positive known evidence for GMAC, tamper rejection under all
three signing algorithms, and the SMB 3.1.1 KDF, but lacks a complete
known-answer matrix for SMB 2.x HMAC, SMB 3.0.x CMAC, SMB 3.1.1 CMAC/GMAC,
compound padding, and raw-wire preauthentication transcripts.

The remaining item is an assurance gap, not a known interoperability failure.
`signing_required=false` is **not** a defect and must not be
reinterpreted as “disable signing.” It means that this client does not require
signing; the peer or established session can still require it, and the client
may still sign optional traffic.

## 1. SecurityMode: support and requirement are different facts

### NEGOTIATE Request

The client request has two independent bits:

- `SMB2_NEGOTIATE_SIGNING_ENABLED` (`0x0001`) says signing is enabled/supported
  by the client. The server must ignore this bit.
- `SMB2_NEGOTIATE_SIGNING_REQUIRED` (`0x0002`) says the client requires
  security signatures.

These meanings are normative in [MS-SMB2, SMB2 NEGOTIATE
Request](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/e14db7ff-763a-4263-8b10-0c3944f52fc5).
When the client's global `RequireMessageSigning` is false, the client still
sends `SIGNING_ENABLED`; when true it sends `SIGNING_REQUIRED`. See
[MS-SMB2, initiating multichannel-capable SMB2
negotiation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/77f696b8-9aa0-4ed1-abb2-c097c0ccb05a).

smb-rs maps `ConnectionConfig.signing_required` to the NEGOTIATE required bit
and continues to advertise support in `crates/smb/src/connection.rs:533-535`.
The public facade defaults this setting to false and explicitly documents that
false does not disable signing (`crates/smb/src/facade/mod.rs:18-24`). This is
the correct public semantic.

### NEGOTIATE Response and the effective requirement

On receipt of the response, a client must set the connection's signing
requirement when the server returns `SIGNING_REQUIRED`. A later session's
effective requirement is therefore the logical union of the local client
policy and the server/connection requirement, subject to the guest/null and
encryption rules below. The server cannot use an optional response to cancel a
client's own required policy. See [MS-SMB2, Receiving an SMB2 NEGOTIATE
Response](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/3b29f3af-86f9-4962-8cf3-43471cb59363)
and [MS-SMB2, Handling a New
Authentication](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/7fd079ca-17e6-4f02-8449-46b606ea289c).

smb-rs does not currently retain an explicit `Connection.RequireSigning`
field, but its ready-state behavior is conservative: every non-guest,
non-null, unencrypted session request is signed. Thus a server-required
session is not accidentally emitted unsigned. The missing state distinction
does, however, make it harder to prove exact optional-versus-required policy.

### SESSION_SETUP Request

The one-byte `SESSION_SETUP.SecurityMode` repeats the same meanings:
`SIGNING_ENABLED=0x01`, `SIGNING_REQUIRED=0x02`; the server ignores the enabled
bit. See [MS-SMB2, SMB2 SESSION_SETUP
Request](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5a3c2c28-d6b0-48ed-b917-a86b2ca4575f).
The client processing rule requires `SIGNING_REQUIRED` when its
`RequireMessageSigning` policy is true and `SIGNING_ENABLED` otherwise; see
[Handling a New
Authentication](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/7fd079ca-17e6-4f02-8449-46b606ea289c).

The initial audit found that `SESSION_SETUP` always sent only
`SIGNING_ENABLED`. The finalized implementation at
`crates/smb/src/session/setup.rs:249-257` now also sets `SIGNING_REQUIRED` from
`ConnectionConfig.signing_required`. Transcript tests cover both false and
true policy values.

## 2. Algorithms and signing keys by dialect

| Dialect | Message signature algorithm | Key material / derivation |
| --- | --- | --- |
| SMB 2.0.2 / 2.1 | HMAC-SHA256, first 16 output bytes | The 16-byte session key is used directly as the signing key. |
| SMB 3.0 / 3.0.2 | AES-128-CMAC | SP800-108 counter-mode KDF, HMAC-SHA256 PRF; key = session key, label `SMB2AESCMAC\0`, context `SmbSign\0`, 128-bit output. |
| SMB 3.1.1 | Negotiated HMAC-SHA256 (`0x0000`), AES-CMAC (`0x0001`), or AES-GMAC (`0x0002`); AES-CMAC is the fallback when no algorithm ID was negotiated | Same KDF construction; label `SMBSigningKey\0`, context = the session's 64-byte preauthentication integrity hash, 128-bit signing key. |

The signing algorithm IDs and the rule that the client list is in descending
preference order are defined by [MS-SMB2,
SMB2_SIGNING_CAPABILITIES request](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/cb9b5d66-b6be-4d18-aa66-8784a871cc10).
The protocol defines the IDs and placement of the client's most-preferred
algorithm, but it does not impose a universal security ranking among the three;
the concrete GMAC/CMAC/HMAC order below is this project's policy.
The response must select exactly one algorithm; see [the response
structure](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/91897c76-e3a2-4601-b3ce-40f343fa4a6d)
and [client response
processing](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/3b29f3af-86f9-4962-8cf3-43471cb59363).
The KDF is SP800-108 counter mode with a 32-bit counter and HMAC-SHA256 PRF;
see [MS-SMB2, Generating Cryptographic
Keys](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/da4e579e-02ce-4e27-bbce-3fc816a3ff92)
and the dialect-specific inputs in [Handling a New
Authentication](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/7fd079ca-17e6-4f02-8449-46b606ea289c).

smb-rs maps these rules as follows:

- HMAC-SHA256, AES-CMAC, and AES-GMAC implementations live in
  `crates/smb/src/crypto/signing.rs`.
- SMB 2.x uses HMAC-SHA256 and the session key directly; SMB 3.x uses the KDF
  and the dialect label/context in `crates/smb/src/session/state.rs:64-141`.
- `crates/smb/src/dialects.rs:111-138` selects the correct dialect default and
  `crates/smb/src/dialects.rs:182,251` supplies the 3.1.1 and 3.0.x labels.
- The key output is deliberately 16 bytes in
  `crates/smb/src/crypto/kbkdf.rs`.

The algorithm offer uses `crypto::SIGNING_ALGOS` verbatim
(`crates/smb/src/connection.rs:385-388,569-570`). The initial audit caught the
reverse HMAC/CMAC/GMAC order. The finalized constant and its regression test in
`crates/smb/src/crypto/signing.rs` now lock the project policy to GMAC, CMAC,
HMAC. The tested storage targets independently selected AES-CMAC, so this
ordering fix does not rewrite their observed negotiation result.

## 3. How a signature is calculated and verified

For an outgoing message, the sender sets `SMB2_FLAGS_SIGNED`, clears the
16-byte SMB2 Header `Signature`, signs the complete SMB2 message, and stores
the resulting 16 bytes. SMB 2.x uses the first 16 bytes of HMAC-SHA256. SMB
3.x uses AES-CMAC unless SMB 3.1.1 selected a different algorithm. Compound
messages are signed per command; the bytes through the next command offset,
including compound padding, participate in that member's signature. These
rules are in [MS-SMB2, Signing An Outgoing
Message](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/a3e9ea1e-53c8-4cff-94bd-d98fb20417c0).

AES-GMAC uses a 12-byte nonce. Its first eight bytes are `MessageId`; the final
four bytes encode the sender direction and `CANCEL` condition with the other
bits zero. The same normative signing section defines this construction.
smb-rs implements it in `crates/smb/src/crypto/signing.rs:239-246`.

Verification saves the received signature, zeroes the field, recomputes over
the identical byte range, and compares the 16-byte result. See [MS-SMB2,
Verifying an Incoming
Message](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5b570c0b-0854-4324-8fb5-d410692dde3e).
smb-rs signs immutable wire segments without concatenation and verifies the
received raw bytes in `crates/smb/src/session/signer.rs:27-90`. Its compound
path signs/verifies each padded member slice in
`crates/smb/src/runtime/wire.rs:420-500,790-845`.

## 4. Which messages must be signed

The protocol policy is:

- SMB 2.x requests on a signing-required session must be signed.
- SMB 3.x requests on a signing-required session must be signed when neither
  the session nor tree requires encryption.
- When signing is not required, the client may still sign.
- A signed, unencrypted request or response must have its signature verified;
  an invalid signature is rejected.
- An unsigned request on a server session that requires signing is rejected
  with `STATUS_ACCESS_DENIED`.
- `NEGOTIATE` itself must not carry `SMB2_FLAGS_SIGNED`.

See [MS-SMB2, client Signing the
Message](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/973630a8-8aa1-4398-89a8-13cf830f194d),
[server Verifying the
Signature](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/85df1680-2ee7-4d25-a916-a982371ddc75),
and [server Signing the
Message](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/d594481c-f6d5-4de5-8842-9099063d41e7).

Important exceptions and stage rules are:

- Guest and null/anonymous sessions clear the established session signing
  requirement. There is a normative edge-case tension for SMB 3.1.1 setup:
  the client rule says a successful final `SESSION_SETUP` response without
  `SMB2_FLAGS_SIGNED` is an error, while the server rule mandates signing that
  response only when the result is not guest/anonymous. Therefore insecure
  guest acceptance must remain an explicit compatibility policy and must not
  weaken the non-guest path.
- A new session's final authentication request is not the same as that final
  response: the server only establishes the session signing key after it has
  accepted the authentication. smb-rs therefore sends a new-session final
  continuation unsigned, then derives the signer before receiving the signed
  success response. A multichannel binding uses an established session and is
  signed.
- SMB 3.x encryption supplies integrity for the transform envelope. If a
  message was successfully decrypted, ordinary SMB2 Header signature
  verification is skipped; an encrypted session/tree is not additionally
  signed at the plain-message layer.
- On the client response path, a successfully decrypted response, an
  unsolicited response whose `MessageId` is all ones, and an interim
  `STATUS_PENDING` response skip the ordinary required-signature check.

The authentication rules are in [MS-SMB2, Handling a New
Authentication](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/7fd079ca-17e6-4f02-8449-46b606ea289c),
and the client response exceptions are in [MS-SMB2, Verifying the
Signature](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/36172e53-ac81-48fb-b2e3-caa3761b9157).

smb-rs's normal channel path selects encryption before signing and otherwise
signs non-guest sessions (`crates/smb/src/session/channel.rs:109-128`). It
rejects an unprotected normal response at the session boundary and verifies
any signed raw response in the wire pipeline. The final non-guest setup
response guard is at `crates/smb/src/session/setup.rs:199-207`; guest/null
acceptance is separately controlled by `allow_unsigned_guest_access`.

## 5. SMB 3.1.1 preauthentication integrity

SMB 3.1.1 negotiates preauthentication integrity through a negotiate context.
The currently defined hash is SHA-512 (`0x0001`), with an optional salt. See
[MS-SMB2, SMB2_PREAUTH_INTEGRITY_CAPABILITIES](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5a07bd66-4734-4af8-abcf-5a44ff7ee0e5).

The rolling transcript starts at 64 zero bytes. Each step is
`SHA512(previous_hash || exact_wire_message)`. It includes the raw NEGOTIATE
request and response, then each `SESSION_SETUP` request and each intermediate
`STATUS_MORE_PROCESSING_REQUIRED` response. For the successful final round,
the final request is included before deriving `SMBSigningKey`; the signed
success response is not added to the KDF context. This ordering avoids a
circular dependency between the signing key and the response signature. The
client algorithm is specified by [Receiving an SMB2 NEGOTIATE
Response](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/3b29f3af-86f9-4962-8cf3-43471cb59363)
and [Handling a New
Authentication](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/7fd079ca-17e6-4f02-8449-46b606ea289c).

smb-rs implements the rolling SHA-512 state in
`crates/smb/src/connection/preauth_hash.rs`, seeds it with exact NEGOTIATE
request/response bytes in `crates/smb/src/connection.rs:442-448`, and advances
it for setup traffic in `crates/smb/src/runtime/wire.rs:211-227,528-545,809-813`.
The derived channel signer is installed before the final response is admitted.

The initial response validator checked only the first preauthentication
algorithm when the context happened to exist. The finalized validator at
`crates/smb/src/dialects.rs:188-247` requires exactly one preauthentication
context and exactly one supported hash, rejects duplicate signing contexts,
and—when a signing context is present—requires exactly one supported selected
algorithm. Missing signing capabilities retain the specification's AES-CMAC
fallback. Negative tests cover missing and duplicate preauthentication
contexts.

## 6. Packet-capture acceptance procedure

Use an isolated test path and capture the complete TCP connection from SYN
through file close. Do not publish authentication blobs, addresses, account
names, session keys, or decrypted payloads. Wireshark's authoritative SMB2
display-field reference includes `smb2.sec_mode.sign_enabled`,
`smb2.sec_mode.sign_required`, `smb2.negotiate_context.signing_id`,
`smb2.flags.signature`, `smb2.signature`, `smb2.good_signature`,
`smb2.bad_signature`, the session guest/null/encrypt flags, and encrypted
transform fields; see the [Wireshark SMB2 display filter
reference](https://www.wireshark.org/docs/dfref/s/smb2.html).

Example inspection commands, with `capture.pcapng` kept outside retained test
artifacts:

```bash
tshark -r capture.pcapng -Y 'smb2.cmd == 0' \
  -T fields -e frame.number -e ip.src -e smb2.dialect \
  -e smb2.sec_mode.sign_enabled -e smb2.sec_mode.sign_required \
  -e smb2.negotiate_context.signing_id

tshark -r capture.pcapng -Y 'smb2.cmd == 1' \
  -T fields -e frame.number -e smb2.flags.signature -e smb2.signature \
  -e smb2.ses_flags.guest -e smb2.ses_flags.null -e smb2.ses_flags.encrypt

tshark -r capture.pcapng \
  -Y 'smb2 && smb2.sesid != 0 && smb2.cmd != 0' \
  -T fields -e frame.number -e smb2.cmd -e smb2.sesid \
  -e smb2.flags.signature -e smb2.signature \
  -e smb2.good_signature -e smb2.bad_signature
```

Acceptance requires all of the following:

1. Default policy: NEGOTIATE and SESSION_SETUP advertise enabled but not
   client-required signing; normal authenticated application messages may
   nevertheless be signed.
2. Required policy: both NEGOTIATE and SESSION_SETUP carry the client-required
   bit.
3. The SMB 3.1.1 response selects exactly one algorithm that the request
   offered; every signed application frame has the signed flag and a non-zero
   16-byte signature.
4. Wireshark reports no bad signatures. Where packet decryption keys are
   securely available, it reports good signatures for checked frames.
5. A controlled payload-bit tamper is rejected, and a deliberately unsigned
   business request on a required session fails without exposing business
   response data.
6. For an encrypted session/tree, the capture shows the SMB3 transform
   envelope; absence of a second plain SMB2 Header signature is expected.
7. Guest/null behavior is tested only with explicit authorization and is not
   generalized to normal users.

The SMB header's non-zero signature alone is evidence that a sender attempted
signing, not proof that it used the correct key or byte range. A positive
verifier result or an independent known-answer computation is needed for
cryptographic correctness.

## 7. Evidence available in this repository

The following targeted commands were run against the audited worktree:

```text
cargo test -p smb --all-features --lib session::signer::tests
  4 passed: GMAC known result/segmented equivalence; HMAC, CMAC, and GMAC
  valid-signature acceptance plus tamper rejection

cargo test -p smb --all-features --lib session::state::tests::test_key_deriver
  1 passed: SMB 3.1.1 signing-key derivation vector

cargo test -p smb --all-features --test conformance_anonymous
  2 passed

cargo test -p smb --all-features --test conformance_windows_dc_ntlm
  3 passed

cargo test -p smb --all-features --test conformance_smb302
  1 passed
```

The finalized full library suite passed 158/158 tests, including the four new
SMB 3.1.1 negotiate-validation tests. During the audit, a red regression test
first reproduced the preference-order defect: the implementation returned
HMAC, CMAC, GMAC while the expected project policy was GMAC, CMAC, HMAC. After
the implementation correction, the full suite passed.

The repository's separate [CIFS API versus kernel mount validation
report](../validation/cifs-api-vs-kernel-mount-performance-2026-09-02.md)
records successful signed SMB 3.1.1 write/read/content-verification/cleanup on
two independent storage implementations, plus packet evidence that normal
traffic carried the signed flag and a non-zero signature. That is valuable
interoperability evidence. It does not replace known-answer verification of
every dialect/algorithm or prove an unsigned performance mode.

The feature boundary was also exercised directly. Builds containing only
HMAC, only CMAC, or only GMAC each passed the applicable signer tests. A build
with no signing algorithm now compiles and passes clippy without warnings; in
that build, `signing_required=true` is rejected by configuration validation
instead of being silently downgraded.

Finally, the release-mode public API was run with `signing_required=true`
against both controlled storage profiles. Each target completed one warm-up
and five measured samples; every sample wrote and read back 16 MiB, verified
every returned byte, and deleted the test object. Both profiles passed. The
observed one-connection median throughput was 27.88 MiB/s write and 27.30
MiB/s read on DXN, and 22.59 MiB/s write and 23.20 MiB/s read on FAS. These
numbers are interoperability evidence from this run, not durable performance
baselines.

## 8. Required closure tests

Before declaring signing fully conformant, add or retain these gates:

- NEGOTIATE and SESSION_SETUP SecurityMode transcript tests for both public
  policy values.
- SMB 2.1 HMAC-SHA256, SMB 3.0.2 AES-CMAC, and SMB 3.1.1 AES-CMAC/AES-GMAC
  known-answer tests using independent vectors.
- An AES-GMAC nonce matrix covering client/server direction and `CANCEL`.
- A compound-message vector proving that each member includes its padding.
- A raw-byte SMB 3.1.1 preauthentication transcript test covering at least one
  intermediate authentication round and the successful final request.
- Additional negative negotiate tests for unsupported/unoffered signing
  algorithms and no preauth hash overlap. Missing/duplicate preauth contexts
  and invalid hash/signing cardinalities are already covered.
- A correctly signed final non-guest `SESSION_SETUP` response acceptance test,
  plus unsigned and bad-signature rejection tests.
- Required-session unsigned request rejection, optional-session signed request
  acceptance, guest/null behavior, encrypted-envelope behavior, and
  multichannel channel-key tests.
- Retain the feature-matrix tests proving that required signing fails
  configuration when no signing implementation is compiled, and that every
  advertised algorithm is actually constructible.

Only after the remaining gates and the packet-capture checklist pass should
“all SMB 2/3 signing modes work” be treated as established. Current evidence
supports the narrower statement: signed SMB 3.1.1 AES-CMAC interoperability
works on the tested real servers, the concrete negotiation-policy defects
found in this audit are fixed, and complete cross-dialect cryptographic
assurance still needs the listed vectors.
