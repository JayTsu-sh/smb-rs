# Negotiated signing policy validation

Implementation branch: `feat/negotiated-signing`, based on `d8291b3`.

The public API is `Client::with_signing_policy(SigningPolicy::WhenRequired)`.
`Required` remains the default. NEGOTIATE and SESSION_SETUP carry the policy;
the server signing requirement is retained in negotiated properties and combined
with client policy when the session becomes ready. Reconnect negotiates afresh.
Optional sessions omit ordinary request signing and accept unsigned responses
without running their signature calculation. Signed responses are still verified.
SMB 3.1.1 TREE_CONNECT requests/responses and setup/binding protection remain in
place. Encryption and its integrity verification are unchanged. Guest access
cannot override a server-required signature.

## FAS2750 live evidence

Shared resource: `ontap_lisaauto_cifs`, tested independently through
`10.128.61.200` and `10.128.61.201`. Both reported SecurityMode 1 (enabled, not
required). No appliance settings changed. Each test created a unique file,
wrote 4 MiB + 4 KiB, flushed, read it back with complete byte comparison, and
deleted/closed the file and client. All four policy/endpoint combinations passed.

| Policy | Client NEGOTIATE SecurityMode | READ/WRITE requests | READ/WRITE responses | TREE_CONNECT |
|---|---:|---|---|---|
| Required | 3 | signed | signed | signed |
| WhenRequired | 1 | unsigned | unsigned | signed |

Packet-header observations are in [signing-wire.json](2026-09-16-signing-wire.json).
Each combination observed five READ and five WRITE requests and their responses.
Raw packet captures were kept in restricted temporary files and removed. These
are functional debug-build probes, not a controlled performance benchmark.
Credentials were passed through the environment and are not part of the report.

The ignored test `signing_policy_live::negotiated_signing_roundtrip` reproduces
file validation with `SMB_SIGNING_TEST_POLICY=required|when-required`, plus the
existing `SMB_RUST_TESTS_SERVER`, `SMB_RUST_TESTS_SHARE`,
`SMB_RUST_TESTS_USER_NAME`, and `SMB_RUST_TESTS_PASSWORD` environment variables.
Run with `--features real-server-tests --test signing_policy_live -- --ignored`.

## Regression scope

Unit coverage checks the client/server policy matrix, capability advertisement,
server-required guest rejection, unsigned wire processing without an installed
signer, and verification/rejection of valid/tampered signed responses under an
optional session. SMB 3.0.2 conformance checks that WhenRequired still signs the
final authentication request and rejects an unsigned final response when the
server requires signing. Existing Windows DC and anonymous setup tests run too.
Live server-required mode was not tested by changing FAS settings; it is covered
by deterministic fixtures. No live transport-disconnect/multichannel fault was
injected in this change.

Protocol references:
- [Client signing](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/973630a8-8aa1-4398-89a8-13cf830f194d)
- [Server ordinary response signing](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/d594481c-f6d5-4de5-8842-9099063d41e7)
- [Client verification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/36172e53-ac81-48fb-b2e3-caa3761b9157)
- [SMB 3.1.1 tree connect](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/decadb64-9619-46e5-8892-c634213396d2)

Validation completed: 141 library tests with test-support; 10 selected conformance/domain tests; 3 doctests passed (4 existing ignored); all-target/all-feature Clippy with warnings denied; formatting and diff whitespace checks. Four FAS endpoint/policy probes passed with signed/unsigned packet assertions.
