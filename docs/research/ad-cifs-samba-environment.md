# AD-authenticated CIFS access: current design and environment

## Scope and sources

This is a read-only planning note for making a normal AD user able to list,
read, and write a controlled file in a CIFS share through `smb-rs`. It does
not retain credentials, endpoints, or command output.

The current target facts were supplied for this effort: the share is exported
by **Samba**, its backing storage is Ceph-backed but explicitly **not CephFS**,
and an AD domain controller exists. Those facts are not independently verified
by the repository. Consequently Samba—not the Ceph backing store—owns SMB
SessionSetup, AD integration, Kerberos service-principal handling, and SMB
signing behaviour. The Ceph backend still matters to the file-operation part of
the test (POSIX/ACL semantics, durability, quotas, and snapshots), but it does
not establish an AD identity or Kerberos service ticket.

All implementation claims below cite primary local sources. Historical ONTAP
documents are cited only to distinguish the existing validation design from
this Samba target; they are not Samba configuration guidance.

## Observed Samba target state

A read-only interactive inspection of the current target confirms that its
Samba 4.13 member-server join and winbind DC connectivity are healthy. The
effective configuration uses `security = ADS`, the expected AD realm, `ntlm
auth = ntlmv2-only`, default server signing, and SMB 2.02 through SMB 3
protocol limits. Samba uses the system keytab and does not use the default
domain for unqualified account names.

The inspected share is backed by the Ceph client but is exported by Samba. Its
current allow and write lists name only the administrator account, so it cannot
yet validate least-privilege AD-user access. The gateway's hostname is not
currently resolvable as a domain FQDN from the runner. The gateway was about
eight hours ahead of the DC because `chronyd` had no upstream source and used
its local stratum. It was corrected once from the DC's LDAP time, reducing the
Samba-reported offset to seconds, but UDP NTP to the DC was unavailable and
the clock remains unsynchronized. A reachable persistent NTP source is still
required before Kerberos can be accepted.

No configuration, directory object, share ACL, file, or service state was
changed during this inspection, apart from setting the gateway clock and RTC
to the domain controller's current time at the user's request. The observed
values are environment evidence, not a substitute for the code/documentation
sources cited below.

## Observed end-to-end NTLM failure

After time correction, the existing real-server test still reaches SMB
negotiation and the initial NTLM exchange but loses the connection on the next
SessionSetup request. The Samba log records `NT_STATUS_INVALID_HANDLE` before
its NTLM pre-authentication handler receives a username or password, followed
by an attempt to sign without an SMB2 signing key and `NT_STATUS_ACCESS_DENIED`.
The same gateway successfully records normal NTLMv2 sessions from other
clients. This isolates the immediate failure to the client's multi-round
SessionSetup session-ID/signing-state handling, rather than AD credentials,
share ACLs, or the Ceph backend.

## Current public configuration path

- The supported public path is `Client::connect_share(ShareTarget,
  Credentials)`, which authenticates first and then connects the named share.
  [facade implementation](../../crates/smb/src/facade/mod.rs#L55-L90)
- The public credential type has `Ntlm { username, password }`, `Anonymous`,
  and a refresh `Provider`; it has no public `Kerberos` credential/policy
  variant. Anonymous is explicitly rejected by the domain adapter. Secrets are
  stored in `Zeroizing<String>`. [credential model and adapter](../../crates/smb/src/domain/mod.rs#L39-L79)
  [constructors](../../crates/smb/src/domain/mod.rs#L181-L191)
- The domain facade constructs `RuntimeClient`, which unconditionally creates
  the legacy client with `LegacyClientConfig::default()`. Therefore consumers
  of the current public API cannot choose NTLM-only, Kerberos-only, or an
  ordered fallback policy; nor can they supply a connection configuration.
  [runtime boundary](../../crates/smb/src/runtime/port.rs#L69-L112)
  [legacy client configuration](../../crates/smb/src/client/config.rs#L1-L60)
- A lower, test-only API re-exports `ConnectionConfig`; its
  `AuthMethodsConfig` defaults to NTLM enabled and enables Kerberos only when
  the crate is built with feature `kerberos`. It is not part of the ordinary
  public facade. [auth-method configuration](../../crates/smb/src/connection/config.rs#L114-L195)
  [test-only export boundary](../../crates/smb/src/lib.rs#L38-L63)

**Decision implication:** the first implementation decision is not merely
which server mechanism to prefer. The public domain API needs an explicit,
observable authentication-policy seam if the product must guarantee Kerberos
first, deliberately permit NTLMv2 fallback, or report which mechanism actually
authenticated the session.

## NTLM and Kerberos support/limitations

- The lower authenticator creates SSPI `Negotiate` with the enabled package
  list. With the feature and configuration enabled that list includes Kerberos
  and NTLM; otherwise it disables Kerberos. [SSPI package selection](../../crates/smb/src/session/authenticator.rs#L88-L118)
  [selection logic](../../crates/smb/src/session/authenticator.rs#L158-L166)
  [Cargo feature](../../crates/smb/Cargo.toml#L138-L153)
- Its Kerberos target is constructed literally as `cifs/<server name>`. The
  connection preserves the caller's `server` string as `server_name`, even
  though it separately resolves that string to an IP address for transport.
  An IP-only share target would therefore request `cifs/<IP>`, rather than a
  hostname-based CIFS SPN. [target construction](../../crates/smb/src/session/authenticator.rs#L120-L122)
  [connection construction](../../crates/smb/src/client/smb_client.rs#L27-L41)
  [server-name preservation](../../crates/smb/src/connection.rs#L142-L158)
- Kerberos execution is compiled behind `kerberos` and uses an async SSPI
  network client for TCP, UDP, or HTTP(S) KDC requests. [GSS execution
  contract](../../crates/smb/src/session/gss.rs#L1-L50)
  [network client](../../crates/smb/src/session/sspi_network_client.rs#L71-L179)
- There is a known first-attempt SessionSetup limitation in the production
  state machine: it records that a session ID is needed before the session
  state required for channel construction and signature validation. This is
  mechanism-independent and can affect a real signed NTLM or Kerberos setup.
  [known limitation](../../crates/smb/src/session/setup.rs#L189-L211)
- The “Windows DC NTLM” regression is a scripted transport plus mock GSS test;
  it checks only that the client signs its final SessionSetup request. It is not
  an end-to-end AD, NTLM, or Kerberos test. [test scope](../../crates/smb/tests/conformance_windows_dc_ntlm.rs#L1-L27)
  [mock mechanism](../../crates/smb/tests/conformance_windows_dc_ntlm.rs#L45-L80)

## Existing real-server validation and safety constraints

- The checked-in real-appliance acceptance matrix is specifically an isolated
  **ONTAP** design, with run-owned volumes/shares, a restricted SMB test
  identity, and exact inventory-based cleanup. It must not be treated as the
  topology of the Samba/Ceph target. [scope and topology](../../docs/validation/fas2750-acceptance.md#L5-L55)
- That historical matrix gates NTLMv2, signing, share connection, and full
  file/directory lifecycle including write/read byte verification; it requires
  secrets to arrive through a file descriptor, hidden input, or CI provider,
  never command lines/logs/repository files. [authentication and I/O gates](../../docs/validation/fas2750-acceptance.md#L97-L124)
  [secret and privilege rules](../../docs/validation/fas2750-acceptance.md#L212-L242)
- The existing ignored performance harness creates and overwrites generated
  files on a caller-provisioned writable share. It is unsuitable for the target
  share until there is an isolated AD-user-writable test directory and a
  target-specific cleanup contract. [harness scope](../../crates/smb/tests/ontap_performance.rs#L1-L14)
  [write path](../../crates/smb/tests/ontap_performance.rs#L188-L209)
- Repository roadmaps explicitly leave Kerberos as later work; there is no
  committed real Kerberos acceptance gate. [milestone boundary](../../docs/evidence/W6-accepted-checkpoint.md#L70-L75)

## Facts required before Kerberos can be validated

The following are blocking facts, not assumptions to fill in from the current
IP address or credentials:

1. The Samba gateway's canonical DNS FQDN and the exact `cifs/<FQDN>` SPN(s)
   registered in AD, including whether aliases/CNAMEs are supported.
2. DNS resolution from the test runner to that FQDN, and a route from the
   runner to the AD KDC (including the KDC transport that SSPI will use).
3. Time synchronization status for runner, AD/KDC, and Samba gateway.
4. Samba version and effective AD/member-server configuration: domain join
   health, selected identity-mapping/winbind settings, Kerberos and NTLM
   policy, SMB dialect min/max, and signing requirement. Do not infer any of
   these from the Ceph backend.
5. A dedicated non-administrator AD test user and an isolated, writable share
   directory. The share ACL and the backing filesystem/identity-mapping ACL
   must both allow list/read/write for that user. The permitted test filename
   prefix and cleanup owner must also be defined.
6. The intended client build feature set (`kerberos` included) and the desired
   product policy: Kerberos required, or NTLMv2 permitted only as an explicit
   fallback. Current public APIs cannot enforce or report that distinction.

## Recommended validation boundary once the facts exist

Use the Samba FQDN (not the raw IP) and inject the dedicated user's secret by
file descriptor or an equivalent secret provider. First run a non-mutating
preflight that records DNS/KDC/time/Samba AD-join and effective signing facts
without exposing credentials. Then use one run-owned directory and one
uniquely named file to prove, in order: authenticate, TreeConnect, enumerate,
create/write, close/reopen/read-back byte equality, and ownership-checked
cleanup. Capture the negotiated dialect, signing result, selected SSPI
mechanism, and server-side Samba audit evidence without payloads or secrets.

This requires a target-specific Samba validation plan; no CephFS-specific
configuration is implied or recommended.
