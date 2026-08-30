# ONTAP 9.19.1 first-phase SMB acceptance gates

## Scope and method

This note assesses which optional SMB capabilities can be made reliable first-phase acceptance gates for `smb-rs` against a FAS2750 running ONTAP 9.19.1. The authorized change boundary is an isolated volume, Snapshot, and share under the existing domain-joined `lizy` SVM. No device changes were made for this research.

Sources are limited to NetApp's ONTAP documentation and Microsoft's normative SMB protocol documentation.

The accepted executable matrix and resource-safety protocol derived from this
research are specified in `docs/validation/fas2750-acceptance.md`.

## Recommendation

| Capability | First-phase hard gate? | Safe acceptance boundary |
|---|---:|---|
| SMB signing | **Yes, qualified** | Require the client to negotiate and use signing, then verify valid signatures and rejection of tampered signed traffic. Do not require changing the SVM-wide `is-signing-required` policy. |
| SMB encryption | **Yes** | Add `encrypt-data` only to the isolated test share; verify encrypted tree connect and encrypted file operations. |
| Previous Versions / Snapshots | **Yes** | Create a Snapshot on the isolated volume, expose it with `showsnapshot`/Snapshot access, and verify enumeration/read of an earlier version. |
| Continuously available share | **Partial only** | Gate negotiation of persistent handles on an isolated CA share. Do not gate real nondisruptive takeover/giveback in phase one. |
| Kerberos | **No, not from this authorization alone** | Promote only when the runner has correct DNS, time, KDC reachability, an AD principal/ticket, and the CIFS SPN path is verified. |
| SMB Multichannel | **No, not from this authorization alone** | Promote only after the SVM-wide option and suitable multi-NIC/multi-LIF topology are explicitly authorized and verified. |

The practical first-phase expansion is therefore **signing, share-scoped encryption, and Snapshot/Previous Versions**, plus a narrower **CA persistent-handle protocol check**. Kerberos, true CA failover, and Multichannel depend on infrastructure or changes outside an isolated share.

## Findings by capability

### SMB signing: hard gate, without changing SVM policy

ONTAP supports SMB signing when requested by a client, while the administrator may separately require signing for the whole SVM. For SMB 2.x and SMB 3.x, signing capability is always enabled; the policy controls whether it is required. NetApp documents `vserver cifs security modify ... -is-signing-required true` as an SVM security setting and notes that new connection behavior is affected.[NetApp: SMB signing overview](https://docs.netapp.com/us-en/ontap/smb-admin/signing-enhance-network-security-concept.html) [NetApp: signing policy behavior](https://docs.netapp.com/us-en/ontap/smb-admin/client-signing-policies-communication-concept.html) [NetApp: require incoming signing](https://docs.netapp.com/us-en/ontap/smb-admin/enable-disable-required-signing-incoming-traffic-task.html)

Consequently, an isolated share is not an isolation boundary for the server's “signing required” setting. Phase one can nevertheless make the client's signing implementation a hard gate by requesting/negotiating signing and validating signed exchanges. Temporarily requiring signing on `lizy` would affect new connections to every share on that SVM and should require separate operational approval.

Microsoft's SMB2 specification defines signing and verification in section 3.1.4.1, including setting `SMB2_FLAGS_SIGNED`, calculating the signature, and disconnecting when required signature validation fails. That gives the client-side gate a normative oracle.[Microsoft MS-SMB2: Signing an Outgoing Message](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/48a3d8e2-dca2-4adf-8200-efaeb28b2604)

### SMB encryption: hard gate at isolated-share scope

ONTAP supports encryption either for the entire SVM or for selected shares. If the SVM-level encryption requirement is false and the share has `encrypt-data`, encryption begins at tree connect for that share. This is exactly the authorized isolation boundary; clients without encryption support cannot access the share.[NetApp: SMB encryption configuration model](https://docs.netapp.com/us-en/ontap/smb-admin/configure-required-encryption-concept.html) [NetApp: share properties](https://docs.netapp.com/us-en/ontap/smb-admin/add-remove-share-properties-existing-share-task.html)

Encryption adds CPU cost on both client and server, and NetApp recommends measuring it in the actual environment. It should therefore be a correctness/interoperability hard gate with a separately reported encrypted-throughput result, not use the unencrypted zero-copy budget as its pass criterion.[NetApp: SMB encryption performance impact](https://docs.netapp.com/us-en/ontap/smb-admin/performance-impact-encryption-concept.html)

The gate should verify dialect/cipher negotiation, encrypted tree traffic, round-trip data integrity, and failure on malformed authentication tags. SMB encryption necessarily transforms data and is not a literal zero-copy path.

### Previous Versions and Snapshots: hard gate on the isolated volume

ONTAP requires an enabled Snapshot policy associated with the volume, client access to Snapshot data, and at least one Snapshot. NetApp also documents enabling Snapshot directory access and the `showsnapshot` share property.[NetApp: Previous Versions requirements](https://docs.netapp.com/us-en/ontap/smb-admin/requirements-microsoft-previous-versions-concept.html) [NetApp: create the Snapshot configuration](https://docs.netapp.com/us-en/ontap/smb-admin/create-snapshot-config-previous-versions-access-task.html) [NetApp: share properties](https://docs.netapp.com/us-en/ontap/smb-admin/add-remove-share-properties-existing-share-task.html)

All prerequisites can be confined to the dedicated test volume/share. A deterministic test can write version A, create a named Snapshot, overwrite with version B, enumerate the prior version through SMB, read and verify version A, and then remove the Snapshot and test resources. No scheduled policy is necessary if the test creates an explicit Snapshot and configures Snapshot visibility.

### Continuously available shares: persistent-handle gate only

The `continuously-available` share property permits supporting clients to open files persistently and protects those opens across events such as failover and giveback. ONTAP documents additional requirements for nondisruptive application-server use: an NTFS-style volume created as NTFS, `oplocks`, compatible offline-file/symlink settings, and exclusion of incompatible share properties such as home directory, attribute cache, and BranchCache.[NetApp: share properties](https://docs.netapp.com/us-en/ontap/smb-admin/add-remove-share-properties-existing-share-task.html) [NetApp: verify CA share configuration](https://docs.netapp.com/us-en/ontap/smb-hyper-v-sql/verify-continuously-available-share-config-task.html) [NetApp: CA requirements and considerations](https://docs.netapp.com/us-en/ontap/pdfs/sidebar/Configuration_requirements_and_considerations.pdf)

Creating a correctly configured isolated CA share is safe enough to test persistent-handle create/reconnect semantics. A real transparent-failover acceptance test, however, requires takeover/giveback or another disruptive cluster event and validation of Witness/reconnect behavior. Creating a share does not authorize that cluster-wide operation. Thus phase one should hard-gate persistent-handle protocol behavior, while treating end-to-end nondisruptive failover as a later, separately approved gate.

### Kerberos: defer until AD and runner prerequisites are controlled

ONTAP supports Kerberos and NTLM for domain users, and Kerberos is its default domain authentication method. But Kerberos authentication requires the client to contact the AD KDC and obtain credentials for the server principal.[NetApp: SMB client authentication](https://docs.netapp.com/us-en/ontap/smb-admin/authentication-access-security-concept.html)

An isolated volume/share does not establish the client-side prerequisites: DNS canonical naming rather than an IP-only target, synchronized time, KDC reachability, a usable domain principal or keytab/ticket cache, and correct CIFS service-principal registration. Testing only with a username/password that currently negotiates NTLMv2 does not prove Kerberos. Kerberos can become a hard gate after those AD/runner facts are independently verified and their lifecycle is under test control; it should not be a phase-one hard gate under the present authorization.

### SMB Multichannel: defer until SVM and network topology are controlled

ONTAP's Multichannel enablement is an SMB-server/SVM option (`-is-multichannel-enabled`), not a share property, and defaults to false. Clients require SMB 3.0 or later and automatically use multiple connections only when the cluster/client NIC topology is suitable. NetApp describes one connection per 1 GbE NIC and up to four per 10 GbE-or-faster NIC, with multiple NICs enabling additional paths.[NetApp: configure SMB Multichannel](https://docs.netapp.com/us-en/ontap/smb-admin/configure-multichannel-performance-task.html) [NetApp: available SMB server options](https://docs.netapp.com/us-en/ontap/smb-admin/server-options-reference.html)

Enabling it changes behavior for the SVM and an isolated share cannot manufacture independent network paths. A reliable hard gate needs explicit authorization for the SVM-wide option plus verified data LIF/NIC/subnet reachability from the test runner. Until then, phase one may unit/integration-test the client's Multichannel state machine, but cannot claim a real FAS2750 Multichannel acceptance gate.

## Operational guardrails for eventual execution

- Use unique, run-scoped names for the volume, share, Snapshot, directories, and files; never modify the existing production-like share.
- Snapshot/Previous Versions and share encryption can be provisioned and cleaned up entirely inside the authorized resources.
- Do not toggle SVM-wide signing, encryption, or Multichannel settings without a separate change window and rollback plan; existing/new sessions outside the test share can be affected.
- Do not perform takeover/giveback merely to test CA behavior without explicit cluster-operation approval.
- Record negotiated dialect, signing/encryption flags, cipher, authentication mechanism, persistent-handle context, connection count, and ONTAP session evidence as acceptance artifacts.
- Keep credentials out of command lines, logs, repository files, and tracker content.
