---
status: accepted
---

# Validate on isolated run-owned ONTAP resources

Real-server acceptance uses uniquely identified, run-owned volumes, shares,
Snapshots, sessions, and files governed by a persisted resource inventory. A
run may mutate and clean up only objects whose name, comment, SVM, and manifest
identity all match; existing shares and SVM, AD, network, and cluster settings
remain read-only. This makes real FAS2750 verification a hard release gate
without turning tests into broad infrastructure automation.

The gate includes SMB 3.1.1/NTLMv2/signing, file and directory lifecycle,
leases/oplocks/change-notify, share encryption, Previous Versions, concurrency,
fault recovery, and performance. CA persistent handles are hard only when the
authorized isolated prerequisites are available; takeover/giveback remains out
of scope. The complete topology, matrix, evidence schema, and cleanup protocol
are in `docs/validation/fas2750-acceptance.md`.
