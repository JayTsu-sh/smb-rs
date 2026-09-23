# Real CIFS validation report — 2026-09-23

## Scope and controls

This report covers the approved production-like SMB shares using the public
`smb-rs` client. Credentials were supplied through inherited file descriptors;
they are not recorded here. Every mutating matrix case owned a unique
`smb-rs-matrix-<pid>-<time>` directory and removed only that exact directory
and its exact children.

The FAS Unix security-style share and the retired DXN AD-service share are
explicitly out of scope. FAS validation uses the isolated NTFS
security-style share only.

## Executed matrix

Command class: `cargo test -p smb --features real-server-tests --test
real_cifs_matrix -- --ignored --test-threads=1`.

| Target profile | Authentication | DACL write | ACL create-time inheritance | Functional matrix | Cleanup | Verdict |
| --- | --- | --- | --- | --- | --- | --- |
| FAS isolated NTFS | Local CIFS user | Query + idempotent replacement | Windows marked (`INHERITED_ACE`) | Pass | Pass | Pass |
| DXN ACL | ACL user | Query + idempotent replacement | POSIX-mapped effective inheritance | Pass | Pass | Pass |
| OpenFS guest | Guest, empty password | Query + idempotent replacement | POSIX-mapped effective inheritance | Pass | Pass | Pass |
| Windows local | Local Windows account | Query + idempotent replacement | Windows marked (`INHERITED_ACE`) | Pass | Pass | Pass |

The four-profile execution completed with four passes and no residual-object
cleanup failures.

Each functional matrix result includes:

1. SMB negotiate, authentication, tree connect, and orderly close.
2. Open and enumerate the share root through `SharePath(".")`.
3. Create a directory; create/write/flush/read exact bytes; metadata query;
   rename; and exact deletion.
4. A 1 MiB single-file transfer with four transfer chunks in flight, followed
   by byte-for-byte verification.
5. Sixteen independent small-file create/write/flush/read operations in
   parallel.
6. DACL read followed by atomic idempotent DACL replacement.
7. An inheritable parent ACE and a newly created child. Windows/FAS require
   the child response to carry `INHERITED_ACE`; mapped targets require the
   effective ACE while allowing their backend-specific marker behavior.

## Windows ACL finding and resolution

The first strict Windows inheritance run propagated access but omitted
`INHERITED_ACE`. A minimized real-server probe showed that the test had
replaced the parent DACL without requesting `SE_DACL_AUTO_INHERIT_REQ`.
After the matrix added that request bit for `windows-marked`, the Windows
child response carried the inherited marker and the strict test passed.

This corrected the acceptance scenario only. No production SMB ACL encoding
or decoding behavior was changed.

## FAS ACL specialist coverage

The isolated FAS share passed the matrix's strict DACL and create-time
inheritance coverage. The deeper specialist suite covers explicit allow/deny,
protection/unprotection, and automatic-propagation observations. It requires a
distinguishable account-domain or POSIX-mapped trustee SID.

The current isolated share's root DACL exposes only the broad `Everyone` ACE.
That ACE already grants the masks used by the specialist test, so it cannot
validly distinguish whether a later parent ACE was blocked by a protected
child. The specialist test correctly rejects that condition instead of treating
it as a product failure. Re-run it after supplying an approved dedicated
trustee through `SMB_FAS_ACL_TEST_TRUSTEE_SID`.

Prior FAS capability validation established that create-time inheritance is
supported, while automatic recalculation of a parent ACL onto existing
descendants is not a required/available FAS behavior. The matrix intentionally
does not treat that latter optional behavior as a pass condition.

## Not executed in this run

| Scenario | Reason | Status |
| --- | --- | --- |
| Snapshot creation, previous-version read, and snapshot deletion | Requires a separately orchestrated ONTAP management-plane snapshot lifecycle | Not run |
| Management-initiated CIFS session close and stale-handle recovery | Requires a dedicated management action tied to the exact test session | Not run |
| Persistent handles / continuously available share | Requires a CA share | Not applicable to the approved shares |
| SMB Multichannel / failover | Requires multiple approved data paths and SVM-wide configuration | Not run |
| Wrong-password probe | Avoided because of account-lockout policy risk | Not run |

Therefore the functional, concurrent-I/O, root-path, DACL, and create-time
inheritance acceptance matrix is complete for the four approved shares. The
management-plane scenarios above remain intentionally unclaimed, not passed.
