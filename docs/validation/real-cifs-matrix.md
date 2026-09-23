# Real CIFS matrix

`crates/smb/tests/real_cifs_matrix.rs` is the repeatable acceptance suite for
the approved live shares. It deliberately excludes the FAS Unix
security-style share and the retired DXN AD share. No address, account, or
secret is checked into this repository.

The suite has one ignored test per controlled profile:

| Test | Profile | Scope |
| --- | --- | --- |
| `real_cifs_matrix_fas_ntfs` | `FAS_NTFS` | Isolated FAS NTFS security-style share only |
| `real_cifs_matrix_dxn_acl` | `DXN_ACL` | Approved DXN ACL share |
| `real_cifs_matrix_openfs_guest` | `OPENFS_GUEST` | Approved OpenFS guest share |
| `real_cifs_matrix_windows_local` | `WINDOWS_LOCAL` | Approved Windows local-account share |

Each run creates a unique `smb-rs-matrix-<pid>-<time>` directory. It deletes
only the exact child names it created and then its exact root directory. It
does not enumerate a share to decide what to delete, and it never removes a
prefix match. A cleanup failure is a test failure and leaves the exact root
name in the test output for an operator to resolve.

## Controlled-profile contract

For profile `P`, the runner passes these file-descriptor numbers rather than
secret values:

| Variable | Meaning |
| --- | --- |
| `SMB_CIFS_MATRIX_P_SERVER_FD` | Server address or name |
| `SMB_CIFS_MATRIX_P_SHARE_FD` | Share name |
| `SMB_CIFS_MATRIX_P_USERNAME_FD` | User name, including domain when applicable |
| `SMB_CIFS_MATRIX_P_PASSWORD_FD` | Password; omitted only for guest access |
| `SMB_CIFS_MATRIX_P_EXPECTED_SERVER_FD` | Authorized server binding; must exactly match `SERVER_FD` |
| `SMB_CIFS_MATRIX_P_EXPECTED_SHARE_FD` | Authorized share binding; must exactly match `SHARE_FD` |
| `SMB_CIFS_MATRIX_P_PASSWORD_EMPTY=yes` | Selects the empty guest password instead of `PASSWORD_FD` |
| `SMB_CIFS_MATRIX_P_DACL_WRITE=yes` | Enables DACL query and idempotent write |
| `SMB_CIFS_MATRIX_P_ACL_INHERITANCE=windows-marked` | Requires a child to report `INHERITED_ACE` |
| `SMB_CIFS_MATRIX_P_ACL_INHERITANCE=posix-mapped` | Requires inherited effective access but permits the POSIX mapper to omit `INHERITED_ACE` |
| `SMB_CIFS_MATRIX_P_ACL_TRUSTEE_SID_FD` | Optional accepted trustee SID when discovery from the parent DACL is insufficient |

`ACL_INHERITANCE` requires `DACL_WRITE=yes`. The profile owner selects its
backend semantics explicitly: FAS NTFS and Windows use `windows-marked`; a
POSIX-mapped DXN backend may use `posix-mapped`. The OpenFS profile must be
classified from its observed DACL behavior before enabling inheritance rather
than assuming Windows semantics for a guest share.

The suite verifies:

- negotiate/authenticate/tree connect and clean close;
- open and enumerate the share root via `SharePath(".")`;
- create, write, flush, exact read-back, metadata, rename, and exact delete;
- a one-MiB single-file transfer with four chunk operations in flight;
- sixteen independent small-file create/write/read/flush operations in
  parallel;
- optional DACL query followed by atomic idempotent DACL replacement;
- optional create-time ACL inheritance from a parent directory to a new child.

It intentionally does **not** make parent-ACL changes retroactively rewrite
existing children a pass condition. FAS testing established that this is an
optional server capability, distinct from ordinary create-time inheritance.
Snapshot creation/deletion and management-initiated CIFS session closure stay
in their specialist tests because they need a separately authorized management
plane and an isolated resource manifest.

Run one profile only after exporting its controlled descriptors:

```text
cargo test -p smb --features real-server-tests --test real_cifs_matrix -- --ignored real_cifs_matrix_fas_ntfs
```

## Latest controlled execution

On 2026-09-23, the suite completed against all four approved targets with
exact-run-root cleanup:

| Profile | DACL | Create-time inheritance | Result |
| --- | --- | --- | --- |
| FAS NTFS | Query and idempotent set | `windows-marked` | Pass |
| DXN ACL | Query and idempotent set | `posix-mapped` | Pass |
| OpenFS guest | Query and idempotent set | `posix-mapped` | Pass |
| Windows local | Query and idempotent set | `windows-marked` | Pass |

The first Windows strict run omitted `SE_DACL_AUTO_INHERIT_REQ` when replacing
the parent DACL. The server consequently materialized effective child access
without `INHERITED_ACE`. The matrix now sets that request bit for
`windows-marked`; the repeated real-server run returned inherited child ACEs
and passed. This is an acceptance-test correction, not a change to the SMB
client's ACL decoder.
