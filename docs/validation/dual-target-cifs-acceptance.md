# Dual-target CIFS acceptance

These ignored integration tests validate the SMB client separately against two
existing CIFS shares:

- `cifs_acceptance_dxn_ad` uses the `dxn-ad` profile and an AD validation
  principal.
- `cifs_acceptance_fas_local` uses the `fas-local` profile and a local CIFS
  validation principal.

They must run only on an authorized, controlled runner. They do not install
software, provision storage, or use ONTAP management access.

## Profile inputs

Each profile has no defaults. Its controlled secret provider supplies the
following inherited descriptors; the runner supplies their descriptor numbers
through the named environment variables.

| Profile-specific variable suffix | Meaning |
| --- | --- |
| `SERVER_FD` | SMB server identity |
| `SHARE_FD` | Share name |
| `EXPECTED_SERVER_FD` | Controlled-runner server identity the profile is authorized to test; must exactly match `SERVER_FD` |
| `EXPECTED_SHARE_FD` | Controlled-runner share name the profile is authorized to test; must exactly match `SHARE_FD` |
| `USERNAME_FD` | Validation username |
| `PASSWORD_FD` | Valid password |
| `REJECT_PASSWORD_FD` | Distinct, known-wrong password for one rejection probe |
| `EVIDENCE_PATH` | Output location for secret-free profile evidence JSON |
| `ACCOUNT_LOCKOUT_ATTESTED` | `yes` only when one failed login is authorized; otherwise `no` |

The full names begin with either `SMB_CIFS_ACCEPTANCE_DXN_AD_` or
`SMB_CIFS_ACCEPTANCE_FAS_LOCAL_`. Both tests also require
`SMB_CIFS_ACCEPTANCE_COMMIT`, a 7–40 digit lowercase hexadecimal commit ID.
For `dxn-ad`, `USERNAME_FD` must contain the domain-qualified AD identity;
an unqualified name can be mapped by Samba's guest policy instead of the
validation principal.

To validate valid authentication and file I/O without attempting an incorrect
password, run the profile-specific positive test:

```text
cargo test -p smb --features real-server-tests --test dual_target_cifs -- --ignored cifs_positive_dxn_ad
cargo test -p smb --features real-server-tests --test dual_target_cifs -- --ignored cifs_positive_fas_local
```

Those tests authenticate with the valid profile identity, connect the share,
perform a create-new/write/flush/read round trip, and exact-object delete then
close. A target that cannot be reached is recorded as
`Blocked/target-unavailable`; it is never a passing result.

### FAS ACL specialist checks

The ignored FAS ACL tests in `crates/smb/tests/fas2750_acl.rs` preferentially
use the same `SMB_CIFS_ACCEPTANCE_FAS_LOCAL_*_FD` descriptor contract. They
also require `EXPECTED_SERVER_FD` and `EXPECTED_SHARE_FD` to match the supplied
target before any SMB connection is opened. A partially supplied profile is an
error; it never falls back to another share. The legacy
`SMB_RUST_TESTS_*_FD` inputs remain only for a deliberately configured local
or manual harness.

After account-lockout policy authorization, the full acceptance tests also
perform one wrong-password SessionSetup probe. They require the two additional
profile variables `REJECT_PASSWORD_FD` and `ACCOUNT_LOCKOUT_ATTESTED=yes`:

```text
cargo test -p smb --features real-server-tests --test dual_target_cifs -- --ignored cifs_acceptance_dxn_ad
cargo test -p smb --features real-server-tests --test dual_target_cifs -- --ignored cifs_acceptance_fas_local
```

## Aggregate result

After both profile artifacts exist, a controlled runner sets these paths:

- `SMB_CIFS_ACCEPTANCE_DXN_AD_EVIDENCE_PATH`
- `SMB_CIFS_ACCEPTANCE_FAS_LOCAL_EVIDENCE_PATH`
- `SMB_CIFS_ACCEPTANCE_AGGREGATE_EVIDENCE_PATH`
- `SMB_CIFS_ACCEPTANCE_CHECKPOINT_SUMMARY_PATH`

Then it invokes the ignored aggregation test:

```text
cargo test -p smb-tests --test cifs_acceptance_artifacts -- --ignored aggregate_dual_target_cifs_evidence
```

The aggregate accepts only one passing artifact for each required profile with
the same commit ID. It writes a secret-free aggregate JSON and, only on success,
a short Markdown checkpoint summary. The controlled CI retains those artifacts
for 30 days; ordinary pull-request CI receives no device credentials.
