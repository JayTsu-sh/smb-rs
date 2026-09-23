# DXN AD-authenticated CIFS access investigation

Date: 2026-09-01

## Current authorization design

The Samba service is joined to the `DSM2026` Active Directory domain.  The
`ad-service-cifs` share has `valid users = administrator` and `write list =
administrator`; it is therefore directly authorized for the domain
`Administrator` account, not for a dedicated least-privilege test principal.

Winbind resolves `DSM2026\\Administrator` as an AD-backed Unix identity.  Other
directory users being resolvable by Winbind does not grant them access to this
share: they are absent from the share's `valid users` and `write list`.

The global Samba policy uses `map to guest = Bad User`.  All real AD validation
must consequently use a domain-qualified identity.  An unqualified unknown
name can otherwise be mapped to guest and cannot establish that AD
authentication or share authorization worked.

## Validation result and blocking condition

The positive, public-API DXN profile was run with the domain-qualified
`Administrator` validation identity.  The client recorded an unknown request
outcome before a usable session/share was established, so no test file was
created and no cleanup action was needed.

The DXN control plane reports a cluster health error.  CTDB reports only the
node that owns the CIFS public addresses as healthy; the two peer nodes are
unhealthy.  The SMB endpoint is therefore operating with degraded cluster
health, which is the current blocker to interpreting a client-side timeout as
an AD authorization failure.

## Safe next step

Restore CTDB and Samba health first, then re-run the positive DXN profile with
the domain-qualified authorized identity.  If the intended acceptance user
must be non-administrative, create a dedicated AD principal and update this
share's `valid users` and `write list` deliberately; merely creating or
discovering another AD user will not grant it access.
