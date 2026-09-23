# DXN POSIX-mapped CIFS ACL validation

Date: 2026-09-02 (Asia/Shanghai)
Target: `\\10.131.7.201\acl_src`
Validation identity: `acl` (password omitted)
Result: **passed**

## Interface constraint

ACL style is not part of the public smb-rs interface. Both target families use
the same atomic `Share::query_security` and `Share::set_security` operations.
No public `AclStyle` enum, flag, or branching requirement was added.

Internally, smb-rs retains account-domain and POSIX-mapped user/group ACEs,
plus the `Everyone` (`S-1-1-0`) and `SYSTEM` (`S-1-5-18`) special trustees.
Other non-account trustees are omitted on both query and set, without exposing
that compatibility rule to callers.

The corrected DXN test discovers an already valid mapped group trustee from
the DACL returned by the server. For this run it was `S-1-22-2-4001`. Every
mutation reuses that server-resolved SID; the test never creates or injects a
Windows well-known trustee.

## Complete flow

| Stage | Returned result |
| --- | --- |
| Parent create/query | `0x8004`, four ACEs; mapped group `S-1-22-2-4001/0x001301bf` |
| Mark existing mapped-group ACE OI/CI | Exact SID, mask and OI/CI read back |
| Child directory create | Parent mapped-group ACE copied; server also retained its ordinary group ACE |
| Child file create | Mapped-group access ACE present; no Windows `INHERITED_ACE` marker |
| File self-DACL atomic round trip | Exact descriptor round-tripped |
| Protect child directory | `DACL_PROTECTED=true`, control `0x9004` |
| Change parent mapped-group mask | Parent changed from `0x001301bf` to `0x001301ff` |
| Query protected child | Old mask retained; parent change blocked |
| Query existing unprotected child file | Old mask retained; DXN does not dynamically recalculate it |
| Create sibling after parent change | Updated `0x001301ff` mapped-group ACE copied at create time |
| Clear child protection only | `DACL_PROTECTED=false`; server does not synthesize the changed parent entry |
| Submit complete target DACL | Updated mapped-group ACE and OI/CI preserved atomically |
| Cleanup | File and all three directories deleted; exact parent re-open returned not-found |

## Parent ACL after the valid POSIX-mapped mutation

```json
{
  "control": {
    "raw_le_hex": "0x8004",
    "dacl_present": true,
    "dacl_auto_inherited": false,
    "dacl_protected": false
  },
  "aces": [
    ["S-1-5-21-30867142-2047894945-2797183231-1014", "0x001f01ff", false, false, false],
    ["S-1-22-2-4001", "0x001301bf", true, true, false],
    ["S-1-1-0", "0x001201bf", false, false, false],
    ["S-1-5-18", "0x001f01ff", false, false, false]
  ]
}
```

Each ACE tuple is `[trustee_sid, access_mask, object_inherit,
container_inherit, inherited]`.

## Child directory ACL after create

```json
{
  "control": {
    "raw_le_hex": "0x8004",
    "dacl_present": true,
    "dacl_auto_inherited": false,
    "dacl_protected": false
  },
  "aces": [
    ["S-1-5-21-30867142-2047894945-2797183231-1014", "0x001f01ff", false, false, false],
    ["S-1-22-2-4001", "0x001301bf", false, false, false],
    ["S-1-1-0", "0x001201bf", false, false, false],
    ["S-1-5-18", "0x001f01ff", false, false, false],
    ["S-1-22-2-4001", "0x001301bf", true, true, false]
  ]
}
```

The duplicate mapped-group entries are the actual server response: one normal
access entry plus one create-time copied OI/CI entry. Neither is marked with
Windows `INHERITED_ACE`.

## Final observations

```json
{
  "mapped_group_sid": "S-1-22-2-4001",
  "parent_inheritable_ace_preserved": true,
  "child_directory_copied_parent_ace": true,
  "child_directory_marks_ace_inherited": false,
  "child_file_copied_parent_ace": true,
  "child_file_marks_ace_inherited": false,
  "file_self_dacl_roundtrip": true,
  "inheritance_disabled": true,
  "protected_child_blocks_parent_change": true,
  "existing_unprotected_file_tracks_parent_change": false,
  "new_sibling_copies_updated_parent_ace": true,
  "new_sibling_marks_ace_inherited": false,
  "inheritance_unprotected_without_merge": true,
  "unprotect_only_synthesizes_parent_change": false,
  "atomic_target_dacl_applied": true
}
```

The false inheritance-marker and dynamic-update fields describe expected DXN
Linux ACL behavior; they are observations, not failed Windows-style assertions.
The acceptance assertions require transparent descriptor round-trip,
create-time copy, protection, atomic replacement, and cleanup, all of which
passed.
