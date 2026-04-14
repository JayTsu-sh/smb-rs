#![allow(unused_parens)]

//! LSARPC (Local Security Authority Remote Procedure Call) interface.
//!
//! Implements a subset of [MS-LSAD](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad>)
//! for resolving SIDs to account names over SMB named pipes.
//!
//! Supported operations:
//! - [`LsaRpc::open_policy2`] - Opens a policy handle ([OPNUM 44](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/2a482ccf-1f89-4693-8594-855ff738ae8a>))
//! - [`LsaRpc::lookup_sids`] - Resolves SIDs to account names ([OPNUM 15](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/eb55ec23-17e0-4eae-89f4-cd610f9e7f2d>))
//! - [`LsaRpc::close`] - Closes the policy handle ([OPNUM 0](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/c3e0af02-cb83-4956-979d-4ff72e11e06e>))

use crate::{interface::*, pdu::DceRpcSyntaxId};

use crate::ndr64::*;
use binrw::prelude::*;
use maybe_async::maybe_async;
use smb_dtyp::{make_guid, SID};

// ─── Context handle (20 bytes) ──────────────────────────────────────────────

/// A 20-byte RPC context handle used by LSARPC operations.
///
/// [MS-LSAD 2.2.2.1](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/22e1e37e-500f-4c04-bb10-1a2dd1639dac>)
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct LsaHandle {
    pub context_handle_attributes: u32,
    pub context_handle_uuid: [u8; 16],
}

// ─── NTSTATUS ───────────────────────────────────────────────────────────────

/// NT status code returned by LSARPC operations.
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct NtStatus(pub u32);

impl NtStatus {
    pub const SUCCESS: Self = Self(0x00000000);
    pub const SOME_NOT_MAPPED: Self = Self(0x00000107);
    pub const NONE_MAPPED: Self = Self(0xC0000073);

    pub fn is_success(&self) -> bool {
        self.0 == Self::SUCCESS.0 || self.0 == Self::SOME_NOT_MAPPED.0
    }
}

impl std::fmt::Display for NtStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::SUCCESS => write!(f, "STATUS_SUCCESS"),
            Self::SOME_NOT_MAPPED => write!(f, "STATUS_SOME_NOT_MAPPED"),
            Self::NONE_MAPPED => write!(f, "STATUS_NONE_MAPPED"),
            _ => write!(f, "NTSTATUS(0x{:08X})", self.0),
        }
    }
}

// ─── ACCESS_MASK for policy ─────────────────────────────────────────────────

/// Desired access mask for LsarOpenPolicy2.
///
/// [MS-LSAD 2.4.1.1](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/87bacab0-e828-4b4c-a5df-d7b520816757>)
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct PolicyAccessMask(pub u32);

impl PolicyAccessMask {
    /// POLICY_LOOKUP_NAMES (0x00000800) - required for LsarLookupSids.
    pub const LOOKUP_NAMES: Self = Self(0x00000800);
}

// ─── LsarOpenPolicy2 (OPNUM 44) ────────────────────────────────────────────

/// Input for [LsarOpenPolicy2](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/2a482ccf-1f89-4693-8594-855ff738ae8a>)
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
struct LsarOpenPolicy2In {
    /// Server name (optional, usually the target machine name).
    system_name: NdrAlign<NdrPtr<NdrString<u16>>, 4>,
    /// Object attributes - LSAPR_OBJECT_ATTRIBUTES (zeroed).
    object_attributes_length: NdrAlign<u32, 4>,
    object_attributes_root_dir: NdrAlign<NdrPtr<u8>, 4>,
    object_attributes_object_name: NdrAlign<NdrPtr<u8>, 4>,
    object_attributes_attributes: NdrAlign<u32, 4>,
    object_attributes_security_descriptor: NdrAlign<NdrPtr<u8>, 4>,
    object_attributes_security_qos: NdrAlign<NdrPtr<u8>, 4>,
    /// Desired access - POLICY_LOOKUP_NAMES.
    desired_access: NdrAlign<PolicyAccessMask, 4>,
}

/// Output for LsarOpenPolicy2.
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
struct LsarOpenPolicy2Out {
    policy_handle: LsaHandle,
    status: NtStatus,
}

impl RpcCall for LsarOpenPolicy2In {
    const OPNUM: u16 = 44;
    type ResponseType = LsarOpenPolicy2Out;
}

// ─── SID array serialization (custom) ──────────────────────────────────────

/// LSAPR_SID_ENUM_BUFFER - custom serialization because SID doesn't
/// conform to NdrArray's trait bounds.
///
/// NDR64 wire format:
/// ```text
/// entries: u32 (count)
/// ptr_ref_id: u64 (pointer to conformant array)
/// max_count: u64
/// per-SID: ref_id (u64)
/// per-SID: SID data
/// ```
#[derive(Debug, PartialEq, Eq)]
struct LsaSidEnumBuffer {
    sids: Vec<SID>,
}

impl BinWrite for LsaSidEnumBuffer {
    type Args<'a> = ();

    fn write_options<W: std::io::Write + std::io::Seek>(
        &self,
        writer: &mut W,
        endian: binrw::endian::Endian,
        _args: Self::Args<'_>,
    ) -> binrw::BinResult<()> {
        let count = self.sids.len() as u32;
        // entries (aligned to 4)
        NdrAlign::<u32, 4>::from(count).write_options(writer, endian, ())?;
        // pointer ref_id for the array (non-null)
        NdrAlign::<u64>::from(REF_ID_UNIQUE_DEFAULT).write_options(writer, endian, ())?;
        // max_count of conformant array
        NdrAlign::<u64>::from(count as u64).write_options(writer, endian, ())?;
        // First pass: write ref_ids for each SID pointer
        for _ in &self.sids {
            NdrAlign::<u64>::from(REF_ID_UNIQUE_DEFAULT).write_options(writer, endian, ())?;
        }
        // Second pass: write SID data
        for sid in &self.sids {
            sid.write_options(writer, endian, ())?;
        }
        Ok(())
    }
}

// We only write LsaSidEnumBuffer, never read it (it's request-only).
impl BinRead for LsaSidEnumBuffer {
    type Args<'a> = ();

    fn read_options<R: std::io::Read + std::io::Seek>(
        _reader: &mut R,
        _endian: binrw::endian::Endian,
        _args: Self::Args<'_>,
    ) -> binrw::BinResult<Self> {
        Ok(Self { sids: Vec::new() })
    }
}

// ─── LsarLookupSids (OPNUM 15) ─────────────────────────────────────────────

/// Lookup level for LsarLookupSids.
///
/// [MS-LSAD 2.2.16](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/9c5fded5-801a-4e07-8328-6e00b8e5f2a2>)
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[brw(repr(u16))]
pub enum LsaLookupLevel {
    /// Searches all name-resolution mechanisms.
    LsapLookupWksta = 1,
}

/// Input for [LsarLookupSids](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/eb55ec23-17e0-4eae-89f4-cd610f9e7f2d>)
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
struct LsarLookupSidsIn {
    /// Policy handle from LsarOpenPolicy2.
    policy_handle: LsaHandle,
    /// SIDs to look up.
    sid_enum_buffer: NdrAlign<LsaSidEnumBuffer, 4>,
    /// LSAPR_TRANSLATED_NAMES (initially empty).
    translated_names_entries: NdrAlign<u32, 4>,
    translated_names_names: NdrAlign<NdrPtr<u8>, 4>,
    /// Lookup level.
    lookup_level: NdrAlign<LsaLookupLevel, 4>,
    /// Mapped count (initially 0).
    mapped_count: NdrAlign<u32, 4>,
}

impl RpcCall for LsarLookupSidsIn {
    const OPNUM: u16 = 15;
    type ResponseType = LsarLookupSidsOut;
}

// ─── LsarLookupSids response (custom deserialization) ──────────────────────

/// SID type (well-known account types).
///
/// [MS-LSAD 2.2.13](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/46d31912-e447-47c1-a025-c6ff84e25b8b>)
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[brw(repr(u16))]
pub enum SidNameUse {
    User = 1,
    Group = 2,
    Domain = 3,
    Alias = 4,
    WellKnownGroup = 5,
    DeletedAccount = 6,
    Invalid = 7,
    Unknown = 8,
    Computer = 9,
    Label = 10,
    LogonSession = 11,
}

/// NDR RPC_UNICODE_STRING buffer (conformant-varying u16 array).
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[allow(unused_variables, clippy::all)]
pub struct LsaUnicodeStringBuffer {
    #[bw(calc = (chars.len() as u64).into())]
    #[br(temp)]
    max_count: NdrAlign<u64>,
    #[bw(calc = 0u64.into())]
    #[br(temp)]
    #[br(assert(*offset == 0))]
    offset: NdrAlign<u64>,
    #[bw(calc = (chars.len() as u64).into())]
    #[br(temp)]
    #[br(assert(*actual_count <= *max_count))]
    actual_count: NdrAlign<u64>,
    #[br(count = *actual_count)]
    pub chars: Vec<u16>,
}

impl LsaUnicodeStringBuffer {
    pub fn to_string_lossy(&self) -> String {
        String::from_utf16_lossy(&self.chars)
    }
}

/// A parsed translated name from the LsarLookupSids response.
#[derive(Debug)]
struct ParsedTranslatedName {
    use_type: SidNameUse,
    name: Option<String>,
    domain_index: i32,
}

/// A parsed domain from the referenced domain list.
#[derive(Debug)]
struct ParsedDomain {
    name: Option<String>,
}

/// Output for LsarLookupSids - parsed manually because the NDR structures
/// are complex (RPC_UNICODE_STRING arrays with deferred pointers).
#[derive(Debug)]
#[allow(dead_code)]
struct LsarLookupSidsOut {
    domains: Vec<ParsedDomain>,
    names: Vec<ParsedTranslatedName>,
    mapped_count: u32,
    status: NtStatus,
}

impl BinRead for LsarLookupSidsOut {
    type Args<'a> = ();

    fn read_options<R: std::io::Read + std::io::Seek>(
        reader: &mut R,
        endian: binrw::endian::Endian,
        _args: Self::Args<'_>,
    ) -> binrw::BinResult<Self> {
        // 1. Referenced domains pointer
        let domains_ref_id = *NdrAlign::<u64>::read_options(reader, endian, ())?;
        let domains = if domains_ref_id != NULL_PTR_REF_ID {
            parse_referenced_domain_list(reader, endian)?
        } else {
            Vec::new()
        };

        // 2. LSAPR_TRANSLATED_NAMES
        let names = parse_translated_names(reader, endian)?;

        // 3. Mapped count
        let mapped_count = *NdrAlign::<u32>::read_options(reader, endian, ())?;

        // 4. NTSTATUS
        let status = NtStatus::read_options(reader, endian, ())?;

        Ok(Self {
            domains,
            names,
            mapped_count,
            status,
        })
    }
}

impl BinWrite for LsarLookupSidsOut {
    type Args<'a> = ();

    fn write_options<W: std::io::Write + std::io::Seek>(
        &self,
        _writer: &mut W,
        _endian: binrw::endian::Endian,
        _args: Self::Args<'_>,
    ) -> binrw::BinResult<()> {
        // Response-only structure; writing not needed.
        Ok(())
    }
}

/// Parse LSAPR_REFERENCED_DOMAIN_LIST from the response stream.
fn parse_referenced_domain_list<R: std::io::Read + std::io::Seek>(
    reader: &mut R,
    endian: binrw::endian::Endian,
) -> binrw::BinResult<Vec<ParsedDomain>> {
    // entries count
    let entries = *NdrAlign::<u32>::read_options(reader, endian, ())?;
    // pointer to domain array
    let domains_array_ref = *NdrAlign::<u64>::read_options(reader, endian, ())?;
    // max_entries
    let _max_entries = *NdrAlign::<u32>::read_options(reader, endian, ())?;

    if domains_array_ref == NULL_PTR_REF_ID || entries == 0 {
        return Ok(Vec::new());
    }

    // Conformant array: max_count
    let max_count = *NdrAlign::<u64>::read_options(reader, endian, ())?;
    let count = std::cmp::min(entries as u64, max_count) as usize;

    // First pass: read fixed-size parts of each LSAPR_TRUST_INFORMATION
    // (name_length, name_max_length, name_ref_id, domain_sid_ref_id)
    struct DomainFixedPart {
        name_length: u16,
        name_ref_id: u64,
        sid_ref_id: u64,
    }
    let mut fixed_parts = Vec::with_capacity(count);
    for _ in 0..count {
        let name_length = *NdrAlign::<u16, 4>::read_options(reader, endian, ())?;
        let _name_max_length = *NdrAlign::<u16, 4>::read_options(reader, endian, ())?;
        let name_ref_id = *NdrAlign::<u64>::read_options(reader, endian, ())?;
        let sid_ref_id = *NdrAlign::<u64>::read_options(reader, endian, ())?;
        fixed_parts.push(DomainFixedPart {
            name_length,
            name_ref_id,
            sid_ref_id,
        });
    }

    // Second pass: read deferred pointer data (name buffers and SIDs)
    let mut domains = Vec::with_capacity(count);
    for part in &fixed_parts {
        let name = if part.name_ref_id != NULL_PTR_REF_ID && part.name_length > 0 {
            let buf = LsaUnicodeStringBuffer::read_options(reader, endian, ())?;
            Some(buf.to_string_lossy())
        } else {
            None
        };
        // Skip SID data if present
        if part.sid_ref_id != NULL_PTR_REF_ID {
            let _sid = SID::read_options(reader, endian, ())?;
        }
        domains.push(ParsedDomain { name });
    }

    Ok(domains)
}

/// Parse LSAPR_TRANSLATED_NAMES from the response stream.
fn parse_translated_names<R: std::io::Read + std::io::Seek>(
    reader: &mut R,
    endian: binrw::endian::Endian,
) -> binrw::BinResult<Vec<ParsedTranslatedName>> {
    // entries count
    let entries = *NdrAlign::<u32>::read_options(reader, endian, ())?;
    // pointer to names array
    let names_ref_id = *NdrAlign::<u64>::read_options(reader, endian, ())?;

    if names_ref_id == NULL_PTR_REF_ID || entries == 0 {
        return Ok(Vec::new());
    }

    // Conformant array: max_count
    let max_count = *NdrAlign::<u64>::read_options(reader, endian, ())?;
    let count = std::cmp::min(entries as u64, max_count) as usize;

    // First pass: read fixed-size parts of each LSAPR_TRANSLATED_NAME
    struct NameFixedPart {
        use_type: SidNameUse,
        name_length: u16,
        name_ref_id: u64,
        domain_index: i32,
    }
    let mut fixed_parts = Vec::with_capacity(count);
    for _ in 0..count {
        let use_type = *NdrAlign::<SidNameUse, 4>::read_options(reader, endian, ())?;
        let name_length = *NdrAlign::<u16, 4>::read_options(reader, endian, ())?;
        let _name_max_length = *NdrAlign::<u16, 4>::read_options(reader, endian, ())?;
        let name_ref_id = *NdrAlign::<u64>::read_options(reader, endian, ())?;
        let domain_index = *NdrAlign::<i32, 4>::read_options(reader, endian, ())?;
        fixed_parts.push(NameFixedPart {
            use_type,
            name_length,
            name_ref_id,
            domain_index,
        });
    }

    // Second pass: read deferred pointer data (name buffers)
    let mut names = Vec::with_capacity(count);
    for part in &fixed_parts {
        let name = if part.name_ref_id != NULL_PTR_REF_ID && part.name_length > 0 {
            let buf = LsaUnicodeStringBuffer::read_options(reader, endian, ())?;
            Some(buf.to_string_lossy())
        } else {
            None
        };
        names.push(ParsedTranslatedName {
            use_type: part.use_type,
            name,
            domain_index: part.domain_index,
        });
    }

    Ok(names)
}

// ─── LsarClose (OPNUM 0) ───────────────────────────────────────────────────

/// Input for [LsarClose](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/c3e0af02-cb83-4956-979d-4ff72e11e06e>)
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
struct LsarCloseIn {
    object_handle: LsaHandle,
}

/// Output for LsarClose.
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
struct LsarCloseOut {
    object_handle: LsaHandle,
    status: NtStatus,
}

impl RpcCall for LsarCloseIn {
    const OPNUM: u16 = 0;
    type ResponseType = LsarCloseOut;
}

// ─── Public result types ────────────────────────────────────────────────────

/// Result of a SID-to-name lookup for a single SID.
#[derive(Debug, Clone)]
pub struct TranslatedName {
    /// The account name (e.g., "Administrator").
    pub name: String,
    /// The domain name (e.g., "BUILTIN", "NT AUTHORITY").
    pub domain: String,
    /// The SID type (user, group, alias, etc.).
    pub sid_type: SidNameUse,
}

impl TranslatedName {
    /// Returns the fully qualified name as `DOMAIN\Name`.
    pub fn full_name(&self) -> String {
        if self.domain.is_empty() {
            self.name.clone()
        } else {
            format!("{}\\{}", self.domain, self.name)
        }
    }
}

impl std::fmt::Display for TranslatedName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.full_name())
    }
}

// ─── LsaRpc interface ──────────────────────────────────────────────────────

/// LSARPC interface for SID-to-name resolution over SMB named pipes.
///
/// # Usage
///
/// ```text
/// let pipe = client.open_pipe(server, "lsarpc").await?;
/// let mut lsa: LsaRpc<_> = pipe.bind().await?;
/// let handle = lsa.open_policy2(r"\\server").await?;
/// let names = lsa.lookup_sids(&handle, &sids).await?;
/// lsa.close(handle).await?;
/// ```
pub struct LsaRpc<T>
where
    T: BoundRpcConnection,
{
    bound_pipe: T,
}

impl<T> LsaRpc<T>
where
    T: BoundRpcConnection,
{
    /// Opens a policy handle on the target server.
    ///
    /// The handle must be closed with [`LsaRpc::close`] when no longer needed.
    ///
    /// # Arguments
    /// * `server_name` - The target server name (e.g., `r"\\server"`).
    #[maybe_async]
    pub async fn open_policy2(&mut self, server_name: &str) -> crate::Result<LsaHandle> {
        let input = LsarOpenPolicy2In {
            system_name: NdrPtr::from(server_name.parse::<NdrString<u16>>().unwrap()).into(),
            object_attributes_length: 24u32.into(),
            object_attributes_root_dir: NdrPtr::from(None).into(),
            object_attributes_object_name: NdrPtr::from(None).into(),
            object_attributes_attributes: 0u32.into(),
            object_attributes_security_descriptor: NdrPtr::from(None).into(),
            object_attributes_security_qos: NdrPtr::from(None).into(),
            desired_access: PolicyAccessMask::LOOKUP_NAMES.into(),
        };
        let output = self.bound_pipe.send_receive(input).await?;
        if !output.status.is_success() {
            return Err(crate::SmbRpcError::InvalidResponseData(
                "LsarOpenPolicy2 failed",
            ));
        }
        Ok(output.policy_handle)
    }

    /// Resolves a list of SIDs to their account names and domains.
    ///
    /// Returns a `Vec<Option<TranslatedName>>` where each element corresponds
    /// to the input SID at the same index. `None` indicates the SID could not
    /// be resolved.
    ///
    /// # Arguments
    /// * `policy_handle` - Handle from [`LsaRpc::open_policy2`].
    /// * `sids` - The SIDs to resolve.
    #[maybe_async]
    pub async fn lookup_sids(
        &mut self,
        policy_handle: &LsaHandle,
        sids: &[SID],
    ) -> crate::Result<Vec<Option<TranslatedName>>> {
        let input = LsarLookupSidsIn {
            policy_handle: policy_handle.clone(),
            sid_enum_buffer: LsaSidEnumBuffer {
                sids: sids.to_vec(),
            }
            .into(),
            translated_names_entries: 0u32.into(),
            translated_names_names: NdrPtr::from(None).into(),
            lookup_level: LsaLookupLevel::LsapLookupWksta.into(),
            mapped_count: 0u32.into(),
        };

        let output = self.bound_pipe.send_receive(input).await?;

        // STATUS_NONE_MAPPED is acceptable — means no SIDs resolved.
        if !output.status.is_success() && output.status != NtStatus::NONE_MAPPED {
            return Err(crate::SmbRpcError::InvalidResponseData(
                "LsarLookupSids failed",
            ));
        }

        let result = output
            .names
            .iter()
            .map(|entry| {
                let name = match &entry.name {
                    Some(n) => n.clone(),
                    None => return None,
                };

                if entry.use_type == SidNameUse::Unknown {
                    return None;
                }

                let domain_index = entry.domain_index;
                let domain = if domain_index >= 0
                    && (domain_index as usize) < output.domains.len()
                {
                    output.domains[domain_index as usize]
                        .name
                        .clone()
                        .unwrap_or_default()
                } else {
                    String::new()
                };

                Some(TranslatedName {
                    name,
                    domain,
                    sid_type: entry.use_type,
                })
            })
            .collect();

        Ok(result)
    }

    /// Closes a policy handle previously opened with [`LsaRpc::open_policy2`].
    #[maybe_async]
    pub async fn close(&mut self, policy_handle: LsaHandle) -> crate::Result<()> {
        let input = LsarCloseIn {
            object_handle: policy_handle,
        };
        let output = self.bound_pipe.send_receive(input).await?;
        if !output.status.is_success() {
            return Err(crate::SmbRpcError::InvalidResponseData("LsarClose failed"));
        }
        Ok(())
    }
}

impl<T> super::base::RpcInterface<T> for LsaRpc<T>
where
    T: BoundRpcConnection,
{
    /// LSARPC interface UUID: `12345778-1234-abcd-ef00-0123456789ab` version 0.0
    const SYNTAX_ID: DceRpcSyntaxId = DceRpcSyntaxId {
        uuid: make_guid!("12345778-1234-abcd-ef00-0123456789ab"),
        version: 0,
    };

    fn new(bound_pipe: T) -> Self {
        LsaRpc { bound_pipe }
    }
}

#[cfg(test)]
mod test {
    use binrw::{io::Cursor, prelude::*};
    use smb_tests::*;
    use std::str::FromStr;

    use super::*;

    fn make_test_handle() -> LsaHandle {
        LsaHandle {
            context_handle_attributes: 0,
            context_handle_uuid: [
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                0x0d, 0x0e, 0x0f, 0x10,
            ],
        }
    }

    // ─── NtStatus tests ─────────────────────────────────────────────────

    #[test]
    fn test_ntstatus_is_success() {
        assert!(NtStatus::SUCCESS.is_success());
        assert!(NtStatus::SOME_NOT_MAPPED.is_success());
        assert!(!NtStatus::NONE_MAPPED.is_success());
        assert!(!NtStatus(0xC0000001).is_success());
    }

    #[test]
    fn test_ntstatus_display() {
        assert_eq!(NtStatus::SUCCESS.to_string(), "STATUS_SUCCESS");
        assert_eq!(
            NtStatus::SOME_NOT_MAPPED.to_string(),
            "STATUS_SOME_NOT_MAPPED"
        );
        assert_eq!(NtStatus::NONE_MAPPED.to_string(), "STATUS_NONE_MAPPED");
        assert_eq!(NtStatus(0xDEAD).to_string(), "NTSTATUS(0x0000DEAD)");
    }

    // ─── TranslatedName tests ───────────────────────────────────────────

    #[test]
    fn test_translated_name_full_name_with_domain() {
        let tn = TranslatedName {
            name: "Administrator".into(),
            domain: "BUILTIN".into(),
            sid_type: SidNameUse::Alias,
        };
        assert_eq!(tn.full_name(), r"BUILTIN\Administrator");
        assert_eq!(tn.to_string(), r"BUILTIN\Administrator");
    }

    #[test]
    fn test_translated_name_full_name_without_domain() {
        let tn = TranslatedName {
            name: "Everyone".into(),
            domain: String::new(),
            sid_type: SidNameUse::WellKnownGroup,
        };
        assert_eq!(tn.full_name(), "Everyone");
        assert_eq!(tn.to_string(), "Everyone");
    }

    // ─── LsaHandle round-trip ───────────────────────────────────────────

    test_binrw! {
        LsaHandle: make_test_handle()
            => "000000000102030405060708090a0b0c0d0e0f10"
    }

    // ─── LsarOpenPolicy2Out round-trip ──────────────────────────────────

    test_binrw! {
        LsarOpenPolicy2Out => success: LsarOpenPolicy2Out {
            policy_handle: make_test_handle(),
            status: NtStatus::SUCCESS,
        } => "000000000102030405060708090a0b0c0d0e0f1000000000"
    }

    test_binrw_read! {
        LsarOpenPolicy2Out => failure: LsarOpenPolicy2Out {
            policy_handle: LsaHandle {
                context_handle_attributes: 0,
                context_handle_uuid: [0u8; 16],
            },
            status: NtStatus::NONE_MAPPED,
        } => "0000000000000000000000000000000000000000730000c0"
    }

    // ─── LsarCloseIn round-trip ─────────────────────────────────────────

    test_binrw! {
        LsarCloseIn: LsarCloseIn {
            object_handle: make_test_handle(),
        } => "000000000102030405060708090a0b0c0d0e0f10"
    }

    // ─── LsarCloseOut round-trip ────────────────────────────────────────

    test_binrw! {
        LsarCloseOut => zeroed: LsarCloseOut {
            object_handle: LsaHandle {
                context_handle_attributes: 0,
                context_handle_uuid: [0u8; 16],
            },
            status: NtStatus::SUCCESS,
        } => "0000000000000000000000000000000000000000 00000000"
    }

    // ─── RpcCall OPNUM verification ─────────────────────────────────────

    #[test]
    fn test_opnum_values() {
        assert_eq!(LsarCloseIn::OPNUM, 0);
        assert_eq!(LsarLookupSidsIn::OPNUM, 15);
        assert_eq!(LsarOpenPolicy2In::OPNUM, 44);
    }

    // ─── RpcInterface SYNTAX_ID verification ────────────────────────────

    #[test]
    fn test_lsarpc_syntax_id() {
        // Verify the well-known LSARPC interface UUID from MS-LSAD
        let expected_uuid = make_guid!("12345778-1234-abcd-ef00-0123456789ab");
        let syntax = DceRpcSyntaxId {
            uuid: expected_uuid,
            version: 0,
        };
        // Validate that the UUID bytes match the canonical LSARPC UUID
        assert_eq!(
            syntax.uuid,
            make_guid!("12345778-1234-abcd-ef00-0123456789ab")
        );
        assert_eq!(syntax.version, 0);
    }

    // ─── LsaSidEnumBuffer serialization ─────────────────────────────────

    #[test]
    fn test_sid_enum_buffer_write_single_sid() {
        let sid = SID::from_str("S-1-5-18").unwrap(); // SYSTEM
        let buf = LsaSidEnumBuffer {
            sids: vec![sid.clone()],
        };
        let mut cursor = Cursor::new(Vec::new());
        buf.write_le(&mut cursor).unwrap();
        let data = cursor.into_inner();

        // Verify structure:
        // entries=1 (4 bytes, aligned to 4)
        assert_eq!(&data[0..4], &1u32.to_le_bytes());
        // After possible padding, ref_id (8 bytes at offset 8 due to NDR64 alignment)
        // The NdrAlign::<u64> aligns to 8
        let ref_id_offset = 8; // 4 bytes entries + 4 bytes padding
        assert_eq!(
            u64::from_le_bytes(data[ref_id_offset..ref_id_offset + 8].try_into().unwrap()),
            REF_ID_UNIQUE_DEFAULT
        );
        // max_count (8 bytes)
        let mc_offset = ref_id_offset + 8;
        assert_eq!(
            u64::from_le_bytes(data[mc_offset..mc_offset + 8].try_into().unwrap()),
            1u64 // 1 SID
        );
        // SID ref_id (8 bytes)
        let sid_ref_offset = mc_offset + 8;
        assert_eq!(
            u64::from_le_bytes(data[sid_ref_offset..sid_ref_offset + 8].try_into().unwrap()),
            REF_ID_UNIQUE_DEFAULT
        );
        // SID data follows: verify it deserializes back
        let sid_data_offset = sid_ref_offset + 8;
        let mut sid_cursor = Cursor::new(&data[sid_data_offset..]);
        let parsed_sid = SID::read_le(&mut sid_cursor).unwrap();
        assert_eq!(parsed_sid, sid);
    }

    #[test]
    fn test_sid_enum_buffer_write_multiple_sids() {
        let sid1 = SID::from_str("S-1-5-18").unwrap();
        let sid2 = SID::from_str("S-1-1-0").unwrap(); // Everyone
        let buf = LsaSidEnumBuffer {
            sids: vec![sid1, sid2],
        };
        let mut cursor = Cursor::new(Vec::new());
        buf.write_le(&mut cursor).unwrap();
        let data = cursor.into_inner();

        // entries = 2
        assert_eq!(&data[0..4], &2u32.to_le_bytes());
        // max_count = 2
        let mc_offset = 16; // 4 entries + 4 pad + 8 ref_id
        assert_eq!(
            u64::from_le_bytes(data[mc_offset..mc_offset + 8].try_into().unwrap()),
            2u64
        );
        // Two ref_ids should follow
        let ref1_offset = mc_offset + 8;
        let ref2_offset = ref1_offset + 8;
        assert_eq!(
            u64::from_le_bytes(data[ref1_offset..ref1_offset + 8].try_into().unwrap()),
            REF_ID_UNIQUE_DEFAULT
        );
        assert_eq!(
            u64::from_le_bytes(data[ref2_offset..ref2_offset + 8].try_into().unwrap()),
            REF_ID_UNIQUE_DEFAULT
        );
    }

    #[test]
    fn test_sid_enum_buffer_write_empty() {
        let buf = LsaSidEnumBuffer { sids: vec![] };
        let mut cursor = Cursor::new(Vec::new());
        buf.write_le(&mut cursor).unwrap();
        let data = cursor.into_inner();
        // entries = 0
        assert_eq!(&data[0..4], &0u32.to_le_bytes());
    }

    // ─── LsaUnicodeStringBuffer round-trip ──────────────────────────────

    #[test]
    fn test_unicode_string_buffer_roundtrip() {
        let original = LsaUnicodeStringBuffer {
            chars: "SYSTEM".encode_utf16().collect(),
        };
        let mut cursor = Cursor::new(Vec::new());
        original.write_le(&mut cursor).unwrap();

        let data = cursor.into_inner();
        let mut read_cursor = Cursor::new(&data);
        let parsed = LsaUnicodeStringBuffer::read_le(&mut read_cursor).unwrap();
        assert_eq!(parsed.to_string_lossy(), "SYSTEM");
    }

    #[test]
    fn test_unicode_string_buffer_empty() {
        let original = LsaUnicodeStringBuffer { chars: vec![] };
        let mut cursor = Cursor::new(Vec::new());
        original.write_le(&mut cursor).unwrap();

        let data = cursor.into_inner();
        let mut read_cursor = Cursor::new(&data);
        let parsed = LsaUnicodeStringBuffer::read_le(&mut read_cursor).unwrap();
        assert_eq!(parsed.to_string_lossy(), "");
        assert!(parsed.chars.is_empty());
    }

    // ─── LsarLookupSidsOut deserialization ──────────────────────────────

    /// Helper: builds a synthetic LsarLookupSidsOut binary response.
    ///
    /// Contains 1 domain ("BUILTIN") and 1 translated name ("Administrators",
    /// type=Alias, domain_index=0), with STATUS_SUCCESS.
    fn build_lookup_response_single_name() -> Vec<u8> {
        let endian = binrw::endian::Endian::Little;
        let mut c = Cursor::new(Vec::new());

        // === Referenced domains pointer (non-null) ===
        NdrAlign::<u64>::from(REF_ID_UNIQUE_DEFAULT)
            .write_options(&mut c, endian, ())
            .unwrap();

        // === LSAPR_REFERENCED_DOMAIN_LIST ===
        // entries = 1
        NdrAlign::<u32>::from(1u32)
            .write_options(&mut c, endian, ())
            .unwrap();
        // domains array pointer
        NdrAlign::<u64>::from(REF_ID_UNIQUE_DEFAULT)
            .write_options(&mut c, endian, ())
            .unwrap();
        // max_entries = 1
        NdrAlign::<u32>::from(1u32)
            .write_options(&mut c, endian, ())
            .unwrap();

        // Domain array conformant max_count
        NdrAlign::<u64>::from(1u64)
            .write_options(&mut c, endian, ())
            .unwrap();

        // LSAPR_TRUST_INFORMATION[0] - fixed part
        let domain_name: Vec<u16> = "BUILTIN".encode_utf16().collect();
        let name_byte_len = (domain_name.len() * 2) as u16;
        // name_length
        NdrAlign::<u16, 4>::from(name_byte_len)
            .write_options(&mut c, endian, ())
            .unwrap();
        // name_max_length
        NdrAlign::<u16, 4>::from(name_byte_len)
            .write_options(&mut c, endian, ())
            .unwrap();
        // name_buffer ref_id
        NdrAlign::<u64>::from(REF_ID_UNIQUE_DEFAULT)
            .write_options(&mut c, endian, ())
            .unwrap();
        // domain_sid ref_id
        NdrAlign::<u64>::from(REF_ID_UNIQUE_DEFAULT)
            .write_options(&mut c, endian, ())
            .unwrap();

        // Deferred: domain name buffer
        let domain_buf = LsaUnicodeStringBuffer {
            chars: domain_name,
        };
        domain_buf.write_options(&mut c, endian, ()).unwrap();

        // Deferred: domain SID (S-1-5-32)
        let domain_sid = SID::from_str("S-1-5-32").unwrap();
        domain_sid.write_options(&mut c, endian, ()).unwrap();

        // === LSAPR_TRANSLATED_NAMES ===
        // entries = 1
        NdrAlign::<u32>::from(1u32)
            .write_options(&mut c, endian, ())
            .unwrap();
        // names array pointer
        NdrAlign::<u64>::from(REF_ID_UNIQUE_DEFAULT)
            .write_options(&mut c, endian, ())
            .unwrap();

        // Names array conformant max_count
        NdrAlign::<u64>::from(1u64)
            .write_options(&mut c, endian, ())
            .unwrap();

        // LSAPR_TRANSLATED_NAME[0] - fixed part
        let acct_name: Vec<u16> = "Administrators".encode_utf16().collect();
        let acct_byte_len = (acct_name.len() * 2) as u16;
        // use_type = Alias (4)
        NdrAlign::<SidNameUse, 4>::from(SidNameUse::Alias)
            .write_options(&mut c, endian, ())
            .unwrap();
        // name_length
        NdrAlign::<u16, 4>::from(acct_byte_len)
            .write_options(&mut c, endian, ())
            .unwrap();
        // name_max_length
        NdrAlign::<u16, 4>::from(acct_byte_len)
            .write_options(&mut c, endian, ())
            .unwrap();
        // name_buffer ref_id
        NdrAlign::<u64>::from(REF_ID_UNIQUE_DEFAULT)
            .write_options(&mut c, endian, ())
            .unwrap();
        // domain_index = 0
        NdrAlign::<i32, 4>::from(0i32)
            .write_options(&mut c, endian, ())
            .unwrap();

        // Deferred: account name buffer
        let acct_buf = LsaUnicodeStringBuffer { chars: acct_name };
        acct_buf.write_options(&mut c, endian, ()).unwrap();

        // === mapped_count ===
        NdrAlign::<u32>::from(1u32)
            .write_options(&mut c, endian, ())
            .unwrap();

        // === NTSTATUS ===
        NtStatus::SUCCESS.write_options(&mut c, endian, ()).unwrap();

        c.into_inner()
    }

    #[test]
    fn test_lookup_sids_out_parse_single_name() {
        let data = build_lookup_response_single_name();
        let mut cursor = Cursor::new(&data);
        let result = LsarLookupSidsOut::read_le(&mut cursor).unwrap();

        assert_eq!(result.status, NtStatus::SUCCESS);
        assert_eq!(result.mapped_count, 1);
        assert_eq!(result.domains.len(), 1);
        assert_eq!(result.domains[0].name.as_deref(), Some("BUILTIN"));
        assert_eq!(result.names.len(), 1);
        assert_eq!(result.names[0].use_type, SidNameUse::Alias);
        assert_eq!(result.names[0].name.as_deref(), Some("Administrators"));
        assert_eq!(result.names[0].domain_index, 0);
    }

    /// Helper: builds a response with no domains and no names (NONE_MAPPED).
    fn build_lookup_response_none_mapped() -> Vec<u8> {
        let endian = binrw::endian::Endian::Little;
        let mut c = Cursor::new(Vec::new());

        // Referenced domains pointer (null)
        NdrAlign::<u64>::from(NULL_PTR_REF_ID)
            .write_options(&mut c, endian, ())
            .unwrap();

        // LSAPR_TRANSLATED_NAMES: entries = 0
        NdrAlign::<u32>::from(0u32)
            .write_options(&mut c, endian, ())
            .unwrap();
        // names array pointer (null)
        NdrAlign::<u64>::from(NULL_PTR_REF_ID)
            .write_options(&mut c, endian, ())
            .unwrap();

        // mapped_count = 0
        NdrAlign::<u32>::from(0u32)
            .write_options(&mut c, endian, ())
            .unwrap();

        // NTSTATUS = NONE_MAPPED
        NtStatus::NONE_MAPPED
            .write_options(&mut c, endian, ())
            .unwrap();

        c.into_inner()
    }

    #[test]
    fn test_lookup_sids_out_parse_none_mapped() {
        let data = build_lookup_response_none_mapped();
        let mut cursor = Cursor::new(&data);
        let result = LsarLookupSidsOut::read_le(&mut cursor).unwrap();

        assert_eq!(result.status, NtStatus::NONE_MAPPED);
        assert_eq!(result.mapped_count, 0);
        assert!(result.domains.is_empty());
        assert!(result.names.is_empty());
    }

    /// Helper: builds a response with 2 domains and 2 names (one resolved, one Unknown).
    fn build_lookup_response_partial() -> Vec<u8> {
        let endian = binrw::endian::Endian::Little;
        let mut c = Cursor::new(Vec::new());

        // === Referenced domains (non-null, 2 domains) ===
        NdrAlign::<u64>::from(REF_ID_UNIQUE_DEFAULT)
            .write_options(&mut c, endian, ())
            .unwrap();

        // entries = 2
        NdrAlign::<u32>::from(2u32)
            .write_options(&mut c, endian, ())
            .unwrap();
        // domains array pointer
        NdrAlign::<u64>::from(REF_ID_UNIQUE_DEFAULT)
            .write_options(&mut c, endian, ())
            .unwrap();
        // max_entries = 2
        NdrAlign::<u32>::from(2u32)
            .write_options(&mut c, endian, ())
            .unwrap();

        // Domain array conformant max_count = 2
        NdrAlign::<u64>::from(2u64)
            .write_options(&mut c, endian, ())
            .unwrap();

        // Domain[0] "NT AUTHORITY" fixed part
        let d0_name: Vec<u16> = "NT AUTHORITY".encode_utf16().collect();
        let d0_len = (d0_name.len() * 2) as u16;
        NdrAlign::<u16, 4>::from(d0_len)
            .write_options(&mut c, endian, ())
            .unwrap();
        NdrAlign::<u16, 4>::from(d0_len)
            .write_options(&mut c, endian, ())
            .unwrap();
        NdrAlign::<u64>::from(REF_ID_UNIQUE_DEFAULT)
            .write_options(&mut c, endian, ())
            .unwrap();
        NdrAlign::<u64>::from(REF_ID_UNIQUE_DEFAULT)
            .write_options(&mut c, endian, ())
            .unwrap();

        // Domain[1] "MYDOM" fixed part
        let d1_name: Vec<u16> = "MYDOM".encode_utf16().collect();
        let d1_len = (d1_name.len() * 2) as u16;
        NdrAlign::<u16, 4>::from(d1_len)
            .write_options(&mut c, endian, ())
            .unwrap();
        NdrAlign::<u16, 4>::from(d1_len)
            .write_options(&mut c, endian, ())
            .unwrap();
        NdrAlign::<u64>::from(REF_ID_UNIQUE_DEFAULT)
            .write_options(&mut c, endian, ())
            .unwrap();
        NdrAlign::<u64>::from(REF_ID_UNIQUE_DEFAULT)
            .write_options(&mut c, endian, ())
            .unwrap();

        // Deferred: domain[0] name buffer + SID
        LsaUnicodeStringBuffer {
            chars: d0_name,
        }
        .write_options(&mut c, endian, ())
        .unwrap();
        SID::from_str("S-1-5-18")
            .unwrap()
            .write_options(&mut c, endian, ())
            .unwrap();

        // Deferred: domain[1] name buffer + SID
        LsaUnicodeStringBuffer {
            chars: d1_name,
        }
        .write_options(&mut c, endian, ())
        .unwrap();
        SID::from_str("S-1-5-21-100-200-300")
            .unwrap()
            .write_options(&mut c, endian, ())
            .unwrap();

        // === LSAPR_TRANSLATED_NAMES (2 entries) ===
        NdrAlign::<u32>::from(2u32)
            .write_options(&mut c, endian, ())
            .unwrap();
        NdrAlign::<u64>::from(REF_ID_UNIQUE_DEFAULT)
            .write_options(&mut c, endian, ())
            .unwrap();

        // max_count = 2
        NdrAlign::<u64>::from(2u64)
            .write_options(&mut c, endian, ())
            .unwrap();

        // Name[0]: "SYSTEM", WellKnownGroup, domain_index=0
        let n0: Vec<u16> = "SYSTEM".encode_utf16().collect();
        let n0_len = (n0.len() * 2) as u16;
        NdrAlign::<SidNameUse, 4>::from(SidNameUse::WellKnownGroup)
            .write_options(&mut c, endian, ())
            .unwrap();
        NdrAlign::<u16, 4>::from(n0_len)
            .write_options(&mut c, endian, ())
            .unwrap();
        NdrAlign::<u16, 4>::from(n0_len)
            .write_options(&mut c, endian, ())
            .unwrap();
        NdrAlign::<u64>::from(REF_ID_UNIQUE_DEFAULT)
            .write_options(&mut c, endian, ())
            .unwrap();
        NdrAlign::<i32, 4>::from(0i32)
            .write_options(&mut c, endian, ())
            .unwrap();

        // Name[1]: Unknown, null name, domain_index=-1
        NdrAlign::<SidNameUse, 4>::from(SidNameUse::Unknown)
            .write_options(&mut c, endian, ())
            .unwrap();
        NdrAlign::<u16, 4>::from(0u16)
            .write_options(&mut c, endian, ())
            .unwrap();
        NdrAlign::<u16, 4>::from(0u16)
            .write_options(&mut c, endian, ())
            .unwrap();
        NdrAlign::<u64>::from(NULL_PTR_REF_ID)
            .write_options(&mut c, endian, ())
            .unwrap();
        NdrAlign::<i32, 4>::from(-1i32)
            .write_options(&mut c, endian, ())
            .unwrap();

        // Deferred: name[0] buffer
        LsaUnicodeStringBuffer { chars: n0 }
            .write_options(&mut c, endian, ())
            .unwrap();
        // name[1] has null ref_id, no deferred data

        // mapped_count = 1
        NdrAlign::<u32>::from(1u32)
            .write_options(&mut c, endian, ())
            .unwrap();

        // STATUS_SOME_NOT_MAPPED
        NtStatus::SOME_NOT_MAPPED
            .write_options(&mut c, endian, ())
            .unwrap();

        c.into_inner()
    }

    #[test]
    fn test_lookup_sids_out_parse_partial() {
        let data = build_lookup_response_partial();
        let mut cursor = Cursor::new(&data);
        let result = LsarLookupSidsOut::read_le(&mut cursor).unwrap();

        assert_eq!(result.status, NtStatus::SOME_NOT_MAPPED);
        assert_eq!(result.mapped_count, 1);

        // 2 domains
        assert_eq!(result.domains.len(), 2);
        assert_eq!(result.domains[0].name.as_deref(), Some("NT AUTHORITY"));
        assert_eq!(result.domains[1].name.as_deref(), Some("MYDOM"));

        // 2 names, one resolved, one Unknown
        assert_eq!(result.names.len(), 2);
        assert_eq!(result.names[0].use_type, SidNameUse::WellKnownGroup);
        assert_eq!(result.names[0].name.as_deref(), Some("SYSTEM"));
        assert_eq!(result.names[0].domain_index, 0);

        assert_eq!(result.names[1].use_type, SidNameUse::Unknown);
        assert!(result.names[1].name.is_none());
        assert_eq!(result.names[1].domain_index, -1);
    }

    // ─── LsarOpenPolicy2In serialization ────────────────────────────────

    #[test]
    fn test_open_policy2_in_serializes() {
        let input = LsarOpenPolicy2In {
            system_name: NdrPtr::from(r"\\SRV".parse::<NdrString<u16>>().unwrap()).into(),
            object_attributes_length: 24u32.into(),
            object_attributes_root_dir: NdrPtr::from(None).into(),
            object_attributes_object_name: NdrPtr::from(None).into(),
            object_attributes_attributes: 0u32.into(),
            object_attributes_security_descriptor: NdrPtr::from(None).into(),
            object_attributes_security_qos: NdrPtr::from(None).into(),
            desired_access: PolicyAccessMask::LOOKUP_NAMES.into(),
        };
        let serialized = input.serialize();
        // Must not be empty; basic sanity
        assert!(serialized.len() > 20);
        // Desired access POLICY_LOOKUP_NAMES (0x800) should appear near the end
        let last_4 = &serialized[serialized.len() - 4..];
        assert_eq!(last_4, &0x00000800u32.to_le_bytes());
    }

    // ─── LsarLookupSidsIn serialization ─────────────────────────────────

    #[test]
    fn test_lookup_sids_in_serializes_with_sid() {
        let handle = make_test_handle();
        let sid = SID::from_str("S-1-5-32-544").unwrap(); // Administrators
        let input = LsarLookupSidsIn {
            policy_handle: handle.clone(),
            sid_enum_buffer: LsaSidEnumBuffer {
                sids: vec![sid.clone()],
            }
            .into(),
            translated_names_entries: 0u32.into(),
            translated_names_names: NdrPtr::from(None).into(),
            lookup_level: LsaLookupLevel::LsapLookupWksta.into(),
            mapped_count: 0u32.into(),
        };
        let serialized = input.serialize();

        // Handle bytes should appear at the start
        assert_eq!(&serialized[0..4], &0u32.to_le_bytes()); // attributes
        assert_eq!(
            &serialized[4..20],
            &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
        );

        // SID data should be present somewhere in the serialized bytes.
        // S-1-5-32-544 has sub_authority [32, 544], authority=5
        // In binary: revision=1, count=2, authority=000000000005 (big-endian), sub=[32, 544]
        let sid_bytes = {
            let mut c = Cursor::new(Vec::new());
            sid.write_le(&mut c).unwrap();
            c.into_inner()
        };
        // SID data must appear in serialized output
        let found = serialized
            .windows(sid_bytes.len())
            .any(|w| w == sid_bytes.as_slice());
        assert!(found, "SID bytes not found in serialized output");
    }

    // ─── SidNameUse round-trip ──────────────────────────────────────────

    #[test]
    fn test_sid_name_use_roundtrip() {
        let variants = [
            (SidNameUse::User, 1u16),
            (SidNameUse::Group, 2),
            (SidNameUse::Domain, 3),
            (SidNameUse::Alias, 4),
            (SidNameUse::WellKnownGroup, 5),
            (SidNameUse::DeletedAccount, 6),
            (SidNameUse::Invalid, 7),
            (SidNameUse::Unknown, 8),
            (SidNameUse::Computer, 9),
            (SidNameUse::Label, 10),
            (SidNameUse::LogonSession, 11),
        ];
        for (variant, expected_val) in variants {
            let mut cursor = Cursor::new(Vec::new());
            variant.write_le(&mut cursor).unwrap();
            let bytes = cursor.into_inner();
            assert_eq!(bytes, expected_val.to_le_bytes());

            let mut read_cursor = Cursor::new(&bytes);
            let parsed = SidNameUse::read_le(&mut read_cursor).unwrap();
            assert_eq!(parsed, variant);
        }
    }

    // ─── PolicyAccessMask ───────────────────────────────────────────────

    #[test]
    fn test_policy_access_mask_lookup_names() {
        assert_eq!(PolicyAccessMask::LOOKUP_NAMES.0, 0x00000800);
        let mut cursor = Cursor::new(Vec::new());
        PolicyAccessMask::LOOKUP_NAMES.write_le(&mut cursor).unwrap();
        assert_eq!(cursor.into_inner(), vec![0x00, 0x08, 0x00, 0x00]);
    }
}
