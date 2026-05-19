//! Hand-built server-frame factories for transcript-replay tests.
//!
//! Each helper returns the raw SMB body bytes (no NetBIOS 4-byte length
//! prefix — that's added inside [`MockTransport`]) of a single server
//! response. Tests push them into [`TranscriptControl::push_server_frame`]
//! in the order the production driver will read them.
//!
//! These factories use the production `smb-msg` serializer rather than
//! manually emitting hex, so any future on-wire field-layout change in
//! `smb-msg` cannot drift this test fixture out of sync.

use binrw::prelude::*;
use bytes::Bytes;
use smb_dtyp::Guid;
use smb_dtyp::binrw_util::file_time::FileTime;
use smb_msg::{
    EncryptionCapabilities, EncryptionCipher, GlobalCapabilities, HashAlgorithm, HeaderFlags,
    NegotiateContext, NegotiateDialect, NegotiateResponse, NegotiateSecurityMode, PlainResponse,
    PreauthIntegrityCapabilities, ResponseContent, SessionFlags, SessionSetupResponse,
    SigningAlgorithmId, SigningCapabilities, Status,
};
use std::io::Cursor;

/// Helper: serialize any `PlainResponse` to a `Bytes` body (signature=0,
/// signed flag=0 — server responses in conformance tests are unsigned
/// because the simplest mock GSS doesn't derive matching signing keys).
fn encode(resp: PlainResponse) -> Bytes {
    let mut buf = Vec::with_capacity(256);
    resp.write(&mut Cursor::new(&mut buf))
        .expect("BinWrite never fails for hand-built PlainResponse");
    Bytes::from(buf)
}

/// Build the NegotiateResponse the test "Windows DC" server emits.
///
/// Models a Windows Server 2022 domain controller behaviour:
/// - SMB 3.1.1 selected
/// - `signing_required = true` (this is the trigger for today's bug)
/// - PreauthIntegrityCapabilities (mandatory at 3.1.1)
/// - EncryptionCapabilities advertising AES-128-CCM
/// - SigningCapabilities advertising HMAC-SHA256
/// - `caps.encryption = false` (DCs typically don't push transport
///   encryption on top of session-level signing — matches the real DC
///   capture this test was derived from).
pub fn negotiate_response_windows_dc() -> Bytes {
    let content = NegotiateResponse {
        security_mode: NegotiateSecurityMode::new()
            .with_signing_enabled(true)
            .with_signing_required(true),
        dialect_revision: NegotiateDialect::Smb0311,
        server_guid: Guid::from([
            0x7c, 0x67, 0xc9, 0xee, 0x0e, 0xc8, 0x0b, 0x41, 0xb7, 0xfe, 0x5b, 0xb7, 0xc4, 0xb0,
            0x9c, 0xee,
        ]),
        capabilities: GlobalCapabilities::new()
            .with_dfs(true)
            .with_leasing(true)
            .with_large_mtu(true)
            .with_directory_leasing(true),
        max_transact_size: 8 * 1024 * 1024,
        max_read_size: 8 * 1024 * 1024,
        max_write_size: 8 * 1024 * 1024,
        system_time: FileTime::default(),
        server_start_time: FileTime::default(),
        // The GSSAPI buffer in NEGOTIATE response normally carries a SPNEGO
        // mech-list (selecting NTLM/Kerberos). The production client only
        // forwards whatever bytes are here to sspi for the *first* GSS
        // round — and our MockGss ignores the input. So any plausible-
        // looking byte sequence is fine.
        buffer: vec![0x60, 0x18, 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02],
        negotiate_context_list: Some(vec![
            negotiate_ctx_preauth(),
            negotiate_ctx_encryption(),
            negotiate_ctx_signing(),
        ]),
    };
    encode(make_response(ResponseContent::Negotiate(content), 0, Status::Success))
}

fn negotiate_ctx_preauth() -> NegotiateContext {
    PreauthIntegrityCapabilities {
        hash_algorithms: vec![HashAlgorithm::Sha512],
        // 32-byte salt — actual bytes do not matter for the test because
        // MockGss bypasses the real key derivation.
        salt: vec![0xa7; 32],
    }
    .into()
}

fn negotiate_ctx_encryption() -> NegotiateContext {
    EncryptionCapabilities {
        ciphers: vec![EncryptionCipher::Aes128Ccm],
    }
    .into()
}

fn negotiate_ctx_signing() -> NegotiateContext {
    SigningCapabilities {
        signing_algorithms: vec![SigningAlgorithmId::HmacSha256],
    }
    .into()
}

/// Build the SessionSetup Response #1 (intermediate round) carrying an
/// NTLM Type2-shaped GSS challenge.
///
/// Status: `STATUS_MORE_PROCESSING_REQUIRED` — server signals the
/// client to continue the GSS exchange.
pub fn session_setup_response_intermediate(session_id: u64) -> Bytes {
    let content = SessionSetupResponse {
        session_flags: SessionFlags::new(),
        // Bytes ignored by MockGss; we use a recognisable prefix for
        // wireshark-style debugging if the test ever drops into a
        // packet trace.
        buffer: b"<scripted-ntlm-type2-challenge>".to_vec(),
    };
    encode(make_response_with_session(
        ResponseContent::SessionSetup(content),
        1,
        Status::MoreProcessingRequired,
        session_id,
    ))
}

/// Build the SessionSetup Response #2 (final round) reporting success.
///
/// Note: in real life the server signs this response. Our mock leaves
/// it unsigned because MockGss doesn't derive a matching signing key.
/// The production driver enforces that the *final* response on a
/// non-anonymous session is signed (setup.rs:159-170), so this test
/// hits that check and surfaces an error — which is fine: we inspect
/// the captured client frames *before* the error to verify whether
/// Request #2 itself was signed (the actual Windows-DC bug).
pub fn session_setup_response_final(session_id: u64) -> Bytes {
    let content = SessionSetupResponse {
        session_flags: SessionFlags::new(),
        buffer: vec![],
    };
    encode(make_response_with_session(
        ResponseContent::SessionSetup(content),
        2,
        Status::Success,
        session_id,
    ))
}

/// Build a SessionSetup Response #2 (final round) reporting success
/// **on an anonymous session** — `session_flags.is_null_session = true`.
///
/// MS-SMB2 §3.2.5.3.1 lets the driver accept an unsigned final
/// response in this case (no SessionKey is derived, so signing isn't
/// possible). Used by the `conformance_anonymous` test to verify that
/// the SessionSetup path doesn't over-eagerly reject the success
/// reply.
pub fn session_setup_response_final_anonymous(session_id: u64) -> Bytes {
    let content = SessionSetupResponse {
        session_flags: SessionFlags::new().with_is_null_session(true),
        buffer: vec![],
    };
    encode(make_response_with_session(
        ResponseContent::SessionSetup(content),
        2,
        Status::Success,
        session_id,
    ))
}

/// Variant of [`negotiate_response_windows_dc`] modeling a permissive
/// server: signing is *enabled* but **not required**. Identical
/// dialect / capability shape otherwise. Used by the anonymous-session
/// test where the client must still send + sign per spec, but the
/// server policy doesn't force it.
pub fn negotiate_response_signing_optional() -> Bytes {
    let content = NegotiateResponse {
        security_mode: NegotiateSecurityMode::new().with_signing_enabled(true),
        // signing_required omitted (defaults false) — the difference
        // from `negotiate_response_windows_dc` is this single bit.
        dialect_revision: NegotiateDialect::Smb0311,
        server_guid: smb_dtyp::Guid::from([
            0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x40, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ]),
        capabilities: GlobalCapabilities::new()
            .with_dfs(true)
            .with_leasing(true)
            .with_large_mtu(true)
            .with_directory_leasing(true),
        max_transact_size: 8 * 1024 * 1024,
        max_read_size: 8 * 1024 * 1024,
        max_write_size: 8 * 1024 * 1024,
        system_time: smb_dtyp::binrw_util::file_time::FileTime::default(),
        server_start_time: smb_dtyp::binrw_util::file_time::FileTime::default(),
        buffer: vec![0x60, 0x18, 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02],
        negotiate_context_list: Some(vec![
            negotiate_ctx_preauth(),
            negotiate_ctx_encryption(),
            negotiate_ctx_signing(),
        ]),
    };
    encode(make_response(
        ResponseContent::Negotiate(content),
        0,
        Status::Success,
    ))
}

fn make_response(content: ResponseContent, message_id: u64, status: Status) -> PlainResponse {
    let mut resp = PlainResponse::new(content);
    // Only patch the fields that differ from the defaulted header
    // `PlainResponse::new` already gives us — credit_charge/request,
    // status, server_to_redir flag, and message_id. The rest
    // (`command`, `tree_id`, `session_id`, `signature`, etc.) are
    // either already correct or zero by default.
    resp.header.credit_charge = 1;
    resp.header.credit_request = 1;
    resp.header.status = status as u32;
    resp.header.flags = HeaderFlags::new().with_server_to_redir(true);
    resp.header.message_id = message_id;
    resp
}

fn make_response_with_session(
    content: ResponseContent,
    message_id: u64,
    status: Status,
    session_id: u64,
) -> PlainResponse {
    let mut resp = make_response(content, message_id, status);
    resp.header.session_id = session_id;
    resp
}
