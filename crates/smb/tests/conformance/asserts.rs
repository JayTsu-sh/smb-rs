//! Assertion helpers that decode captured client frames from the
//! [`MockTransport`] into structured SMB views suitable for `assert!`s
//! at the protocol level.
//!
//! Each helper reads from a raw `Bytes` frame (SMB body without the
//! 4-byte NetBIOS prefix — that's what [`TranscriptControl::captured_client_frames`]
//! returns) and panics with a helpful message when the input doesn't
//! look like the kind of frame expected.

use bytes::Bytes;
use smb_msg::{Command, Header};

/// Decoded view of an outbound client frame's SMB2 header.
///
/// Cheap to construct from raw bytes; covers the small subset of
/// fields conformance tests typically assert on.
#[derive(Debug, Clone)]
pub struct ClientFrameHeader {
    pub command: Command,
    pub credit_charge: u16,
    pub message_id: u64,
    pub tree_id: Option<u32>,
    pub session_id: u64,
    pub signature: u128,
    pub signed_flag: bool,
}

impl ClientFrameHeader {
    /// Parse the leading SMB2 header out of an outbound client frame.
    ///
    /// Returns `None` if the frame is too short to contain a header or
    /// the parse fails for any reason — callers usually `.expect()` it
    /// since at the conformance-test layer parse failure is itself a
    /// regression worth surfacing loudly.
    pub fn try_parse(frame: &Bytes) -> Option<Self> {
        use binrw::BinRead;
        use std::io::Cursor;

        let mut cur = Cursor::new(frame.as_ref());
        let header = Header::read(&mut cur).ok()?;
        Some(Self {
            command: header.command,
            credit_charge: header.credit_charge,
            message_id: header.message_id,
            tree_id: header.tree_id,
            session_id: header.session_id,
            signature: header.signature,
            signed_flag: header.flags.signed(),
        })
    }

    /// Convenience: parse-or-panic with the frame index in the message
    /// so failures point at the offending frame.
    pub fn parse_frame(frame: &Bytes, frame_idx: usize) -> Self {
        Self::try_parse(frame).unwrap_or_else(|| {
            panic!(
                "Failed to parse SMB2 header from client frame #{frame_idx} \
                 ({} bytes): {:02x?}",
                frame.len(),
                &frame[..frame.len().min(64)]
            )
        })
    }
}

/// Assert that a frame is a signed final SessionSetup Request — the
/// linchpin protocol property that today's Windows-DC bug violates.
///
/// Specifically (per MS-SMB2 §3.3.5.5.3): when a non-anonymous SMB 3.x
/// session is being established, the *final* SessionSetup Request
/// (i.e. the one carrying NTLM Type3 or the Kerberos AP_REQ that
/// completes auth) must:
///
/// 1. carry `command == SessionSetup`
/// 2. set `header.flags.signed = true`
/// 3. have a non-zero `signature`
///
/// Failing any of these is the signature of the silent-drop bug on
/// Windows DCs (and any other server with `signing_required = true`).
pub fn assert_signed_final_session_setup(frame: &Bytes, frame_idx: usize) {
    let h = ClientFrameHeader::parse_frame(frame, frame_idx);
    assert_eq!(
        h.command,
        Command::SessionSetup,
        "frame #{frame_idx} expected to be SessionSetup, got {:?}",
        h.command
    );
    assert!(
        h.signed_flag,
        "frame #{frame_idx} (final SessionSetup) is NOT signed (flags.signed=false) — \
         this is the Windows-DC bug: per MS-SMB2 §3.3.5.5.3 the final \
         SessionSetup Request must be signed"
    );
    assert_ne!(
        h.signature, 0,
        "frame #{frame_idx} (final SessionSetup) has zero signature — signing flag \
         is set but transformer didn't compute a real signature"
    );
}

/// Assert that a frame is an *intermediate* SessionSetup Request: a
/// SessionSetup that is **not** the final one in the GSS exchange.
/// These are typically unsigned (session keys not yet derived).
pub fn assert_intermediate_session_setup(frame: &Bytes, frame_idx: usize) {
    let h = ClientFrameHeader::parse_frame(frame, frame_idx);
    assert_eq!(
        h.command,
        Command::SessionSetup,
        "frame #{frame_idx} expected to be SessionSetup, got {:?}",
        h.command
    );
}
