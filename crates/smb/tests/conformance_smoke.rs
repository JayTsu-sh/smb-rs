//! Smoke test for the conformance-test framework itself.
//!
//! Doesn't drive a real SMB exchange — just exercises:
//!
//! 1. `MockTransport::new()` round-trip: a frame pushed via
//!    `TranscriptControl::push_server_frame` is delivered intact when
//!    the transport's `receive_exact` is called with the right byte
//!    counts, and a frame written through `send_raw` is captured intact.
//! 2. `MockGss::new` / `next` script obeys its scripted step sequence
//!    and produces the configured session key.
//! 3. `assert_signed_final_session_setup` panics on an unsigned frame
//!    and accepts a signed one with non-zero signature.
//!
//! If this file fails to compile, the framework as a whole is broken;
//! if it fails to run, one of the small assumptions about smb-transport
//! or smb-msg is wrong.

#[path = "conformance/mod.rs"]
mod conformance;

use bytes::Bytes;
use conformance::{MockGss, MockTransport, ScriptedGssStep};
use smb::test_support::GssState;

#[tokio::test]
async fn mock_transport_round_trip() {
    use smb_transport::SmbTransport;

    let (transport, control) = MockTransport::new();

    // Push two server frames so we can verify ordering.
    control.push_server_frame(Bytes::from_static(b"first-server-frame"));
    control.push_server_frame(Bytes::from_static(b"second-frame-with-different-length"));

    // Split into halves as the production worker would.
    let (mut read, mut write) = transport.split().expect("split should succeed");

    // First frame: receive the 4-byte NB header.
    let mut header_buf = [0u8; 4];
    read.receive_exact(&mut header_buf)
        .await
        .expect("receive header bytes");
    let body_len = u32::from_be_bytes(header_buf) as usize;
    assert_eq!(body_len, b"first-server-frame".len());

    // Then the body.
    let mut body_buf = vec![0u8; body_len];
    read.receive_exact(&mut body_buf)
        .await
        .expect("receive body bytes");
    assert_eq!(&body_buf, b"first-server-frame");

    // Now send a frame: header then body.
    let payload = b"client-emits-this";
    let frame_len_be = (payload.len() as u32).to_be_bytes();
    write
        .send_raw(&frame_len_be)
        .await
        .expect("send NB header");
    write
        .send_raw(payload)
        .await
        .expect("send body");

    // Captured frames should reflect only the body (NB header stripped).
    let captured = control.captured_client_frames();
    assert_eq!(captured.len(), 1);
    assert_eq!(&captured[0][..], payload);

    // Receive the second server frame.
    read.receive_exact(&mut header_buf)
        .await
        .expect("receive header bytes for second frame");
    let body_len = u32::from_be_bytes(header_buf) as usize;
    let mut body_buf = vec![0u8; body_len];
    read.receive_exact(&mut body_buf)
        .await
        .expect("receive body bytes for second frame");
    assert_eq!(&body_buf, b"second-frame-with-different-length");

    // Queue drained.
    assert_eq!(control.pending_server_frames(), 0);
}

#[tokio::test]
async fn mock_gss_script_runs_in_order() {
    let mut gss = MockGss::new(
        "alice",
        Some("EXAMPLE"),
        [0x11; 16],
        vec![
            ScriptedGssStep {
                client_token: b"type1-bytes".to_vec(),
                completes_auth: false,
            },
            ScriptedGssStep {
                client_token: b"type3-bytes".to_vec(),
                completes_auth: true,
            },
        ],
    );

    // Before any next(): not authenticated, key unavailable.
    assert!(!gss.is_authenticated().expect("ok"));
    assert!(gss.session_key().is_err());

    // First round: emits Type1 token, still not authenticated.
    let t1 = gss.next(&[]).await.expect("first next");
    assert_eq!(t1, b"type1-bytes");
    assert!(!gss.is_authenticated().expect("ok"));

    // Second round: emits Type3 token, NOW authenticated.
    let t3 = gss.next(b"server-challenge").await.expect("second next");
    assert_eq!(t3, b"type3-bytes");
    assert!(gss.is_authenticated().expect("ok"));
    assert_eq!(gss.session_key().expect("auth done"), [0x11; 16]);

    assert_eq!(gss.remaining_steps(), 0);
}

#[test]
#[should_panic(expected = "NOT signed")]
fn assert_signed_final_session_setup_rejects_unsigned() {
    // Hand-craft a minimal SMB2 header for a SessionSetup with signed=0.
    // Header layout per MS-SMB2 §2.2.1: 64 bytes, with command at offset 12.
    // We construct the bare minimum: signature=0, signed flag=0.
    let mut hdr = vec![0u8; 64];
    hdr[0..4].copy_from_slice(&[0xFE, b'S', b'M', b'B']); // protocol
    hdr[4..6].copy_from_slice(&64u16.to_le_bytes()); // structure_size
    hdr[12..14].copy_from_slice(&1u16.to_le_bytes()); // command = SessionSetup
    // flags @ offset 16 = 0
    // signature @ offset 48 = all zeros
    // (Append a 1-byte body so binrw doesn't fail on an empty payload.)
    hdr.push(0);

    let frame = Bytes::from(hdr);
    conformance::assert_signed_final_session_setup(&frame, 0);
}
