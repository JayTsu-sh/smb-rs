//! Conformance test: SMB 3.0.2 + `signing_required = true`.
//!
//! Locks the "dialect doesn't support preauth integrity" branch of
//! the transformer's preauth-hash plumbing. SMB 3.0.2 negotiates
//! without a Negotiate context list, so:
//!
//! - `PreauthHashState` stays `Unsupported` on the connection,
//! - `Transformer::transform_outgoing` / `transform_incoming`'s
//!   auto-ingest is a noop (the `Unsupported.next(_)` branch),
//! - `snapshot_preauth_finalized` returns `Ok(None)`,
//! - `ChannelInfo::new` derives the SigningKey using the static
//!   `SmbSign\0` context (the `preauth_hash = None` branch in
//!   `SessionAlgosFactory::smb3xx_make_signer`).
//!
//! But MS-SMB2 §3.3.5.5.3's "non-anonymous SMB 3.x SessionSetup
//! final Request must be signed" rule applies independently of the
//! preauth-integrity feature. The driver must still produce a
//! signed final Request — this test asserts that exactly.

#[path = "conformance/mod.rs"]
mod conformance;

use bytes::Bytes;
use conformance::transcripts::{
    negotiate_response_smb302_signing_required, session_setup_response_final,
    session_setup_response_intermediate,
};
use conformance::{MockGss, MockTransport, ScriptedGssStep, assert_signed_final_session_setup};
use smb::{Connection, ConnectionConfig};
use smb_dtyp::Guid;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn smb302_signing_required_signs_final_session_setup() {
    const SESSION_ID: u64 = 0x0000_0302_8000_000A;

    let (transport, control) = MockTransport::new();
    control.push_server_frame(negotiate_response_smb302_signing_required());
    control.push_server_frame(session_setup_response_intermediate(SESSION_ID));
    control.push_server_frame(session_setup_response_final(SESSION_ID));

    let mut config = ConnectionConfig::default();
    config.smb2_only_negotiate = true;
    config.timeout = Some(std::time::Duration::from_secs(5));
    let conn = Connection::from_transport(transport, "smb302.test", Guid::generate(), config)
        .await
        .expect("Negotiate must succeed against SMB 3.0.2 mock server");

    let gss = MockGss::new(
        "bob",
        Some("EXAMPLE"),
        [0x22; 16],
        vec![
            ScriptedGssStep {
                client_token: b"<scripted-ntlm-type1-smb302>".to_vec(),
                completes_auth: false,
            },
            ScriptedGssStep {
                client_token: b"<scripted-ntlm-type3-smb302>".to_vec(),
                completes_auth: true,
            },
        ],
    );

    // The mock server's final SessionSetup Response is unsigned, so
    // the driver rejects it with SetupError::UnsignedFinalResponse —
    // same flow as the windows-dc test. We capture but don't fail on
    // this; the real assertion is on the client-emitted frames.
    let auth_result = conn.authenticate_with_gss(gss).await;
    match &auth_result {
        Err(smb::Error::Setup(smb::error::SetupError::UnsignedFinalResponse)) => {}
        Err(other) => panic!(
            "expected SetupError::UnsignedFinalResponse against the mock unsigned reply, got: {other}"
        ),
        Ok(_) => panic!(
            "authenticate_with_gss unexpectedly succeeded — the mock server's final response is unsigned"
        ),
    }

    // worker.send() returns once the message is queued on the worker's
    // send channel, before the worker task issues send_raw — wait for
    // the wire-side effect explicitly to avoid races with the
    // pre-queued mock responses. See `TranscriptControl::wait_for_captured_frames`.
    assert!(
        control
            .wait_for_captured_frames(3, std::time::Duration::from_secs(2))
            .await,
        "timed out waiting for 3 client frames; got {}",
        control.client_frame_count()
    );
    let frames = control.captured_client_frames();
    drop(conn);

    assert!(
        frames.len() >= 3,
        "expected at least 3 client frames (Negotiate + 2× SessionSetup), got {}",
        frames.len()
    );

    // Frame #2 is the final SessionSetup Request (NTLM Type3). Per
    // MS-SMB2 §3.3.5.5.3 it must be signed even though SMB 3.0.2
    // doesn't fold the request into a preauth hash.
    let req2: &Bytes = &frames[2];
    assert_signed_final_session_setup(req2, 2);
}
