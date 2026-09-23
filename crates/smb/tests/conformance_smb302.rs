//! Conformance test: SMB 3.0.2 final SessionSetup continuation.
//!
//! Locks the "dialect doesn't support preauth integrity" branch of
//! the transformer's preauth-hash plumbing. SMB 3.0.2 negotiates
//! without a Negotiate context list, so:
//!
//! - `PreauthHashState` stays `Unsupported` on the connection,
//! - the runtime wire pipeline's outgoing/incoming transform path
//!   auto-ingest is a noop (the `Unsupported.next(_)` branch),
//! - `snapshot_preauth_finalized` returns `Ok(None)`,
//! - `ChannelInfo::new` derives the SigningKey using the static
//!   `SmbSign\0` context (the `preauth_hash = None` branch in
//!   `SessionAlgosFactory::smb3xx_make_signer`).
//!
//! A new SMB 3.0.2 session sends an unsigned final SessionSetup continuation.

#[path = "conformance/mod.rs"]
mod conformance;

use bytes::Bytes;
use conformance::transcripts::{
    negotiate_response_smb302_signing_required, session_setup_response_final,
    session_setup_response_intermediate,
};
use conformance::{
    MockGss, ScriptedGssStep, ScriptedTransport, assert_unsigned_final_session_setup,
};
use smb::test_support::{Connection, ConnectionConfig};
use smb_dtyp::Guid;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn smb302_new_session_final_continuation_is_unsigned() {
    const SESSION_ID: u64 = 0x0000_0302_8000_000A;

    let (transport, control) = ScriptedTransport::new();
    control.push_server_frame(negotiate_response_smb302_signing_required());
    control.push_server_frame(session_setup_response_intermediate(SESSION_ID));
    control.push_server_frame(session_setup_response_final(SESSION_ID));

    let config = ConnectionConfig {
        smb2_only_negotiate: true,
        timeout: Some(std::time::Duration::from_secs(5)),
        ..Default::default()
    };
    let conn = Connection::from_transport(transport, "smb302.test", Guid::generate(), config)
        .await
        .expect("Negotiate must succeed against SMB 3.0.2 mock server");

    assert!(conn.conn_info().unwrap().negotiation.signing_required);
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

    let auth_result = conn.authenticate_with_gss(gss).await;
    match auth_result {
        Err(smb::Error::Setup(smb::error::SetupError::UnsignedFinalResponse)) => {}
        Err(error) => panic!("an unsigned final response returned the wrong error: {error}"),
        Ok(_) => panic!("an unsigned final response must be rejected"),
    }

    // worker.send() returns once the message is queued on the worker's
    // send channel, before the worker task issues send_raw — wait for
    // the wire-side effect explicitly to avoid races with the
    // pre-queued scripted responses. See
    // `ScriptedTransportControl::wait_for_client_frames`.
    assert!(
        control
            .wait_for_client_frames(3, std::time::Duration::from_secs(2))
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

    // Frame #2 is the final SessionSetup Request (NTLM Type3). It carries
    // the SessionId supplied by the intermediate response and remains
    // unsigned until the channel is established.
    let req2: &Bytes = &frames[2];
    assert_unsigned_final_session_setup(req2, 2, SESSION_ID);
}
