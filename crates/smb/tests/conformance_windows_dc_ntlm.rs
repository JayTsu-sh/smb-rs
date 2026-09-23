//! Conformance test: Windows DC + SMB 3.1.1 with required signing.
//!
//! A new session sends an unsigned final SessionSetup continuation. The mock
//! final response is deliberately unsigned and must be rejected.

#[path = "conformance/mod.rs"]
mod conformance;

use bytes::Bytes;
use conformance::transcripts::{
    negotiate_response_signing_optional, negotiate_response_windows_dc,
    session_setup_response_final, session_setup_response_intermediate,
};
use conformance::{
    MockGss, ScriptedGssStep, ScriptedTransport, assert_negotiate_signing_policy,
    assert_session_setup_signing_policy, assert_unsigned_final_session_setup,
};
use smb::test_support::{Connection, ConnectionConfig};
use smb_dtyp::Guid;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn windows_dc_new_session_final_continuation_is_unsigned() {
    const SESSION_ID: u64 = 0x0029_4cb6_8000_0009;

    // -- 1. Set up the mock and queue the scripted server frames. --
    let (transport, control) = ScriptedTransport::new();
    control.push_server_frame(negotiate_response_windows_dc());
    control.push_server_frame(session_setup_response_intermediate(SESSION_ID));
    control.push_server_frame(session_setup_response_final(SESSION_ID));

    // -- 2. Drive Negotiate via the production Connection path. --
    // smb2_only_negotiate skips the optional SMB1 multi-protocol probe
    // (one fewer scripted frame to write) — same as the production
    // configuration that triggered the user's bug report.
    let config = ConnectionConfig {
        smb2_only_negotiate: true,
        timeout: Some(std::time::Duration::from_secs(5)),
        ..Default::default()
    };
    let conn = Connection::from_transport(transport, "windows-dc.test", Guid::generate(), config)
        .await
        .expect("Connection::from_transport (Negotiate) must succeed against scripted server");

    // -- 3. Drive SessionSetup with a mock NTLM-style 2-round GSS. --
    let gss = MockGss::new(
        "alice",
        Some("EXAMPLE"),
        [0x11; 16],
        vec![
            ScriptedGssStep {
                client_token: b"<scripted-ntlm-type1>".to_vec(),
                completes_auth: false,
            },
            ScriptedGssStep {
                client_token: b"<scripted-ntlm-type3>".to_vec(),
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

    // -- 4. Inspect what the client put on the wire. --
    //
    // The driver's `worker.send()` returns when the message is queued on
    // the worker's send channel, not when `send_raw` actually completes.
    // On a real wire the response cannot arrive before the request goes
    // out, so the test is naturally serialised; with ScriptedTransport's
    // pre-queued responses the two halves are decoupled, so we must
    // explicitly wait for the captured-frames side effect before
    // asserting on it. See `ScriptedTransportControl::wait_for_client_frames`.
    assert!(
        control
            .wait_for_client_frames(3, std::time::Duration::from_secs(2))
            .await,
        "timed out waiting for 3 client frames; got {}",
        control.client_frame_count()
    );
    let frames = control.captured_client_frames();
    drop(conn); // explicit: surfaces any future drop bug instead of leaking it
    assert!(
        frames.len() >= 3,
        "expected at least 3 client frames (Negotiate + 2× SessionSetup), got {}: \
         {:#?}",
        frames.len(),
        frames.iter().map(|f| f.len()).collect::<Vec<_>>()
    );

    // Frame indexing:
    //   #0 = Negotiate Request                          (never signed)
    //   #1 = SessionSetup Request #1 (NTLM Type1)       (unsigned)
    //   #2 = SessionSetup Request #2 (NTLM Type3)       (unsigned, SessionId set)
    let req2: &Bytes = &frames[2];
    assert_session_setup_signing_policy(&frames[1], true, true);
    assert_session_setup_signing_policy(req2, true, true);
    assert_unsigned_final_session_setup(req2, 2, SESSION_ID);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unsigned_non_guest_final_response_is_rejected_when_guest_access_is_allowed() {
    const SESSION_ID: u64 = 0x0029_4cb6_8000_0010;

    let (transport, control) = ScriptedTransport::new();
    control.push_server_frame(negotiate_response_windows_dc());
    control.push_server_frame(session_setup_response_intermediate(SESSION_ID));
    control.push_server_frame(session_setup_response_final(SESSION_ID));

    let config = ConnectionConfig {
        smb2_only_negotiate: true,
        timeout: Some(std::time::Duration::from_secs(5)),
        allow_unsigned_guest_access: true,
        ..Default::default()
    };
    let conn = Connection::from_transport(transport, "windows-dc.test", Guid::generate(), config)
        .await
        .expect("Negotiate must succeed against scripted server");
    let gss = MockGss::new(
        "alice",
        Some("EXAMPLE"),
        [0x11; 16],
        vec![
            ScriptedGssStep {
                client_token: b"<scripted-ntlm-type1>".to_vec(),
                completes_auth: false,
            },
            ScriptedGssStep {
                client_token: b"<scripted-ntlm-type3>".to_vec(),
                completes_auth: true,
            },
        ],
    );

    let auth_result = conn.authenticate_with_gss(gss).await;
    match auth_result {
        Err(smb::Error::Setup(smb::error::SetupError::UnsignedFinalResponse)) => {}
        Err(error) => panic!("an unsigned final response returned the wrong error: {error}"),
        Ok(_) => panic!(
            "allow_unsigned_guest_access must not admit an unsigned non-guest final response"
        ),
    }
    drop(conn);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_required_signing_is_advertised_to_optional_server() {
    const SESSION_ID: u64 = 0x0029_4cb6_8000_0011;

    let (transport, control) = ScriptedTransport::new();
    control.push_server_frame(negotiate_response_signing_optional());
    control.push_server_frame(session_setup_response_intermediate(SESSION_ID));
    control.push_server_frame(session_setup_response_final(SESSION_ID));
    let config = ConnectionConfig {
        smb2_only_negotiate: true,
        timeout: Some(std::time::Duration::from_secs(5)),
        signing_required: true,
        ..Default::default()
    };
    let conn =
        Connection::from_transport(transport, "optional-signing.test", Guid::generate(), config)
            .await
            .expect("Negotiate must succeed");
    let gss = MockGss::new(
        "alice",
        Some("EXAMPLE"),
        [0x44; 16],
        vec![
            ScriptedGssStep {
                client_token: b"<type1>".to_vec(),
                completes_auth: false,
            },
            ScriptedGssStep {
                client_token: b"<type3>".to_vec(),
                completes_auth: true,
            },
        ],
    );

    assert!(matches!(
        conn.authenticate_with_gss(gss).await,
        Err(smb::Error::Setup(
            smb::error::SetupError::UnsignedFinalResponse
        ))
    ));
    assert_negotiate_signing_policy(&control.captured_client_frames()[0], true);
    let frames = control.captured_client_frames();
    assert_session_setup_signing_policy(&frames[1], true, true);
    assert_session_setup_signing_policy(&frames[2], true, true);
    drop(conn);
}
