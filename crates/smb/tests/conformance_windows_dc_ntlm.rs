//! Conformance test: Windows DC + SMB 3.1.1 + `signing_required=true`.
//!
//! Locks the fix shipped in **S3b-minimal**: the final SessionSetup
//! Request on a non-anonymous SMB 3.x session **MUST** be signed
//! (MS-SMB2 §3.3.5.5.3). Regressing on this property would re-introduce
//! the 10-second silent-drop bug against Windows AD domain controllers
//! and any other server with `signing_required = true`.
//!
//! ## What the assertion covers
//!
//! Only the *client*'s wire bytes for the final SessionSetup Request:
//! `header.flags.signed = true` and a non-zero `signature`. Everything
//! the server does (verify the signature, send a signed response, etc.)
//! is **out of scope** — this is a unit-style regression test on the
//! driver, not an end-to-end protocol test.
//!
//! ## Why `authenticate_with_gss` is allowed to return Err
//!
//! The mock server's final SessionSetup Response is deliberately
//! emitted unsigned, because [`MockGss`] does not derive a real MAC
//! key. The production driver therefore correctly rejects it with
//! `"Expected a signed message!"` after the client has already put
//! all three request frames on the wire. We swallow that Err on
//! purpose; if it ever changes to `Ok`, that's a separate signal
//! worth investigating (probably means the server-verify path got
//! disabled by accident), but it does not invalidate the client-side
//! property under test.

#[path = "conformance/mod.rs"]
mod conformance;

use bytes::Bytes;
use conformance::transcripts::{
    negotiate_response_windows_dc, session_setup_response_final,
    session_setup_response_intermediate,
};
use conformance::{
    MockGss, MockTransport, ScriptedGssStep, assert_signed_final_session_setup,
};
use smb::{Connection, ConnectionConfig};
use smb_dtyp::Guid;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn windows_dc_signing_required_signs_final_session_setup() {
    const SESSION_ID: u64 = 0x0029_4cb6_8000_0009;

    // -- 1. Set up the mock and queue the scripted server frames. --
    let (transport, control) = MockTransport::new();
    control.push_server_frame(negotiate_response_windows_dc());
    control.push_server_frame(session_setup_response_intermediate(SESSION_ID));
    control.push_server_frame(session_setup_response_final(SESSION_ID));

    // -- 2. Drive Negotiate via the production Connection path. --
    let mut config = ConnectionConfig::default();
    // smb2_only_negotiate skips the optional SMB1 multi-protocol probe
    // (one fewer scripted frame to write) — same as the production
    // configuration that triggered the user's bug report.
    config.smb2_only_negotiate = true;
    config.timeout = Some(std::time::Duration::from_secs(5));
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

    // The mock server's final SessionSetup Response carries an unsigned
    // success status, which the production driver rejects with
    // `Expected a signed message!` — that's *correct* behaviour and
    // independent of the client-side bug we're asserting below. We
    // capture but don't fail on this Err; the real assertion is on the
    // client-emitted frames.
    if let Err(e) = &auth_result {
        eprintln!(
            "authenticate_with_gss returned Err (expected for now — the test asserts \
             a separate property below): {e}"
        );
    }

    // -- 4. Inspect what the client put on the wire. --
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
    //   #2 = SessionSetup Request #2 (NTLM Type3)       (MUST be signed)
    let req2: &Bytes = &frames[2];
    assert_signed_final_session_setup(req2, 2);
}
