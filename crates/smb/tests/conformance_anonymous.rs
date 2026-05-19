//! Conformance test: anonymous session + SMB 3.1.1 + signing optional.
//!
//! Covers the spec branch that lets the driver accept an **unsigned**
//! final SessionSetup Response when the resulting session is
//! anonymous (`session_flags.is_null_session = true`). MS-SMB2
//! §3.2.5.3.1: no SessionKey is derived for an anonymous bind, so the
//! server has no signing material; the client must *not* fall through
//! to `SetupError::UnsignedFinalResponse` in this case.
//!
//! This locks the negation of the Windows-DC regression — the same
//! "unsigned final response" wire pattern that's an error there is
//! the *expected* outcome here. The driver's `is_guest_or_null_session`
//! short-circuit must keep working.

#[path = "conformance/mod.rs"]
mod conformance;

use conformance::transcripts::{
    negotiate_response_signing_optional, session_setup_response_final_anonymous,
    session_setup_response_intermediate,
};
use conformance::{MockGss, MockTransport, ScriptedGssStep};
use smb::{Connection, ConnectionConfig};
use smb_dtyp::Guid;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn anonymous_session_accepts_unsigned_final_response() {
    const SESSION_ID: u64 = 0x0000_1234_5678_9abc;

    let (transport, control) = MockTransport::new();
    control.push_server_frame(negotiate_response_signing_optional());
    control.push_server_frame(session_setup_response_intermediate(SESSION_ID));
    control.push_server_frame(session_setup_response_final_anonymous(SESSION_ID));

    let mut config = ConnectionConfig::default();
    config.smb2_only_negotiate = true;
    config.timeout = Some(std::time::Duration::from_secs(5));
    // Anonymous sessions must be permitted by config or the driver
    // rejects the success reply outright (state.rs::ready check).
    config.allow_unsigned_guest_access = true;
    let conn = Connection::from_transport(transport, "samba-anon.test", Guid::generate(), config)
        .await
        .expect("Negotiate must succeed");

    // Scripted GSS mirrors the windows-dc test but the resulting
    // session is flagged anonymous by the server, so the final
    // response — unsigned — is accepted on the spec's anonymous path.
    let gss = MockGss::new(
        "anonymous",
        None,
        [0x00; 16],
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

    let result = conn.authenticate_with_gss(gss).await;

    // Drop the connection now to make any future drop bug surface in
    // this test rather than in the windows-dc one.
    drop(conn);

    // Driver must accept the unsigned response because the session is
    // anonymous. If it instead returned `SetupError::UnsignedFinalResponse`,
    // the windows-dc regression got over-broad.
    let session = result.expect(
        "anonymous session: unsigned final SessionSetup Response is spec-valid; \
         driver must not return SetupError::UnsignedFinalResponse here",
    );

    // session_id should match what the mock server advertised.
    assert_eq!(session.session_id(), SESSION_ID);

    // Don't hold the session into Drop: same MockTransport-deadlock
    // concern as the windows-dc test.
    std::mem::forget(session);
}
