use super::SigningPolicy;
use crate::Error;
use crate::connection::ConnectionConfig;
use crate::connection::connection_info::{ConnectionInfo, NegotiatedProperties};
use crate::connection::preauth_hash::PreauthHashState;
use crate::dialects::DialectImpl;
use crate::runtime::wire::{TransformError, TransformPhase, WirePipeline};
use crate::session::{ChannelInfo, SessionAndChannel, SessionInfo};
use binrw::BinWrite;
use bytes::Bytes;
use smb_dtyp::Guid;
use smb_msg::{
    Dialect, GlobalCapabilities, LogoffResponse, PlainResponse, ResponseContent, SessionFlags,
};
use std::{io::Cursor, sync::Arc};
use tokio::sync::RwLock;

fn connection(policy: SigningPolicy, server_required: bool) -> ConnectionInfo {
    ConnectionInfo {
        server_name: "signing.test".into(),
        server_address: "127.0.0.1:445".parse().unwrap(),
        negotiation: NegotiatedProperties {
            server_guid: Guid::generate(),
            signing_required: server_required,
            caps: GlobalCapabilities::new(),
            max_transact_size: 1048576,
            max_read_size: 1048576,
            max_write_size: 1048576,
            auth_buffer: vec![],
            signing_algo: None,
            encryption_cipher: None,
            compression: None,
            dialect_rev: Dialect::Smb0302,
        },
        dialect: DialectImpl::new(Dialect::Smb0302),
        config: ConnectionConfig {
            signing_policy: policy,
            ..Default::default()
        },
        preauth_hash: PreauthHashState::Unsupported,
        client_guid: Guid::generate(),
    }
}

#[test]
fn session_combines_client_policy_and_server_requirement() {
    assert_eq!(SigningPolicy::default(), SigningPolicy::Required);
    for (policy, server, unsigned) in [
        (SigningPolicy::Required, false, false),
        (SigningPolicy::Required, true, false),
        (SigningPolicy::WhenRequired, false, true),
        (SigningPolicy::WhenRequired, true, false),
    ] {
        let info = connection(policy, server);
        let mut session = SessionInfo::new(7);
        session.setup(&[0x42; 16], &None, &info).unwrap();
        // Optional bulk IO must not relax authentication setup checks.
        assert!(!session.allow_unsigned().unwrap());
        session.ready(SessionFlags::new(), &info).unwrap();
        assert_eq!(session.allow_unsigned().unwrap(), unsigned);
        assert!(!session.is_guest_or_anonymous().unwrap());
    }
}

#[test]
fn server_required_signing_cannot_be_bypassed_by_guest_option() {
    let mut info = connection(SigningPolicy::WhenRequired, true);
    info.config.allow_unsigned_guest_access = true;
    let mut session = SessionInfo::new(7);
    session.setup(&[0x42; 16], &None, &info).unwrap();
    assert!(
        session
            .ready(SessionFlags::new().with_is_guest(true), &info)
            .is_err()
    );
}

fn encoded(response: &PlainResponse) -> Bytes {
    let mut cursor = Cursor::new(Vec::new());
    response.header.write(&mut cursor).unwrap();
    cursor.get_mut().extend_from_slice(&[4, 0, 0, 0]);
    Bytes::from(cursor.into_inner())
}

#[tokio::test]
async fn optional_unsigned_response_needs_no_signer_but_signed_response_is_verified() {
    let info = Arc::new(connection(SigningPolicy::WhenRequired, false));
    let wire = WirePipeline::default();
    wire.negotiated(&info).await.unwrap();
    let mut response = PlainResponse::new(ResponseContent::Logoff(LogoffResponse {}));
    response.header.session_id = 7;
    response.header.message_id = 3;
    response.header.flags.set_server_to_redir(true);
    // No signer has been installed: an unsigned response must avoid crypto entirely.
    let result = wire
        .transform_incoming_all(encoded(&response))
        .await
        .unwrap();
    assert!(!result[0].form.signed_or_encrypted());

    let mut session = SessionInfo::new(7);
    session.setup(&[0x42; 16], &None, &info).unwrap();
    session.ready(SessionFlags::new(), &info).unwrap();
    let channel = ChannelInfo::new(0, &[0x42; 16], &None, &info).unwrap();
    let mut signer = channel.signer().unwrap().clone();
    let state = Arc::new(SessionAndChannel::new(7, Arc::new(RwLock::new(session))));
    state.set_channel(channel);
    wire.session_started(&state).await.unwrap();
    response.header.flags.set_signed(true);
    let raw = encoded(&response);
    response.header.signature = signer
        .signature_for_segments(&mut response.header, [raw.as_ref()])
        .unwrap();
    let valid = wire
        .transform_incoming_all(encoded(&response))
        .await
        .unwrap();
    assert!(valid[0].form.signed_or_encrypted());
    response.header.signature ^= 1;
    assert!(matches!(
        wire.transform_incoming_all(encoded(&response)).await,
        Err(Error::TranformFailed(TransformError {
            phase: TransformPhase::SignVerify,
            ..
        }))
    ));
}
