use bytes::Bytes;
use smb_transport::test_support::ScriptedTransport;
use smb_transport::{IoVec, SmbTransport};
use std::io::ErrorKind;
use std::time::Duration;

#[tokio::test]
async fn scripted_server_frame_round_trips_through_transport_interface() {
    let (transport, control) = ScriptedTransport::new();
    control.push_server_frame(Bytes::from_static(b"server-frame"));

    let (mut read, _) = transport.split().expect("scripted transport splits");
    let received = read.receive().await.expect("scripted frame is readable");

    assert_eq!(received, Bytes::from_static(b"server-frame"));
    assert_eq!(control.pending_server_frames(), 0);
}

#[tokio::test]
async fn framed_read_can_be_consumed_across_arbitrary_exact_read_sizes() {
    let (transport, control) = ScriptedTransport::new();
    control.push_server_frame(Bytes::from_static(b"abcdef"));
    let (mut read, _) = transport.split().expect("scripted transport splits");
    let mut first = [0u8; 2];
    let mut second = [0u8; 3];
    let mut third = [0u8; 5];

    read.receive_exact(&mut first)
        .await
        .expect("first fragment");
    read.receive_exact(&mut second)
        .await
        .expect("second fragment");
    read.receive_exact(&mut third)
        .await
        .expect("third fragment");

    assert_eq!(
        [first.as_slice(), second.as_slice(), third.as_slice()].concat(),
        b"\0\0\0\x06abcdef"
    );
}

#[tokio::test]
async fn waiting_for_an_unwritten_frame_stops_at_the_deadline() {
    let (_transport, control) = ScriptedTransport::new();

    assert!(
        !control
            .wait_for_client_frames(1, Duration::from_millis(1))
            .await
    );
}

#[tokio::test]
async fn scheduled_read_fault_preserves_the_unread_server_frame() {
    let (transport, control) = ScriptedTransport::new();
    control.push_server_frame(Bytes::from_static(b"still-queued"));
    control.fail_read_on(1, ErrorKind::ConnectionReset);
    let (mut read, _) = transport.split().expect("scripted transport splits");

    let error = read.receive().await.expect_err("scheduled read must fail");

    assert!(matches!(
        error,
        smb_transport::TransportError::IoError(error)
            if error.kind() == ErrorKind::ConnectionReset
    ));
    assert_eq!(control.pending_server_frames(), 1);
}

#[tokio::test]
async fn scheduled_write_fault_keeps_frames_captured_before_the_fault() {
    let (transport, control) = ScriptedTransport::new();
    control.fail_write_on(3, ErrorKind::BrokenPipe);
    let (_, mut write) = transport.split().expect("scripted transport splits");

    write
        .send(&IoVec::from(b"first".to_vec()))
        .await
        .expect("first frame succeeds");
    let error = write
        .send(&IoVec::from(b"second".to_vec()))
        .await
        .expect_err("third send_raw operation must fail");

    assert!(matches!(
        error,
        smb_transport::TransportError::IoError(error) if error.kind() == ErrorKind::BrokenPipe
    ));
    assert_eq!(
        control.captured_client_frames(),
        vec![Bytes::from_static(b"first")]
    );
}

#[tokio::test]
async fn scatter_gather_write_is_captured_as_one_frame_without_polling() {
    let (transport, control) = ScriptedTransport::new();
    let (_, mut write) = transport.split().expect("scripted transport splits");
    let mut payload = IoVec::default();
    payload.add_bytes(Bytes::from_static(b"shared-"));
    payload.add_owned(b"owned".to_vec());

    write.send(&payload).await.expect("scatter write succeeds");
    assert!(
        control
            .wait_for_client_frames(1, Duration::from_millis(50))
            .await
    );
    assert_eq!(
        control.captured_client_frames(),
        vec![Bytes::from_static(b"shared-owned")]
    );
}
