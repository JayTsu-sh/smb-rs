use bytes::Bytes;
use smb_transport::test_support::ScriptedTransport;
use smb_transport::{IoVec, SendFrame, SmbTransport};
use std::io::ErrorKind;
use std::time::Duration;

#[tokio::test]
async fn scripted_server_frame_round_trips_through_transport_interface() {
    let (transport, control) = ScriptedTransport::new();
    control.push_server_frame(Bytes::from_static(b"server-frame"));

    let (mut read, _) = transport.split().expect("scripted transport splits");
    let received = read.receive().await.expect("scripted frame is readable");

    assert_eq!(received.as_bytes(), &Bytes::from_static(b"server-frame"));
    assert_eq!(control.pending_server_frames(), 0);
}

#[tokio::test]
async fn announced_frame_over_limit_is_rejected_before_body_read() {
    let (transport, control) = ScriptedTransport::new();
    control.push_server_frame(Bytes::from_static(b"too-large"));
    let (mut read, _) = transport.split().expect("scripted transport splits");

    let error = read
        .receive_with_limit(4)
        .await
        .expect_err("announced length exceeds cap");

    assert!(matches!(
        error,
        smb_transport::TransportError::FrameTooLarge {
            announced: 9,
            maximum: 4
        }
    ));
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

    let first = SendFrame::from_iovec(IoVec::from(b"first".to_vec())).unwrap();
    write.send(&first).await.expect("first frame succeeds");
    let second = SendFrame::from_iovec(IoVec::from(b"second".to_vec())).unwrap();
    let error = write
        .send(&second)
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

    let payload = SendFrame::from_iovec(payload).unwrap();
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

#[test]
fn production_cursor_survives_every_scripted_short_write_size() {
    for maximum_write in 1..=15 {
        let (_transport, control) = ScriptedTransport::new();
        let frame = SendFrame::from_segments(
            vec![
                Bytes::from_static(b"meta"),
                Bytes::new(),
                Bytes::from_static(b"payload"),
            ],
            3,
        )
        .unwrap();
        control.capture_send_frame(&frame, maximum_write).unwrap();
        assert_eq!(
            control.captured_client_frames(),
            vec![Bytes::from_static(b"metapayload")],
            "maximum_write={maximum_write}",
        );
    }

    let (_transport, control) = ScriptedTransport::new();
    let frame = SendFrame::from_segments(vec![Bytes::from_static(b"x")], 1).unwrap();
    assert!(matches!(
        control.capture_send_frame(&frame, 0),
        Err(smb_transport::TransportError::WriteZero)
    ));
}

#[tokio::test]
async fn progress_send_reports_every_positive_short_write() {
    for maximum in 1..=15 {
        let (transport, control) = ScriptedTransport::new();
        control.set_maximum_write(maximum);
        let (_, mut write) = transport.split().expect("scripted transport splits");
        let frame = SendFrame::from_segments(
            vec![Bytes::from_static(b"meta"), Bytes::from_static(b"payload")],
            2,
        )
        .unwrap();
        let mut advances = Vec::new();
        write
            .send_with_progress(&frame, &mut |bytes| advances.push(bytes))
            .await
            .expect("progress send succeeds");
        assert!(advances.iter().all(|bytes| *bytes > 0 && *bytes <= maximum));
        assert_eq!(advances.iter().sum::<usize>(), 4 + frame.total_len());
        assert_eq!(
            control.captured_client_frames(),
            vec![Bytes::from_static(b"metapayload")]
        );
    }
}

#[tokio::test]
async fn zero_progress_is_typed_before_any_frame_is_captured() {
    let (transport, control) = ScriptedTransport::new();
    control.set_maximum_write(0);
    let (_, mut write) = transport.split().expect("scripted transport splits");
    let frame = SendFrame::from_segments(vec![Bytes::from_static(b"x")], 1).unwrap();
    let mut advances = Vec::new();
    let error = write
        .send_with_progress(&frame, &mut |bytes| advances.push(bytes))
        .await
        .expect_err("zero progress must fail");
    assert!(matches!(error, smb_transport::TransportError::WriteZero));
    assert!(advances.is_empty());
    assert!(control.captured_client_frames().is_empty());
}
