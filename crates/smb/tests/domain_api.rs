use bytes::Bytes;
#[cfg(feature = "real-server-tests")]
use futures_util::StreamExt;
#[cfg(feature = "real-server-tests")]
use smb::{
    Batch, BatchOutcome, CancelToken, DirectoryEvent, DirectoryWatchOptions, Error,
    TransferOptions, TransferProgress,
};
use smb::{
    Client, ClientConfig, CloseOutcome, Credentials, Directory, DirectoryOpenOptions, File,
    FileCursor, FileOpenOptions, Pipe, PipeName, ReplayPolicy, Session, Share, SharePath,
    ShareTarget, Transfer, TransferEvents,
};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeek, AsyncSeekExt, AsyncWrite, AsyncWriteExt};

#[cfg(feature = "real-server-tests")]
mod common;

fn assert_send_sync<T: Send + Sync>() {}
fn assert_clone<T: Clone>() {}
fn assert_send<T: Send>() {}
fn assert_cursor<T: AsyncRead + AsyncWrite + AsyncSeek + Unpin + Send>() {}

#[test]
fn public_spine_types_are_send_sync_and_domain_named() {
    assert_send_sync::<Client>();
    assert_send_sync::<Session>();
    assert_send_sync::<Share>();
    assert_send_sync::<File>();
    assert_send_sync::<Directory>();
    assert_send_sync::<Pipe>();
    assert_clone::<Client>();
    assert_clone::<Session>();
    assert_clone::<Share>();
    assert_cursor::<FileCursor<'static>>();
    assert_send::<Transfer<'static>>();
    assert_send::<TransferEvents>();

    let target = ShareTarget::new("server", "share").unwrap();
    assert_eq!(target.server(), "server");
    assert_eq!(target.share(), "share");
    assert_eq!(
        SharePath::new("dir/file.bin").unwrap().as_str(),
        "dir\\file.bin"
    );
    assert_eq!(PipeName::new("srvsvc").unwrap().as_str(), "srvsvc");
    assert!(PipeName::new("dir/pipe").is_err());
}

#[allow(dead_code)]
async fn pipe_operations_compile(share: &Share) -> smb::Result<()> {
    let pipe = share.open_pipe(&PipeName::new("srvsvc")?).await?;
    pipe.write(Bytes::from_static(b"request")).await?;
    let _ = pipe.read(4096).await?;
    let _ = pipe.transact(Bytes::from_static(b"request"), 4096).await?;
    assert_eq!(pipe.close().await?, CloseOutcome::Confirmed);
    Ok(())
}

#[allow(dead_code)]
async fn common_and_explicit_session_paths_compile(
    target: ShareTarget,
    credentials: Credentials,
) -> smb::Result<()> {
    let client = Client::new(ClientConfig::default());
    let share = client.connect_share(&target, credentials).await?;
    let path = SharePath::new("domain-spine.bin")?;
    let directory_path = SharePath::new("domain-directory")?;
    let directory = share
        .open_directory(&directory_path, DirectoryOpenOptions::create_new())
        .await?;
    let _entries = directory.collect_entries("*").await?;
    directory.delete().await?;
    assert_eq!(directory.close().await?, CloseOutcome::Confirmed);
    let file = share
        .open_file(&path, FileOpenOptions::overwrite())
        .timeout(Duration::from_secs(5))
        .await?;
    file.write_at(0, Bytes::from_static(b"domain"))
        .deadline(Instant::now() + Duration::from_secs(5))
        .replay(ReplayPolicy::Never)
        .await?;
    let mut caller_buffer = [0_u8; 6];
    file.read_at_into(0, &mut caller_buffer).await?;
    file.write_at_from(6, b"-slice").await?;
    file.write_all_at(12, Bytes::from_static(b"-all")).await?;
    let mut cursor = file.cursor();
    cursor.seek(std::io::SeekFrom::Start(0)).await?;
    let mut cursor_buffer = [0_u8; 6];
    cursor.read_exact(&mut cursor_buffer).await?;
    cursor.write_all(b"cursor").await?;
    assert_eq!(file.close().await?, CloseOutcome::Confirmed);
    assert_eq!(file.close().await?, CloseOutcome::AlreadyClosed);

    let session = client
        .authenticate(target.server(), Credentials::ntlm("user", "secret"))
        .await?;
    let share = session.connect_share(target.share()).await?;
    let file = share
        .open_file(&path, FileOpenOptions::open_existing())
        .await?;
    let _bytes = file
        .read_exact_at(0, 6)
        .timeout(Duration::from_secs(5))
        .replay(ReplayPolicy::Idempotent)
        .await?;
    file.delete().await?;
    assert_eq!(file.close().await?, CloseOutcome::Confirmed);
    share.close().await?;
    session.close().await?;
    client.close().await
}

#[cfg(feature = "real-server-tests")]
#[test_log::test(tokio::test(flavor = "multi_thread"))]
#[ignore = "requires an explicitly provisioned writable real-server share"]
async fn domain_spine_roundtrips_without_protocol_escape_hatches() -> smb::Result<()> {
    let target = ShareTarget::new(common::smb_tests_server(), common::smb_tests_share())?;
    let client = Client::new(ClientConfig::default());
    let share = client
        .connect_share(&target, common::smb_test_credentials())
        .await?;
    let path = SharePath::new("domain-spine-roundtrip.bin")?;

    let directory_name = format!("domain-directory-roundtrip-{}", std::process::id());
    let directory_path = SharePath::new(&directory_name)?;
    let directory = share
        .open_directory(&directory_path, DirectoryOpenOptions::create_new())
        .timeout(Duration::from_secs(10))
        .await?;
    let cancel_watch = CancelToken::new();
    let mut events = directory.watch(
        DirectoryWatchOptions::default()
            .recursive(true)
            .cancellation(cancel_watch.clone()),
    );
    let original = SharePath::new(format!("{directory_name}/event-original.bin"))?;
    let renamed = SharePath::new(format!("{directory_name}/event-renamed.bin"))?;
    let observe = async {
        let mut added = false;
        let mut renamed_pair = false;
        let mut removed = false;
        while !(added && renamed_pair && removed) {
            match events.next().await.transpose()? {
                Some(DirectoryEvent::Added { path }) if path == "event-original.bin" => {
                    added = true
                }
                Some(DirectoryEvent::Renamed { from, to })
                    if from == "event-original.bin" && to == "event-renamed.bin" =>
                {
                    renamed_pair = true
                }
                Some(DirectoryEvent::Removed { path }) if path == "event-renamed.bin" => {
                    removed = true
                }
                Some(_) => {}
                None => return Err(Error::InvalidState("directory event stream ended".into())),
            }
        }
        smb::Result::Ok(())
    };
    let mutate = async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let event_file = share
            .open_file(&original, FileOpenOptions::overwrite())
            .await?;
        event_file.rename(&renamed).await?;
        let entries = directory.collect_entries("*").await?;
        assert!(
            entries
                .iter()
                .any(|entry| entry.name() == "event-renamed.bin")
        );
        event_file.delete().await?;
        event_file.close().await?;
        smb::Result::Ok(())
    };
    tokio::time::timeout(Duration::from_secs(15), async {
        tokio::try_join!(observe, mutate)
    })
    .await
    .map_err(|_| Error::InvalidState("directory event validation timed out".into()))??;
    cancel_watch.cancel();
    assert!(
        tokio::time::timeout(Duration::from_secs(5), events.next())
            .await
            .map_err(|_| Error::InvalidState("directory watch cancellation timed out".into()))?
            .is_none()
    );
    drop(events);
    directory.delete().await?;
    assert_eq!(directory.close().await?, CloseOutcome::Confirmed);

    let cancellation = CancelToken::new();
    cancellation.cancel();
    assert!(matches!(
        share
            .open_file(&path, FileOpenOptions::overwrite())
            .cancellation(cancellation)
            .await,
        Err(Error::Cancelled("domain operation"))
    ));
    assert!(matches!(
        share
            .open_file(&path, FileOpenOptions::overwrite())
            .deadline(Instant::now() - Duration::from_millis(1))
            .await,
        Err(Error::OperationTimeout(..))
    ));

    let file = share
        .open_file(&path, FileOpenOptions::overwrite())
        .timeout(Duration::from_secs(10))
        .await?;
    let payload = Bytes::from_static(b"domain-first");
    assert_eq!(
        file.write_at(0, payload.clone())
            .timeout(Duration::from_secs(10))
            .replay(ReplayPolicy::Never)
            .await?,
        payload.len()
    );
    let (first_close, second_close) = tokio::join!(file.close(), file.close());
    let outcomes = [first_close?, second_close?];
    assert!(outcomes.contains(&CloseOutcome::Confirmed));
    assert!(outcomes.contains(&CloseOutcome::AlreadyClosed));

    let session = client
        .authenticate(target.server(), common::smb_test_credentials())
        .await?;
    let share = session.connect_share(target.share()).await?;
    let file = share
        .open_file(&path, FileOpenOptions::open_existing())
        .await?;
    assert_eq!(
        file.read_at(0, payload.len() as u32)
            .timeout(Duration::from_secs(10))
            .replay(ReplayPolicy::Idempotent)
            .await?,
        payload
    );
    let mut first_cursor = file.cursor();
    let mut second_cursor = file.cursor();
    let mut first_cursor_bytes = vec![0_u8; payload.len()];
    let mut second_cursor_bytes = vec![0_u8; payload.len()];
    first_cursor.read_exact(&mut first_cursor_bytes).await?;
    second_cursor.read_exact(&mut second_cursor_bytes).await?;
    assert_eq!(first_cursor_bytes, payload);
    assert_eq!(second_cursor_bytes, payload);
    assert_eq!(first_cursor.position(), payload.len() as u64);
    assert_eq!(second_cursor.position(), payload.len() as u64);

    let slice_suffix = b"-slice";
    file.write_at_from(payload.len() as u64, slice_suffix)
        .timeout(Duration::from_secs(10))
        .await?;
    let owned_suffix = Bytes::from_static(b"-all");
    file.write_all_at(
        (payload.len() + slice_suffix.len()) as u64,
        owned_suffix.clone(),
    )
    .timeout(Duration::from_secs(10))
    .await?;
    let expected_len = payload.len() + slice_suffix.len() + owned_suffix.len();
    let complete = file
        .read_exact_at(0, expected_len as u32)
        .timeout(Duration::from_secs(10))
        .replay(ReplayPolicy::Idempotent)
        .await?;
    assert_eq!(&complete[..payload.len()], payload.as_ref());
    assert_eq!(
        &complete[payload.len()..payload.len() + slice_suffix.len()],
        slice_suffix
    );
    assert_eq!(
        &complete[payload.len() + slice_suffix.len()..],
        owned_suffix
    );
    file.delete().await?;
    assert_eq!(file.close().await?, CloseOutcome::Confirmed);
    share.close().await?;
    session.close().await?;
    client.close().await
}

#[cfg(feature = "real-server-tests")]
#[test_log::test(tokio::test(flavor = "multi_thread"))]
#[ignore = "requires a real server exposing the standard IPC service pipes"]
async fn domain_named_pipe_open_cancel_and_close() -> smb::Result<()> {
    let client = Client::new(ClientConfig::default());
    let server = common::smb_tests_server();
    let session = client
        .authenticate(&server, common::smb_test_credentials())
        .await?;
    let ipc = session.connect_share("IPC$").await?;
    let pipe = ipc.open_pipe(&PipeName::new("srvsvc")?).await?;

    let cancel = CancelToken::new();
    cancel.cancel();
    assert!(matches!(
        pipe.transact(Bytes::from_static(b"not-admitted"), 4096)
            .cancellation(cancel)
            .await,
        Err(Error::Cancelled("domain operation"))
    ));
    assert_eq!(pipe.close().await?, CloseOutcome::Confirmed);
    assert_eq!(pipe.close().await?, CloseOutcome::AlreadyClosed);
    ipc.close().await?;
    session.close().await?;
    client.close().await
}

#[cfg(feature = "real-server-tests")]
#[test_log::test(tokio::test(flavor = "multi_thread"))]
#[ignore = "requires an isolated writable real-server share"]
async fn domain_directory_query_only() -> smb::Result<()> {
    let target = ShareTarget::new(common::smb_tests_server(), common::smb_tests_share())?;
    let client = Client::new(ClientConfig::default());
    let share = client
        .connect_share(&target, common::smb_test_credentials())
        .await?;
    let path = SharePath::new(format!("query-only-{}", std::process::id()))?;
    let directory = share
        .open_directory(&path, DirectoryOpenOptions::create_new())
        .await?;
    let entries = directory.collect_entries("*").await?;
    assert!(entries.iter().any(|entry| entry.name() == "."));
    directory.delete().await?;
    directory.close().await?;
    share.close().await?;
    client.close().await
}

#[cfg(feature = "real-server-tests")]
#[test_log::test(tokio::test(flavor = "multi_thread"))]
#[ignore = "requires an isolated writable real-server share"]
async fn domain_batch_and_concurrent_transfer() -> smb::Result<()> {
    let target = ShareTarget::new(common::smb_tests_server(), common::smb_tests_share())?;
    let client = Client::new(ClientConfig::default());
    let share = client
        .connect_share(&target, common::smb_test_credentials())
        .await?;
    let suffix = std::process::id();
    let source_path = SharePath::new(format!("domain-transfer-source-{suffix}.bin"))?;
    let destination_path = SharePath::new(format!("domain-transfer-destination-{suffix}.bin"))?;
    let payload = Bytes::from(
        (0..(2 * 1024 * 1024 + 137))
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>(),
    );

    let source = share
        .open_file(&source_path, FileOpenOptions::overwrite())
        .await?;
    source.write_all_at(0, payload.clone()).await?;
    source.close().await?;
    let source = share
        .open_file(&source_path, FileOpenOptions::open_existing())
        .await?;
    let destination = share
        .open_file(&destination_path, FileOpenOptions::overwrite())
        .await?;

    let marker = Bytes::from_static(b"batch-marker");
    let mut batch = Batch::new();
    let write = batch.push(destination.batch_write_at(0, marker.clone()));
    let read = batch.push(destination.batch_read_at(0, marker.len() as u32).after(write));
    let outcomes = batch.execute().await?;
    assert!(matches!(
        outcomes.outcome(write),
        Some(BatchOutcome::Success(count)) if *count == marker.len()
    ));
    match outcomes.outcome(read) {
        Some(BatchOutcome::Success(bytes)) => assert_eq!(*bytes, marker),
        other => panic!("unexpected batch read outcome: {other:?}"),
    }

    let mut transfer = source.transfer_to(
        &destination,
        TransferOptions::default()
            .concurrency(4)
            .chunk_size(256 * 1024)
            .timeout(Duration::from_secs(30)),
    );
    let mut progress = transfer.take_events().expect("events are taken once");
    let observe = async {
        let mut last = 0_u64;
        while let Some(event) = progress.next().await {
            if let TransferProgress::ChunkCompleted { transferred, .. } = event {
                last = last.max(transferred);
            }
        }
        last
    };
    let (report, observed) = tokio::join!(transfer, observe);
    let report = report?;
    assert_eq!(report.bytes(), payload.len() as u64);
    assert_eq!(observed, payload.len() as u64);
    assert_eq!(
        destination.read_exact_at(0, payload.len() as u32).await?,
        payload
    );

    let cancellation = CancelToken::new();
    cancellation.cancel();
    assert!(matches!(
        source
            .transfer_to(
                &destination,
                TransferOptions::default().cancellation(cancellation)
            )
            .await,
        Err(Error::Cancelled("domain operation"))
    ));

    source.delete().await?;
    destination.delete().await?;
    source.close().await?;
    destination.close().await?;
    share.close().await?;
    client.close().await
}
