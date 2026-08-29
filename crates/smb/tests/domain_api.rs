use bytes::Bytes;
#[cfg(feature = "real-server-tests")]
use smb::{CancelToken, Error};
use smb::{
    Client, ClientConfig, Credentials, File, FileCursor, FileOpenOptions, ReplayPolicy, Session,
    Share, SharePath, ShareTarget,
};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeek, AsyncSeekExt, AsyncWrite, AsyncWriteExt};

#[cfg(feature = "real-server-tests")]
mod common;

fn assert_send_sync<T: Send + Sync>() {}
fn assert_clone<T: Clone>() {}
fn assert_cursor<T: AsyncRead + AsyncWrite + AsyncSeek + Unpin + Send>() {}

#[test]
fn public_spine_types_are_send_sync_and_domain_named() {
    assert_send_sync::<Client>();
    assert_send_sync::<Session>();
    assert_send_sync::<Share>();
    assert_send_sync::<File>();
    assert_clone::<Client>();
    assert_clone::<Session>();
    assert_clone::<Share>();
    assert_cursor::<FileCursor<'static>>();

    let target = ShareTarget::new("server", "share").unwrap();
    assert_eq!(target.server(), "server");
    assert_eq!(target.share(), "share");
    assert_eq!(
        SharePath::new("dir/file.bin").unwrap().as_str(),
        "dir\\file.bin"
    );
}

#[allow(dead_code)]
async fn common_and_explicit_session_paths_compile(
    target: ShareTarget,
    credentials: Credentials,
) -> smb::Result<()> {
    let client = Client::new(ClientConfig::default());
    let share = client.connect_share(&target, credentials).await?;
    let path = SharePath::new("domain-spine.bin")?;
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
    file.close().await?;

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
    file.close().await?;
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
    file.close().await?;

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
    file.delete().await?;
    file.close().await?;
    share.close().await?;
    session.close().await?;
    client.close().await
}
