use bytes::Bytes;
use smb::{
    domain::{Credentials, File, FileOpenOptions, Session, Share, SharePath, ShareTarget},
    facade::{Client, ClientConfig},
};

fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn public_spine_types_are_send_sync_and_domain_named() {
    assert_send_sync::<Client>();
    assert_send_sync::<Session>();
    assert_send_sync::<Share>();
    assert_send_sync::<File>();

    let target = ShareTarget::new("server", "share").unwrap();
    assert_eq!(target.server(), "server");
    assert_eq!(target.share(), "share");
    assert_eq!(SharePath::new("dir/file.bin").unwrap().as_str(), "dir\\file.bin");
}

#[allow(dead_code)]
async fn common_and_explicit_session_paths_compile(
    target: ShareTarget,
    credentials: Credentials,
) -> smb::Result<()> {
    let client = Client::new(ClientConfig::default());
    let share = client.connect_share(&target, credentials).await?;
    let path = SharePath::new("domain-spine.bin")?;
    let file = share.open_file(&path, FileOpenOptions::overwrite()).await?;
    file.write_at(0, Bytes::from_static(b"domain")).await?;
    file.close().await?;

    let session = client
        .authenticate(target.server(), Credentials::ntlm("user", "secret"))
        .await?;
    let share = session.connect_share(target.share()).await?;
    let file = share.open_file(&path, FileOpenOptions::open_existing()).await?;
    let _bytes = file.read_at(0, 6).await?;
    file.delete().await?;
    file.close().await?;
    share.close().await?;
    session.close().await?;
    client.close().await
}
