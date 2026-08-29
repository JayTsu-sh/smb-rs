mod common;

use bytes::Bytes;
use common::{make_server_connection, smb_tests_share};
use serial_test::serial;
use smb::{FileCreateArgs, protocol::FileAccessMask};
use smb_fscc::FileDispositionInformation;

#[test_log::test(tokio::test(flavor = "multi_thread"))]
#[serial]
async fn test_bytes_write_and_read_preserve_verified_payload() -> smb::Result<()> {
    let share = smb_tests_share();
    let (client, share_path) = make_server_connection(&share, None).await?;
    let path = share_path.with_path("wire_bytes_roundtrip.bin");
    let payload = Bytes::from(
        (0..1024 * 1024)
            .map(|index| ((index * 31 + 17) & 0xff) as u8)
            .collect::<Vec<_>>(),
    );

    let file = client
        .create_file(
            &path,
            &FileCreateArgs::make_create_new(Default::default(), Default::default()),
        )
        .await?
        .into_file()?;
    assert_eq!(
        file.write_block_zc(payload.clone(), 0, None).await?,
        payload.len()
    );
    file.close().await?;

    let file = client
        .create_file(
            &path,
            &FileCreateArgs::make_open_existing(
                FileAccessMask::new()
                    .with_file_read_data(true)
                    .with_delete(true),
            ),
        )
        .await?
        .into_file()?;
    let received = file
        .read_block_bytes(payload.len() as u32, 0, None, false)
        .await?;
    assert_eq!(received, payload);
    file.set_info(FileDispositionInformation::default()).await?;
    file.close().await?;
    Ok(())
}
