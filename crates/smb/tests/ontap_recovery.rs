//! Explicit real-server Connection-generation recovery gate.

mod common;

use common::{make_server_connection, smb_tests_share};
use smb::{FileCreateArgs, ReadAt, WriteAt};
use std::time::{Duration, Instant};

#[test_log::test(tokio::test(flavor = "multi_thread"))]
#[ignore = "requires isolated ONTAP resources and exact-session disruption"]
async fn connection_transport_recovers_into_a_new_generation(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let share = smb_tests_share();
    let (client, share_path) = make_server_connection(&share, None).await?;
    let server = share_path.server().to_owned();
    let path = share_path.with_path(&format!(
        "smb-rs-recovery-{}.bin",
        std::process::id()
    ));
    let file = client
        .create_file(
            &path,
            &FileCreateArgs::make_overwrite(Default::default(), Default::default()),
        )
        .await?
        .into_file()?;
    file.write_at(b"generation-one", 0).await?;

    let connection = client.get_connection(&server).await?;
    let initial = connection
        .observed_generation()
        .ok_or("connection has no active generation")?;
    println!("RECOVERY_DISRUPTION_READY");

    let deadline = Instant::now() + Duration::from_secs(45);
    let replacement = loop {
        if let Some(generation) = connection.observed_generation()
            && generation != initial
        {
            break generation;
        }
        if Instant::now() >= deadline {
            return Err("connection generation did not recover before deadline".into());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    assert!(replacement > initial);

    let mut byte = [0_u8; 1];
    let stale = file.read_at(&mut byte, 0).await;
    assert!(
        stale.is_err(),
        "ordinary Resource from the lost generation must not migrate silently"
    );
    println!("RECOVERY_GENERATION_REPLACED");
    connection.close().await?;
    Ok(())
}
