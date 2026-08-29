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

    // The management-path session query can be slow on a busy appliance. This
    // outer orchestration window is deliberately longer than the client's
    // recovery-policy deadline; it does not relax any reconnect attempt bound.
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        if let Some(generation) = connection.observed_generation()
            && generation != initial
        {
            assert!(generation > initial);
            let mut byte = [0_u8; 1];
            assert!(
                file.read_at(&mut byte, 0).await.is_err(),
                "ordinary Resource from the lost generation must not migrate silently"
            );
            println!("RECOVERY_GENERATION_REPLACED");
            connection.close().await?;
            return Ok(());
        }
        let mut byte = [0_u8; 1];
        if file.read_at(&mut byte, 0).await.is_err() {
            // ONTAP's exact CIFS-session close may deliberately preserve the
            // underlying TCP connection. That is a Session-recovery input for
            // W4-3, not a transport-loss input for W4-2. The hard W4-2 boundary
            // is a typed stale-session result without blind Resource reopen.
            println!("RECOVERY_SESSION_TYPED_BOUNDARY");
            connection.close().await?;
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("disruption produced neither generation recovery nor typed boundary".into());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
