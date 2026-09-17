//! Explicit appliance probe; uses a unique file and always attempts cleanup.
mod common;

use bytes::Bytes;
use smb::{Client, FileOpenOptions, SharePath, ShareTarget, SigningPolicy};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires an explicitly configured SMB share"]
async fn negotiated_signing_roundtrip() -> smb::Result<()> {
    let policy = match std::env::var("SMB_SIGNING_TEST_POLICY").as_deref() {
        Ok("required") => SigningPolicy::Required,
        Ok("when-required") => SigningPolicy::WhenRequired,
        _ => {
            return Err(smb::Error::InvalidArgument(
                "set SMB_SIGNING_TEST_POLICY".into(),
            ));
        }
    };
    let client = Client::with_signing_policy(policy);
    let target = ShareTarget::new(common::smb_tests_server(), common::smb_tests_share())?;
    let share = client
        .connect_share(&target, common::smb_test_credentials())
        .timeout(Duration::from_secs(20))
        .await?;
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| smb::Error::InvalidArgument("clock before epoch".into()))?
        .as_nanos();
    let path = SharePath::new(format!("smb-signing-probe-{}-{unique}", std::process::id()))?;
    let file = share
        .open_file(&path, FileOpenOptions::create_new())
        .await?;
    let started = Instant::now();
    let result = async {
        let payload = Bytes::from(
            (0..(4 * 1024 * 1024 + 4096))
                .map(|i| ((i * 37 + i / 251) % 256) as u8)
                .collect::<Vec<_>>(),
        );
        file.write_all_at(0, payload.clone())
            .timeout(Duration::from_secs(30))
            .await?;
        file.flush().await?;
        let mut offset = 0;
        while offset < payload.len() {
            let bytes = file.read_at(offset as u64, 1024 * 1024).await?;
            if bytes.is_empty() || bytes.as_ref() != &payload[offset..offset + bytes.len()] {
                return Err(smb::Error::InvalidMessage("probe content mismatch".into()));
            }
            offset += bytes.len();
        }
        println!(
            "policy={policy:?} bytes={} elapsed_ms={:.3} content=verified",
            payload.len(),
            started.elapsed().as_secs_f64() * 1000.0
        );
        Ok(())
    }
    .await;
    let delete = file.delete().await;
    let close = file.close().await;
    let client_close = client.close().await;
    result?;
    delete?;
    close?;
    client_close?;
    Ok(())
}
