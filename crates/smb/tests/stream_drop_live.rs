//! Live reproduction for issue #75: dropping a `Directory::entries()` stream after its first
//! item must not fail the connection generation, and the next operation on the same share
//! must keep working.
//!
//! Needs a real server (`SMB_RUST_TESTS_SERVER` / `_USER_NAME` / `_PASSWORD` / `_SHARE`).
//! Run with `RUST_LOG=smb=warn` to see the generation-exit cause when it fails.
mod common;

use futures_util::StreamExt;
use smb::{Client, DirectoryOpenOptions, SharePath, ShareTarget};
use std::time::Duration;

const ROUNDS: usize = 48;

#[test_log::test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
#[ignore = "requires an explicitly configured SMB share"]
async fn dropping_a_listing_mid_way_keeps_the_next_operation_working() -> smb::Result<()> {
    let target = ShareTarget::new(common::smb_tests_server(), common::smb_tests_share())?;
    let root = SharePath::new(".")?;
    let mut failures = Vec::new();
    for round in 0..ROUNDS {
        let client = Client::new();
        let share = client
            .connect_share(&target, common::smb_test_credentials())
            .timeout(Duration::from_secs(20))
            .await?;

        let directory = share
            .open_directory(&root, DirectoryOpenOptions::open_existing())
            .await?;
        let mut first = None;
        {
            let mut entries = directory.entries("*");
            while let Some(entry) = entries.next().await {
                let entry = entry?;
                if matches!(entry.name(), "." | "..") {
                    continue;
                }
                first = Some(entry.name().to_owned());
                break; // the stream is dropped here, mid-batch
            }
        }
        directory.close().await?;

        // The "next operation": the pattern the caller sees failing.
        let result = async {
            let again = share
                .open_directory(&root, DirectoryOpenOptions::open_existing())
                .await?;
            let count = again.entries("*").count().await;
            again.close().await?;
            smb::Result::Ok(count)
        }
        .await;
        match result {
            Ok(count) => eprintln!("round {round:02}: ok (first={first:?}, entries={count})"),
            Err(error) => {
                eprintln!("round {round:02}: NEXT OPERATION FAILED: {error}");
                failures.push((round, error.to_string()));
            }
        }
        let _ = share.close().await;
    }
    assert!(
        failures.is_empty(),
        "{} of {ROUNDS} rounds failed: {failures:?}",
        failures.len()
    );
    Ok(())
}
