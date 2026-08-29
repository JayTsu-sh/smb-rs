//! Explicit real-server W4-6 event-policy gates.

mod common;

use common::{make_server_connection, smb_tests_share};
use futures_util::StreamExt;
use smb::{Directory, FileCreateArgs};
use smb_fscc::{
    DirAccessMask, FileDispositionInformation, FileRenameInformation, NotifyAction,
};
use smb_msg::NotifyFilter;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

#[test_log::test(tokio::test(flavor = "multi_thread"))]
#[ignore = "requires an isolated writable real-server share"]
async fn create_rename_delete_and_cancel_are_bounded_change_events(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let share = smb_tests_share();
    let (client, root) = make_server_connection(&share, None).await?;
    let client = Arc::new(client);
    let directory = Arc::new(
        client
            .create_file(
                &root,
                &FileCreateArgs::make_open_existing(
                    DirAccessMask::new().with_list_directory(true).into(),
                ),
            )
            .await?
            .into_dir()?,
    );
    let cancel = CancellationToken::new();
    let mut events = Box::pin(Directory::watch_stream_cancellable(
        &directory,
        NotifyFilter::all(),
        true,
        cancel.clone(),
    )?);

    let stem = format!("w46-events-{}", std::process::id());
    let original = format!("{stem}-original.bin");
    let renamed = format!("{stem}-renamed.bin");
    let mutate = tokio::spawn({
        let client = client.clone();
        let root = root.clone();
        let original = original.clone();
        let renamed = renamed.clone();
        async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let file = client
                .create_file(
                    &root.with_path(&original),
                    &FileCreateArgs::make_overwrite(Default::default(), Default::default()),
                )
                .await?
                .into_file()?;
            file.set_info(FileRenameInformation {
                replace_if_exists: false.into(),
                root_directory: 0,
                file_name: renamed.clone().into(),
            })
            .await?;
            file.set_info(FileDispositionInformation {
                delete_pending: true.into(),
            })
            .await?;
            file.close().await?;
            smb::Result::Ok(())
        }
    });

    let collect = async {
        let mut added = false;
        let mut renamed_old = false;
        let mut renamed_new = false;
        let mut removed = false;
        while !(added && renamed_old && renamed_new && removed) {
            let event = events
                .next()
                .await
                .ok_or("change-notify stream ended before all events")??;
            let name = event.file_name.to_string();
            match event.action {
                NotifyAction::Added if name == original => added = true,
                NotifyAction::RenamedOldName if name == original => renamed_old = true,
                NotifyAction::RenamedNewName if name == renamed => renamed_new = true,
                NotifyAction::Removed if name == renamed => removed = true,
                _ => {}
            }
        }
        Result::<(), Box<dyn std::error::Error + Send + Sync>>::Ok(())
    };
    tokio::time::timeout(Duration::from_secs(15), collect).await??;
    mutate.await??;

    cancel.cancel();
    assert!(
        tokio::time::timeout(Duration::from_secs(5), events.next())
            .await
            .is_ok(),
        "cancelled watch must reach a terminal stream result"
    );
    println!("CHANGE_NOTIFY_CREATE_RENAME_DELETE");
    println!("CHANGE_NOTIFY_CANCELLED");
    directory.close().await?;
    Ok(())
}
