//! Real-server CHANGE_NOTIFY probe. Credentials are read from SMB_NOTIFY_* environment variables.
//! Run with: cargo run -p smb --example notify_probe
use bytes::Bytes;
use futures_util::StreamExt;
use smb::{
    CancelToken, Client, Credentials, Directory, DirectoryEvent, DirectoryOpenOptions,
    DirectoryWatchOptions, Error, FileOpenOptions, MetadataUpdate, Share, SharePath, ShareTarget,
};
use std::{
    env,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    sync::mpsc,
    task::JoinHandle,
    time::{sleep, timeout},
};

type Events = mpsc::Receiver<smb::Result<DirectoryEvent>>;

fn setting(name: &str) -> smb::Result<String> {
    env::var(name).map_err(|_| Error::InvalidArgument(format!("missing {name}")))
}

fn path(base: &str, name: &str) -> smb::Result<SharePath> {
    SharePath::new(format!("{base}/{name}"))
}

async fn expected(events: &mut Events, kind: &str, name: &str) -> smb::Result<()> {
    timeout(Duration::from_secs(10), async {
        while let Some(event) = events.recv().await {
            let event = event?;
            println!("EVENT {event:?}");
            let matched = match &event {
                DirectoryEvent::Added { path } => kind == "Added" && path == name,
                DirectoryEvent::Removed { path } => kind == "Removed" && path == name,
                DirectoryEvent::Modified { path } => kind == "Modified" && path == name,
                DirectoryEvent::Renamed { from, to } => {
                    kind == "Renamed" && format!("{from}->{to}") == name
                }
                _ => false,
            };
            if matched {
                println!("PASS {kind} {name}");
                return Ok(());
            }
        }
        Err(Error::InvalidState("watch stream ended".into()))
    })
    .await
    .map_err(|_| Error::InvalidState(format!("timed out waiting for {kind} {name}")))?
}

async fn settle(events: &mut Events) -> smb::Result<()> {
    while let Ok(Some(event)) = timeout(Duration::from_millis(300), events.recv()).await {
        println!("EVENT {:?}", event?);
    }
    Ok(())
}

fn observe(
    directory: Directory,
    recursive: bool,
    cancel: CancelToken,
) -> (Events, JoinHandle<smb::Result<()>>) {
    let (tx, rx) = mpsc::channel(1024);
    let task = tokio::spawn(async move {
        let mut events = directory.watch(
            DirectoryWatchOptions::default()
                .recursive(recursive)
                .cancellation(cancel),
        );
        while let Some(event) = events.next().await {
            if tx.send(event).await.is_err() {
                break;
            }
        }
        drop(events);
        directory.close().await?;
        Ok(())
    });
    (rx, task)
}

async fn matrix(
    share: &Share,
    base: &str,
    events: &mut Events,
    recursive: bool,
) -> smb::Result<()> {
    // A ready marker proves a real response was delivered before the actual matrix starts.
    sleep(Duration::from_secs(1)).await;
    let ready = share
        .open_file(&path(base, "ready")?, FileOpenOptions::create_new())
        .await?;
    ready.close().await?;
    expected(events, "Added", "ready").await?;
    settle(events).await?;

    let file_path = path(base, "file.txt")?;
    let file = share
        .open_file(&file_path, FileOpenOptions::create_new())
        .await?;
    file.close().await?;
    expected(events, "Added", "file.txt").await?;
    settle(events).await?;
    let file = share
        .open_file(
            &file_path,
            FileOpenOptions::open_existing().write(true).delete(true),
        )
        .await?;
    file.write_all_at(0, Bytes::from_static(b"notify content change"))
        .await?;
    file.flush().await?;
    file.close().await?;
    expected(events, "Modified", "file.txt").await?;
    settle(events).await?;
    let file = share
        .open_file(
            &file_path,
            FileOpenOptions::open_existing()
                .write_attributes(true)
                .delete(true),
        )
        .await?;
    file.set_metadata(MetadataUpdate {
        written: Some(UNIX_EPOCH + Duration::from_secs(1_700_000_001)),
        ..Default::default()
    })
    .await?;
    file.close().await?;
    expected(events, "Modified", "file.txt").await?;
    settle(events).await?;
    let file = share
        .open_file(&file_path, FileOpenOptions::open_existing().delete(true))
        .await?;
    file.rename(&path(base, "renamed.txt")?).await?;
    expected(events, "Renamed", "file.txt->renamed.txt").await?;
    file.delete().await?;
    file.close().await?;
    expected(events, "Removed", "renamed.txt").await?;

    let dir = share
        .open_directory(&path(base, "child")?, DirectoryOpenOptions::create_new())
        .await?;
    expected(events, "Added", "child").await?;
    settle(events).await?;
    dir.set_metadata(MetadataUpdate {
        written: Some(UNIX_EPOCH + Duration::from_secs(1_700_000_002)),
        ..Default::default()
    })
    .await?;
    expected(events, "Modified", "child").await?;
    settle(events).await?;
    let nested = share
        .open_file(
            &path(base, "child/nested.txt")?,
            FileOpenOptions::create_new(),
        )
        .await?;
    nested.close().await?;
    if recursive {
        expected(events, "Added", "child\\nested.txt").await?;
        settle(events).await?;
        let nested = share
            .open_file(
                &path(base, "child/nested.txt")?,
                FileOpenOptions::open_existing().write(true),
            )
            .await?;
        nested
            .write_all_at(0, Bytes::from_static(b"nested content"))
            .await?;
        nested.flush().await?;
        nested.close().await?;
        expected(events, "Modified", "child\\nested.txt").await?;
    } else {
        let nested_seen = timeout(Duration::from_secs(2), async {
            while let Some(event) = events.recv().await {
                let event = event?;
                println!("EVENT {event:?}");
                if matches!(event, DirectoryEvent::Added { ref path } if path == "child\\nested.txt") { return Ok(true); }
            }
            smb::Result::Ok(false)
        }).await;
        if matches!(nested_seen, Ok(Ok(true))) {
            return Err(Error::InvalidState(
                "nonrecursive watch reported nested creation".into(),
            ));
        }
        if let Ok(Err(error)) = nested_seen {
            return Err(error);
        }
        println!("PASS nonrecursive excludes child\\nested.txt (2s observation)");
    }
    let nested = share
        .open_file(
            &path(base, "child/nested.txt")?,
            FileOpenOptions::open_existing().delete(true),
        )
        .await?;
    nested.delete().await?;
    nested.close().await?;
    if recursive {
        expected(events, "Removed", "child\\nested.txt").await?;
    }
    dir.rename(&path(base, "renamed-child")?).await?;
    expected(events, "Renamed", "child->renamed-child").await?;
    dir.delete().await?;
    dir.close().await?;
    expected(events, "Removed", "renamed-child").await?;
    Ok(())
}

async fn cleanup(share: &Share, base: &str) -> smb::Result<()> {
    let dir = share
        .open_directory(
            &SharePath::new(base)?,
            DirectoryOpenOptions::open_existing().delete(true),
        )
        .await?;
    for entry in dir.collect_entries("*").await? {
        let entry_path = path(base, entry.name())?;
        if entry.is_directory() {
            Box::pin(cleanup(share, entry_path.as_str())).await?;
        } else {
            let file = share
                .open_file(&entry_path, FileOpenOptions::open_existing().delete(true))
                .await?;
            file.delete().await?;
            file.close().await?;
        }
    }
    dir.delete().await?;
    dir.close().await?;
    Ok(())
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> smb::Result<()> {
    let target = ShareTarget::new(setting("SMB_NOTIFY_SERVER")?, setting("SMB_NOTIFY_SHARE")?)?;
    let observer = Client::new();
    let writer = Client::new();
    let watched = observer
        .connect_share(
            &target,
            Credentials::ntlm(setting("SMB_NOTIFY_USER")?, setting("SMB_NOTIFY_PASSWORD")?),
        )
        .await?;
    let share = writer
        .connect_share(
            &target,
            Credentials::ntlm(setting("SMB_NOTIFY_USER")?, setting("SMB_NOTIFY_PASSWORD")?),
        )
        .await?;
    println!(
        "Connected observer and independent writer to {} / {}",
        target.server(),
        target.share()
    );
    let run_id = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::InvalidState("system clock before epoch".into()))?
        .as_millis();
    let result = async {
        for recursive in [true, false] {
            let base = format!("notify-{run_id}-{}-{recursive}", std::process::id());
            let created = share
                .open_directory(&SharePath::new(&base)?, DirectoryOpenOptions::create_new())
                .await?;
            created.close().await?;
            let dir = watched
                .open_directory(
                    &SharePath::new(&base)?,
                    DirectoryOpenOptions::open_existing(),
                )
                .await?;
            let cancel = CancelToken::new();
            let (mut events, task) = observe(dir, recursive, cancel.clone());
            println!("CASE recursive={recursive} directory={base}");
            let result = matrix(&share, &base, &mut events, recursive).await;
            cancel.cancel();
            // Keep the receiver alive until the producer exits to validate cancellation itself.
            let stopped = timeout(Duration::from_secs(5), task)
                .await
                .map_err(|_| Error::InvalidState("watch cancellation timed out".into()))?
                .map_err(|_| Error::InvalidState("watch task failed".into()))?;
            println!("CLEANUP {base}");
            let cleaned = cleanup(&share, &base).await;
            result?;
            stopped?;
            cleaned?;
            println!("PASS cancellation and cleanup recursive={recursive}");
        }
        smb::Result::Ok(())
    }
    .await;
    let writer_closed = writer.close().await;
    let observer_closed = observer.close().await;
    result?;
    writer_closed?;
    observer_closed?;
    let verifier = Client::new();
    let verification = async {
        let share = verifier
            .connect_share(
                &target,
                Credentials::ntlm(setting("SMB_NOTIFY_USER")?, setting("SMB_NOTIFY_PASSWORD")?),
            )
            .await?;
        let root = share
            .open_directory(&SharePath::new(".")?, DirectoryOpenOptions::open_existing())
            .await?;
        let prefix = format!("notify-{run_id}-{}-", std::process::id());
        if root
            .collect_entries("*")
            .await?
            .iter()
            .any(|entry| entry.name().starts_with(&prefix))
        {
            return Err(Error::InvalidState(
                "probe left test directories behind".into(),
            ));
        }
        root.close().await?;
        println!("PASS fresh connection confirms test directories removed");
        smb::Result::Ok(())
    }
    .await;
    let verifier_closed = verifier.close().await;
    verification?;
    verifier_closed?;
    println!("PASS all notify probes");
    Ok(())
}
