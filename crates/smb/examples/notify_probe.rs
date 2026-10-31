//! Real-server CHANGE_NOTIFY probe. Credentials are read from SMB_NOTIFY_* environment variables.
//! Run with: cargo run -p smb --example notify_probe
use bytes::Bytes;
use futures_util::StreamExt;
use smb::{
    CancelToken, Client, CloseOutcome, Credentials, Directory, DirectoryEvent,
    DirectoryOpenOptions, DirectoryWatchOptions, Error, FileOpenOptions, MetadataUpdate, Share,
    SharePath, ShareTarget,
};
use std::{
    env, io, process,
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

fn confirm_close(outcome: CloseOutcome) -> smb::Result<()> {
    match outcome {
        CloseOutcome::Confirmed | CloseOutcome::AlreadyClosed => Ok(()),
        CloseOutcome::OutcomeUnknown => Err(Error::OutcomeUnknown),
    }
}

async fn close_client(client: &Client) -> smb::Result<()> {
    let report = client.close().await?;
    if let Some(cause) = report.first_teardown_cause() {
        return Err(Error::InvalidState(format!(
            "client teardown failed: {cause}"
        )));
    }
    Ok(())
}

async fn settle(events: &mut Events) -> smb::Result<()> {
    timeout(Duration::from_secs(10), async {
        loop {
            match timeout(Duration::from_millis(300), events.recv()).await {
                Ok(Some(event)) => println!("EVENT {:?}", event?),
                Ok(None) => return Err(Error::InvalidState("watch stream ended".into())),
                Err(_) => return Ok(()),
            }
        }
    })
    .await
    .map_err(|_| Error::InvalidState("watch never became idle".into()))?
}

async fn expect_no_nested(events: &mut Events, name: &str) -> smb::Result<()> {
    match timeout(Duration::from_secs(2), async {
        while let Some(event) = events.recv().await {
            let event = event?;
            println!("EVENT {event:?}");
            if matches!(event, DirectoryEvent::Added { ref path } if path == name) {
                return Err(Error::InvalidState(
                    "nonrecursive watch reported nested creation".into(),
                ));
            }
        }
        Err(Error::InvalidState("watch stream ended".into()))
    })
    .await
    {
        Ok(result) => result,
        Err(_) => Ok(()),
    }
}

async fn stop_observer(mut task: JoinHandle<smb::Result<()>>, budget: Duration) -> smb::Result<()> {
    match timeout(budget, &mut task).await {
        Ok(result) => result.map_err(|error| Error::IoError(io::Error::other(error)))?,
        Err(_) => {
            task.abort();
            let _ = task.await;
            Err(Error::InvalidState("watch cancellation timed out".into()))
        }
    }
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
        confirm_close(directory.close().await?)?;
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
    confirm_close(ready.close().await?)?;
    expected(events, "Added", "ready").await?;
    settle(events).await?;

    let file_path = path(base, "file.txt")?;
    let file = share
        .open_file(&file_path, FileOpenOptions::create_new())
        .await?;
    confirm_close(file.close().await?)?;
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
    confirm_close(file.close().await?)?;
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
    confirm_close(file.close().await?)?;
    expected(events, "Modified", "file.txt").await?;
    settle(events).await?;
    let file = share
        .open_file(&file_path, FileOpenOptions::open_existing().delete(true))
        .await?;
    file.rename(&path(base, "renamed.txt")?).await?;
    expected(events, "Renamed", "file.txt->renamed.txt").await?;
    file.delete().await?;
    confirm_close(file.close().await?)?;
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
    confirm_close(nested.close().await?)?;
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
        confirm_close(nested.close().await?)?;
        expected(events, "Modified", "child\\nested.txt").await?;
    } else {
        expect_no_nested(events, "child\\nested.txt").await?;
        println!("PASS nonrecursive excludes child\\nested.txt (2s observation)");
    }
    let nested = share
        .open_file(
            &path(base, "child/nested.txt")?,
            FileOpenOptions::open_existing().delete(true),
        )
        .await?;
    nested.delete().await?;
    confirm_close(nested.close().await?)?;
    if recursive {
        expected(events, "Removed", "child\\nested.txt").await?;
    }
    dir.rename(&path(base, "renamed-child")?).await?;
    expected(events, "Renamed", "child->renamed-child").await?;
    dir.delete().await?;
    confirm_close(dir.close().await?)?;
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
            confirm_close(file.close().await?)?;
        }
    }
    dir.delete().await?;
    confirm_close(dir.close().await?)?;
    Ok(())
}

async fn run_probe(
    target: &ShareTarget,
    observer: &Client,
    writer: &Client,
    owned_directories: &mut Vec<String>,
    run_id: u128,
) -> smb::Result<()> {
    let watched = observer
        .connect_share(
            target,
            Credentials::ntlm(setting("SMB_NOTIFY_USER")?, setting("SMB_NOTIFY_PASSWORD")?),
        )
        .await?;
    let share = writer
        .connect_share(
            target,
            Credentials::ntlm(setting("SMB_NOTIFY_USER")?, setting("SMB_NOTIFY_PASSWORD")?),
        )
        .await?;
    println!(
        "Connected observer and independent writer to {} / {}",
        target.server(),
        target.share()
    );
    for recursive in [true, false] {
        let base = format!("notify-{run_id}-{}-{recursive}", process::id());
        let created = share
            .open_directory(&SharePath::new(&base)?, DirectoryOpenOptions::create_new())
            .await?;
        // Register ownership before any later setup or close can fail. After both
        // clients close, a fresh connection cleans up only these exact names.
        owned_directories.push(base.clone());
        confirm_close(created.close().await?)?;
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
        // Keep the receiver alive until the producer exits. A timed-out task is
        // aborted and joined; final client teardown releases its server handles.
        let stopped = stop_observer(task, Duration::from_secs(5)).await;
        println!("CLEANUP {base}");
        let cleaned = cleanup(&share, &base).await;
        result?;
        stopped?;
        cleaned?;
        println!("PASS cancellation and cleanup recursive={recursive}");
    }
    Ok(())
}

async fn recover_and_verify(target: &ShareTarget, owned_directories: &[String]) -> smb::Result<()> {
    if owned_directories.is_empty() {
        return Ok(());
    }
    let verifier = Client::new();
    let verification = async {
        let share = verifier
            .connect_share(
                target,
                Credentials::ntlm(setting("SMB_NOTIFY_USER")?, setting("SMB_NOTIFY_PASSWORD")?),
            )
            .await?;
        let root = share
            .open_directory(&SharePath::new(".")?, DirectoryOpenOptions::open_existing())
            .await?;
        let entries = root.collect_entries("*").await?;
        for base in owned_directories {
            if entries.iter().any(|entry| entry.name() == base) {
                println!("RECOVERY CLEANUP {base}");
                cleanup(&share, base).await?;
            }
        }
        if root
            .collect_entries("*")
            .await?
            .iter()
            .any(|entry| owned_directories.iter().any(|base| entry.name() == base))
        {
            return Err(Error::InvalidState(
                "probe left test directories behind".into(),
            ));
        }
        confirm_close(root.close().await?)?;
        Ok(())
    }
    .await;
    let verifier_closed = close_client(&verifier).await;
    verification?;
    verifier_closed?;
    println!("PASS fresh connection confirms test directories removed");
    Ok(())
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> smb::Result<()> {
    let target = ShareTarget::new(setting("SMB_NOTIFY_SERVER")?, setting("SMB_NOTIFY_SHARE")?)?;
    let run_id = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::InvalidState("system clock before epoch".into()))?
        .as_millis();
    let observer = Client::new();
    let writer = Client::new();
    let mut owned_directories = Vec::new();
    let result = run_probe(&target, &observer, &writer, &mut owned_directories, run_id).await;
    // Always attempt both teardowns and recovery, including failures during setup.
    let writer_closed = close_client(&writer).await;
    let observer_closed = close_client(&observer).await;
    let recovered = recover_and_verify(&target, &owned_directories).await;
    for failure in [&result, &writer_closed, &observer_closed, &recovered] {
        if let Err(error) = failure {
            eprintln!("FAIL {error}");
        }
    }
    result?;
    writer_closed?;
    observer_closed?;
    recovered?;
    println!("PASS all notify probes");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        future::pending,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
    };
    use tokio::sync::oneshot;

    #[test]
    fn uncertain_handle_close_is_not_a_pass() {
        assert!(matches!(
            confirm_close(CloseOutcome::OutcomeUnknown),
            Err(Error::OutcomeUnknown)
        ));
        assert!(confirm_close(CloseOutcome::Confirmed).is_ok());
        assert!(confirm_close(CloseOutcome::AlreadyClosed).is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn quiet_window_requires_a_live_stream() {
        let (sender, mut events) = mpsc::channel(1);
        drop(sender);
        assert!(matches!(
            settle(&mut events).await,
            Err(Error::InvalidState(_))
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn nonrecursive_check_rejects_closed_or_failed_streams() {
        let (sender, mut events) = mpsc::channel(1);
        drop(sender);
        assert!(matches!(
            expect_no_nested(&mut events, "child\\nested.txt").await,
            Err(Error::InvalidState(_))
        ));
        let (sender, mut events) = mpsc::channel(1);
        sender.send(Err(Error::ConnectionStopped)).await.unwrap();
        assert!(matches!(
            expect_no_nested(&mut events, "child\\nested.txt").await,
            Err(Error::ConnectionStopped)
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn nonrecursive_check_rejects_nested_creation_but_allows_other_events() {
        let (sender, mut events) = mpsc::channel(1);
        sender
            .send(Ok(DirectoryEvent::Added {
                path: "child\\nested.txt".into(),
            }))
            .await
            .unwrap();
        assert!(matches!(
            expect_no_nested(&mut events, "child\\nested.txt").await,
            Err(Error::InvalidState(_))
        ));
        sender
            .send(Ok(DirectoryEvent::Modified {
                path: "child".into(),
            }))
            .await
            .unwrap();
        assert!(
            expect_no_nested(&mut events, "child\\nested.txt")
                .await
                .is_ok()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn timed_out_observer_is_aborted_and_joined() {
        struct DropFlag(Arc<AtomicBool>);
        impl Drop for DropFlag {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }
        let dropped = Arc::new(AtomicBool::new(false));
        let (started, began) = oneshot::channel();
        let task = tokio::spawn({
            let dropped = dropped.clone();
            async move {
                let _guard = DropFlag(dropped);
                let _ = started.send(());
                pending::<()>().await;
                smb::Result::Ok(())
            }
        });
        began.await.unwrap();
        assert!(matches!(
            stop_observer(task, Duration::from_secs(5)).await,
            Err(Error::InvalidState(_))
        ));
        // This is observed only after the task was destroyed, not merely detached.
        assert!(dropped.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn observer_failure_is_propagated() {
        let task = tokio::spawn(async { Err(Error::ConnectionStopped) });
        assert!(matches!(
            stop_observer(task, Duration::from_secs(5)).await,
            Err(Error::ConnectionStopped)
        ));
    }
}
