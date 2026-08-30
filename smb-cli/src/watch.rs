use crate::Cli;
use crate::path::RemotePath;
use clap::Parser;
use futures_util::StreamExt;
use smb::{
    CancelToken, Client, ClientConfig, Credentials, Directory, DirectoryOpenOptions,
    DirectoryWatchOptions, SharePath, ShareTarget,
};
use std::error::Error;

#[derive(Parser, Debug)]
pub struct WatchCmd {
    /// The UNC path to the share, file, or directory to query.
    pub path: RemotePath,

    /// Whether to watch recursively in all subdirectories.
    #[arg(short, long, default_value_t = false)]
    pub recursive: bool,

    /// The number of changes to watch for before exiting. If not specified, will watch indefinitely.
    #[arg(short)]
    pub number: Option<usize>,
}

pub async fn watch(cmd: &WatchCmd, cli: &Cli) -> Result<(), Box<dyn Error>> {
    if cmd.path.share().is_none() || cmd.path.share().unwrap().is_empty() {
        return Err("Path must include a share name".into());
    }

    let share_name = cmd
        .path
        .share()
        .filter(|share| !share.is_empty())
        .ok_or("Path must include a share name")?;
    let relative_path = cmd
        .path
        .path()
        .filter(|path| !path.is_empty())
        .ok_or("Path must include a directory")?;
    let client = Client::new(ClientConfig::default());
    let share = client
        .connect_share(
            &ShareTarget::new(cmd.path.server(), share_name)?,
            Credentials::ntlm(cli.username.clone(), cli.password.clone()),
        )
        .await?;
    let directory = share
        .open_directory(
            &SharePath::new(relative_path)?,
            DirectoryOpenOptions::open_existing(),
        )
        .await?;

    tracing::info!("Watching directory: {}", cmd.path);
    watch_dir(&directory, cmd.recursive, cmd.number.unwrap_or(usize::MAX)).await?;

    directory.close().await?;
    share.close().await?;
    client.close().await?;
    Ok(())
}

async fn watch_dir(
    directory: &Directory,
    recursive: bool,
    number: usize,
) -> Result<(), Box<dyn Error>> {
    let cancellation = CancelToken::new();
    ctrlc::set_handler({
        let cancellation = cancellation.clone();
        move || {
            tracing::info!("Cancellation requested, stopping watch...");
            cancellation.cancel();
        }
    })?;

    directory
        .watch(
            DirectoryWatchOptions::default()
                .recursive(recursive)
                .cancellation(cancellation),
        )
        .take(number)
        .for_each(|res| {
            match res {
                Ok(info) => {
                    tracing::info!("Change detected: {:?}", info);
                }
                Err(e) => {
                    tracing::error!("Error watching directory: {}", e);
                }
            }
            futures::future::ready(())
        })
        .await;

    Ok(())
}
