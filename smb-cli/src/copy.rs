use crate::{Cli, path::Path};
use bytes::Bytes;
use clap::Parser;
use futures_util::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use smb::{
    Client, ClientConfig, Credentials, File, FileOpenOptions, Share, SharePath, ShareTarget,
    TransferOptions, TransferProgress,
};
use std::error::Error;
use tokio::{
    fs,
    io::{AsyncReadExt, AsyncWriteExt},
};

const COPY_CHUNK_SIZE: usize = 1024 * 1024;
const REMOTE_CONCURRENCY: usize = 8;

#[derive(Parser, Debug)]
pub struct CopyCmd {
    /// Force copy, overwriting existing file(s).
    #[arg(short, long)]
    pub force: bool,

    /// Source path
    pub from: Path,
    /// Destination path
    pub to: Path,
}

enum CopyFileValue {
    Local(fs::File),
    Remote { file: File, share: Share },
}

struct CopyFile {
    value: CopyFileValue,
    len: u64,
}

impl CopyFile {
    async fn open(
        path: &Path,
        client: &Client,
        cli: &Cli,
        command: &CopyCmd,
        read: bool,
    ) -> smb::Result<Self> {
        match path {
            Path::Local(path) => {
                let file = fs::OpenOptions::new()
                    .read(read)
                    .write(!read)
                    .create(!read)
                    .create_new(!read && !command.force)
                    .truncate(!read)
                    .open(path)
                    .await?;
                let len = if read {
                    file.metadata().await?.len()
                } else {
                    0
                };
                Ok(Self {
                    value: CopyFileValue::Local(file),
                    len,
                })
            }
            Path::Remote(path) => {
                let share_name = path.share().ok_or_else(|| {
                    smb::Error::InvalidArgument("remote copy path requires a share".into())
                })?;
                let relative = path.path().filter(|path| !path.is_empty()).ok_or_else(|| {
                    smb::Error::InvalidArgument("remote copy path requires a file".into())
                })?;
                let target = ShareTarget::new(path.server(), share_name)?;
                let share = client
                    .connect_share(
                        &target,
                        Credentials::ntlm(cli.username.clone(), cli.password.clone()),
                    )
                    .await?;
                let options = if read {
                    FileOpenOptions::open_existing()
                } else if command.force {
                    FileOpenOptions::overwrite()
                } else {
                    FileOpenOptions::create_new()
                };
                let file = share.open_file(&SharePath::new(relative)?, options).await?;
                let len = if read { file.len().await? } else { 0 };
                Ok(Self {
                    value: CopyFileValue::Remote { file, share },
                    len,
                })
            }
        }
    }

    async fn close(self) -> smb::Result<()> {
        if let CopyFileValue::Remote { file, share } = self.value {
            file.close().await?;
            share.close().await?;
        }
        Ok(())
    }
}

fn progress_bar(len: u64) -> ProgressBar {
    let progress = ProgressBar::new(len);
    progress.set_style(
        ProgressStyle::with_template(
            "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})",
        )
        .expect("static progress template is valid")
        .progress_chars("#>-"),
    );
    progress
}

async fn copy_remote_to_remote(source: &File, destination: &File, len: u64) -> smb::Result<()> {
    let mut transfer = source.transfer_to(
        destination,
        TransferOptions::default()
            .concurrency(REMOTE_CONCURRENCY)
            .chunk_size(COPY_CHUNK_SIZE as u32),
    );
    let mut events = transfer
        .take_events()
        .ok_or_else(|| smb::Error::InvalidState("transfer progress already taken".into()))?;
    let progress = progress_bar(len);
    let observe = async {
        while let Some(event) = events.next().await {
            if let TransferProgress::ChunkCompleted { transferred, .. } = event {
                progress.set_position(transferred);
            }
        }
    };
    let (report, ()) = tokio::join!(transfer, observe);
    let report = report?;
    progress.set_position(report.bytes());
    progress.finish_with_message("Copy complete");
    Ok(())
}

async fn copy_local_to_remote(
    source: &mut fs::File,
    destination: &File,
    len: u64,
) -> smb::Result<()> {
    let progress = progress_bar(len);
    let mut offset = 0_u64;
    let mut buffer = vec![0_u8; COPY_CHUNK_SIZE];
    loop {
        let count = source.read(&mut buffer).await?;
        if count == 0 {
            break;
        }
        destination
            .write_all_at(offset, Bytes::copy_from_slice(&buffer[..count]))
            .await?;
        offset += count as u64;
        progress.set_position(offset);
    }
    progress.finish_with_message("Copy complete");
    Ok(())
}

async fn copy_remote_to_local(
    source: &File,
    destination: &mut fs::File,
    len: u64,
) -> smb::Result<()> {
    let progress = progress_bar(len);
    let mut offset = 0_u64;
    while offset < len {
        let length = (len - offset).min(COPY_CHUNK_SIZE as u64) as u32;
        let bytes = source.read_exact_at(offset, length).await?;
        destination.write_all(&bytes).await?;
        offset += bytes.len() as u64;
        progress.set_position(offset);
    }
    progress.finish_with_message("Copy complete");
    Ok(())
}

pub async fn copy(command: &CopyCmd, cli: &Cli) -> Result<(), Box<dyn Error>> {
    if matches!(command.from, Path::Local(_)) && matches!(command.to, Path::Local(_)) {
        return Err("copying between two local files is not supported".into());
    }

    let client = Client::new(ClientConfig::default());
    let mut source = CopyFile::open(&command.from, &client, cli, command, true).await?;
    let mut destination = CopyFile::open(&command.to, &client, cli, command, false).await?;
    let source_len = source.len;
    let result = match (&mut source.value, &mut destination.value) {
        (CopyFileValue::Local(source), CopyFileValue::Remote { file, .. }) => {
            copy_local_to_remote(source, file, source_len).await
        }
        (CopyFileValue::Remote { file, .. }, CopyFileValue::Local(destination)) => {
            copy_remote_to_local(file, destination, source_len).await
        }
        (
            CopyFileValue::Remote { file: source, .. },
            CopyFileValue::Remote {
                file: destination, ..
            },
        ) => copy_remote_to_remote(source, destination, source_len).await,
        (CopyFileValue::Local(_), CopyFileValue::Local(_)) => unreachable!(),
    };

    let destination_close = destination.close().await;
    let source_close = source.close().await;
    let client_close = client.close().await;
    result?;
    destination_close?;
    source_close?;
    client_close?;
    Ok(())
}
