use std::{collections::VecDeque, error::Error, fmt::Display};

use clap::{Parser, ValueEnum};
use smb::{
    Client, ClientConfig, Credentials, Directory, DirectoryOpenOptions, Resource, Share, SharePath,
    ShareTarget, UncPath,
};

use crate::Cli;

#[derive(Debug, Clone, Copy, Default, ValueEnum, PartialEq, Eq, PartialOrd, Ord)]
pub enum RecursiveMode {
    #[default]
    NonRecursive,
    List,
}

impl Display for RecursiveMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NonRecursive => write!(f, "non-recursive"),
            Self::List => write!(f, "list"),
        }
    }
}

#[derive(Parser, Debug)]
pub struct InfoCmd {
    /// The UNC path to the server, share, file, or directory to query.
    pub path: UncPath,

    #[arg(short, long, default_value_t = RecursiveMode::NonRecursive)]
    pub recursive: RecursiveMode,

    /// Quota is an explicit extension and is not part of basic metadata.
    #[arg(long, default_value_t = false)]
    pub show_quota: bool,

    /// Extended attributes are an explicit extension and are not part of basic metadata.
    #[arg(long, default_value_t = false)]
    pub show_ea: bool,
}

pub async fn info(command: &InfoCmd, cli: &Cli) -> Result<(), Box<dyn Error>> {
    if command.show_quota || command.show_ea {
        return Err(smb::Error::UnsupportedOperation(
            "quota and extended-attribute extensions are not activated on the domain interface"
                .into(),
        )
        .into());
    }

    let client = Client::new(ClientConfig::default());
    let credentials = || Credentials::ntlm(cli.username.clone(), cli.password.clone());
    let Some(share_name) = command.path.share().filter(|share| !share.is_empty()) else {
        let shares = client
            .enumerate_shares(command.path.server(), credentials())
            .await?;
        tracing::info!("Available shares on {}:", command.path.server());
        for share in shares {
            tracing::info!("  - {} ({:?})", share.name(), share.kind());
        }
        client.close().await?;
        return Ok(());
    };
    let relative = command
        .path
        .path()
        .filter(|path| !path.is_empty())
        .ok_or_else(|| {
            smb::Error::InvalidArgument("info requires a path below the Share root".into())
        })?;
    let share = client
        .connect_share(
            &ShareTarget::new(command.path.server(), share_name)?,
            credentials(),
        )
        .await?;
    let resource = share.open(&SharePath::new(relative)?).await?;
    match resource {
        Resource::File(file) => {
            let metadata = file.metadata().await?;
            tracing::info!("{}", command.path);
            tracing::info!("  - Size: {} bytes", metadata.len());
            tracing::info!("  - Created: {:?}", metadata.created());
            tracing::info!("  - Written: {:?}", metadata.written());
            tracing::info!("  - Accessed: {:?}", metadata.accessed());
            file.close().await?;
        }
        Resource::Directory(directory) => {
            list_directories(&share, relative, directory, command.recursive).await?;
        }
        Resource::Pipe(pipe) => {
            tracing::info!("{} is a named Pipe", command.path);
            pipe.close().await?;
        }
    }
    share.close().await?;
    client.close().await?;
    Ok(())
}

// Kept out of the Interface: traversal owns each Directory until it has been
// fully consumed and explicitly closed.
async fn list_directories(
    share: &Share,
    root: &str,
    directory: Directory,
    recursive: RecursiveMode,
) -> smb::Result<()> {
    let mut pending = VecDeque::from([(root.to_owned(), directory)]);
    while let Some((path, directory)) = pending.pop_front() {
        tracing::info!("{path}/");
        for entry in directory.collect_entries("*").await? {
            if matches!(entry.name(), "." | "..") {
                continue;
            }
            let child = format!("{path}\\{}", entry.name());
            if entry.is_directory() {
                tracing::info!("  - (D) {child}/");
                if recursive == RecursiveMode::List {
                    let opened = share
                        .open_directory(
                            &SharePath::new(&child)?,
                            DirectoryOpenOptions::open_existing(),
                        )
                        .await?;
                    pending.push_back((child, opened));
                }
            } else {
                tracing::info!("  - (F) {child} ({} bytes)", entry.len());
            }
        }
        directory.close().await?;
    }
    Ok(())
}
