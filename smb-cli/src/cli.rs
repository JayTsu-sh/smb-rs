use crate::{copy::CopyCmd, info::InfoCmd, security::SecurityCmd, watch::WatchCmd};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(version, about, long_about = None)]
pub struct Cli {
    #[arg(short, long)]
    pub username: String,
    #[arg(short, long)]
    pub password: String,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Copies files to/from a share.
    Copy(CopyCmd),
    /// Retrieves information about a share or a path.
    Info(InfoCmd),
    /// Configures object security
    Security(SecurityCmd),
    /// Watches for changes in a directory.
    Watch(WatchCmd),
}
