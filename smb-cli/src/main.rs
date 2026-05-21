use std::error::Error;
use std::io::IsTerminal;

use clap::Parser;
use smb_cli::*;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    _main().await.map_err(|e| {
        tracing::error!("Error: {e}");
        e
    })
}

async fn _main() -> Result<(), Box<dyn Error>> {
    // Default to info; honor RUST_LOG. tracing-log feature captures records from log-based crates.
    let filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();
    let stderr = std::io::stderr();
    let ansi = stderr.is_terminal();
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(ansi)
        .init();
    tracing::debug!("Starting smb-cli {}", env!("CARGO_PKG_VERSION"));

    let cli = Cli::parse();

    // In macOS, we need to attach, since local network connections are problematic when
    // the debugger starts the process.
    #[cfg(all(feature = "profiling", target_os = "macos"))]
    {
        println!("Profiling enabled on macOS. Attach profiler, and Enter to begin running.");
        let mut s = String::new();
        std::io::stdin().read_line(&mut s)?;
    }

    match &cli.command {
        Commands::Copy(cmd) => {
            tracing::info!("Copying {:?} to {:?}", cmd.from, cmd.to);
            copy::copy(cmd, &cli).await?;
        }
        Commands::Info(cmd) => {
            tracing::info!("Getting info for {:?}", cmd.path);
            info::info(cmd, &cli).await?;
        }
        Commands::Security(cmd) => {
            security::security(cmd, &cli).await?;
        }
        Commands::Watch(watch_cmd) => {
            tracing::info!("Watching for changes in {:?}", watch_cmd.path);
            watch::watch(watch_cmd, &cli).await?;
        }
    }

    Ok(())
}
