//! Explicit real-appliance throughput gate at the public domain seam.

mod common;

use bytes::Bytes;
use futures_util::future::try_join_all;
use serde_json::json;
use smb::{Client, ClientConfig, File, FileOpenOptions, SharePath, ShareTarget};
use std::time::{Duration, Instant};

const CHUNK_SIZE: usize = 1024 * 1024;
const DEFAULT_BYTES_PER_STREAM: usize = 64 * 1024 * 1024;

struct Stream {
    client: Client,
    file: File,
    pattern: Bytes,
}

#[test_log::test(tokio::test(flavor = "multi_thread"))]
#[ignore = "requires an isolated real-server performance share"]
async fn plain_or_encrypted_concurrency_matrix() -> smb::Result<()> {
    let bytes_per_stream = std::env::var("SMB_RUST_PERF_BYTES")
        .ok()
        .map(|value| value.parse::<usize>())
        .transpose()
        .map_err(|_| smb::Error::InvalidArgument("invalid performance payload size".into()))?
        .unwrap_or(DEFAULT_BYTES_PER_STREAM);
    if bytes_per_stream == 0 || !bytes_per_stream.is_multiple_of(CHUNK_SIZE) {
        return Err(smb::Error::InvalidArgument(
            "performance payload must be a non-zero multiple of 1 MiB".into(),
        ));
    }

    for concurrency in [1_usize, 4] {
        let mut samples = Vec::new();
        for sample in 0..6 {
            let measured = run_sample(concurrency, bytes_per_stream, sample).await?;
            if sample != 0 {
                samples.push(measured);
            }
        }
        let mut writes = samples.iter().map(|sample| sample.0).collect::<Vec<_>>();
        let mut reads = samples.iter().map(|sample| sample.1).collect::<Vec<_>>();
        writes.sort_by(f64::total_cmp);
        reads.sort_by(f64::total_cmp);
        println!(
            "{}",
            json!({
                "concurrency": concurrency,
                "bytes_per_stream": bytes_per_stream,
                "samples": samples,
                "write_mib_s_median": writes[2],
                "write_mib_s_p95": writes[4],
                "read_mib_s_median": reads[2],
                "read_mib_s_p95": reads[4],
                "peak_rss_kib": peak_rss_kib(),
            })
        );
    }
    Ok(())
}

async fn run_sample(
    concurrency: usize,
    bytes_per_stream: usize,
    sample: usize,
) -> smb::Result<(f64, f64)> {
    let mut streams = Vec::with_capacity(concurrency);
    for stream in 0..concurrency {
        let client = Client::new(ClientConfig::default());
        let share = client
            .connect_share(
                &ShareTarget::new(common::smb_tests_server(), common::smb_tests_share())?,
                common::smb_test_credentials(),
            )
            .await?;
        let path = SharePath::new(format!(
            "w6-perf-{}-{sample}-{stream}.bin",
            std::process::id()
        ))?;
        let file = share.open_file(&path, FileOpenOptions::overwrite()).await?;
        let pattern = Bytes::from(vec![(stream as u8).wrapping_mul(37); CHUNK_SIZE]);
        streams.push(Stream {
            client,
            file,
            pattern,
        });
    }

    let started = Instant::now();
    try_join_all(streams.iter().map(|stream| async move {
        for offset in (0..bytes_per_stream).step_by(CHUNK_SIZE) {
            stream
                .file
                .write_all_at(offset as u64, stream.pattern.clone())
                .timeout(Duration::from_secs(30))
                .await?;
        }
        smb::Result::Ok(())
    }))
    .await?;
    let write_seconds = started.elapsed().as_secs_f64();

    let started = Instant::now();
    try_join_all(streams.iter().map(|stream| async move {
        for offset in (0..bytes_per_stream).step_by(CHUNK_SIZE) {
            let actual = stream
                .file
                .read_exact_at(offset as u64, CHUNK_SIZE as u32)
                .timeout(Duration::from_secs(30))
                .await?;
            if actual != stream.pattern {
                return Err(smb::Error::InvalidMessage(
                    "performance read-back mismatch".into(),
                ));
            }
        }
        smb::Result::Ok(())
    }))
    .await?;
    let read_seconds = started.elapsed().as_secs_f64();

    for stream in streams {
        stream.file.delete().await?;
        stream.file.close().await?;
        stream.client.close().await?;
    }
    let mib = (bytes_per_stream * concurrency) as f64 / (1024.0 * 1024.0);
    Ok((mib / write_seconds, mib / read_seconds))
}

fn peak_rss_kib() -> Option<u64> {
    std::fs::read_to_string("/proc/self/status")
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("VmHWM:"))?
        .split_ascii_whitespace()
        .next()?
        .parse()
        .ok()
}
