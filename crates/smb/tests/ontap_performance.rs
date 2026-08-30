//! Explicit real-appliance throughput gate at the public domain seam.

mod common;

use bytes::Bytes;
use futures_util::{StreamExt, future::try_join_all, stream::FuturesUnordered};
use serde_json::json;
use smb::{Client, ClientConfig, File, FileOpenOptions, SharePath, ShareTarget};
use std::time::{Duration, Instant};

const CHUNK_SIZE: usize = 1024 * 1024;
const DEFAULT_BYTES_PER_CONNECTION: usize = 1024 * 1024 * 1024;
const MEASURED_SAMPLES: usize = 5;
const MAX_CV: f64 = 0.10;

#[derive(Clone, Copy)]
struct Shape {
    connections: usize,
    inflight_per_connection: usize,
    baseline_write_mib_s: f64,
    baseline_read_mib_s: f64,
    maximum_rss_kib: u64,
}

const SHAPES: [Shape; 3] = [
    Shape {
        connections: 1,
        inflight_per_connection: 1,
        baseline_write_mib_s: 9.083,
        baseline_read_mib_s: 8.676,
        maximum_rss_kib: 90_050,
    },
    Shape {
        connections: 1,
        inflight_per_connection: 16,
        baseline_write_mib_s: 9.083,
        baseline_read_mib_s: 8.676,
        maximum_rss_kib: 90_050,
    },
    Shape {
        connections: 4,
        inflight_per_connection: 16,
        baseline_write_mib_s: 10.608,
        baseline_read_mib_s: 35.409,
        maximum_rss_kib: 89_201,
    },
];

struct Stream {
    client: Client,
    file: File,
    pattern: Bytes,
}

#[derive(Debug)]
struct Statistics {
    median: f64,
    p95: f64,
    cv: f64,
}

#[test_log::test(tokio::test(flavor = "multi_thread"))]
#[ignore = "requires release mode and an isolated real-server performance share"]
async fn plain_or_encrypted_concurrency_matrix() -> smb::Result<()> {
    if cfg!(debug_assertions) {
        return Err(smb::Error::InvalidArgument(
            "the performance hard gate must run with --release".into(),
        ));
    }
    let mode = PerformanceMode::from_env()?;
    let bytes_per_connection = payload_from_env()?;

    for shape in selected_shapes()? {
        let mut writes = Vec::with_capacity(MEASURED_SAMPLES);
        let mut reads = Vec::with_capacity(MEASURED_SAMPLES);
        for sample in 0..=MEASURED_SAMPLES {
            let measured = run_sample(shape, bytes_per_connection, sample).await?;
            if sample != 0 {
                writes.push(measured.0);
                reads.push(measured.1);
            }
        }
        let write = statistics(&writes);
        let read = statistics(&reads);
        let rss = peak_rss_kib().ok_or_else(|| {
            smb::Error::InvalidMessage("Linux peak RSS measurement is unavailable".into())
        })?;
        println!(
            "{}",
            json!({
                "mode": mode.label(),
                "connections": shape.connections,
                "inflight_per_connection": shape.inflight_per_connection,
                "bytes_per_connection": bytes_per_connection,
                "measured_samples": MEASURED_SAMPLES,
                "write_mib_s": { "median": write.median, "p95": write.p95, "cv": write.cv },
                "read_mib_s": { "median": read.median, "p95": read.p95, "cv": read.cv },
                "peak_rss_kib": rss,
            })
        );
        require_stable("write", &write)?;
        require_stable("read", &read)?;
        if mode == PerformanceMode::Plain && bytes_per_connection == DEFAULT_BYTES_PER_CONNECTION {
            require_plain_baseline(shape, &write, &read, rss)?;
        }
    }
    Ok(())
}

fn selected_shapes() -> smb::Result<Vec<Shape>> {
    let Ok(selected) = std::env::var("SMB_RUST_PERF_SHAPE") else {
        return Ok(SHAPES.to_vec());
    };
    let shape = SHAPES
        .into_iter()
        .find(|shape| {
            selected == format!("{}x{}", shape.connections, shape.inflight_per_connection)
        })
        .ok_or_else(|| {
            smb::Error::InvalidArgument("SMB_RUST_PERF_SHAPE must be 1x1, 1x16, or 4x16".into())
        })?;
    Ok(vec![shape])
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum PerformanceMode {
    Plain,
    Encrypted,
}

impl PerformanceMode {
    fn from_env() -> smb::Result<Self> {
        match std::env::var("SMB_RUST_PERF_MODE").as_deref() {
            Ok("plain") => Ok(Self::Plain),
            Ok("encrypted") => Ok(Self::Encrypted),
            _ => Err(smb::Error::InvalidArgument(
                "SMB_RUST_PERF_MODE must be plain or encrypted".into(),
            )),
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Plain => "plain",
            Self::Encrypted => "encrypted",
        }
    }
}

fn payload_from_env() -> smb::Result<usize> {
    let bytes = std::env::var("SMB_RUST_PERF_BYTES")
        .ok()
        .map(|value| value.parse::<usize>())
        .transpose()
        .map_err(|_| smb::Error::InvalidArgument("invalid performance payload size".into()))?
        .unwrap_or(DEFAULT_BYTES_PER_CONNECTION);
    if bytes == 0 || bytes % bytes.min(CHUNK_SIZE) != 0 {
        return Err(smb::Error::InvalidArgument(
            "performance payload must be non-zero and 1 MiB-aligned above 1 MiB".into(),
        ));
    }
    Ok(bytes)
}

async fn run_sample(
    shape: Shape,
    bytes_per_connection: usize,
    sample: usize,
) -> smb::Result<(f64, f64)> {
    let mut streams = Vec::with_capacity(shape.connections);
    for connection in 0..shape.connections {
        let client = Client::new(ClientConfig::default());
        let share = client
            .connect_share(
                &ShareTarget::new(common::smb_tests_server(), common::smb_tests_share())?,
                common::smb_test_credentials(),
            )
            .await?;
        let path = SharePath::new(format!(
            "w6-perf-{}-{sample}-{connection}.bin",
            std::process::id()
        ))?;
        let file = share.open_file(&path, FileOpenOptions::overwrite()).await?;
        let chunk_size = chunk_size(bytes_per_connection, shape.inflight_per_connection)?;
        let pattern = Bytes::from(vec![(connection as u8).wrapping_mul(37); chunk_size]);
        streams.push(Stream {
            client,
            file,
            pattern,
        });
    }

    let transfer = async {
        let started = Instant::now();
        try_join_all(streams.iter().map(|stream| {
            write_windowed(stream, bytes_per_connection, shape.inflight_per_connection)
        }))
        .await?;
        let write_seconds = started.elapsed().as_secs_f64();

        let started = Instant::now();
        try_join_all(streams.iter().map(|stream| {
            read_windowed(stream, bytes_per_connection, shape.inflight_per_connection)
        }))
        .await?;
        smb::Result::Ok((write_seconds, started.elapsed().as_secs_f64()))
    }
    .await;

    let cleanup = cleanup_streams(streams).await;
    let (write_seconds, read_seconds) = match (transfer, cleanup) {
        (Ok(timings), Ok(())) => timings,
        (Err(error), _) => return Err(error),
        (Ok(_), Err(error)) => return Err(error),
    };
    let mib = (bytes_per_connection * shape.connections) as f64 / (1024.0 * 1024.0);
    Ok((mib / write_seconds, mib / read_seconds))
}

fn chunk_size(bytes_per_connection: usize, inflight: usize) -> smb::Result<usize> {
    let chunk_size = CHUNK_SIZE.min(bytes_per_connection / inflight.max(1));
    if chunk_size == 0 || bytes_per_connection % chunk_size != 0 {
        return Err(smb::Error::InvalidArgument(
            "payload cannot be divided into the requested in-flight window".into(),
        ));
    }
    Ok(chunk_size)
}

async fn cleanup_streams(streams: Vec<Stream>) -> smb::Result<()> {
    let mut first_error = None;
    for stream in streams {
        if let Err(error) = stream.file.delete().await
            && first_error.is_none()
        {
            first_error = Some(error);
        }
        if let Err(error) = stream.file.close().await
            && first_error.is_none()
        {
            first_error = Some(error);
        }
        if let Err(error) = stream.client.close().await
            && first_error.is_none()
        {
            first_error = Some(error);
        }
    }
    first_error.map_or(Ok(()), Err)
}

async fn write_windowed(
    stream: &Stream,
    bytes_per_connection: usize,
    inflight: usize,
) -> smb::Result<()> {
    let chunk_size = stream.pattern.len();
    for first in (0..bytes_per_connection).step_by(chunk_size * inflight) {
        let last = (first + chunk_size * inflight).min(bytes_per_connection);
        try_join_all((first..last).step_by(chunk_size).map(|offset| {
            stream
                .file
                .write_all_at(offset as u64, stream.pattern.clone())
                .timeout(Duration::from_secs(30))
        }))
        .await?;
    }
    Ok(())
}

async fn read_windowed(
    stream: &Stream,
    bytes_per_connection: usize,
    inflight: usize,
) -> smb::Result<()> {
    let chunk_size = stream.pattern.len();
    for first in (0..bytes_per_connection).step_by(chunk_size * inflight) {
        let last = (first + chunk_size * inflight).min(bytes_per_connection);
        let pending = (first..last)
            .step_by(chunk_size)
            .map(|offset| {
                stream
                    .file
                    .read_exact_at(offset as u64, chunk_size as u32)
                    .timeout(Duration::from_secs(30))
            })
            .collect::<FuturesUnordered<_>>();
        futures_util::pin_mut!(pending);
        while let Some(actual) = pending.next().await {
            if actual? != stream.pattern {
                return Err(smb::Error::InvalidMessage(
                    "performance read-back mismatch".into(),
                ));
            }
        }
    }
    Ok(())
}

fn statistics(samples: &[f64]) -> Statistics {
    assert_eq!(samples.len(), MEASURED_SAMPLES);
    let mut sorted = samples.to_vec();
    sorted.sort_by(f64::total_cmp);
    let mean = samples.iter().sum::<f64>() / samples.len() as f64;
    let variance = samples
        .iter()
        .map(|sample| (sample - mean).powi(2))
        .sum::<f64>()
        / samples.len() as f64;
    Statistics {
        median: sorted[sorted.len() / 2],
        p95: sorted[((sorted.len() as f64 * 0.95).ceil() as usize) - 1],
        cv: variance.sqrt() / mean,
    }
}

fn require_stable(direction: &str, statistics: &Statistics) -> smb::Result<()> {
    if statistics.cv > MAX_CV {
        return Err(smb::Error::InvalidMessage(format!(
            "{direction} sample coefficient of variation exceeds 10%"
        )));
    }
    Ok(())
}

fn require_plain_baseline(
    shape: Shape,
    write: &Statistics,
    read: &Statistics,
    rss_kib: u64,
) -> smb::Result<()> {
    if write.median < shape.baseline_write_mib_s * 0.9 {
        return Err(smb::Error::InvalidMessage(
            "plain write throughput is below 90% of baseline".into(),
        ));
    }
    if read.median < shape.baseline_read_mib_s * 0.9 {
        return Err(smb::Error::InvalidMessage(
            "plain read throughput is below 90% of baseline".into(),
        ));
    }
    if rss_kib > shape.maximum_rss_kib {
        return Err(smb::Error::InvalidMessage(
            "plain peak RSS exceeds 110% of baseline".into(),
        ));
    }
    Ok(())
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

#[test]
fn statistics_use_nearest_rank_p95_and_population_cv() {
    let actual = statistics(&[8.0, 10.0, 9.0, 11.0, 12.0]);
    assert_eq!(actual.median, 10.0);
    assert_eq!(actual.p95, 12.0);
    assert!((actual.cv - 0.141_421_356).abs() < 0.000_001);
}

#[test]
fn chunk_size_preserves_real_inflight_requests_for_small_payloads() {
    assert_eq!(chunk_size(64 * 1024, 16).unwrap(), 4 * 1024);
    assert_eq!(chunk_size(1024 * 1024, 16).unwrap(), 64 * 1024);
    assert_eq!(chunk_size(1024 * 1024 * 1024, 16).unwrap(), CHUNK_SIZE);
}
