//! Explicit real-appliance throughput gate at the public domain seam.

mod common;

use bytes::Bytes;
use futures_util::{StreamExt, future::try_join_all, stream::FuturesUnordered};
use serde_json::json;
use smb::{Client, ClientConfig, File, FileOpenOptions, IoCapabilities, SharePath, ShareTarget};
use std::time::{Duration, Instant};

const MINIMUM_BYTES_PER_SAMPLE: usize = 16 * 1024 * 1024;
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
    write_pattern: Bytes,
    read_chunk: usize,
    fill: u8,
}

struct Measurement {
    write_mib_s: f64,
    read_mib_s: f64,
    capabilities: IoCapabilities,
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
    let chunk_limit = chunk_limit_from_env()?;
    let signing_required = signing_required_from_env()?;
    let repetitions =
        MINIMUM_BYTES_PER_SAMPLE.saturating_add(bytes_per_connection - 1) / bytes_per_connection;

    for shape in selected_shapes()? {
        let mut writes = Vec::with_capacity(MEASURED_SAMPLES);
        let mut reads = Vec::with_capacity(MEASURED_SAMPLES);
        let mut capabilities = None;
        for sample in 0..=MEASURED_SAMPLES {
            let measured = run_sample(
                shape,
                bytes_per_connection,
                repetitions,
                sample,
                chunk_limit,
                signing_required,
            )
            .await?;
            if capabilities
                .replace(measured.capabilities)
                .is_some_and(|previous| previous != measured.capabilities)
            {
                return Err(smb::Error::InvalidMessage(
                    "negotiated I/O capabilities changed between samples".into(),
                ));
            }
            if sample != 0 {
                writes.push(measured.write_mib_s);
                reads.push(measured.read_mib_s);
            }
        }
        let capabilities = capabilities.expect("at least the warm-up sample ran");
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
                "repetitions_per_sample": repetitions,
                "requested_chunk_limit": chunk_limit,
                "signing_required": signing_required,
                "negotiated_maximum_read_chunk": capabilities.maximum_read_chunk(),
                "negotiated_maximum_write_chunk": capabilities.maximum_write_chunk(),
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

#[test_log::test(tokio::test(flavor = "multi_thread"))]
#[ignore = "requires release mode and an isolated real-server performance share"]
async fn signed_4k_multi_file_single_connection() -> smb::Result<()> {
    if cfg!(debug_assertions) {
        return Err(smb::Error::InvalidArgument(
            "the performance hard gate must run with --release".into(),
        ));
    }

    const FILES: usize = 16;
    const REPETITIONS: usize = MINIMUM_BYTES_PER_SAMPLE / (FILES * 4096);
    let client = Client::with_config(ClientConfig {
        signing_required: true,
    });
    let share = client
        .connect_share(
            &ShareTarget::new(common::smb_tests_server(), common::smb_tests_share())?,
            common::smb_test_credentials(),
        )
        .await?;
    let suffix = format!("{}-{:08x}", std::process::id(), rand::random::<u32>());
    let mut files = Vec::with_capacity(FILES);
    for index in 0..FILES {
        let path = SharePath::new(format!("driver-multifile-{suffix}-{index}.bin"))?;
        match share.open_file(&path, FileOpenOptions::overwrite()).await {
            Ok(file) => files.push(file),
            Err(error) => {
                for file in files {
                    let _ = file.delete().await;
                    let _ = file.close().await;
                }
                let _ = client.close().await;
                return Err(error);
            }
        }
    }
    let pattern = Bytes::from(vec![0x6d; 4096]);

    let measured = async {
        let mut writes = Vec::with_capacity(MEASURED_SAMPLES);
        let mut reads = Vec::with_capacity(MEASURED_SAMPLES);
        for sample in 0..=MEASURED_SAMPLES {
            let started = Instant::now();
            for _ in 0..REPETITIONS {
                try_join_all(files.iter().map(|file| {
                    file.write_all_at(0, pattern.clone())
                        .timeout(Duration::from_secs(30))
                }))
                .await?;
            }
            let write_seconds = started.elapsed().as_secs_f64();

            let started = Instant::now();
            for _ in 0..REPETITIONS {
                let contents = try_join_all(
                    files
                        .iter()
                        .map(|file| file.read_exact_at(0, 4096).timeout(Duration::from_secs(30))),
                )
                .await?;
                if contents.iter().any(|actual| actual != &pattern) {
                    return Err(smb::Error::InvalidMessage(
                        "multi-file performance read verification failed".into(),
                    ));
                }
            }
            let read_seconds = started.elapsed().as_secs_f64();
            if sample != 0 {
                let mib = (FILES * 4096 * REPETITIONS) as f64 / (1024.0 * 1024.0);
                writes.push(mib / write_seconds);
                reads.push(mib / read_seconds);
            }
        }
        smb::Result::Ok((statistics(&writes), statistics(&reads)))
    }
    .await;

    let cleanup = async {
        let mut first_error = None;
        for file in files {
            if let Err(error) = file.delete().await
                && first_error.is_none()
            {
                first_error = Some(error);
            }
            if let Err(error) = file.close().await
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        }
        if let Err(error) = client.close().await
            && first_error.is_none()
        {
            first_error = Some(error);
        }
        first_error.map_or(Ok(()), Err)
    }
    .await;

    let (write, read) = measured?;
    cleanup?;
    println!(
        "{}",
        json!({
            "mode": "signed-4k-multi-file",
            "connections": 1,
            "files": FILES,
            "inflight_per_connection": FILES,
            "payload_bytes": 4096,
            "repetitions_per_sample": REPETITIONS,
            "measured_samples": MEASURED_SAMPLES,
            "write_mib_s": { "median": write.median, "p95": write.p95, "cv": write.cv },
            "read_mib_s": { "median": read.median, "p95": read.p95, "cv": read.cv },
        })
    );
    require_stable("multi-file write", &write)?;
    require_stable("multi-file read", &read)?;
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
    if bytes == 0 {
        return Err(smb::Error::InvalidArgument(
            "performance payload must be non-zero".into(),
        ));
    }
    Ok(bytes)
}

fn chunk_limit_from_env() -> smb::Result<Option<usize>> {
    let chunk_limit = std::env::var("SMB_RUST_PERF_CHUNK_BYTES")
        .ok()
        .map(|value| value.parse::<usize>())
        .transpose()
        .map_err(|_| smb::Error::InvalidArgument("invalid performance chunk size".into()))?;
    if chunk_limit == Some(0) {
        return Err(smb::Error::InvalidArgument(
            "performance chunk size must be non-zero".into(),
        ));
    }
    Ok(chunk_limit)
}

fn signing_required_from_env() -> smb::Result<bool> {
    match std::env::var("SMB_RUST_PERF_SIGNING_REQUIRED").as_deref() {
        Err(_) | Ok("false") => Ok(false),
        Ok("true") => Ok(true),
        Ok(_) => Err(smb::Error::InvalidArgument(
            "SMB_RUST_PERF_SIGNING_REQUIRED must be true or false".into(),
        )),
    }
}

async fn run_sample(
    shape: Shape,
    bytes_per_connection: usize,
    repetitions: usize,
    sample: usize,
    chunk_limit: Option<usize>,
    signing_required: bool,
) -> smb::Result<Measurement> {
    let mut streams = Vec::with_capacity(shape.connections);
    let mut negotiated_capabilities = None;
    for connection in 0..shape.connections {
        let client = Client::with_config(ClientConfig { signing_required });
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
        let capabilities = file.io_capabilities();
        if negotiated_capabilities
            .replace(capabilities)
            .is_some_and(|previous| previous != capabilities)
        {
            return Err(smb::Error::InvalidMessage(
                "connections negotiated different I/O capabilities".into(),
            ));
        }
        let write_chunk = chunk_size(
            capabilities.maximum_write_chunk(),
            bytes_per_connection,
            shape.inflight_per_connection,
            chunk_limit,
        )?;
        let read_chunk = chunk_size(
            capabilities.maximum_read_chunk(),
            bytes_per_connection,
            shape.inflight_per_connection,
            chunk_limit,
        )?;
        let fill = (connection as u8).wrapping_mul(37);
        streams.push(Stream {
            client,
            file,
            write_pattern: Bytes::from(vec![fill; write_chunk]),
            read_chunk,
            fill,
        });
    }

    let transfer = async {
        let started = Instant::now();
        for _ in 0..repetitions {
            try_join_all(streams.iter().map(|stream| {
                write_windowed(stream, bytes_per_connection, shape.inflight_per_connection)
            }))
            .await?;
        }
        let write_seconds = started.elapsed().as_secs_f64();

        let started = Instant::now();
        for _ in 0..repetitions {
            try_join_all(streams.iter().map(|stream| {
                read_windowed(stream, bytes_per_connection, shape.inflight_per_connection)
            }))
            .await?;
        }
        smb::Result::Ok((write_seconds, started.elapsed().as_secs_f64()))
    }
    .await;

    let cleanup = cleanup_streams(streams).await;
    let (write_seconds, read_seconds) = match (transfer, cleanup) {
        (Ok(timings), Ok(())) => timings,
        (Err(error), _) => return Err(error),
        (Ok(_), Err(error)) => return Err(error),
    };
    let mib = (bytes_per_connection * shape.connections * repetitions) as f64 / (1024.0 * 1024.0);
    Ok(Measurement {
        write_mib_s: mib / write_seconds,
        read_mib_s: mib / read_seconds,
        capabilities: negotiated_capabilities.expect("at least one connection was created"),
    })
}

fn chunk_size(
    negotiated_maximum: u32,
    bytes_per_connection: usize,
    inflight: usize,
    chunk_limit: Option<usize>,
) -> smb::Result<usize> {
    let chunk_size = negotiated_maximum as usize;
    let chunk_size = chunk_size.min(chunk_limit.unwrap_or(usize::MAX));
    let chunk_size = chunk_size.min(bytes_per_connection / inflight.max(1));
    if chunk_size == 0 || !bytes_per_connection.is_multiple_of(chunk_size) {
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
    let chunk_size = stream.write_pattern.len();
    for first in (0..bytes_per_connection).step_by(chunk_size * inflight) {
        let last = (first + chunk_size * inflight).min(bytes_per_connection);
        try_join_all((first..last).step_by(chunk_size).map(|offset| {
            stream
                .file
                .write_all_at(offset as u64, stream.write_pattern.clone())
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
    let chunk_size = stream.read_chunk;
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
            let actual = actual?;
            if actual.len() != chunk_size || actual.iter().any(|byte| *byte != stream.fill) {
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
    let negotiated = 1024 * 1024;
    assert_eq!(
        chunk_size(negotiated, 64 * 1024, 16, None).unwrap(),
        4 * 1024
    );
    assert_eq!(
        chunk_size(negotiated, 1024 * 1024, 16, None).unwrap(),
        64 * 1024
    );
    assert_eq!(
        chunk_size(negotiated, 1024 * 1024 * 1024, 16, None).unwrap(),
        negotiated as usize
    );
    assert_eq!(
        chunk_size(negotiated, 1024 * 1024, 1, Some(256 * 1024)).unwrap(),
        256 * 1024
    );
}
