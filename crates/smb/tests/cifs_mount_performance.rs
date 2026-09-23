//! Compares the public smb-rs data path with a kernel-mounted CIFS path.
//!
//! The mount must target the same share as the smb-rs connection and use
//! `cache=none`, so both paths measure remote I/O instead of Linux page cache.

#![cfg(feature = "real-server-tests")]

mod common;

use bytes::Bytes;
use futures_util::future::try_join_all;
use serde_json::json;
use smb::{Client, File, FileOpenOptions, SharePath, ShareTarget};
use std::{
    env,
    error::Error,
    fs::{self, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

const PAYLOADS: [usize; 3] = [4 * 1024, 40 * 1024 * 1024, 1024 * 1024 * 1024];
const DEFAULT_MINIMUM_TRANSFER_BYTES: usize = 16 * 1024 * 1024;
const DEFAULT_SAMPLES: usize = 3;
const DEFAULT_INFLIGHT: usize = 16;

type BenchResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

#[derive(Clone, Copy)]
enum DataPath {
    SmbRs,
    KernelMount,
}

impl DataPath {
    const fn label(self) -> &'static str {
        match self {
            Self::SmbRs => "smb-rs",
            Self::KernelMount => "kernel-mount",
        }
    }
}

#[derive(Clone, Copy)]
enum Direction {
    Write,
    Read,
}

impl Direction {
    const fn label(self) -> &'static str {
        match self {
            Self::Write => "write",
            Self::Read => "read",
        }
    }
}

#[derive(Default)]
struct DirectionSamples {
    seconds: Vec<f64>,
    throughput: Vec<f64>,
}

#[derive(Default)]
struct PathSamples {
    write: DirectionSamples,
    read: DirectionSamples,
}

#[test_log::test(tokio::test(flavor = "multi_thread"))]
#[ignore = "requires release mode, a writable CIFS share, and the same share mounted with cache=none"]
async fn compare_smb_rs_with_kernel_cifs_mount() -> BenchResult<()> {
    if cfg!(debug_assertions) {
        return Err("performance comparison must run with --release".into());
    }

    let mount_root = required_mount_root()?;
    validate_uncached_cifs_mount(&mount_root)?;
    let target = env::var("SMB_RUST_PERF_TARGET_LABEL")
        .map_err(|_| "SMB_RUST_PERF_TARGET_LABEL is required")?;
    let samples = positive_env("SMB_RUST_PERF_SAMPLES", DEFAULT_SAMPLES)?;
    let minimum_transfer = positive_env(
        "SMB_RUST_PERF_MINIMUM_TRANSFER_BYTES",
        DEFAULT_MINIMUM_TRANSFER_BYTES,
    )?;
    let inflight = positive_env("SMB_RUST_PERF_INFLIGHT", DEFAULT_INFLIGHT)?;
    let payloads = payloads_from_env()?;

    let client = Client::new();
    let share = client
        .connect_share(
            &ShareTarget::new(common::smb_tests_server(), common::smb_tests_share())?,
            common::smb_test_credentials(),
        )
        .await?;
    let suffix = format!("{}-{:08x}", std::process::id(), rand::random::<u32>());
    let smb_path = SharePath::new(format!("smb-rs-perf-{suffix}.bin"))?;
    let mount_path = mount_root.join(format!("kernel-cifs-perf-{suffix}.bin"));
    let smb_file = share
        .open_file(&smb_path, FileOpenOptions::overwrite())
        .await?;
    let mut mount_file = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&mount_path)?;

    let benchmark = run_matrix(
        &target,
        &smb_file,
        &mut mount_file,
        samples,
        minimum_transfer,
        inflight,
        &payloads,
    )
    .await;

    let smb_delete = smb_file.delete().await;
    let smb_close = smb_file.close().await;
    drop(mount_file);
    let mount_delete = fs::remove_file(&mount_path);
    let share_close = share.close().await;
    let client_close = client.close().await;

    benchmark?;
    smb_delete?;
    smb_close?;
    mount_delete?;
    share_close?;
    client_close?;
    Ok(())
}

async fn run_matrix(
    target: &str,
    smb_file: &File,
    mount_file: &mut fs::File,
    samples: usize,
    minimum_transfer: usize,
    inflight: usize,
    payloads: &[usize],
) -> BenchResult<()> {
    let capabilities = smb_file.io_capabilities();
    for &payload_bytes in payloads {
        let repetitions = minimum_transfer.div_ceil(payload_bytes).max(1);
        let smb_chunk = payload_bytes.min(capabilities.maximum_write_chunk() as usize);
        let smb_read_chunk = payload_bytes.min(capabilities.maximum_read_chunk() as usize);
        let mount_chunk = payload_bytes.min(smb_chunk).min(smb_read_chunk);
        if !payload_bytes.is_multiple_of(smb_chunk)
            || !payload_bytes.is_multiple_of(smb_read_chunk)
            || !payload_bytes.is_multiple_of(mount_chunk)
        {
            return Err("payload must divide evenly into negotiated chunks".into());
        }
        let pattern = Bytes::from(vec![pattern_byte(payload_bytes); smb_chunk]);
        let mount_pattern = vec![pattern_byte(payload_bytes); mount_chunk];
        mount_file.set_len(payload_bytes as u64)?;

        let mut smb_samples = PathSamples::default();
        let mut mount_samples = PathSamples::default();
        for sample in 0..=samples {
            let warmup = sample == 0;
            if sample % 2 == 0 {
                measure_smb(
                    target,
                    smb_file,
                    payload_bytes,
                    repetitions,
                    inflight,
                    smb_read_chunk,
                    &pattern,
                    sample,
                    warmup,
                    &mut smb_samples,
                )
                .await?;
                measure_mount(
                    target,
                    mount_file,
                    payload_bytes,
                    repetitions,
                    &mount_pattern,
                    sample,
                    warmup,
                    &mut mount_samples,
                )?;
            } else {
                measure_mount(
                    target,
                    mount_file,
                    payload_bytes,
                    repetitions,
                    &mount_pattern,
                    sample,
                    warmup,
                    &mut mount_samples,
                )?;
                measure_smb(
                    target,
                    smb_file,
                    payload_bytes,
                    repetitions,
                    inflight,
                    smb_read_chunk,
                    &pattern,
                    sample,
                    warmup,
                    &mut smb_samples,
                )
                .await?;
            }
        }
        print_summary(
            target,
            DataPath::SmbRs,
            payload_bytes,
            repetitions,
            &smb_samples,
        );
        print_summary(
            target,
            DataPath::KernelMount,
            payload_bytes,
            repetitions,
            &mount_samples,
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn measure_smb(
    target: &str,
    file: &File,
    payload_bytes: usize,
    repetitions: usize,
    inflight: usize,
    read_chunk: usize,
    pattern: &Bytes,
    sample: usize,
    warmup: bool,
    samples: &mut PathSamples,
) -> BenchResult<()> {
    let started = Instant::now();
    for _ in 0..repetitions {
        smb_write(file, payload_bytes, inflight, pattern).await?;
    }
    file.flush().await?;
    record_sample(
        target,
        DataPath::SmbRs,
        Direction::Write,
        payload_bytes,
        repetitions,
        sample,
        warmup,
        started.elapsed().as_secs_f64(),
        &mut samples.write,
    );

    let started = Instant::now();
    for _ in 0..repetitions {
        smb_read(
            file,
            payload_bytes,
            inflight,
            read_chunk,
            pattern_byte(payload_bytes),
        )
        .await?;
    }
    record_sample(
        target,
        DataPath::SmbRs,
        Direction::Read,
        payload_bytes,
        repetitions,
        sample,
        warmup,
        started.elapsed().as_secs_f64(),
        &mut samples.read,
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn measure_mount(
    target: &str,
    file: &mut fs::File,
    payload_bytes: usize,
    repetitions: usize,
    pattern: &[u8],
    sample: usize,
    warmup: bool,
    samples: &mut PathSamples,
) -> BenchResult<()> {
    let started = Instant::now();
    for _ in 0..repetitions {
        file.seek(SeekFrom::Start(0))?;
        for _ in (0..payload_bytes).step_by(pattern.len()) {
            file.write_all(pattern)?;
        }
    }
    file.sync_all()?;
    record_sample(
        target,
        DataPath::KernelMount,
        Direction::Write,
        payload_bytes,
        repetitions,
        sample,
        warmup,
        started.elapsed().as_secs_f64(),
        &mut samples.write,
    );

    let expected = pattern_byte(payload_bytes);
    let mut buffer = vec![0; pattern.len()];
    let started = Instant::now();
    for _ in 0..repetitions {
        file.seek(SeekFrom::Start(0))?;
        for _ in (0..payload_bytes).step_by(buffer.len()) {
            file.read_exact(&mut buffer)?;
            if buffer.iter().any(|byte| *byte != expected) {
                return Err("kernel CIFS read-back mismatch".into());
            }
        }
    }
    record_sample(
        target,
        DataPath::KernelMount,
        Direction::Read,
        payload_bytes,
        repetitions,
        sample,
        warmup,
        started.elapsed().as_secs_f64(),
        &mut samples.read,
    );
    Ok(())
}

async fn smb_write(
    file: &File,
    payload_bytes: usize,
    inflight: usize,
    pattern: &Bytes,
) -> smb::Result<()> {
    let window = pattern.len() * inflight;
    for first in (0..payload_bytes).step_by(window) {
        let last = (first + window).min(payload_bytes);
        try_join_all((first..last).step_by(pattern.len()).map(|offset| {
            file.write_all_at(offset as u64, pattern.clone())
                .timeout(Duration::from_secs(60))
        }))
        .await?;
    }
    Ok(())
}

async fn smb_read(
    file: &File,
    payload_bytes: usize,
    inflight: usize,
    chunk: usize,
    expected: u8,
) -> smb::Result<()> {
    let window = chunk * inflight;
    for first in (0..payload_bytes).step_by(window) {
        let last = (first + window).min(payload_bytes);
        let chunks = try_join_all((first..last).step_by(chunk).map(|offset| {
            file.read_exact_at(offset as u64, chunk as u32)
                .timeout(Duration::from_secs(60))
        }))
        .await?;
        if chunks
            .iter()
            .any(|actual| actual.len() != chunk || actual.iter().any(|byte| *byte != expected))
        {
            return Err(smb::Error::InvalidMessage(
                "smb-rs performance read-back mismatch".into(),
            ));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn record_sample(
    target: &str,
    data_path: DataPath,
    direction: Direction,
    payload_bytes: usize,
    repetitions: usize,
    sample: usize,
    warmup: bool,
    seconds: f64,
    samples: &mut DirectionSamples,
) {
    let transferred_bytes = payload_bytes * repetitions;
    let throughput = mib_per_second(transferred_bytes, seconds);
    println!(
        "PERF_RECORD {}",
        json!({
            "record_type": "sample",
            "target": target,
            "data_path": data_path.label(),
            "direction": direction.label(),
            "payload_bytes": payload_bytes,
            "repetitions": repetitions,
            "transferred_bytes": transferred_bytes,
            "sample": sample,
            "warmup": warmup,
            "seconds": seconds,
            "mib_per_second": throughput,
        })
    );
    if !warmup {
        samples.seconds.push(seconds);
        samples.throughput.push(throughput);
    }
}

fn print_summary(
    target: &str,
    data_path: DataPath,
    payload_bytes: usize,
    repetitions: usize,
    samples: &PathSamples,
) {
    for (direction, samples) in [
        (Direction::Write, &samples.write),
        (Direction::Read, &samples.read),
    ] {
        println!(
            "PERF_RECORD {}",
            json!({
                "record_type": "summary",
                "target": target,
                "data_path": data_path.label(),
                "direction": direction.label(),
                "payload_bytes": payload_bytes,
                "repetitions": repetitions,
                "samples": samples.throughput.len(),
                "median_seconds": percentile(&samples.seconds, 0.50),
                "p95_seconds": percentile(&samples.seconds, 0.95),
                "median_mib_per_second": percentile(&samples.throughput, 0.50),
                "p95_mib_per_second": percentile(&samples.throughput, 0.95),
                "coefficient_of_variation": coefficient_of_variation(&samples.throughput),
            })
        );
    }
}

fn required_mount_root() -> BenchResult<PathBuf> {
    let path =
        env::var("SMB_RUST_PERF_MOUNT_PATH").map_err(|_| "SMB_RUST_PERF_MOUNT_PATH is required")?;
    Ok(fs::canonicalize(path)?)
}

fn validate_uncached_cifs_mount(path: &Path) -> BenchResult<()> {
    let path = path
        .to_str()
        .ok_or("SMB_RUST_PERF_MOUNT_PATH must be valid UTF-8")?;
    let mounts = fs::read_to_string("/proc/self/mounts")?;
    let fields = mounts
        .lines()
        .filter_map(|line| {
            let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
            (fields.len() >= 4 && fields[1] == path).then_some(fields)
        })
        .next()
        .ok_or("performance path is not a distinct mount point")?;
    if fields[2] != "cifs" {
        return Err("performance mount must use the CIFS filesystem".into());
    }
    if !fields[3].split(',').any(|option| option == "cache=none") {
        return Err("performance CIFS mount must use cache=none".into());
    }
    Ok(())
}

fn positive_env(name: &str, default: usize) -> BenchResult<usize> {
    let value = env::var(name)
        .ok()
        .map(|value| value.parse::<usize>())
        .transpose()?
        .unwrap_or(default);
    if value == 0 {
        return Err(format!("{name} must be positive").into());
    }
    Ok(value)
}

fn payloads_from_env() -> BenchResult<Vec<usize>> {
    let Some(value) = env::var("SMB_RUST_PERF_PAYLOAD_BYTES").ok() else {
        return Ok(PAYLOADS.to_vec());
    };
    let payload = value.parse::<usize>()?;
    if !PAYLOADS.contains(&payload) {
        return Err("SMB_RUST_PERF_PAYLOAD_BYTES must be 4096, 41943040, or 1073741824".into());
    }
    Ok(vec![payload])
}

fn pattern_byte(payload_bytes: usize) -> u8 {
    (payload_bytes as u8).wrapping_mul(37).wrapping_add(0x5a)
}

fn mib_per_second(bytes: usize, seconds: f64) -> f64 {
    bytes as f64 / (1024.0 * 1024.0) / seconds
}

fn percentile(values: &[f64], percentile: f64) -> f64 {
    assert!(!values.is_empty());
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    sorted[((sorted.len() as f64 * percentile).ceil() as usize).saturating_sub(1)]
}

fn coefficient_of_variation(values: &[f64]) -> f64 {
    assert!(!values.is_empty());
    let mean = values.iter().sum::<f64>() / values.len() as f64;
    let variance = values
        .iter()
        .map(|value| (value - mean).powi(2))
        .sum::<f64>()
        / values.len() as f64;
    variance.sqrt() / mean
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_payloads_and_small_transfer_repetitions_are_stable() {
        assert_eq!(PAYLOADS, [4096, 41_943_040, 1_073_741_824]);
        assert_eq!(DEFAULT_MINIMUM_TRANSFER_BYTES.div_ceil(PAYLOADS[0]), 4096);
        assert_eq!(DEFAULT_MINIMUM_TRANSFER_BYTES.div_ceil(PAYLOADS[1]), 1);
    }

    #[test]
    fn summary_statistics_use_nearest_rank_and_population_cv() {
        assert_eq!(percentile(&[8.0, 10.0, 9.0, 11.0, 12.0], 0.5), 10.0);
        assert_eq!(percentile(&[8.0, 10.0, 9.0, 11.0, 12.0], 0.95), 12.0);
        assert!(
            (coefficient_of_variation(&[8.0, 10.0, 9.0, 11.0, 12.0]) - 0.141_421_356).abs()
                < 0.000_001
        );
    }
}
