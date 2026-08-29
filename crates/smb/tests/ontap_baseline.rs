//! Explicit real-server data-path baseline.
//!
//! This test is ignored by default because it requires an isolated writable
//! share. Credentials are read through the common runtime environment only.

mod common;

use common::{make_server_connection, smb_tests_share};
use smb::{FileCreateArgs, ReadAt, WriteAt};
use smb_fscc::{FileAccessMask, FileDispositionInformation};
use std::{env, time::Instant};

const IO_CHUNK: usize = 1024 * 1024;

fn configured_sizes() -> Result<Vec<u64>, Box<dyn std::error::Error + Send + Sync>> {
    env::var("SMB_BASELINE_SIZES")
        .unwrap_or_else(|_| "4096,65536,1048576,1073741824".to_string())
        .split(',')
        .map(|value| Ok(value.trim().parse()?))
        .collect()
}

fn pattern_byte(offset: u64) -> u8 {
    ((offset.wrapping_mul(31).wrapping_add(17)) & 0xff) as u8
}

async fn run_stream(
    stream: usize,
    size: u64,
) -> Result<(f64, f64), Box<dyn std::error::Error + Send + Sync>> {
    let share = smb_tests_share();
    let (client, share_path) = make_server_connection(&share, None).await?;
    let path = share_path.with_path(&format!(
        "smb-rs-baseline-{}-{stream}-{size}.bin",
        std::process::id()
    ));
    let file = client
        .create_file(
            &path,
            &FileCreateArgs::make_create_new(Default::default(), Default::default()),
        )
        .await?
        .into_file()?;

    let mut write_buf = vec![0u8; IO_CHUNK.min(size as usize)];
    let write_started = Instant::now();
    let mut offset = 0u64;
    while offset < size {
        let len = write_buf.len().min((size - offset) as usize);
        for (index, byte) in write_buf[..len].iter_mut().enumerate() {
            *byte = pattern_byte(offset + index as u64);
        }
        let mut written = 0usize;
        while written < len {
            let count = file
                .write_at(&write_buf[written..len], offset + written as u64)
                .await?;
            if count == 0 {
                return Err("zero-length SMB write before payload completion".into());
            }
            written += count;
        }
        offset += len as u64;
    }
    let write_seconds = write_started.elapsed().as_secs_f64();
    file.close().await?;

    // Reopen after writing because the current File object retains the EOF
    // value returned by CREATE and does not update it after Write requests.
    let file = client
        .create_file(
            &path,
            &FileCreateArgs::make_open_existing(
                FileAccessMask::new()
                    .with_delete(true)
                    .with_file_read_data(true)
                    .with_file_read_attributes(true),
            ),
        )
        .await?
        .into_file()?;

    let mut read_buf = vec![0u8; IO_CHUNK.min(size as usize)];
    let read_started = Instant::now();
    offset = 0;
    while offset < size {
        let len = read_buf.len().min((size - offset) as usize);
        let mut read = 0usize;
        while read < len {
            let count = file
                .read_at(&mut read_buf[read..len], offset + read as u64)
                .await?;
            if count == 0 {
                return Err("unexpected SMB EOF during baseline verification".into());
            }
            read += count;
        }
        for (index, byte) in read_buf[..len].iter().copied().enumerate() {
            if byte != pattern_byte(offset + index as u64) {
                return Err(format!("payload mismatch at offset {}", offset + index as u64).into());
            }
        }
        offset += len as u64;
    }
    let read_seconds = read_started.elapsed().as_secs_f64();

    file.set_info(FileDispositionInformation {
        delete_pending: true.into(),
    })
    .await?;
    file.close().await?;
    Ok((write_seconds, read_seconds))
}

#[test_log::test(tokio::test(flavor = "multi_thread"))]
#[ignore = "requires an explicitly provisioned writable real-server share"]
async fn ontap_data_path_baseline() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let concurrency: usize = env::var("SMB_BASELINE_CONCURRENCY")
        .unwrap_or_else(|_| "1".to_string())
        .parse()?;
    if concurrency == 0 {
        return Err("SMB_BASELINE_CONCURRENCY must be greater than zero".into());
    }

    println!("size_bytes,streams,write_seconds,read_seconds,write_mib_s,read_mib_s");
    for size in configured_sizes()? {
        let started = Instant::now();
        let results = futures_util::future::try_join_all(
            (0..concurrency).map(|stream| run_stream(stream, size)),
        )
        .await?;
        let elapsed = started.elapsed().as_secs_f64();
        let write_seconds = results.iter().map(|result| result.0).fold(0.0, f64::max);
        let read_seconds = results.iter().map(|result| result.1).fold(0.0, f64::max);
        let total_mib = size as f64 * concurrency as f64 / (1024.0 * 1024.0);
        println!(
            "{size},{concurrency},{write_seconds:.6},{read_seconds:.6},{:.3},{:.3}",
            total_mib / write_seconds,
            total_mib / read_seconds
        );
        eprintln!("baseline wall seconds for {size} x {concurrency}: {elapsed:.6}");
    }
    Ok(())
}
