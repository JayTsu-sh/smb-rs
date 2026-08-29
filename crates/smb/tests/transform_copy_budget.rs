use std::alloc::System;
use std::sync::Arc;

use smb::compression::Compressor;
use smb_msg::{CompressionAlgorithm, CompressionCapabilities, CompressionCapsFlags};
use smb_tests::memory::{TrackingAllocator, measure_memory};

#[global_allocator]
static ALLOCATOR: TrackingAllocator<System> = TrackingAllocator::new(System);

#[tokio::test]
async fn lz4_writes_into_one_payload_sized_final_transform_allocation() {
    let source = vec![0x5a; 1024 * 1024];
    let compressor = Compressor::new(&Arc::new(CompressionCapabilities {
        flags: CompressionCapsFlags::new().with_chained(true),
        compression_algorithms: vec![CompressionAlgorithm::LZ4],
    }));
    let (_, harness) = measure_memory(async {}).await;

    let (transformed, report) =
        measure_memory(async { compressor.compress_transform(&source, 52).unwrap() }).await;
    let allocated = report
        .allocated_bytes
        .saturating_sub(harness.allocated_bytes);

    assert_eq!(&transformed[52..56], b"\xfcSMB");
    assert_eq!(
        report.reallocations, 0,
        "final arena must not grow: {report:?}"
    );
    assert!(
        allocated >= source.len() as u64,
        "final transform arena must be allocation-accounted: {report:?}",
    );
    assert!(
        allocated < (source.len() * 2) as u64,
        "compression must not allocate a second payload-sized output: {report:?}",
    );
}
