use std::alloc::System;

use bytes::Bytes;
use smb_msg::{FileId, PlainRequest, WireBuilder, WriteFlags, WriteRequest};
use smb_tests::memory::{TrackingAllocator, measure_memory, record_payload_copy};

#[global_allocator]
static ALLOCATOR: TrackingAllocator<System> = TrackingAllocator::new(System);

fn request(length: usize) -> PlainRequest {
    PlainRequest::new(WriteRequest::new(0, FileId::EMPTY, WriteFlags::new(), length as u32).into())
}

#[tokio::test]
async fn bytes_write_seals_without_payload_copy_or_payload_sized_allocation() {
    let payload = Bytes::from(vec![0x5a; 1024 * 1024]);
    let payload_pointer = payload.as_ptr();
    let payload_len = payload.len();
    let (_, harness) = measure_memory(async {}).await;

    let mut request = request(payload_len);
    let (message, report) = measure_memory(async move {
        let mut builder = WireBuilder::encode(std::iter::once(&mut request), 2).unwrap();
        builder.attach_payload(payload).unwrap();
        builder.finalize_offsets().unwrap();
        builder.finish_unsigned().unwrap();
        builder.seal().unwrap()
    })
    .await;

    assert_eq!(report.payload_copies, 0);
    assert!(
        report.allocations.saturating_sub(harness.allocations) <= 4,
        "Bytes write metadata allocation budget exceeded: {report:?}",
    );
    assert!(
        report.allocated_bytes < payload_len as u64,
        "metadata allocations must stay below one payload-sized allocation: {report:?}",
    );
    assert_eq!(message.segments().nth(1).unwrap().as_ptr(), payload_pointer);
}

#[tokio::test]
async fn slice_write_records_its_only_payload_copy_at_the_api_boundary() {
    let source = vec![0x5a; 64 * 1024];
    let source_pointer = source.as_ptr();

    let (message, report) = measure_memory(async {
        record_payload_copy(source.len());
        let payload = Bytes::copy_from_slice(&source);
        let mut request = request(payload.len());
        let mut builder = WireBuilder::encode(std::iter::once(&mut request), 2).unwrap();
        builder.attach_payload(payload).unwrap();
        builder.finalize_offsets().unwrap();
        builder.finish_unsigned().unwrap();
        builder.seal().unwrap()
    })
    .await;

    assert_eq!(report.payload_copies, 1);
    assert_eq!(report.payload_copied_bytes, source.len() as u64);
    assert_ne!(message.segments().nth(1).unwrap().as_ptr(), source_pointer);
}

#[tokio::test]
async fn transform_transition_allocates_exactly_one_final_contiguous_arena() {
    let payload = Bytes::from(vec![0x3c; 1024 * 1024]);
    let mut request = request(payload.len());
    let mut builder = WireBuilder::encode(std::iter::once(&mut request), 2).unwrap();
    builder.attach_payload(payload).unwrap();
    builder.finalize_offsets().unwrap();
    builder.finish_unsigned().unwrap();
    let message = builder.seal().unwrap();
    let expected = message.total_len() + 52;
    let (_, harness) = measure_memory(async {}).await;

    let (arena, report) = measure_memory(async move { message.into_contiguous(52).unwrap() }).await;

    assert_eq!(arena.len(), expected);
    assert_eq!(
        report.reallocations, 0,
        "transform arena must not grow: {report:?}"
    );
    assert_eq!(
        report
            .allocated_bytes
            .saturating_sub(harness.allocated_bytes),
        expected as u64,
        "transform transition must allocate only its final arena: {report:?}",
    );
}
