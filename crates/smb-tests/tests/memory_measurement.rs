use smb_tests::memory::{RetainedPayload, TrackingAllocator, measure_memory, record_payload_copy};
use std::alloc::System;

#[global_allocator]
static ALLOCATOR: TrackingAllocator<System> = TrackingAllocator::new(System);

#[tokio::test]
async fn allocation_scope_reports_allocated_and_released_bytes() {
    let (_, report) = measure_memory(async {
        let payload = Box::new([0x5au8; 4096]);
        std::hint::black_box(&payload);
        drop(payload);
    })
    .await;

    assert!(report.allocations >= 1);
    assert!(report.allocated_bytes >= 4096);
    assert!(report.peak_live_bytes >= 4096);
    assert_eq!(report.live_bytes, 0);
}

#[tokio::test]
async fn retained_payload_move_and_drop_settle_exactly_once() {
    let (_, report) = measure_memory(async {
        let payload = RetainedPayload::new(8192);
        let moved = payload;
        assert_eq!(moved.bytes(), 8192);
        drop(moved);
    })
    .await;

    assert_eq!(report.retained_payload_peak_bytes, 8192);
    assert_eq!(report.retained_payload_bytes, 0);
}

#[tokio::test]
async fn payload_copy_events_are_attributed_to_the_active_scope() {
    let (_, report) = measure_memory(async {
        record_payload_copy(4096);
        record_payload_copy(64);
    })
    .await;

    assert_eq!(report.payload_copies, 2);
    assert_eq!(report.payload_copied_bytes, 4160);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_scopes_do_not_attribute_each_others_payload() {
    let (left, right) = tokio::join!(
        measure_memory(async {
            let payload = RetainedPayload::new(1024);
            tokio::task::yield_now().await;
            drop(payload);
        }),
        measure_memory(async {
            let payload = RetainedPayload::new(4096);
            tokio::task::yield_now().await;
            drop(payload);
        })
    );

    assert_eq!(left.1.retained_payload_peak_bytes, 1024);
    assert_eq!(right.1.retained_payload_peak_bytes, 4096);
}

#[tokio::test]
async fn nested_scope_temporarily_replaces_outer_attribution() {
    let (_, outer) = measure_memory(async {
        let outer_payload = RetainedPayload::new(1024);
        let (_, inner) = measure_memory(async {
            let inner_payload = RetainedPayload::new(2048);
            drop(inner_payload);
        })
        .await;
        assert_eq!(inner.retained_payload_peak_bytes, 2048);
        drop(outer_payload);
    })
    .await;

    assert_eq!(outer.retained_payload_peak_bytes, 1024);
    assert_eq!(outer.retained_payload_bytes, 0);
}

#[tokio::test]
async fn reallocation_is_counted_and_released_without_live_byte_underflow() {
    let (_, report) = measure_memory(async {
        let mut payload = Vec::with_capacity(8);
        payload.extend_from_slice(b"12345678");
        payload.reserve_exact(4096);
        std::hint::black_box(&payload);
        drop(payload);
    })
    .await;

    assert!(report.reallocations >= 1);
    assert!(report.allocated_bytes >= 4096);
    assert_eq!(report.live_bytes, 0);
}

#[tokio::test]
async fn freeing_an_outer_allocation_inside_a_scope_saturates_at_zero() {
    let allocation = Box::new([0u8; 512]);
    let (_, report) = measure_memory(async move {
        drop(allocation);
    })
    .await;

    assert_eq!(report.live_bytes, 0);
    assert!(report.deallocated_bytes >= 512);
}

#[tokio::test]
async fn report_has_stable_machine_readable_field_names() {
    let (_, report) = measure_memory(async {}).await;
    let value = serde_json::to_value(report).expect("memory report serializes");

    assert!(value.get("allocations").is_some());
    assert!(value.get("reallocations").is_some());
    assert!(value.get("allocated_bytes").is_some());
    assert!(value.get("deallocated_bytes").is_some());
    assert!(value.get("live_bytes").is_some());
    assert!(value.get("peak_live_bytes").is_some());
    assert!(value.get("retained_payload_bytes").is_some());
    assert!(value.get("retained_payload_peak_bytes").is_some());
    assert!(value.get("payload_copies").is_some());
    assert!(value.get("payload_copied_bytes").is_some());
}
