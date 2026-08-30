//! Task-scoped memory accounting for tests and benchmarks.

use serde::Serialize;
use std::alloc::{GlobalAlloc, Layout};
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

tokio::task_local! {
    static CURRENT_MEASUREMENT: Arc<MemoryCounters>;
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct MemoryReport {
    pub payload_copies: u64,
    pub payload_copied_bytes: u64,
    pub allocations: u64,
    pub reallocations: u64,
    pub allocated_bytes: u64,
    pub deallocated_bytes: u64,
    pub live_bytes: u64,
    pub peak_live_bytes: u64,
    pub retained_payload_bytes: u64,
    pub retained_payload_peak_bytes: u64,
}

#[derive(Debug, Default)]
struct MemoryCounters {
    payload_copies: AtomicU64,
    payload_copied_bytes: AtomicU64,
    allocations: AtomicU64,
    reallocations: AtomicU64,
    allocated_bytes: AtomicU64,
    deallocated_bytes: AtomicU64,
    live_bytes: AtomicU64,
    peak_live_bytes: AtomicU64,
    retained_payload_bytes: AtomicU64,
    retained_payload_peak_bytes: AtomicU64,
}

impl MemoryCounters {
    fn add_payload_copy(&self, bytes: usize) {
        self.payload_copies.fetch_add(1, Ordering::Relaxed);
        self.payload_copied_bytes
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }

    fn add_allocation(&self, bytes: usize) {
        let bytes = bytes as u64;
        self.allocations.fetch_add(1, Ordering::Relaxed);
        self.allocated_bytes.fetch_add(bytes, Ordering::Relaxed);
        let live = self.live_bytes.fetch_add(bytes, Ordering::Relaxed) + bytes;
        update_peak(&self.peak_live_bytes, live);
    }

    fn add_deallocation(&self, bytes: usize) {
        let bytes = bytes as u64;
        self.deallocated_bytes.fetch_add(bytes, Ordering::Relaxed);
        saturating_sub(&self.live_bytes, bytes);
    }

    fn add_reallocation(&self, old_bytes: usize, new_bytes: usize) {
        self.reallocations.fetch_add(1, Ordering::Relaxed);
        self.allocated_bytes
            .fetch_add(new_bytes as u64, Ordering::Relaxed);
        self.deallocated_bytes
            .fetch_add(old_bytes as u64, Ordering::Relaxed);
        saturating_sub(&self.live_bytes, old_bytes as u64);
        let live = self
            .live_bytes
            .fetch_add(new_bytes as u64, Ordering::Relaxed)
            + new_bytes as u64;
        update_peak(&self.peak_live_bytes, live);
    }

    fn retain_payload(&self, bytes: u64) {
        let retained = self
            .retained_payload_bytes
            .fetch_add(bytes, Ordering::Relaxed)
            + bytes;
        update_peak(&self.retained_payload_peak_bytes, retained);
    }

    fn release_payload(&self, bytes: u64) {
        saturating_sub(&self.retained_payload_bytes, bytes);
    }

    fn report(&self) -> MemoryReport {
        MemoryReport {
            payload_copies: self.payload_copies.load(Ordering::Relaxed),
            payload_copied_bytes: self.payload_copied_bytes.load(Ordering::Relaxed),
            allocations: self.allocations.load(Ordering::Relaxed),
            reallocations: self.reallocations.load(Ordering::Relaxed),
            allocated_bytes: self.allocated_bytes.load(Ordering::Relaxed),
            deallocated_bytes: self.deallocated_bytes.load(Ordering::Relaxed),
            live_bytes: self.live_bytes.load(Ordering::Relaxed),
            peak_live_bytes: self.peak_live_bytes.load(Ordering::Relaxed),
            retained_payload_bytes: self.retained_payload_bytes.load(Ordering::Relaxed),
            retained_payload_peak_bytes: self.retained_payload_peak_bytes.load(Ordering::Relaxed),
        }
    }
}

fn update_peak(peak: &AtomicU64, candidate: u64) {
    let mut observed = peak.load(Ordering::Relaxed);
    while candidate > observed {
        match peak.compare_exchange_weak(observed, candidate, Ordering::Relaxed, Ordering::Relaxed)
        {
            Ok(_) => return,
            Err(actual) => observed = actual,
        }
    }
}

fn saturating_sub(value: &AtomicU64, amount: u64) {
    let _ = value.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        Some(current.saturating_sub(amount))
    });
}

fn with_current_measurement(action: impl FnOnce(&MemoryCounters)) {
    let _ = CURRENT_MEASUREMENT.try_with(|counters| action(counters));
}

/// Run one future with task-local memory attribution.
pub async fn measure_memory<F>(future: F) -> (F::Output, MemoryReport)
where
    F: Future,
{
    let counters = Arc::new(MemoryCounters::default());
    let output = CURRENT_MEASUREMENT
        .scope(Arc::clone(&counters), future)
        .await;
    (output, counters.report())
}

/// Record one project-owned duplication of file payload bytes.
pub fn record_payload_copy(bytes: usize) {
    with_current_measurement(|counters| counters.add_payload_copy(bytes));
}

/// Owned accounting guard for payload bytes retained by an operation/window.
pub struct RetainedPayload {
    bytes: u64,
    counters: Option<Arc<MemoryCounters>>,
}

impl RetainedPayload {
    pub fn new(bytes: usize) -> Self {
        let counters = CURRENT_MEASUREMENT.try_with(Arc::clone).ok();
        if let Some(counters) = &counters {
            counters.retain_payload(bytes as u64);
        }
        Self {
            bytes: bytes as u64,
            counters,
        }
    }

    pub fn bytes(&self) -> usize {
        self.bytes as usize
    }
}

impl Drop for RetainedPayload {
    fn drop(&mut self) {
        if let Some(counters) = &self.counters {
            counters.release_payload(self.bytes);
        }
    }
}

/// Global allocator wrapper that attributes memory traffic to the active task.
pub struct TrackingAllocator<A> {
    inner: A,
}

impl<A> TrackingAllocator<A> {
    pub const fn new(inner: A) -> Self {
        Self { inner }
    }
}

// SAFETY: every operation delegates to `A` with the original pointer/layout
// contract. Accounting touches only atomics and never changes allocator output.
unsafe impl<A: GlobalAlloc> GlobalAlloc for TrackingAllocator<A> {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: delegated with the caller-provided valid layout.
        let pointer = unsafe { self.inner.alloc(layout) };
        if !pointer.is_null() {
            with_current_measurement(|counters| counters.add_allocation(layout.size()));
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: delegated with the caller-provided valid layout.
        let pointer = unsafe { self.inner.alloc_zeroed(layout) };
        if !pointer.is_null() {
            with_current_measurement(|counters| counters.add_allocation(layout.size()));
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        with_current_measurement(|counters| counters.add_deallocation(layout.size()));
        // SAFETY: delegated with the original allocation pointer and layout.
        unsafe { self.inner.dealloc(pointer, layout) };
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: delegated with the original allocation pointer/layout and a
        // caller-provided replacement size.
        let replacement = unsafe { self.inner.realloc(pointer, layout, new_size) };
        if !replacement.is_null() {
            with_current_measurement(|counters| counters.add_reallocation(layout.size(), new_size));
        }
        replacement
    }
}
