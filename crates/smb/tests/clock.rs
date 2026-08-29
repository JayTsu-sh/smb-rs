#![cfg(feature = "test-support")]

use futures_util::poll;
use smb::test_support::{Clock, ManualClock, MonotonicTime, TokioClock};
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::Duration;

#[tokio::test]
async fn manual_sleep_completes_only_when_advanced_to_its_deadline() {
    let clock = ManualClock::new();
    let deadline = clock.now().saturating_add(Duration::from_secs(5));
    let mut sleep = std::pin::pin!(clock.sleep_until(deadline));

    assert!(matches!(poll!(&mut sleep), Poll::Pending));
    clock
        .advance(Duration::from_secs(4))
        .await
        .expect("time advances");
    assert!(matches!(poll!(&mut sleep), Poll::Pending));
    clock
        .advance(Duration::from_secs(1))
        .await
        .expect("time reaches deadline");
    sleep.await;
}

#[tokio::test]
async fn cloned_manual_clocks_share_timeline_and_cancelled_sleepers_leave_queue() {
    let clock = ManualClock::new();
    let clone = clock.clone();
    let sleep = clock.sleep_until(clock.now().saturating_add(Duration::from_secs(10)));
    assert_eq!(clock.pending_sleepers(), 1);

    drop(sleep);
    assert_eq!(clone.pending_sleepers(), 0);
    clone
        .advance(Duration::from_secs(3))
        .await
        .expect("clone advances shared clock");
    assert_eq!(
        clock.now(),
        MonotonicTime::ZERO.saturating_add(Duration::from_secs(3))
    );
}

#[tokio::test]
async fn equal_deadlines_wake_in_registration_order() {
    let clock = ManualClock::new();
    let deadline = clock.now().saturating_add(Duration::from_secs(1));
    let first_sleep = clock.sleep_until(deadline);
    let second_sleep = clock.sleep_until(deadline);
    let wake_order = Arc::new(Mutex::new(Vec::new()));

    let first_order = Arc::clone(&wake_order);
    let first = tokio::spawn(async move {
        first_sleep.await;
        first_order.lock().expect("wake order lock").push(1);
    });
    let second_order = Arc::clone(&wake_order);
    let second = tokio::spawn(async move {
        second_sleep.await;
        second_order.lock().expect("wake order lock").push(2);
    });

    clock
        .advance(Duration::from_secs(1))
        .await
        .expect("time reaches equal deadlines");
    first.await.expect("first sleeper joins");
    second.await.expect("second sleeper joins");

    assert_eq!(*wake_order.lock().expect("wake order lock"), vec![1, 2]);
}

#[tokio::test]
async fn manual_clock_rejects_backwards_time_and_saturates_overflow() {
    let clock = ManualClock::new();
    clock
        .advance(Duration::from_secs(2))
        .await
        .expect("time advances");
    assert!(clock.advance_to(MonotonicTime::ZERO).await.is_err());

    clock
        .advance_to(MonotonicTime::MAX)
        .await
        .expect("maximum is representable");
    clock
        .advance(Duration::MAX)
        .await
        .expect("overflow saturates");
    assert_eq!(clock.now(), MonotonicTime::MAX);
}

#[tokio::test(start_paused = true)]
async fn tokio_clock_uses_the_runtime_monotonic_driver() {
    let clock = TokioClock::new();
    let deadline = clock.now().saturating_add(Duration::from_secs(30));
    let sleep = clock.sleep_until(deadline);

    tokio::time::advance(Duration::from_secs(30)).await;
    sleep.await;
}
