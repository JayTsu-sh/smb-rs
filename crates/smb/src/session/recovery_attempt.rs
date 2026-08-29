use crate::clock::Clock;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AttemptTimedOut;

pub(crate) async fn run_bounded_attempt<T>(
    clock: Arc<dyn Clock>,
    timeout: Duration,
    attempt: impl Future<Output = T>,
) -> Result<T, AttemptTimedOut> {
    let deadline = clock.now().saturating_add(timeout);
    tokio::pin!(attempt);
    tokio::select! {
        result = &mut attempt => Ok(result),
        _ = clock.sleep_until(deadline) => Err(AttemptTimedOut),
    }
}

#[cfg(all(test, feature = "test-support"))]
mod tests {
    use super::*;
    use crate::clock::ManualClock;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct DropWitness(Arc<AtomicBool>);

    impl Drop for DropWitness {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn manual_deadline_cancels_the_exact_pending_attempt() {
        let clock = Arc::new(ManualClock::new());
        let dropped = Arc::new(AtomicBool::new(false));
        let task = tokio::spawn({
            let clock = clock.clone();
            let dropped = dropped.clone();
            async move {
                run_bounded_attempt(clock, Duration::from_secs(2), async move {
                    let _witness = DropWitness(dropped);
                    futures_util::future::pending::<()>().await;
                })
                .await
            }
        });
        tokio::task::yield_now().await;
        assert_eq!(clock.pending_sleepers(), 1);

        clock.advance(Duration::from_secs(2)).await.unwrap();

        assert_eq!(task.await.unwrap(), Err(AttemptTimedOut));
        assert!(dropped.load(Ordering::SeqCst));
        assert_eq!(clock.pending_sleepers(), 0);
    }

    #[tokio::test]
    async fn completed_attempt_removes_its_manual_deadline() {
        let clock = Arc::new(ManualClock::new());
        assert_eq!(
            run_bounded_attempt(clock.clone(), Duration::from_secs(2), async { 7 }).await,
            Ok(7)
        );
        tokio::task::yield_now().await;
        assert_eq!(clock.pending_sleepers(), 0);
    }
}
