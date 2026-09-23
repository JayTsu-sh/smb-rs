use std::sync::Arc;

use tokio::sync::Semaphore;

const MINIMUM_OFFLOAD_BYTES: usize = 64 * 1024;

#[derive(Clone)]
pub(crate) struct BoundedCryptoExecutor {
    permits: Arc<Semaphore>,
}

impl Default for BoundedCryptoExecutor {
    fn default() -> Self {
        Self::new(Self::recommended_parallelism())
    }
}

impl BoundedCryptoExecutor {
    pub(crate) fn recommended_parallelism() -> usize {
        std::thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(1)
            .min(4)
    }

    pub(crate) fn new(parallelism: usize) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(parallelism.max(1))),
        }
    }

    pub(crate) fn should_offload(&self, work_bytes: usize) -> bool {
        work_bytes >= MINIMUM_OFFLOAD_BYTES
    }

    pub(crate) async fn execute<F, T>(
        &self,
        work_bytes: usize,
        job: F,
    ) -> Result<T, tokio::task::JoinError>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        if !self.should_offload(work_bytes) {
            return Ok(job());
        }
        let permit = self
            .permits
            .clone()
            .acquire_owned()
            .await
            .expect("the crypto executor never closes its semaphore");
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            job()
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Condvar, Mutex};
    use std::time::Duration;

    use futures_util::future::join_all;
    use tokio::sync::mpsc;

    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn executor_never_starts_more_jobs_than_its_parallelism() {
        let executor = BoundedCryptoExecutor::new(2);
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let (started, mut starts) = mpsc::unbounded_channel();
        let jobs = (0..4)
            .map(|job_id| {
                let executor = executor.clone();
                let gate = gate.clone();
                let started = started.clone();
                tokio::spawn(async move {
                    executor
                        .execute(usize::MAX, move || {
                            started.send(job_id).unwrap();
                            let (lock, ready) = &*gate;
                            let released = lock.lock().unwrap();
                            drop(ready.wait_while(released, |released| !*released).unwrap());
                            job_id
                        })
                        .await
                        .unwrap()
                })
            })
            .collect::<Vec<_>>();
        drop(started);

        starts.recv().await.unwrap();
        starts.recv().await.unwrap();
        let third_started = tokio::time::timeout(Duration::from_millis(100), starts.recv())
            .await
            .ok()
            .flatten();

        let (lock, ready) = &*gate;
        *lock.lock().unwrap() = true;
        ready.notify_all();
        let completed = join_all(jobs).await;

        assert_eq!(third_started, None);
        assert!(completed.into_iter().all(|result| result.is_ok()));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn small_jobs_stay_inline_when_large_job_permits_are_busy() {
        let executor = BoundedCryptoExecutor::new(1);
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let (started, mut starts) = mpsc::unbounded_channel();
        let large = tokio::spawn({
            let executor = executor.clone();
            let gate = gate.clone();
            async move {
                executor
                    .execute(usize::MAX, move || {
                        started.send(()).unwrap();
                        let (lock, ready) = &*gate;
                        let released = lock.lock().unwrap();
                        drop(ready.wait_while(released, |released| !*released).unwrap());
                    })
                    .await
                    .unwrap();
            }
        });
        starts.recv().await.unwrap();

        let small =
            tokio::time::timeout(Duration::from_millis(100), executor.execute(1, || 42)).await;

        let (lock, ready) = &*gate;
        *lock.lock().unwrap() = true;
        ready.notify_all();
        large.await.unwrap();
        assert_eq!(small.unwrap().unwrap(), 42);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_caller_does_not_release_a_running_jobs_permit() {
        let executor = BoundedCryptoExecutor::new(1);
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let (started, mut starts) = mpsc::unbounded_channel();

        let first = tokio::spawn({
            let executor = executor.clone();
            let gate = gate.clone();
            let started = started.clone();
            async move {
                executor
                    .execute(usize::MAX, move || {
                        started.send(1).unwrap();
                        let (lock, ready) = &*gate;
                        let released = lock.lock().unwrap();
                        drop(ready.wait_while(released, |released| !*released).unwrap());
                    })
                    .await
            }
        });
        assert_eq!(starts.recv().await, Some(1));
        first.abort();
        assert!(first.await.unwrap_err().is_cancelled());

        let second = tokio::spawn({
            let executor = executor.clone();
            let started = started.clone();
            async move {
                executor
                    .execute(usize::MAX, move || started.send(2).unwrap())
                    .await
            }
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(100), starts.recv())
                .await
                .is_err()
        );

        let (lock, ready) = &*gate;
        *lock.lock().unwrap() = true;
        ready.notify_all();
        assert_eq!(starts.recv().await, Some(2));
        second.await.unwrap().unwrap();
    }
}
