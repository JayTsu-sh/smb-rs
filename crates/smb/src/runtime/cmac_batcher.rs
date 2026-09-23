use std::{
    collections::VecDeque,
    sync::{Arc, Mutex, MutexGuard},
};

use bytes::Bytes;
use tokio::sync::oneshot;

use crate::session::MessageSigner;

use crate::crypto::PORTABLE_CMAC_LANES;

pub(crate) const MINIMUM_BATCH_CMAC_BYTES: usize = 1024;
pub(crate) const MAXIMUM_INLINE_BATCH_CMAC_BYTES: usize = 64 * 1024 - 1;

#[derive(Clone, Default)]
pub(crate) struct CmacBatcher {
    state: Arc<Mutex<BatchState>>,
}

#[derive(Default)]
struct BatchState {
    queue: VecDeque<BatchJob>,
    leader_active: bool,
    #[cfg(test)]
    observed_batch_sizes: Vec<usize>,
}

struct BatchJob {
    key_id: usize,
    signer: MessageSigner,
    segments: Vec<Bytes>,
    complete: oneshot::Sender<crate::Result<u128>>,
}

impl CmacBatcher {
    pub(crate) fn should_batch(bytes: usize) -> bool {
        (MINIMUM_BATCH_CMAC_BYTES..=MAXIMUM_INLINE_BATCH_CMAC_BYTES).contains(&bytes)
    }

    pub(crate) async fn sign(
        &self,
        signer: MessageSigner,
        segments: Vec<Bytes>,
    ) -> crate::Result<u128> {
        let key_id = signer.batch_cmac_key_id().ok_or_else(|| {
            crate::Error::InvalidState("only RustCrypto CMAC jobs may enter the batcher".into())
        })?;
        let (complete, completed) = oneshot::channel();
        let is_leader = {
            let mut state = lock(&self.state);
            state.queue.push_back(BatchJob {
                key_id,
                signer,
                segments,
                complete,
            });
            if state.leader_active {
                false
            } else {
                state.leader_active = true;
                true
            }
        };

        if is_leader {
            let mut guard = LeaderGuard::new(Arc::clone(&self.state));
            // One scheduler turn lets other already-ready preparation futures
            // enqueue without introducing a timer or a coalescing deadline.
            tokio::task::yield_now().await;
            self.drain();
            guard.disarm();
        }

        completed.await.unwrap_or_else(|_| {
            Err(crate::Error::InvalidState(
                "batched CMAC coordinator stopped before completion".into(),
            ))
        })
    }

    fn drain(&self) {
        loop {
            let jobs = {
                let mut state = lock(&self.state);
                let Some(first) = state.queue.pop_front() else {
                    state.leader_active = false;
                    return;
                };
                let key_id = first.key_id;
                let mut jobs = Vec::with_capacity(PORTABLE_CMAC_LANES);
                jobs.push(first);
                while jobs.len() < PORTABLE_CMAC_LANES {
                    let Some(index) = state.queue.iter().position(|job| job.key_id == key_id)
                    else {
                        break;
                    };
                    jobs.push(
                        state
                            .queue
                            .remove(index)
                            .expect("a located CMAC batch job must remain queued"),
                    );
                }
                #[cfg(test)]
                state.observed_batch_sizes.push(jobs.len());
                jobs
            };

            let messages = jobs
                .iter()
                .map(|job| job.segments.clone())
                .collect::<Vec<_>>();
            let result = jobs[0].signer.calculate_cmac_batch(&messages);
            match result {
                Some(Ok(signatures)) if signatures.len() == jobs.len() => {
                    for (job, signature) in jobs.into_iter().zip(signatures) {
                        let _ = job.complete.send(Ok(signature));
                    }
                }
                _ => {
                    for job in jobs {
                        let _ = job.complete.send(Err(crate::Error::InvalidState(
                            "batched CMAC calculation failed".into(),
                        )));
                    }
                }
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn observed_batch_sizes(&self) -> Vec<usize> {
        lock(&self.state).observed_batch_sizes.clone()
    }
}

struct LeaderGuard {
    state: Arc<Mutex<BatchState>>,
    armed: bool,
}

impl LeaderGuard {
    fn new(state: Arc<Mutex<BatchState>>) -> Self {
        Self { state, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for LeaderGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let jobs = {
            let mut state = lock(&self.state);
            state.leader_active = false;
            state.queue.drain(..).collect::<Vec<_>>()
        };
        for job in jobs {
            let _ = job.complete.send(Err(crate::Error::InvalidState(
                "batched CMAC leader was cancelled".into(),
            )));
        }
    }
}

fn lock(state: &Mutex<BatchState>) -> MutexGuard<'_, BatchState> {
    state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use futures_util::future::join_all;
    use smb_msg::SigningAlgorithmId;

    use crate::crypto::make_signing_algo;

    use super::*;

    fn signer(key: [u8; 16]) -> MessageSigner {
        MessageSigner::new(make_signing_algo(SigningAlgorithmId::AesCmac, &key).unwrap())
    }

    #[tokio::test]
    async fn ready_jobs_with_one_key_are_signed_together() {
        let batcher = CmacBatcher::default();
        let key = [0x5a; 16];
        let signer = signer(key);
        let jobs = (0..PORTABLE_CMAC_LANES)
            .map(|index| {
                let batcher = batcher.clone();
                let signer = signer.clone();
                let mut message = vec![0xa5; 4160];
                message[0] ^= index as u8;
                async move {
                    batcher
                        .sign(signer, vec![Bytes::from(message)])
                        .await
                        .unwrap()
                }
            })
            .collect::<Vec<_>>();

        let signatures = join_all(jobs).await;

        assert_eq!(signatures.len(), PORTABLE_CMAC_LANES);
        assert!(signatures.windows(2).all(|pair| pair[0] != pair[1]));
        assert_eq!(batcher.observed_batch_sizes(), [PORTABLE_CMAC_LANES]);
    }

    #[tokio::test]
    async fn different_session_groups_use_their_own_keys() {
        let batcher = CmacBatcher::default();
        let message = Bytes::from(vec![0xa5; 4160]);
        let first = batcher.sign(signer([0x11; 16]), vec![message.clone()]);
        let second = batcher.sign(signer([0x22; 16]), vec![message]);

        let (first, second) = tokio::join!(first, second);

        assert_ne!(first.unwrap(), second.unwrap());
    }

    #[tokio::test]
    async fn cancelled_leader_releases_the_queue_for_the_next_job() {
        use std::task::Poll;
        use std::time::Duration;

        let batcher = CmacBatcher::default();
        let signer = signer([0x44; 16]);
        let mut cancelled =
            Box::pin(batcher.sign(signer.clone(), vec![Bytes::from(vec![0xa5; 4160])]));
        assert!(matches!(
            futures_util::poll!(cancelled.as_mut()),
            Poll::Pending
        ));
        drop(cancelled);

        let replacement = tokio::time::timeout(
            Duration::from_secs(1),
            batcher.sign(signer, vec![Bytes::from(vec![0x5a; 4160])]),
        )
        .await;

        assert!(replacement.unwrap().is_ok());
    }

    #[tokio::test(flavor = "current_thread")]
    #[ignore = "manual release-mode CMAC coordinator throughput probe"]
    async fn four_lane_coordinator_4160_byte_throughput_probe() {
        use std::{hint::black_box, time::Instant};

        const ITERATIONS: usize = 25_000;
        let batcher = CmacBatcher::default();
        let signer = signer([0x5a; 16]);
        let payloads = (0..PORTABLE_CMAC_LANES)
            .map(|index| {
                let mut payload = vec![0xa5; 4160];
                payload[0] ^= index as u8;
                Bytes::from(payload)
            })
            .collect::<Vec<_>>();

        let started = Instant::now();
        for _ in 0..ITERATIONS {
            let jobs = payloads
                .iter()
                .map(|payload| batcher.sign(signer.clone(), vec![black_box(payload.clone())]));
            black_box(join_all(jobs).await);
        }
        let elapsed = started.elapsed();
        let messages = ITERATIONS * PORTABLE_CMAC_LANES;
        let nanos_per_message = elapsed.as_nanos() / messages as u128;
        let mebibytes_per_second =
            4160_f64 * messages as f64 / elapsed.as_secs_f64() / (1024.0 * 1024.0);
        eprintln!(
            "CMAC_COORDINATOR_4LANE_4160 messages={messages} ns_per_message={nanos_per_message} mib_per_s={mebibytes_per_second:.2}"
        );
    }
}
