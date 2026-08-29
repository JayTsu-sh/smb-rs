use futures_core::future::BoxFuture;
use futures_util::FutureExt;
use std::time::Duration;

#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct MonotonicTime(u64);

impl MonotonicTime {
    pub const ZERO: Self = Self(0);
    #[cfg(feature = "test-support")]
    pub const MAX: Self = Self(u64::MAX);

    pub fn saturating_add(self, duration: Duration) -> Self {
        let nanoseconds = u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX);
        Self(self.0.saturating_add(nanoseconds))
    }

    fn as_duration(self) -> Duration {
        Duration::from_nanos(self.0)
    }
}

pub trait Clock: Send + Sync + 'static {
    fn now(&self) -> MonotonicTime;
    fn sleep_until(&self, deadline: MonotonicTime) -> BoxFuture<'static, ()>;
}

#[derive(Clone, Debug)]
pub struct TokioClock {
    origin: tokio::time::Instant,
}

impl TokioClock {
    pub fn new() -> Self {
        Self {
            origin: tokio::time::Instant::now(),
        }
    }
}

impl Default for TokioClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for TokioClock {
    fn now(&self) -> MonotonicTime {
        MonotonicTime::ZERO.saturating_add(self.origin.elapsed())
    }

    fn sleep_until(&self, deadline: MonotonicTime) -> BoxFuture<'static, ()> {
        let Some(deadline) = self.origin.checked_add(deadline.as_duration()) else {
            return futures_util::future::pending().boxed();
        };
        tokio::time::sleep_until(deadline).boxed()
    }
}

#[cfg(feature = "test-support")]
mod manual {
    use super::{Clock, MonotonicTime};
    use futures_core::future::BoxFuture;
    use futures_util::FutureExt;
    use std::collections::BTreeMap;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll};
    use std::time::Duration;
    use tokio::sync::oneshot;

    #[derive(Clone, Debug, Default)]
    pub struct ManualClock {
        state: Arc<Mutex<ManualClockState>>,
    }

    #[derive(Debug, Default)]
    struct ManualClockState {
        now: MonotonicTime,
        next_sequence: u64,
        sleepers: BTreeMap<(MonotonicTime, u64), oneshot::Sender<()>>,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
    pub enum ManualClockError {
        #[error("manual clock cannot move backwards")]
        Backwards,
        #[error("manual clock state is unavailable")]
        StateUnavailable,
    }

    impl ManualClock {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn pending_sleepers(&self) -> usize {
            self.state
                .lock()
                .map(|state| state.sleepers.len())
                .unwrap_or_default()
        }

        pub async fn advance(&self, duration: Duration) -> Result<(), ManualClockError> {
            self.advance_to(self.now().saturating_add(duration)).await
        }

        pub async fn advance_to(&self, target: MonotonicTime) -> Result<(), ManualClockError> {
            let ready = {
                let mut state = self
                    .state
                    .lock()
                    .map_err(|_| ManualClockError::StateUnavailable)?;
                if target < state.now {
                    return Err(ManualClockError::Backwards);
                }
                state.now = target;
                let ready_keys: Vec<_> = state
                    .sleepers
                    .range(..=(target, u64::MAX))
                    .map(|(key, _)| *key)
                    .collect();
                ready_keys
                    .into_iter()
                    .filter_map(|key| state.sleepers.remove(&key))
                    .collect::<Vec<_>>()
            };
            for sleeper in ready {
                let _ = sleeper.send(());
                tokio::task::yield_now().await;
            }
            Ok(())
        }
    }

    impl Clock for ManualClock {
        fn now(&self) -> MonotonicTime {
            self.state
                .lock()
                .map(|state| state.now)
                .unwrap_or(MonotonicTime::MAX)
        }

        fn sleep_until(&self, deadline: MonotonicTime) -> BoxFuture<'static, ()> {
            let mut state = match self.state.lock() {
                Ok(state) => state,
                Err(_) => return futures_util::future::ready(()).boxed(),
            };
            if deadline <= state.now {
                return futures_util::future::ready(()).boxed();
            }
            let sequence = state.next_sequence;
            state.next_sequence = state.next_sequence.saturating_add(1);
            let key = (deadline, sequence);
            let (sender, receiver) = oneshot::channel();
            state.sleepers.insert(key, sender);
            ManualSleep {
                key,
                state: Arc::clone(&self.state),
                receiver,
            }
            .boxed()
        }
    }

    struct ManualSleep {
        key: (MonotonicTime, u64),
        state: Arc<Mutex<ManualClockState>>,
        receiver: oneshot::Receiver<()>,
    }

    impl Future for ManualSleep {
        type Output = ();

        fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
            Pin::new(&mut self.receiver).poll(context).map(|_| ())
        }
    }

    impl Drop for ManualSleep {
        fn drop(&mut self) {
            if let Ok(mut state) = self.state.lock() {
                state.sleepers.remove(&self.key);
            }
        }
    }
}

#[cfg(feature = "test-support")]
pub use manual::{ManualClock, ManualClockError};
