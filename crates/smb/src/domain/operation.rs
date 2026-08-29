use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use futures_core::future::BoxFuture;
use tokio_util::sync::CancellationToken;

use crate::{Error, error::TimedOutTask};

pub type CancelToken = CancellationToken;
pub type Deadline = Instant;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ReplayPolicy {
    #[default]
    Never,
    IfUncommitted,
    Idempotent,
    DurableReconnectOnly,
}

#[derive(Clone)]
pub(crate) struct OperationContext {
    pub(crate) deadline: Option<Deadline>,
    pub(crate) cancellation: CancelToken,
    pub(crate) replay: ReplayPolicy,
}

type Start<'a, T> = Box<
    dyn FnOnce(OperationContext) -> BoxFuture<'a, crate::Result<T>> + Send + 'a,
>;

/// A lazy domain operation. Constructing or dropping it before first poll has
/// no protocol side effect.
#[must_use = "operations do nothing until polled or awaited"]
pub struct Operation<'a, T> {
    start: Option<Start<'a, T>>,
    future: Option<BoxFuture<'a, crate::Result<T>>>,
    deadline: Option<Deadline>,
    external_cancellation: Option<CancelToken>,
    cancellation: CancelToken,
    replay: ReplayPolicy,
    started: bool,
    completed: bool,
}

impl<'a, T> Operation<'a, T> {
    pub(crate) fn new(
        start: impl FnOnce(OperationContext) -> BoxFuture<'a, crate::Result<T>> + Send + 'a,
    ) -> Self {
        Self {
            start: Some(Box::new(start)),
            future: None,
            deadline: None,
            external_cancellation: None,
            cancellation: CancelToken::new(),
            replay: ReplayPolicy::Never,
            started: false,
            completed: false,
        }
    }

    pub fn deadline(mut self, deadline: Deadline) -> Self {
        self.deadline = Some(deadline);
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.deadline = Some(Instant::now() + timeout);
        self
    }

    pub fn cancellation(mut self, cancellation: CancelToken) -> Self {
        self.external_cancellation = Some(cancellation);
        self
    }

    pub fn replay(mut self, replay: ReplayPolicy) -> Self {
        self.replay = replay;
        self
    }

    pub fn request_cancel(&self) {
        self.cancellation.cancel();
    }
}

impl<'a, T: 'a> Future for Operation<'a, T> {
    type Output = crate::Result<T>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.future.is_none() {
            self.started = true;
            let Some(start) = self.start.take() else {
                self.completed = true;
                return Poll::Ready(Err(Error::InvalidState(
                    "operation was polled after terminal completion".into(),
                )));
            };
            let context = OperationContext {
                deadline: self.deadline,
                cancellation: self.cancellation.clone(),
                replay: self.replay,
            };
            let future = start(context.clone());
            self.future = Some(Box::pin(run_bounded(
                future,
                context,
                self.external_cancellation.clone(),
            )));
        }
        let Some(future) = self.future.as_mut() else {
            self.completed = true;
            return Poll::Ready(Err(Error::InvalidState(
                "operation start did not install a future".into(),
            )));
        };
        let result = future.as_mut().poll(cx);
        if result.is_ready() {
            self.completed = true;
        }
        result
    }
}

impl<T> Drop for Operation<'_, T> {
    fn drop(&mut self) {
        if self.started && !self.completed {
            self.cancellation.cancel();
        }
    }
}

async fn run_bounded<T>(
    future: BoxFuture<'_, crate::Result<T>>,
    context: OperationContext,
    external: Option<CancelToken>,
) -> crate::Result<T> {
    let deadline = context.deadline;
    let started = Instant::now();
    let deadline_wait = async move {
        match deadline {
            Some(deadline) => tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await,
            None => std::future::pending().await,
        }
    };
    let external_wait = async move {
        match external {
            Some(token) => token.cancelled().await,
            None => std::future::pending().await,
        }
    };
    tokio::select! {
        biased;
        _ = context.cancellation.cancelled() => Err(Error::Cancelled("domain operation")),
        _ = external_wait => {
            context.cancellation.cancel();
            Err(Error::Cancelled("domain operation"))
        }
        _ = deadline_wait => {
            context.cancellation.cancel();
            Err(Error::OperationTimeout(TimedOutTask::ReceiveNextMessage, started.elapsed()))
        }
        result = future => result,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use futures_util::future::poll_fn;

    use super::*;

    #[tokio::test]
    async fn unpolled_operation_has_no_side_effect() {
        let starts = Arc::new(AtomicUsize::new(0));
        let observed = starts.clone();
        let operation = Operation::<()>::new(move |_| {
            observed.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Ok(()) })
        });
        drop(operation);
        assert_eq!(starts.load(Ordering::SeqCst), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn deadline_and_external_cancel_are_typed_and_terminal() {
        let never = || Box::pin(std::future::pending()) as BoxFuture<'_, crate::Result<()>>;
        let deadline = Operation::new(move |_| never()).timeout(Duration::from_secs(5));
        tokio::pin!(deadline);
        tokio::time::advance(Duration::from_secs(5)).await;
        assert!(matches!(deadline.await, Err(Error::OperationTimeout(..))));

        let token = CancelToken::new();
        let cancelled = Operation::new(move |_| never()).cancellation(token.clone());
        token.cancel();
        assert!(matches!(cancelled.await, Err(Error::Cancelled("domain operation"))));
    }

    #[tokio::test]
    async fn drop_after_first_poll_cancels_the_admitted_context() {
        let captured = Arc::new(std::sync::Mutex::new(None));
        let observed = captured.clone();
        let mut operation = Box::pin(Operation::<()>::new(move |context| {
            *observed.lock().unwrap() = Some(context.cancellation.clone());
            Box::pin(async move {
                context.cancellation.cancelled().await;
                Ok(())
            })
        }));
        poll_fn(|cx| {
            assert!(operation.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        drop(operation);
        assert!(captured.lock().unwrap().as_ref().unwrap().is_cancelled());
    }
}
