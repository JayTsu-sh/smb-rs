use std::{
    any::Any,
    marker::PhantomData,
    sync::atomic::{AtomicU64, Ordering},
};

use bytes::Bytes;
use futures_core::future::BoxFuture;

#[cfg(test)]
use super::CancelToken;
use super::{File, Operation, operation::OperationContext};
use crate::Error;

type ErasedValue = Box<dyn Any + Send>;
type BatchAction<'a> =
    Box<dyn FnOnce(OperationContext) -> BoxFuture<'a, crate::Result<ErasedValue>> + Send + 'a>;
static NEXT_BATCH_ID: AtomicU64 = AtomicU64::new(1);

/// A typed reference to one member of a [`Batch`].
#[derive(Debug, Eq, PartialEq)]
pub struct BatchRef<T> {
    batch_id: u64,
    index: usize,
    _value: PhantomData<fn() -> T>,
}

impl<T> Copy for BatchRef<T> {}

impl<T> Clone for BatchRef<T> {
    fn clone(&self) -> Self {
        *self
    }
}

/// A domain operation that has explicitly declared itself batch-compatible.
#[must_use = "batch commands must be pushed into a Batch"]
pub struct BatchCommand<'a, T> {
    action: BatchAction<'a>,
    dependency: Option<(u64, usize)>,
    _value: PhantomData<fn() -> T>,
}

impl<'a, T> BatchCommand<'a, T> {
    fn new(
        action: impl FnOnce(OperationContext) -> BoxFuture<'a, crate::Result<T>> + Send + 'a,
    ) -> Self
    where
        T: Send + 'static,
    {
        Self {
            action: Box::new(move |context| {
                Box::pin(async move { action(context).await.map(|value| Box::new(value) as _) })
            }),
            dependency: None,
            _value: PhantomData,
        }
    }

    pub fn after<U>(mut self, dependency: BatchRef<U>) -> Self {
        self.dependency = Some((dependency.batch_id, dependency.index));
        self
    }
}

struct Member<'a> {
    action: BatchAction<'a>,
    dependency: Option<(u64, usize)>,
}

/// A typed collection of domain commands executed under one operation policy.
pub struct Batch<'a> {
    id: u64,
    members: Vec<Member<'a>>,
}

impl<'a> Batch<'a> {
    pub fn new() -> Self {
        Self {
            id: NEXT_BATCH_ID.fetch_add(1, Ordering::Relaxed),
            members: Vec::new(),
        }
    }

    pub fn push<T>(&mut self, command: BatchCommand<'a, T>) -> BatchRef<T>
    where
        T: Send + 'static,
    {
        let reference = BatchRef {
            batch_id: self.id,
            index: self.members.len(),
            _value: PhantomData,
        };
        self.members.push(Member {
            action: command.action,
            dependency: command.dependency,
        });
        reference
    }

    pub fn execute(self) -> Operation<'a, BatchResult> {
        Operation::new(move |context| {
            Box::pin(async move {
                for (index, member) in self.members.iter().enumerate() {
                    if member.dependency.is_some_and(|(batch_id, dependency)| {
                        batch_id != self.id || dependency >= index
                    }) {
                        return Err(Error::InvalidArgument(
                            "batch dependency must reference an earlier member of the same batch"
                                .into(),
                        ));
                    }
                }
                let mut outcomes = Vec::with_capacity(self.members.len());
                for member in self.members {
                    if member.dependency.is_some_and(|index| {
                        !matches!(outcomes.get(index.1), Some(MemberOutcome::Success(_)))
                    }) {
                        outcomes.push(MemberOutcome::DependencyFailed);
                        continue;
                    }
                    match (member.action)(context.clone()).await {
                        Ok(value) => outcomes.push(MemberOutcome::Success(value)),
                        Err(error) => outcomes.push(MemberOutcome::Failed(error)),
                    }
                }
                Ok(BatchResult { outcomes })
            })
        })
    }
}

enum MemberOutcome {
    Success(ErasedValue),
    Failed(Error),
    DependencyFailed,
}

/// The typed outcome of one batch member.
#[derive(Debug)]
pub enum BatchOutcome<'a, T> {
    Success(&'a T),
    Failed(&'a Error),
    DependencyFailed,
}

/// Per-member outcomes from one submitted batch.
pub struct BatchResult {
    outcomes: Vec<MemberOutcome>,
}

impl BatchResult {
    pub fn len(&self) -> usize {
        self.outcomes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.outcomes.is_empty()
    }

    pub fn outcome<T: 'static>(&self, reference: BatchRef<T>) -> Option<BatchOutcome<'_, T>> {
        match self.outcomes.get(reference.index)? {
            MemberOutcome::Success(value) => value.downcast_ref().map(BatchOutcome::Success),
            MemberOutcome::Failed(error) => Some(BatchOutcome::Failed(error)),
            MemberOutcome::DependencyFailed => Some(BatchOutcome::DependencyFailed),
        }
    }
}

impl Default for Batch<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl File {
    pub fn batch_read_at(&self, offset: u64, max_len: u32) -> BatchCommand<'_, Bytes> {
        BatchCommand::new(move |context| {
            Box::pin(async move {
                let replay = context.runtime_replay();
                self.inner
                    .read_at(
                        offset,
                        max_len.min(self.inner.maximum_read_size()),
                        context.remaining()?,
                        context.cancellation,
                        replay,
                    )
                    .await
            })
        })
    }

    pub fn batch_write_at(&self, offset: u64, bytes: Bytes) -> BatchCommand<'_, usize> {
        BatchCommand::new(move |context| {
            Box::pin(async move {
                let replay = context.runtime_replay();
                if bytes.len() > self.inner.maximum_write_size() as usize {
                    return Err(Error::InvalidArgument(
                        "batch write exceeds the negotiated maximum write size".into(),
                    ));
                }
                self.inner
                    .write_at(
                        offset,
                        bytes,
                        context.remaining()?,
                        context.cancellation,
                        replay,
                    )
                    .await
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    fn command<T: Send + 'static>(
        calls: Arc<Mutex<Vec<&'static str>>>,
        name: &'static str,
        result: crate::Result<T>,
    ) -> BatchCommand<'static, T> {
        BatchCommand::new(move |_| {
            Box::pin(async move {
                calls.lock().unwrap().push(name);
                result
            })
        })
    }

    #[tokio::test]
    async fn member_failure_is_local_and_only_dependants_are_skipped() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut batch = Batch::new();
        let failed = batch.push(command::<usize>(
            Arc::clone(&calls),
            "failed",
            Err(Error::InvalidState("injected".into())),
        ));
        let dependant =
            batch.push(command(Arc::clone(&calls), "dependant", Ok(2_u64)).after(failed));
        let independent = batch.push(command(Arc::clone(&calls), "independent", Ok(3_u32)));

        let result = batch.execute().await.unwrap();
        assert!(matches!(
            result.outcome(failed),
            Some(BatchOutcome::Failed(_))
        ));
        assert!(matches!(
            result.outcome(dependant),
            Some(BatchOutcome::DependencyFailed)
        ));
        assert!(matches!(
            result.outcome(independent),
            Some(BatchOutcome::Success(3))
        ));
        assert_eq!(*calls.lock().unwrap(), ["failed", "independent"]);
    }

    #[tokio::test]
    async fn successful_typed_references_recover_distinct_value_types() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut batch = Batch::new();
        let bytes = batch.push(command(
            Arc::clone(&calls),
            "bytes",
            Ok(Bytes::from_static(b"batch")),
        ));
        let count = batch.push(command(Arc::clone(&calls), "count", Ok(5_usize)).after(bytes));

        let result = batch.execute().await.unwrap();
        assert!(matches!(
            result.outcome(bytes),
            Some(BatchOutcome::Success(value)) if value.as_ref() == b"batch"
        ));
        assert!(matches!(
            result.outcome(count),
            Some(BatchOutcome::Success(5))
        ));
        assert_eq!(*calls.lock().unwrap(), ["bytes", "count"]);
    }

    #[tokio::test]
    async fn cross_batch_dependency_rejects_the_whole_submission_before_execution() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut first = Batch::new();
        let foreign = first.push(command(Arc::clone(&calls), "foreign", Ok(1_u8)));
        let mut second = Batch::new();
        second.push(command(Arc::clone(&calls), "must-not-run", Ok(2_u8)).after(foreign));

        assert!(matches!(
            second.execute().await,
            Err(Error::InvalidArgument(_))
        ));
        assert!(calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn batch_cancellation_before_poll_has_no_member_side_effects() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut batch = Batch::new();
        batch.push(command(Arc::clone(&calls), "must-not-run", Ok(1_u8)));
        let cancellation = CancelToken::new();
        cancellation.cancel();

        assert!(matches!(
            batch.execute().cancellation(cancellation).await,
            Err(Error::Cancelled("domain operation"))
        ));
        assert!(calls.lock().unwrap().is_empty());
    }
}
