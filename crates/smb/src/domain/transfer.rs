use std::{
    collections::BTreeMap,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use bytes::Bytes;
use futures_core::{Stream, future::BoxFuture};
use futures_util::{FutureExt, StreamExt, stream::FuturesUnordered};
use tokio::sync::broadcast;

use super::{CancelToken, File, Operation, ReplayPolicy};
use crate::Error;

#[derive(Clone)]
pub struct TransferOptions {
    concurrency: usize,
    chunk_size: u32,
    deadline: Option<Instant>,
    cancellation: Option<CancelToken>,
    progress_capacity: usize,
}

impl Default for TransferOptions {
    fn default() -> Self {
        Self {
            concurrency: 4,
            chunk_size: 1024 * 1024,
            deadline: None,
            cancellation: None,
            progress_capacity: 64,
        }
    }
}

impl TransferOptions {
    pub const fn concurrency(mut self, concurrency: usize) -> Self {
        self.concurrency = concurrency;
        self
    }

    pub const fn chunk_size(mut self, chunk_size: u32) -> Self {
        self.chunk_size = chunk_size;
        self
    }

    pub const fn deadline(mut self, deadline: Instant) -> Self {
        self.deadline = Some(deadline);
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.deadline = Some(Instant::now() + timeout);
        self
    }

    pub fn cancellation(mut self, cancellation: CancelToken) -> Self {
        self.cancellation = Some(cancellation);
        self
    }

    pub const fn progress_capacity(mut self, capacity: usize) -> Self {
        self.progress_capacity = capacity;
        self
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransferProgress {
    ChunkCompleted {
        offset: u64,
        bytes: u32,
        transferred: u64,
        total: u64,
    },
    Lagged {
        skipped: u64,
    },
}

pub struct TransferEvents {
    inner: Pin<Box<dyn Stream<Item = TransferProgress> + Send>>,
}

impl Stream for TransferEvents {
    type Item = TransferProgress;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.inner.as_mut().poll_next(cx)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransferReport {
    bytes: u64,
    chunks: u64,
}

impl TransferReport {
    pub const fn bytes(&self) -> u64 {
        self.bytes
    }

    pub const fn chunks(&self) -> u64 {
        self.chunks
    }

}

#[must_use = "transfers do nothing until polled or awaited"]
pub struct Transfer<'a> {
    operation: Operation<'a, TransferReport>,
    events: Option<TransferEvents>,
}

impl Transfer<'_> {
    pub fn take_events(&mut self) -> Option<TransferEvents> {
        self.events.take()
    }
}

impl Future for Transfer<'_> {
    type Output = crate::Result<TransferReport>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.operation).poll(cx)
    }
}

impl File {
    pub fn transfer_to<'a>(
        &'a self,
        destination: &'a File,
        options: TransferOptions,
    ) -> Transfer<'a> {
        let capacity = options.progress_capacity.max(1);
        let (progress, receiver) = broadcast::channel(capacity);
        let events = TransferEvents {
            inner: Box::pin(futures_util::stream::unfold(
                receiver,
                |mut receiver| async move {
                    match receiver.recv().await {
                        Ok(event) => Some((event, receiver)),
                        Err(broadcast::error::RecvError::Lagged(skipped)) => {
                            Some((TransferProgress::Lagged { skipped }, receiver))
                        }
                        Err(broadcast::error::RecvError::Closed) => None,
                    }
                },
            )),
        };
        let deadline = options.deadline;
        let cancellation = options.cancellation.clone();
        let operation = Operation::new(move |context| {
            let read = move |offset: u64, length: u32, cancellation: CancelToken| {
                async move {
                    self.read_exact_at(offset, length)
                        .cancellation(cancellation)
                        .replay(ReplayPolicy::Idempotent)
                        .await
                }
                .boxed()
            };
            let write = move |offset: u64, bytes: Bytes, cancellation: CancelToken| {
                async move {
                    let length = u32::try_from(bytes.len())?;
                    destination
                        .write_all_at(offset, bytes)
                        .cancellation(cancellation)
                        .await?;
                    Ok(length)
                }
                .boxed()
            };
            Box::pin(async move {
                let length = self.inner.len().await?;
                let mut options = options;
                options.chunk_size = options
                    .chunk_size
                    .min(self.inner.maximum_read_size())
                    .min(destination.inner.maximum_write_size());
                run_transfer(length, options, context.cancellation, progress, read, write).await
            })
        });
        let operation = match (deadline, cancellation) {
            (Some(deadline), Some(cancellation)) => {
                operation.deadline(deadline).cancellation(cancellation)
            }
            (Some(deadline), None) => operation.deadline(deadline),
            (None, Some(cancellation)) => operation.cancellation(cancellation),
            (None, None) => operation,
        };
        Transfer {
            operation,
            events: Some(events),
        }
    }
}

async fn run_transfer<'a, ReadChunk, WriteChunk>(
    length: u64,
    options: TransferOptions,
    cancellation: CancelToken,
    progress: broadcast::Sender<TransferProgress>,
    read_chunk: ReadChunk,
    write_chunk: WriteChunk,
) -> crate::Result<TransferReport>
where
    ReadChunk: Fn(u64, u32, CancelToken) -> BoxFuture<'a, crate::Result<Bytes>> + Clone + 'a,
    WriteChunk: Fn(u64, Bytes, CancelToken) -> BoxFuture<'a, crate::Result<u32>> + Clone + 'a,
{
    if options.concurrency == 0 || options.chunk_size == 0 {
        return Err(Error::InvalidArgument(
            "transfer concurrency and chunk size must be non-zero".into(),
        ));
    }
    let mut pending = FuturesUnordered::new();
    let mut ready: BTreeMap<u64, Bytes> = BTreeMap::new();
    let mut next_read = 0_u64;
    let mut next_write = 0_u64;
    let mut transferred = 0_u64;
    let mut chunks = 0_u64;
    loop {
        while pending.len() + ready.len() < options.concurrency && next_read < length {
            let remaining = length - next_read;
            let chunk_length = remaining.min(u64::from(options.chunk_size)) as u32;
            let offset = next_read;
            next_read += u64::from(chunk_length);
            let read = read_chunk.clone();
            let token = cancellation.clone();
            pending.push(async move {
                let bytes = read(offset, chunk_length, token)
                    .await
                    .map_err(|error| (offset, error))?;
                if bytes.len() != chunk_length as usize {
                    return Err((
                        offset,
                        Error::InvalidMessage(
                            "transfer read completed with a short byte count".into(),
                        ),
                    ));
                }
                Ok((offset, bytes))
            });
        }

        if let Some(bytes) = ready.remove(&next_write) {
            let expected = u32::try_from(bytes.len())?;
            let written = write_chunk(next_write, bytes, cancellation.clone())
                .await
                .map_err(|source| Error::TransferFailed {
                    offset: next_write,
                    transferred,
                    source: Box::new(source),
                })?;
            if written != expected {
                return Err(Error::TransferFailed {
                    offset: next_write,
                    transferred,
                    source: Box::new(Error::InvalidMessage(
                        "transfer write completed with a short byte count".into(),
                    )),
                });
            }
            let offset = next_write;
            next_write += u64::from(written);
            transferred += u64::from(written);
            chunks += 1;
            let _ = progress.send(TransferProgress::ChunkCompleted {
                offset,
                bytes: written,
                transferred,
                total: length,
            });
            continue;
        }

        match pending.next().await {
            Some(result) => {
                let (offset, bytes) = result.map_err(|(offset, source)| Error::TransferFailed {
                    offset,
                    transferred,
                    source: Box::new(source),
                })?;
                ready.insert(offset, bytes);
            }
            None if ready.is_empty() => break,
            None => {
                return Err(Error::InvalidState(
                    "transfer scheduler cannot reach the next ordered write".into(),
                ));
            }
        }
    }
    Ok(TransferReport {
        bytes: transferred,
        chunks,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    use futures_util::StreamExt;
    use tokio::sync::Notify;

    use super::*;

    #[tokio::test]
    async fn scheduler_bounds_concurrent_reads_and_orders_writes() {
        let active = Arc::new(AtomicUsize::new(0));
        let maximum = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(Notify::new());
        let (progress, mut receiver) = broadcast::channel(8);
        let read = {
            let active = Arc::clone(&active);
            let maximum = Arc::clone(&maximum);
            let release = Arc::clone(&release);
            move |offset, length, _| {
                let active = Arc::clone(&active);
                let maximum = Arc::clone(&maximum);
                let release = Arc::clone(&release);
                async move {
                    let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                    maximum.fetch_max(now, Ordering::SeqCst);
                    if offset == 0 {
                        release.notified().await;
                    } else {
                        release.notify_waiters();
                    }
                    active.fetch_sub(1, Ordering::SeqCst);
                    Ok(Bytes::from(vec![0_u8; length as usize]))
                }
                .boxed()
            }
        };
        let writes = Arc::new(Mutex::new(Vec::new()));
        let write = {
            let writes = Arc::clone(&writes);
            move |offset, bytes: Bytes, _| {
                let writes = Arc::clone(&writes);
                async move {
                    writes.lock().unwrap().push(offset);
                    Ok(bytes.len() as u32)
                }
                .boxed()
            }
        };
        let report = run_transfer(
            12,
            TransferOptions::default().concurrency(2).chunk_size(4),
            CancelToken::new(),
            progress,
            read,
            write,
        )
        .await
        .unwrap();
        assert_eq!(report.bytes(), 12);
        assert_eq!(report.chunks(), 3);
        assert_eq!(maximum.load(Ordering::SeqCst), 2);
        assert_eq!(*writes.lock().unwrap(), [0, 4, 8]);
        let first = receiver.recv().await.unwrap();
        assert!(matches!(
            first,
            TransferProgress::ChunkCompleted { offset: 0, .. }
        ));
    }

    #[tokio::test]
    async fn short_chunk_and_invalid_policy_are_typed_failures() {
        let (progress, _) = broadcast::channel(1);
        let short = |_offset, length: u32, _| {
            async move { Ok(Bytes::from(vec![0_u8; length.saturating_sub(1) as usize])) }.boxed()
        };
        let write = |_, bytes: Bytes, _| async move { Ok(bytes.len() as u32) }.boxed();
        assert!(matches!(
            run_transfer(
                4,
                TransferOptions::default().chunk_size(4),
                CancelToken::new(),
                progress,
                short,
                write,
            )
            .await,
            Err(Error::TransferFailed {
                offset: 0,
                transferred: 0,
                ..
            })
        ));

        let (progress, _) = broadcast::channel(1);
        let never_read = |_, _, _| async { unreachable!() }.boxed();
        let never_write = |_, _, _| async { unreachable!() }.boxed();
        assert!(matches!(
            run_transfer(
                4,
                TransferOptions::default().concurrency(0),
                CancelToken::new(),
                progress,
                never_read,
                never_write,
            )
            .await,
            Err(Error::InvalidArgument(_))
        ));
    }

    #[tokio::test]
    async fn bounded_progress_reports_lag_with_a_resynchronizing_total() {
        let (progress, receiver) = broadcast::channel(1);
        let read =
            |_, length, _| async move { Ok(Bytes::from(vec![0_u8; length as usize])) }.boxed();
        let write = |_, bytes: Bytes, _| async move { Ok(bytes.len() as u32) }.boxed();
        let report = run_transfer(
            12,
            TransferOptions::default().concurrency(1).chunk_size(4),
            CancelToken::new(),
            progress,
            read,
            write,
        )
        .await
        .unwrap();
        assert_eq!(report.bytes(), 12);
        let mut events = TransferEvents {
            inner: Box::pin(futures_util::stream::unfold(
                receiver,
                |mut receiver| async move {
                    match receiver.recv().await {
                        Ok(event) => Some((event, receiver)),
                        Err(broadcast::error::RecvError::Lagged(skipped)) => {
                            Some((TransferProgress::Lagged { skipped }, receiver))
                        }
                        Err(broadcast::error::RecvError::Closed) => None,
                    }
                },
            )),
        };
        assert!(matches!(
            events.next().await,
            Some(TransferProgress::Lagged { skipped: 2 })
        ));
        assert!(matches!(
            events.next().await,
            Some(TransferProgress::ChunkCompleted {
                transferred: 12,
                total: 12,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn cancellation_stops_inflight_chunks_with_the_typed_terminal() {
        let cancellation = CancelToken::new();
        let started = Arc::new(Notify::new());
        let read = {
            let started = Arc::clone(&started);
            move |_, _, cancellation: CancelToken| {
                let started = Arc::clone(&started);
                async move {
                    started.notify_one();
                    cancellation.cancelled().await;
                    Err(Error::Cancelled("transfer chunk"))
                }
                .boxed()
            }
        };
        let write = |_, bytes: Bytes, _| async move { Ok(bytes.len() as u32) }.boxed();
        let (progress, _) = broadcast::channel(1);
        let running = tokio::spawn(run_transfer(
            8,
            TransferOptions::default().concurrency(2).chunk_size(4),
            cancellation.clone(),
            progress,
            read,
            write,
        ));
        started.notified().await;
        cancellation.cancel();
        assert!(matches!(
            running.await.unwrap(),
            Err(Error::TransferFailed {
                source,
                ..
            }) if matches!(*source, Error::Cancelled("transfer chunk"))
        ));
    }

    #[tokio::test]
    async fn partial_failure_reports_exact_committed_prefix_and_offset() {
        let read = |offset, length, _| {
            async move {
                if offset == 4 {
                    Err(Error::InvalidState("injected read failure".into()))
                } else {
                    Ok(Bytes::from(vec![0_u8; length as usize]))
                }
            }
            .boxed()
        };
        let write = |_, bytes: Bytes, _| async move { Ok(bytes.len() as u32) }.boxed();
        let (progress, mut receiver) = broadcast::channel(4);
        assert!(matches!(
            run_transfer(
                8,
                TransferOptions::default().concurrency(1).chunk_size(4),
                CancelToken::new(),
                progress,
                read,
                write,
            )
            .await,
            Err(Error::TransferFailed {
                offset: 4,
                transferred: 4,
                ..
            })
        ));
        assert!(matches!(
            receiver.recv().await,
            Ok(TransferProgress::ChunkCompleted {
                offset: 0,
                transferred: 4,
                ..
            })
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn transfer_deadline_cancels_every_inflight_chunk() {
        let started = Arc::new(AtomicUsize::new(0));
        let read = {
            let started = Arc::clone(&started);
            move |_, _, cancellation: CancelToken| {
                let started = Arc::clone(&started);
                async move {
                    started.fetch_add(1, Ordering::SeqCst);
                    cancellation.cancelled().await;
                    Err(Error::Cancelled("deadline drain"))
                }
                .boxed()
            }
        };
        let write = |_, bytes: Bytes, _| async move { Ok(bytes.len() as u32) }.boxed();
        let (progress, _) = broadcast::channel(1);
        let operation = Operation::new(move |context| {
            Box::pin(run_transfer(
                8,
                TransferOptions::default().concurrency(2).chunk_size(4),
                context.cancellation,
                progress,
                read,
                write,
            ))
        })
        .timeout(Duration::from_secs(1));
        let running = tokio::spawn(operation);
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(1)).await;

        assert!(matches!(
            running.await.unwrap(),
            Err(Error::OperationTimeout(..))
        ));
        assert_eq!(started.load(Ordering::SeqCst), 2);
    }
}
