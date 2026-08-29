use super::ResourceHandle;
use crate::Error;
use crate::command::ResponseOptions;
use smb_fscc::*;
use smb_msg::*;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::sync::{Mutex, MutexGuard, mpsc};

/// A directory resource on the server.
/// This is used to query the directory for its contents,
/// and may not be created directly -- but via [Resource][super::Resource], opened
/// from a [Tree][crate::tree::Tree]
pub struct Directory {
    pub handle: ResourceHandle,
    access: DirAccessMask,
    /// This lock prevents iterating the directory twice at the same time.
    /// This is required since query directory state is tied to the handle of
    /// the directory (hence, to this structure's instance).
    query_lock: Mutex<()>,
}

impl Directory {
    pub fn new(handle: ResourceHandle) -> Self {
        let access: DirAccessMask = handle.access.into();
        Directory {
            handle,
            access,
            query_lock: Default::default(),
        }
    }

    /// An internal method that performs a query on the directory.
    /// # Arguments
    /// * `pattern` - The pattern to match against the file names in the directory. Use wildcards like `*` and `?` to match multiple files.
    /// * `restart` - Whether to restart the scan or not. This is used to indicate whether this is the first query or not.
    /// # Returns
    /// * A vector of [`QueryDirectoryInfoValue`] objects, containing the results of the query.
    /// * If the query returned [`Status::NoMoreFiles`], an empty vector is returned.
    async fn send_query<T>(
        &self,
        pattern: &str,
        restart: bool,
        buffer_size: u32,
    ) -> crate::Result<Vec<T>>
    where
        T: QueryDirectoryInfoValue + for<'a> binrw::prelude::BinWrite<Args<'a> = ()>,
    {
        if !self.access.list_directory() {
            return Err(Error::MissingPermissions("file_list_directory".to_string()));
        }

        debug_assert!(buffer_size <= self.conn_info.negotiation.max_transact_size);
        if buffer_size > self.conn_info.negotiation.max_transact_size {
            return Err(Error::InvalidArgument(format!(
                "Buffer size {} exceeds maximum transact size {}",
                buffer_size, self.conn_info.negotiation.max_transact_size
            )));
        }

        tracing::debug!("Querying directory {}", self.handle.name());

        let response = self
            .handle
            .send_receive(
                QueryDirectoryRequest {
                    file_information_class: T::CLASS_ID,
                    flags: QueryDirectoryFlags::new().with_restart_scans(restart),
                    file_index: 0,
                    file_id: self.handle.file_id().await?,
                    output_buffer_length: buffer_size,
                    file_name: pattern.into(),
                }
                .into(),
            )
            .await;

        let response = match response {
            Ok(res) => res,
            Err(Error::UnexpectedMessageStatus(Status::U32_NO_MORE_FILES)) => {
                tracing::debug!("No more files in directory");
                return Ok(vec![]);
            }
            Err(Error::UnexpectedMessageStatus(Status::U32_INFO_LENGTH_MISMATCH)) => {
                return Err(Error::InvalidArgument(format!(
                    "Provided query buffer size {buffer_size} is too small to contain directory information"
                )));
            }
            Err(e @ Error::UnexpectedMessageStatus(Status::U32_INVALID_INFO_CLASS)) => {
                tracing::debug!(
                    "Error querying directory (server does not support this info class): {e}"
                );
                return Err(e);
            }
            Err(e) => {
                tracing::error!("Error querying directory: {e}");
                return Err(e);
            }
        };

        Ok(response
            .message
            .content
            .to_querydirectory()?
            .read_output()?)
    }

    const QUERY_DIRECTORY_DEFAULT_BUFFER_SIZE: u32 = 0x10000;

    /// Asynchronously iterates over the directory contents, using the provided pattern and information type.
    /// # Arguments
    /// * `pattern` - The pattern to match against the file names in the directory. Use wildcards like `*` and `?` to match multiple files.
    /// * `info` - The information type to query. This is a trait object that implements the [`QueryDirectoryInfoValue`] trait.
    /// # Returns
    /// * An iterator over the directory contents, yielding [`QueryDirectoryInfoValue`] objects.
    /// # Returns
    /// [`iter_stream::QueryDirectoryStream`] - Which implements [futures_core::Stream] and can be used to iterate over the directory contents.
    /// # Notes
    /// * **IMPORTANT** Calling this method BLOCKS ANY ADDITIONAL CALLS to this method on THIS structure instance.
    ///   Hence, you should not call this method on the same instance from multiple threads. This is for thread safety,
    ///   since SMB2 does not allow multiple queries on the same handle at the same time. Re-open the directory and
    ///   create a new instance of this structure to query the directory again.
    /// * You must use [`futures_util::StreamExt`] to consume the stream.
    ///   See (<https://tokio.rs/tokio/tutorial/streams>) for more information on how to use streams.
    pub fn query<'a, T>(
        this: &'a Arc<Self>,
        pattern: &str,
    ) -> impl Future<Output = crate::Result<iter_stream::QueryDirectoryStream<'a, T>>>
    where
        T: QueryDirectoryInfoValue + for<'b> binrw::prelude::BinWrite<Args<'b> = ()> + Send,
    {
        Self::query_with_options(this, pattern, Self::QUERY_DIRECTORY_DEFAULT_BUFFER_SIZE)
    }

    /// Asynchronously iterates over the directory contents, using the provided pattern and information type.
    /// # Arguments
    /// * `pattern` - The pattern to match against the file names in the directory. Use wildcards like `*` and `?` to match multiple files.
    /// * `info` - The information type to query. This is a trait object that implements the [`QueryDirectoryInfoValue`] trait.
    /// * `buffer_size` - The size of the query buffer, in bytes.
    /// # Returns
    /// * An iterator over the directory contents, yielding [`QueryDirectoryInfoValue`] objects.
    /// # Returns
    /// [`iter_stream::QueryDirectoryStream`] - Which implements [futures_core::Stream] and can be used to iterate over the directory contents.
    /// # Notes
    /// * **IMPORTANT** Calling this method BLOCKS ANY ADDITIONAL CALLS to this method on THIS structure instance.
    ///   Hence, you should not call this method on the same instance from multiple threads. This is for thread safety,
    ///   since SMB2 does not allow multiple queries on the same handle at the same time. Re-open the directory and
    ///   create a new instance of this structure to query the directory again.
    /// * You must use [`futures_util::StreamExt`] to consume the stream.
    ///   See [<https://tokio.rs/tokio/tutorial/streams>] for more information on how to use streams.
    /// * The actual buffer size that may be used depends on the negotiated transact size given by the server.
    ///   In case of `buffer_size` > `max_transact_size`, the function would use the minimum, and log a warning.
    pub async fn query_with_options<'a, T>(
        this: &'a Arc<Self>,
        pattern: &str,
        buffer_size: u32,
    ) -> crate::Result<iter_stream::QueryDirectoryStream<'a, T>>
    where
        T: QueryDirectoryInfoValue + for<'b> binrw::prelude::BinWrite<Args<'b> = ()> + Send,
    {
        let max_allowed_buffer_size = this.conn_info.negotiation.max_transact_size;
        if buffer_size > max_allowed_buffer_size {
            tracing::warn!(
                "Buffer size {} is larger than max transact size {}. Using minimum.",
                buffer_size,
                max_allowed_buffer_size
            );
        }
        let buffer_size = buffer_size.min(max_allowed_buffer_size);

        iter_stream::QueryDirectoryStream::new(this, pattern.to_string(), buffer_size).await
    }

    /// Watches the directory for changes.
    /// # Arguments
    /// * `filter` - The filter to use for the changes. This is a bitmask of the changes to watch for.
    /// * `recursive` - Whether to watch the directory recursively or not.
    /// # Returns
    /// * A vector of [`FileNotifyInformation`] objects, containing the changes that occurred.
    /// # Notes
    /// * This is a long-running operation, and will block until a result is received. See [`watch_timeout`][Self::watch_timeout] for a version that supports a timeout.
    #[tracing::instrument(level = "debug", skip_all, fields(recursive = recursive))]
    pub async fn watch(
        &self,
        filter: NotifyFilter,
        recursive: bool,
    ) -> crate::Result<Vec<FileNotifyInformation>> {
        self.watch_timeout(filter, recursive, Duration::MAX).await
    }

    /// Watches the directory for changes, with a specified timeout.
    /// # Arguments
    /// * `filter` - The filter to use for the changes. This is a bitmask of the changes to watch for.
    /// * `recursive` - Whether to watch the directory recursively or not.
    /// # Returns
    /// * A vector of [`FileNotifyInformation`] objects, containing the changes that occurred.
    /// # Notes
    /// * This is a long-running operation, and will block until a result is received or the provided timeout elapses.
    ///  If the timeout elapses, an error of type [`Error::OperationTimeout`] is returned.
    /// * A similar method without timeout is available as [`watch`][Self::watch].
    #[tracing::instrument(level = "debug", skip_all, fields(recursive = recursive, timeout_ms = timeout.as_millis() as u64))]
    pub async fn watch_timeout(
        &self,
        filter: NotifyFilter,
        recursive: bool,
        timeout: std::time::Duration,
    ) -> crate::Result<Vec<FileNotifyInformation>> {
        self._watch_options(
            filter,
            recursive,
            ResponseOptions::new().with_timeout(timeout),
        )
        .await
        .into()
    }

    /// Watches the directory for changes, returning a [`Stream`][`futures_core::Stream`] of notifications.
    ///
    /// * See [`watch_stream_cancellable`][Self::watch_stream_cancellable] for a version that supports cancellation,
    ///   via a [`CancellationToken`].
    ///
    /// # Arguments
    /// * `filter` - The filter to use for the changes. This is a bitmask of the changes to watch for.
    /// * `recursive` - Whether to watch the directory recursively or not.
    /// # Returns
    /// * A stream of [`FileNotifyInformation`] objects, containing the changes that occurred.
    ///
    /// # Notes
    /// Error handling in this stream is done by returning `Result<FileNotifyInformation>`.
    pub fn watch_stream(
        this: &Arc<Self>,
        filter: NotifyFilter,
        recursive: bool,
    ) -> crate::Result<impl futures_core::Stream<Item = crate::Result<FileNotifyInformation>>> {
        Self::watch_stream_cancellable(this, filter, recursive, Default::default())
    }

    pub fn watch_stream_cancellable(
        this: &Arc<Self>,
        filter: NotifyFilter,
        recursive: bool,
        cancel: tokio_util::sync::CancellationToken,
    ) -> crate::Result<impl futures_core::Stream<Item = crate::Result<FileNotifyInformation>>> {
        const EVENT_CAPACITY: usize = 1024;
        let (sender, receiver) = tokio::sync::mpsc::channel(EVENT_CAPACITY);
        let receive_options = ResponseOptions::default()
            .with_timeout(Duration::MAX)
            .with_async_msg_ids(Default::default())
            .with_cancellation_token(cancel.clone());

        tokio::spawn({
            let directory = this.clone();
            let cancel = cancel.clone();
            async move {
                loop {
                    let result = directory
                        ._watch_options(filter, recursive, receive_options.clone())
                        .await;
                    match result {
                        DirectoryWatchResult::Notifications(items) => {
                            if !publish_change_batch(
                                &sender,
                                items,
                                &cancel,
                                EVENT_CAPACITY,
                            )
                            .await
                            {
                                return;
                            }
                        }
                        DirectoryWatchResult::Cancelled => {
                            if !cancel.is_cancelled() && !sender.is_closed() {
                                let _ = sender
                                    .send(Err(Error::Cancelled("watch cancelled unexpectedly")))
                                    .await;
                            }
                            return;
                        }
                        DirectoryWatchResult::Cleanup => return,
                        other => {
                            let result: crate::Result<Vec<FileNotifyInformation>> = other.into();
                            if let Err(error) = result {
                                let _ = sender.send(Err(error)).await;
                            }
                            return;
                        }
                    }
                }
            }
        });

        Ok(DirectoryWatchStream {
            receiver: tokio_stream::wrappers::ReceiverStream::new(receiver),
            cancel,
        })
    }

    /// (Internal) Watches the directory for changes, with an optional timeout.
    ///
    /// This method accepts the `ResponseOptions` struct, allowing more fine-tuned control over the receive operation.
    /// It uses:
    /// * `timeout` - to set the timeout for the receive operation.
    /// * `async_msg_ids` - to allow async notifications.
    /// * `async_cancel` - to allow cancellation of the receive operation.
    async fn _watch_options(
        &self,
        filter: NotifyFilter,
        recursive: bool,
        options: ResponseOptions<'_>,
    ) -> DirectoryWatchResult {
        if !self.access.list_directory() {
            return DirectoryWatchResult::Error(Error::MissingPermissions(
                "list_directory".to_string(),
            ));
        }
        let output_buffer_length = self.calc_transact_size(None);

        let file_id = match self.file_id().await {
            Ok(id) => id,
            Err(e) => return DirectoryWatchResult::Error(e),
        };

        let response = self
            .handle
            .context
            .execute_content(
                ChangeNotifyRequest {
                    file_id,
                    flags: NotifyFlags::new().with_watch_tree(recursive),
                    completion_filter: filter,
                    output_buffer_length,
                }
                .into(),
                ResponseOptions {
                    allow_async: true,
                    async_cancel: options.async_cancel,
                    async_msg_ids: options.async_msg_ids,
                    timeout: options.timeout,
                    cmd: Some(Command::ChangeNotify),
                    status: &[
                        Status::Success,
                        Status::Cancelled,
                        Status::NotifyCleanup,
                        Status::NotifyEnumDir,
                    ],
                    ..Default::default()
                },
            )
            .await;

        let response = match response {
            Ok(res) => match res.message.header.status {
                Status::U32_SUCCESS => res,
                // Cancellation from CancelRequest
                Status::U32_CANCELLED => return DirectoryWatchResult::Cancelled,
                Status::U32_NOTIFY_CLEANUP => return DirectoryWatchResult::Cleanup,
                Status::U32_NOTIFY_ENUM_DIR => {
                    return DirectoryWatchResult::NotifyEnumDir {
                        provided_size: output_buffer_length as usize,
                    };
                }
                s => {
                    tracing::debug!("Unexpected status while watching directory: {s:?}");
                    return DirectoryWatchResult::Error(Error::UnexpectedMessageStatus(s));
                }
            },
            // Other cancellation (token)
            Err(Error::Cancelled(_)) => return DirectoryWatchResult::Cancelled,
            Err(e) => {
                tracing::debug!("Error watching directory: {e}");
                return DirectoryWatchResult::Error(e);
            }
        };

        let change_notify = match response.message.content.to_changenotify() {
            Ok(cn) => cn,
            Err(e) => return DirectoryWatchResult::Error(e.into()),
        };

        DirectoryWatchResult::Notifications(change_notify.buffer.into())
    }

    /// Queries the quota information for the current file.
    /// # Arguments
    /// * `info` - The information to query - a [`QueryQuotaInfo`].
    pub async fn query_quota_info(
        &self,
        info: QueryQuotaInfo,
    ) -> crate::Result<Vec<FileQuotaInformation>> {
        self.query_quota_info_with_options(info, None).await
    }
    /// Queries the quota information for the current file.
    /// # Arguments
    /// * `info` - The information to query - a [`QueryQuotaInfo`].
    pub async fn query_quota_info_with_options(
        &self,
        info: QueryQuotaInfo,
        output_buffer_length: Option<usize>,
    ) -> crate::Result<Vec<FileQuotaInformation>> {
        if output_buffer_length.is_some_and(|x| x < FileQuotaInformation::MIN_SIZE) {
            return Err(Error::BufferTooSmall {
                data_type: "FileQuotaInformation",
                required: FileQuotaInformation::MIN_SIZE.into(),
                provided: output_buffer_length.unwrap(),
            });
        }

        Ok(self
            .handle
            .query_common(
                QueryInfoRequest {
                    info_type: InfoType::Quota,
                    info_class: Default::default(),
                    output_buffer_length: 0,
                    additional_info: AdditionalInfo::new(),
                    flags: QueryInfoFlags::new()
                        .with_restart_scan(info.restart_scan.into())
                        .with_return_single_entry(info.return_single.into()),
                    file_id: self.handle.file_id().await?,
                    data: GetInfoRequestData::Quota(info),
                },
                output_buffer_length,
                std::any::type_name::<FileQuotaInformation>(),
            )
            .await?
            .as_quota()?
            .into())
    }
}

async fn publish_change_batch(
    sender: &tokio::sync::mpsc::Sender<crate::Result<FileNotifyInformation>>,
    items: Vec<FileNotifyInformation>,
    cancel: &tokio_util::sync::CancellationToken,
    capacity: usize,
) -> bool {
    for item in items {
        match sender.try_send(Ok(item)) {
            Ok(()) => {}
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                cancel.cancel();
                return false;
            }
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                cancel.cancel();
                let _ = sender
                    .send(Err(Error::EventQueueOverflow {
                        event: "change-notify",
                        capacity,
                    }))
                    .await;
                return false;
            }
        }
    }
    true
}

struct DirectoryWatchStream {
    receiver: tokio_stream::wrappers::ReceiverStream<crate::Result<FileNotifyInformation>>,
    cancel: tokio_util::sync::CancellationToken,
}

impl futures_core::Stream for DirectoryWatchStream {
    type Item = crate::Result<FileNotifyInformation>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.receiver).poll_next(cx)
    }
}

impl Drop for DirectoryWatchStream {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod watch_stream_tests {
    use super::*;

    fn notification(name: &str) -> FileNotifyInformation {
        FileNotifyInformation {
            action: NotifyAction::Added,
            file_name: name.into(),
        }
    }

    #[tokio::test]
    async fn consumer_lag_cancels_watch_and_reports_typed_overflow() {
        let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
        let cancel = tokio_util::sync::CancellationToken::new();
        let publish = tokio::spawn({
            let cancel = cancel.clone();
            async move {
                publish_change_batch(
                    &sender,
                    vec![notification("first"), notification("second")],
                    &cancel,
                    1,
                )
                .await
            }
        });
        assert!(receiver.recv().await.unwrap().is_ok());
        let overflow = receiver.recv().await.unwrap().unwrap_err();
        assert!(matches!(
            overflow,
            Error::EventQueueOverflow {
                event: "change-notify",
                capacity: 1,
            }
        ));
        assert!(!publish.await.unwrap());
        assert!(cancel.is_cancelled());
    }

    #[test]
    fn dropping_stream_cancels_its_owner_task() {
        let cancel = tokio_util::sync::CancellationToken::new();
        let (_sender, receiver) = tokio::sync::mpsc::channel(1);
        let stream = DirectoryWatchStream {
            receiver: tokio_stream::wrappers::ReceiverStream::new(receiver),
            cancel: cancel.clone(),
        };
        drop(stream);
        assert!(cancel.is_cancelled());
    }
}

/// Single result from a directory watch operation.
///
/// Implements `From<DirectoryWatchResult>` to convert into `Result<Vec<FileNotifyInformation>>`.
/// Note that all states except `Notifications` are converted into errors.
pub enum DirectoryWatchResult {
    /// A vector of file change notifications.
    Notifications(Vec<FileNotifyInformation>),

    /// The specified buffer size cannot contain the results.
    NotifyEnumDir { provided_size: usize },

    /// The watch was cleaned up by the server.
    ///
    /// This is usually due to file being closed, while watch is still active.
    Cleanup,

    /// The watch was cancelled by the user.
    Cancelled,

    /// An error occurred while watching the directory.
    Error(crate::Error),
}

impl From<DirectoryWatchResult> for crate::Result<Vec<FileNotifyInformation>> {
    fn from(val: DirectoryWatchResult) -> Self {
        match val {
            DirectoryWatchResult::Notifications(v) => Ok(v),
            DirectoryWatchResult::Cancelled => Err(Error::Cancelled("watch cancelled")),
            DirectoryWatchResult::Cleanup => Err(Error::Cancelled("watch cleaned up by server")),
            DirectoryWatchResult::Error(e) => Err(e),
            DirectoryWatchResult::NotifyEnumDir { provided_size } => Err(Error::BufferTooSmall {
                data_type: "FileNotifyInformation",
                required: None,
                provided: provided_size,
            }),
        }
    }
}

impl Deref for Directory {
    type Target = ResourceHandle;

    fn deref(&self) -> &Self::Target {
        &self.handle
    }
}

impl DerefMut for Directory {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.handle
    }
}

pub mod iter_stream {
    use super::*;
    use futures_core::Stream;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    /// A stream that allows you to iterate over the contents of a directory.
    /// See [Directory::query] for more information on how to use it.
    pub struct QueryDirectoryStream<'a, T> {
        /// A channel to receive the results from the query.
        /// This is used to send the results from the query loop to the stream.
        receiver: tokio::sync::mpsc::Receiver<crate::Result<T>>,
        /// This is used to wake up the query (against the server) loop when more data is required,
        /// since the iterator is lazy and will not fetch data until it is needed.
        notify_fetch_next: Arc<tokio::sync::Notify>,
        /// Holds the lock while iterating the directory,
        /// to prevent multiple queries at the same time.
        /// See [Directory::query] for more information.
        _lock_guard: MutexGuard<'a, ()>,
    }

    impl<'a, T> QueryDirectoryStream<'a, T>
    where
        T: QueryDirectoryInfoValue + for<'b> binrw::prelude::BinWrite<Args<'b> = ()> + Send,
    {
        pub async fn new(
            directory: &'a Arc<Directory>,
            pattern: String,
            buffer_size: u32,
        ) -> crate::Result<Self> {
            let (sender, receiver) = tokio::sync::mpsc::channel(1024);
            let notify_fetch_next = Arc::new(tokio::sync::Notify::new());
            {
                let notify_fetch_next = notify_fetch_next.clone();
                let directory = directory.clone();
                tokio::spawn(async move {
                    Self::fetch_loop(
                        directory,
                        pattern,
                        buffer_size,
                        sender,
                        notify_fetch_next.clone(),
                    )
                    .await;
                });
            }
            let guard = directory.query_lock.lock().await;
            Ok(Self {
                receiver,
                notify_fetch_next,
                _lock_guard: guard,
            })
        }

        async fn fetch_loop(
            directory: Arc<Directory>,
            pattern: String,
            buffer_size: u32,
            sender: mpsc::Sender<crate::Result<T>>,
            notify_fetch_next: Arc<tokio::sync::Notify>,
        ) {
            let mut is_first = true;
            loop {
                let result = directory
                    .send_query::<T>(&pattern, is_first, buffer_size)
                    .await;
                is_first = false;

                match result {
                    Ok(items) => {
                        if items.is_empty() {
                            // No more files, exit the loop
                            break;
                        }
                        for item in items {
                            if sender.send(Ok(item)).await.is_err() {
                                return; // Receiver dropped
                            }
                        }
                    }
                    Err(e) => {
                        if sender.send(Err(e)).await.is_err() {
                            return; // Receiver dropped
                        }
                    }
                }

                // Notify the stream that a new batch is available
                notify_fetch_next.notify_waiters();
                notify_fetch_next.notified().await;
            }
        }
    }

    impl<'a, T> Stream for QueryDirectoryStream<'a, T>
    where
        T: QueryDirectoryInfoValue + Unpin + Send,
    {
        type Item = crate::Result<T>;

        fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            let this = self.get_mut();
            match this.receiver.poll_recv(cx) {
                Poll::Ready(Some(value)) => {
                    if this.receiver.is_empty() {
                        this.notify_fetch_next.notify_waiters() // Notify that batch is done
                    }
                    Poll::Ready(Some(value))
                }
                Poll::Ready(None) => Poll::Ready(None), // Stream is closed!
                Poll::Pending => Poll::Pending,
            }
        }
    }
}
