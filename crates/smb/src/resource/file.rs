use super::*;
use bytes::Bytes;
use std::ops::{Deref, DerefMut};

pub(crate) struct FileOperationOptions {
    pub(crate) timeout: Option<std::time::Duration>,
    pub(crate) cancellation: Option<tokio_util::sync::CancellationToken>,
    pub(crate) replay: crate::runtime::ReplayPolicy,
}

impl Default for FileOperationOptions {
    fn default() -> Self {
        Self {
            timeout: None,
            cancellation: None,
            replay: crate::runtime::ReplayPolicy::NeverReplay,
        }
    }
}

/// An opened file on the server.
///
/// # [std::io] Support
/// The [File] struct also supports the [Read][std::io::Read] and [Write][std::io::Write] traits.
/// Note that both of these traits are blocking, and will block the current thread until the operation is complete.
/// Use [File::read_block] and [File::write_block] for non-blocking operations.
/// The [File] struct also implements the [Seek][std::io::Seek] trait.
/// This allows you to seek to a specific position in the file, combined with the [Read][std::io::Read] and [Write][std::io::Write] traits.
/// Using any of the implemented [std::io] traits mentioned above should have no effect on calling the other, non-blocking methods.
/// Since we would NOT like to call a tokio task from a blocking context, these traits are **NOT** implemented in the async context!
///
/// You may not directly create this struct. Instead, use the [Tree::create][crate::tree::Tree::create] method to gain
/// a proper handle against the server in the shape of a [Resource], that can be then converted to a [File].
pub struct File {
    // `pub(crate)` so [`crate::resource::Resource::handle_mut`] can take a
    // mutable borrow during Phase C lease-slot attachment. External callers
    // still go through [`File::handle()`].
    pub(crate) handle: ResourceHandle,

    end_of_file: u64,
}

impl File {
    pub(crate) fn maximum_read_size(&self) -> u32 {
        self.handle.conn_info.negotiation.max_read_size
    }

    pub(crate) fn maximum_write_size(&self) -> u32 {
        self.handle.conn_info.negotiation.max_write_size
    }

    pub fn new(handle: ResourceHandle, end_of_file: u64) -> Self {
        File {
            handle,
            end_of_file,
        }
    }

    /// Returns the server-reported size at the moment the file was
    /// opened. Used by the Phase C lease cache to snapshot the file size
    /// in [`crate::lease::ResourceProto`] so cache-hit reopens can
    /// surface the same size without an extra QueryInfo RT.
    pub(crate) fn end_of_file(&self) -> u64 {
        self.end_of_file
    }

    pub(crate) async fn read_block_bytes_with_options(
        &self,
        max_len: u32,
        pos: u64,
        channel: Option<u32>,
        unbuffered: bool,
        options: FileOperationOptions,
    ) -> crate::Result<bytes::Bytes> {
        if max_len == 0 {
            return Ok(bytes::Bytes::new());
        }

        if !self.access.file_read_data() {
            return Err(Error::MissingPermissions("file read data".into()));
        }

        let response = self
            .send_read_request_with_options(max_len, pos, channel, unbuffered, options)
            .await?;
        if response.message.header.status()? == Status::EndOfFile {
            return Ok(bytes::Bytes::new());
        }
        let content = response
            .message
            .content
            .to_read()
            .map_err(|error| Error::InvalidMessage(error.to_string()))?;

        let data_range = content
            .data_range(response.raw.len())
            .map_err(|error| Error::InvalidMessage(error.to_string()))?;

        // Zero-copy: slice the immutable frame owner without copying payload.
        Ok(response.raw.slice(data_range.as_range()))
    }

    async fn send_read_request_with_options(
        &self,
        length: u32,
        pos: u64,
        channel: Option<u32>,
        unbuffered: bool,
        operation: FileOperationOptions,
    ) -> crate::Result<crate::command::CommandResponse> {
        let mut flags = ReadFlags::new();
        if self.handle.conn_info.config.compression_enabled
            && self.handle.conn_info.dialect.supports_compression()
        {
            flags.set_read_compressed(true);
        }

        if unbuffered && self.handle.conn_info.negotiation.dialect_rev >= Dialect::Smb0302 {
            flags.set_read_unbuffered(true);
        }

        let request = CommandRequest::new(
            ReadRequest {
                flags,
                length,
                offset: pos,
                file_id: self.handle.file_id().await?,
                minimum_count: 1,
            }
            .into(),
        )
        .with_channel_id(channel);

        let mut options = ResponseOptions::new()
            .with_allow_async(true)
            .with_cmd(Some(Command::Read))
            .with_status(&[Status::Success, Status::EndOfFile]);
        if let Some(timeout) = operation.timeout {
            options = options.with_timeout(timeout);
        }
        if let Some(cancellation) = operation.cancellation {
            options = options.with_cancellation_token(cancellation);
        }
        self.handle
            .execute_request_with_replay(request, options, operation.replay)
            .await
    }

    pub(crate) async fn write_block_zc_with_options(
        &self,
        buf: Bytes,
        pos: u64,
        channel: Option<u32>,
        operation: FileOperationOptions,
    ) -> crate::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        if !self.access.file_write_data() {
            return Err(Error::MissingPermissions("file write data".into()));
        }

        tracing::debug!(
            "Writing {} bytes at offset {} to {}",
            buf.len(),
            pos,
            self.handle.name()
        );

        // Bytes provides zero-copy clone via internal reference counting.
        let outgoing = CommandRequest::new(
            WriteRequest::new(
                pos,
                self.handle.file_id().await?,
                WriteFlags::new(),
                buf.len() as u32,
            )
            .into(),
        )
        .with_additional_data(buf)
        .with_channel_id(channel);

        let mut options = ResponseOptions::new().with_allow_async(true);
        if let Some(timeout) = operation.timeout {
            options = options.with_timeout(timeout);
        }
        if let Some(cancellation) = operation.cancellation {
            options = options.with_cancellation_token(cancellation);
        }
        let response = self
            .handle
            .execute_request_with_replay(outgoing, options, operation.replay)
            .await?;

        let content = response
            .message
            .content
            .to_write()
            .map_err(|error| Error::InvalidMessage(error.to_string()))?;
        let actual_written_length = content.count as usize;
        tracing::debug!(
            "Wrote {} bytes to {}.",
            actual_written_length,
            self.handle.name()
        );
        Ok(actual_written_length)
    }

    /// Sends a flush request to the server to flush the file.
    #[tracing::instrument(level = "debug", skip_all, fields(name = %self.handle.name()))]
    pub async fn flush(&self) -> std::io::Result<()> {
        let _response = self
            .handle
            .execute_content(
                FlushRequest {
                    file_id: self.handle.file_id().await.map_err(std::io::Error::other)?,
                }
                .into(),
                ResponseOptions::new().with_allow_async(true),
            )
            .await
            .map_err(|e| std::io::Error::other(e.to_string()))?;

        tracing::debug!("Flushed {}.", self.handle.name());
        Ok(())
    }
}

impl Deref for File {
    type Target = ResourceHandle;

    fn deref(&self) -> &Self::Target {
        &self.handle
    }
}

impl DerefMut for File {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.handle
    }
}
