use std::ops::{Deref, DerefMut};

use bytes::Bytes;
use smb_msg::{IoctlBuffer, PipeTransceiveRequest, ReadRequest, WriteRequest};

use super::{ResourceHandle, file::FileOperationOptions};
use crate::command::{CommandRequest, ResponseOptions};

pub struct Pipe {
    pub(crate) handle: ResourceHandle,
}

impl Pipe {
    pub fn new(handle: ResourceHandle) -> Self {
        Self { handle }
    }

    pub(crate) async fn read_bytes_with_options(
        &self,
        max_len: u32,
        operation: FileOperationOptions,
    ) -> crate::Result<Bytes> {
        if max_len == 0 {
            return Ok(Bytes::new());
        }
        let request = CommandRequest::new(
            ReadRequest {
                flags: Default::default(),
                length: max_len,
                offset: 0,
                file_id: self.handle.file_id().await?,
                minimum_count: 0,
            }
            .into(),
        );
        let mut options = ResponseOptions::new().with_allow_async(true);
        if let Some(timeout) = operation.timeout {
            options = options.with_timeout(timeout);
        }
        if let Some(cancellation) = operation.cancellation {
            options = options.with_cancellation_token(cancellation);
        }
        let response = self
            .handle
            .execute_request_with_replay(request, options, operation.replay)
            .await?;
        let content = response.message.content.to_read()?;
        let range = content.data_range(response.raw.len())?;
        Ok(response.raw.slice(range.as_range()))
    }

    pub(crate) async fn write_bytes_with_options(
        &self,
        bytes: Bytes,
        operation: FileOperationOptions,
    ) -> crate::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let expected = u32::try_from(bytes.len())?;
        let request = CommandRequest::new(
            WriteRequest::new(
                0,
                self.handle.file_id().await?,
                Default::default(),
                expected,
            )
            .into(),
        )
        .with_additional_data(bytes);
        let mut options = ResponseOptions::new().with_allow_async(true);
        if let Some(timeout) = operation.timeout {
            options = options.with_timeout(timeout);
        }
        if let Some(cancellation) = operation.cancellation {
            options = options.with_cancellation_token(cancellation);
        }
        let response = self
            .handle
            .execute_request_with_replay(request, options, operation.replay)
            .await?;
        Ok(response.message.content.to_write()?.count as usize)
    }

    pub(crate) async fn transact_bytes(
        &self,
        request: Bytes,
        max_response: u32,
        operation: FileOperationOptions,
    ) -> crate::Result<Bytes> {
        let response = self
            .handle
            .fsctl_with_operation(
                PipeTransceiveRequest::from(IoctlBuffer::from(request.to_vec())),
                max_response,
                operation,
            )
            .await?;
        Ok(Bytes::copy_from_slice(response.as_ref()))
    }
}

impl Deref for Pipe {
    type Target = ResourceHandle;

    fn deref(&self) -> &Self::Target {
        &self.handle
    }
}

impl DerefMut for Pipe {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.handle
    }
}
