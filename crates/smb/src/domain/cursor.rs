use std::{
    io::{Error as IoError, ErrorKind, SeekFrom},
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use futures_core::future::BoxFuture;
use tokio::io::{AsyncRead, AsyncSeek, AsyncWrite, ReadBuf};

use super::File;

/// An independent cursor over a File. Positioned File operations remain
/// concurrent because cursor position belongs to this value alone.
pub struct FileCursor<'a> {
    file: &'a File,
    position: u64,
    pending_read: Option<BoxFuture<'a, crate::Result<Bytes>>>,
    pending_write: Option<BoxFuture<'a, crate::Result<usize>>>,
}

impl<'a> FileCursor<'a> {
    pub(crate) fn new(file: &'a File) -> Self {
        Self {
            file,
            position: 0,
            pending_read: None,
            pending_write: None,
        }
    }

    pub const fn position(&self) -> u64 {
        self.position
    }

    fn io_error(error: crate::Error) -> IoError {
        IoError::other(error)
    }

    fn seek_from(base: u64, delta: i64) -> std::io::Result<u64> {
        if delta >= 0 {
            base.checked_add(delta as u64)
                .ok_or_else(|| IoError::new(ErrorKind::InvalidInput, "seek offset overflow"))
        } else {
            base.checked_sub(delta.unsigned_abs())
                .ok_or_else(|| IoError::new(ErrorKind::InvalidInput, "seek before file start"))
        }
    }
}

impl AsyncRead for FileCursor<'_> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if self.pending_read.is_none() {
            let length = match u32::try_from(buffer.remaining()) {
                Ok(length) => length,
                Err(error) => {
                    return Poll::Ready(Err(IoError::new(ErrorKind::InvalidInput, error)));
                }
            };
            let file = self.file;
            let position = self.position;
            self.pending_read = Some(Box::pin(file.read_at(position, length)));
        }
        let Some(future) = self.pending_read.as_mut() else {
            return Poll::Ready(Err(IoError::other("read future was not installed")));
        };
        let result = future.as_mut().poll(cx);
        match result {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(bytes)) => {
                self.pending_read = None;
                buffer.put_slice(&bytes);
                self.position = self
                    .position
                    .checked_add(bytes.len() as u64)
                    .ok_or_else(|| {
                        IoError::new(ErrorKind::InvalidData, "read position overflow")
                    })?;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => {
                self.pending_read = None;
                Poll::Ready(Err(Self::io_error(error)))
            }
        }
    }
}

impl AsyncWrite for FileCursor<'_> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if buffer.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.pending_write.is_none() {
            let file = self.file;
            let position = self.position;
            let bytes = Bytes::copy_from_slice(buffer);
            self.pending_write = Some(Box::pin(file.write_at(position, bytes)));
        }
        let Some(future) = self.pending_write.as_mut() else {
            return Poll::Ready(Err(IoError::other("write future was not installed")));
        };
        let result = future.as_mut().poll(cx);
        match result {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(written)) => {
                self.pending_write = None;
                self.position = self.position.checked_add(written as u64).ok_or_else(|| {
                    IoError::new(ErrorKind::InvalidData, "write position overflow")
                })?;
                Poll::Ready(Ok(written))
            }
            Poll::Ready(Err(error)) => {
                self.pending_write = None;
                Poll::Ready(Err(Self::io_error(error)))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncSeek for FileCursor<'_> {
    fn start_seek(mut self: Pin<&mut Self>, position: SeekFrom) -> std::io::Result<()> {
        if self.pending_read.is_some() || self.pending_write.is_some() {
            return Err(IoError::new(
                ErrorKind::InvalidInput,
                "cannot seek while cursor I/O is pending",
            ));
        }
        self.position = match position {
            SeekFrom::Start(position) => position,
            SeekFrom::Current(delta) => Self::seek_from(self.position, delta)?,
            SeekFrom::End(delta) => Self::seek_from(self.file.opened_len(), delta)?,
        };
        Ok(())
    }

    fn poll_complete(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<u64>> {
        Poll::Ready(Ok(self.position))
    }
}

#[cfg(test)]
mod tests {
    use super::FileCursor;

    #[test]
    fn relative_seek_is_checked_in_both_directions() {
        assert_eq!(FileCursor::seek_from(10, 5).unwrap(), 15);
        assert_eq!(FileCursor::seek_from(10, -5).unwrap(), 5);
        assert!(FileCursor::seek_from(0, -1).is_err());
        assert!(FileCursor::seek_from(u64::MAX, 1).is_err());
    }
}
