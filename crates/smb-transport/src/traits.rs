use binrw::{BinRead, BinWrite};
use bytes::{Bytes, BytesMut};
use futures_core::future::BoxFuture;
use futures_util::FutureExt;
use std::{io::Cursor, net::SocketAddr};

use crate::{IoVec, SmbTcpMessageHeader, error::Result};

#[allow(async_fn_in_trait)]
pub trait SmbTransport: Send + SmbTransportRead + SmbTransportWrite {
    fn connect<'a>(
        &'a mut self,
        server_name: &'a str,
        address: SocketAddr,
    ) -> BoxFuture<'a, Result<()>>;

    fn default_port(&self) -> u16;

    /// Splits the transport into two separate transports:
    /// One for reading, and one for writing,
    /// given that the transport has both the reading and writing capabilities.
    fn split(self: Box<Self>) -> Result<(Box<dyn SmbTransportRead>, Box<dyn SmbTransportWrite>)>;

    /// Returns the local address of the transport.
    fn remote_address(&self) -> Result<SocketAddr>;
}

pub trait SmbTransportWrite: Send {
    fn send_raw<'a>(&'a mut self, buf: &'a [u8]) -> BoxFuture<'a, Result<()>>;

    fn send<'a>(&'a mut self, data: &'a IoVec) -> BoxFuture<'a, Result<()>> {
        async {
            // Transport Header (stack-allocated, no heap allocation for 4 bytes)
            let header = SmbTcpMessageHeader {
                stream_protocol_length: data.total_size() as u32,
            };
            let mut header_buf = [0u8; SmbTcpMessageHeader::SIZE];
            header.write(&mut Cursor::new(header_buf.as_mut_slice()))?;
            self.send_raw(&header_buf).await?;

            for buf in data.iter() {
                self.send_raw(buf).await?;
            }

            Ok(())
        }
        .boxed()
    }
}

pub trait SmbTransportWriteExt: SmbTransportWrite {
    /// Use this method to send a SMB message to the server.
    /// This sends the message itself, adding the transport header.
    fn send<'a>(&'a mut self, message: &'a [u8]) -> BoxFuture<'a, Result<()>>;
}

pub trait SmbTransportRead: Send {
    fn receive_exact<'a>(&'a mut self, out_buf: &'a mut [u8]) -> BoxFuture<'a, Result<()>>;

    /// Receive an SMB message from the transport, returning the raw bytes as `Bytes`.
    ///
    /// Uses `BytesMut` internally for zero-copy `freeze()` into `Bytes`.
    fn receive<'a>(&'a mut self) -> BoxFuture<'a, Result<Bytes>> {
        async {
            // Transport Header
            let mut header_data = [0; SmbTcpMessageHeader::SIZE];
            self.receive_exact(&mut header_data).await?;
            let header = SmbTcpMessageHeader::read(&mut Cursor::new(header_data))?;

            // Content - use BytesMut for zero-copy freeze into Bytes.
            let len = header.stream_protocol_length as usize;
            let mut data = BytesMut::zeroed(len);
            self.receive_exact(&mut data).await?;

            tracing::trace!(
                "Received SMB message of {} bytes from server: {:?}",
                data.len(),
                &data[..]
            );

            Ok(data.freeze())
        }
        .boxed()
    }
}

pub trait SmbTransportReadExt: SmbTransportRead {
    /// Use this method to receive a SMB message from the server.
    /// This returns the message itself, dropping the transport header.
    fn receive<'a>(&'a mut self) -> BoxFuture<'a, Result<Bytes>>;
}

impl SmbTransportReadExt for dyn SmbTransportRead + '_ {
    #[inline]
    fn receive<'a>(&'a mut self) -> BoxFuture<'a, Result<Bytes>> {
        self.receive()
    }
}

impl SmbTransportReadExt for dyn SmbTransport + '_ {
    #[inline]
    fn receive<'a>(&'a mut self) -> BoxFuture<'a, Result<Bytes>> {
        self.receive()
    }
}
