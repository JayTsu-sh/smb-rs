use crate::error::*;
use crate::{SmbTransport, SmbTransportRead, SmbTransportWrite};

use futures_core::future::BoxFuture;
use std::net::SocketAddr;
use std::time::Duration;

use futures_util::FutureExt;
use tokio::{
    io::{self, AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, tcp},
    select,
};

use binrw::prelude::*;

type TcpRead = tcp::OwnedReadHalf;
type TcpWrite = tcp::OwnedWriteHalf;
pub struct TcpTransport {
    reader: Option<TcpRead>,
    writer: Option<TcpWrite>,
    timeout: Duration,
}

impl TcpTransport {
    pub const DEFAULT_PORT: u16 = 445;

    pub fn new(timeout: Duration) -> TcpTransport {
        TcpTransport {
            reader: None,
            writer: None,
            timeout,
        }
    }

    /// Connects to a NetBios server in the specified endpoint with a timeout.
    /// This is the async version of [connect](NetBiosClient::connect) -
    /// using the [tokio::net::TcpStream] as the underlying socket provider.
    async fn connect_timeout(&mut self, endpoint: &SocketAddr) -> Result<TcpStream> {
        if self.timeout == Duration::ZERO {
            tracing::debug!("Connecting to {endpoint}.",);
            return TcpStream::connect(&endpoint).await.map_err(Into::into);
        }

        tracing::debug!("Connecting to {endpoint} with timeout {:?}.", self.timeout);
        select! {
            res = TcpStream::connect(&endpoint) => res.map_err(Into::into),
            _ = tokio::time::sleep(self.timeout) => Err(
                TransportError::Timeout(self.timeout)
            ),
        }
    }

    /// Split socket into read and write halves.
    fn split_socket(socket: TcpStream) -> (TcpRead, TcpWrite) {
        socket.into_split()
    }

    /// Maps a TCP error to a crate error.
    /// Connection aborts and unexpected EOFs are mapped to [Error::NotConnected].
    #[inline]
    fn map_tcp_error(e: io::Error) -> TransportError {
        if e.kind() == io::ErrorKind::ConnectionAborted || e.kind() == io::ErrorKind::UnexpectedEof
        {
            tracing::error!("Got IO error: {e} -- Connection Error, notify NotConnected!");
            return TransportError::NotConnected;
        }
        if e.kind() == io::ErrorKind::WouldBlock {
            tracing::trace!("Got IO error: {e} -- with ErrorKind::WouldBlock.");
        } else {
            tracing::error!("Got IO error: {e} -- Mapping to IO error.",);
        }
        e.into()
    }

    #[inline]
    async fn receive_exact(&mut self, out_buf: &mut [u8]) -> Result<()> {
        let reader = self.reader.as_mut().ok_or(TransportError::NotConnected)?;
        tracing::trace!("Reading {} bytes.", out_buf.len());
        reader
            .read_exact(out_buf)
            .await
            .map_err(Self::map_tcp_error)?;
        tracing::trace!("Read {} bytes OK.", out_buf.len());
        Ok(())
    }

    #[inline]
    async fn send_raw(&mut self, message: &[u8]) -> Result<()> {
        tracing::trace!("Sending {} bytes.", message.len());
        let writer = self.writer.as_mut().ok_or(TransportError::NotConnected)?;
        writer
            .write_all(message)
            .await
            .map_err(Self::map_tcp_error)?;
        Ok(())
    }

    #[inline]
    #[tracing::instrument(level = "debug", skip_all, fields(addr = %server_address))]
    async fn do_connect(&mut self, _server_name: &str, server_address: SocketAddr) -> Result<()> {
        let socket = self.connect_timeout(&server_address).await?;
        let (r, w) = Self::split_socket(socket);
        self.reader = Some(r);
        self.writer = Some(w);
        Ok(())
    }
}

impl SmbTransport for TcpTransport {
    fn connect<'a>(
        &'a mut self,
        server_name: &'a str,
        server_address: SocketAddr,
    ) -> BoxFuture<'a, Result<()>> {
        self.do_connect(server_name, server_address).boxed()
    }

    fn split(self: Box<Self>) -> Result<(Box<dyn SmbTransportRead>, Box<dyn SmbTransportWrite>)> {
        Ok((
            Box::new(Self {
                reader: self.reader,
                writer: None,
                timeout: self.timeout,
            }),
            Box::new(Self {
                reader: None,
                writer: self.writer,
                timeout: self.timeout,
            }),
        ))
    }

    fn default_port(&self) -> u16 {
        Self::DEFAULT_PORT
    }

    fn remote_address(&self) -> Result<SocketAddr> {
        self.reader
            .as_ref()
            .ok_or(TransportError::NotConnected)?
            .peer_addr()
            .map_err(Into::into)
    }
}

impl SmbTransportWrite for TcpTransport {
    fn send_raw<'a>(&'a mut self, buf: &'a [u8]) -> BoxFuture<'a, Result<()>> {
        self.send_raw(buf).boxed()
    }

    /// Override send for TCP async: use `write_all_buf` with vectored I/O support.
    /// This sends header + all IoVec buffers using minimal syscalls via `Buf::chunks_vectored`.
    fn send<'a>(&'a mut self, data: &'a crate::IoVec) -> BoxFuture<'a, Result<()>> {
        use crate::iovec::HeaderAndIoVec;
        use tokio::io::AsyncWriteExt;

        async {
            let header = crate::SmbTcpMessageHeader {
                stream_protocol_length: data.total_size() as u32,
            };
            let mut header_buf = [0u8; crate::SmbTcpMessageHeader::SIZE];
            header.write(&mut std::io::Cursor::new(header_buf.as_mut_slice()))?;

            let mut buf = HeaderAndIoVec::new(&header_buf, data);
            let writer = self.writer.as_mut().ok_or(TransportError::NotConnected)?;
            writer
                .write_all_buf(&mut buf)
                .await
                .map_err(Self::map_tcp_error)?;

            Ok(())
        }
        .boxed()
    }
}

impl SmbTransportRead for TcpTransport {
    fn receive_exact<'a>(&'a mut self, out_buf: &'a mut [u8]) -> BoxFuture<'a, Result<()>> {
        self.receive_exact(out_buf).boxed()
    }
}
