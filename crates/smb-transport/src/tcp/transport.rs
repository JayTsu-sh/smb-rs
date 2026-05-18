use crate::error::*;
use crate::{SmbTransport, SmbTransportRead, SmbTransportWrite};

#[cfg(feature = "async")]
use futures_core::future::BoxFuture;
use maybe_async::*;
use std::net::SocketAddr;
use std::time::Duration;

#[cfg(feature = "async")]
use futures_util::FutureExt;
#[cfg(not(feature = "async"))]
use std::{
    io::{self, Read, Write},
    net::TcpStream,
};
#[cfg(feature = "async")]
use tokio::{
    io::{self, AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, tcp},
    select,
};

use binrw::prelude::*;

#[cfg(feature = "async")]
type TcpRead = tcp::OwnedReadHalf;
#[cfg(feature = "async")]
type TcpWrite = tcp::OwnedWriteHalf;

#[cfg(not(feature = "async"))]
type TcpRead = TcpStream;
#[cfg(not(feature = "async"))]
type TcpWrite = TcpStream;
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
    /// This is the threaded version of [connect](NetBiosClient::connect) -
    /// using the [std::net::TcpStream] as the underlying socket provider.
    #[cfg(not(feature = "async"))]
    fn connect_timeout(&mut self, endpoint: &SocketAddr) -> Result<TcpStream> {
        if self.timeout == Duration::ZERO {
            tracing::debug!("Connecting to {endpoint}.");
            return TcpStream::connect(endpoint).map_err(Into::into);
        }

        tracing::debug!("Connecting to {endpoint} with timeout {:?}.", self.timeout);
        TcpStream::connect_timeout(endpoint, self.timeout).map_err(|e| match e.kind() {
            io::ErrorKind::TimedOut => {
                tracing::error!("Connection timed out after {:?}", self.timeout);
                TransportError::Timeout(self.timeout)
            }
            _ => {
                tracing::error!("Failed to connect to {endpoint}: {e}");
                e.into()
            }
        })
    }

    /// Connects to a NetBios server in the specified endpoint with a timeout.
    /// This is the async version of [connect](NetBiosClient::connect) -
    /// using the [tokio::net::TcpStream] as the underlying socket provider.
    #[cfg(feature = "async")]
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

    /// Async implementation of split socket to read and write halves.
    #[cfg(feature = "async")]
    fn split_socket(socket: TcpStream) -> (TcpRead, TcpWrite) {
        socket.into_split()
    }

    /// Sync implementation of split socket to read and write halves.
    #[cfg(not(feature = "async"))]
    fn split_socket(socket: TcpStream) -> (TcpRead, TcpWrite) {
        let rsocket = socket.try_clone().unwrap();
        let wsocket = socket;

        (rsocket, wsocket)
    }

    /// For synchronous implementations, gets the read timeout for the connection.
    #[cfg(not(feature = "async"))]
    pub fn read_timeout(&self) -> Result<Option<std::time::Duration>> {
        self.reader
            .as_ref()
            .ok_or(TransportError::NotConnected)?
            .read_timeout()
            .map_err(|e| e.into())
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

    #[maybe_async]
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

    #[maybe_async::maybe_async]
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

    #[maybe_async::maybe_async]
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
    #[cfg(feature = "async")]
    fn connect<'a>(
        &'a mut self,
        server_name: &'a str,
        server_address: SocketAddr,
    ) -> BoxFuture<'a, Result<()>> {
        self.do_connect(server_name, server_address).boxed()
    }
    #[cfg(not(feature = "async"))]
    fn connect(&mut self, server_name: &str, server_address: SocketAddr) -> Result<()> {
        self.do_connect(server_name, server_address)
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
    #[cfg(feature = "async")]
    fn send_raw<'a>(&'a mut self, buf: &'a [u8]) -> BoxFuture<'a, Result<()>> {
        self.send_raw(buf).boxed()
    }
    #[cfg(not(feature = "async"))]
    fn send_raw(&mut self, buf: &[u8]) -> Result<()> {
        self.send_raw(buf)
    }

    /// Override send for TCP async: use `write_all_buf` with vectored I/O support.
    /// This sends header + all IoVec buffers using minimal syscalls via `Buf::chunks_vectored`.
    #[cfg(feature = "async")]
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
    #[cfg(feature = "async")]
    fn receive_exact<'a>(&'a mut self, out_buf: &'a mut [u8]) -> BoxFuture<'a, Result<()>> {
        self.receive_exact(out_buf).boxed()
    }
    #[cfg(not(feature = "async"))]
    fn receive_exact(&mut self, out_buf: &mut [u8]) -> Result<()> {
        self.receive_exact(out_buf)
    }

    #[cfg(not(feature = "async"))]
    fn set_read_timeout(&self, timeout: std::time::Duration) -> Result<()> {
        self.reader
            .as_ref()
            .ok_or(TransportError::NotConnected)?
            .set_read_timeout(Some(timeout))
            .map_err(|e| e.into())
    }
}
