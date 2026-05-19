//! In-process [`SmbTransport`] mock for deterministic transcript replay.
//!
//! # Model
//!
//! A [`TranscriptControl`] handle is created up front. Tests push **server
//! frames** (raw SMB body bytes — *without* the 4-byte NetBIOS length
//! prefix) into the control's queue; the production [`Connection`] code
//! then drives the [`MockTransport`] via the standard
//! [`SmbTransport`]/[`SmbTransportRead`]/[`SmbTransportWrite`] traits,
//! consuming queued frames on each `receive()` and capturing each
//! outbound `send()` for later assertion.
//!
//! Captured client frames are also stored as raw SMB body bytes (the
//! 4-byte NetBIOS header is stripped). This makes transcript assertions
//! independent of framing detail.
//!
//! # Threading
//!
//! Internally everything is guarded by `std::sync::Mutex`. The mock is
//! intended for single-connection test scenarios where send/recv runs on
//! tokio tasks but contention is trivial. Mutexes are never held across
//! `.await` points.
//!
//! # Lifetime
//!
//! `Connection::from_transport` calls `transport.split()` early. The
//! resulting read and write halves carry independent state but share the
//! same [`TranscriptControl`] via `Arc`, so the test driver can still
//! push frames and inspect captures from outside.

use bytes::{Buf, Bytes, BytesMut};
use futures_core::future::BoxFuture;
use futures_util::FutureExt;
use smb_transport::error::{Result, TransportError};
use smb_transport::{SmbTransport, SmbTransportRead, SmbTransportWrite};
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::sync::Notify;

/// Shared scripting / inspection handle. Cheap to `clone()`.
#[derive(Clone, Debug, Default)]
pub struct TranscriptControl {
    inner: Arc<TranscriptInner>,
}

#[derive(Default, Debug)]
struct TranscriptInner {
    server_frames: Mutex<VecDeque<Bytes>>,
    client_frames: Mutex<Vec<Bytes>>,
    /// Notified by `push_server_frame` so a `MockRead` that's currently
    /// waiting on an empty queue can wake up. Without this, the read
    /// half would either busy-spin or have to return an error — and
    /// returning `TransportError::NotConnected` triggers a worker-wide
    /// shutdown that interrupts the client *before* it gets to send
    /// the next request.
    frame_pushed: Notify,
}

impl TranscriptControl {
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue a server-emitted SMB message (raw bytes, no NetBIOS prefix)
    /// to be delivered on the next `receive()` call.
    pub fn push_server_frame(&self, frame: impl Into<Bytes>) {
        self.inner
            .server_frames
            .lock()
            .expect("transcript mutex poisoned")
            .push_back(frame.into());
        // Wake any read half currently parked on an empty queue.
        self.inner.frame_pushed.notify_one();
    }

    /// Snapshot of every wire frame the client has emitted so far.
    /// Each entry is one SMB message body (the 4-byte NB header is stripped).
    pub fn captured_client_frames(&self) -> Vec<Bytes> {
        self.inner
            .client_frames
            .lock()
            .expect("transcript mutex poisoned")
            .clone()
    }

    /// Number of frames captured. Equivalent to
    /// `self.captured_client_frames().len()` but avoids the clone.
    pub fn client_frame_count(&self) -> usize {
        self.inner
            .client_frames
            .lock()
            .expect("transcript mutex poisoned")
            .len()
    }

    /// Number of server frames still queued for delivery (i.e. that the
    /// client has not yet read).
    pub fn pending_server_frames(&self) -> usize {
        self.inner
            .server_frames
            .lock()
            .expect("transcript mutex poisoned")
            .len()
    }
}

/// Full-duplex mock. Implements [`SmbTransport`] so it can be passed to
/// [`Connection::from_transport`]; on `split()` it yields independent
/// read and write halves that share the underlying [`TranscriptControl`].
pub struct MockTransport {
    read: MockRead,
    write: MockWrite,
    remote_addr: SocketAddr,
}

impl MockTransport {
    /// Construct a fresh transport bound to a synthetic loopback address.
    /// Returns `(transport, control)` so tests can drive both sides.
    pub fn new() -> (Box<Self>, TranscriptControl) {
        let control = TranscriptControl::new();
        let transport = Self {
            read: MockRead::new(control.clone()),
            write: MockWrite::new(control.clone()),
            remote_addr: "127.0.0.1:445".parse().expect("fixed literal addr"),
        };
        (Box::new(transport), control)
    }
}

impl SmbTransport for MockTransport {
    fn connect<'a>(
        &'a mut self,
        _server_name: &'a str,
        _address: SocketAddr,
    ) -> BoxFuture<'a, Result<()>> {
        async { Ok(()) }.boxed()
    }

    fn default_port(&self) -> u16 {
        445
    }

    fn split(
        self: Box<Self>,
    ) -> Result<(Box<dyn SmbTransportRead>, Box<dyn SmbTransportWrite>)> {
        let me = *self;
        Ok((Box::new(me.read), Box::new(me.write)))
    }

    fn remote_address(&self) -> Result<SocketAddr> {
        Ok(self.remote_addr)
    }
}

// The full-duplex form must also expose the half traits because
// `SmbTransport: SmbTransportRead + SmbTransportWrite`. The production
// `Connection::from_transport` path immediately calls `split()`, so
// in practice these are never exercised on the un-split object —
// nevertheless we forward them properly for completeness.

impl SmbTransportRead for MockTransport {
    fn receive_exact<'a>(&'a mut self, out_buf: &'a mut [u8]) -> BoxFuture<'a, Result<()>> {
        self.read.receive_exact(out_buf)
    }
}

impl SmbTransportWrite for MockTransport {
    fn send_raw<'a>(&'a mut self, buf: &'a [u8]) -> BoxFuture<'a, Result<()>> {
        self.write.send_raw(buf)
    }
}

// -- Read half -------------------------------------------------------------

/// Read half of [`MockTransport`].
///
/// Models the production wire-read state machine: each frame is consumed
/// from the front of [`TranscriptControl::server_frames`] and prepended
/// with the 4-byte NetBIOS length prefix that the production
/// [`SmbTransportRead::receive`] default impl expects to parse. The
/// resulting bytes are then drip-fed through successive `receive_exact()`
/// calls (one for the 4-byte header, one for the body).
pub struct MockRead {
    control: TranscriptControl,
    /// Bytes ready to be consumed by upcoming `receive_exact` calls,
    /// holding `[4-byte NB header || SMB body]`. Refilled when empty.
    buffer: BytesMut,
}

impl MockRead {
    fn new(control: TranscriptControl) -> Self {
        Self {
            control,
            buffer: BytesMut::new(),
        }
    }

    async fn refill_from_queue(&mut self) -> Result<()> {
        loop {
            // Acquire the `Notified` future BEFORE the empty-check, per
            // tokio's documented race-free pattern. If
            // `push_server_frame` notifies between our pop attempt and
            // `notified().await`, the notification is buffered on the
            // already-registered Notified and we wake on the next poll
            // instead of hanging forever.
            let notified = self.control.inner.frame_pushed.notified();
            tokio::pin!(notified);

            let popped = {
                let mut q = self
                    .control
                    .inner
                    .server_frames
                    .lock()
                    .expect("transcript mutex poisoned");
                q.pop_front()
            };
            if let Some(frame) = popped {
                let len = frame.len() as u32;
                self.buffer.reserve(4 + frame.len());
                self.buffer.extend_from_slice(&len.to_be_bytes());
                self.buffer.extend_from_slice(&frame);
                return Ok(());
            }
            // Queue empty — park until a push wakes us. Returning an
            // error here would tear the worker down and prevent the
            // client from sending later requests, breaking transcripts
            // that push more frames after the first.
            notified.await;
        }
    }
}

impl SmbTransportRead for MockRead {
    fn receive_exact<'a>(&'a mut self, out_buf: &'a mut [u8]) -> BoxFuture<'a, Result<()>> {
        async move {
            let mut filled = 0;
            while filled < out_buf.len() {
                if self.buffer.is_empty() {
                    self.refill_from_queue().await?;
                }
                let take = std::cmp::min(self.buffer.len(), out_buf.len() - filled);
                out_buf[filled..filled + take].copy_from_slice(&self.buffer[..take]);
                self.buffer.advance(take);
                filled += take;
            }
            Ok(())
        }
        .boxed()
    }
}

// -- Write half ------------------------------------------------------------

/// Write half of [`MockTransport`].
///
/// `SmbTransportWrite`'s default `send(IoVec)` invokes `send_raw` once
/// for the 4-byte NB header, then once per IoVec chunk for the body. We
/// reassemble each logical frame by tracking how many body bytes remain
/// after the NB header has arrived; once the body is complete the frame
/// is appended to [`TranscriptControl::client_frames`].
pub struct MockWrite {
    control: TranscriptControl,
    phase: SendPhase,
    body_accumulator: Vec<u8>,
}

enum SendPhase {
    AwaitingHeader,
    AwaitingBody { remaining: usize },
}

impl MockWrite {
    fn new(control: TranscriptControl) -> Self {
        Self {
            control,
            phase: SendPhase::AwaitingHeader,
            body_accumulator: Vec::new(),
        }
    }

    fn feed(&mut self, mut buf: &[u8]) -> Result<()> {
        while !buf.is_empty() {
            match self.phase {
                SendPhase::AwaitingHeader => {
                    if buf.len() < 4 {
                        return Err(TransportError::IoError(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!(
                                "MockTransport: NetBIOS header send_raw received only {} bytes, expected 4",
                                buf.len()
                            ),
                        )));
                    }
                    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
                    self.phase = SendPhase::AwaitingBody {
                        remaining: len as usize,
                    };
                    self.body_accumulator.clear();
                    self.body_accumulator.reserve(len as usize);
                    buf = &buf[4..];
                }
                SendPhase::AwaitingBody { remaining } => {
                    let take = std::cmp::min(remaining, buf.len());
                    self.body_accumulator.extend_from_slice(&buf[..take]);
                    let new_remaining = remaining - take;
                    if new_remaining == 0 {
                        let frame =
                            Bytes::from(std::mem::take(&mut self.body_accumulator));
                        self.control
                            .inner
                            .client_frames
                            .lock()
                            .expect("transcript mutex poisoned")
                            .push(frame);
                        self.phase = SendPhase::AwaitingHeader;
                    } else {
                        self.phase = SendPhase::AwaitingBody {
                            remaining: new_remaining,
                        };
                    }
                    buf = &buf[take..];
                }
            }
        }
        Ok(())
    }
}

impl SmbTransportWrite for MockWrite {
    fn send_raw<'a>(&'a mut self, buf: &'a [u8]) -> BoxFuture<'a, Result<()>> {
        async move { self.feed(buf) }.boxed()
    }
}
