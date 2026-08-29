//! Deterministic transport Adapter for protocol and lifecycle tests.

use crate::error::{Result, TransportError};
use crate::iovec::SendCursor;
use crate::{SendFrame, SmbTransport, SmbTransportRead, SmbTransportWrite};
use bytes::{Buf, Bytes, BytesMut};
use futures_core::future::BoxFuture;
use futures_util::FutureExt;
use std::collections::{BTreeMap, VecDeque};
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::Notify;

#[derive(Clone, Debug, Default)]
pub struct ScriptedTransportControl {
    inner: Arc<ScriptedTransportState>,
}

#[derive(Debug, Default)]
struct ScriptedTransportState {
    server_frames: Mutex<VecDeque<Bytes>>,
    client_frames: Mutex<Vec<Bytes>>,
    read_faults: Mutex<BTreeMap<usize, ErrorKind>>,
    write_faults: Mutex<BTreeMap<usize, ErrorKind>>,
    read_operations: AtomicUsize,
    write_operations: AtomicUsize,
    frame_pushed: Notify,
    frame_captured: Notify,
}

impl ScriptedTransportControl {
    pub fn push_server_frame(&self, frame: impl Into<Bytes>) {
        self.inner
            .server_frames
            .lock()
            .expect("scripted transport server queue poisoned")
            .push_back(frame.into());
        self.inner.frame_pushed.notify_one();
    }

    pub fn pending_server_frames(&self) -> usize {
        self.inner
            .server_frames
            .lock()
            .expect("scripted transport server queue poisoned")
            .len()
    }

    /// Fail one one-based `receive_exact` operation with a typed I/O error.
    pub fn fail_read_on(&self, operation: usize, kind: ErrorKind) {
        assert!(operation > 0, "scripted operation indexes are one-based");
        self.inner
            .read_faults
            .lock()
            .expect("scripted transport read faults poisoned")
            .insert(operation, kind);
    }

    /// Fail one one-based `send_raw` operation with a typed I/O error.
    pub fn fail_write_on(&self, operation: usize, kind: ErrorKind) {
        assert!(operation > 0, "scripted operation indexes are one-based");
        self.inner
            .write_faults
            .lock()
            .expect("scripted transport write faults poisoned")
            .insert(operation, kind);
    }

    pub fn captured_client_frames(&self) -> Vec<Bytes> {
        self.inner
            .client_frames
            .lock()
            .expect("scripted transport client frames poisoned")
            .clone()
    }

    pub fn client_frame_count(&self) -> usize {
        self.inner
            .client_frames
            .lock()
            .expect("scripted transport client frames poisoned")
            .len()
    }

    pub async fn wait_for_client_frames(
        &self,
        minimum: usize,
        timeout: std::time::Duration,
    ) -> bool {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let captured = self.inner.frame_captured.notified();
            tokio::pin!(captured);
            if self.client_frame_count() >= minimum {
                return true;
            }
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return false;
            }
            if tokio::time::timeout(remaining, captured).await.is_err() {
                return self.client_frame_count() >= minimum;
            }
        }
    }

    /// Deterministically drive the production send cursor with writes no
    /// larger than `maximum_write`, capturing the resulting framed message.
    pub fn capture_send_frame(&self, frame: &SendFrame, maximum_write: usize) -> Result<()> {
        if maximum_write == 0 {
            return Err(TransportError::WriteZero);
        }
        let mut writer = ScriptedWrite::new(self.clone());
        let mut cursor = SendCursor::new(frame)?;
        while cursor.has_remaining() {
            let chunk = cursor.chunk();
            let written = chunk.len().min(maximum_write);
            if written == 0 {
                return Err(TransportError::WriteZero);
            }
            writer.feed(&chunk[..written])?;
            cursor.try_advance(written)?;
        }
        Ok(())
    }

    fn take_read_fault(&self) -> Option<ErrorKind> {
        let operation = self.inner.read_operations.fetch_add(1, Ordering::Relaxed) + 1;
        self.inner
            .read_faults
            .lock()
            .expect("scripted transport read faults poisoned")
            .remove(&operation)
    }

    fn take_write_fault(&self) -> Option<ErrorKind> {
        let operation = self.inner.write_operations.fetch_add(1, Ordering::Relaxed) + 1;
        self.inner
            .write_faults
            .lock()
            .expect("scripted transport write faults poisoned")
            .remove(&operation)
    }
}

pub struct ScriptedTransport {
    read: ScriptedRead,
    write: ScriptedWrite,
    remote_address: SocketAddr,
}

impl ScriptedTransport {
    pub fn new() -> (Box<Self>, ScriptedTransportControl) {
        let control = ScriptedTransportControl::default();
        let transport = Self {
            read: ScriptedRead::new(control.clone()),
            write: ScriptedWrite::new(control.clone()),
            remote_address: SocketAddr::from(([127, 0, 0, 1], 445)),
        };
        (Box::new(transport), control)
    }
}

impl SmbTransport for ScriptedTransport {
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

    fn split(self: Box<Self>) -> Result<(Box<dyn SmbTransportRead>, Box<dyn SmbTransportWrite>)> {
        Ok((Box::new(self.read), Box::new(self.write)))
    }

    fn remote_address(&self) -> Result<SocketAddr> {
        Ok(self.remote_address)
    }
}

impl SmbTransportRead for ScriptedTransport {
    fn receive_exact<'a>(&'a mut self, out: &'a mut [u8]) -> BoxFuture<'a, Result<()>> {
        self.read.receive_exact(out)
    }
}

impl SmbTransportWrite for ScriptedTransport {
    fn send_raw<'a>(&'a mut self, bytes: &'a [u8]) -> BoxFuture<'a, Result<()>> {
        self.write.send_raw(bytes)
    }
}

struct ScriptedRead {
    control: ScriptedTransportControl,
    buffered: BytesMut,
}

impl ScriptedRead {
    fn new(control: ScriptedTransportControl) -> Self {
        Self {
            control,
            buffered: BytesMut::new(),
        }
    }

    async fn refill(&mut self) {
        loop {
            let notified = self.control.inner.frame_pushed.notified();
            tokio::pin!(notified);
            let frame = self
                .control
                .inner
                .server_frames
                .lock()
                .expect("scripted transport server queue poisoned")
                .pop_front();
            if let Some(frame) = frame {
                self.buffered.reserve(4 + frame.len());
                self.buffered
                    .extend_from_slice(&(frame.len() as u32).to_be_bytes());
                self.buffered.extend_from_slice(&frame);
                return;
            }
            notified.await;
        }
    }
}

impl SmbTransportRead for ScriptedRead {
    fn receive_exact<'a>(&'a mut self, out: &'a mut [u8]) -> BoxFuture<'a, Result<()>> {
        async move {
            if let Some(kind) = self.control.take_read_fault() {
                return Err(TransportError::IoError(std::io::Error::new(
                    kind,
                    "scripted read fault",
                )));
            }
            let mut filled = 0;
            while filled < out.len() {
                if self.buffered.is_empty() {
                    self.refill().await;
                }
                let count = self.buffered.len().min(out.len() - filled);
                out[filled..filled + count].copy_from_slice(&self.buffered[..count]);
                self.buffered.advance(count);
                filled += count;
            }
            Ok(())
        }
        .boxed()
    }
}

struct ScriptedWrite {
    control: ScriptedTransportControl,
    phase: WritePhase,
    body: Vec<u8>,
}

enum WritePhase {
    Header { bytes: [u8; 4], filled: usize },
    Body(usize),
}

impl ScriptedWrite {
    fn new(control: ScriptedTransportControl) -> Self {
        Self {
            control,
            phase: WritePhase::Header {
                bytes: [0; 4],
                filled: 0,
            },
            body: Vec::new(),
        }
    }

    fn feed(&mut self, mut bytes: &[u8]) -> Result<()> {
        while !bytes.is_empty() {
            let mut transition = None;
            match &mut self.phase {
                WritePhase::Header {
                    bytes: header,
                    filled,
                } => {
                    let count = (4 - *filled).min(bytes.len());
                    header[*filled..*filled + count].copy_from_slice(&bytes[..count]);
                    *filled += count;
                    bytes = &bytes[count..];
                    if *filled < 4 {
                        continue;
                    }
                    let length = u32::from_be_bytes(*header);
                    self.body.clear();
                    self.body.reserve(length as usize);
                    transition = Some(WritePhase::Body(length as usize));
                }
                WritePhase::Body(remaining) => {
                    let count = (*remaining).min(bytes.len());
                    self.body.extend_from_slice(&bytes[..count]);
                    bytes = &bytes[count..];
                    *remaining -= count;
                    if *remaining == 0 {
                        self.control
                            .inner
                            .client_frames
                            .lock()
                            .expect("scripted transport client frames poisoned")
                            .push(Bytes::from(std::mem::take(&mut self.body)));
                        self.control.inner.frame_captured.notify_waiters();
                        transition = Some(WritePhase::Header {
                            bytes: [0; 4],
                            filled: 0,
                        });
                    }
                }
            }
            if let Some(next) = transition {
                self.phase = next;
            }
        }
        Ok(())
    }
}

impl SmbTransportWrite for ScriptedWrite {
    fn send_raw<'a>(&'a mut self, bytes: &'a [u8]) -> BoxFuture<'a, Result<()>> {
        async move {
            if let Some(kind) = self.control.take_write_fault() {
                return Err(TransportError::IoError(std::io::Error::new(
                    kind,
                    "scripted write fault",
                )));
            }
            self.feed(bytes)
        }
        .boxed()
    }
}
