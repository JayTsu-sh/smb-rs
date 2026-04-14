use bytes::Bytes;
use std::ops::{Deref, DerefMut};

/// A buffer in an IoVec, either owned or shared.
///
/// This implements Deref to `&[u8]` for easy access to the underlying data.
///
/// Note that DerefMut is also implemented, but will panic if called on a Shared buffer,
/// since shared buffers cannot be mutated by default!
#[derive(Debug, Clone)]
pub enum IoVecBuf {
    Owned(Vec<u8>),
    Shared(Bytes),
}

impl Deref for IoVecBuf {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        match self {
            IoVecBuf::Owned(v) => v.as_slice(),
            IoVecBuf::Shared(v) => v.as_ref(),
        }
    }
}

impl DerefMut for IoVecBuf {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            IoVecBuf::Owned(v) => v.as_mut_slice(),
            IoVecBuf::Shared(_) => {
                panic!("Cannot get mutable reference to shared IoVecBuf");
            }
        }
    }
}

impl From<Vec<u8>> for IoVecBuf {
    fn from(v: Vec<u8>) -> Self {
        IoVecBuf::Owned(v)
    }
}

impl From<Bytes> for IoVecBuf {
    fn from(v: Bytes) -> Self {
        IoVecBuf::Shared(v)
    }
}

/// A vector of buffers for zero-copy I/O operations.
#[derive(Debug, Clone, Default)]
pub struct IoVec(Vec<IoVecBuf>);

impl IoVec {
    /// Returns the total size of all buffers in the IoVec (in bytes).
    pub fn total_size(&self) -> usize {
        self.0.iter().map(|buf| buf.len()).sum()
    }

    /// Inserts a new owned buffer to the IoVec, and returns a mutable reference to it.
    pub fn insert_owned(&mut self, at: usize, buf: Vec<u8>) -> &mut Vec<u8> {
        let to_add = IoVecBuf::Owned(buf);
        self.0.insert(at, to_add);
        match self.0.get_mut(at) {
            Some(IoVecBuf::Owned(v)) => v,
            _ => unreachable!(),
        }
    }

    /// Adds a new owned buffer to the end of the IoVec, and returns a mutable reference to it.
    pub fn add_owned(&mut self, buf: Vec<u8>) -> &mut Vec<u8> {
        self.insert_owned(self.0.len(), buf)
    }

    /// Adds a shared (zero-copy) `Bytes` buffer to the end of the IoVec.
    pub fn add_bytes(&mut self, buf: Bytes) {
        self.0.push(IoVecBuf::Shared(buf));
    }

    /// Consolidates all buffers into a single owned buffer,
    /// and puts it in the IoVec, replacing all previous buffers.
    pub fn consolidate(&mut self) -> &mut Vec<u8> {
        // Fast path: single owned buffer — no allocation or copy needed.
        if self.0.len() == 1 && matches!(self.0[0], IoVecBuf::Owned(_)) {
            match &mut self.0[0] {
                IoVecBuf::Owned(v) => return v,
                _ => unreachable!(),
            }
        }

        let mut consolidated = Vec::with_capacity(self.total_size());
        for buf in self.0.iter() {
            consolidated.extend_from_slice(buf);
        }
        self.0.clear();
        self.add_owned(consolidated)
    }
}

impl From<Vec<IoVecBuf>> for IoVec {
    fn from(v: Vec<IoVecBuf>) -> Self {
        Self(v)
    }
}

impl From<IoVecBuf> for IoVec {
    fn from(v: IoVecBuf) -> Self {
        Self(vec![v])
    }
}

impl From<Vec<u8>> for IoVec {
    fn from(v: Vec<u8>) -> Self {
        Self(vec![IoVecBuf::Owned(v)])
    }
}

impl From<Vec<Vec<u8>>> for IoVec {
    fn from(v: Vec<Vec<u8>>) -> Self {
        Self(v.into_iter().map(IoVecBuf::Owned).collect())
    }
}

impl Deref for IoVec {
    type Target = [IoVecBuf];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for IoVec {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// Helper that chains a fixed header with an IoVec for vectored async I/O.
///
/// Implements `bytes::Buf` so it can be passed to `tokio::io::AsyncWriteExt::write_all_buf`,
/// which handles vectored writes and partial-write retries internally.
pub struct HeaderAndIoVec<'a> {
    header: &'a [u8],
    header_pos: usize,
    iovec: &'a IoVec,
    buf_index: usize,
    buf_pos: usize,
}

impl<'a> HeaderAndIoVec<'a> {
    pub fn new(header: &'a [u8], iovec: &'a IoVec) -> Self {
        Self {
            header,
            header_pos: 0,
            iovec,
            buf_index: 0,
            buf_pos: 0,
        }
    }
}

impl bytes::Buf for HeaderAndIoVec<'_> {
    fn remaining(&self) -> usize {
        let header_remaining = self.header.len() - self.header_pos;
        let iovec_total: usize = self.iovec.iter().skip(self.buf_index).map(|b| b.len()).sum();
        let iovec_remaining = iovec_total - self.buf_pos;
        header_remaining + iovec_remaining
    }

    fn chunk(&self) -> &[u8] {
        // First serve the header
        if self.header_pos < self.header.len() {
            return &self.header[self.header_pos..];
        }
        // Then serve IoVec buffers
        if self.buf_index < self.iovec.len() {
            return &self.iovec[self.buf_index][self.buf_pos..];
        }
        &[]
    }

    fn advance(&mut self, mut cnt: usize) {
        // Advance through header first
        let header_remaining = self.header.len() - self.header_pos;
        if cnt <= header_remaining {
            self.header_pos += cnt;
            return;
        }
        cnt -= header_remaining;
        self.header_pos = self.header.len();

        // Advance through IoVec buffers
        while cnt > 0 && self.buf_index < self.iovec.len() {
            let buf_remaining = self.iovec[self.buf_index].len() - self.buf_pos;
            if cnt < buf_remaining {
                self.buf_pos += cnt;
                return;
            }
            cnt -= buf_remaining;
            self.buf_index += 1;
            self.buf_pos = 0;
        }
    }

    fn chunks_vectored<'b>(&'b self, dst: &mut [std::io::IoSlice<'b>]) -> usize {
        if dst.is_empty() {
            return 0;
        }

        let mut filled = 0;

        // Header chunk
        if self.header_pos < self.header.len() {
            dst[filled] = std::io::IoSlice::new(&self.header[self.header_pos..]);
            filled += 1;
            if filled >= dst.len() {
                return filled;
            }
        }

        // IoVec chunks
        for (i, buf) in self.iovec.iter().enumerate().skip(self.buf_index) {
            if filled >= dst.len() {
                break;
            }
            let start = if i == self.buf_index { self.buf_pos } else { 0 };
            if start < buf.len() {
                dst[filled] = std::io::IoSlice::new(&buf[start..]);
                filled += 1;
            }
        }

        filled
    }
}
