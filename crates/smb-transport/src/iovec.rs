use binrw::BinWrite;
use bytes::Bytes;
use std::ops::{Deref, DerefMut};

use crate::{SendFrame, SmbTcpMessageHeader, TransportError, error::Result};

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

    /// Consume the compatibility representation and freeze every segment.
    pub fn into_bytes(self) -> Vec<Bytes> {
        self.0
            .into_iter()
            .map(|segment| match segment {
                IoVecBuf::Owned(bytes) => Bytes::from(bytes),
                IoVecBuf::Shared(bytes) => bytes,
            })
            .collect()
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

/// Transport-private cursor over framing header and immutable frame segments.
/// All write progress lives here; advancing never mutates the message.
pub(crate) struct SendCursor<'a> {
    header: [u8; SmbTcpMessageHeader::SIZE],
    header_pos: usize,
    frame: &'a SendFrame,
    segment_index: usize,
    segment_pos: usize,
}

impl<'a> SendCursor<'a> {
    pub(crate) fn new(frame: &'a SendFrame) -> Result<Self> {
        let length =
            u32::try_from(frame.total_len()).map_err(|_| TransportError::FrameTooLarge {
                announced: frame.total_len(),
                maximum: u32::MAX as usize,
            })?;
        let mut header = [0_u8; SmbTcpMessageHeader::SIZE];
        SmbTcpMessageHeader {
            stream_protocol_length: length,
        }
        .write(&mut std::io::Cursor::new(header.as_mut_slice()))?;
        Ok(Self {
            header,
            header_pos: 0,
            frame,
            segment_index: 0,
            segment_pos: 0,
        })
    }

    pub(crate) fn try_advance(&mut self, mut count: usize) -> Result<()> {
        let remaining = bytes::Buf::remaining(self);
        if count > remaining {
            return Err(TransportError::CursorAdvanceOutOfBounds {
                requested: count,
                remaining,
            });
        }

        let header_remaining = self.header.len() - self.header_pos;
        let header_count = count.min(header_remaining);
        self.header_pos += header_count;
        count -= header_count;

        while count > 0 {
            let segment = &self.frame.segments()[self.segment_index];
            let segment_remaining = segment.len() - self.segment_pos;
            let consumed = count.min(segment_remaining);
            self.segment_pos += consumed;
            count -= consumed;
            if self.segment_pos == segment.len() {
                self.segment_index += 1;
                self.segment_pos = 0;
            }
        }
        Ok(())
    }
}

impl bytes::Buf for SendCursor<'_> {
    fn remaining(&self) -> usize {
        let header = self.header.len() - self.header_pos;
        let segments = self
            .frame
            .segments()
            .iter()
            .enumerate()
            .skip(self.segment_index)
            .map(|(index, segment)| {
                if index == self.segment_index {
                    segment.len() - self.segment_pos
                } else {
                    segment.len()
                }
            })
            .sum::<usize>();
        header + segments
    }

    fn chunk(&self) -> &[u8] {
        if self.header_pos < self.header.len() {
            return &self.header[self.header_pos..];
        }
        self.frame
            .segments()
            .iter()
            .enumerate()
            .skip(self.segment_index)
            .find_map(|(index, segment)| {
                let start = if index == self.segment_index {
                    self.segment_pos
                } else {
                    0
                };
                (start < segment.len()).then(|| &segment[start..])
            })
            .unwrap_or_default()
    }

    fn advance(&mut self, count: usize) {
        self.try_advance(count)
            .expect("bytes::Buf::advance contract violated");
    }

    fn chunks_vectored<'b>(&'b self, destination: &mut [std::io::IoSlice<'b>]) -> usize {
        if destination.is_empty() {
            return 0;
        }
        let mut filled = 0;
        if self.header_pos < self.header.len() {
            destination[filled] = std::io::IoSlice::new(&self.header[self.header_pos..]);
            filled += 1;
        }
        for (index, segment) in self
            .frame
            .segments()
            .iter()
            .enumerate()
            .skip(self.segment_index)
        {
            if filled == destination.len() {
                break;
            }
            let start = if index == self.segment_index {
                self.segment_pos
            } else {
                0
            };
            if start < segment.len() {
                destination[filled] = std::io::IoSlice::new(&segment[start..]);
                filled += 1;
            }
        }
        filled
    }
}

#[cfg(test)]
mod send_cursor_tests {
    use super::*;
    use bytes::Buf;

    fn frame() -> SendFrame {
        SendFrame::from_segments(
            vec![
                Bytes::from_static(b"ab"),
                Bytes::new(),
                Bytes::from_static(b"cdef"),
            ],
            3,
        )
        .unwrap()
    }

    #[test]
    fn every_partial_write_position_preserves_the_golden_frame() {
        let expected = b"\0\0\0\x06abcdef";
        for split in 0..=expected.len() {
            let frame = frame();
            let mut cursor = SendCursor::new(&frame).unwrap();
            cursor.try_advance(split).unwrap();
            let mut slices = std::array::from_fn::<_, 8, _>(|_| std::io::IoSlice::new(&[]));
            let count = cursor.chunks_vectored(&mut slices);
            let actual = slices[..count]
                .iter()
                .flat_map(|slice| slice.iter().copied())
                .collect::<Vec<_>>();
            assert_eq!(actual, expected[split..], "split={split}");
            assert_eq!(cursor.remaining(), expected.len() - split);
        }
    }

    #[test]
    fn out_of_bounds_advance_is_typed_and_does_not_move_cursor() {
        let frame = frame();
        let mut cursor = SendCursor::new(&frame).unwrap();
        let remaining = cursor.remaining();
        assert!(matches!(
            cursor.try_advance(remaining + 1),
            Err(TransportError::CursorAdvanceOutOfBounds {
                requested,
                remaining: actual
            }) if requested == remaining + 1 && actual == remaining
        ));
        assert_eq!(cursor.remaining(), remaining);
    }
}
