use bytes::Bytes;

use crate::{IoVec, TransportError, error::Result};

/// Default hard ceiling for one direct-TCP SMB payload (the framing field is
/// 24 bits wide). The length is checked before allocating the receive arena.
pub const DEFAULT_MAX_FRAME_SIZE: usize = 0x00ff_ffff;

/// The sole immutable owner of one complete transport payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportFrame(Bytes);

impl TransportFrame {
    pub fn from_bytes(bytes: Bytes, max_len: usize) -> Result<Self> {
        if bytes.len() > max_len {
            return Err(TransportError::FrameTooLarge {
                announced: bytes.len(),
                maximum: max_len,
            });
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &Bytes {
        &self.0
    }

    pub fn into_bytes(self) -> Bytes {
        self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Immutable outbound segments accepted by transport. Conversion from the
/// W2 compatibility `IoVec` consumes every owner; shared payload pointers are
/// preserved and owned metadata is frozen without another copy.
#[derive(Clone, Debug)]
pub struct SendFrame {
    segments: Vec<Bytes>,
    total_len: usize,
}

impl SendFrame {
    pub fn from_iovec(iovec: IoVec) -> Result<Self> {
        Self::from_segments(iovec.into_bytes(), usize::MAX)
    }

    pub fn from_segments(segments: Vec<Bytes>, maximum_segments: usize) -> Result<Self> {
        if segments.is_empty() {
            return Err(TransportError::InvalidMessage);
        }
        if segments.len() > maximum_segments {
            return Err(TransportError::SegmentLimitExceeded {
                actual: segments.len(),
                maximum: maximum_segments,
            });
        }
        let total_len = segments
            .iter()
            .try_fold(0_usize, |total, segment| total.checked_add(segment.len()));
        let total_len = total_len.ok_or(TransportError::InvalidMessage)?;
        if total_len == 0 {
            return Err(TransportError::InvalidMessage);
        }
        if total_len > u32::MAX as usize {
            return Err(TransportError::FrameTooLarge {
                announced: total_len,
                maximum: u32::MAX as usize,
            });
        }
        Ok(Self {
            segments,
            total_len,
        })
    }

    pub fn total_len(&self) -> usize {
        self.total_len
    }

    pub fn segments(&self) -> &[Bytes] {
        &self.segments
    }
}

impl AsRef<[u8]> for TransportFrame {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn freezes_bytes_without_copy_and_enforces_limit() {
        let bytes = Bytes::from_static(b"frame");
        let frame = TransportFrame::from_bytes(bytes.clone(), bytes.len()).unwrap();
        assert_eq!(frame.as_bytes().as_ptr(), bytes.as_ptr());
        assert_eq!(frame.as_ref(), b"frame");

        assert!(matches!(
            TransportFrame::from_bytes(bytes, 4),
            Err(TransportError::FrameTooLarge {
                announced: 5,
                maximum: 4
            })
        ));
    }

    #[test]
    fn outbound_frame_rejects_empty_and_segment_overflow() {
        assert!(matches!(
            SendFrame::from_segments(vec![Bytes::new()], 1),
            Err(TransportError::InvalidMessage)
        ));
        assert!(matches!(
            SendFrame::from_segments(vec![Bytes::from_static(b"a"), Bytes::from_static(b"b")], 1),
            Err(TransportError::SegmentLimitExceeded {
                actual: 2,
                maximum: 1
            })
        ));
    }
}
