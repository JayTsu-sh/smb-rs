use bytes::Bytes;

use crate::{TransportError, error::Result};

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
}
