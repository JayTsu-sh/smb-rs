use bytes::Bytes;
use std::ops::Range;

use crate::{Result, SmbMsgError};

/// Atomic decode result: typed fixed metadata and its immutable frame owner.
/// Validated variable fields can only slice this retained owner.
#[derive(Clone, Debug)]
pub struct DecodedFrame<T> {
    owner: Bytes,
    value: T,
}

impl<T> DecodedFrame<T> {
    pub(crate) fn new(owner: Bytes, value: T) -> Self {
        Self { owner, value }
    }

    pub fn value(&self) -> &T {
        &self.value
    }

    pub fn slice(&self, range: WireRange) -> Bytes {
        self.owner.slice(range.as_range())
    }

    pub fn into_parts(self) -> (T, Bytes) {
        (self.value, self.owner)
    }
}

/// A byte range proven to be contained in one decoded SMB member.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WireRange {
    start: usize,
    end: usize,
}

impl WireRange {
    pub(crate) fn validate(
        field: &'static str,
        offset: usize,
        length: usize,
        member_len: usize,
        minimum_offset: usize,
        alignment: usize,
    ) -> Result<Self> {
        if offset < minimum_offset || alignment == 0 || offset % alignment != 0 {
            return Err(SmbMsgError::InvalidWireRange {
                field,
                offset,
                length,
            });
        }
        let end = offset
            .checked_add(length)
            .ok_or(SmbMsgError::InvalidWireRange {
                field,
                offset,
                length,
            })?;
        if end > member_len {
            return Err(SmbMsgError::InvalidWireRange {
                field,
                offset,
                length,
            });
        }
        Ok(Self { start: offset, end })
    }

    pub fn as_range(self) -> Range<usize> {
        self.start..self.end
    }

    pub fn len(self) -> usize {
        self.end - self.start
    }

    pub fn is_empty(self) -> bool {
        self.start == self.end
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_exact_end_and_empty_ranges() {
        assert_eq!(
            WireRange::validate("data", 8, 8, 16, 8, 1)
                .unwrap()
                .as_range(),
            8..16
        );
        assert!(
            WireRange::validate("data", 16, 0, 16, 8, 1)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn rejects_underflow_overflow_alignment_and_member_escape() {
        assert!(WireRange::validate("data", 7, 1, 16, 8, 1).is_err());
        assert!(WireRange::validate("data", usize::MAX, 2, usize::MAX, 0, 1).is_err());
        assert!(WireRange::validate("data", 9, 1, 16, 8, 2).is_err());
        assert!(WireRange::validate("data", 12, 5, 16, 8, 1).is_err());
    }

    #[test]
    fn decoded_frame_slices_share_the_owner() {
        let owner = Bytes::from_static(b"metadata-payload");
        let decoded = DecodedFrame::new(owner.clone(), 7_u8);
        let range = WireRange::validate("data", 9, 7, owner.len(), 0, 1).unwrap();
        let payload = decoded.slice(range);
        assert_eq!(payload, Bytes::from_static(b"payload"));
        assert_eq!(payload.as_ptr(), owner.slice(9..).as_ptr());
    }

    #[test]
    fn small_range_space_matches_checked_arithmetic_oracle() {
        for member_len in 0_usize..32 {
            for offset in 0_usize..40 {
                for length in 0_usize..40 {
                    let expected = offset >= 4
                        && offset % 2 == 0
                        && offset
                            .checked_add(length)
                            .is_some_and(|end| end <= member_len);
                    assert_eq!(
                        WireRange::validate("field", offset, length, member_len, 4, 2).is_ok(),
                        expected,
                        "member={member_len} offset={offset} length={length}",
                    );
                }
            }
        }
    }
}
