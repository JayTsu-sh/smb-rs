use std::io::{Seek, SeekFrom, Write};
use std::ops::Range;

use binrw::BinWrite;
use bytes::{Bytes, BytesMut};

use crate::{Header, PlainRequest, Result, SmbMsgError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BuildState {
    Encoded,
    OffsetsFinalized,
    Protected,
}

/// Mutable codec-owned construction state for one SMB wire message.
pub struct WireBuilder {
    metadata: BytesMut,
    payloads: Vec<Bytes>,
    member_ranges: Vec<Range<usize>>,
    segment_limit: usize,
    state: BuildState,
    patched_members: usize,
}

impl WireBuilder {
    /// Encode one or more SMB requests into a single metadata arena. Compound
    /// member offsets are relative to each member's SMB header and every
    /// non-final member is padded to an eight-byte boundary.
    pub fn encode<'a>(
        requests: impl IntoIterator<Item = &'a mut PlainRequest>,
        segment_limit: usize,
    ) -> Result<Self> {
        let requests = requests.into_iter();
        let (request_count, upper) = requests.size_hint();
        if upper != Some(request_count) {
            return Err(invalid("wire request iterator must have an exact length"));
        }
        if request_count == 0 {
            return Err(invalid("wire builder requires at least one request"));
        }
        if segment_limit == 0 {
            return Err(invalid("wire segment limit must include metadata"));
        }

        let mut metadata = BytesMut::with_capacity(request_count * (Header::STRUCT_SIZE + 64));
        let mut member_ranges = if request_count > 1 {
            Vec::with_capacity(request_count)
        } else {
            Vec::new()
        };

        for (index, request) in requests.enumerate() {
            let start = metadata.len();
            request.header.next_command = 0;
            request.write(&mut MetadataCursor::at_end(&mut metadata))?;

            let is_last = index + 1 == request_count;
            if !is_last {
                let aligned_end = metadata
                    .len()
                    .checked_add(7)
                    .map(|value| value & !7)
                    .ok_or_else(|| invalid("compound metadata length overflow"))?;
                metadata.resize(aligned_end, 0);
                request.header.next_command = u32::try_from(aligned_end - start)
                    .map_err(|_| invalid("compound member length exceeds u32"))?;
                patch_header(&mut metadata, start, &request.header)?;
            }
            if request_count > 1 {
                member_ranges.push(start..metadata.len());
            }
        }

        Ok(Self {
            metadata,
            payloads: Vec::new(),
            member_ranges,
            segment_limit,
            state: BuildState::Encoded,
            patched_members: 0,
        })
    }

    /// Attach a caller-owned immutable payload without copying it.
    pub fn attach_payload(&mut self, payload: Bytes) -> Result<()> {
        self.require_state(BuildState::Encoded)?;
        if payload.is_empty() {
            return Ok(());
        }
        if 1 + self.payloads.len() >= self.segment_limit {
            return Err(invalid("wire segment limit exceeded"));
        }
        self.payloads.push(payload);
        Ok(())
    }

    /// Seal offset/layout mutation. W2-3 is the only later stage allowed to
    /// add the restricted signature patch before immutable transport handoff.
    pub fn finalize_offsets(&mut self) -> Result<()> {
        self.require_state(BuildState::Encoded)?;
        self.state = BuildState::OffsetsFinalized;
        Ok(())
    }

    /// Ordered chunks covered by one SMB signature. A single request includes
    /// its metadata followed by payload segments; compound members are limited
    /// to their validated padded metadata range.
    pub fn signing_segments(&self, member: usize) -> Result<impl Iterator<Item = &[u8]>> {
        self.require_state(BuildState::OffsetsFinalized)?;
        let range = self.builder_member_range(member)?;
        let metadata = self
            .metadata
            .get(range)
            .ok_or_else(|| invalid("signature member range escaped metadata"))?;
        let payloads = if self.member_count() == 1 {
            self.payloads.as_slice()
        } else {
            &[]
        };
        Ok(std::iter::once(metadata).chain(payloads.iter().map(Bytes::as_ref)))
    }

    /// Patch exactly the 16-byte SMB2 header signature field. Members must be
    /// patched in wire order, preventing duplicate or skipped signatures.
    pub fn patch_signature(&mut self, member: usize, signature: u128) -> Result<()> {
        self.require_state(BuildState::OffsetsFinalized)?;
        if member != self.patched_members {
            return Err(invalid("signature patches must follow member order"));
        }
        let range = self.builder_member_range(member)?;
        let start = range
            .start
            .checked_add(48)
            .ok_or_else(|| invalid("signature range overflow"))?;
        let end = start + 16;
        let target = self
            .metadata
            .get_mut(start..end)
            .ok_or_else(|| invalid("signature range escaped metadata"))?;
        target.copy_from_slice(&signature.to_le_bytes());
        self.patched_members += 1;
        Ok(())
    }

    pub fn finish_signed(&mut self) -> Result<()> {
        self.require_state(BuildState::OffsetsFinalized)?;
        if self.patched_members != self.member_count() {
            return Err(invalid("not every wire member has a signature"));
        }
        self.state = BuildState::Protected;
        Ok(())
    }

    pub fn finish_unsigned(&mut self) -> Result<()> {
        self.require_state(BuildState::OffsetsFinalized)?;
        if self.patched_members != 0 {
            return Err(invalid("partially signed message cannot become unsigned"));
        }
        self.state = BuildState::Protected;
        Ok(())
    }

    pub fn seal(self) -> Result<WireMessage> {
        self.require_state(BuildState::Protected)?;
        let total_len = self
            .payloads
            .iter()
            .try_fold(self.metadata.len(), |total, payload| {
                total.checked_add(payload.len())
            })
            .ok_or_else(|| invalid("wire message length overflow"))?;
        Ok(WireMessage {
            metadata: self.metadata.freeze(),
            payloads: self.payloads,
            member_ranges: self.member_ranges,
            total_len,
        })
    }

    fn require_state(&self, expected: BuildState) -> Result<()> {
        if self.state == expected {
            Ok(())
        } else {
            Err(invalid("invalid wire builder state transition"))
        }
    }

    fn member_count(&self) -> usize {
        self.member_ranges.len().max(1)
    }

    fn builder_member_range(&self, index: usize) -> Result<Range<usize>> {
        if self.member_ranges.is_empty() {
            if index == 0 {
                Ok(0..self.metadata.len())
            } else {
                Err(invalid("wire member index out of bounds"))
            }
        } else {
            self.member_ranges
                .get(index)
                .cloned()
                .ok_or_else(|| invalid("wire member index out of bounds"))
        }
    }
}

/// Immutable ordered metadata and payload segments ready for protection or
/// transport. It deliberately has no consolidation or mutable access method.
#[derive(Clone, Debug)]
pub struct WireMessage {
    metadata: Bytes,
    payloads: Vec<Bytes>,
    member_ranges: Vec<Range<usize>>,
    total_len: usize,
}

/// Immutable contiguous owner produced by compression and/or encryption.
/// Construction consumes the transform arena; callers cannot regain mutable
/// access after protection completes.
#[derive(Clone, Debug)]
pub struct TransformFrame(Bytes);

impl TransformFrame {
    pub fn from_vec(bytes: Vec<u8>) -> Result<Self> {
        if bytes.is_empty() {
            return Err(invalid("transform frame cannot be empty"));
        }
        Ok(Self(Bytes::from(bytes)))
    }

    pub fn as_bytes(&self) -> &Bytes {
        &self.0
    }

    pub fn into_bytes(self) -> Bytes {
        self.0
    }
}

impl WireMessage {
    pub fn total_len(&self) -> usize {
        self.total_len
    }

    pub fn segment_count(&self) -> usize {
        1 + self.payloads.len()
    }

    pub fn segments(&self) -> impl Iterator<Item = &[u8]> {
        std::iter::once(self.metadata.as_ref()).chain(self.payloads.iter().map(Bytes::as_ref))
    }

    /// Consume all segment owners into a single transform input arena. This is
    /// the only payload-copying transition and is unreachable for plain send.
    pub fn into_contiguous(self, prefix: usize) -> Result<Vec<u8>> {
        let capacity = prefix
            .checked_add(self.total_len)
            .ok_or_else(|| invalid("transform arena length overflow"))?;
        let mut contiguous = Vec::with_capacity(capacity);
        contiguous.resize(prefix, 0);
        contiguous.extend_from_slice(&self.metadata);
        for payload in self.payloads {
            contiguous.extend_from_slice(&payload);
        }
        Ok(contiguous)
    }

    pub fn into_segments(self) -> Vec<Bytes> {
        std::iter::once(self.metadata)
            .chain(self.payloads)
            .collect()
    }

    pub fn member_count(&self) -> usize {
        self.member_ranges.len().max(1)
    }

    pub fn member_range(&self, index: usize) -> Option<Range<usize>> {
        if self.member_ranges.is_empty() {
            (index == 0).then(|| 0..self.metadata.len())
        } else {
            self.member_ranges.get(index).cloned()
        }
    }
}

fn patch_header(metadata: &mut BytesMut, start: usize, header: &Header) -> Result<()> {
    let end = start
        .checked_add(Header::STRUCT_SIZE)
        .ok_or_else(|| invalid("header range overflow"))?;
    let target = metadata
        .get_mut(start..end)
        .ok_or_else(|| invalid("encoded member is shorter than SMB header"))?;
    header.write(&mut std::io::Cursor::new(target))?;
    Ok(())
}

fn invalid(message: &str) -> SmbMsgError {
    SmbMsgError::InvalidData(message.to_owned())
}

/// Seekable logical cursor over one member inside the shared metadata arena.
/// Logical positions start at the member's header, while storage remains in
/// the single arena.
struct MetadataCursor<'a> {
    arena: &'a mut BytesMut,
    base: usize,
    position: usize,
}

impl<'a> MetadataCursor<'a> {
    fn at_end(arena: &'a mut BytesMut) -> Self {
        let base = arena.len();
        Self {
            arena,
            base,
            position: 0,
        }
    }

    fn absolute_position(&self) -> Result<usize> {
        self.base
            .checked_add(self.position)
            .ok_or_else(|| invalid("metadata cursor position overflow"))
    }
}

impl Write for MetadataCursor<'_> {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        let start = self.absolute_position().map_err(std::io::Error::other)?;
        let end = start
            .checked_add(buffer.len())
            .ok_or_else(|| std::io::Error::other("metadata write overflow"))?;
        if end > self.arena.len() {
            self.arena.resize(end, 0);
        }
        self.arena[start..end].copy_from_slice(buffer);
        self.position += buffer.len();
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Seek for MetadataCursor<'_> {
    fn seek(&mut self, from: SeekFrom) -> std::io::Result<u64> {
        let member_len = self.arena.len().saturating_sub(self.base);
        let next = match from {
            SeekFrom::Start(offset) => i128::from(offset),
            SeekFrom::Current(offset) => self.position as i128 + i128::from(offset),
            SeekFrom::End(offset) => member_len as i128 + i128::from(offset),
        };
        if next < 0 || next > usize::MAX as i128 {
            return Err(std::io::Error::other("metadata seek out of range"));
        }
        self.position = next as usize;
        Ok(self.position as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Command, FileId, RequestContent, WriteFlags, WriteRequest};
    use binrw::BinWrite;

    fn write_request(length: u32) -> PlainRequest {
        PlainRequest::new(RequestContent::Write(WriteRequest::new(
            0,
            FileId::EMPTY,
            WriteFlags::new(),
            length,
        )))
    }

    #[test]
    fn payload_pointer_survives_builder_and_seal() {
        let payload = Bytes::from_static(b"payload");
        let pointer = payload.as_ptr();
        let mut requests = [write_request(payload.len() as u32)];
        let mut builder = WireBuilder::encode(&mut requests, 2).unwrap();
        builder.attach_payload(payload).unwrap();
        builder.finalize_offsets().unwrap();
        builder.finish_unsigned().unwrap();
        let message = builder.seal().unwrap();
        assert_eq!(message.segment_count(), 2);
        assert_eq!(message.segments().nth(1).unwrap().as_ptr(), pointer);
    }

    #[test]
    fn logical_segments_match_golden_codec_bytes() {
        let payload = Bytes::from_static(b"golden-payload");
        let golden_request = write_request(payload.len() as u32);
        let mut golden = Vec::new();
        golden_request
            .write(&mut std::io::Cursor::new(&mut golden))
            .unwrap();
        golden.extend_from_slice(&payload);

        let mut request = write_request(payload.len() as u32);
        let mut builder = WireBuilder::encode(std::iter::once(&mut request), 2).unwrap();
        builder.attach_payload(payload).unwrap();
        builder.finalize_offsets().unwrap();
        builder.finish_unsigned().unwrap();
        let actual = builder
            .seal()
            .unwrap()
            .segments()
            .flat_map(|segment| segment.iter().copied())
            .collect::<Vec<_>>();

        assert_eq!(actual, golden);
    }

    #[test]
    fn compound_members_share_one_aligned_metadata_segment() {
        let mut requests = [write_request(1), write_request(2)];
        requests[0].header.command = Command::Write;
        let mut builder = WireBuilder::encode(&mut requests, 1).unwrap();
        builder.finalize_offsets().unwrap();
        builder.finish_unsigned().unwrap();
        let message = builder.seal().unwrap();
        assert_eq!(message.segment_count(), 1);
        assert_eq!(message.member_count(), 2);
        assert_eq!(message.member_range(0).unwrap().end % 8, 0);
        assert_eq!(
            requests[0].header.next_command as usize,
            message.member_range(0).unwrap().len()
        );
    }

    #[test]
    fn rejects_invalid_transitions_and_segment_overflow() {
        let mut requests = [write_request(1)];
        let builder = WireBuilder::encode(&mut requests, 2).unwrap();
        assert!(builder.seal().is_err());

        let mut builder = WireBuilder::encode(&mut requests, 1).unwrap();
        assert!(builder.attach_payload(Bytes::from_static(b"x")).is_err());
        builder.finalize_offsets().unwrap();
        assert!(builder.attach_payload(Bytes::from_static(b"x")).is_err());
    }

    #[test]
    fn signing_state_rejects_skipped_duplicate_and_partial_protection() {
        let mut requests = [write_request(1), write_request(2)];
        let mut builder = WireBuilder::encode(&mut requests, 1).unwrap();
        builder.finalize_offsets().unwrap();

        assert!(builder.finish_signed().is_err());
        assert!(builder.patch_signature(1, 1).is_err());
        builder.patch_signature(0, 1).unwrap();
        assert!(builder.patch_signature(0, 1).is_err());
        assert!(builder.finish_unsigned().is_err());
        assert!(builder.finish_signed().is_err());
        builder.patch_signature(1, 2).unwrap();
        builder.finish_signed().unwrap();
        assert!(builder.signing_segments(0).is_err());
        assert!(builder.seal().is_ok());
    }

    #[test]
    fn signature_patch_changes_only_header_field_and_preserves_payload_owner() {
        let payload = Bytes::from_static(b"signed-payload");
        let payload_pointer = payload.as_ptr();
        let mut requests = [write_request(payload.len() as u32)];
        let mut builder = WireBuilder::encode(&mut requests, 2).unwrap();
        builder.attach_payload(payload).unwrap();
        builder.finalize_offsets().unwrap();
        let before = builder
            .signing_segments(0)
            .unwrap()
            .next()
            .unwrap()
            .to_vec();

        let signature = 0x0011_2233_4455_6677_8899_aabb_ccdd_eeff;
        builder.patch_signature(0, signature).unwrap();
        let after = builder
            .signing_segments(0)
            .unwrap()
            .next()
            .unwrap()
            .to_vec();
        assert_eq!(&before[..48], &after[..48]);
        assert_eq!(&before[64..], &after[64..]);
        assert_eq!(&after[48..64], &signature.to_le_bytes());

        builder.finish_signed().unwrap();
        let message = builder.seal().unwrap();
        assert_eq!(message.segments().nth(1).unwrap().as_ptr(), payload_pointer);
    }

    #[test]
    fn empty_payload_does_not_consume_a_segment() {
        let mut requests = [write_request(0)];
        let mut builder = WireBuilder::encode(&mut requests, 1).unwrap();
        builder.attach_payload(Bytes::new()).unwrap();
        builder.finalize_offsets().unwrap();
        builder.finish_unsigned().unwrap();
        assert_eq!(builder.seal().unwrap().segment_count(), 1);
    }

    #[test]
    fn multiple_payloads_keep_order_and_identity() {
        let first = Bytes::from_static(b"first");
        let second = Bytes::from_static(b"second");
        let first_pointer = first.as_ptr();
        let second_pointer = second.as_ptr();
        let mut requests = [write_request(11)];
        let mut builder = WireBuilder::encode(&mut requests, 3).unwrap();
        builder.attach_payload(first).unwrap();
        builder.attach_payload(second).unwrap();
        builder.finalize_offsets().unwrap();
        builder.finish_unsigned().unwrap();
        let message = builder.seal().unwrap();
        let segments = message.segments().collect::<Vec<_>>();
        assert_eq!(segments[1].as_ptr(), first_pointer);
        assert_eq!(segments[2].as_ptr(), second_pointer);
        assert_eq!(segments[1], b"first");
        assert_eq!(segments[2], b"second");
    }

    #[test]
    fn transform_transition_consumes_segments_into_one_prefixed_owner() {
        let payload = Bytes::from_static(b"payload");
        let mut requests = [write_request(payload.len() as u32)];
        let mut builder = WireBuilder::encode(&mut requests, 2).unwrap();
        builder.attach_payload(payload).unwrap();
        builder.finalize_offsets().unwrap();
        builder.finish_unsigned().unwrap();

        let message = builder.seal().unwrap();
        let golden = message
            .segments()
            .flat_map(|segment| segment.iter().copied())
            .collect::<Vec<_>>();
        let contiguous = message.into_contiguous(7).unwrap();
        assert_eq!(&contiguous[..7], &[0; 7]);
        assert_eq!(&contiguous[7..], golden);
    }

    #[test]
    fn transform_frame_freezes_the_final_arena_without_copy() {
        let arena = vec![1, 2, 3, 4];
        let pointer = arena.as_ptr();
        let frame = TransformFrame::from_vec(arena).unwrap();
        assert_eq!(frame.as_bytes().as_ptr(), pointer);
        assert_eq!(frame.as_bytes().as_ref(), &[1, 2, 3, 4]);
        assert!(TransformFrame::from_vec(Vec::new()).is_err());
    }
}
