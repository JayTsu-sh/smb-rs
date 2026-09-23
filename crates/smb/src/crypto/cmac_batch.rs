use aes::{
    Aes128,
    cipher::{Block, BlockCipherEncrypt, KeyInit},
};
use bytes::Bytes;

use super::CryptoError;

/// Number of independent AES blocks processed together by RustCrypto's
/// 64-bit portable fixslice backend.
pub(crate) const PORTABLE_CMAC_LANES: usize = 4;

#[derive(Clone, Copy)]
pub(crate) struct CmacBatchInput<'a> {
    pub(crate) segments: &'a [Bytes],
}

/// One AES-128-CMAC key schedule shared by a batch of independent messages.
///
/// CMAC is serial within one message, but the portable RustCrypto AES backend
/// can advance four independent chaining states with one fixslice operation.
#[derive(Clone)]
pub(crate) struct BatchCmac128 {
    cipher: Aes128,
    complete_subkey: Block<Aes128>,
    partial_subkey: Block<Aes128>,
}

impl BatchCmac128 {
    pub(crate) fn new(key: &[u8; 16]) -> Self {
        let cipher = Aes128::new(key.into());
        let mut encrypted_zero = Block::<Aes128>::default();
        cipher.encrypt_block(&mut encrypted_zero);
        let complete_subkey = double(encrypted_zero);
        let partial_subkey = double(complete_subkey);
        Self {
            cipher,
            complete_subkey,
            partial_subkey,
        }
    }

    pub(crate) fn sign_batch(
        &self,
        inputs: &[CmacBatchInput<'_>],
    ) -> Result<Vec<u128>, CryptoError> {
        let mut cursors = inputs
            .iter()
            .map(|input| MessageCursor::new(input.segments).map(Some))
            .collect::<Result<Vec<_>, _>>()?;
        let mut signatures = vec![0_u128; cursors.len()];
        let mut lanes: [Option<Lane<'_>>; PORTABLE_CMAC_LANES] = std::array::from_fn(|_| None);
        let mut next = 0;
        fill_idle_lanes(&mut lanes, &mut cursors, &mut next);

        while lanes.iter().any(Option::is_some) {
            let mut states: [Block<Aes128>; PORTABLE_CMAC_LANES] = Default::default();
            for (state, lane) in states.iter_mut().zip(&mut lanes) {
                let Some(lane) = lane else { continue };
                *state = lane.state;
                let mut message_block = Block::<Aes128>::default();
                let filled = lane.cursor.read_block(&mut message_block);
                if lane.cursor.blocks_remaining == 1 {
                    let subkey = if lane.cursor.is_complete_final_block() {
                        &self.complete_subkey
                    } else {
                        message_block[filled] = 0x80;
                        &self.partial_subkey
                    };
                    xor_block(&mut message_block, subkey);
                }
                xor_block(state, &message_block);
            }

            // Passing exactly four blocks is intentional. On the 64-bit
            // portable backend this selects one full fixslice state instead
            // of four single-block calls with three unused lanes each.
            self.cipher.encrypt_blocks(&mut states);

            for (state, lane) in states.into_iter().zip(&mut lanes) {
                let Some(active) = lane else { continue };
                active.state = state;
                active.cursor.blocks_remaining -= 1;
                if active.cursor.blocks_remaining == 0 {
                    signatures[active.input_index] = u128::from_le_bytes(state.into());
                    *lane = None;
                }
            }
            fill_idle_lanes(&mut lanes, &mut cursors, &mut next);
        }

        Ok(signatures)
    }
}

struct Lane<'a> {
    input_index: usize,
    cursor: MessageCursor<'a>,
    state: Block<Aes128>,
}

struct MessageCursor<'a> {
    segments: &'a [Bytes],
    segment_index: usize,
    segment_offset: usize,
    total_len: usize,
    blocks_remaining: usize,
}

impl<'a> MessageCursor<'a> {
    fn new(segments: &'a [Bytes]) -> Result<Self, CryptoError> {
        let total_len = segments.iter().try_fold(0_usize, |total, segment| {
            total
                .checked_add(segment.len())
                .ok_or(CryptoError::CmacInputTooLong)
        })?;
        Ok(Self {
            segments,
            segment_index: 0,
            segment_offset: 0,
            total_len,
            blocks_remaining: total_len.div_ceil(16).max(1),
        })
    }

    fn read_block(&mut self, block: &mut Block<Aes128>) -> usize {
        let mut filled = 0;
        while filled < block.len() && self.segment_index < self.segments.len() {
            let segment = &self.segments[self.segment_index];
            if self.segment_offset == segment.len() {
                self.segment_index += 1;
                self.segment_offset = 0;
                continue;
            }
            let available = &segment[self.segment_offset..];
            let take = available.len().min(block.len() - filled);
            block[filled..filled + take].copy_from_slice(&available[..take]);
            filled += take;
            self.segment_offset += take;
        }
        filled
    }

    fn is_complete_final_block(&self) -> bool {
        self.total_len != 0 && self.total_len.is_multiple_of(16)
    }
}

fn fill_idle_lanes<'a>(
    lanes: &mut [Option<Lane<'a>>; PORTABLE_CMAC_LANES],
    cursors: &mut [Option<MessageCursor<'a>>],
    next: &mut usize,
) {
    for lane in lanes.iter_mut().filter(|lane| lane.is_none()) {
        let Some(cursor) = cursors.get_mut(*next).and_then(Option::take) else {
            break;
        };
        *lane = Some(Lane {
            input_index: *next,
            cursor,
            state: Block::<Aes128>::default(),
        });
        *next += 1;
    }
}

fn xor_block(target: &mut Block<Aes128>, input: &Block<Aes128>) {
    for (target, input) in target.iter_mut().zip(input) {
        *target ^= input;
    }
}

fn double(input: Block<Aes128>) -> Block<Aes128> {
    let mut output = Block::<Aes128>::default();
    let mut carry = 0_u8;
    for (output, input) in output.iter_mut().rev().zip(input.iter().rev()) {
        *output = (*input << 1) | carry;
        carry = *input >> 7;
    }
    if carry != 0 {
        output[15] ^= 0x87;
    }
    output
}

#[cfg(test)]
mod tests {
    use cmac::{Cmac, Mac};

    use super::*;

    #[test]
    fn batch_matches_rustcrypto_for_lengths_segments_and_lane_refills() {
        let key = [0x5a; 16];
        let messages = (0..11)
            .map(|index| {
                let len = [0, 1, 15, 16, 17, 31, 32, 63, 64, 4095, 4160][index];
                (0..len)
                    .map(|offset| (index as u8).wrapping_mul(17).wrapping_add(offset as u8))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let segment_storage = messages
            .iter()
            .enumerate()
            .map(|(index, message)| {
                let first = (index * 7).min(message.len());
                let second = (first + 13).min(message.len());
                vec![
                    Bytes::copy_from_slice(&message[..first]),
                    Bytes::copy_from_slice(&message[first..second]),
                    Bytes::copy_from_slice(&message[second..]),
                ]
            })
            .collect::<Vec<_>>();
        let inputs = segment_storage
            .iter()
            .map(|segments| CmacBatchInput { segments })
            .collect::<Vec<_>>();

        let actual = BatchCmac128::new(&key).sign_batch(&inputs).unwrap();
        let expected = messages
            .iter()
            .map(|message| {
                let mut cmac = Cmac::<Aes128>::new_from_slice(&key).unwrap();
                cmac.update(message);
                u128::from_le_bytes(cmac.finalize().into_bytes().into())
            })
            .collect::<Vec<_>>();

        assert_eq!(actual, expected);
    }

    #[test]
    fn batch_matches_rfc_4493_vectors() {
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let message = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a,
        ];
        let empty_segments = [];
        let message_segments = [
            Bytes::copy_from_slice(&message[..7]),
            Bytes::copy_from_slice(&message[7..]),
        ];
        let inputs = [
            CmacBatchInput {
                segments: &empty_segments,
            },
            CmacBatchInput {
                segments: &message_segments,
            },
        ];

        let signatures = BatchCmac128::new(&key).sign_batch(&inputs).unwrap();

        assert_eq!(
            signatures[0].to_le_bytes(),
            [
                0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59, 0x37, 0x28, 0x7f, 0xa3, 0x7d, 0x12, 0x9b, 0x75,
                0x67, 0x46,
            ]
        );
        assert_eq!(
            signatures[1].to_le_bytes(),
            [
                0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44, 0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a,
                0x28, 0x7c,
            ]
        );
    }

    #[test]
    #[ignore = "manual release-mode four-lane CMAC throughput probe"]
    fn four_lane_4160_byte_throughput_probe() {
        use std::{hint::black_box, time::Instant};

        const ITERATIONS: usize = 25_000;
        let key = [0x5a; 16];
        let payloads = [[0xa5; 4160]; PORTABLE_CMAC_LANES];
        let segment_storage = payloads
            .iter()
            .map(|payload| [Bytes::copy_from_slice(payload)])
            .collect::<Vec<_>>();
        let inputs = segment_storage
            .iter()
            .map(|segments| CmacBatchInput { segments })
            .collect::<Vec<_>>();
        let batch = BatchCmac128::new(&key);

        let started = Instant::now();
        for _ in 0..ITERATIONS {
            black_box(batch.sign_batch(black_box(&inputs)).unwrap());
        }
        let elapsed = started.elapsed();
        let messages = ITERATIONS * PORTABLE_CMAC_LANES;
        let nanos_per_message = elapsed.as_nanos() / messages as u128;
        let mebibytes_per_second =
            4160_f64 * messages as f64 / elapsed.as_secs_f64() / (1024.0 * 1024.0);
        eprintln!(
            "CMAC_4LANE_4160 messages={messages} ns_per_message={nanos_per_message} mib_per_s={mebibytes_per_second:.2}"
        );
    }
}
