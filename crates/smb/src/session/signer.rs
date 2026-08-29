//! Message signing implementation.

use binrw::prelude::*;
use std::io::Cursor;

use crate::{Error, crypto};
use smb_msg::Header;
use smb_transport::IoVec;

/// A struct for writing and verifying SMB message signatures.
///
/// This struct is NOT thread-safe, use clones for concurrent access.
/// Cloning is cheap since `SigningAlgoEnum` is stack-allocated (no heap allocation).
#[derive(Debug, Clone)]
pub struct MessageSigner {
    signing_algo: crypto::SigningAlgoEnum,
}

impl MessageSigner {
    pub fn new(signing_algo: crypto::SigningAlgoEnum) -> MessageSigner {
        MessageSigner { signing_algo }
    }

    /// Verifies the signature of a message using contiguous raw bytes.
    pub fn verify_signature(&mut self, header: &mut Header, raw: &[u8]) -> crate::Result<()> {
        let calculated_signature = self._calculate_signature_bytes(header, raw)?;
        if calculated_signature != header.signature {
            return Err(Error::SignatureVerificationFailed);
        }
        Ok(())
    }

    /// Signs a message.
    ///
    /// This function assumes that the provided iovec contains the plain message header at the beginning of the first buffer.
    pub fn sign_message(&mut self, header: &mut Header, all_data: &mut IoVec) -> crate::Result<()> {
        header.signature = self._calculate_signature_iovec(header, all_data)?;

        // Update raw data to include the signature.
        let header_buffer = all_data.get_mut(0).unwrap();
        debug_assert!(
            header_buffer.len() >= Header::STRUCT_SIZE,
            "First buffer must contain the entire header."
        );
        let mut header_writer = Cursor::new(&mut header_buffer[0..Header::STRUCT_SIZE]);
        header.write(&mut header_writer)?;
        Ok(())
    }

    /// Calculate an outgoing signature directly over immutable sealed chunks.
    /// The first chunk must begin with the SMB2 header.
    pub(crate) fn signature_for_segments<'a>(
        &mut self,
        header: &mut Header,
        segments: impl IntoIterator<Item = &'a [u8]>,
    ) -> crate::Result<u128> {
        let mut segments = segments.into_iter();
        let first = segments.next().ok_or_else(|| {
            Error::InvalidMessage("Signed message has no metadata segment".to_string())
        })?;
        if first.len() < Header::STRUCT_SIZE {
            return Err(Error::InvalidMessage(
                "Signed message is shorter than the SMB2 header".to_string(),
            ));
        }

        let signature_backup = header.signature;
        header.signature = 0;
        let mut header_bytes = Cursor::new([0; Header::STRUCT_SIZE]);
        header.write(&mut header_bytes)?;
        header.signature = signature_backup;

        self.signing_algo.start(header);
        self.signing_algo.update(&header_bytes.into_inner());
        self.signing_algo.update(&first[Header::STRUCT_SIZE..]);
        for segment in segments {
            self.signing_algo.update(segment);
        }
        Ok(self.signing_algo.finalize())
    }

    /// Calculate signature from contiguous bytes (for incoming verification).
    fn _calculate_signature_bytes(
        &mut self,
        header: &mut Header,
        data: &[u8],
    ) -> crate::Result<u128> {
        if data.len() < Header::STRUCT_SIZE {
            return Err(Error::InvalidMessage(
                "Signed message is shorter than the SMB2 header".to_string(),
            ));
        }
        let mut header_bytes = [0u8; Header::STRUCT_SIZE];
        header_bytes.copy_from_slice(&data[..Header::STRUCT_SIZE]);
        header_bytes[48..64].fill(0);

        // Start signing session with the header.
        self.signing_algo.start(header);
        self.signing_algo.update(&header_bytes);

        // Skip the header portion of the raw data.
        if data.len() >= Header::STRUCT_SIZE {
            self.signing_algo.update(&data[Header::STRUCT_SIZE..]);
        }

        Ok(self.signing_algo.finalize())
    }

    /// Calculate signature from IoVec (for outgoing signing).
    fn _calculate_signature_iovec(
        &mut self,
        header: &mut Header,
        data: &IoVec,
    ) -> crate::Result<u128> {
        // Write header with signature set to 0.
        let signature_backup = header.signature;
        header.signature = 0;
        let mut header_bytes = Cursor::new([0; Header::STRUCT_SIZE]);
        header.write(&mut header_bytes)?;
        header.signature = signature_backup;

        // Start signing session with the header.
        self.signing_algo.start(header);
        self.signing_algo.update(&header_bytes.into_inner());

        if data.first().unwrap().len() >= Header::STRUCT_SIZE {
            self.signing_algo
                .update(&data.first().unwrap()[Header::STRUCT_SIZE..]);
        }

        for buf in data.iter().skip(1) {
            self.signing_algo.update(buf);
        }

        Ok(self.signing_algo.finalize())
    }
}

#[cfg(all(test, feature = "sign_gmac"))]
mod tests {
    use crate::crypto::make_signing_algo;

    use super::*;

    const TEST_SIGNING_KEY: [u8; 16] = [
        0xAC, 0x36, 0xE9, 0x54, 0x3C, 0xD8, 0x88, 0xF0, 0xA8, 0x41, 0x23, 0xE4, 0x6B, 0xB2, 0xA0,
        0xD7,
    ];

    #[test]
    #[cfg(feature = "sign_gmac")]
    fn test_calc_signature() {
        // Some random session logoff request for testing.

        use smb_msg::SigningAlgorithmId;
        use smb_transport::{IoVec, IoVecBuf};

        let header_data = vec![
            0xfeu8, 0x53, 0x4d, 0x42, 0x40, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0x0, 0x1, 0x0,
            0x18, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x9, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x53, 0x20, 0xc, 0x21, 0x0, 0x0, 0x0, 0x0, 0x76,
            0x23, 0x4b, 0x3c, 0x81, 0x2f, 0x51, 0xab, 0x8a, 0x5c, 0xf9, 0xfa, 0x43, 0xd4, 0xeb,
            0x28,
        ];
        let next_data = vec![0x4, 0x0, 0x0, 0x0];
        let mut header = Header::read_le(&mut Cursor::new(
            &header_data.as_slice()[..Header::STRUCT_SIZE],
        ))
        .unwrap();

        let mut signer = MessageSigner::new(
            make_signing_algo(SigningAlgorithmId::AesGmac, &TEST_SIGNING_KEY).unwrap(),
        );

        let iovec = IoVec::from(vec![
            IoVecBuf::from(header_data.clone()),
            IoVecBuf::from(next_data.clone()),
        ]);
        let signature = signer
            ._calculate_signature_iovec(&mut header, &iovec)
            .expect("signature calculation failed");

        // Also verify the bytes-based path produces the same result.
        let mut signer2 = MessageSigner::new(
            make_signing_algo(SigningAlgorithmId::AesGmac, &TEST_SIGNING_KEY)
                .expect("algo creation failed"),
        );
        let mut combined = header_data.clone();
        combined.extend_from_slice(&next_data);
        let signature2 = signer2
            ._calculate_signature_bytes(&mut header, &combined)
            .expect("bytes signature failed");
        let mut signer3 = MessageSigner::new(
            make_signing_algo(SigningAlgorithmId::AesGmac, &TEST_SIGNING_KEY)
                .expect("algo creation failed"),
        );
        let signature3 = signer3
            .signature_for_segments(&mut header, [header_data.as_slice(), next_data.as_slice()])
            .expect("segmented signature failed");
        assert_eq!(signature, 0x28ebd443faf95c8aab512f813c4b2376);
        assert_eq!(signature2, signature);
        assert_eq!(signature3, signature);
    }
}
