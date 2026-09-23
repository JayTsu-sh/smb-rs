use smb_msg::*;

use super::CryptoError;

type SigningKey = [u8; 16];

pub fn make_signing_algo(
    signing_algorithm: SigningAlgorithmId,
    signing_key: &SigningKey,
) -> Result<SigningAlgoEnum, CryptoError> {
    #[cfg(not(any(
        feature = "sign_hmac",
        feature = "sign_cmac_rustcrypto",
        feature = "sign_gmac"
    )))]
    let _ = signing_key;

    if !SIGNING_ALGOS.contains(&signing_algorithm) {
        return Err(CryptoError::UnsupportedSigningAlgorithm(signing_algorithm));
    }
    match signing_algorithm {
        #[cfg(feature = "sign_hmac")]
        SigningAlgorithmId::HmacSha256 => Ok(hmac_signer::HmacSha256Signer::build(signing_key)),
        #[cfg(feature = "sign_cmac_rustcrypto")]
        SigningAlgorithmId::AesCmac => Ok(cmac_signer::Cmac128Signer::build(signing_key)?),
        #[cfg(feature = "sign_gmac")]
        SigningAlgorithmId::AesGmac => Ok(gmac_signer::Gmac128Signer::build(signing_key)),
        #[cfg(not(all(
            feature = "sign_cmac_rustcrypto",
            feature = "sign_gmac",
            feature = "sign_hmac"
        )))]
        _ => Err(CryptoError::UnsupportedSigningAlgorithm(signing_algorithm)),
    }
}

pub const SIGNING_ALGOS: &[SigningAlgorithmId] = &[
    #[cfg(feature = "sign_gmac")]
    SigningAlgorithmId::AesGmac,
    #[cfg(feature = "sign_cmac_rustcrypto")]
    SigningAlgorithmId::AesCmac,
    #[cfg(feature = "sign_hmac")]
    SigningAlgorithmId::HmacSha256,
];

/// Stack-allocated enum of all signing algorithm implementations.
///
/// This replaces `Box<dyn SigningAlgo>` to avoid heap allocation on every clone.
/// Each variant is feature-gated to match the available signing algorithms.
#[derive(Clone)]
#[allow(clippy::large_enum_variant)] // Boxing adds an allocation to every signed request.
pub enum SigningAlgoEnum {
    #[cfg(feature = "sign_hmac")]
    HmacSha256(hmac_signer::HmacSha256Signer),
    #[cfg(feature = "sign_cmac_rustcrypto")]
    Cmac128(cmac_signer::Cmac128Signer),
    #[cfg(feature = "sign_gmac")]
    Gmac128(gmac_signer::Gmac128Signer),
}

impl SigningAlgoEnum {
    /// Sign one message without joining its independently owned wire segments.
    pub fn sign_segments<'a>(
        &mut self,
        _header: &Header,
        _first: &[u8],
        _segments: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<u128, CryptoError> {
        match self {
            #[cfg(feature = "sign_hmac")]
            Self::HmacSha256(s) => Ok(s.sign_segments(_first, _segments)),
            #[cfg(feature = "sign_cmac_rustcrypto")]
            Self::Cmac128(s) => s.sign_segments(_first, _segments),
            #[cfg(feature = "sign_gmac")]
            Self::Gmac128(s) => Ok(s.sign_segments(_header, _first, _segments)),
            #[cfg(not(any(
                feature = "sign_hmac",
                feature = "sign_cmac_rustcrypto",
                feature = "sign_gmac"
            )))]
            _ => unreachable!("no signing algorithm is compiled"),
        }
    }

    #[cfg(feature = "sign_cmac_rustcrypto")]
    pub(crate) fn sign_cmac_batch(
        &self,
        inputs: &[crate::crypto::CmacBatchInput<'_>],
    ) -> Option<Result<Vec<u128>, CryptoError>> {
        match self {
            Self::Cmac128(signer) => Some(signer.sign_batch(inputs)),
            #[allow(unreachable_patterns)]
            _ => None,
        }
    }

    #[cfg(feature = "sign_cmac_rustcrypto")]
    pub(crate) fn is_batchable_cmac(&self) -> bool {
        matches!(self, Self::Cmac128(_))
    }

    #[cfg(feature = "sign_cmac_rustcrypto")]
    pub(crate) fn batch_cmac_key_id(&self) -> Option<usize> {
        match self {
            Self::Cmac128(signer) => Some(signer.batch_key_id()),
            #[allow(unreachable_patterns)]
            _ => None,
        }
    }
}

impl std::fmt::Debug for SigningAlgoEnum {
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(feature = "sign_hmac")]
            Self::HmacSha256(s) => s.fmt(_f),
            #[cfg(feature = "sign_cmac_rustcrypto")]
            Self::Cmac128(s) => s.fmt(_f),
            #[cfg(feature = "sign_gmac")]
            Self::Gmac128(_) => _f.debug_struct("Gmac128Signer").finish(),
            #[cfg(not(any(
                feature = "sign_hmac",
                feature = "sign_cmac_rustcrypto",
                feature = "sign_gmac"
            )))]
            _ => unreachable!("no signing algorithm is compiled"),
        }
    }
}

#[cfg(feature = "sign_hmac")]
mod hmac_signer {
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;

    use super::*;

    type HmacSha256 = Hmac<Sha256>;

    #[derive(Debug, Clone)]
    pub struct HmacSha256Signer {
        hmac: Option<HmacSha256>,
    }

    impl HmacSha256Signer {
        pub fn build(signing_key: &SigningKey) -> SigningAlgoEnum {
            SigningAlgoEnum::HmacSha256(HmacSha256Signer {
                hmac: Some(HmacSha256::new_from_slice(signing_key).unwrap()),
            })
        }

        pub fn sign_segments<'a>(
            &mut self,
            first: &[u8],
            segments: impl IntoIterator<Item = &'a [u8]>,
        ) -> u128 {
            let hmac = self.hmac.as_mut().unwrap();
            hmac.update(first);
            for segment in segments {
                hmac.update(segment);
            }
            let result = self.hmac.take().unwrap().finalize().into_bytes();
            u128::from_le_bytes(result[0..16].try_into().unwrap())
        }
    }
}

#[cfg(feature = "sign_cmac_rustcrypto")]
mod cmac_signer {
    use std::sync::Arc;

    use aes::Aes128;
    use cmac::{Cmac, KeyInit};
    use hmac::Mac;

    use super::*;

    #[derive(Clone)]
    pub struct Cmac128Signer {
        cmac: Option<Cmac<Aes128>>,
        batch: Arc<crate::crypto::BatchCmac128>,
    }

    impl std::fmt::Debug for Cmac128Signer {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("Cmac128Signer").finish_non_exhaustive()
        }
    }

    impl Cmac128Signer {
        pub fn build(signing_key: &SigningKey) -> Result<SigningAlgoEnum, CryptoError> {
            Ok(SigningAlgoEnum::Cmac128(Cmac128Signer {
                cmac: Some(Cmac::new_from_slice(signing_key)?),
                batch: Arc::new(crate::crypto::BatchCmac128::new(signing_key)),
            }))
        }

        pub fn sign_segments<'a>(
            &mut self,
            first: &[u8],
            segments: impl IntoIterator<Item = &'a [u8]>,
        ) -> Result<u128, CryptoError> {
            let cmac = self.cmac.as_mut().unwrap();
            cmac.update(first);
            for segment in segments {
                cmac.update(segment);
            }
            Ok(u128::from_le_bytes(
                self.cmac.take().unwrap().finalize().into_bytes().into(),
            ))
        }

        pub(super) fn sign_batch(
            &self,
            inputs: &[crate::crypto::CmacBatchInput<'_>],
        ) -> Result<Vec<u128>, CryptoError> {
            self.batch.sign_batch(inputs)
        }

        pub(super) fn batch_key_id(&self) -> usize {
            Arc::as_ptr(&self.batch) as usize
        }
    }
}

#[cfg(feature = "sign_gmac")]
mod gmac_signer {
    use tokio::sync::OnceCell;

    use aes::Aes128;
    use aes_gcm::{
        Aes128Gcm, Key,
        aead::{AeadInOut, KeyInit},
    };
    use binrw::prelude::*;

    use super::*;

    type Gmac128Nonce = [u8; 12];

    #[derive(Clone)]
    pub struct Gmac128Signer {
        gmac: Aes128Gcm,
        nonce: OnceCell<Gmac128Nonce>,
        // no online mode implemented in RustCrypto,
        // so we'll buffer the input until finalized().
        buffer: Vec<u8>,
    }

    impl Gmac128Signer {
        pub fn build(key: &SigningKey) -> SigningAlgoEnum {
            let key = Key::<Aes128>::from(*key);
            SigningAlgoEnum::Gmac128(Gmac128Signer {
                gmac: Aes128Gcm::new(&key),
                nonce: OnceCell::new(),
                buffer: vec![],
            })
        }

        pub fn sign_segments<'a>(
            &mut self,
            header: &Header,
            first: &[u8],
            segments: impl IntoIterator<Item = &'a [u8]>,
        ) -> u128 {
            // The nonce is derived from the message ID.
            self.nonce.set(Self::make_nonce(header)).unwrap();
            debug_assert!(self.nonce.get().is_some());

            // Currently buffered until finalized.
            self.buffer.extend_from_slice(first);
            for segment in segments {
                self.buffer.extend_from_slice(segment);
            }
            debug_assert!(self.nonce.get().is_some());

            let mut empty_data: Vec<u8> = vec![];
            let result = self
                .gmac
                .encrypt_inout_detached(
                    self.nonce.get().unwrap().into(),
                    &self.buffer,
                    empty_data.as_mut_slice().into(),
                )
                .unwrap();
            u128::from_le_bytes(result.into())
        }

        fn make_nonce(header: &Header) -> Gmac128Nonce {
            debug_assert!(header.message_id > 0 && header.message_id != u64::MAX);

            // MS-SMB2 2.2.41.1 / 3.1.4.1: 64-bit message id, then the
            // server-to-redir and cancel bits, then 30 zero bits.
            let mut nonce: Gmac128Nonce = [0; 12];
            nonce[..8].copy_from_slice(&header.message_id.to_le_bytes());
            nonce[8] = u8::from(header.flags.server_to_redir())
                | (u8::from(header.command == Command::Cancel) << 1);
            nonce
        }
    }
}

#[cfg(all(test, feature = "sign_cmac_rustcrypto"))]
mod cmac_tests {
    use super::*;

    #[test]
    fn aes_cmac_matches_rfc_4493_for_segmented_input() {
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let message = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a,
        ];
        let expected = [
            0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44, 0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a,
            0x28, 0x7c,
        ];
        let mut signer = make_signing_algo(SigningAlgorithmId::AesCmac, &key)
            .expect("AES-CMAC signer must be available");

        let signature = signer
            .sign_segments(&test_header(), &message[..7], [&message[7..]])
            .unwrap();

        assert_eq!(signature.to_le_bytes(), expected);
    }

    #[test]
    #[ignore = "manual release-mode CMAC throughput probe"]
    fn aes_cmac_4160_byte_throughput_probe() {
        use std::{hint::black_box, time::Instant};

        const ITERATIONS: usize = 100_000;
        let key = [0x5a; 16];
        let payload = [0xa5; 4160];
        let base = make_signing_algo(SigningAlgorithmId::AesCmac, &key).unwrap();
        let header = test_header();
        let started = Instant::now();
        for _ in 0..ITERATIONS {
            let mut signer = base.clone();
            black_box(
                signer
                    .sign_segments(&header, black_box(payload.as_slice()), std::iter::empty())
                    .unwrap(),
            );
        }
        let elapsed = started.elapsed();
        let nanos_per_operation = elapsed.as_nanos() / ITERATIONS as u128;
        let mebibytes_per_second =
            payload.len() as f64 * ITERATIONS as f64 / elapsed.as_secs_f64() / (1024.0 * 1024.0);
        eprintln!(
            "CMAC_4160 iterations={ITERATIONS} ns_per_op={nanos_per_operation} mib_per_s={mebibytes_per_second:.2}"
        );
    }

    fn test_header() -> Header {
        Header {
            credit_charge: 1,
            status: 0,
            command: Command::Echo,
            credit_request: 1,
            flags: HeaderFlags::new(),
            next_command: 0,
            message_id: 1,
            tree_id: Some(0),
            async_id: None,
            session_id: 1,
            signature: 0,
        }
    }
}

#[cfg(all(
    test,
    feature = "sign_gmac",
    feature = "sign_cmac_rustcrypto",
    feature = "sign_hmac"
))]
mod preference_tests {
    use super::*;

    #[test]
    fn signing_algorithms_are_offered_in_strongest_first_order() {
        assert_eq!(
            SIGNING_ALGOS,
            &[
                SigningAlgorithmId::AesGmac,
                SigningAlgorithmId::AesCmac,
                SigningAlgorithmId::HmacSha256,
            ]
        );
    }
}
