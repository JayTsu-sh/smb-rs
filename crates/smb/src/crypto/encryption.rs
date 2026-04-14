use std::fmt::Debug;

use smb_msg::EncryptionNonce;

use super::CryptoError;

/// Holds the signature of the payload after encryption.
pub struct EncryptionResult {
    pub signature: u128,
}

/// A trait for an implementation of an encryption algorithm.
///
/// Note: All methods take `&self` since the underlying AES-GCM/CCM ciphers are stateless
/// after key setup. This allows sharing the algo across threads without cloning.
pub trait EncryptingAlgo: Debug + Send + Sync {
    /// Algo-specific encryption function, in-place.
    fn encrypt(
        &self,
        payload: &mut [u8],
        header_data: &[u8],
        nonce: &EncryptionNonce,
    ) -> Result<EncryptionResult, CryptoError>;

    /// Algo-specific decryption function, in-place.
    fn decrypt(
        &self,
        payload: &mut [u8],
        header_data: &[u8],
        nonce: &EncryptionNonce,
        signature: u128,
    ) -> Result<(), CryptoError>;

    /// Returns the size of the nonce required by the encryption algorithm.
    fn nonce_size(&self) -> usize;
}

#[cfg(feature = "__encrypt_core")]
mod impls;
#[cfg(feature = "__encrypt_core")]
pub use impls::*;

#[cfg(not(feature = "__encrypt_core"))]
mod disabled;
#[cfg(not(feature = "__encrypt_core"))]
pub use disabled::*;

#[cfg(any(feature = "encrypt_aes128ccm", feature = "encrypt_aes256ccm"))]
mod encrypt_ccm;

#[cfg(any(feature = "encrypt_aes128gcm", feature = "encrypt_aes256gcm"))]
mod encrypt_gcm;
