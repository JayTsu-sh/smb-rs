//! Message encryption/decryption implementation.

use binrw::prelude::*;
use rand::RngCore;
use rand::rngs::OsRng;
use std::io::Cursor;
use std::sync::Arc;

use crate::crypto;
use smb_msg::{Response, encrypted::*};

/// Encrypts SMB2 messages with a session-derived AEAD key.
///
/// `Clone` is cheap (`Arc`-clone of the algo handle). The trait doc on
/// [`crypto::EncryptingAlgo`] guarantees `&self` thread-safety after
/// key setup, and the per-message nonce is drawn from `OsRng` inside
/// [`Self::encrypt_message`] — so clones can encrypt concurrently
/// without risk of nonce reuse.
#[derive(Clone, Debug)]
pub struct MessageEncryptor {
    algo: Arc<dyn crypto::EncryptingAlgo>,
}

impl MessageEncryptor {
    pub fn new(algo: Arc<dyn crypto::EncryptingAlgo>) -> MessageEncryptor {
        MessageEncryptor { algo }
    }

    /// Encrypts one contiguous transform payload in-place.
    pub fn encrypt_message(
        &self,
        message: &mut [u8],
        session_id: u64,
    ) -> crate::Result<EncryptedHeader> {
        debug_assert!(session_id != 0);

        // Serialize message:
        let mut header = EncryptedHeader {
            signature: 0,
            nonce: self.gen_nonce(),
            original_message_size: u32::try_from(message.len()).map_err(|_| {
                crate::Error::InvalidMessage("encrypted transform exceeds u32".to_string())
            })?,
            session_id,
        };

        let result = self
            .algo
            .encrypt(message, &header.aead_bytes(), &header.nonce)?;

        header.signature = result.signature;

        tracing::debug!("Encrypted message with signature: {:?}", header.signature);

        Ok(header)
    }

    fn gen_nonce(&self) -> [u8; 16] {
        let mut nonce = [0; 16];
        // Generate self.algo.nonce_size() random bytes:
        OsRng.fill_bytes(&mut nonce[..self.algo.nonce_size()]);
        nonce
    }
}

/// Decrypts SMB2 messages with a session-derived AEAD key. See
/// [`MessageEncryptor`] for the rationale behind `Clone`.
#[derive(Clone, Debug)]
pub struct MessageDecryptor {
    algo: Arc<dyn crypto::EncryptingAlgo>,
}

impl MessageDecryptor {
    pub fn new(algo: Arc<dyn crypto::EncryptingAlgo>) -> MessageDecryptor {
        MessageDecryptor { algo }
    }

    pub fn decrypt_message(&self, msg_in: EncryptedMessage) -> crate::Result<(Response, Vec<u8>)> {
        if msg_in.encrypted_message.len() != msg_in.header.original_message_size as usize {
            return Err(crate::Error::InvalidMessage(
                "encrypted payload length does not match OriginalMessageSize".to_string(),
            ));
        }
        if msg_in.header.nonce[self.algo.nonce_size()..]
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err(crate::Error::InvalidMessage(
                "encrypted nonce has non-zero unused bytes".to_string(),
            ));
        }
        // decrypt in-place
        let mut buffer = msg_in.encrypted_message;
        let aead_bytes = msg_in.header.aead_bytes();
        let nonce = msg_in.header.nonce;
        let signature = msg_in.header.signature;
        self.algo
            .decrypt(&mut buffer, &aead_bytes, &nonce, signature)?;

        tracing::trace!("Decrypted message data bytes: {:x?}", &buffer);
        // deserialize
        let result = Response::read(&mut Cursor::new(&buffer))?;

        tracing::debug!("Decrypted with signature {}", msg_in.header.signature);
        Ok((result, buffer))
    }
}

#[cfg(all(test, feature = "encrypt_aes128gcm"))]
mod tests {
    use super::*;
    use smb_msg::EncryptionCipher;

    #[test]
    fn final_transform_arena_is_encrypted_in_place_and_tamper_is_rejected() {
        let algo = crypto::make_encrypting_algo(EncryptionCipher::Aes128Gcm, &[0x5a; 16])
            .expect("AES-GCM test algorithm");
        let encryptor = MessageEncryptor::new(algo.clone());
        let plaintext = b"one-owner-transform";
        let mut payload = plaintext.to_vec();
        let header = encryptor
            .encrypt_message(&mut payload, 7)
            .expect("encrypt in place");
        assert_ne!(payload, plaintext);

        algo.decrypt(
            &mut payload,
            &header.aead_bytes(),
            &header.nonce,
            header.signature,
        )
        .expect("decrypt verified transform");
        assert_eq!(payload, plaintext);

        payload[0] ^= 1;
        assert!(
            algo.decrypt(
                &mut payload,
                &header.aead_bytes(),
                &header.nonce,
                header.signature,
            )
            .is_err()
        );
    }

    #[test]
    fn encrypted_envelope_rejects_size_and_unused_nonce_before_plaintext_parse() {
        let algo = crypto::make_encrypting_algo(EncryptionCipher::Aes128Gcm, &[0x7b; 16])
            .expect("AES-GCM test algorithm");
        let encryptor = MessageEncryptor::new(algo.clone());
        let decryptor = MessageDecryptor::new(algo);

        let mut payload = b"not parsed".to_vec();
        let header = encryptor.encrypt_message(&mut payload, 9).unwrap();
        payload.pop();
        assert!(matches!(
            decryptor.decrypt_message(EncryptedMessage {
                header,
                encrypted_message: payload,
            }),
            Err(crate::Error::InvalidMessage(message))
                if message.contains("OriginalMessageSize")
        ));

        let mut payload = b"not parsed".to_vec();
        let mut header = encryptor.encrypt_message(&mut payload, 9).unwrap();
        header.nonce[15] = 1;
        assert!(matches!(
            decryptor.decrypt_message(EncryptedMessage {
                header,
                encrypted_message: payload,
            }),
            Err(crate::Error::InvalidMessage(message)) if message.contains("nonce")
        ));
    }
}
