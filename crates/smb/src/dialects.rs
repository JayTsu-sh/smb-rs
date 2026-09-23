//! Implements SMB-dialect-specific types and functions.

use std::sync::Arc;

use crate::{
    Error,
    connection::ConnectionConfig,
    connection::{connection_info::NegotiatedProperties, preauth_hash},
    crypto,
};
use smb_msg::{
    Dialect, GlobalCapabilities, NegotiateContextType, NegotiateResponse, ShareCacheMode,
    ShareFlags, SigningAlgorithmId, TreeCapabilities,
};

/// This is a utility struct that returns constants and functions for the given dialect.
#[derive(Debug)]
pub struct DialectImpl {
    pub dialect: Dialect,
}

impl DialectImpl {
    pub fn new(dialect: Dialect) -> Arc<Self> {
        Arc::new(Self { dialect })
    }

    pub fn get_negotiate_caps_mask(&self) -> GlobalCapabilities {
        let mut mask = GlobalCapabilities::new().with_dfs(true);

        mask.set_leasing(self.dialect > Dialect::Smb0202);
        mask.set_large_mtu(self.dialect > Dialect::Smb0202);

        mask.set_multi_channel(self.dialect > Dialect::Smb021);
        mask.set_persistent_handles(self.dialect > Dialect::Smb021);
        mask.set_directory_leasing(self.dialect > Dialect::Smb021);

        mask.set_encryption(Dialect::Smb030 <= self.dialect && self.dialect <= Dialect::Smb0302);

        mask.set_notifications(self.dialect == Dialect::Smb0311);

        mask
    }

    pub fn get_share_flags_mask(&self) -> ShareFlags {
        let mut mask = ShareFlags::new()
            .with_caching_mode(ShareCacheMode::All)
            .with_dfs(true)
            .with_dfs_root(true)
            .with_restrict_exclusive_opens(true)
            .with_force_shared_delete(true)
            .with_allow_namespace_caching(true)
            .with_access_based_directory_enum(true)
            .with_force_levelii_oplock(true)
            .with_identity_remoting(true)
            .with_isolated_transport(true);

        if self.dialect > Dialect::Smb0202 {
            mask.set_enable_hash_v1(true);
        }
        if self.dialect >= Dialect::Smb021 {
            mask.set_enable_hash_v2(true);
        }
        if self.dialect.is_smb3() {
            mask.set_encrypt_data(true);
        }
        if self.dialect >= Dialect::Smb0311 {
            mask.set_compress_data(true);
        }

        mask
    }

    pub fn get_tree_connect_caps_mask(&self) -> TreeCapabilities {
        let mut mask = TreeCapabilities::new().with_dfs(true);

        if self.dialect.is_smb3() {
            mask = mask
                .with_continuous_availability(true)
                .with_scaleout(true)
                .with_cluster(true);
        }

        if self.dialect >= Dialect::Smb0302 {
            mask.set_asymmetric(true);
        }

        if self.dialect == Dialect::Smb0311 {
            mask = mask.with_redirect_to_owner(true);
        }

        mask
    }

    pub fn process_negotiate_request(
        &self,
        response: &NegotiateResponse,
        state: &mut NegotiatedProperties,
        config: &ConnectionConfig,
    ) -> crate::Result<()> {
        match self.dialect {
            Dialect::Smb0311 => Smb311.process_negotiate_request(response, state, config),
            Dialect::Smb0302 | Dialect::Smb030 => {
                Smb30X.process_negotiate_request(response, state, config)
            }
            Dialect::Smb021 | Dialect::Smb0202 => {
                Smb201.process_negotiate_request(response, state, config)
            }
        }
    }

    /// Returns the signing key derivation label for SMB 3.x dialects.
    ///
    /// SMB 2.0.2 and 2.1 do not use key derivation — they use the session key directly
    /// as the signing key (handled by `smb2_make_signer`). This method should only be
    /// called for SMB 3.x dialects.
    pub fn get_signing_derive_label(&self) -> crate::Result<&[u8]> {
        match self.dialect {
            Dialect::Smb0311 => Ok(Smb311::SIGNING_KEY_LABEL),
            Dialect::Smb0302 | Dialect::Smb030 => Ok(Smb30X::SIGNING_KEY_LABEL),
            Dialect::Smb0202 | Dialect::Smb021 => Err(crate::Error::InvalidState(
                "SMB 2.x dialects do not support signing key derivation".to_string(),
            )),
        }
    }

    pub fn preauth_hash_supported(&self) -> bool {
        self.dialect == Dialect::Smb0311
    }

    pub fn default_signing_algo(&self) -> SigningAlgorithmId {
        match self.dialect {
            Dialect::Smb0311 | Dialect::Smb0302 | Dialect::Smb030 => SigningAlgorithmId::AesCmac,
            Dialect::Smb0202 | Dialect::Smb021 => SigningAlgorithmId::HmacSha256,
        }
    }

    pub fn supports_compression(&self) -> bool {
        self.dialect == Dialect::Smb0311
    }

    pub fn supports_encryption(&self) -> bool {
        self.dialect.is_smb3()
    }

    pub fn s2c_encrypt_key_derive_label(&self) -> crate::Result<&[u8]> {
        match self.dialect {
            Dialect::Smb0311 => Ok(Smb311::ENCRYPTION_S2C_KEY_LABEL),
            Dialect::Smb0302 | Dialect::Smb030 => Ok(Smb30X::ENCRYPTION_KEY_LABEL),
            Dialect::Smb0202 | Dialect::Smb021 => Err(crate::Error::InvalidState(
                "Encryption is not supported for SMB 2.x dialects".to_string(),
            )),
        }
    }
    pub fn c2s_encrypt_key_derive_label(&self) -> crate::Result<&[u8]> {
        match self.dialect {
            Dialect::Smb0311 => Ok(Smb311::ENCRYPTION_C2S_KEY_LABEL),
            Dialect::Smb0302 | Dialect::Smb030 => Ok(Smb30X::ENCRYPTION_KEY_LABEL),
            Dialect::Smb0202 | Dialect::Smb021 => Err(crate::Error::InvalidState(
                "Encryption is not supported for SMB 2.x dialects".to_string(),
            )),
        }
    }
}

trait DialectMethods {
    const SIGNING_KEY_LABEL: &'static [u8];
    fn process_negotiate_request(
        &self,
        response: &NegotiateResponse,
        _state: &mut NegotiatedProperties,
        config: &ConnectionConfig,
    ) -> crate::Result<()>;
}

struct Smb311;
impl Smb311 {
    pub const ENCRYPTION_S2C_KEY_LABEL: &'static [u8] = b"SMBS2CCipherKey\x00";
    pub const ENCRYPTION_C2S_KEY_LABEL: &'static [u8] = b"SMBC2SCipherKey\x00";
}

impl DialectMethods for Smb311 {
    const SIGNING_KEY_LABEL: &'static [u8] = b"SMBSigningKey\x00";
    fn process_negotiate_request(
        &self,
        response: &NegotiateResponse,
        state: &mut NegotiatedProperties,
        config: &ConnectionConfig,
    ) -> crate::Result<()> {
        let contexts = response
            .negotiate_context_list
            .as_ref()
            .ok_or_else(|| Error::InvalidMessage("Expected negotiate context list".to_string()))?;

        let preauth_context_count = contexts
            .iter()
            .filter(|context| {
                context.context_type == NegotiateContextType::PreauthIntegrityCapabilities
            })
            .count();
        if preauth_context_count != 1 {
            return Err(Error::NegotiationError(
                "SMB 3.1.1 requires exactly one preauthentication integrity context".into(),
            ));
        }

        let signing_context_count = contexts
            .iter()
            .filter(|context| context.context_type == NegotiateContextType::SigningCapabilities)
            .count();
        if signing_context_count > 1 {
            return Err(Error::NegotiationError(
                "SMB 3.1.1 response contains multiple signing capability contexts".into(),
            ));
        }

        let ctx_signing = response.get_ctx_signing_capabilities();
        let signing_algo = if let Some(ctx) = ctx_signing {
            if ctx.signing_algorithms.len() != 1 {
                return Err(Error::NegotiationError(
                    "The server must select exactly one signing algorithm".into(),
                ));
            }
            let signing_algo = &ctx.signing_algorithms[0];
            if !crypto::SIGNING_ALGOS.contains(signing_algo) {
                return Err(Error::NegotiationError(
                    "Unsupported signing algorithm selected!".into(),
                ));
            }
            Some(signing_algo)
        } else {
            None
        };

        let ctx_integrity = response
            .get_ctx_preauth_integrity_capabilities()
            .expect("preauthentication context count was validated above");
        if ctx_integrity.hash_algorithms.len() != 1 {
            return Err(Error::NegotiationError(
                "The server must select exactly one preauthentication integrity algorithm".into(),
            ));
        }
        if !preauth_hash::SUPPORTED_ALGOS.contains(&ctx_integrity.hash_algorithms[0]) {
            return Err(Error::NegotiationError(
                "Unsupported preauth integrity algorithm received".into(),
            ));
        }

        // And verify that the encryption algorithm is supported.
        let encryption = response.get_ctx_encryption_capabilities();
        let first_cipher = encryption.and_then(|ctx| ctx.ciphers.first());
        if let Some(encryption_cipher) = first_cipher {
            if !crypto::ENCRYPTING_ALGOS.contains(encryption_cipher) {
                return Err(Error::NegotiationError(
                    "Unsupported encryption algorithm received".into(),
                ));
            }
        } else if config.encryption_mode.is_required() {
            return Err(Error::NegotiationError(
                "Encryption is required, but no algorithms provided by the server".into(),
            ));
        }

        let compression = response.get_ctx_compression_capabilities().cloned();

        state.signing_algo = signing_algo.copied();
        state.encryption_cipher = first_cipher.copied();
        state.compression = compression;

        Ok(())
    }
}

/// SMB 3.0 and 3.0.2
struct Smb30X;
impl Smb30X {
    pub const ENCRYPTION_KEY_LABEL: &'static [u8] = b"SMB2AESCCM\x00";
}

impl DialectMethods for Smb30X {
    const SIGNING_KEY_LABEL: &'static [u8] = b"SMB2AESCMAC\x00";
    fn process_negotiate_request(
        &self,
        response: &NegotiateResponse,
        _state: &mut NegotiatedProperties,
        config: &ConnectionConfig,
    ) -> crate::Result<()> {
        if response.negotiate_context_list.is_some() {
            return Err(Error::InvalidMessage(
                "Negotiate context list not expected".to_string(),
            ));
        }

        if config.encryption_mode.is_required() && !response.capabilities.encryption() {
            return Err(Error::NegotiationError(
                "Encryption is required, but cap not supported by the server.".into(),
            ));
        }

        Ok(())
    }
}

struct Smb201;

impl DialectMethods for Smb201 {
    const SIGNING_KEY_LABEL: &'static [u8] = b"";

    fn process_negotiate_request(
        &self,
        response: &NegotiateResponse,
        _state: &mut NegotiatedProperties,
        _config: &ConnectionConfig,
    ) -> crate::Result<()> {
        if response.negotiate_context_list.is_some() {
            return Err(Error::InvalidMessage(
                "Negotiate context list not expected".to_string(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use smb_dtyp::{Guid, binrw_util::file_time::FileTime};
    use smb_msg::{
        EncryptionCapabilities, EncryptionCipher, GlobalCapabilities, HashAlgorithm,
        NegotiateContext, NegotiateDialect, NegotiateResponse, NegotiateSecurityMode,
        PreauthIntegrityCapabilities, SigningAlgorithmId, SigningCapabilities,
    };

    use super::*;

    fn preauth(algorithms: Vec<HashAlgorithm>) -> NegotiateContext {
        PreauthIntegrityCapabilities {
            hash_algorithms: algorithms,
            salt: vec![],
        }
        .into()
    }

    fn signing(algorithms: Vec<SigningAlgorithmId>) -> NegotiateContext {
        SigningCapabilities {
            signing_algorithms: algorithms,
        }
        .into()
    }

    fn response(contexts: Vec<NegotiateContext>) -> NegotiateResponse {
        NegotiateResponse {
            security_mode: NegotiateSecurityMode::new().with_signing_enabled(true),
            dialect_revision: NegotiateDialect::Smb0311,
            server_guid: Guid::from([0; 16]),
            capabilities: GlobalCapabilities::new(),
            max_transact_size: 1024,
            max_read_size: 1024,
            max_write_size: 1024,
            system_time: FileTime::default(),
            server_start_time: FileTime::default(),
            buffer: vec![],
            negotiate_context_list: Some(contexts),
        }
    }

    fn state() -> NegotiatedProperties {
        NegotiatedProperties {
            server_guid: Guid::from([0; 16]),
            signing_required: false,
            caps: GlobalCapabilities::new(),
            max_transact_size: 1024,
            max_read_size: 1024,
            max_write_size: 1024,
            auth_buffer: vec![],
            signing_algo: None,
            encryption_cipher: None,
            compression: None,
            dialect_rev: Dialect::Smb0311,
        }
    }

    #[test]
    fn smb311_rejects_missing_preauth_context() {
        let response = response(vec![signing(vec![SigningAlgorithmId::AesCmac])]);

        assert!(
            Smb311
                .process_negotiate_request(&response, &mut state(), &ConnectionConfig::default())
                .is_err()
        );
    }

    #[test]
    fn smb311_rejects_multiple_preauth_contexts() {
        let response = response(vec![
            preauth(vec![HashAlgorithm::Sha512]),
            preauth(vec![HashAlgorithm::Sha512]),
        ]);

        assert!(
            Smb311
                .process_negotiate_request(&response, &mut state(), &ConnectionConfig::default())
                .is_err()
        );
    }

    #[test]
    fn smb311_rejects_preauth_algorithm_count_other_than_one() {
        let response = response(vec![preauth(vec![
            HashAlgorithm::Sha512,
            HashAlgorithm::Sha512,
        ])]);

        assert!(
            Smb311
                .process_negotiate_request(&response, &mut state(), &ConnectionConfig::default())
                .is_err()
        );
    }

    #[test]
    fn smb311_rejects_signing_algorithm_count_other_than_one() {
        let response = response(vec![
            preauth(vec![HashAlgorithm::Sha512]),
            signing(vec![
                SigningAlgorithmId::AesCmac,
                SigningAlgorithmId::HmacSha256,
            ]),
            EncryptionCapabilities {
                ciphers: vec![EncryptionCipher::Aes128Ccm],
            }
            .into(),
        ]);

        assert!(
            Smb311
                .process_negotiate_request(&response, &mut state(), &ConnectionConfig::default())
                .is_err()
        );
    }
}
