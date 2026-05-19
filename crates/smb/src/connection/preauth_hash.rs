use sha2::{Digest, Sha512};

use smb_msg::HashAlgorithm;

pub type PreauthHashValue = [u8; 64];

pub const SUPPORTED_ALGOS: &[HashAlgorithm] = &[HashAlgorithm::Sha512];

#[derive(Debug, Clone, Default)]
pub enum PreauthHashState {
    /// This state always transitions to itself, and calling `unwrap_final_hash` returns `None`.
    /// Also the `Default` so that holders constructed before `negotiated()`
    /// runs are in the safest possible state (no integrity tracking).
    #[default]
    Unsupported,

    InProgress(PreauthHashValue),
    Finished(PreauthHashValue),
}

impl PreauthHashState {
    pub fn begin() -> PreauthHashState {
        PreauthHashState::InProgress([0; 64])
    }

    pub fn unsupported() -> PreauthHashState {
        PreauthHashState::Unsupported
    }

    pub fn next(self, data: &[u8]) -> crate::Result<PreauthHashState> {
        match self {
            PreauthHashState::InProgress(hash) => {
                let mut hasher = Sha512::new();
                hasher.update(hash);
                hasher.update(data);

                Ok(PreauthHashState::InProgress(hasher.finalize().into()))
            }
            PreauthHashState::Unsupported => Ok(PreauthHashState::Unsupported),
            PreauthHashState::Finished(_) => Err(crate::Error::InvalidState(
                "Preauth hash already finished".to_string(),
            )),
        }
    }

    pub fn finish(self) -> crate::Result<PreauthHashState> {
        match self {
            PreauthHashState::InProgress(hash) => Ok(PreauthHashState::Finished(hash)),
            PreauthHashState::Unsupported => Ok(PreauthHashState::Unsupported),
            PreauthHashState::Finished(_) => Err(crate::Error::InvalidState(
                "Preauth hash already finished".to_string(),
            )),
        }
    }

    pub fn unwrap_final_hash(&self) -> crate::Result<Option<&PreauthHashValue>> {
        match self {
            PreauthHashState::Finished(hash) => Ok(Some(hash)),
            PreauthHashState::Unsupported => Ok(None),
            PreauthHashState::InProgress(_) => Err(crate::Error::InvalidState(
                "Preauth hash not finished".to_string(),
            )),
        }
    }
}
