//! Negotiated signing policy for authenticated SMB sessions.

/// Controls signing of ordinary SMB requests and responses.
///
/// Protocol-mandated authentication, binding and SMB 3.1.1 tree-connect
/// protection is retained under both policies. Encryption is independent.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum SigningPolicy {
    /// Require message integrity even when the server does not require it.
    #[default]
    Required,
    /// Omit ordinary message signing when the server permits it.
    ///
    /// Server-required signing is always honored. Without encryption,
    /// unsigned traffic has no SMB message integrity protection.
    WhenRequired,
}

impl SigningPolicy {
    pub(crate) const fn required(self, server_requires: bool) -> bool {
        matches!(self, Self::Required) || server_requires
    }
}

#[cfg(test)]
#[path = "signing_tests.rs"]
mod tests;
