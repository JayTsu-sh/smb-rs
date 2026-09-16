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

/// Whether a session the server downgraded to guest or anonymous may proceed.
///
/// Guest and null sessions carry no session key, so their traffic cannot be signed or
/// encrypted (MS-SMB2 3.2.5.3.1). Allowing them trades message integrity for access to
/// shares that map unknown users to a guest account.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum GuestPolicy {
    /// Reject sessions flagged `SMB2_SESSION_FLAG_IS_GUEST` / `IS_NULL`.
    #[default]
    Deny,
    /// Accept unsigned guest or anonymous sessions when the server does not require signing.
    AllowUnsigned,
}

impl GuestPolicy {
    pub(crate) const fn allows_unsigned(self) -> bool {
        matches!(self, Self::AllowUnsigned)
    }
}

impl SigningPolicy {
    pub(crate) const fn required(self, server_requires: bool) -> bool {
        matches!(self, Self::Required) || server_requires
    }
}

#[cfg(test)]
#[path = "signing_tests.rs"]
mod tests;
