//! GSS-API authentication state abstraction.
//!
//! The session setup state machine drives a GSS exchange (NTLM 2-round,
//! Kerberos 1- or 2-round) by feeding server-emitted challenge tokens
//! and consuming client-emitted response tokens, until the underlying
//! mechanism reports completion and exposes a SessionKey.
//!
//! Production code uses [`super::authenticator::Authenticator`], which
//! wraps `sspi::Negotiate`. Tests inject a hand-rolled mock that
//! returns a scripted sequence of tokens plus a fixed session key,
//! enabling deterministic transcript-replay tests of the setup path
//! without depending on a live KDC or NTLM password-derived secrets.

use crate::crypto::KeyToDerive;
use maybe_async::*;
use sspi::Username;

/// Abstract GSS-API authentication state.
///
/// Implementors drive a multi-step token exchange. Each call to
/// [`Self::next`] consumes the most recent server token and produces
/// the next client token. After [`Self::is_authenticated`] transitions
/// to `true`, [`Self::session_key`] yields the 16-byte SessionKey used
/// to derive SMB signing/encryption keys.
///
/// The trait is `Send` so that drivers can `.await` across it in async
/// builds and so that mock implementors can be moved into spawned tasks
/// for parallel scenarios.
#[maybe_async(AFIT)]
#[allow(async_fn_in_trait)]
pub trait GssState: std::fmt::Debug + Send {
    /// User identity used by the driver for logging only.
    fn user_name(&self) -> &Username;

    /// Whether the GSS exchange has reached its final success state.
    ///
    /// Drivers MUST call this after every [`Self::next`] to know whether
    /// the very next outgoing SessionSetup Request is the *final* one
    /// (and therefore must be signed per MS-SMB2 §3.3.5.5.3).
    fn is_authenticated(&self) -> crate::Result<bool>;

    /// Returns the negotiated SessionKey (first 16 bytes of the GSS key).
    ///
    /// Calling this before [`Self::is_authenticated`] returns `true` is
    /// an error; for `sspi`-backed implementors this typically maps to
    /// `SecurityStatus::InvalidHandle`.
    fn session_key(&self) -> crate::Result<KeyToDerive>;

    /// Consume a server token (empty slice on the first call) and
    /// produce the next client token. For Kerberos this may perform
    /// network I/O (KDC fetch); for NTLM it is purely local computation.
    async fn next(&mut self, server_token: &[u8]) -> crate::Result<Vec<u8>>;
}
