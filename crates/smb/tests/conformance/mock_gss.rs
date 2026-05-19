//! Mock [`GssState`] for deterministic SessionSetup tests.
//!
//! Production code drives an `sspi::Negotiate` whose per-round output
//! depends on random NTLM challenges and password-derived secrets —
//! neither reproducible across runs. For transcript tests we substitute
//! a hand-scripted GSS that returns a predetermined sequence of client
//! tokens and exposes a fixed session key.
//!
//! Plug it into a connection via
//! [`smb::Connection::authenticate_with_gss`] (gated by the
//! `test-support` feature on the `smb` crate).

use smb::test_support::GssState;
use std::collections::VecDeque;

/// One scripted GSS round produced by [`MockGss::next`].
#[derive(Debug, Clone)]
pub struct ScriptedGssStep {
    /// Bytes the mock will emit as the next *client* token.
    pub client_token: Vec<u8>,
    /// If `true`, the mock transitions to `is_authenticated() == true`
    /// after returning this token. Only the *final* scripted step
    /// should set this to `true`.
    pub completes_auth: bool,
}

/// Hand-scripted GSS state machine.
///
/// Invariants enforced via `assert!` in [`Self::new`]:
/// - at least one step
/// - the last step must set `completes_auth = true`
///
/// Panics if [`Self::next`] is called more times than the script has
/// steps, or if [`Self::session_key`] is called before authentication
/// completes — every such case is a real test bug.
#[derive(Debug)]
pub struct MockGss {
    user_name: sspi::Username,
    steps: VecDeque<ScriptedGssStep>,
    session_key: [u8; 16],
    authenticated: bool,
}

impl MockGss {
    /// Construct a scripted GSS mock.
    ///
    /// * `account` / `domain` populate the `sspi::Username` reported via
    ///   [`GssState::user_name`] (the driver only reads it for logging).
    /// * `session_key` is the fixed 16-byte secret the mock will surface
    ///   once authentication completes. Choose anything (e.g.
    ///   `[0x11; 16]`) — the test then derives expected signing keys
    ///   from it via the same SP800-108 KDF the production code uses.
    /// * `steps` is the ordered list of client tokens to emit on
    ///   successive [`Self::next`] calls.
    pub fn new(
        account: &str,
        domain: Option<&str>,
        session_key: [u8; 16],
        steps: Vec<ScriptedGssStep>,
    ) -> Self {
        assert!(
            !steps.is_empty(),
            "MockGss requires at least one scripted step"
        );
        assert!(
            steps.last().map(|s| s.completes_auth).unwrap_or(false),
            "the final scripted MockGss step must set completes_auth=true"
        );
        let user_name = match domain {
            Some(d) => sspi::Username::new(account, Some(d))
                .expect("MockGss: failed to build sspi::Username"),
            None => sspi::Username::parse(account)
                .expect("MockGss: failed to parse sspi::Username"),
        };
        Self {
            user_name,
            steps: VecDeque::from(steps),
            session_key,
            authenticated: false,
        }
    }

    /// Returns the number of script steps that have not yet been
    /// consumed by [`Self::next`].
    pub fn remaining_steps(&self) -> usize {
        self.steps.len()
    }
}

impl GssState for MockGss {
    fn user_name(&self) -> &sspi::Username {
        &self.user_name
    }

    fn is_authenticated(&self) -> smb::Result<bool> {
        Ok(self.authenticated)
    }

    fn session_key(&self) -> smb::Result<[u8; 16]> {
        if !self.authenticated {
            return Err(smb::Error::InvalidState(
                "MockGss::session_key called before auth complete".to_string(),
            ));
        }
        Ok(self.session_key)
    }

    async fn next(&mut self, _server_token: &[u8]) -> smb::Result<Vec<u8>> {
        let step = self.steps.pop_front().unwrap_or_else(|| {
            panic!(
                "MockGss::next called more times than scripted steps were provided \
                 (test should script exactly as many rounds as the driver invokes)"
            )
        });
        if step.completes_auth {
            self.authenticated = true;
        }
        Ok(step.client_token)
    }
}
