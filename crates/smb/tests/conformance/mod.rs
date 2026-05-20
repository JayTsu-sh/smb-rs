//! Conformance test framework.
//!
//! Deterministic SessionSetup / protocol transcript replay against the
//! production [`smb::Connection`] code path. See sub-modules:
//!
//! - [`mock_transport`] — in-process [`SmbTransport`] with scripted
//!   server frames and captured client frames
//! - [`mock_gss`]       — hand-scripted [`GssState`] mock (NTLM-style
//!   2-round exchange or any other shape)
//! - [`asserts`]        — protocol-level assertion helpers for the
//!   captured client frames
//!
//! Test binaries pull this module in via `#[path = "conformance/mod.rs"] mod conformance;`.
//! See `tests/conformance_smoke.rs` for a minimal example.

// Per-binary dead_code is the norm here: each test binary uses some
// helpers but not others, and we don't want to write `#[allow]` at every
// callsite.
#![allow(dead_code, unused_imports)]

pub mod asserts;
pub mod mock_gss;
pub mod mock_transport;
pub mod transcripts;

pub use asserts::{
    ClientFrameHeader, assert_intermediate_session_setup, assert_signed_final_session_setup,
};
pub use mock_gss::{MockGss, ScriptedGssStep};
pub use mock_transport::{MockTransport, TranscriptControl};
