#![doc = include_str!("../docs/index.md")]
#![forbid(unsafe_code)]

pub mod client;
mod clock;
pub mod compression;
pub mod connection;
pub mod crypto;
pub mod dialects;
pub mod docs;
pub mod domain;
pub mod error;
pub mod facade;
pub mod lease;
pub mod command;
pub mod resource;
pub(crate) mod runtime;
#[cfg(feature = "test-support")]
mod scenario;
pub mod session;
pub mod tree;

/// Test-only API surface.
///
/// Enabled by the `test-support` cargo feature, this module re-exports
/// internals required for deterministic SessionSetup transcript-replay
/// tests (see `tests/conformance/`). Items here are **not** part of
/// the stable public API — they may change without a SemVer bump and
/// must never be relied upon by downstream code outside of test fixtures.
#[cfg(feature = "test-support")]
pub mod test_support {
    pub use crate::clock::{Clock, ManualClock, ManualClockError, MonotonicTime, TokioClock};
    pub use crate::scenario::{
        LifecycleScenario, ScenarioError, ScenarioEvent, ScenarioReport, ScenarioTaskError,
        TerminalOutcome, TerminalProbe,
    };
    pub use crate::session::gss::GssState;
    pub use smb_transport::test_support::{ScriptedTransport, ScriptedTransportControl};
}

pub use client::UncPath;
pub use connection::ConnectionConfig;
pub use domain::{
    Credentials, Directory, File, FileOpenOptions, Pipe, Resource, Session, Share, SharePath,
    ShareTarget,
};
pub use error::Error;
pub use facade::{Client, ClientConfig};
pub use lease::{LeaseBreakAckOutcome, LeaseBreakEvent, OplockBreakEvent};
pub use resource::{
    DurableOpenGrant, DurableOpenRequest, FileCreateArgs, GetLen, LeaseGrant, PipeRpcConnection,
    ReadAt, ReadAtChannel, ResourceHandle, WriteAt, WriteAtChannel,
};
pub use tree::DfsRootTreeRef;

pub use smb_dtyp::*;
pub use smb_fscc::*;
pub use smb_msg::*;
pub use smb_transport as transport;

/// SMB Result type
pub type Result<T> = std::result::Result<T, crate::Error>;
