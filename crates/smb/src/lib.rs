#![doc = include_str!("../docs/index.md")]
#![forbid(unsafe_code)]

#[allow(
    dead_code,
    reason = "crate-private protocol implementation exercised through the domain interface"
)]
pub(crate) mod client;
mod clock;
#[allow(
    dead_code,
    reason = "crate-private wire model includes protocol-fixture observations"
)]
pub(crate) mod command;
pub mod compression;
#[allow(
    dead_code,
    reason = "optional protocol paths are exercised by deterministic fixtures"
)]
pub(crate) mod connection;
pub mod crypto;
pub mod dialects;
pub mod docs;
pub mod domain;
pub mod error;
pub mod facade;
mod signing;
pub use signing::{GuestPolicy, SigningPolicy};
#[allow(dead_code, reason = "conditional lease and oplock server-event paths")]
pub(crate) mod lease;
#[allow(
    dead_code,
    reason = "crate-private implementation consumed through runtime::port"
)]
pub(crate) mod resource;
pub(crate) mod runtime;
#[cfg(feature = "test-support")]
mod scenario;
#[allow(
    dead_code,
    reason = "crate-private implementation consumed through runtime::port"
)]
pub(crate) mod session;
#[allow(
    dead_code,
    reason = "crate-private implementation consumed through runtime::port"
)]
pub(crate) mod tree;

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
    pub use crate::connection::{Connection, ConnectionConfig};
    pub use crate::scenario::{
        LifecycleScenario, ScenarioError, ScenarioEvent, ScenarioReport, ScenarioTaskError,
        TerminalOutcome, TerminalProbe,
    };
    pub use crate::session::gss::GssState;
    pub use smb_transport::test_support::{ScriptedTransport, ScriptedTransportControl};
}

pub use domain::{
    Batch, BatchCommand, BatchOutcome, BatchRef, BatchResult, CancelToken, CloseOutcome,
    CloseReport, CredentialProvider, Credentials, Deadline, Directory, DirectoryEntries,
    DirectoryEntry, DirectoryEvent, DirectoryEvents, DirectoryOpenOptions, DirectoryWatchOptions,
    File, FileCursor, FileOpenOptions, IoCapabilities, MetadataOpenOptions, MetadataUpdate,
    ObjectGeneration, OpenInfo, OpenKind, Operation, Pipe, PipeName, PreviousVersion, ReplayPolicy,
    Resource, ResourceMetadata, RpcPipeConnection, SecurityDescriptor, SecurityOpenOptions,
    SecuritySelection, Session, SessionInfo, Share, ShareInfo, SharePath, ShareTarget, Transfer,
    TransferEvents, TransferOptions, TransferProgress, TransferReport,
};
pub use error::Error;
pub use facade::{Client, RemoteShare, ShareKind};

/// Explicit protocol-value namespace for extension and diagnostic code.
/// Normal facade/domain callers do not need these wire-level types.
pub mod protocol {
    pub use smb_dtyp::*;
    pub use smb_fscc::*;
    pub use smb_msg::*;
}
pub use smb_transport as transport;

/// SMB Result type
pub type Result<T> = std::result::Result<T, crate::Error>;
