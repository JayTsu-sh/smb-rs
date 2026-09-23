#![doc = include_str!("../docs/index.md")]
#![forbid(unsafe_code)]

pub(crate) mod client;
mod clock;
pub(crate) mod command;
pub mod compression;
pub(crate) mod connection;
pub mod crypto;
pub mod dialects;
pub mod docs;
pub mod domain;
pub mod error;
pub mod facade;
mod signing;
pub use signing::{GuestPolicy, SigningPolicy};
pub(crate) mod lease;
pub(crate) mod resource;
pub(crate) mod runtime;
#[cfg(feature = "test-support")]
mod scenario;
pub(crate) mod session;
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
    ACE, ACL, AccessAce, AccessCallbackAce, AccessMask, AccessObjectAce, AccessObjectCallbackAce,
    AceFlags, AceType, AceValue, AclRevision, Batch, BatchCommand, BatchOutcome, BatchRef,
    BatchResult, CancelToken, CloseOutcome,
    CloseReport, CredentialProvider, Credentials, Deadline, Directory, DirectoryEntries,
    DirectoryEntry, DirectoryEvent, DirectoryEvents, DirectoryOpenOptions, DirectoryWatchOptions,
    File, FileCursor, FileOpenOptions, IoCapabilities, MetadataOpenOptions, MetadataUpdate,
    ObjectGeneration, OpenInfo, OpenKind, Operation, Pipe, PipeName, PreviousVersion, ReplayPolicy,
    Resource, ResourceMetadata, RpcPipeConnection, SID, SecurityDescriptor, SecurityDescriptorControl,
    SecurityOpenOptions, SecuritySelection, Session, SessionInfo, Share, ShareInfo, SharePath, ShareTarget, Transfer,
    TransferEvents, TransferOptions, TransferProgress, TransferReport,
};
pub use error::Error;
pub use facade::{Client, ClientConfig, RemoteShare, ShareKind};

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
