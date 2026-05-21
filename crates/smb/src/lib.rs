#![doc = include_str!("../docs/index.md")]
#![forbid(unsafe_code)]

pub mod client;
pub mod compression;
pub mod connection;
pub mod crypto;
pub mod dialects;
pub mod docs;
pub mod error;
pub mod lease;
pub mod msg_handler;
pub mod resource;
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
    pub use crate::session::gss::GssState;
}

pub use client::{Client, ClientConfig, UncPath};
pub use connection::{Connection, ConnectionConfig};
pub use error::Error;
pub use lease::LeaseBreakEvent;
pub use resource::{
    Directory, File, FileCreateArgs, GetLen, LeaseGrant, Pipe, PipeRpcConnection, ReadAt,
    ReadAtChannel, Resource, ResourceHandle, WriteAt, WriteAtChannel,
};
pub use session::Session;
pub use tree::{DfsRootTreeRef, Tree};

pub use smb_dtyp::*;
pub use smb_fscc::*;
pub use smb_msg::*;
pub use smb_transport as transport;

/// SMB Result type
pub type Result<T> = std::result::Result<T, crate::Error>;

// Re-exports of some dependencies for convenience
pub mod sync_helpers;
