use smb_dtyp::Guid;
use smb_msg::LeaseState;

use crate::ConnectionConfig;

/// Configuration for the SMB client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientConfig {
    /// Whether to enable DFS (Distributed File System) resolution for the client.
    /// This includes resolving DFS referrals and accessing DFS namespaces.
    ///
    /// - If this is set to `false`, the client might return [`Status::PathNotCovered`][smb_msg::Status::PathNotCovered] errors
    ///   when trying to access DFS paths, instead of automatically resolving them.
    pub dfs: bool,

    /// Configuration related to the SMB connections made by the client.
    /// See [`ConnectionConfig`] for more details.
    pub connection: ConnectionConfig,

    pub client_guid: Guid,

    /// Default lease state to request on every `create_file` call that
    /// doesn't already carry a `FileCreateArgs::lease_request`. `None`
    /// (default) keeps the legacy "no lease" behavior on a per-call
    /// basis; setting `Some(LeaseState::new().with_read_caching(true).with_handle_caching(true))`
    /// makes the client opportunistically request a HandleCaching lease
    /// for every open so the per-connection lease cache (Phase C) can
    /// dedupe subsequent opens against the same path.
    ///
    /// The lease key for each path is derived deterministically from
    /// the [`crate::UncPath`] string and the client's `lease_key_salt`,
    /// so:
    ///   * within one Client, repeat opens of the same path use the
    ///     same lease key — the server reuses the lease,
    ///   * across two Client instances on the same machine, the salt
    ///     differs so lease keys differ — the server treats them as
    ///     two independent clients, no cross-talk.
    ///
    /// Servers without leasing capability silently ignore the request
    /// context, so this is safe to enable by default on capable clients.
    pub default_lease_state: Option<LeaseState>,

    /// Random 64-bit salt mixed into every auto-generated lease key
    /// (see [`Self::default_lease_state`]). Initialized to a fresh
    /// random value on `Default::default()`. Two Client instances see
    /// different salts so they don't accidentally share lease state on
    /// the server side.
    pub lease_key_salt: u64,

    #[cfg(feature = "rdma")]
    pub rdma_type: Option<crate::transport::RdmaType>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            dfs: true,
            connection: ConnectionConfig::default(),
            client_guid: Guid::generate(),
            default_lease_state: None,
            lease_key_salt: rand::random(),
            #[cfg(feature = "rdma")]
            rdma_type: None,
        }
    }
}
