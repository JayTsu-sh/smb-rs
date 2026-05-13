//! Client-side SMB lease lifecycle events and cache.
//!
//! Phase A wired up the *request + grant* side of SMB Handle Lease via
//! [`crate::FileCreateArgs::lease_request`] and [`crate::LeaseGrant`].
//! Phase B added the *break* side: the server can, at any time, notify the
//! client that a previously-granted lease is being revoked or downgraded
//! (MS-SMB2 2.2.23.2). This module exposes [`LeaseBreakEvent`] mirroring the
//! on-wire `LeaseBreakNotify` plus a timestamp.
//!
//! Phase C introduces the [`LeaseSlot`] cache: when the server grants a
//! lease, the connection holds onto the FileId so subsequent Opens against
//! the same path can be served from cache (skipping the Create RT). The
//! actual `Close` is deferred until either (a) the last live reference
//! drops *and* the slot has been tombstoned, or (b) an explicit eviction
//! runs (e.g. before `delete` or `rename`).

use smb_dtyp::Guid;
use smb_msg::{FileId, LeaseState};
use std::sync::RwLock;
use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::time::Instant;

/// A single lease-break notification received from the server, normalized
/// into a `Copy`-cheap form for fan-out across subscribers.
///
/// The client-side reaction is two-step:
/// 1. Receive the [`LeaseBreakEvent`] (this struct) and start invalidating
///    any cached state keyed on `lease_key`.
/// 2. Send a `LeaseBreakAck` back to the server within the 35-second timeout.
///    Phase B sends the ack automatically before publishing the event; Phase C
///    will additionally drive any deferred `Close` for the affected handle.
///
/// Reference: MS-SMB2 2.2.23.2 (LeaseBreakNotification).
#[derive(Debug, Clone, Copy)]
pub struct LeaseBreakEvent {
    /// Client-generated key that identifies the lease being broken. Matches
    /// the value the client originally placed in `RequestLease.lease_key`.
    pub lease_key: Guid,
    /// The lease state the client currently holds, per the server's view.
    /// In normal operation this matches what the server most recently
    /// granted; a divergence usually means concurrent break notifications.
    pub current_state: LeaseState,
    /// The lease state the server wants to downgrade to. Often `0` (full
    /// revocation), occasionally a subset (e.g., losing `write_caching`
    /// while keeping `read_caching`).
    pub new_state: LeaseState,
    /// Epoch value used to track lease-state changes for v2 leases.
    /// Zero for v1 leases (SMB 2.1) or when the server isn't tracking
    /// epochs for this open.
    pub epoch: u16,
    /// `true` when the server expects a `LeaseBreakAck` reply within the
    /// 35-second timeout. `false` indicates the server is just informing
    /// us of an unconditional downgrade; no reply is required.
    pub ack_required: bool,
    /// Wall-clock instant the client received the notification, used for
    /// observability and to drive ack-timeout backstops in Phase C.
    pub received_at: Instant,
}

/// A cached, lease-protected open. Owned by the
/// connection's `lease_table`; multiple [`crate::ResourceHandle`] instances
/// may share an `Arc<LeaseSlot>` and operate on the same server-side
/// `FileId`. The actual `Close` is deferred until both:
///
/// 1. The slot's `refcount` drops to zero — no live handle references it.
/// 2. The slot is `tombstoned` — either by a server-side
///    `LeaseBreakNotify` that dropped enough caching bits, or by an
///    explicit `Client::evict_lease` call before a destructive op.
///
/// Until both conditions are met, the FileId stays live on the server and
/// new Opens against the same path hit the cache for free.
///
/// Phase C lays down the type and the insert path; cache hits, deferred
/// close, and break-driven tombstoning land in later micro-steps of the
/// same phase.
pub struct LeaseSlot {
    /// The file path (relative to the share root) the lease was opened
    /// against. Used as the lookup key inside the per-connection table
    /// and for diagnostic logs.
    pub path: String,
    /// Tree the original Create was issued on. Future cache hits must
    /// reuse the same tree so per-tree access permissions match.
    pub tree_id: u32,
    /// Server-assigned FileId for the open. Cached hits reuse this FileId
    /// on every operation; the wire `Close` is only sent when the slot is
    /// destroyed.
    pub file_id: FileId,
    /// Client-generated lease key, normalized to u128 so it can be
    /// matched against [`LeaseBreakEvent::lease_key`] via [`Guid::as_u128`].
    pub lease_key: u128,
    /// Current granted lease state. The break-listener task downgrades
    /// this under `write` when the server's `LeaseBreakNotify` says so.
    pub granted_state: RwLock<LeaseState>,
    /// Number of live [`crate::ResourceHandle`] clones referencing this
    /// slot. The wire `Close` is deferred until this hits zero *and* the
    /// slot is tombstoned.
    pub refcount: AtomicUsize,
    /// `true` once the lease is no longer eligible for new cache hits —
    /// either a server break dropped caching bits, or the caller
    /// explicitly evicted. The next `refcount == 0` transition triggers
    /// the real `Close`.
    pub tombstoned: AtomicBool,
    /// Last time the slot was created or hit. Used by
    /// `flush_idle_leases(Duration)` to evict slots whose lease the
    /// server may have silently dropped on its side.
    pub last_used: RwLock<Instant>,
}

impl LeaseSlot {
    /// Construct a new slot from a successful Create response. Initial
    /// refcount is `1` (the caller's handle), not tombstoned.
    pub fn new(
        path: String,
        tree_id: u32,
        file_id: FileId,
        lease_key: u128,
        granted_state: LeaseState,
    ) -> Self {
        Self {
            path,
            tree_id,
            file_id,
            lease_key,
            granted_state: RwLock::new(granted_state),
            refcount: AtomicUsize::new(1),
            tombstoned: AtomicBool::new(false),
            last_used: RwLock::new(Instant::now()),
        }
    }
}
