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

use crate::connection::connection_info::ConnectionInfo;
use crate::msg_handler::HandlerReference;
use crate::resource::ResourceMessageHandle;
use smb_dtyp::Guid;
use smb_fscc::FileAccessMask;
use smb_msg::{CreateDisposition, FileId, LeaseState, ShareType};
use std::sync::Arc;
use std::sync::RwLock;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Instant;
use time::PrimitiveDateTime;

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

/// Internal handler/conn-info prototype captured at slot-insert time so a
/// later cache hit can construct a fresh [`crate::ResourceHandle`] sharing
/// the same FileId without re-issuing Create. Held inside [`LeaseSlot`]
/// behind an `Arc` so cloning is cheap and stable across hits.
pub(crate) struct ResourceProto {
    /// Shared handler chain — `Arc`-backed under the hood, so cloning into
    /// a new ResourceHandle on hit is just a refcount bump.
    pub handler: HandlerReference<ResourceMessageHandle>,
    /// Snapshot of the connection's negotiated info at create time; the
    /// same instance every resulting ResourceHandle reads from. Cheap to
    /// clone (Arc).
    pub conn_info: Arc<ConnectionInfo>,
    /// Server's reported created time at the moment of the original
    /// Create. We surface this on cache-hit handles unchanged — the
    /// HandleCaching lease guarantees no one else changed the file.
    pub created: PrimitiveDateTime,
    /// Server's last-modified time at the moment of the original Create,
    /// surfaced unchanged on cache hits for the same reason as `created`.
    pub modified: PrimitiveDateTime,
    /// Share type of the originating Create (Disk / Pipe). Used to
    /// reconstruct the right `Resource::{File,Directory,Pipe}` variant.
    pub share_type: ShareType,
    /// File size at the moment of the original Create. Surfaced on hit;
    /// the lease covers data state, so this remains accurate as long as
    /// the lease isn't tombstoned.
    pub endof_file: u64,
    /// Whether the original Create returned a directory. Cache hits must
    /// match the requested kind (`CreateOptions::directory_file()`).
    pub is_dir: bool,
    /// Granted access at the moment of the original Create, as expanded
    /// by the server in the Maximal-Access response context. Surfaced
    /// unchanged on cache-hit handles so callers see the same `access()`
    /// before vs. after caching.
    pub access: FileAccessMask,
    /// User-requested access mask from `FileCreateArgs::desired_access`
    /// at original-Create time, *before* server expansion. Cache-hit
    /// eligibility compares the *new* request against this so that the
    /// generic-vs-specific bit mismatch (the server expands `generic_*`
    /// into specific bits when filling Maximal-Access) doesn't cause a
    /// spurious miss when the caller repeats the same logical request.
    pub requested_access: FileAccessMask,
    /// Lease epoch reported by the server at grant time. Stored only for
    /// diagnostics; the lease lifecycle is keyed on `lease_key`, not epoch.
    pub epoch_at_grant: u16,
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
    /// Reconstruction snapshot (Phase C.3): everything a cache hit needs
    /// to materialize a fresh `ResourceHandle` without sending Create on
    /// the wire. `pub(crate)` because it references internal handler
    /// types; external callers don't need direct access.
    pub(crate) proto: Arc<ResourceProto>,
}

impl LeaseSlot {
    /// Construct a new slot from a successful Create response, capturing
    /// both the lease identity (key/state/file_id) and a [`ResourceProto`]
    /// snapshot for future cache-hit reconstruction. Initial refcount is
    /// `1` (the caller's handle that triggered the Create), not tombstoned.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_with_proto(
        path: String,
        tree_id: u32,
        file_id: FileId,
        lease_key: u128,
        granted_state: LeaseState,
        proto: Arc<ResourceProto>,
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
            proto,
        }
    }

    /// Phase C.3: attempt to satisfy the caller's `args` from this cached
    /// slot. Returns `true` (with `refcount` already incremented) when the
    /// caller may skip the wire Create and reuse the slot's `FileId`.
    /// Returns `false` (no side effects) otherwise.
    ///
    /// The bar for a hit is intentionally strict so we never silently mask
    /// a real semantic difference between requests:
    /// * Disposition must be `Open` — anything that may overwrite, supersede
    ///   or create-if-missing has to hit the wire.
    /// * The slot's lease must still have `HandleCaching` — that's the bit
    ///   that lets the client treat the FileId as durable across app-level
    ///   close (MS-SMB2 2.2.13.2.10).
    /// * The slot must not be tombstoned (no in-flight break revoking it).
    /// * Directory-vs-file kind must match the caller's expectation.
    /// * Requested access must be a subset of the slot's granted access.
    ///
    /// Note on access: we compare the requested bits as a subset of the
    /// snapshot's granted bits. This is conservative — a server that
    /// expanded `generic_read` into specific bits at first Create will
    /// snapshot the expanded mask; matching the same `generic_read`
    /// request will pass that subset check.
    pub(crate) fn try_acquire_for_reuse(
        &self,
        requested_access: FileAccessMask,
        requested_disposition: CreateDisposition,
        wants_directory: bool,
    ) -> bool {
        if requested_disposition != CreateDisposition::Open {
            return false;
        }
        if self.tombstoned.load(Ordering::Acquire) {
            return false;
        }
        if wants_directory != self.proto.is_dir {
            return false;
        }

        // HandleCaching is the wire-level promise that lets us defer the
        // Close. Without it, the server may have already released the
        // FileId on its side after our last close call.
        let state = match self.granted_state.read() {
            Ok(s) => *s,
            Err(_) => return false,
        };
        if !state.handle_caching() {
            return false;
        }

        // Access subset check: the *new* request's bits must be a subset
        // of the bits *the original Create requested*. Comparing against
        // the server's Maximal-Access response would mis-fire because
        // the server expands `generic_*` into specific bits, so a
        // user-level `generic_read` request would look "smaller" than
        // its own expansion and miss. Tracking `proto.requested_access`
        // separately keeps the apples-to-apples comparison.
        let req = u32::from_le_bytes(requested_access.into_bytes());
        let cached_req = u32::from_le_bytes(self.proto.requested_access.into_bytes());
        if (req & !cached_req) != 0 {
            return false;
        }

        // All gates passed: mark the slot as freshly used and bump the
        // refcount under Acquire/Release so the deferred-close path in
        // `Resource::Drop` observes our increment.
        self.refcount.fetch_add(1, Ordering::AcqRel);
        if let Ok(mut last) = self.last_used.write() {
            *last = Instant::now();
        }
        true
    }

    /// Phase C.4: decrement the refcount on close/drop. Returns
    /// [`SlotReleaseAction::CloseAndEvict`] when this caller was the
    /// last live reference *and* the slot is tombstoned — at which point
    /// the caller must send the deferred wire `Close` and remove the
    /// slot from the per-connection table. In all other cases returns
    /// [`SlotReleaseAction::KeepCached`] and the slot stays in the
    /// table for future hits.
    pub(crate) fn release_one(&self) -> SlotReleaseAction {
        let prev = self.refcount.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(prev > 0, "lease slot refcount underflow");
        if prev == 1 && self.tombstoned.load(Ordering::Acquire) {
            SlotReleaseAction::CloseAndEvict
        } else {
            SlotReleaseAction::KeepCached
        }
    }
}

/// Outcome of [`LeaseSlot::release_one`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SlotReleaseAction {
    /// Slot stays in the cache; either there are still live references
    /// or the slot has not been tombstoned and can serve future hits.
    KeepCached,
    /// Last live reference dropped and the slot is tombstoned — the
    /// caller is responsible for sending the wire `Close` and removing
    /// the entry from the connection's `lease_table`.
    CloseAndEvict,
}
