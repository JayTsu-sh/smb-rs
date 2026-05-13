//! Client-side SMB lease lifecycle events.
//!
//! Phase A wired up the *request + grant* side of SMB Handle Lease via
//! [`crate::FileCreateArgs::lease_request`] and [`crate::LeaseGrant`].
//! Phase B (this module) adds the *break* side: the server can, at any time,
//! notify the client that a previously-granted lease is being revoked or
//! downgraded (MS-SMB2 2.2.23.2). The client must reply with a
//! `LeaseBreakAck` within roughly 35 seconds, or the server will revoke the
//! lease unilaterally.
//!
//! This module exposes a [`LeaseBreakEvent`] type that mirrors the on-wire
//! `LeaseBreakNotify` plus a timestamp, and a broadcast channel on
//! [`crate::Client`] (via `Client::subscribe_lease_breaks`) so higher layers
//! (Phase C `lease_table`, Phase D `cifs.rs::handle_cache`) can react to
//! invalidations.

use smb_dtyp::Guid;
use smb_msg::LeaseState;
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
