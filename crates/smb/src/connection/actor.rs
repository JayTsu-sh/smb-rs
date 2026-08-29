//! Connection-level state actor (S7).
//!
//! Owns the per-connection mutable `HashMap` state (sessions table and
//! lease cache) and serialises access to them through a command
//! mailbox. The motivating goal is to eliminate the
//! `Mutex<HashMap<...>>` + `_with_session` lock-dance patterns that
//! accumulated in `ConnectionMessageHandler`, replacing every shared
//! map with single-owner state behind a typed command interface.
//!
//! # S7 migration status
//!
//! This module is delivered in three steps:
//!
//! 1. **T1 (this commit)**: scaffolding only. The actor task is
//!    spawned by [`ConnectionMessageHandler::new`] and the handle is
//!    stored alongside the existing `Mutex<HashMap<...>>` fields. No
//!    caller dispatches through the actor yet, so the actor's
//!    `sessions` and `lease_table` stay empty. Existing mutex-backed
//!    methods remain authoritative.
//!
//! 2. **T2**: caller migration. Each `ConnectionMessageHandler`
//!    method that mutates an actor-owned field is rewritten to
//!    `dispatch` a [`ConnectionCommand`] instead of locking. As each
//!    method moves, the underlying mutex field becomes write-dead and
//!    is removed in the same commit.
//!
//! 3. **T3**: cleanup. With the last caller migrated, the residual
//!    mutex fields and helper paths (`_with_session`, etc.) are
//!    deleted, leaving the actor as the single source of truth.
//!
//! # Design notes
//!
//! - The actor's `run` loop processes commands serially in a single
//!   tokio task. Command handlers are synchronous: every state
//!   mutation in T1 is in-memory bookkeeping (no `.await`), so there
//!   is no danger of holding the mailbox while blocked on I/O.
//! - Each command carries a `oneshot::Sender<Reply>` for the actor to
//!   return a typed result. Callers that don't care about a reply
//!   still receive `()` so they can detect actor-shutdown races as
//!   `Error::ConnectionStopped`.
//! - The handle is `Clone` (it just wraps an `mpsc::Sender`). When
//!   every clone is dropped, the receiver returns `None` and the
//!   actor task exits gracefully.
//! - The actor does **not** own protocol sequencing, credit accounting,
//!   pending requests, transport I/O, or notification delivery. Those are
//!   generation-runtime responsibilities; this temporary actor only owns
//!   the lease/session maps pending their W3-6 migration.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Weak;
use std::time::Duration;
use std::time::Instant;

use smb_fscc::FileAccessMask;
use smb_msg::{CreateDisposition, LeaseState};
use tokio::sync::mpsc;
use tokio::sync::oneshot;

use super::LeaseEviction;
use crate::lease::LeaseSlot;
use crate::session::ChannelMessageHandler;

/// Capacity of the actor's command mailbox. A connection rarely has
/// more than a handful of concurrent state-mutating operations in
/// flight (session setup, lease cache hit, lease-break ack), so a
/// small bound keeps memory pressure low while leaving headroom that
/// callers don't backpressure each other under normal traffic.
const COMMAND_QUEUE_CAPACITY: usize = 64;

/// Commands accepted by [`ConnectionActor`]. Each variant carries a
/// `oneshot::Sender<Reply>` for the actor to return a typed result.
//
// `Debug` is intentionally not derived: the reply payloads (`LeaseSlot`,
// `LeaseEviction`, `ChannelMessageHandler`) don't implement `Debug` and
// commands aren't logged anyway — the actor traces individual outcomes
// inside `handle`.
pub(crate) enum ConnectionCommand {
    // ─── lease table ────────────────────────────────────────────────
    /// Insert (or replace) a slot keyed by `slot.path`. Returns the
    /// displaced slot — if any — so the caller can run the post-insert
    /// tombstone / wire-Close logic that today lives in
    /// `ConnectionMessageHandler::insert_lease_slot`.
    InsertLease {
        slot: Arc<LeaseSlot>,
        reply: oneshot::Sender<Option<Arc<LeaseSlot>>>,
    },
    /// Returns the number of slots currently cached.
    LeaseSlotCount { reply: oneshot::Sender<usize> },
    /// Returns a clone of the slot under `path`, if any.
    PeekLease {
        path: String,
        reply: oneshot::Sender<Option<Arc<LeaseSlot>>>,
    },
    /// Find the open that owns a server-supplied lease key. Lease-break
    /// acknowledgements must travel through that open's exact tree/session.
    FindLeaseByKey {
        lease_key: u128,
        reply: oneshot::Sender<Option<Arc<LeaseSlot>>>,
    },
    /// Atomically look up `path` and call `LeaseSlot::try_acquire_for_reuse`
    /// inside the actor's single-owner state. Replaces the old
    /// `lease_table.lock()` critical section that wrapped both
    /// operations.
    TryAcquireLease {
        path: String,
        requested_access: FileAccessMask,
        requested_disposition: CreateDisposition,
        wants_directory: bool,
        reply: oneshot::Sender<Option<Arc<LeaseSlot>>>,
    },
    /// Phase C.5 evict: remove the slot, tombstone it, and report
    /// whether the caller owes a wire Close (`needs_wire_close = true`
    /// iff `refcount == 0` at removal time).
    TakeLeaseForEvict {
        path: String,
        reply: oneshot::Sender<Option<LeaseEviction>>,
    },
    /// Phase C.5 idle sweep: tombstone + remove every slot whose
    /// `last_used` predates `Instant::now() - older_than`. Returns
    /// the list of evictions so the caller can flush wire Closes for
    /// slots that had zero refcount.
    SweepIdleLeases {
        older_than: Duration,
        reply: oneshot::Sender<Vec<LeaseEviction>>,
    },
    /// Apply a server-initiated lease break: remove every slot whose
    /// `lease_key` matches, tombstone it, and overwrite its cached
    /// `granted_state` with the server's new state. Returns the removed
    /// slots so the caller can emit per-slot tracing without iterating
    /// the table again. Unlike `TakeLeaseForEvict`, the caller does not
    /// owe a wire Close — the server has already revoked the FileId.
    ApplyLeaseBreak {
        lease_key: u128,
        new_state: LeaseState,
        reply: oneshot::Sender<Vec<Arc<LeaseSlot>>>,
    },

    // ─── sessions table ─────────────────────────────────────────────
    /// Insert a session's channel-handler weak reference. The actor
    /// keeps the weak so that dropped sessions can be garbage-collected
    /// on the next iteration that tries to upgrade them.
    InsertSession {
        session_id: u64,
        handler: Weak<ChannelMessageHandler>,
        reply: oneshot::Sender<()>,
    },
    /// Look up the channel handler for a specific `session_id` and try
    /// to upgrade its weak reference. Used by `notify()` to route a
    /// server response back to the session it belongs to. Returns:
    ///   - `Ok(Some(handler))` — session is known and still alive
    ///   - `Ok(None)` — session_id not in the table (unknown session)
    ///   - `Err(SessionGone)` — session was registered but its `Arc` has
    ///     since been dropped (caller surfaces this as `InvalidState`)
    GetSession {
        session_id: u64,
        reply: oneshot::Sender<Result<Option<Arc<ChannelMessageHandler>>, SessionGone>>,
    },
}

/// Sentinel returned by [`ConnectionCommand::GetSession`] when the
/// requested session was registered but every strong reference has been
/// dropped — i.e. the session ended without being explicitly removed
/// from the table. Distinguished from "unknown session_id" so the caller
/// can map it to [`crate::Error::InvalidState`] while a genuine cache
/// miss yields a warn-and-skip.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SessionGone;

/// Background task that serially owns the per-connection mutable
/// state. Constructed and spawned by [`Self::spawn`]; the returned
/// [`ConnectionActorHandle`] is the only way to talk to the running
/// task.
pub(crate) struct ConnectionActor {
    sessions: HashMap<u64, Weak<ChannelMessageHandler>>,
    lease_table: HashMap<String, Arc<LeaseSlot>>,
    rx: mpsc::Receiver<ConnectionCommand>,
}

/// Cheap, clonable handle to a [`ConnectionActor`]. Holds the send
/// half of the command mailbox; when every clone is dropped the
/// actor's `recv` returns `None` and the task exits gracefully.
#[derive(Clone, Debug)]
pub(crate) struct ConnectionActorHandle {
    tx: mpsc::Sender<ConnectionCommand>,
}

impl ConnectionActor {
    /// Spawn the actor task and return its handle.
    pub(crate) fn spawn() -> ConnectionActorHandle {
        let (tx, rx) = mpsc::channel(COMMAND_QUEUE_CAPACITY);
        let actor = Self {
            sessions: HashMap::with_capacity(1),
            lease_table: HashMap::new(),
            rx,
        };
        tokio::spawn(actor.run());
        ConnectionActorHandle { tx }
    }

    async fn run(mut self) {
        while let Some(cmd) = self.rx.recv().await {
            self.handle(cmd);
        }
        tracing::debug!("ConnectionActor exiting (all handles dropped)");
    }

    fn handle(&mut self, cmd: ConnectionCommand) {
        match cmd {
            ConnectionCommand::InsertLease { slot, reply } => {
                let key = slot.path.clone();
                let displaced = self.lease_table.insert(key, slot);
                let _ = reply.send(displaced);
            }
            ConnectionCommand::LeaseSlotCount { reply } => {
                let _ = reply.send(self.lease_table.len());
            }
            ConnectionCommand::PeekLease { path, reply } => {
                let _ = reply.send(self.lease_table.get(&path).cloned());
            }
            ConnectionCommand::FindLeaseByKey { lease_key, reply } => {
                let slot = self
                    .lease_table
                    .values()
                    .find(|slot| slot.lease_key == lease_key)
                    .cloned();
                let _ = reply.send(slot);
            }
            ConnectionCommand::TryAcquireLease {
                path,
                requested_access,
                requested_disposition,
                wants_directory,
                reply,
            } => {
                let result = self.lease_table.get(&path).cloned().and_then(|slot| {
                    if slot.try_acquire_for_reuse(
                        requested_access,
                        requested_disposition,
                        wants_directory,
                    ) {
                        Some(slot)
                    } else {
                        None
                    }
                });
                let _ = reply.send(result);
            }
            ConnectionCommand::TakeLeaseForEvict { path, reply } => {
                use std::sync::atomic::Ordering;
                let result = self.lease_table.remove(&path).map(|slot| {
                    slot.tombstoned.store(true, Ordering::Release);
                    let live = slot.refcount.load(Ordering::Acquire);
                    let needs_wire_close = live == 0;
                    tracing::debug!(
                        path = %slot.path,
                        live_handles = live,
                        needs_wire_close,
                        "Lease slot tombstoned and removed by actor",
                    );
                    LeaseEviction {
                        slot,
                        needs_wire_close,
                    }
                });
                let _ = reply.send(result);
            }
            ConnectionCommand::SweepIdleLeases { older_than, reply } => {
                use std::sync::atomic::Ordering;
                let cutoff = Instant::now().checked_sub(older_than);
                let result = match cutoff {
                    None => Vec::new(),
                    Some(cutoff) => {
                        // Two-phase to avoid mutating while iterating.
                        let victims: Vec<String> = self
                            .lease_table
                            .iter()
                            .filter_map(|(k, slot)| match slot.last_used.read() {
                                Ok(ts) if *ts <= cutoff => Some(k.clone()),
                                _ => None,
                            })
                            .collect();
                        let mut out = Vec::with_capacity(victims.len());
                        for path in victims {
                            if let Some(slot) = self.lease_table.remove(&path) {
                                slot.tombstoned.store(true, Ordering::Release);
                                let live = slot.refcount.load(Ordering::Acquire);
                                let needs_wire_close = live == 0;
                                tracing::debug!(
                                    path = %slot.path,
                                    live_handles = live,
                                    needs_wire_close,
                                    "Lease slot tombstoned by sweep (actor)",
                                );
                                out.push(LeaseEviction {
                                    slot,
                                    needs_wire_close,
                                });
                            }
                        }
                        out
                    }
                };
                let _ = reply.send(result);
            }
            ConnectionCommand::ApplyLeaseBreak {
                lease_key,
                new_state,
                reply,
            } => {
                use std::sync::atomic::Ordering;
                // Two-phase under the actor's single-owner lock so a
                // concurrent TryAcquireLease either runs strictly before
                // (and gets a still-valid slot whose wire I/O may racily
                // fail — recoverable) or strictly after (and finds the
                // slot gone, falling back to a fresh wire Create).
                let victim_paths: Vec<String> = self
                    .lease_table
                    .iter()
                    .filter(|(_, slot)| slot.lease_key == lease_key)
                    .map(|(k, _)| k.clone())
                    .collect();
                let removed: Vec<Arc<LeaseSlot>> = victim_paths
                    .into_iter()
                    .filter_map(|p| {
                        let slot = self.lease_table.remove(&p)?;
                        slot.tombstoned.store(true, Ordering::Release);
                        if let Ok(mut state) = slot.granted_state.write() {
                            *state = new_state;
                        }
                        Some(slot)
                    })
                    .collect();
                let _ = reply.send(removed);
            }
            ConnectionCommand::InsertSession {
                session_id,
                handler,
                reply,
            } => {
                self.sessions.insert(session_id, handler);
                let _ = reply.send(());
            }
            ConnectionCommand::GetSession { session_id, reply } => {
                let result = match self.sessions.get(&session_id) {
                    None => Ok(None),
                    Some(weak) => match weak.upgrade() {
                        Some(handler) => Ok(Some(handler)),
                        None => Err(SessionGone),
                    },
                };
                let _ = reply.send(result);
            }
        }
    }
}

impl ConnectionActorHandle {
    /// Send a command to the actor and await its reply. Returns
    /// [`crate::Error::ConnectionStopped`] when the actor has already
    /// shut down (e.g. the caller is racing against connection close)
    /// or when the actor task somehow dropped the reply channel.
    async fn dispatch<T>(
        &self,
        build: impl FnOnce(oneshot::Sender<T>) -> ConnectionCommand,
    ) -> crate::Result<T> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(build(reply))
            .await
            .map_err(|_| crate::Error::ConnectionStopped)?;
        rx.await.map_err(|_| crate::Error::ConnectionStopped)
    }

    pub(crate) async fn insert_lease(
        &self,
        slot: Arc<LeaseSlot>,
    ) -> crate::Result<Option<Arc<LeaseSlot>>> {
        self.dispatch(|reply| ConnectionCommand::InsertLease { slot, reply })
            .await
    }

    pub(crate) async fn lease_slot_count(&self) -> crate::Result<usize> {
        self.dispatch(|reply| ConnectionCommand::LeaseSlotCount { reply })
            .await
    }

    pub(crate) async fn peek_lease(&self, path: String) -> crate::Result<Option<Arc<LeaseSlot>>> {
        self.dispatch(|reply| ConnectionCommand::PeekLease { path, reply })
            .await
    }

    pub(crate) async fn find_lease_by_key(
        &self,
        lease_key: u128,
    ) -> crate::Result<Option<Arc<LeaseSlot>>> {
        self.dispatch(|reply| ConnectionCommand::FindLeaseByKey { lease_key, reply })
            .await
    }

    pub(crate) async fn try_acquire_lease(
        &self,
        path: String,
        requested_access: FileAccessMask,
        requested_disposition: CreateDisposition,
        wants_directory: bool,
    ) -> crate::Result<Option<Arc<LeaseSlot>>> {
        self.dispatch(|reply| ConnectionCommand::TryAcquireLease {
            path,
            requested_access,
            requested_disposition,
            wants_directory,
            reply,
        })
        .await
    }

    pub(crate) async fn take_lease_for_evict(
        &self,
        path: String,
    ) -> crate::Result<Option<LeaseEviction>> {
        self.dispatch(|reply| ConnectionCommand::TakeLeaseForEvict { path, reply })
            .await
    }

    pub(crate) async fn sweep_idle_leases(
        &self,
        older_than: Duration,
    ) -> crate::Result<Vec<LeaseEviction>> {
        self.dispatch(|reply| ConnectionCommand::SweepIdleLeases { older_than, reply })
            .await
    }

    pub(crate) async fn apply_lease_break(
        &self,
        lease_key: u128,
        new_state: LeaseState,
    ) -> crate::Result<Vec<Arc<LeaseSlot>>> {
        self.dispatch(|reply| ConnectionCommand::ApplyLeaseBreak {
            lease_key,
            new_state,
            reply,
        })
        .await
    }

    pub(crate) async fn insert_session(
        &self,
        session_id: u64,
        handler: Weak<ChannelMessageHandler>,
    ) -> crate::Result<()> {
        self.dispatch(|reply| ConnectionCommand::InsertSession {
            session_id,
            handler,
            reply,
        })
        .await
    }

    /// Look up `session_id` and upgrade its weak handler reference.
    /// The outer `Result` reports actor-channel health (Err = actor
    /// has shut down); the inner `Result` distinguishes unknown
    /// session (`Ok(None)`) from a known-but-dropped session
    /// (`Err(SessionGone)`).
    pub(crate) async fn get_session(
        &self,
        session_id: u64,
    ) -> crate::Result<Result<Option<Arc<ChannelMessageHandler>>, SessionGone>> {
        self.dispatch(|reply| ConnectionCommand::GetSession { session_id, reply })
            .await
    }
}
