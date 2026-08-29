//! Short-critical-section connection registry.
//!
//! This state is domain bookkeeping, not a peer request authority. It owns no
//! task, mailbox, transport handle, credit, MessageId, pending request, or
//! lifecycle outcome. Callers take one bounded mutex only for in-memory map
//! operations and release it before any wire I/O.

use std::collections::HashMap;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use smb_fscc::FileAccessMask;
use smb_msg::{CreateDisposition, LeaseState};
use tokio::sync::Mutex;

use super::LeaseEviction;
use crate::lease::LeaseSlot;
use crate::session::ChannelMessageHandler;

#[derive(Debug, Clone, Copy)]
pub(crate) struct SessionGone;

#[derive(Default)]
struct RegistryState {
    sessions: HashMap<u64, Weak<ChannelMessageHandler>>,
    leases: HashMap<String, Arc<LeaseSlot>>,
}

#[derive(Default)]
pub(crate) struct ConnectionRegistry {
    state: Mutex<RegistryState>,
}

impl ConnectionRegistry {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) async fn insert_lease(&self, slot: Arc<LeaseSlot>) -> Option<Arc<LeaseSlot>> {
        self.state.lock().await.leases.insert(slot.path.clone(), slot)
    }

    pub(crate) async fn lease_slot_count(&self) -> usize {
        self.state.lock().await.leases.len()
    }

    pub(crate) async fn peek_lease(&self, path: &str) -> Option<Arc<LeaseSlot>> {
        self.state.lock().await.leases.get(path).cloned()
    }

    pub(crate) async fn find_lease_by_key(&self, lease_key: u128) -> Option<Arc<LeaseSlot>> {
        self.state
            .lock()
            .await
            .leases
            .values()
            .find(|slot| slot.lease_key == lease_key)
            .cloned()
    }

    pub(crate) async fn try_acquire_lease(
        &self,
        path: &str,
        requested_access: FileAccessMask,
        requested_disposition: CreateDisposition,
        wants_directory: bool,
    ) -> Option<Arc<LeaseSlot>> {
        self.state
            .lock()
            .await
            .leases
            .get(path)
            .cloned()
            .filter(|slot| {
                slot.try_acquire_for_reuse(
                    requested_access,
                    requested_disposition,
                    wants_directory,
                )
            })
    }

    pub(crate) async fn take_lease_for_evict(&self, path: &str) -> Option<LeaseEviction> {
        use std::sync::atomic::Ordering;
        self.state.lock().await.leases.remove(path).map(|slot| {
            slot.tombstoned.store(true, Ordering::Release);
            let live = slot.refcount.load(Ordering::Acquire);
            LeaseEviction {
                slot,
                needs_wire_close: live == 0,
            }
        })
    }

    pub(crate) async fn sweep_idle_leases(&self, older_than: Duration) -> Vec<LeaseEviction> {
        use std::sync::atomic::Ordering;
        let Some(cutoff) = Instant::now().checked_sub(older_than) else {
            return Vec::new();
        };
        let mut state = self.state.lock().await;
        let victims = state
            .leases
            .iter()
            .filter_map(|(path, slot)| match slot.last_used.read() {
                Ok(last_used) if *last_used <= cutoff => Some(path.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();
        victims
            .into_iter()
            .filter_map(|path| state.leases.remove(&path))
            .map(|slot| {
                slot.tombstoned.store(true, Ordering::Release);
                let live = slot.refcount.load(Ordering::Acquire);
                LeaseEviction {
                    slot,
                    needs_wire_close: live == 0,
                }
            })
            .collect()
    }

    pub(crate) async fn apply_lease_break(
        &self,
        lease_key: u128,
        new_state: LeaseState,
    ) -> Vec<Arc<LeaseSlot>> {
        use std::sync::atomic::Ordering;
        let mut state = self.state.lock().await;
        let victims = state
            .leases
            .iter()
            .filter(|(_, slot)| slot.lease_key == lease_key)
            .map(|(path, _)| path.clone())
            .collect::<Vec<_>>();
        victims
            .into_iter()
            .filter_map(|path| state.leases.remove(&path))
            .inspect(|slot| {
                slot.tombstoned.store(true, Ordering::Release);
                if let Ok(mut granted) = slot.granted_state.write() {
                    *granted = new_state;
                }
            })
            .collect()
    }

    pub(crate) async fn insert_session(
        &self,
        session_id: u64,
        handler: Weak<ChannelMessageHandler>,
    ) {
        self.state.lock().await.sessions.insert(session_id, handler);
    }

    pub(crate) async fn get_session(
        &self,
        session_id: u64,
    ) -> Result<Option<Arc<ChannelMessageHandler>>, SessionGone> {
        match self.state.lock().await.sessions.get(&session_id) {
            None => Ok(None),
            Some(handler) => handler.upgrade().map(Some).ok_or(SessionGone),
        }
    }
}
