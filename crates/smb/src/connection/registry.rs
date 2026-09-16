//! Short-critical-section connection registry.
//!
//! This state is domain bookkeeping, not a peer request authority. It owns no
//! task, mailbox, transport handle, credit, MessageId, pending request, or
//! lifecycle outcome. Callers take one bounded mutex only for in-memory map
//! operations and release it before any wire I/O.

use std::collections::HashMap;
use std::sync::{Arc, Weak};

use tokio::sync::Mutex;

use crate::lease::OplockSlot;
use crate::session::{ChannelContext, SessionContext};

#[derive(Debug, Clone, Copy)]
pub(crate) struct SessionGone;

#[derive(Default)]
struct RegistryState {
    sessions: HashMap<u64, Weak<SessionContext>>,
    oplocks: HashMap<(u64, u64), Weak<OplockSlot>>,
}

#[derive(Default)]
pub(crate) struct ConnectionRegistry {
    state: Mutex<RegistryState>,
}

impl ConnectionRegistry {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) async fn insert_oplock(&self, slot: &Arc<OplockSlot>) {
        self.state.lock().await.oplocks.insert(
            (slot.file_id().persistent, slot.file_id().volatile),
            Arc::downgrade(slot),
        );
    }

    pub(crate) async fn find_oplock(&self, file_id: smb_msg::FileId) -> Option<Arc<OplockSlot>> {
        let mut state = self.state.lock().await;
        let key = (file_id.persistent, file_id.volatile);
        let slot = state.oplocks.get(&key).and_then(Weak::upgrade);
        if slot.is_none() {
            state.oplocks.remove(&key);
        }
        slot
    }

    pub(crate) async fn insert_session(&self, session_id: u64, context: Weak<SessionContext>) {
        self.state.lock().await.sessions.insert(session_id, context);
    }

    pub(crate) async fn replace_session(
        &self,
        previous: u64,
        replacement: u64,
        context: Weak<SessionContext>,
    ) {
        let mut state = self.state.lock().await;
        state.sessions.remove(&previous);
        state.sessions.insert(replacement, context);
    }

    pub(crate) async fn recoverable_sessions(&self) -> Vec<Arc<SessionContext>> {
        let mut state = self.state.lock().await;
        state
            .sessions
            .retain(|_, context| context.strong_count() != 0);
        state.sessions.values().filter_map(Weak::upgrade).collect()
    }

    pub(crate) async fn get_session(
        &self,
        session_id: u64,
    ) -> Result<Option<Arc<ChannelContext>>, SessionGone> {
        match self.state.lock().await.sessions.get(&session_id) {
            None => Ok(None),
            Some(context) => context
                .upgrade()
                .map(|context| Some(context.primary_channel()))
                .ok_or(SessionGone),
        }
    }
}
