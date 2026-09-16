//! Client-side oplock bookkeeping.
//!
//! The runtime requests batch/level-II oplocks on opens it recovers across
//! reconnects; [`OplockSlot`] tracks the current level and the object token so
//! server-initiated `OplockBreakNotify` messages can be acknowledged. Handle
//! leases are not requested by this client, so lease breaks are only logged.

use crate::tree::TreeContext;
use smb_msg::{FileId, OplockLevel};
use std::sync::Arc;
use std::sync::RwLock;

pub(crate) struct OplockSlot {
    generation: arc_swap::ArcSwap<OplockGeneration>,
    pub(crate) level: RwLock<OplockLevel>,
    pub(crate) context: Arc<TreeContext>,
}

struct OplockGeneration {
    file_id: FileId,
    object: crate::runtime::ObjectToken,
}

impl OplockSlot {
    pub(crate) fn new(
        file_id: FileId,
        level: OplockLevel,
        context: Arc<TreeContext>,
        object: crate::runtime::ObjectToken,
    ) -> Self {
        Self {
            generation: arc_swap::ArcSwap::from_pointee(OplockGeneration { file_id, object }),
            level: RwLock::new(level),
            context,
        }
    }

    pub(crate) fn file_id(&self) -> FileId {
        self.generation.load().file_id
    }

    pub(crate) fn object(&self) -> crate::runtime::ObjectToken {
        self.generation.load().object
    }

    pub(crate) fn replace(&self, file_id: FileId, object: crate::runtime::ObjectToken) {
        self.generation
            .store(Arc::new(OplockGeneration { file_id, object }));
    }
}
