//! Tokio re-exports gathered into a single import path.
//!
//! Originally this module abstracted over std::sync and tokio::sync to support
//! both async and sync builds (via the `maybe_async` macro). The sync build is
//! gone — this module is now a flat alias of tokio types kept for one-line
//! `use crate::sync_helpers::*;` ergonomics in callers.

pub use std::sync::{Arc, Weak};
pub use tokio::{
    select,
    sync::{AcquireError, Mutex, MutexGuard, OnceCell, RwLock, Semaphore, mpsc},
    task::JoinHandle,
};
pub use tokio_util::sync::CancellationToken;
