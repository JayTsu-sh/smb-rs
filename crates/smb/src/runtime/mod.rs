//! Single-generation asynchronous request runtime.
//!
//! This module is the sole destination for request lifecycle authority.  The
//! reducer is deliberately independent of transport I/O so every race can be
//! checked deterministically before the owner task and pumps are connected.

// The next W3 slice wires these types into the owner task. Keeping the
// transition-local allowance here avoids weakening warnings crate-wide.
#[allow(dead_code)]
mod engine;
// Activated by W3-5 as the bootstrap path is cut over incrementally.
#[allow(dead_code)]
mod operation;
#[allow(dead_code)]
mod reducer;
#[allow(dead_code)]
mod state;
pub(crate) mod wire;
