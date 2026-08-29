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
// W4-1 lands the complete hierarchy reducer before each domain object is cut
// over; the allowance is removed when the final object kind is wired.
#[allow(dead_code)]
mod object_state;
// W4-2 starts with a pure reconnect coordinator reducer before transport
// construction is moved behind it.
#[allow(dead_code)]
mod recovery;
#[allow(dead_code)]
mod recovery_driver;
// W4-3 starts with the pure Session reauthentication authority before its
// async coordinator is connected to generation publication.
#[allow(dead_code)]
mod session_recovery;
// W4-4 starts with the pure Share TreeConnect replay authority.
#[allow(dead_code)]
mod share_recovery;
// W4-5 starts with the pure durable/persistent Resource reconnect authority.
#[allow(dead_code)]
mod durable_recovery;
#[allow(dead_code)]
mod reducer;
#[allow(dead_code)]
mod state;
pub(crate) mod wire;

pub(crate) use engine::{
    GenerationExit, RuntimeConfig, RuntimeError, RuntimeHandle, start_generation,
};
pub(crate) use operation::{OperationResult, ResponsePolicy, TypedOperation};
pub(crate) use object_state::{ObjectKind, ObjectToken};
pub(crate) use recovery::RecoveryPolicy;
pub(crate) use recovery_driver::{
    GenerationBootstrap, GenerationPublication, PreparedGeneration, RandomRecoveryJitter,
    RecoveryDriver, RecoveryError,
};
pub(crate) use reducer::{GenerationId, RequestKey, TerminalOutcome};
