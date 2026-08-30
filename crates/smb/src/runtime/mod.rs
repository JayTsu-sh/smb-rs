//! Single-generation asynchronous request runtime.
//!
//! This module is the sole destination for request lifecycle authority.  The
//! reducer is deliberately independent of transport I/O so every race can be
//! checked deterministically before the owner task and pumps are connected.

mod engine;
mod object_state;
mod operation;
pub(crate) mod port;
mod recovery;
mod recovery_driver;
mod reducer;
mod state;
pub(crate) mod wire;

pub(crate) use engine::{
    GenerationExit, RuntimeConfig, RuntimeError, RuntimeHandle, start_generation,
};
#[cfg(test)]
pub(crate) use object_state::{ObjectEffect, ObjectRegistry};
pub(crate) use object_state::{ObjectKind, ObjectToken};
pub(crate) use operation::{OperationResult, ReplayPolicy, ResponsePolicy, TypedOperation};
pub(crate) use recovery::RecoveryPolicy;
pub(crate) use recovery_driver::{
    GenerationBootstrap, GenerationPublication, PreparedGeneration, RandomRecoveryJitter,
    RecoveryDriver, RecoveryError,
};
pub(crate) use reducer::{GenerationId, RequestKey, TerminalOutcome};
