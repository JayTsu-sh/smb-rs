//! Single-generation asynchronous request runtime.
//!
//! This module is the sole destination for request lifecycle authority.  The
//! reducer is deliberately independent of transport I/O so every race can be
//! checked deterministically before the owner task and pumps are connected.

#[allow(
    dead_code,
    reason = "deterministic fixture controls are wider than the production interface"
)]
mod engine;
#[allow(
    dead_code,
    reason = "deterministic lifecycle transitions are fixture-observable"
)]
mod object_state;
#[allow(
    dead_code,
    reason = "contract validation helpers are fixture-observable"
)]
mod operation;
pub(crate) mod port;
mod recovery;
#[allow(
    dead_code,
    reason = "deterministic recovery inspection is fixture-only"
)]
mod recovery_driver;
#[allow(
    dead_code,
    reason = "reducer observations are retained for deterministic assertions"
)]
mod reducer;
#[allow(
    dead_code,
    reason = "state observations are retained for deterministic assertions"
)]
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

mod metadata;
