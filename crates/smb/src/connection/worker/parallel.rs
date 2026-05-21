//! This module contains the implementation for the async worker.
//!
//! The effective backend is exported as [ParallelWorker] from this module.

pub mod backend_trait;
pub mod base;

pub mod async_backend;
use async_backend::AsyncBackend as Backend;

pub type ParallelWorker = base::ParallelWorker<Backend>;
