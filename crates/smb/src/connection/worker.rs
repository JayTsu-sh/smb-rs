pub mod worker_trait;
pub use worker_trait::*;

mod parallel;
pub use parallel::ParallelWorker as WorkerImpl;
