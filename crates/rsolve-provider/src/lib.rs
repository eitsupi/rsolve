//! External registry and provider access adapters for rsolve.
//!
//! This crate must not contain resolver policy, repository materialization, or
//! CLI orchestration.

pub mod cran;
pub(crate) mod snapshot;

pub use snapshot::ReadOnlySnapshotCandidateLoader;
