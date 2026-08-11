//! Composition, lockfile, orchestration, and CLI boundary for nrr.
//!
//! This crate must not move domain, provider, resolver, or repository
//! implementation into the binary beyond composition responsibilities.

pub mod manifest;
pub mod orchestration;

pub use manifest::{
    Manifest, ManifestDependency, ManifestError, ManifestTarget, compose_resolution_request,
    compose_resolution_request_with_locked,
};
pub use orchestration::{
    CranResolutionError, CranResolutionOutcome, resolve_from_cran, resolve_with_loader,
};
