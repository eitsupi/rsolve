//! Composition, lockfile, orchestration, and CLI boundary for nrr.
//!
//! This crate must not move domain, provider, resolver, or repository
//! implementation into the binary beyond composition responsibilities.

pub mod manifest;

pub use manifest::{
    Manifest, ManifestDependency, ManifestError, ManifestTarget, compose_resolution_request,
    compose_resolution_request_with_locked,
};
