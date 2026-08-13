//! Composition, lockfile, orchestration, and CLI boundary for nrr.
//!
//! This crate must not move domain, provider, resolver, or repository
//! implementation into the binary beyond composition responsibilities.

pub mod lock;
pub mod manifest;
pub mod orchestration;
pub mod pak;
pub mod wire;

pub use lock::{
    EnvironmentId, EnvironmentIdError, LockError, LockedDependencyEdge, LockedDistributionRef,
    LockedPackage, LockedResolution, Lockfile,
};
pub use manifest::{
    Manifest, ManifestDependency, ManifestError, ManifestTarget, compose_resolution_request,
    compose_resolution_request_with_locked,
};
pub use orchestration::{
    CranResolutionError, CranResolutionOutcome, ResolutionMode, resolve_from_cran,
    resolve_with_loader, resolve_with_lock,
};
pub use pak::{
    PakArtifact, PakInstallRequest, PakInstallResult, PakInstalledPackage, PakProcessConfig,
    PakProcessError, run_pak,
};
pub use wire::{LockWireError, from_toml, to_toml};
