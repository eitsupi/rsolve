//! Composition, lockfile, orchestration, and CLI boundary for rsolve.
//!
//! This crate must not move domain, provider, resolver, or repository
//! implementation into the binary beyond composition responsibilities.

pub mod cli;
pub(crate) mod filesystem;
pub mod lock;
pub mod manifest;
pub(crate) mod metadata_cache;
pub mod metrics;
pub mod orchestration;
pub mod pak;
mod prepared_snapshot;
pub mod progress;
pub mod wire;

pub use lock::{
    ConsumedLockedGraph, EnvironmentId, EnvironmentIdError, LockError, LockedPackage,
    LockedResolution, Lockfile, consume_locked_graph,
};
pub use manifest::{
    DirectUrl, EffectiveRepository, Endpoint, GitSelector, Manifest, ManifestDependency,
    ManifestDependencySpec, ManifestDocument, ManifestError, ManifestSource, ManifestTarget,
    RegistryProvenancePolicy, RegistrySpec, RepositorySpec, compose_resolution_request,
    compose_resolution_request_with_locked, discover_manifest, load_manifest, parse_manifest,
    read_manifest,
};
pub use orchestration::{
    CranResolutionError, CranResolutionOutcome, LockResolutionPolicy, resolve_from_cran,
    resolve_from_cran_with_publication_cutoff, resolve_with_loader,
    resolve_with_loader_with_publication_cutoff, resolve_with_lock_policy,
};
pub use pak::{
    PakArtifact, PakInstallRequest, PakInstallResult, PakInstalledPackage, PakProcessConfig,
    PakProcessError, run_pak,
};
pub use wire::{LockWireError, from_toml, to_toml};
