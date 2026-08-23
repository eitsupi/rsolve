use std::collections::{BTreeSet, HashSet};
use std::error::Error;
use std::fmt;

use rsolve_core::{
    CandidateLoadError, CandidateLoader, PackageRelease, PublicationCutoff, PublicationDate,
    Resolution, SolverKey,
};
use rsolve_provider::cran::{
    CranRefreshDiagnostic, CranSnapshotPublishError, CranSnapshotRefresherError,
};
use rsolve_provider::{SnapshotStore, SnapshotStoreError};
use rsolve_resolver::{
    DefaultCandidatePreference, PreferLocked, RBasePackageOverlay, RequireLocked,
    ResolutionFailure, Resolver, Unlocked,
};

use crate::lock::{ConsumedLockedGraph, EnvironmentId, LockError, Lockfile, identity_key};
use crate::manifest::{Manifest, ManifestError, compose_resolution_request};
use std::io;
use tempfile::tempdir;

#[cfg(test)]
pub(crate) use crate::prepared_snapshot::collect_cran_dependency_closure;
pub(crate) use crate::prepared_snapshot::{
    cran_registry_id, resolve_from_cran_offline_with_store, resolve_from_cran_with_store,
};

pub(super) struct CandidateLoaderRef<'a>(pub(super) &'a dyn CandidateLoader);

impl CandidateLoader for CandidateLoaderRef<'_> {
    fn releases(&self, package: &SolverKey) -> Result<Vec<PackageRelease>, CandidateLoadError> {
        self.0.releases(package)
    }
}

/// The failure stage of a CRAN-backed resolution orchestration.
#[derive(Debug)]
pub enum CranResolutionError {
    Composition(ManifestError),
    Lock(LockError),
    Provider(CranSnapshotRefresherError),
    Store(SnapshotStoreError),
    TemporaryStore(io::Error),
    Refresh(CandidateLoadError),
    Offline(CandidateLoadError),
    Publish(CranSnapshotPublishError),
    Resolution(ResolutionFailure),
}

impl fmt::Display for CranResolutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Composition(error) => write!(formatter, "manifest composition failed: {error}"),
            Self::Lock(error) => write!(formatter, "lock projection failed: {error}"),
            Self::Provider(error) => {
                write!(formatter, "CRAN provider construction failed: {error}")
            }
            Self::Store(error) => write!(formatter, "CRAN snapshot store failed: {error}"),
            Self::TemporaryStore(error) => {
                write!(formatter, "temporary CRAN snapshot store failed: {error}")
            }
            Self::Refresh(error) => write!(formatter, "CRAN refresh failed: {error}"),
            Self::Offline(error) => write!(formatter, "offline CRAN snapshot failed: {error}"),
            Self::Publish(error) => write!(formatter, "CRAN snapshot publication failed: {error}"),
            Self::Resolution(error) => write!(formatter, "resolution failed: {error}"),
        }
    }
}

impl Error for CranResolutionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Composition(error) => Some(error),
            Self::Lock(error) => Some(error),
            Self::Provider(error) => Some(error),
            Self::Store(error) => Some(error),
            Self::TemporaryStore(error) => Some(error),
            Self::Refresh(error) => Some(error),
            Self::Offline(error) => Some(error),
            Self::Publish(error) => Some(error),
            Self::Resolution(error) => Some(error),
        }
    }
}

/// Whether resolver verification treats locked identities as a preference or
/// an exact constraint. Direct lock consumption is exposed separately through
/// [`crate::lock::ConsumedLockedGraph`] and never invokes a resolver.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LockResolutionPolicy {
    Prefer,
    RequireExact,
}

/// A concrete CRAN resolution together with its per-package refresh diagnostics.
#[derive(Clone, Debug)]
pub struct CranResolutionOutcome {
    pub(super) resolution: Resolution,
    pub(super) diagnostics: Vec<CranRefreshDiagnostic>,
}

impl CranResolutionOutcome {
    pub fn resolution(&self) -> &Resolution {
        &self.resolution
    }

    pub fn diagnostics(&self) -> &[CranRefreshDiagnostic] {
        &self.diagnostics
    }
}

/// Resolve a composed manifest through an injected candidate loader.
///
/// This helper keeps orchestration tests hermetic while exercising the same
/// resolver policy used by the concrete CRAN entry point.
pub fn resolve_with_loader(
    manifest: Manifest,
    loader: &dyn CandidateLoader,
) -> Result<Resolution, CranResolutionError> {
    resolve_with_loader_with_publication_cutoff(manifest, loader, None)
}

pub fn resolve_with_loader_with_publication_cutoff(
    manifest: Manifest,
    loader: &dyn CandidateLoader,
    publication_cutoff: Option<PublicationDate>,
) -> Result<Resolution, CranResolutionError> {
    let request = compose_resolution_request(manifest).map_err(CranResolutionError::Composition)?;
    let request =
        request.with_optional_publication_cutoff(publication_cutoff.map(PublicationCutoff::new));
    let overlay =
        RBasePackageOverlay::new(CandidateLoaderRef(loader), request.target.r_version.clone())
            .map_err(CranResolutionError::Refresh)?;
    resolve_request(request, &overlay)
}

/// Resolve a manifest using a shared logical lock and an injected loader.
///
/// This is the resolver verification/update path; use
/// [`Lockfile::consume_locked_graph`] when the locked graph must be consumed
/// directly without candidate loading. `RequireExact` additionally applies
/// consume applicability and exact non-base identity-set verification after
/// resolution; metadata digests and dependency-edge metadata are not part of
/// that postcondition.
pub fn resolve_with_lock_policy(
    manifest: Manifest,
    lockfile: &Lockfile,
    environment: &EnvironmentId,
    policy: LockResolutionPolicy,
    loader: &dyn CandidateLoader,
) -> Result<Resolution, CranResolutionError> {
    let consumed = if policy == LockResolutionPolicy::RequireExact {
        Some(
            lockfile
                .consume_locked_graph(manifest.clone(), environment)
                .map_err(CranResolutionError::Lock)?,
        )
    } else {
        None
    };
    let request = lockfile
        .resolution_request(manifest, environment)
        .map_err(CranResolutionError::Lock)?;
    let overlay =
        RBasePackageOverlay::new(CandidateLoaderRef(loader), request.target.r_version.clone())
            .map_err(CranResolutionError::Refresh)?;
    let resolution = resolve_request_with_policy(request, &overlay, policy)?;
    if let Some(consumed) = consumed {
        verify_exact_identity_set(&resolution, &consumed)?;
    }
    Ok(resolution)
}

fn verify_exact_identity_set(
    resolution: &Resolution,
    consumed: &ConsumedLockedGraph,
) -> Result<(), CranResolutionError> {
    let expected = consumed
        .packages()
        .iter()
        .map(|package| (package.identity.clone(), package.version.clone()))
        .collect::<HashSet<_>>();
    let actual = resolution
        .packages()
        .iter()
        .filter(|package| !package.identity().provenance().is_r_base_package())
        .map(|package| (package.identity().clone(), package.version().clone()))
        .collect::<HashSet<_>>();
    if expected == actual {
        return Ok(());
    }
    let missing = expected
        .difference(&actual)
        .map(|(identity, version)| semantic_identity_key(identity, version))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let extra = actual
        .difference(&expected)
        .map(|(identity, version)| semantic_identity_key(identity, version))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    Err(CranResolutionError::Lock(
        LockError::ExactIdentitySetMismatch { missing, extra },
    ))
}

fn semantic_identity_key(
    identity: &rsolve_core::ReleaseIdentity,
    version: &rsolve_core::RPackageVersion,
) -> String {
    let count = version.canonical_component_count();
    let canonical_version = version
        .components()
        .take(count)
        .map(|component| component.to_string())
        .collect::<Vec<_>>()
        .join(".");
    format!("{}@{canonical_version}", identity_key(identity))
}

pub(super) fn resolve_request(
    request: rsolve_core::ResolutionRequest,
    loader: &dyn CandidateLoader,
) -> Result<Resolution, CranResolutionError> {
    let preference = DefaultCandidatePreference;
    let unlocked = Unlocked;
    Resolver::new(loader, &preference, &unlocked)
        .resolve(request)
        .map_err(CranResolutionError::Resolution)
}

fn resolve_request_with_policy(
    request: rsolve_core::ResolutionRequest,
    loader: &dyn CandidateLoader,
    policy: LockResolutionPolicy,
) -> Result<Resolution, CranResolutionError> {
    let preference = DefaultCandidatePreference;
    let prefer = PreferLocked;
    let require = RequireLocked;
    let lock_policy: &dyn rsolve_resolver::LockUpdatePolicy = match policy {
        LockResolutionPolicy::Prefer => &prefer,
        LockResolutionPolicy::RequireExact => &require,
    };
    Resolver::new(loader, &preference, lock_policy)
        .resolve(request)
        .map_err(CranResolutionError::Resolution)
}

/// Resolve a manifest against CRAN's synchronous blocking snapshot refresher.
///
/// This boundary is synchronous; callers running inside an async runtime
/// should invoke it on a blocking worker rather than directly on an async
/// executor thread.
pub fn resolve_from_cran(
    manifest: Manifest,
    base_url: impl AsRef<str>,
) -> Result<CranResolutionOutcome, CranResolutionError> {
    resolve_from_cran_with_publication_cutoff(manifest, base_url, None)
}

pub fn resolve_from_cran_with_publication_cutoff(
    manifest: Manifest,
    base_url: impl AsRef<str>,
    publication_cutoff: Option<PublicationDate>,
) -> Result<CranResolutionOutcome, CranResolutionError> {
    let endpoint = canonical_cran_endpoint(base_url.as_ref())?;
    let directory = tempdir().map_err(CranResolutionError::TemporaryStore)?;
    let store = SnapshotStore::open(directory.path(), cran_registry_id(&endpoint))
        .map_err(CranResolutionError::Store)?;
    resolve_from_cran_with_store(manifest, endpoint, publication_cutoff, &store)
}

fn canonical_cran_endpoint(input: &str) -> Result<Box<str>, CranResolutionError> {
    let input = input.trim();
    if input.is_empty() {
        return Err(CranResolutionError::Provider(
            CranSnapshotRefresherError::InvalidBaseUrl {
                diagnostic: "CRAN base URL must not be empty".into(),
            },
        ));
    }
    let mut url = url::Url::parse(input).map_err(|error| {
        CranResolutionError::Provider(CranSnapshotRefresherError::InvalidBaseUrl {
            diagnostic: format!("invalid CRAN base URL: {error}").into(),
        })
    })?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(CranResolutionError::Provider(
            CranSnapshotRefresherError::InvalidBaseUrl {
                diagnostic: "CRAN base URL must use HTTP or HTTPS".into(),
            },
        ));
    }
    if url.host_str().is_none() || url.cannot_be_a_base() {
        return Err(CranResolutionError::Provider(
            CranSnapshotRefresherError::InvalidBaseUrl {
                diagnostic: "CRAN base URL must be hierarchical and include a host".into(),
            },
        ));
    }
    if url.query().is_some() {
        return Err(CranResolutionError::Provider(
            CranSnapshotRefresherError::InvalidBaseUrl {
                diagnostic: "CRAN base URL must not include a query".into(),
            },
        ));
    }
    if url.fragment().is_some() {
        return Err(CranResolutionError::Provider(
            CranSnapshotRefresherError::InvalidBaseUrl {
                diagnostic: "CRAN base URL must not include a fragment".into(),
            },
        ));
    }
    let path = url.path().trim_end_matches('/').to_owned();
    url.set_path(if path.is_empty() { "/" } else { &path });
    Ok(url.to_string().trim_end_matches('/').into())
}

#[cfg(test)]
mod tests;
