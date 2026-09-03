//! Direct Git source acquisition for the composed-resolution boundary.
//!
//! This adapter intentionally exposes only resolver candidates and the
//! canonical release identity. Git's cache layout and process protocol stay
//! in `rsolve-provider`.

use std::path::Path;

use rsolve_core::{
    CandidateLoadError, CandidateLoadResult, CandidateLoader, DependencySourceConstraint,
    NonRepositoryExposure, PackageRequirement, PreparedCandidate, Provenance, RepositorySubdir,
    ResolutionRequest, RootRequirement, SolverKey,
};
use rsolve_provider::source_control::git::{
    GitBackend, GitCacheError, GitRevisionRequest, GitSelector, GitSourceRequest,
};
use rsolve_provider::source_control::{
    DescriptionProjectionError, DescriptionProjectionRequest, project_description,
};
use thiserror::Error;

use crate::manifest::{
    ComposedEnvironment, ComposedRootIntent, GitSelector as ManifestGitSelector, ManifestError,
    ManifestSource,
};

#[derive(Debug, Error)]
pub(crate) enum DirectGitError {
    #[error("Git source acquisition failed for {package}: {source}")]
    Acquisition {
        package: rsolve_core::PackageName,
        source: GitCacheError,
    },
    #[error("DESCRIPTION projection failed for {package}: {source}")]
    Description {
        package: rsolve_core::PackageName,
        source: DescriptionProjectionError,
    },
    #[error("direct Git DESCRIPTION package mismatch for {package}: found {actual}")]
    PackageMismatch {
        package: rsolve_core::PackageName,
        actual: rsolve_core::PackageName,
    },
    #[error(
        "direct Git DESCRIPTION version {version} does not satisfy the root constraint for {package}"
    )]
    VersionMismatch {
        package: rsolve_core::PackageName,
        version: rsolve_core::RPackageVersion,
    },
    #[error("direct Git acquired identity does not match the requested source for {package}")]
    IdentityMismatch { package: rsolve_core::PackageName },
    #[error("direct source composition failed: {0}")]
    Composition(ManifestError),
}

#[derive(Debug)]
pub(crate) struct PreparedDirectGit {
    pub(crate) request: ResolutionRequest,
    pub(crate) loader: DirectGitCandidateLoader,
}

struct AcquiredDirectGit {
    release: rsolve_core::PackageRelease,
}

trait DirectGitAcquirer {
    fn acquire(
        &self,
        cache_root: &Path,
        root: &ComposedRootIntent,
        request: &GitSourceRequest,
    ) -> Result<AcquiredDirectGit, DirectGitError>;
}

struct SystemDirectGitAcquirer {
    backend: GitBackend,
}

impl DirectGitAcquirer for SystemDirectGitAcquirer {
    fn acquire(
        &self,
        cache_root: &Path,
        root: &ComposedRootIntent,
        request: &GitSourceRequest,
    ) -> Result<AcquiredDirectGit, DirectGitError> {
        let acquired = self
            .backend
            .acquire_cached(cache_root, request)
            .map_err(|source| DirectGitError::Acquisition {
                package: root.name.clone(),
                source,
            })?;
        let identity = rsolve_core::ReleaseIdentity::new(
            root.name.clone(),
            Provenance::GitCommit {
                repository: acquired.url().clone(),
                commit: acquired.commit().clone(),
                subdirectory: request.subdirectory.clone(),
            },
        );
        let expected = PackageRequirement::new(
            root.name.clone(),
            DependencySourceConstraint::Any,
            root.constraint.clone(),
        )
        .map_err(|error| {
            DirectGitError::Composition(ManifestError::InvalidDependency(error.to_string()))
        })?;
        let release = project_description(
            acquired.view(),
            DescriptionProjectionRequest::new(&identity, &expected),
        )
        .map_err(|source| DirectGitError::Description {
            package: root.name.clone(),
            source,
        })?;
        Ok(AcquiredDirectGit { release })
    }
}

/// A resolver-facing loader for exact-only direct source candidates. Such a
/// candidate can satisfy only the exact root identity that acquired it; it is
/// never advertised as a repository or as an ordinary installed-name source.
#[derive(Debug)]
pub(crate) struct DirectGitCandidateLoader {
    candidates: Vec<PreparedCandidate>,
}

impl DirectGitCandidateLoader {
    pub(crate) fn is_empty(&self) -> bool {
        self.candidates.is_empty()
    }
}

impl CandidateLoader for DirectGitCandidateLoader {
    fn releases(&self, subject: &SolverKey) -> Result<Vec<PreparedCandidate>, CandidateLoadError> {
        Ok(self
            .candidates
            .iter()
            .filter(|candidate| candidate.is_eligible_for(subject))
            .cloned()
            .collect())
    }

    fn load(&self, subject: &SolverKey) -> Result<CandidateLoadResult, CandidateLoadError> {
        self.releases(subject)
            .map(|candidates| CandidateLoadResult::new(candidates, Vec::new()))
    }
}

pub(crate) fn prepare(
    composed: &ComposedEnvironment,
    cache_root: &Path,
    offline: bool,
) -> Result<PreparedDirectGit, DirectGitError> {
    let acquirer = SystemDirectGitAcquirer {
        backend: GitBackend::system(),
    };
    prepare_with_acquirer(composed, cache_root, offline, &acquirer)
}

fn prepare_with_acquirer<A: DirectGitAcquirer>(
    composed: &ComposedEnvironment,
    cache_root: &Path,
    offline: bool,
    acquirer: &A,
) -> Result<PreparedDirectGit, DirectGitError> {
    let mut roots = Vec::with_capacity(composed.roots.len());
    let mut candidates = Vec::new();

    for root in &composed.roots {
        let source = match &root.source {
            ManifestSource::Registry { repository: None } => DependencySourceConstraint::Any,
            ManifestSource::Registry {
                repository: Some(repository),
            } => DependencySourceConstraint::Repository {
                repository: repository.clone(),
            },
            ManifestSource::Git {
                url,
                selector,
                subdirectory,
            } => {
                let subdirectory = subdirectory
                    .as_deref()
                    .map(RepositorySubdir::new)
                    .transpose()
                    .map_err(|error| {
                        DirectGitError::Composition(ManifestError::InvalidDependencyField {
                            name: root.name.to_string(),
                            reason: error.to_string(),
                        })
                    })?;
                let revision =
                    revision_for(composed, root, selector, subdirectory.as_ref(), offline);
                let request = GitSourceRequest {
                    url: url.clone(),
                    revision,
                    subdirectory: subdirectory.clone(),
                    offline,
                };
                let acquired = acquirer.acquire(cache_root, root, &request)?;
                if acquired.release.identity().name() != &root.name {
                    return Err(DirectGitError::PackageMismatch {
                        package: root.name.clone(),
                        actual: acquired.release.identity().name().clone(),
                    });
                }
                if !root.constraint.satisfies(acquired.release.version()) {
                    return Err(DirectGitError::VersionMismatch {
                        package: root.name.clone(),
                        version: acquired.release.version().clone(),
                    });
                }
                let identity = acquired.release.identity().clone();
                if !matches!(
                    identity.provenance(),
                    Provenance::GitCommit {
                        repository,
                        subdirectory: identity_subdirectory,
                        ..
                    } if repository == url && identity_subdirectory == &subdirectory
                ) {
                    return Err(DirectGitError::IdentityMismatch {
                        package: root.name.clone(),
                    });
                }
                let release = acquired.release;
                let candidate =
                    PreparedCandidate::new(release, NonRepositoryExposure::ExactOnly, Vec::new())
                        .map_err(|error| {
                        DirectGitError::Composition(ManifestError::InvalidDependency(
                            error.to_string(),
                        ))
                    })?;
                candidates.push(candidate);
                DependencySourceConstraint::Exact(identity)
            }
            ManifestSource::Url { .. } | ManifestSource::Path { .. } => {
                return Err(DirectGitError::Composition(
                    ManifestError::DirectSourceRequiresAcquisition {
                        name: root.name.clone(),
                    },
                ));
            }
        };
        let package = PackageRequirement::new(root.name.clone(), source, root.constraint.clone())
            .map_err(|error| {
            DirectGitError::Composition(ManifestError::InvalidDependency(error.to_string()))
        })?;
        roots.push(RootRequirement {
            package,
            expansion: root.expansion,
        });
    }

    let publication_cutoff = composed
        .published_before
        .map(rsolve_core::PublicationCutoff::new);
    let request = ResolutionRequest::new(
        roots,
        composed.target.clone(),
        composed.r_requirement.clone(),
        composed.locked.clone(),
    )
    .with_optional_publication_cutoff(publication_cutoff);
    Ok(PreparedDirectGit {
        request,
        loader: DirectGitCandidateLoader { candidates },
    })
}

fn revision_for(
    composed: &ComposedEnvironment,
    root: &ComposedRootIntent,
    selector: &ManifestGitSelector,
    subdirectory: Option<&RepositorySubdir>,
    offline: bool,
) -> GitRevisionRequest {
    if offline {
        // A compatible lock pins the mutable selector before it reaches the
        // provider. Full-OID Rev is already immutable and can be used as-is.
        if !matches!(selector, ManifestGitSelector::Rev(value) if rsolve_core::GitCommitId::new(value).is_ok())
            && let Some(commit) =
                composed
                    .locked
                    .values()
                    .find_map(|identity| match identity.provenance() {
                        Provenance::GitCommit {
                            repository,
                            commit,
                            subdirectory: locked_subdir,
                        } if repository
                            == match &root.source {
                                ManifestSource::Git { url, .. } => url,
                                _ => unreachable!(),
                            }
                            && locked_subdir.as_ref() == subdirectory
                            && identity.name() == &root.name =>
                        {
                            Some(commit.clone())
                        }
                        _ => None,
                    })
        {
            return GitRevisionRequest::Pinned(commit);
        }
    }
    GitRevisionRequest::Requested(match selector {
        ManifestGitSelector::DefaultBranch => GitSelector::DefaultBranch,
        ManifestGitSelector::Branch(value) => GitSelector::Branch(value.clone()),
        ManifestGitSelector::Tag(value) => GitSelector::Tag(value.clone()),
        ManifestGitSelector::Rev(value) => GitSelector::Rev(value.clone()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    use rsolve_core::{
        DeclaredDependency, PackageRelease, RPackageVersion, ReleaseIdentity, ReleaseMetadata,
        ReleaseObservation, ResolutionTarget, VersionConstraint,
    };

    struct FixtureAcquirer {
        url: rsolve_core::NormalizedGitUrl,
        commit: rsolve_core::GitCommitId,
        requests: RefCell<Vec<GitRevisionRequest>>,
        offline: RefCell<Vec<bool>>,
        package: rsolve_core::PackageName,
        version: RPackageVersion,
    }

    impl DirectGitAcquirer for FixtureAcquirer {
        fn acquire(
            &self,
            _cache_root: &Path,
            _root: &ComposedRootIntent,
            request: &GitSourceRequest,
        ) -> Result<AcquiredDirectGit, DirectGitError> {
            self.requests.borrow_mut().push(request.revision.clone());
            self.offline.borrow_mut().push(request.offline);
            let identity = ReleaseIdentity::new(
                self.package.clone(),
                Provenance::GitCommit {
                    repository: self.url.clone(),
                    commit: self.commit.clone(),
                    subdirectory: request.subdirectory.clone(),
                },
            );
            let release = PackageRelease::try_from(ReleaseObservation {
                observed_package: self.package.clone(),
                observed_version: self.version.clone(),
                metadata: ReleaseMetadata::new(BTreeMap::new()).unwrap(),
                identity,
                publication: None,
                declared_dependencies: Vec::<DeclaredDependency>::new(),
                distributions: Vec::new(),
            })
            .unwrap();
            Ok(AcquiredDirectGit { release })
        }
    }

    fn composed(
        locked: rsolve_core::LockedIdentities,
        selector: ManifestGitSelector,
    ) -> ComposedEnvironment {
        ComposedEnvironment {
            environment: crate::EnvironmentId::new("default").unwrap(),
            r_requirement: VersionConstraint::unconstrained(),
            published_before: None,
            target: ResolutionTarget::new(RPackageVersion::parse("4.4.0").unwrap()),
            repositories: Vec::new(),
            roots: vec![ComposedRootIntent {
                name: rsolve_core::PackageName::new("gitpkg").unwrap(),
                constraint: VersionConstraint::from_clause(
                    rsolve_core::RelationOp::Ge,
                    RPackageVersion::parse("1.0.0").unwrap(),
                ),
                source: ManifestSource::Git {
                    url: rsolve_core::NormalizedGitUrl::new("https://example.test/repo").unwrap(),
                    selector,
                    subdirectory: None,
                },
                expansion: rsolve_core::RootExpansionPolicy::HardOnly,
            }],
            locked,
        }
    }

    fn fixture() -> FixtureAcquirer {
        FixtureAcquirer {
            url: rsolve_core::NormalizedGitUrl::new("https://example.test/repo").unwrap(),
            commit: rsolve_core::GitCommitId::new("0123456789012345678901234567890123456789")
                .unwrap(),
            requests: RefCell::new(Vec::new()),
            offline: RefCell::new(Vec::new()),
            package: rsolve_core::PackageName::new("gitpkg").unwrap(),
            version: RPackageVersion::parse("1.2.0").unwrap(),
        }
    }

    #[test]
    fn git_only_requested_root_is_exact_only_and_resolves_without_repositories() {
        let acquirer = fixture();
        let prepared = prepare_with_acquirer(
            &composed(
                rsolve_core::LockedIdentities::new(),
                ManifestGitSelector::Branch("main".into()),
            ),
            Path::new("/unused"),
            false,
            &acquirer,
        )
        .unwrap();
        assert!(matches!(
            acquirer.requests.borrow().as_slice(),
            [GitRevisionRequest::Requested(GitSelector::Branch(value))] if value == "main"
        ));
        let root = &prepared.request.roots[0].package;
        assert!(matches!(
            root.source(),
            DependencySourceConstraint::Exact(_)
        ));
        assert!(
            prepared
                .loader
                .releases(&SolverKey::InstalledName(root.name().clone()))
                .unwrap()
                .is_empty()
        );
        let outcome =
            super::super::resolve_prepared_request(prepared.request, &prepared.loader).unwrap();
        assert_eq!(outcome.resolution().packages().len(), 1);
        assert_eq!(
            outcome.resolution().packages()[0].visible_repository_ids(),
            &[]
        );
        assert_eq!(
            prepared.loader.candidates[0].non_repository_exposure(),
            NonRepositoryExposure::ExactOnly
        );
    }

    #[test]
    fn offline_mutable_selector_uses_a_compatible_locked_commit_as_pinned() {
        let acquirer = fixture();
        let identity = ReleaseIdentity::new(
            rsolve_core::PackageName::new("gitpkg").unwrap(),
            Provenance::GitCommit {
                repository: acquirer.url.clone(),
                commit: acquirer.commit.clone(),
                subdirectory: None,
            },
        );
        let mut locked = rsolve_core::LockedIdentities::new();
        locked.insert(SolverKey::Exact(identity.clone()), identity);
        // The solver key and value intentionally agree; this mirrors the
        // lock projection consumed by the CLI before offline composition.
        let prepared = prepare_with_acquirer(
            &composed(locked, ManifestGitSelector::Branch("main".into())),
            Path::new("/unused"),
            true,
            &acquirer,
        )
        .unwrap();
        assert!(matches!(
            acquirer.requests.borrow().as_slice(),
            [GitRevisionRequest::Pinned(commit)] if commit == &acquirer.commit
        ));
        assert!(!prepared.loader.is_empty());
    }

    #[test]
    fn offline_unpinned_mutable_selector_reaches_provider_as_requested_offline() {
        let acquirer = fixture();
        prepare_with_acquirer(
            &composed(
                rsolve_core::LockedIdentities::new(),
                ManifestGitSelector::Branch("main".into()),
            ),
            Path::new("/unused"),
            true,
            &acquirer,
        )
        .unwrap();
        assert_eq!(acquirer.offline.borrow().as_slice(), &[true]);
        assert!(matches!(
            acquirer.requests.borrow().as_slice(),
            [GitRevisionRequest::Requested(GitSelector::Branch(value))] if value == "main"
        ));
    }

    #[test]
    fn projected_package_and_version_failures_keep_package_context() {
        let mut package_failure = fixture();
        package_failure.package = rsolve_core::PackageName::new("other").unwrap();
        let error = prepare_with_acquirer(
            &composed(
                rsolve_core::LockedIdentities::new(),
                ManifestGitSelector::DefaultBranch,
            ),
            Path::new("/unused"),
            false,
            &package_failure,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            DirectGitError::PackageMismatch { package, actual }
                if package.as_str() == "gitpkg" && actual.as_str() == "other"
        ));

        let mut version_failure = fixture();
        version_failure.version = RPackageVersion::parse("0.1.0").unwrap();
        let error = prepare_with_acquirer(
            &composed(
                rsolve_core::LockedIdentities::new(),
                ManifestGitSelector::DefaultBranch,
            ),
            Path::new("/unused"),
            false,
            &version_failure,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            DirectGitError::VersionMismatch { package, .. } if package.as_str() == "gitpkg"
        ));

        let mut identity_failure = fixture();
        identity_failure.url =
            rsolve_core::NormalizedGitUrl::new("https://example.test/other").unwrap();
        let error = prepare_with_acquirer(
            &composed(
                rsolve_core::LockedIdentities::new(),
                ManifestGitSelector::DefaultBranch,
            ),
            Path::new("/unused"),
            false,
            &identity_failure,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            DirectGitError::IdentityMismatch { package } if package.as_str() == "gitpkg"
        ));
    }
}
