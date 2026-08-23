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
        .map(|package| package.identity.clone())
        .collect::<HashSet<_>>();
    let actual = resolution
        .packages()
        .iter()
        .filter(|package| !package.identity().provenance().is_r_base_package())
        .map(|package| package.identity().clone())
        .collect::<HashSet<_>>();
    if expected == actual {
        return Ok(());
    }
    let missing = expected
        .difference(&actual)
        .map(identity_key)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let extra = actual
        .difference(&expected)
        .map(identity_key)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    Err(CranResolutionError::Lock(
        LockError::ExactIdentitySetMismatch { missing, extra },
    ))
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
mod tests {
    use super::*;
    use rsolve_core::{
        CandidateLoadError, CandidateLoadErrorCategory, DependencyKind, DependencyRequirement,
        DependencySourceConstraint, PackageName, PackageNamespace, PackageRelease, Provenance,
        RPackageVersion, ReleaseIdentity, ReleaseMetadata, ReleaseObservation, ResolutionTarget,
        SolverKey, VersionConstraint,
    };
    use rsolve_provider::cran::CranCandidateSnapshot;
    use rsolve_resolver::R_BASE_PACKAGE_NAMES;
    use std::collections::BTreeMap;

    struct FixtureLoader {
        package: PackageRelease,
    }

    struct ChoiceLoader {
        packages: Vec<PackageRelease>,
    }

    impl CandidateLoader for ChoiceLoader {
        fn releases(&self, package: &SolverKey) -> Result<Vec<PackageRelease>, CandidateLoadError> {
            match package {
                SolverKey::InstalledName(name)
                    if self
                        .packages
                        .iter()
                        .any(|release| release.identity().name() == name) =>
                {
                    Ok(self
                        .packages
                        .iter()
                        .filter(|release| release.identity().name() == name)
                        .cloned()
                        .collect())
                }
                SolverKey::InstalledName(_) | SolverKey::R => Ok(Vec::new()),
                _ => Err(CandidateLoadError::new(
                    CandidateLoadErrorCategory::NotFound,
                    "choice fixture has no candidates for this solver key",
                )),
            }
        }
    }

    impl CandidateLoader for FixtureLoader {
        fn releases(&self, package: &SolverKey) -> Result<Vec<PackageRelease>, CandidateLoadError> {
            match package {
                SolverKey::InstalledName(name) if name == self.package.identity().name() => {
                    Ok(vec![self.package.clone()])
                }
                SolverKey::InstalledName(_) => Ok(Vec::new()),
                SolverKey::R => Ok(Vec::new()),
                _ => Err(CandidateLoadError::new(
                    CandidateLoadErrorCategory::NotFound,
                    "fixture has no candidates for this solver key",
                )),
            }
        }
    }

    fn fixture_loader() -> FixtureLoader {
        let package = PackageName::new("fixture").unwrap();
        let version = RPackageVersion::parse("1.0.0").unwrap();
        let identity = ReleaseIdentity::new(
            package.clone(),
            Provenance::RegistryRelease {
                namespace: PackageNamespace::new("cran").unwrap(),
                version: version.clone(),
            },
        );
        let observation = ReleaseObservation {
            identity,
            observed_package: package,
            observed_version: version,
            metadata: ReleaseMetadata::new(BTreeMap::new()).unwrap(),
            publication: None,
            dependencies: Vec::new(),
            distributions: Vec::new(),
        };
        FixtureLoader {
            package: PackageRelease::try_from(observation).unwrap(),
        }
    }

    fn release_with_dependencies(
        name: &PackageName,
        dependencies: Vec<DependencyRequirement>,
    ) -> PackageRelease {
        let version = RPackageVersion::parse("1.0.0").unwrap();
        let identity = ReleaseIdentity::new(
            name.clone(),
            Provenance::RegistryRelease {
                namespace: PackageNamespace::new("cran").unwrap(),
                version: version.clone(),
            },
        );
        PackageRelease::try_from(ReleaseObservation {
            identity,
            observed_package: name.clone(),
            observed_version: version,
            metadata: ReleaseMetadata::new(BTreeMap::new()).unwrap(),
            publication: None,
            dependencies,
            distributions: Vec::new(),
        })
        .unwrap()
    }

    fn release_at_version(name: &PackageName, value: &str) -> PackageRelease {
        let version = RPackageVersion::parse(value).unwrap();
        PackageRelease::try_from(ReleaseObservation {
            identity: ReleaseIdentity::new(
                name.clone(),
                Provenance::RegistryRelease {
                    namespace: PackageNamespace::new("cran").unwrap(),
                    version: version.clone(),
                },
            ),
            observed_package: name.clone(),
            observed_version: version,
            metadata: ReleaseMetadata::new(BTreeMap::new()).unwrap(),
            publication: None,
            dependencies: Vec::new(),
            distributions: Vec::new(),
        })
        .unwrap()
    }

    fn manifest_for(name: PackageName) -> Manifest {
        Manifest::new(
            VersionConstraint::from_clause(
                rsolve_core::RelationOp::Ge,
                RPackageVersion::parse("4.0").unwrap(),
            ),
            crate::manifest::ManifestTarget::new(RPackageVersion::parse("4.4.0").unwrap()),
            vec![crate::manifest::ManifestDependency::new(
                name,
                VersionConstraint::unconstrained(),
            )],
        )
        .unwrap()
    }

    #[test]
    fn cran_registry_ids_are_endpoint_scoped_and_canonical() {
        let first = cran_registry_id("https://cloud.r-project.org/cran");
        let same = cran_registry_id("https://cloud.r-project.org/cran");
        let different = cran_registry_id("https://mirror.example.test/cran");
        assert_eq!(first, same);
        assert_ne!(first, different);
        assert_eq!(
            first.as_str(),
            "cran-sha256:4d1af2a840d22f869630003ab8b6a4677859fb2dc2e67685eca7af1d2aeae7bf"
        );
        assert!(first.as_str().starts_with("cran-sha256:"));
        assert!(first.as_str().chars().all(|character| {
            character == ':'
                || character == '-'
                || character.is_ascii_digit()
                || character.is_ascii_lowercase()
        }));
    }

    #[test]
    fn cran_dependency_closure_is_deterministic_and_excludes_optional_and_r_base() {
        let root = PackageName::new("root").unwrap();
        let first = PackageName::new("first").unwrap();
        let second = PackageName::new("second").unwrap();
        let transitive = PackageName::new("transitive").unwrap();
        let methods = PackageName::new("methods").unwrap();
        let r_base = PackageName::new("R").unwrap();
        let optional = PackageName::new("optional").unwrap();
        let required = |kind, name: &PackageName| {
            DependencyRequirement::new(
                kind,
                name.clone(),
                DependencySourceConstraint::Any,
                VersionConstraint::unconstrained(),
            )
        };
        let root_candidates = vec![
            release_with_dependencies(
                &root,
                vec![
                    required(DependencyKind::Imports, &first),
                    required(DependencyKind::Depends, &methods),
                    required(DependencyKind::Depends, &r_base),
                    required(DependencyKind::Suggests, &optional),
                ],
            ),
            release_with_dependencies(
                &root,
                vec![
                    required(DependencyKind::LinkingTo, &second),
                    required(DependencyKind::Imports, &first),
                ],
            ),
        ];
        let mut calls = Vec::new();
        let closure = collect_cran_dependency_closure(std::slice::from_ref(&root), |batch| {
            calls.push(batch.to_vec());
            match calls.len() {
                1 => Ok(CranCandidateSnapshot::from_candidates([(
                    root.clone(),
                    root_candidates.clone(),
                )])),
                2 => Ok(CranCandidateSnapshot::from_candidates([
                    (
                        first.clone(),
                        vec![release_with_dependencies(
                            &first,
                            vec![required(DependencyKind::Imports, &transitive)],
                        )],
                    ),
                    (
                        second.clone(),
                        vec![release_with_dependencies(&second, vec![])],
                    ),
                ])),
                3 => Ok(CranCandidateSnapshot::from_candidates([(
                    transitive.clone(),
                    vec![release_with_dependencies(&transitive, vec![])],
                )])),
                _ => panic!("closure retried a package"),
            }
        })
        .unwrap();
        assert_eq!(
            closure,
            vec![first.clone(), root.clone(), second, transitive.clone()]
        );
        assert_eq!(
            calls,
            vec![
                vec![root],
                vec![first, PackageName::new("second").unwrap()],
                vec![transitive.clone()]
            ]
        );
        assert!(!closure.contains(&methods));
        assert!(!closure.contains(&r_base));
        assert!(!closure.contains(&optional));
    }

    #[test]
    fn base_only_dependency_closure_skips_refresh_and_publication_inputs() {
        let methods = PackageName::new("methods").unwrap();
        let mut refresh_calls = 0;
        let closure = collect_cran_dependency_closure(std::slice::from_ref(&methods), |_| {
            refresh_calls += 1;
            Ok(CranCandidateSnapshot::default())
        })
        .unwrap();
        assert!(closure.is_empty());
        assert_eq!(refresh_calls, 0);
    }

    #[test]
    fn lock_boundary_uses_prefer_fallback_and_require_exact_policy() {
        let name = PackageName::new("choice").unwrap();
        let old = release_at_version(&name, "1.0.0");
        let newer = release_at_version(&name, "2.0.0");
        let old_resolution = Resolution::new(
            ResolutionTarget::new(RPackageVersion::parse("4.4.0").unwrap()),
            vec![rsolve_core::ResolvedPackage::new(
                SolverKey::InstalledName(name.clone()),
                old,
            )],
        );
        let environment = EnvironmentId::new("default").unwrap();
        let lock = Lockfile::from_resolution(&old_resolution, environment.clone()).unwrap();
        let loader = ChoiceLoader {
            packages: vec![newer.clone()],
        };
        let normal = resolve_with_lock_policy(
            manifest_for(name.clone()),
            &lock,
            &environment,
            LockResolutionPolicy::Prefer,
            &loader,
        )
        .unwrap();
        assert_eq!(normal.selected(&name).unwrap().version(), newer.version());
        assert!(
            resolve_with_lock_policy(
                manifest_for(name),
                &lock,
                &environment,
                LockResolutionPolicy::RequireExact,
                &loader,
            )
            .is_err()
        );
    }

    #[test]
    fn prefer_policy_updates_a_changed_root_without_consume_precondition() {
        let root = PackageName::new("root").unwrap();
        let dependency = PackageName::new("dependency").unwrap();
        let old_root = release_with_dependencies(
            &root,
            vec![DependencyRequirement::new(
                DependencyKind::Imports,
                dependency.clone(),
                DependencySourceConstraint::Any,
                VersionConstraint::unconstrained(),
            )],
        );
        let old_dependency = release_with_dependencies(&dependency, Vec::new());
        let old_resolution = Resolution::new(
            ResolutionTarget::new(RPackageVersion::parse("4.4.0").unwrap()),
            vec![
                rsolve_core::ResolvedPackage::new(SolverKey::InstalledName(root.clone()), old_root),
                rsolve_core::ResolvedPackage::new(
                    SolverKey::InstalledName(dependency),
                    old_dependency,
                ),
            ],
        );
        let environment = EnvironmentId::new("default").unwrap();
        let lock = Lockfile::from_resolution(&old_resolution, environment.clone()).unwrap();
        let changed_manifest = Manifest::new(
            VersionConstraint::from_clause(
                rsolve_core::RelationOp::Ge,
                RPackageVersion::parse("4.0").unwrap(),
            ),
            crate::manifest::ManifestTarget::new(RPackageVersion::parse("4.4.0").unwrap()),
            vec![crate::manifest::ManifestDependency::new(
                root.clone(),
                VersionConstraint::from_clause(
                    rsolve_core::RelationOp::Ge,
                    RPackageVersion::parse("2.0.0").unwrap(),
                ),
            )],
        )
        .unwrap();
        assert!(matches!(
            lock.consume_locked_graph(changed_manifest.clone(), &environment),
            Err(LockError::DirectRootVersionMismatch { .. })
        ));

        let newer_root = release_at_version(&root, "2.0.0");
        let resolution = resolve_with_lock_policy(
            changed_manifest,
            &lock,
            &environment,
            LockResolutionPolicy::Prefer,
            &ChoiceLoader {
                packages: vec![newer_root.clone()],
            },
        )
        .unwrap();
        assert_eq!(
            resolution.selected(&root).unwrap().version(),
            newer_root.version()
        );
    }

    #[test]
    fn require_exact_rejects_new_transitive_identity_from_upstream_metadata() {
        let root = PackageName::new("root").unwrap();
        let extra = PackageName::new("extra").unwrap();
        let old_resolution = Resolution::new(
            ResolutionTarget::new(RPackageVersion::parse("4.4.0").unwrap()),
            vec![rsolve_core::ResolvedPackage::new(
                SolverKey::InstalledName(root.clone()),
                release_at_version(&root, "1.0.0"),
            )],
        );
        let environment = EnvironmentId::new("default").unwrap();
        let lock = Lockfile::from_resolution(&old_resolution, environment.clone()).unwrap();
        let refreshed_root = release_with_dependencies(
            &root,
            vec![DependencyRequirement::new(
                DependencyKind::Imports,
                extra.clone(),
                DependencySourceConstraint::Any,
                VersionConstraint::unconstrained(),
            )],
        );
        let error = resolve_with_lock_policy(
            manifest_for(root),
            &lock,
            &environment,
            LockResolutionPolicy::RequireExact,
            &ChoiceLoader {
                packages: vec![
                    refreshed_root,
                    release_with_dependencies(&extra, Vec::new()),
                ],
            },
        )
        .unwrap_err();
        assert!(matches!(
            error,
            CranResolutionError::Lock(LockError::ExactIdentitySetMismatch { missing, extra })
                if missing.is_empty() && extra.len() == 1
        ));
    }

    #[test]
    fn require_exact_identity_mismatch_diagnostics_are_order_independent() {
        let root = PackageName::new("root").unwrap();
        let first = PackageName::new("first").unwrap();
        let second = PackageName::new("second").unwrap();
        let lock = Lockfile::from_resolution(
            &Resolution::new(
                ResolutionTarget::new(RPackageVersion::parse("4.4.0").unwrap()),
                vec![rsolve_core::ResolvedPackage::new(
                    SolverKey::InstalledName(root.clone()),
                    release_at_version(&root, "1.0.0"),
                )],
            ),
            EnvironmentId::new("default").unwrap(),
        )
        .unwrap();
        let environment = EnvironmentId::new("default").unwrap();
        let refreshed_root = release_with_dependencies(
            &root,
            vec![
                DependencyRequirement::new(
                    DependencyKind::Imports,
                    first.clone(),
                    DependencySourceConstraint::Any,
                    VersionConstraint::unconstrained(),
                ),
                DependencyRequirement::new(
                    DependencyKind::Imports,
                    second.clone(),
                    DependencySourceConstraint::Any,
                    VersionConstraint::unconstrained(),
                ),
            ],
        );
        let first_release = release_with_dependencies(&first, Vec::new());
        let second_release = release_with_dependencies(&second, Vec::new());
        let run = |packages| {
            let Err(CranResolutionError::Lock(LockError::ExactIdentitySetMismatch {
                missing,
                extra,
            })) = resolve_with_lock_policy(
                manifest_for(root.clone()),
                &lock,
                &environment,
                LockResolutionPolicy::RequireExact,
                &ChoiceLoader { packages },
            )
            else {
                panic!("expected deterministic exact identity mismatch");
            };
            (missing, extra)
        };
        assert_eq!(
            run(vec![
                refreshed_root.clone(),
                first_release.clone(),
                second_release.clone(),
            ]),
            run(vec![refreshed_root, second_release, first_release])
        );
    }

    #[test]
    fn source_qualified_not_found_is_propagated_without_refresh_retry() {
        let root = PackageName::new("fixture").unwrap();
        let dependency = PackageName::new("fixture.registry").unwrap();
        let root_release = release_with_dependencies(
            &root,
            vec![DependencyRequirement::new(
                DependencyKind::Imports,
                dependency,
                DependencySourceConstraint::Registry {
                    namespace: PackageNamespace::new("cran").unwrap(),
                },
                VersionConstraint::unconstrained(),
            )],
        );
        let initial = CranCandidateSnapshot::from_candidates([(root.clone(), vec![root_release])]);
        let error = resolve_with_loader(manifest_for(root), &initial).unwrap_err();
        assert!(matches!(
            error,
            CranResolutionError::Resolution(ResolutionFailure::CandidateLoad {
                package: SolverKey::Registry { .. },
                ..
            })
        ));
    }

    #[test]
    fn r_base_overlay_shadows_cran_base_names_but_not_matrix() {
        let target = RPackageVersion::parse("4.4.0").unwrap();
        let methods = PackageName::new("methods").unwrap();
        let matrix = PackageName::new("Matrix").unwrap();
        let cran = CranCandidateSnapshot::from_candidates([
            (
                methods.clone(),
                vec![release_with_dependencies(&methods, Vec::new())],
            ),
            (
                matrix.clone(),
                vec![release_with_dependencies(&matrix, Vec::new())],
            ),
        ]);
        let overlay = RBasePackageOverlay::new(CandidateLoaderRef(&cran), target.clone()).unwrap();
        assert_eq!(R_BASE_PACKAGE_NAMES.len(), 14);
        assert_eq!(
            R_BASE_PACKAGE_NAMES
                .iter()
                .map(|name| PackageName::new(name).unwrap())
                .collect::<std::collections::HashSet<_>>()
                .len(),
            14
        );
        let base_release = overlay
            .releases(&SolverKey::InstalledName(methods.clone()))
            .unwrap();
        assert_eq!(base_release.len(), 1);
        assert!(base_release[0].is_r_base_package());
        assert_eq!(base_release[0].version(), &target);
        assert!(!cran.needs_refresh(&SolverKey::InstalledName(methods)));
        assert!(
            !overlay.releases(&SolverKey::InstalledName(matrix)).unwrap()[0].is_r_base_package()
        );
        let empty = CranCandidateSnapshot::from_candidates([]);
        assert!(empty.needs_refresh(&SolverKey::InstalledName(
            PackageName::new("Matrix").unwrap()
        )));
    }

    #[test]
    fn methods_dependency_uses_target_r_base_without_refresh_or_resolution_output() {
        let root = PackageName::new("fixture").unwrap();
        let methods = PackageName::new("methods").unwrap();
        let target = RPackageVersion::parse("4.4.0").unwrap();
        let root_release = release_with_dependencies(
            &root,
            vec![DependencyRequirement::new(
                DependencyKind::Imports,
                methods.clone(),
                DependencySourceConstraint::Any,
                VersionConstraint::from_clause(rsolve_core::RelationOp::Eq, target.clone()),
            )],
        );
        let resolution = resolve_with_loader(
            manifest_for(root.clone()),
            &CranCandidateSnapshot::from_candidates([(root.clone(), vec![root_release])]),
        )
        .unwrap();
        assert!(resolution.selected(&root).is_some());
        assert!(resolution.selected(&methods).is_none());
    }

    #[test]
    fn incompatible_methods_constraint_is_no_solution_without_refresh() {
        let root = PackageName::new("fixture").unwrap();
        let methods = PackageName::new("methods").unwrap();
        let root_release = release_with_dependencies(
            &root,
            vec![DependencyRequirement::new(
                DependencyKind::Imports,
                methods,
                DependencySourceConstraint::Any,
                VersionConstraint::from_clause(
                    rsolve_core::RelationOp::Eq,
                    RPackageVersion::parse("4.3.0").unwrap(),
                ),
            )],
        );
        let error = resolve_with_loader(
            manifest_for(root.clone()),
            &CranCandidateSnapshot::from_candidates([(root.clone(), vec![root_release])]),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            CranResolutionError::Resolution(ResolutionFailure::NoSolution { .. })
        ));
    }

    #[test]
    fn injected_loader_exercises_manifest_to_resolution_orchestration() {
        let manifest = Manifest::new(
            VersionConstraint::from_clause(
                rsolve_core::RelationOp::Ge,
                RPackageVersion::parse("4.0").unwrap(),
            ),
            crate::manifest::ManifestTarget::new(RPackageVersion::parse("4.4.0").unwrap()),
            vec![crate::manifest::ManifestDependency::new(
                PackageName::new("fixture").unwrap(),
                VersionConstraint::unconstrained(),
            )],
        )
        .unwrap();
        let loader = fixture_loader();
        let resolution = resolve_with_loader(manifest, &loader).unwrap();
        assert_eq!(
            resolution
                .selected(&PackageName::new("fixture").unwrap())
                .unwrap()
                .version(),
            &RPackageVersion::parse("1.0.0").unwrap()
        );
    }

    #[test]
    fn injected_loader_uses_target_r_base_package_without_loader_candidates() {
        let root = PackageName::new("fixture").unwrap();
        let methods = PackageName::new("methods").unwrap();
        let target = RPackageVersion::parse("4.4.0").unwrap();
        let root_release = release_with_dependencies(
            &root,
            vec![DependencyRequirement::new(
                DependencyKind::Imports,
                methods.clone(),
                DependencySourceConstraint::Any,
                VersionConstraint::from_clause(rsolve_core::RelationOp::Eq, target.clone()),
            )],
        );

        let resolution = resolve_with_loader(
            manifest_for(root.clone()),
            &FixtureLoader {
                package: root_release,
            },
        )
        .unwrap();

        assert!(resolution.selected(&root).is_some());
        assert!(resolution.selected(&methods).is_none());
    }

    #[test]
    fn injected_loader_does_not_infer_recommended_packages_as_runtime_provided() {
        let root = PackageName::new("fixture").unwrap();
        let matrix = PackageName::new("Matrix").unwrap();
        let root_release = release_with_dependencies(
            &root,
            vec![DependencyRequirement::new(
                DependencyKind::Imports,
                matrix,
                DependencySourceConstraint::Any,
                VersionConstraint::unconstrained(),
            )],
        );

        let error = resolve_with_loader(
            manifest_for(root),
            &FixtureLoader {
                package: root_release,
            },
        )
        .unwrap_err();

        assert!(matches!(
            error,
            CranResolutionError::Resolution(ResolutionFailure::NoSolution { .. })
        ));
    }
}
