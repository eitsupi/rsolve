use std::cell::Cell;
use std::collections::BTreeMap;

use nrr_core::{
    CandidateLoadError, CandidateLoadErrorCategory, CandidateLoader, DependencyKind,
    DependencyRequirement, DependencySourceConstraint, Distribution, DistributionChannel,
    DistributionMetadata, PackageName, PackageNamespace, PackageRelease, Provenance,
    RPackageVersion, RelationOp, ReleaseAggregation, ReleaseIdentity, ReleaseMetadata,
    ReleaseObservation, ResolutionRequest, ResolutionTarget, SolverKey, Target, VersionConstraint,
};
use nrr_resolver::{DefaultCandidatePreference, PreferLocked, Resolver};

pub struct MatrixCatalog {
    candidates: BTreeMap<PackageName, Vec<PackageRelease>>,
    reverse_next_load: Cell<bool>,
}

impl MatrixCatalog {
    pub fn new() -> Self {
        let matrix_16 = matrix_release(
            "1.6-5",
            VersionConstraint::from_clause(
                RelationOp::Ge,
                RPackageVersion::parse("3.5.0").unwrap(),
            ),
        );
        let matrix_17 = matrix_release(
            "1.7-0",
            VersionConstraint::from_clause(
                RelationOp::Ge,
                RPackageVersion::parse("4.4.0").unwrap(),
            ),
        );
        let methods = plain_release("methods", "4.3.3");

        let mut aggregation = ReleaseAggregation::new();
        for release in [matrix_16, matrix_17, methods] {
            aggregation
                .observe(release)
                .expect("matrix fixture must use canonical release aggregation");
        }

        let mut candidates = BTreeMap::new();
        for release in aggregation.releases() {
            candidates
                .entry(release.identity().name().clone())
                .or_insert_with(Vec::new)
                .push(release.clone());
        }
        for releases in candidates.values_mut() {
            releases.sort_by(|left, right| left.version().cmp(right.version()));
        }
        Self {
            candidates,
            reverse_next_load: Cell::new(false),
        }
    }

    pub fn resolver(&self) -> Resolver<'_> {
        static PREFERENCE: DefaultCandidatePreference = DefaultCandidatePreference;
        static LOCK_POLICY: PreferLocked = PreferLocked;
        Resolver::new(self, &PREFERENCE, &LOCK_POLICY)
    }

    pub fn request(&self, r_version: &str) -> ResolutionRequest {
        self.constrained_request(r_version, VersionConstraint::unconstrained())
    }

    /// A request whose root `Matrix` requirement carries `constraint`.
    pub fn constrained_request(
        &self,
        r_version: &str,
        constraint: VersionConstraint,
    ) -> ResolutionRequest {
        let matrix = PackageName::new("Matrix").unwrap();
        ResolutionRequest::without_lock(
            vec![DependencyRequirement::new(
                DependencyKind::Depends,
                matrix,
                DependencySourceConstraint::Any,
                constraint,
            )],
            ResolutionTarget::new(
                RPackageVersion::parse(r_version).unwrap(),
                Target::new("linux", "x86_64"),
            ),
            VersionConstraint::unconstrained(),
        )
    }
}

impl CandidateLoader for MatrixCatalog {
    fn releases(&self, package: &SolverKey) -> Result<Vec<PackageRelease>, CandidateLoadError> {
        let name = match package {
            SolverKey::InstalledName(name) => name,
            _ => {
                return Err(CandidateLoadError::new(
                    CandidateLoadErrorCategory::NotFound,
                    format!("matrix fixture has no candidates for {package:?}"),
                ));
            }
        };
        let mut releases = self.candidates.get(name).cloned().ok_or_else(|| {
            CandidateLoadError::new(
                CandidateLoadErrorCategory::NotFound,
                format!("matrix fixture has no package {name}"),
            )
        })?;
        let reverse = self.reverse_next_load.get();
        self.reverse_next_load.set(!reverse);
        if reverse {
            releases.reverse();
        }
        Ok(releases)
    }
}

fn matrix_release(version: &str, r_constraint: VersionConstraint) -> ReleaseObservation {
    let package = PackageName::new("Matrix").unwrap();
    ReleaseObservation {
        identity: ReleaseIdentity::new(
            package.clone(),
            Provenance::RegistryRelease {
                namespace: PackageNamespace::new("cran").unwrap(),
                version: RPackageVersion::parse(version).unwrap(),
            },
        ),
        observed_package: package,
        observed_version: RPackageVersion::parse(version).unwrap(),
        metadata: ReleaseMetadata::default(),
        dependencies: vec![
            DependencyRequirement::new(
                DependencyKind::Depends,
                PackageName::new("R").unwrap(),
                DependencySourceConstraint::Any,
                r_constraint,
            ),
            DependencyRequirement::new(
                DependencyKind::Depends,
                PackageName::new("methods").unwrap(),
                DependencySourceConstraint::Any,
                VersionConstraint::unconstrained(),
            ),
        ],
        distributions: vec![Distribution {
            registry: nrr_core::RegistryId::new("cran").unwrap(),
            channel: DistributionChannel::new("source").unwrap(),
            snapshot: None,
            artifacts: Vec::new(),
            observed_metadata: DistributionMetadata::default(),
        }],
    }
}

fn plain_release(name: &str, version: &str) -> ReleaseObservation {
    let package = PackageName::new(name).unwrap();
    let parsed_version = RPackageVersion::parse(version).unwrap();
    ReleaseObservation {
        identity: ReleaseIdentity::new(
            package.clone(),
            Provenance::RegistryRelease {
                namespace: PackageNamespace::new("cran").unwrap(),
                version: parsed_version.clone(),
            },
        ),
        observed_package: package,
        observed_version: parsed_version,
        metadata: ReleaseMetadata::default(),
        dependencies: Vec::new(),
        distributions: vec![Distribution {
            registry: nrr_core::RegistryId::new("cran").unwrap(),
            channel: DistributionChannel::new("source").unwrap(),
            snapshot: None,
            artifacts: Vec::new(),
            observed_metadata: DistributionMetadata::default(),
        }],
    }
}

#[cfg(test)]
#[allow(dead_code)]
pub mod regression_support {
    use super::*;
    use nrr_core::NormalizedGitUrl;
    use nrr_resolver::RequireLocked;
    use std::collections::HashMap;

    pub struct SameVersionCatalog {
        foo: Vec<PackageRelease>,
    }

    impl SameVersionCatalog {
        /// The non-preferred release is returned first, so a reconstruction
        /// that takes the first release with the chosen version picks the
        /// release the preference policy rejected.
        pub fn new() -> Self {
            Self {
                foo: Self::releases(),
            }
        }

        /// The preferred release is returned first, so a reconstruction that
        /// takes the first release with the chosen version picks it even when
        /// a required lock names the other one.
        pub fn with_preferred_first() -> Self {
            let mut foo = Self::releases();
            foo.reverse();
            Self { foo }
        }

        fn releases() -> Vec<PackageRelease> {
            let version = "1.0.0";
            let nonpreferred = registry_candidate(
                "Foo",
                version,
                "other",
                vec![DependencyRequirement::new(
                    DependencyKind::Depends,
                    PackageName::new("WrongDep").unwrap(),
                    DependencySourceConstraint::Any,
                    VersionConstraint::unconstrained(),
                )],
            );
            let preferred = registry_candidate(
                "Foo",
                version,
                "preferred",
                vec![DependencyRequirement::new(
                    DependencyKind::Depends,
                    PackageName::new("PreferredDep").unwrap(),
                    DependencySourceConstraint::Any,
                    VersionConstraint::unconstrained(),
                )],
            );
            vec![nonpreferred, preferred]
        }

        pub fn resolver(&self) -> Resolver<'_> {
            static PREFERENCE: DefaultCandidatePreference = DefaultCandidatePreference;
            static LOCK_POLICY: PreferLocked = PreferLocked;
            Resolver::new(self, &PREFERENCE, &LOCK_POLICY)
        }

        pub fn require_locked_resolver(&self) -> Resolver<'_> {
            static PREFERENCE: DefaultCandidatePreference = DefaultCandidatePreference;
            static LOCK_POLICY: RequireLocked = RequireLocked;
            Resolver::new(self, &PREFERENCE, &LOCK_POLICY)
        }

        pub fn request(&self) -> ResolutionRequest {
            ResolutionRequest::without_lock(
                vec![foo_requirement()],
                ResolutionTarget::new(
                    RPackageVersion::parse("4.4.0").unwrap(),
                    Target::new("linux", "x86_64"),
                ),
                VersionConstraint::unconstrained(),
            )
        }

        pub fn require_nonpreferred_request(&self) -> ResolutionRequest {
            let mut locked = HashMap::new();
            locked.insert(
                SolverKey::InstalledName(PackageName::new("Foo").unwrap()),
                self.nonpreferred_identity(),
            );
            ResolutionRequest::new(
                vec![foo_requirement()],
                ResolutionTarget::new(
                    RPackageVersion::parse("4.4.0").unwrap(),
                    Target::new("linux", "x86_64"),
                ),
                VersionConstraint::unconstrained(),
                locked,
            )
        }

        /// The release `DefaultCandidatePreference` selects when nothing is
        /// locked.  Both releases declare the same version, so the ordering
        /// falls through to the identity tie-break.
        pub fn preferred_identity(&self) -> ReleaseIdentity {
            self.identity_in_namespace("preferred")
        }

        pub fn nonpreferred_identity(&self) -> ReleaseIdentity {
            self.identity_in_namespace("other")
        }

        fn identity_in_namespace(&self, namespace: &str) -> ReleaseIdentity {
            self.foo
                .iter()
                .find(|release| match release.identity().provenance() {
                    Provenance::RegistryRelease {
                        namespace: found, ..
                    } => found.as_str() == namespace,
                    _ => false,
                })
                .expect("fixture must declare both namespaces")
                .identity()
                .clone()
        }
    }

    impl CandidateLoader for SameVersionCatalog {
        fn releases(&self, package: &SolverKey) -> Result<Vec<PackageRelease>, CandidateLoadError> {
            let name = match package {
                SolverKey::InstalledName(name) => name.as_str(),
                _ => {
                    return Err(CandidateLoadError::new(
                        CandidateLoadErrorCategory::NotFound,
                        format!("same-version fixture has no candidates for {package:?}"),
                    ));
                }
            };
            match name {
                "Foo" => Ok(self.foo.clone()),
                "PreferredDep" | "WrongDep" => Ok(vec![plain_candidate(name, "1.0.0")]),
                _ => Err(CandidateLoadError::new(
                    CandidateLoadErrorCategory::NotFound,
                    format!("same-version fixture has no package {name}"),
                )),
            }
        }
    }

    pub struct GitDependencyCatalog {
        choice: Vec<PackageRelease>,
    }

    impl GitDependencyCatalog {
        pub fn new() -> Self {
            let git_dependency = DependencyRequirement::new(
                DependencyKind::Depends,
                PackageName::new("GitOnly").unwrap(),
                DependencySourceConstraint::Git {
                    repository: NormalizedGitUrl::new("https://example.test/git-only.git").unwrap(),
                },
                VersionConstraint::unconstrained(),
            );
            Self {
                choice: vec![
                    registry_candidate("Choice", "1.0.0", "cran", vec![]),
                    registry_candidate("Choice", "2.0.0", "cran", vec![git_dependency]),
                ],
            }
        }

        pub fn resolver(&self) -> Resolver<'_> {
            static PREFERENCE: DefaultCandidatePreference = DefaultCandidatePreference;
            static LOCK_POLICY: PreferLocked = PreferLocked;
            Resolver::new(self, &PREFERENCE, &LOCK_POLICY)
        }

        pub fn request(&self) -> ResolutionRequest {
            ResolutionRequest::without_lock(
                vec![DependencyRequirement::new(
                    DependencyKind::Depends,
                    PackageName::new("Choice").unwrap(),
                    DependencySourceConstraint::Any,
                    VersionConstraint::unconstrained(),
                )],
                ResolutionTarget::new(
                    RPackageVersion::parse("4.4.0").unwrap(),
                    Target::new("linux", "x86_64"),
                ),
                VersionConstraint::unconstrained(),
            )
        }
    }

    impl CandidateLoader for GitDependencyCatalog {
        fn releases(&self, package: &SolverKey) -> Result<Vec<PackageRelease>, CandidateLoadError> {
            if matches!(
                package,
                SolverKey::InstalledName(name) if name.as_str() == "Choice"
            ) {
                return Ok(self.choice.clone());
            }
            Err(CandidateLoadError::new(
                CandidateLoadErrorCategory::NotFound,
                format!("Git dependency fixture has no candidates for {package:?}"),
            ))
        }
    }

    /// The identity of the `Matrix` release declaring `version`.
    pub fn matrix_identity(catalog: &MatrixCatalog, version: &str) -> ReleaseIdentity {
        let wanted = RPackageVersion::parse(version).unwrap();
        catalog.candidates[&PackageName::new("Matrix").unwrap()]
            .iter()
            .find(|release| release.version() == &wanted)
            .expect("matrix fixture must declare the requested version")
            .identity()
            .clone()
    }

    /// A `MatrixCatalog` resolver under the frozen-lock policy.
    pub fn require_locked_matrix_resolver(catalog: &MatrixCatalog) -> Resolver<'_> {
        static PREFERENCE: DefaultCandidatePreference = DefaultCandidatePreference;
        static LOCK_POLICY: RequireLocked = RequireLocked;
        Resolver::new(catalog, &PREFERENCE, &LOCK_POLICY)
    }

    /// `request` with `identity` recorded as the previous `Matrix` lock.
    pub fn with_locked_matrix(
        mut request: ResolutionRequest,
        identity: ReleaseIdentity,
    ) -> ResolutionRequest {
        let mut locked = HashMap::new();
        locked.insert(
            SolverKey::InstalledName(PackageName::new("Matrix").unwrap()),
            identity,
        );
        request.locked = locked;
        request
    }

    pub struct AlternativeCatalog {
        releases: Vec<PackageRelease>,
        reverse: bool,
    }

    impl AlternativeCatalog {
        pub fn new(reverse: bool) -> Self {
            Self {
                releases: ["1.0.0", "2.0.0", "3.0.0", "4.0.0"]
                    .into_iter()
                    .map(|version| registry_candidate("Alternatives", version, "cran", vec![]))
                    .collect(),
                reverse,
            }
        }

        pub fn resolver(&self) -> Resolver<'_> {
            static PREFERENCE: DefaultCandidatePreference = DefaultCandidatePreference;
            static LOCK_POLICY: PreferLocked = PreferLocked;
            Resolver::new(self, &PREFERENCE, &LOCK_POLICY)
        }

        pub fn request(&self) -> ResolutionRequest {
            ResolutionRequest::without_lock(
                vec![DependencyRequirement::new(
                    DependencyKind::Depends,
                    PackageName::new("Alternatives").unwrap(),
                    DependencySourceConstraint::Any,
                    VersionConstraint::unconstrained(),
                )],
                ResolutionTarget::new(
                    RPackageVersion::parse("4.4.0").unwrap(),
                    Target::new("linux", "x86_64"),
                ),
                VersionConstraint::unconstrained(),
            )
        }
    }

    impl CandidateLoader for AlternativeCatalog {
        fn releases(&self, package: &SolverKey) -> Result<Vec<PackageRelease>, CandidateLoadError> {
            if matches!(
                package,
                SolverKey::InstalledName(name) if name.as_str() == "Alternatives"
            ) {
                let mut releases = self.releases.clone();
                if self.reverse {
                    releases.reverse();
                }
                return Ok(releases);
            }
            Err(CandidateLoadError::new(
                CandidateLoadErrorCategory::NotFound,
                format!("alternative fixture has no candidates for {package:?}"),
            ))
        }
    }

    fn foo_requirement() -> DependencyRequirement {
        DependencyRequirement::new(
            DependencyKind::Depends,
            PackageName::new("Foo").unwrap(),
            DependencySourceConstraint::Any,
            VersionConstraint::unconstrained(),
        )
    }

    fn plain_candidate(name: &str, version: &str) -> PackageRelease {
        PackageRelease::try_from(plain_release(name, version)).unwrap()
    }

    fn registry_candidate(
        name: &str,
        version: &str,
        namespace: &str,
        dependencies: Vec<DependencyRequirement>,
    ) -> PackageRelease {
        let package = PackageName::new(name).unwrap();
        let parsed_version = RPackageVersion::parse(version).unwrap();
        PackageRelease::try_from(ReleaseObservation {
            identity: ReleaseIdentity::new(
                package.clone(),
                Provenance::RegistryRelease {
                    namespace: PackageNamespace::new(namespace).unwrap(),
                    version: parsed_version.clone(),
                },
            ),
            observed_package: package,
            observed_version: parsed_version,
            metadata: ReleaseMetadata::default(),
            dependencies,
            distributions: vec![Distribution {
                registry: nrr_core::RegistryId::new("cran").unwrap(),
                channel: DistributionChannel::new("source").unwrap(),
                snapshot: None,
                artifacts: Vec::new(),
                observed_metadata: DistributionMetadata::default(),
            }],
        })
        .unwrap()
    }
}
