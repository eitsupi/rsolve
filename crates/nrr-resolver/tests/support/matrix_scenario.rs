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
        let matrix = PackageName::new("Matrix").unwrap();
        ResolutionRequest::without_lock(
            vec![DependencyRequirement::new(
                DependencyKind::Depends,
                matrix,
                DependencySourceConstraint::Any,
                VersionConstraint::unconstrained(),
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
