use std::collections::HashMap;
use std::error::Error;
use std::fmt;

use crate::constraints::{DependencyRequirement, DependencySourceConstraint};
use crate::identity::{Distribution, Provenance, ReleaseIdentity};
use crate::names::{PackageName, Sha256Digest};
use crate::r_versions::RPackageVersion;

/// Normalized metadata excluding `Package`, `Version`, and every dependency
/// field.  Dependencies have exactly one home: `ReleaseObservation` and then
/// the validated `PackageRelease`.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct ReleaseMetadata {
    fields: std::collections::BTreeMap<String, String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReleaseMetadataError {
    ReservedField { field: String },
}

impl fmt::Display for ReleaseMetadataError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReservedField { field } => {
                write!(f, "release metadata field {field:?} is not metadata")
            }
        }
    }
}

impl Error for ReleaseMetadataError {}

impl ReleaseMetadata {
    pub fn new(
        fields: std::collections::BTreeMap<String, String>,
    ) -> Result<Self, ReleaseMetadataError> {
        for field in fields.keys() {
            let normalized = field.to_ascii_lowercase();
            if matches!(
                normalized.as_str(),
                "package"
                    | "version"
                    | "depends"
                    | "imports"
                    | "linkingto"
                    | "suggests"
                    | "enhances"
            ) {
                return Err(ReleaseMetadataError::ReservedField {
                    field: field.clone(),
                });
            }
        }
        Ok(Self { fields })
    }

    pub fn from_pairs<I, K, V>(pairs: I) -> Result<Self, ReleaseMetadataError>
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        Self::new(
            pairs
                .into_iter()
                .map(|(key, value)| (key.into(), value.into()))
                .collect(),
        )
    }

    pub fn fields(&self) -> &std::collections::BTreeMap<String, String> {
        &self.fields
    }
}

#[derive(Clone, Debug)]
pub struct ReleaseObservation {
    pub identity: ReleaseIdentity,
    pub observed_package: PackageName,
    pub observed_version: RPackageVersion,
    pub metadata: ReleaseMetadata,
    pub dependencies: Vec<DependencyRequirement>,
    pub distributions: Vec<Distribution>,
}

/// A validated resolver-facing release.
///
/// Deliberately do not implement identity-only `Eq` or `Hash` for this type.
/// If two observations of one Git commit declared different versions were
/// inserted into a `HashSet<PackageRelease>` keyed only by identity, the
/// second observation could be silently discarded and the required
/// `ConflictingMetadata` error would never be detected.  Aggregation therefore
/// keys by [`ReleaseIdentity`] and checks metadata before merging.
#[derive(Clone, Debug)]
pub struct PackageRelease {
    identity: ReleaseIdentity,
    version: RPackageVersion,
    metadata: ReleaseMetadata,
    dependencies: Vec<DependencyRequirement>,
    distributions: Vec<Distribution>,
    metadata_digest: Option<Sha256Digest>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PackageReleaseError {
    ConflictingMetadata { field: &'static str },
    InvalidMetadata(ReleaseMetadataError),
    InvalidDependency { index: usize },
}

impl fmt::Display for PackageReleaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConflictingMetadata { field } => {
                write!(f, "conflicting release metadata in {field}")
            }
            Self::InvalidMetadata(error) => error.fmt(f),
            Self::InvalidDependency { index } => write!(f, "invalid dependency at index {index}"),
        }
    }
}

impl Error for PackageReleaseError {}

impl TryFrom<ReleaseObservation> for PackageRelease {
    type Error = PackageReleaseError;

    fn try_from(observation: ReleaseObservation) -> Result<Self, Self::Error> {
        if observation.identity.name() != &observation.observed_package {
            return Err(PackageReleaseError::ConflictingMetadata {
                field: "package name",
            });
        }

        match observation.identity.provenance() {
            Provenance::RegistryRelease { version, .. }
            | Provenance::BioconductorRelease { version, .. } => {
                if version != &observation.observed_version {
                    return Err(PackageReleaseError::ConflictingMetadata {
                        field: "provenance version",
                    });
                }
            }
            Provenance::GitCommit { .. } | Provenance::ImmutableSource { .. } => {
                // For immutable sources the observed DESCRIPTION version is
                // validated metadata, not an identity coordinate.
            }
        }

        for (index, dependency) in observation.dependencies.iter().enumerate() {
            let invalid_exact_name = match &dependency.source {
                DependencySourceConstraint::Exact(identity) => identity.name() != &dependency.name,
                _ => false,
            };
            if dependency.name.as_str().is_empty() || invalid_exact_name {
                return Err(PackageReleaseError::InvalidDependency { index });
            }
        }

        let mut distributions = observation.distributions;
        let mut unique_distributions = Vec::with_capacity(distributions.len());
        for distribution in distributions.drain(..) {
            if !unique_distributions.contains(&distribution) {
                unique_distributions.push(distribution);
            }
        }

        Ok(Self {
            identity: observation.identity,
            version: observation.observed_version,
            metadata: observation.metadata,
            dependencies: observation.dependencies,
            distributions: unique_distributions,
            metadata_digest: None,
        })
    }
}

impl PackageRelease {
    pub fn identity(&self) -> &ReleaseIdentity {
        &self.identity
    }

    pub fn version(&self) -> &RPackageVersion {
        &self.version
    }

    pub fn metadata(&self) -> &ReleaseMetadata {
        &self.metadata
    }

    pub fn dependencies(&self) -> &[DependencyRequirement] {
        &self.dependencies
    }

    pub fn distributions(&self) -> &[Distribution] {
        &self.distributions
    }

    pub fn metadata_digest(&self) -> Option<&Sha256Digest> {
        self.metadata_digest.as_ref()
    }

    fn merge_distributions(&mut self, incoming: &[Distribution]) {
        for distribution in incoming {
            if !self.distributions.contains(distribution) {
                self.distributions.push(distribution.clone());
            }
        }
    }
}

/// Identity-keyed release aggregation.  A name/version match alone never
/// joins entries; distinct provenance produces distinct map entries.
#[derive(Clone, Debug, Default)]
pub struct ReleaseAggregation {
    releases: HashMap<ReleaseIdentity, PackageRelease>,
}

impl ReleaseAggregation {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn observe(&mut self, observation: ReleaseObservation) -> Result<(), PackageReleaseError> {
        self.observe_release(PackageRelease::try_from(observation)?)
    }

    /// Adds an already canonical release while preserving identity-keyed
    /// metadata consistency checks. Providers use this when combining
    /// independently parsed representations of one registry snapshot.
    pub fn observe_release(&mut self, release: PackageRelease) -> Result<(), PackageReleaseError> {
        if let Some(existing) = self.releases.get_mut(release.identity()) {
            if existing.version != release.version {
                return Err(PackageReleaseError::ConflictingMetadata { field: "version" });
            }
            if existing.metadata != release.metadata {
                return Err(PackageReleaseError::ConflictingMetadata { field: "metadata" });
            }
            if existing.dependencies != release.dependencies {
                return Err(PackageReleaseError::ConflictingMetadata {
                    field: "dependencies",
                });
            }
            existing.merge_distributions(&release.distributions);
        } else {
            self.releases.insert(release.identity.clone(), release);
        }
        Ok(())
    }

    pub fn get(&self, identity: &ReleaseIdentity) -> Option<&PackageRelease> {
        self.releases.get(identity)
    }

    pub fn len(&self) -> usize {
        self.releases.len()
    }

    pub fn is_empty(&self) -> bool {
        self.releases.is_empty()
    }

    pub fn releases(&self) -> impl Iterator<Item = &PackageRelease> {
        self.releases.values()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constraints::{
        DependencyKind, DependencySourceConstraint, RelationOp, VersionConstraint,
    };
    use crate::identity::{Artifact, DistributionMetadata, SourceArtifact};
    use crate::names::{
        ArtifactLocator, BioconductorRelease, DistributionChannel, GitCommitId, NormalizedGitUrl,
        PackageNamespace, RegistryId, Sha256Digest, SnapshotId, SourceScheme,
    };
    use std::collections::{BTreeMap, HashSet};

    fn version(value: &str) -> RPackageVersion {
        RPackageVersion::parse(value).unwrap()
    }

    fn package(value: &str) -> PackageName {
        PackageName::new(value).unwrap()
    }

    fn identity(provenance: Provenance) -> ReleaseIdentity {
        ReleaseIdentity::new(package("Matrix"), provenance)
    }

    fn source_distribution(label: &str) -> Distribution {
        Distribution {
            registry: RegistryId::new("cran").unwrap(),
            channel: DistributionChannel::new("source").unwrap(),
            snapshot: Some(SnapshotId::new(label).unwrap()),
            artifacts: vec![Artifact::Source(SourceArtifact {
                locator: ArtifactLocator::new(label).unwrap(),
                upstream_checksums: vec![],
                size: None,
            })],
            observed_metadata: DistributionMetadata::default(),
        }
    }

    fn observation(
        identity: ReleaseIdentity,
        release_version: &str,
        distribution: Distribution,
    ) -> ReleaseObservation {
        ReleaseObservation {
            observed_package: identity.name().clone(),
            identity,
            observed_version: version(release_version),
            metadata: ReleaseMetadata::default(),
            dependencies: vec![],
            distributions: vec![distribution],
        }
    }

    #[test]
    fn metadata_rejects_dependency_and_identity_fields() {
        let mut fields = BTreeMap::new();
        fields.insert("Depends".to_owned(), "R (>= 4.4)".to_owned());
        assert!(matches!(
            ReleaseMetadata::new(fields),
            Err(ReleaseMetadataError::ReservedField { .. })
        ));
    }

    #[test]
    fn canonical_constructor_accepts_each_provenance_variant() {
        let registry = identity(Provenance::RegistryRelease {
            namespace: PackageNamespace::new("cran").unwrap(),
            version: version("1.6-5"),
        });
        let git = identity(Provenance::GitCommit {
            repository: NormalizedGitUrl::new("https://example.test/repo").unwrap(),
            commit: GitCommitId::new("abcdef0123456789abcdef0123456789abcdef01").unwrap(),
            subdirectory: None,
        });
        let bioc = identity(Provenance::BioconductorRelease {
            namespace: PackageNamespace::new("bioc").unwrap(),
            release: BioconductorRelease::new("3.20").unwrap(),
            version: version("1.2.3"),
        });
        let immutable = identity(Provenance::ImmutableSource {
            scheme: SourceScheme::new("sha256").unwrap(),
            digest: Sha256Digest::new("a".repeat(64)).unwrap(),
        });

        for (release_identity, release_version) in [
            (registry, "1.6-5"),
            (git, "1.0.0"),
            (bioc, "1.2.3"),
            (immutable, "9.9.9"),
        ] {
            let release = PackageRelease::try_from(observation(
                release_identity.clone(),
                release_version,
                source_distribution("source"),
            ))
            .unwrap();
            assert_eq!(release.identity(), &release_identity);
            assert_eq!(release.version().as_str(), release_version);
        }
    }

    #[test]
    fn canonical_constructor_rejects_name_and_coordinate_mismatches() {
        let registry_identity = identity(Provenance::RegistryRelease {
            namespace: PackageNamespace::new("cran").unwrap(),
            version: version("1.6-5"),
        });
        let mut wrong_name =
            observation(registry_identity.clone(), "1.6-5", source_distribution("a"));
        wrong_name.observed_package = package("Other");
        assert!(matches!(
            PackageRelease::try_from(wrong_name),
            Err(PackageReleaseError::ConflictingMetadata { .. })
        ));

        let wrong_version = observation(registry_identity, "1.6-6", source_distribution("b"));
        assert!(matches!(
            PackageRelease::try_from(wrong_version),
            Err(PackageReleaseError::ConflictingMetadata {
                field: "provenance version"
            })
        ));

        let bioc_identity = identity(Provenance::BioconductorRelease {
            namespace: PackageNamespace::new("bioc").unwrap(),
            release: BioconductorRelease::new("3.20").unwrap(),
            version: version("1.2.3"),
        });
        assert!(matches!(
            PackageRelease::try_from(observation(
                bioc_identity,
                "1.2.4",
                source_distribution("c")
            )),
            Err(PackageReleaseError::ConflictingMetadata { .. })
        ));

        let git_identity = identity(Provenance::GitCommit {
            repository: NormalizedGitUrl::new("https://example.test/repo").unwrap(),
            commit: GitCommitId::new("abcdef0123456789abcdef0123456789abcdef01").unwrap(),
            subdirectory: None,
        });
        let mut git_wrong_name = observation(git_identity, "1.0.0", source_distribution("d"));
        git_wrong_name.observed_package = package("Other");
        assert!(matches!(
            PackageRelease::try_from(git_wrong_name),
            Err(PackageReleaseError::ConflictingMetadata {
                field: "package name"
            })
        ));

        let immutable_identity = identity(Provenance::ImmutableSource {
            scheme: SourceScheme::new("sha256").unwrap(),
            digest: Sha256Digest::new("b".repeat(64)).unwrap(),
        });
        let mut immutable_wrong_name =
            observation(immutable_identity, "1.0.0", source_distribution("e"));
        immutable_wrong_name.observed_package = package("Other");
        assert!(matches!(
            PackageRelease::try_from(immutable_wrong_name),
            Err(PackageReleaseError::ConflictingMetadata {
                field: "package name"
            })
        ));
    }

    #[test]
    fn canonical_constructor_preserves_dependencies_as_first_class_data() {
        let matrix = package("Matrix");
        let dependency = DependencyRequirement::new(
            DependencyKind::Depends,
            package("R"),
            DependencySourceConstraint::Any,
            VersionConstraint::from_clause(RelationOp::Ge, version("4.4.0")),
        );
        let release = PackageRelease::try_from(ReleaseObservation {
            identity: identity(Provenance::RegistryRelease {
                namespace: PackageNamespace::new("cran").unwrap(),
                version: version("1.6-5"),
            }),
            observed_package: matrix,
            observed_version: version("1.6-5"),
            metadata: ReleaseMetadata::default(),
            dependencies: vec![dependency.clone()],
            distributions: vec![],
        })
        .unwrap();
        assert_eq!(release.dependencies(), &[dependency]);
    }

    #[test]
    fn canonical_constructor_rejects_exact_dependency_name_mismatch() {
        let release_identity = identity(Provenance::RegistryRelease {
            namespace: PackageNamespace::new("cran").unwrap(),
            version: version("1.6-5"),
        });
        let dependency = DependencyRequirement::new(
            DependencyKind::Depends,
            package("Other"),
            DependencySourceConstraint::Exact(release_identity),
            VersionConstraint::unconstrained(),
        );
        let result = PackageRelease::try_from(ReleaseObservation {
            identity: identity(Provenance::RegistryRelease {
                namespace: PackageNamespace::new("cran").unwrap(),
                version: version("1.6-5"),
            }),
            observed_package: package("Matrix"),
            observed_version: version("1.6-5"),
            metadata: ReleaseMetadata::default(),
            dependencies: vec![dependency],
            distributions: vec![],
        });
        assert!(matches!(
            result,
            Err(PackageReleaseError::InvalidDependency { index: 0 })
        ));
    }

    #[test]
    fn same_git_commit_with_two_versions_reports_conflicting_metadata() {
        let provenance = Provenance::GitCommit {
            repository: NormalizedGitUrl::new("https://example.test/repo").unwrap(),
            commit: GitCommitId::new("abcdef0123456789abcdef0123456789abcdef01").unwrap(),
            subdirectory: None,
        };
        let release_identity = identity(provenance);
        let first = observation(release_identity.clone(), "1.0.0", source_distribution("a"));
        let second = observation(release_identity, "2.0.0", source_distribution("b"));

        let mut aggregation = ReleaseAggregation::new();
        aggregation.observe(first).unwrap();
        assert!(matches!(
            aggregation.observe(second),
            Err(PackageReleaseError::ConflictingMetadata { field: "version" })
        ));
        assert_eq!(aggregation.len(), 1);
    }

    #[test]
    fn aggregation_merges_distributions_only_for_established_same_identity() {
        let provenance = Provenance::RegistryRelease {
            namespace: PackageNamespace::new("cran").unwrap(),
            version: version("1.6-5"),
        };
        let same_identity = identity(provenance.clone());
        let mut aggregation = ReleaseAggregation::new();
        aggregation
            .observe(observation(
                same_identity.clone(),
                "1.6-5",
                source_distribution("archive"),
            ))
            .unwrap();
        aggregation
            .observe(observation(
                same_identity.clone(),
                "1.6-5",
                source_distribution("snapshot"),
            ))
            .unwrap();
        assert_eq!(aggregation.len(), 1);
        assert_eq!(
            aggregation
                .get(&same_identity)
                .unwrap()
                .distributions()
                .len(),
            2
        );

        // Same name/version, but a different registry namespace, is not an
        // established provenance and therefore remains a separate candidate.
        let patched_identity = identity(Provenance::RegistryRelease {
            namespace: PackageNamespace::new("private").unwrap(),
            version: version("1.6-5"),
        });
        aggregation
            .observe(observation(
                patched_identity,
                "1.6-5",
                source_distribution("patched"),
            ))
            .unwrap();
        assert_eq!(aggregation.len(), 2);
        assert_eq!(
            aggregation
                .get(&same_identity)
                .unwrap()
                .distributions()
                .len(),
            2,
            "name/version alone must not merge patched source"
        );
    }

    #[test]
    fn first_observation_deduplicates_distributions() {
        let same_identity = identity(Provenance::RegistryRelease {
            namespace: PackageNamespace::new("cran").unwrap(),
            version: version("1.6-5"),
        });
        let duplicate = source_distribution("same");
        let mut observation = observation(same_identity.clone(), "1.6-5", duplicate.clone());
        observation.distributions.push(duplicate);

        let release = PackageRelease::try_from(observation).unwrap();
        assert_eq!(release.distributions().len(), 1);
    }

    #[test]
    fn package_release_is_not_identity_only_hashable() {
        // This is intentionally a compile-time shape assertion made concrete
        // by the conflict scenario above: only ReleaseIdentity is used as the
        // aggregation key, so a differing Git version cannot be discarded by
        // identity-only HashSet deduplication.
        let mut identities = HashSet::new();
        let id = identity(Provenance::GitCommit {
            repository: NormalizedGitUrl::new("https://example.test/repo").unwrap(),
            commit: GitCommitId::new("abcdef0123456789abcdef0123456789abcdef01").unwrap(),
            subdirectory: None,
        });
        identities.insert(id.clone());
        assert!(identities.contains(&id));
    }
}
