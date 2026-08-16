use std::collections::HashMap;
use std::error::Error;
use std::fmt;

use sha2::{Digest, Sha256};

use crate::constraints::{
    DependencyKind, DependencyRequirement, DependencySourceConstraint, RelationOp,
};
use crate::identity::{Distribution, Provenance, ReleaseIdentity};
use crate::names::{PackageName, Sha256Digest};
use crate::publication::ReleasePublication;
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
                    | "published"
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
    pub publication: Option<ReleasePublication>,
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
    publication: Option<ReleasePublication>,
    dependencies: Vec<DependencyRequirement>,
    distributions: Vec<Distribution>,
    metadata_digest: Sha256Digest,
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
            Provenance::RBasePackage { r_version } => {
                if r_version != &observation.observed_version {
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

        let metadata_digest = canonical_metadata_digest(
            &observation.identity,
            &observation.observed_version,
            &observation.dependencies,
        );
        Ok(Self {
            identity: observation.identity,
            version: observation.observed_version,
            metadata: observation.metadata,
            publication: observation.publication,
            dependencies: observation.dependencies,
            distributions: unique_distributions,
            metadata_digest,
        })
    }
}

// This is a fingerprint of validated logical/solver metadata, not an
// arbitrary DESCRIPTION passthrough, repository observation, or distribution
// and artifact bytes.
const METADATA_DIGEST_DOMAIN: &[u8] = b"rsolve.logical-release-metadata\0v1";

fn canonical_metadata_digest(
    identity: &ReleaseIdentity,
    observed_version: &RPackageVersion,
    dependencies: &[DependencyRequirement],
) -> Sha256Digest {
    let mut encoded = Vec::new();
    append_bytes(&mut encoded, METADATA_DIGEST_DOMAIN);
    append_identity(&mut encoded, identity);
    append_version(&mut encoded, observed_version);

    let mut dependency_records = dependencies
        .iter()
        .map(encode_dependency)
        .collect::<Vec<_>>();
    dependency_records.sort();
    dependency_records.dedup();
    append_u64(&mut encoded, dependency_records.len() as u64);
    for dependency in dependency_records {
        append_bytes(&mut encoded, &dependency);
    }

    let digest = Sha256::digest(encoded);
    let mut hex = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write;
        write!(&mut hex, "{byte:02x}").expect("writing to String cannot fail");
    }
    Sha256Digest::new(hex).expect("SHA-256 output is always a valid digest")
}

fn encode_dependency(dependency: &DependencyRequirement) -> Vec<u8> {
    let mut encoded = Vec::new();
    encoded.push(match dependency.kind {
        DependencyKind::Depends => 0,
        DependencyKind::Imports => 1,
        DependencyKind::LinkingTo => 2,
        DependencyKind::Suggests => 3,
        DependencyKind::Enhances => 4,
    });
    append_string(&mut encoded, dependency.name.as_str());
    append_source_constraint(&mut encoded, &dependency.source);
    let mut clauses = dependency
        .constraint
        .clauses
        .iter()
        .map(|clause| {
            let mut encoded = Vec::new();
            encoded.push(match clause.op {
                RelationOp::Lt => 0,
                RelationOp::Le => 1,
                RelationOp::Eq => 2,
                RelationOp::Ne => 3,
                RelationOp::Ge => 4,
                RelationOp::Gt => 5,
            });
            append_version(&mut encoded, &clause.version);
            encoded
        })
        .collect::<Vec<_>>();
    clauses.sort();
    clauses.dedup();
    append_u64(&mut encoded, clauses.len() as u64);
    for clause in clauses {
        append_bytes(&mut encoded, &clause);
    }
    encoded
}

fn append_source_constraint(encoded: &mut Vec<u8>, source: &DependencySourceConstraint) {
    match source {
        DependencySourceConstraint::Any => encoded.push(0),
        DependencySourceConstraint::Registry { namespace } => {
            encoded.push(1);
            append_string(encoded, namespace.as_str());
        }
        DependencySourceConstraint::Bioconductor { namespace, release } => {
            encoded.push(2);
            append_string(encoded, namespace.as_str());
            append_string(encoded, release.as_str());
        }
        DependencySourceConstraint::Git { repository } => {
            encoded.push(3);
            append_string(encoded, repository.as_str());
        }
        DependencySourceConstraint::Exact(identity) => {
            encoded.push(4);
            append_identity(encoded, identity);
        }
    }
}

fn append_identity(encoded: &mut Vec<u8>, identity: &ReleaseIdentity) {
    append_string(encoded, identity.name().as_str());
    match identity.provenance() {
        Provenance::RBasePackage { r_version } => {
            encoded.push(0);
            append_version(encoded, r_version);
        }
        Provenance::RegistryRelease { namespace, version } => {
            encoded.push(1);
            append_string(encoded, namespace.as_str());
            append_version(encoded, version);
        }
        Provenance::GitCommit {
            repository,
            commit,
            subdirectory,
        } => {
            encoded.push(2);
            append_string(encoded, repository.as_str());
            append_string(encoded, commit.as_str());
            append_optional_string(encoded, subdirectory.as_ref().map(|value| value.as_str()));
        }
        Provenance::BioconductorRelease {
            namespace,
            release,
            version,
        } => {
            encoded.push(3);
            append_string(encoded, namespace.as_str());
            append_string(encoded, release.as_str());
            append_version(encoded, version);
        }
        Provenance::ImmutableSource { scheme, digest } => {
            encoded.push(4);
            append_string(encoded, scheme.as_str());
            append_string(encoded, digest.as_str());
        }
    }
}

fn append_optional_string(encoded: &mut Vec<u8>, value: Option<&str>) {
    match value {
        Some(value) => {
            encoded.push(1);
            append_string(encoded, value);
        }
        None => encoded.push(0),
    }
}

fn append_string(encoded: &mut Vec<u8>, value: &str) {
    append_bytes(encoded, value.as_bytes());
}

/// Encode R versions by their semantic numeric components, never by their
/// retained display spelling.  This keeps equivalent separators, leading
/// zeroes, and trailing zero components at the same digest coordinate.
fn append_version(encoded: &mut Vec<u8>, value: &RPackageVersion) {
    let component_count = value.canonical_component_count();
    append_u64(encoded, component_count as u64);
    for component in value.components().take(component_count) {
        append_u64(encoded, u64::from(component));
    }
}

fn append_bytes(encoded: &mut Vec<u8>, value: &[u8]) {
    append_u64(encoded, value.len() as u64);
    encoded.extend_from_slice(value);
}

fn append_u64(encoded: &mut Vec<u8>, value: u64) {
    encoded.extend_from_slice(&value.to_le_bytes());
}

impl PackageRelease {
    pub fn identity(&self) -> &ReleaseIdentity {
        &self.identity
    }

    pub fn is_r_base_package(&self) -> bool {
        self.identity.provenance().is_r_base_package()
    }

    pub fn version(&self) -> &RPackageVersion {
        &self.version
    }

    pub fn metadata(&self) -> &ReleaseMetadata {
        &self.metadata
    }

    pub fn publication(&self) -> Option<&ReleasePublication> {
        self.publication.as_ref()
    }

    pub fn dependencies(&self) -> &[DependencyRequirement] {
        &self.dependencies
    }

    pub fn distributions(&self) -> &[Distribution] {
        &self.distributions
    }

    /// Returns the canonical fingerprint of validated logical/solver
    /// metadata. Arbitrary DESCRIPTION passthrough fields, repository
    /// observation facts such as publication dates, and distribution or
    /// artifact facts are intentionally excluded.
    pub fn metadata_digest(&self) -> &Sha256Digest {
        &self.metadata_digest
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
            match (existing.publication, release.publication) {
                (Some(left), Some(right)) if left != right => {
                    return Err(PackageReleaseError::ConflictingMetadata {
                        field: "publication",
                    });
                }
                (None, Some(publication)) => existing.publication = Some(publication),
                _ => {}
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
    use crate::publication::PublicationDate;
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
            publication: None,
            dependencies: vec![],
            distributions: vec![distribution],
        }
    }

    fn digest_dependency(name: &str, kind: DependencyKind) -> DependencyRequirement {
        DependencyRequirement::new(
            kind,
            package(name),
            DependencySourceConstraint::Any,
            VersionConstraint::from_clause(RelationOp::Ge, version("1.0")),
        )
    }

    #[test]
    fn metadata_digest_is_canonical_and_excludes_distribution_facts() {
        let provenance = Provenance::RegistryRelease {
            namespace: PackageNamespace::new("cran").unwrap(),
            version: version("1.0"),
        };
        let mut first = observation(
            identity(provenance.clone()),
            "1.0",
            source_distribution("a"),
        );
        first.dependencies = vec![
            digest_dependency("lattice", DependencyKind::Imports),
            digest_dependency("R", DependencyKind::Depends),
        ];
        let mut reversed = first.clone();
        reversed.dependencies.reverse();
        reversed.distributions = vec![source_distribution("different-artifact")];
        let first_release = PackageRelease::try_from(first).unwrap();
        let reversed_release = PackageRelease::try_from(reversed).unwrap();
        assert_eq!(
            first_release.metadata_digest(),
            reversed_release.metadata_digest()
        );

        let mut changed = observation(identity(provenance), "1.0", source_distribution("a"));
        changed.dependencies = vec![digest_dependency("lattice", DependencyKind::Suggests)];
        assert_ne!(
            first_release.metadata_digest(),
            PackageRelease::try_from(changed).unwrap().metadata_digest()
        );
    }

    #[test]
    fn metadata_digest_uses_semantic_versions_and_logical_sources() {
        let dependency = DependencyRequirement::new(
            DependencyKind::Imports,
            package("lattice"),
            DependencySourceConstraint::Any,
            VersionConstraint::from_clause(RelationOp::Ge, version("1.0-0")),
        );
        let equivalent_identity = identity(Provenance::RegistryRelease {
            namespace: PackageNamespace::new("cran").unwrap(),
            version: version("1.6.5"),
        });
        let mut equivalent = observation(
            equivalent_identity,
            "1.6.5",
            source_distribution("equivalent"),
        );
        equivalent.dependencies = vec![dependency.clone()];

        let raw_spelling_identity = identity(Provenance::RegistryRelease {
            namespace: PackageNamespace::new("cran").unwrap(),
            version: version("01.6-5.0"),
        });
        let mut raw_spelling = observation(
            raw_spelling_identity,
            "01.6-5.0",
            source_distribution("different-artifact"),
        );
        raw_spelling.dependencies = vec![DependencyRequirement::new(
            DependencyKind::Imports,
            package("lattice"),
            DependencySourceConstraint::Any,
            VersionConstraint::from_clause(RelationOp::Ge, version("1.0.0")),
        )];
        let equivalent_release = PackageRelease::try_from(equivalent).unwrap();
        let raw_spelling_release = PackageRelease::try_from(raw_spelling).unwrap();
        assert_eq!(
            equivalent_release.metadata_digest(),
            raw_spelling_release.metadata_digest()
        );

        let mut duplicate = observation(
            identity(Provenance::RegistryRelease {
                namespace: PackageNamespace::new("cran").unwrap(),
                version: version("1.6.5"),
            }),
            "1.6.5",
            source_distribution("duplicate"),
        );
        duplicate.dependencies = vec![dependency.clone(), dependency];
        assert_eq!(
            equivalent_release.metadata_digest(),
            PackageRelease::try_from(duplicate)
                .unwrap()
                .metadata_digest()
        );

        let namespace_changed = PackageRelease::try_from(observation(
            identity(Provenance::RegistryRelease {
                namespace: PackageNamespace::new("other").unwrap(),
                version: version("1.6.5"),
            }),
            "1.6.5",
            source_distribution("namespace"),
        ))
        .unwrap();
        assert_ne!(
            equivalent_release.metadata_digest(),
            namespace_changed.metadata_digest()
        );

        let git_identity = |commit: &str| {
            identity(Provenance::GitCommit {
                repository: NormalizedGitUrl::new("https://example.test/repo").unwrap(),
                commit: GitCommitId::new(commit).unwrap(),
                subdirectory: None,
            })
        };
        let git_release = PackageRelease::try_from(observation(
            git_identity("abcdef0123456789abcdef0123456789abcdef01"),
            "1.0.0",
            source_distribution("git-a"),
        ))
        .unwrap();
        let changed_git_release = PackageRelease::try_from(observation(
            git_identity("1234567890abcdef1234567890abcdef12345678"),
            "1.0.0",
            source_distribution("git-b"),
        ))
        .unwrap();
        assert_ne!(
            git_release.metadata_digest(),
            changed_git_release.metadata_digest()
        );

        let source_changed = PackageRelease::try_from(observation(
            identity(Provenance::RegistryRelease {
                namespace: PackageNamespace::new("cran").unwrap(),
                version: version("1.6.5"),
            }),
            "1.6.5",
            source_distribution("source-change"),
        ))
        .unwrap();
        let mut source_observation = observation(
            identity(Provenance::RegistryRelease {
                namespace: PackageNamespace::new("cran").unwrap(),
                version: version("1.6.5"),
            }),
            "1.6.5",
            source_distribution("source-change"),
        );
        source_observation.dependencies = vec![DependencyRequirement::new(
            DependencyKind::Imports,
            package("lattice"),
            DependencySourceConstraint::Registry {
                namespace: PackageNamespace::new("cran").unwrap(),
            },
            VersionConstraint::from_clause(RelationOp::Gt, version("1.0.0")),
        )];
        let changed_dependency = PackageRelease::try_from(source_observation).unwrap();
        assert_ne!(
            source_changed.metadata_digest(),
            changed_dependency.metadata_digest()
        );

        let dependency_variant = |source, op, dependency_version| {
            let mut observation = observation(
                identity(Provenance::RegistryRelease {
                    namespace: PackageNamespace::new("cran").unwrap(),
                    version: version("1.6.5"),
                }),
                "1.6.5",
                source_distribution("dependency-variant"),
            );
            observation.dependencies = vec![DependencyRequirement::new(
                DependencyKind::Imports,
                package("lattice"),
                source,
                VersionConstraint::from_clause(op, version(dependency_version)),
            )];
            PackageRelease::try_from(observation).unwrap()
        };
        assert_ne!(
            equivalent_release.metadata_digest(),
            dependency_variant(
                DependencySourceConstraint::Registry {
                    namespace: PackageNamespace::new("cran").unwrap(),
                },
                RelationOp::Ge,
                "1.0.0",
            )
            .metadata_digest()
        );
        assert_ne!(
            equivalent_release.metadata_digest(),
            dependency_variant(DependencySourceConstraint::Any, RelationOp::Gt, "1.0.0")
                .metadata_digest()
        );
        assert_ne!(
            equivalent_release.metadata_digest(),
            dependency_variant(DependencySourceConstraint::Any, RelationOp::Ge, "1.1.0")
                .metadata_digest()
        );
    }

    #[test]
    fn metadata_digest_changes_for_coordinate_version_but_not_publication() {
        let base_identity = identity(Provenance::RegistryRelease {
            namespace: PackageNamespace::new("cran").unwrap(),
            version: version("1.0"),
        });
        let base = PackageRelease::try_from(observation(
            base_identity.clone(),
            "1.0",
            source_distribution("base"),
        ))
        .unwrap();

        let mut published = observation(base_identity.clone(), "1.0", source_distribution("base"));
        published.publication = Some(ReleasePublication::new(
            PublicationDate::parse("2026-01-01").unwrap(),
        ));
        let published_release = PackageRelease::try_from(published).unwrap();
        assert_eq!(base.metadata_digest(), published_release.metadata_digest());

        let mut published_later = observation(base_identity, "1.0", source_distribution("base"));
        published_later.publication = Some(ReleasePublication::new(
            PublicationDate::parse("2026-02-01").unwrap(),
        ));
        assert_eq!(
            published_release.metadata_digest(),
            PackageRelease::try_from(published_later)
                .unwrap()
                .metadata_digest()
        );

        let changed_version = PackageRelease::try_from(observation(
            identity(Provenance::RegistryRelease {
                namespace: PackageNamespace::new("cran").unwrap(),
                version: version("1.1"),
            }),
            "1.1",
            source_distribution("base"),
        ))
        .unwrap();
        assert_ne!(base.metadata_digest(), changed_version.metadata_digest());

        let other_name = ReleaseIdentity::new(
            package("Other"),
            Provenance::RegistryRelease {
                namespace: PackageNamespace::new("cran").unwrap(),
                version: version("1.0"),
            },
        );
        let other =
            PackageRelease::try_from(observation(other_name, "1.0", source_distribution("base")))
                .unwrap();
        assert_ne!(base.metadata_digest(), other.metadata_digest());
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
    fn publication_facts_merge_unknown_and_reject_conflicting_known_values() {
        let identity = identity(Provenance::RegistryRelease {
            namespace: PackageNamespace::new("cran").unwrap(),
            version: version("1.0.0"),
        });
        let distribution = source_distribution("publication");
        let mut unknown = observation(identity.clone(), "1.0.0", distribution.clone());
        let known_date = PublicationDate::parse("2026-06-24").unwrap();
        let mut known = observation(identity.clone(), "1.0.0", distribution.clone());
        known.publication = Some(ReleasePublication::new(known_date));
        let mut aggregation = ReleaseAggregation::new();
        aggregation.observe(unknown.clone()).unwrap();
        aggregation.observe(known.clone()).unwrap();
        let mut reverse_aggregation = ReleaseAggregation::new();
        reverse_aggregation.observe(known).unwrap();
        reverse_aggregation.observe(unknown.clone()).unwrap();
        assert_eq!(
            aggregation
                .get(&identity)
                .and_then(PackageRelease::publication)
                .map(|publication| publication.date()),
            Some(known_date)
        );
        assert_eq!(
            aggregation
                .get(&identity)
                .expect("forward aggregation release")
                .metadata_digest(),
            reverse_aggregation
                .get(&identity)
                .expect("reverse aggregation release")
                .metadata_digest()
        );

        unknown.publication = Some(ReleasePublication::new(
            PublicationDate::parse("2026-06-25").unwrap(),
        ));
        let mut conflicting = ReleaseAggregation::new();
        conflicting.observe(unknown).unwrap();
        let mut other = observation(identity, "1.0.0", distribution);
        other.publication = Some(ReleasePublication::new(known_date));
        assert!(matches!(
            conflicting.observe(other),
            Err(PackageReleaseError::ConflictingMetadata {
                field: "publication"
            })
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
            publication: None,
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
            publication: None,
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

    #[test]
    fn r_base_provenance_requires_target_version_match() {
        let package = package("methods");
        let target = version("4.4.0");
        let identity = ReleaseIdentity::new(
            package.clone(),
            Provenance::RBasePackage {
                r_version: target.clone(),
            },
        );
        let release = PackageRelease::try_from(ReleaseObservation {
            identity: identity.clone(),
            observed_package: package.clone(),
            observed_version: target.clone(),
            metadata: ReleaseMetadata::new(BTreeMap::new()).unwrap(),
            publication: None,
            dependencies: Vec::new(),
            distributions: Vec::new(),
        })
        .unwrap();
        assert!(release.is_r_base_package());
        assert!(identity.provenance().is_r_base_package());

        let mismatch = PackageRelease::try_from(ReleaseObservation {
            identity,
            observed_package: package,
            observed_version: version("4.3.0"),
            metadata: ReleaseMetadata::new(BTreeMap::new()).unwrap(),
            publication: None,
            dependencies: Vec::new(),
            distributions: Vec::new(),
        });
        assert!(matches!(
            mismatch,
            Err(PackageReleaseError::ConflictingMetadata {
                field: "provenance version"
            })
        ));
    }
}
