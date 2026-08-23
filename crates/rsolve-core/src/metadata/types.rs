use std::error::Error;
use std::fmt;

use crate::constraints::{DependencyRequirement, DependencySourceConstraint};
use crate::identity::{Distribution, Provenance, ReleaseIdentity};
use crate::names::{PackageName, Sha256Digest};
use crate::publication::ReleasePublication;
use crate::r_versions::RPackageVersion;

use super::digest::canonical_metadata_digest;

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
    pub(super) identity: ReleaseIdentity,
    pub(super) version: RPackageVersion,
    pub(super) metadata: ReleaseMetadata,
    pub(super) publication: Option<ReleasePublication>,
    pub(super) dependencies: Vec<DependencyRequirement>,
    pub(super) distributions: Vec<Distribution>,
    pub(super) metadata_digest: Sha256Digest,
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
