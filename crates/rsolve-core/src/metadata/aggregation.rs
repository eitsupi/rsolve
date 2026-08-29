use std::collections::HashMap;

use crate::constraints::DeclaredDependency;
use crate::identity::{Distribution, ReleaseIdentity, canonicalize_distributions};
use crate::names::Sha256Digest;
use crate::publication::ReleasePublication;
use crate::r_versions::RPackageVersion;

use super::types::{PackageRelease, PackageReleaseError, ReleaseMetadata, ReleaseObservation};

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

    pub fn declared_dependencies(&self) -> &[DeclaredDependency] {
        &self.declared_dependencies
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
        canonicalize_distributions(&mut self.distributions);
    }

    pub(crate) fn merge_consistent(
        &mut self,
        incoming: &PackageRelease,
    ) -> Result<(), PackageReleaseError> {
        if self.version != incoming.version {
            return Err(PackageReleaseError::ConflictingMetadata { field: "version" });
        }
        if self.metadata != incoming.metadata {
            return Err(PackageReleaseError::ConflictingMetadata { field: "metadata" });
        }
        let merged_publication = match (self.publication, incoming.publication) {
            (Some(left), Some(right)) if left != right => {
                return Err(PackageReleaseError::ConflictingMetadata {
                    field: "publication",
                });
            }
            (Some(publication), _) | (_, Some(publication)) => Some(publication),
            (None, None) => None,
        };
        if self.declared_dependencies != incoming.declared_dependencies {
            return Err(PackageReleaseError::ConflictingMetadata {
                field: "declared dependencies",
            });
        }
        if self.publication.is_none() {
            self.publication = merged_publication;
        }
        self.merge_distributions(&incoming.distributions);
        Ok(())
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
            existing.merge_consistent(&release)?;
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
