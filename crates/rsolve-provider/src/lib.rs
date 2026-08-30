//! External registry and provider access adapters for rsolve.
//!
//! This crate must not contain resolver policy, repository materialization, or
//! CLI orchestration.

pub mod cran;
pub mod r_universe;
pub(crate) mod snapshot;

pub use snapshot::{ReadOnlySnapshotCandidateLoader, SnapshotStore, SnapshotStoreError};

use rsolve_core::{CandidateCurrentness, PackageRelease, QuarantinedCandidate};

/// A provider-owned observation before repository context is composed.
#[derive(Clone, Debug)]
pub struct RawCandidateObservation {
    release: PackageRelease,
    currentness: CandidateCurrentness,
}

impl RawCandidateObservation {
    pub fn new(release: PackageRelease, currentness: CandidateCurrentness) -> Self {
        Self {
            release,
            currentness,
        }
    }

    pub fn release(&self) -> &PackageRelease {
        &self.release
    }

    pub fn currentness(&self) -> CandidateCurrentness {
        self.currentness
    }
}

/// Raw provider candidates and quarantined coordinates.
#[derive(Clone, Debug)]
pub struct RawCandidateLoadResult {
    observations: Vec<RawCandidateObservation>,
    quarantined: Vec<QuarantinedCandidate>,
}

impl RawCandidateLoadResult {
    pub fn new(
        observations: Vec<RawCandidateObservation>,
        quarantined: Vec<QuarantinedCandidate>,
    ) -> Self {
        Self {
            observations,
            quarantined,
        }
    }

    pub fn into_parts(self) -> (Vec<RawCandidateObservation>, Vec<QuarantinedCandidate>) {
        (self.observations, self.quarantined)
    }

    pub fn observations(&self) -> &[RawCandidateObservation] {
        &self.observations
    }

    /// Returns cloned releases for provider-owned refresh bookkeeping. This
    /// view is not used by the resolver adapter, which consumes observations.
    #[cfg(test)]
    pub(crate) fn candidates(&self) -> Vec<PackageRelease> {
        self.observations
            .iter()
            .map(|observation| observation.release.clone())
            .collect()
    }

    pub fn quarantined(&self) -> &[QuarantinedCandidate] {
        &self.quarantined
    }
}

/// Derive the provider's currentness fact from immutable distribution evidence.
/// Current CRAN distributions have no archive snapshot; historical releases do.
pub(crate) fn currentness_for_release(release: &PackageRelease) -> CandidateCurrentness {
    if release
        .distributions()
        .iter()
        .any(|distribution| distribution.snapshot.is_none())
    {
        CandidateCurrentness::Current
    } else {
        CandidateCurrentness::Historical
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsolve_core::{
        Distribution, DistributionChannel, DistributionMetadata, PackageName, PackageNamespace,
        Provenance, RegistryId, ReleaseIdentity, ReleaseMetadata, ReleaseObservation, SnapshotId,
    };

    fn release(snapshot: Option<&str>) -> PackageRelease {
        release_with_snapshots(&[snapshot])
    }

    fn release_with_snapshots(snapshots: &[Option<&str>]) -> PackageRelease {
        let name = PackageName::new("fixture").unwrap();
        let version = rsolve_core::RPackageVersion::parse("1.0.0").unwrap();
        PackageRelease::try_from(ReleaseObservation {
            identity: ReleaseIdentity::new(
                name.clone(),
                Provenance::RegistryRelease {
                    namespace: PackageNamespace::new("cran").unwrap(),
                    version: version.clone(),
                },
            ),
            observed_package: name,
            observed_version: version,
            metadata: ReleaseMetadata::default(),
            publication: None,
            declared_dependencies: Vec::new(),
            distributions: snapshots
                .iter()
                .enumerate()
                .map(|(index, snapshot)| Distribution {
                    registry: RegistryId::new("cran").unwrap(),
                    channel: DistributionChannel::new(if index == 0 { "source" } else { "binary" })
                        .unwrap(),
                    snapshot: snapshot.map(|value| SnapshotId::new(value).unwrap()),
                    artifacts: Vec::new(),
                    observed_metadata: DistributionMetadata::default(),
                })
                .collect(),
        })
        .unwrap()
    }

    #[test]
    fn raw_release_currentness_preserves_current_and_historical_observations() {
        assert_eq!(
            currentness_for_release(&release(None)),
            CandidateCurrentness::Current
        );
        assert_eq!(
            currentness_for_release(&release(Some("2026-01-01"))),
            CandidateCurrentness::Historical
        );
        assert_eq!(
            currentness_for_release(&release_with_snapshots(&[None, Some("2026-01-01")])),
            CandidateCurrentness::Current
        );
    }
}
