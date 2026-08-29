use std::error::Error;
use std::fmt;

use crate::identity::canonicalize_distributions;
use crate::{
    Distribution, PackageRelease, PackageReleaseError, Provenance, RegistryId, ReleaseIdentity,
    RepositoryId, RepositoryRank, SolverKey,
};

/// Whether a repository entry made a release visible as a candidate.
/// Metadata enrichment never upgrades `MetadataOnly` to `Available`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CandidateAvailability {
    Available,
    MetadataOnly,
}

/// The repository-local currentness fact for one observed release.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CandidateCurrentness {
    Current,
    Historical,
}

/// Facts about one release occurrence in one manifest repository entry.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct RepositoryOccurrence {
    repository: RepositoryId,
    registry: RegistryId,
    availability: CandidateAvailability,
    currentness: CandidateCurrentness,
    rank: RepositoryRank,
    distributions: Vec<Distribution>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RepositoryOccurrenceError {
    DistributionRegistryMismatch {
        repository: RepositoryId,
        expected: RegistryId,
        found: RegistryId,
    },
}

impl fmt::Display for RepositoryOccurrenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DistributionRegistryMismatch {
                repository,
                expected,
                found,
            } => write!(
                formatter,
                "distribution for repository {repository} belongs to registry {found}, expected {expected}"
            ),
        }
    }
}

impl Error for RepositoryOccurrenceError {}

impl RepositoryOccurrence {
    pub fn new(
        repository: RepositoryId,
        registry: RegistryId,
        availability: CandidateAvailability,
        currentness: CandidateCurrentness,
        rank: RepositoryRank,
        distributions: Vec<Distribution>,
    ) -> Result<Self, RepositoryOccurrenceError> {
        validate_distribution_registries(&repository, &registry, &distributions)?;
        let mut occurrence = Self {
            repository,
            registry,
            availability,
            currentness,
            rank,
            distributions,
        };
        canonicalize_distributions(&mut occurrence.distributions);
        Ok(occurrence)
    }

    pub fn repository(&self) -> &RepositoryId {
        &self.repository
    }

    pub fn registry(&self) -> &RegistryId {
        &self.registry
    }

    pub fn availability(&self) -> CandidateAvailability {
        self.availability
    }

    pub fn currentness(&self) -> CandidateCurrentness {
        self.currentness
    }

    pub fn rank(&self) -> RepositoryRank {
        self.rank
    }

    pub fn distributions(&self) -> &[Distribution] {
        &self.distributions
    }

    fn same_facts(&self, other: &Self) -> bool {
        self.repository == other.repository
            && self.registry == other.registry
            && self.availability == other.availability
            && self.currentness == other.currentness
            && self.rank == other.rank
    }

    fn merge_distributions(&mut self, other: &Self) {
        self.distributions
            .extend(other.distributions.iter().cloned());
        canonicalize_distributions(&mut self.distributions);
    }
}

/// A validated release together with the repository observations that make it
/// visible to a source-scoped resolver view.
#[derive(Clone, Debug)]
pub struct PreparedCandidate {
    release: PackageRelease,
    direct: bool,
    occurrences: Vec<RepositoryOccurrence>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PreparedCandidateError {
    Release(PackageReleaseError),
    IdentityMismatch,
    ConflictingReleaseMetadata { field: &'static str },
    ConflictingOccurrence { repository: RepositoryId },
    InvalidOccurrence(RepositoryOccurrenceError),
    DistributionNotInRelease { repository: RepositoryId },
    ReleaseDistributionWithoutOccurrence,
    MissingRepositoryOccurrence,
}

impl fmt::Display for PreparedCandidateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Release(error) => error.fmt(formatter),
            Self::IdentityMismatch => {
                formatter.write_str("prepared candidates have different identities")
            }
            Self::ConflictingReleaseMetadata { field } => {
                write!(formatter, "conflicting release metadata in {field}")
            }
            Self::ConflictingOccurrence { repository } => {
                write!(
                    formatter,
                    "conflicting occurrences for repository {repository}"
                )
            }
            Self::InvalidOccurrence(error) => error.fmt(formatter),
            Self::DistributionNotInRelease { repository } => write!(
                formatter,
                "occurrence for repository {repository} contains an unprojected distribution"
            ),
            Self::ReleaseDistributionWithoutOccurrence => formatter.write_str(
                "prepared release contains a distribution absent from its repository occurrences",
            ),
            Self::MissingRepositoryOccurrence => formatter
                .write_str("a non-direct prepared candidate requires a repository occurrence"),
        }
    }
}

impl Error for PreparedCandidateError {}

impl From<PackageReleaseError> for PreparedCandidateError {
    fn from(error: PackageReleaseError) -> Self {
        Self::Release(error)
    }
}

impl From<RepositoryOccurrenceError> for PreparedCandidateError {
    fn from(error: RepositoryOccurrenceError) -> Self {
        Self::InvalidOccurrence(error)
    }
}

impl PreparedCandidate {
    pub fn new(
        release: PackageRelease,
        direct: bool,
        occurrences: Vec<RepositoryOccurrence>,
    ) -> Result<Self, PreparedCandidateError> {
        let mut candidate = Self {
            release,
            direct,
            occurrences,
        };
        candidate.normalize_and_validate()?;
        Ok(candidate)
    }

    pub fn release(&self) -> &PackageRelease {
        &self.release
    }

    pub fn direct(&self) -> bool {
        self.direct
    }

    pub fn occurrences(&self) -> &[RepositoryOccurrence] {
        &self.occurrences
    }

    pub fn available_occurrences(&self) -> impl Iterator<Item = &RepositoryOccurrence> {
        self.occurrences
            .iter()
            .filter(|occurrence| occurrence.availability == CandidateAvailability::Available)
    }

    pub fn applicable_occurrences<'a>(
        &'a self,
        subject: &'a SolverKey,
    ) -> Vec<&'a RepositoryOccurrence> {
        let Some(subject_name) = subject_name(subject) else {
            return Vec::new();
        };
        if self.release.identity().name() != subject_name {
            return Vec::new();
        }
        if let SolverKey::Exact(identity) = subject
            && self.identity() != identity
        {
            return Vec::new();
        }
        if !provenance_matches(self.release.identity().provenance(), subject) {
            return Vec::new();
        }
        self.available_occurrences()
            .filter(|occurrence| match subject {
                SolverKey::Repository { repository, .. } => occurrence.repository() == repository,
                SolverKey::InstalledName(_)
                | SolverKey::Registry { .. }
                | SolverKey::Bioconductor { .. }
                | SolverKey::Exact(_)
                | SolverKey::R => true,
            })
            .collect()
    }

    pub fn is_eligible_for(&self, subject: &SolverKey) -> bool {
        let Some(subject_name) = subject_name(subject) else {
            return false;
        };
        if self.release.identity().name() != subject_name {
            return false;
        }
        if let SolverKey::Exact(identity) = subject {
            return self.identity() == identity
                && (self.direct || self.available_occurrences().next().is_some());
        }
        !self.applicable_occurrences(subject).is_empty()
    }

    pub fn repository_rank_for(&self, subject: &SolverKey) -> Option<RepositoryRank> {
        self.applicable_occurrences(subject)
            .into_iter()
            .map(RepositoryOccurrence::rank)
            .min()
    }

    pub fn identity(&self) -> &ReleaseIdentity {
        self.release.identity()
    }

    /// Merges observations of one identity without promoting metadata-only
    /// occurrences or copying distributions between repository entries.
    pub fn merge(mut self, incoming: Self) -> Result<Self, PreparedCandidateError> {
        if self.identity() != incoming.identity() {
            return Err(PreparedCandidateError::IdentityMismatch);
        }
        self.release
            .merge_consistent(&incoming.release)
            .map_err(map_release_merge_error)?;
        self.direct |= incoming.direct;
        self.occurrences.extend(incoming.occurrences);
        self.normalize_and_validate()?;
        Ok(self)
    }

    fn normalize_and_validate(&mut self) -> Result<(), PreparedCandidateError> {
        self.occurrences.sort_by(|left, right| {
            left.repository
                .cmp(&right.repository)
                .then_with(|| left.rank.cmp(&right.rank))
                .then_with(|| left.registry.cmp(&right.registry))
                .then_with(|| left.availability.cmp(&right.availability))
                .then_with(|| left.currentness.cmp(&right.currentness))
        });
        let mut normalized: Vec<RepositoryOccurrence> = Vec::with_capacity(self.occurrences.len());
        for occurrence in self.occurrences.drain(..) {
            validate_distribution_registries(
                &occurrence.repository,
                &occurrence.registry,
                &occurrence.distributions,
            )?;
            if let Some(existing) = normalized.last_mut()
                && existing.repository == occurrence.repository
            {
                if !existing.same_facts(&occurrence) {
                    return Err(PreparedCandidateError::ConflictingOccurrence {
                        repository: occurrence.repository,
                    });
                }
                existing.merge_distributions(&occurrence);
                continue;
            }
            normalized.push(occurrence);
        }
        normalized.sort_by(|left, right| {
            left.rank
                .cmp(&right.rank)
                .then_with(|| left.repository.cmp(&right.repository))
                .then_with(|| left.registry.cmp(&right.registry))
                .then_with(|| left.availability.cmp(&right.availability))
                .then_with(|| left.currentness.cmp(&right.currentness))
        });
        self.occurrences = normalized;

        if !self.direct && self.occurrences.is_empty() {
            return Err(PreparedCandidateError::MissingRepositoryOccurrence);
        }

        let occurrence_distributions = self
            .occurrences
            .iter()
            .flat_map(|occurrence| occurrence.distributions.iter());
        for occurrence in &self.occurrences {
            if occurrence
                .distributions
                .iter()
                .any(|distribution| !self.release.distributions().contains(distribution))
            {
                return Err(PreparedCandidateError::DistributionNotInRelease {
                    repository: occurrence.repository.clone(),
                });
            }
        }
        if !self.direct
            && self.release.distributions().iter().any(|distribution| {
                !occurrence_distributions
                    .clone()
                    .any(|candidate| candidate == distribution)
            })
        {
            return Err(PreparedCandidateError::ReleaseDistributionWithoutOccurrence);
        }
        Ok(())
    }
}

/// Identity-keyed union of prepared candidates from multiple repository
/// entries. Distinct provenance remains distinct; only equal identities merge.
#[derive(Clone, Debug, Default)]
pub struct PreparedCandidateSet {
    candidates: std::collections::HashMap<ReleaseIdentity, PreparedCandidate>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PreparedCandidateSetError {
    Candidate(PreparedCandidateError),
}

impl fmt::Display for PreparedCandidateSetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Candidate(error) => error.fmt(formatter),
        }
    }
}

impl Error for PreparedCandidateSetError {}

impl From<PreparedCandidateError> for PreparedCandidateSetError {
    fn from(error: PreparedCandidateError) -> Self {
        Self::Candidate(error)
    }
}

impl PreparedCandidateSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(
        &mut self,
        candidate: PreparedCandidate,
    ) -> Result<(), PreparedCandidateSetError> {
        if let Some(existing) = self.candidates.get(candidate.identity()) {
            let merged = existing.clone().merge(candidate)?;
            self.candidates.insert(merged.identity().clone(), merged);
        } else {
            self.candidates
                .insert(candidate.identity().clone(), candidate);
        }
        Ok(())
    }

    pub fn from_candidates(
        candidates: impl IntoIterator<Item = PreparedCandidate>,
    ) -> Result<Self, PreparedCandidateSetError> {
        let mut set = Self::new();
        for candidate in candidates {
            set.insert(candidate)?;
        }
        Ok(set)
    }

    /// Returns all candidates in unspecified order. Ordering and preference
    /// are resolver policy, not part of this union's identity semantics.
    pub fn candidates(&self) -> Vec<&PreparedCandidate> {
        // Hash-map iteration order is deliberately unspecified. Candidate
        // preference and solver ordering belong to the resolver layer.
        self.candidates.values().collect()
    }

    pub fn applicable<'a>(&'a self, subject: &'a SolverKey) -> Vec<&'a PreparedCandidate> {
        self.candidates()
            .into_iter()
            .filter(|candidate| candidate.is_eligible_for(subject))
            .collect()
    }
}

fn subject_name(subject: &SolverKey) -> Option<&crate::PackageName> {
    match subject {
        SolverKey::Registry { name, .. }
        | SolverKey::Bioconductor { name, .. }
        | SolverKey::Repository { name, .. }
        | SolverKey::InstalledName(name) => Some(name),
        SolverKey::Exact(identity) => Some(identity.name()),
        SolverKey::R => None,
    }
}

fn provenance_matches(provenance: &Provenance, subject: &SolverKey) -> bool {
    match subject {
        SolverKey::Registry { namespace, .. } => matches!(
            provenance,
            Provenance::RegistryRelease { namespace: candidate, .. } if candidate == namespace
        ),
        SolverKey::Bioconductor {
            namespace, release, ..
        } => matches!(
            provenance,
            Provenance::BioconductorRelease {
                namespace: candidate_namespace,
                release: candidate_release,
                ..
            } if candidate_namespace == namespace && candidate_release == release
        ),
        SolverKey::Exact(_) | SolverKey::Repository { .. } | SolverKey::InstalledName(_) => true,
        SolverKey::R => false,
    }
}

fn validate_distribution_registries(
    repository: &RepositoryId,
    registry: &RegistryId,
    distributions: &[Distribution],
) -> Result<(), RepositoryOccurrenceError> {
    for distribution in distributions {
        if &distribution.registry != registry {
            return Err(RepositoryOccurrenceError::DistributionRegistryMismatch {
                repository: repository.clone(),
                expected: registry.clone(),
                found: distribution.registry.clone(),
            });
        }
    }
    Ok(())
}

fn map_release_merge_error(error: PackageReleaseError) -> PreparedCandidateError {
    match error {
        PackageReleaseError::ConflictingMetadata { field } => {
            PreparedCandidateError::ConflictingReleaseMetadata { field }
        }
        other => PreparedCandidateError::Release(other),
    }
}

#[cfg(test)]
#[path = "candidates/tests.rs"]
mod tests;
