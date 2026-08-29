use super::*;
use crate::{
    Artifact, ArtifactLocator, BioconductorRelease, DistributionChannel, GitCommitId,
    NormalizedGitUrl, PackageName, PackageNamespace, Provenance, RPackageVersion, ReleaseMetadata,
    ReleaseObservation, ReleasePublication, SourceArtifact,
};

fn release(name: &str, version: &str) -> PackageRelease {
    release_with_distributions(name, version, Vec::new())
}

fn release_with_publication(name: &str, version: &str, date: Option<&str>) -> PackageRelease {
    let package = PackageName::new(name).unwrap();
    let version = RPackageVersion::parse(version).unwrap();
    PackageRelease::try_from(ReleaseObservation {
        identity: ReleaseIdentity::new(
            package.clone(),
            Provenance::RegistryRelease {
                namespace: PackageNamespace::new("cran").unwrap(),
                version: version.clone(),
            },
        ),
        observed_package: package,
        observed_version: version,
        metadata: ReleaseMetadata::new(Default::default()).unwrap(),
        publication: date
            .map(|date| ReleasePublication::new(crate::PublicationDate::parse(date).unwrap())),
        declared_dependencies: Vec::new(),
        distributions: Vec::new(),
    })
    .unwrap()
}

fn release_with_distributions(
    name: &str,
    version: &str,
    distributions: Vec<Distribution>,
) -> PackageRelease {
    let package = PackageName::new(name).unwrap();
    let version = RPackageVersion::parse(version).unwrap();
    PackageRelease::try_from(ReleaseObservation {
        identity: ReleaseIdentity::new(
            package.clone(),
            Provenance::RegistryRelease {
                namespace: PackageNamespace::new("cran").unwrap(),
                version: version.clone(),
            },
        ),
        observed_package: package,
        observed_version: version,
        metadata: ReleaseMetadata::new(Default::default()).unwrap(),
        publication: None,
        declared_dependencies: Vec::new(),
        distributions,
    })
    .unwrap()
}

fn occurrence(repository: &str, rank: u64) -> RepositoryOccurrence {
    occurrence_with_distributions(repository, rank, Vec::new())
}

fn occurrence_with_distributions(
    repository: &str,
    rank: u64,
    distributions: Vec<Distribution>,
) -> RepositoryOccurrence {
    RepositoryOccurrence::new(
        RepositoryId::new(repository).unwrap(),
        RegistryId::new("registry").unwrap(),
        CandidateAvailability::Available,
        CandidateCurrentness::Current,
        RepositoryRank::new(rank),
        distributions,
    )
    .unwrap()
}

fn distribution(locator: &str) -> Distribution {
    Distribution {
        registry: RegistryId::new("registry").unwrap(),
        channel: DistributionChannel::new("source").unwrap(),
        snapshot: None,
        artifacts: vec![Artifact::Source(SourceArtifact {
            locator: ArtifactLocator::new(locator).unwrap(),
            upstream_checksums: Vec::new(),
            size: None,
        })],
        observed_metadata: Default::default(),
    }
}

fn bioconductor_release(name: &str, version: &str) -> PackageRelease {
    let package = PackageName::new(name).unwrap();
    let version = RPackageVersion::parse(version).unwrap();
    PackageRelease::try_from(ReleaseObservation {
        identity: ReleaseIdentity::new(
            package.clone(),
            Provenance::BioconductorRelease {
                namespace: PackageNamespace::new("bioc").unwrap(),
                release: BioconductorRelease::new("3.20").unwrap(),
                version: version.clone(),
            },
        ),
        observed_package: package,
        observed_version: version,
        metadata: ReleaseMetadata::new(Default::default()).unwrap(),
        publication: None,
        declared_dependencies: Vec::new(),
        distributions: Vec::new(),
    })
    .unwrap()
}

fn git_release(name: &str, version: &str) -> PackageRelease {
    let package = PackageName::new(name).unwrap();
    let version = RPackageVersion::parse(version).unwrap();
    PackageRelease::try_from(ReleaseObservation {
        identity: ReleaseIdentity::new(
            package.clone(),
            Provenance::GitCommit {
                repository: NormalizedGitUrl::new("https://example.org/project.git").unwrap(),
                commit: GitCommitId::new("0123456789012345678901234567890123456789").unwrap(),
                subdirectory: None,
            },
        ),
        observed_package: package,
        observed_version: version,
        metadata: ReleaseMetadata::new(Default::default()).unwrap(),
        publication: None,
        declared_dependencies: Vec::new(),
        distributions: Vec::new(),
    })
    .unwrap()
}

#[test]
fn merge_is_identity_keyed_and_occurrence_order_is_canonical() {
    let first = PreparedCandidate::new(
        release("foo", "1.0.0"),
        NonRepositoryExposure::None,
        vec![occurrence("two", 1)],
    )
    .unwrap();
    let second = PreparedCandidate::new(
        release("foo", "1.0.0"),
        NonRepositoryExposure::None,
        vec![occurrence("one", 0)],
    )
    .unwrap();
    let merged = first.merge(second).unwrap();
    let installed = SolverKey::InstalledName(PackageName::new("foo").unwrap());
    assert_eq!(merged.occurrences()[0].repository().as_str(), "one");
    assert_eq!(
        merged.repository_rank_for(&installed),
        Some(RepositoryRank::new(0))
    );
    assert!(merged.is_eligible_for(&installed));
    assert!(merged.is_eligible_for(&SolverKey::Repository {
        repository: RepositoryId::new("one").unwrap(),
        name: PackageName::new("foo").unwrap(),
    }));
    assert!(!merged.is_eligible_for(&SolverKey::Repository {
        repository: RepositoryId::new("missing").unwrap(),
        name: PackageName::new("foo").unwrap(),
    }));
}

#[test]
fn metadata_only_occurrence_never_makes_candidate_eligible() {
    let candidate = PreparedCandidate::new(
        release("foo", "1.0.0"),
        NonRepositoryExposure::None,
        vec![
            RepositoryOccurrence::new(
                RepositoryId::new("enrichment").unwrap(),
                RegistryId::new("registry").unwrap(),
                CandidateAvailability::MetadataOnly,
                CandidateCurrentness::Historical,
                RepositoryRank::new(0),
                Vec::new(),
            )
            .unwrap(),
        ],
    )
    .unwrap();
    let subject = SolverKey::InstalledName(PackageName::new("foo").unwrap());
    assert!(!candidate.is_eligible_for(&subject));
    assert_eq!(candidate.repository_rank_for(&subject), None);
    let set = PreparedCandidateSet::from_candidates([candidate]).unwrap();
    assert_eq!(set.candidates().len(), 1);
    assert!(set.applicable(&subject).is_empty());
}

#[test]
fn prepared_candidate_set_enriches_unknown_publication_before_solving() {
    let unknown = PreparedCandidate::new(
        release_with_publication("foo", "1.0.0", None),
        NonRepositoryExposure::None,
        vec![occurrence("cran", 0)],
    )
    .unwrap();
    let known = PreparedCandidate::new(
        release_with_publication("foo", "1.0.0", Some("2026-01-02")),
        NonRepositoryExposure::None,
        vec![occurrence("cran", 0)],
    )
    .unwrap();
    let set = PreparedCandidateSet::from_candidates([unknown, known]).unwrap();
    assert_eq!(
        set.candidates()[0]
            .release()
            .publication()
            .unwrap()
            .date()
            .to_string(),
        "2026-01-02"
    );
}

#[test]
fn direct_candidate_can_be_eligible_without_occurrence() {
    let candidate = PreparedCandidate::new(
        release("foo", "1.0.0"),
        NonRepositoryExposure::ExactOnly,
        Vec::new(),
    )
    .unwrap();
    assert_eq!(
        candidate.non_repository_exposure(),
        NonRepositoryExposure::ExactOnly
    );
    let installed = SolverKey::InstalledName(PackageName::new("foo").unwrap());
    assert!(!candidate.is_eligible_for(&installed));
    assert!(candidate.is_eligible_for(&SolverKey::Exact(candidate.identity().clone())));
    assert_eq!(candidate.repository_rank_for(&installed), None);
}

#[test]
fn same_repository_conflicting_occurrences_are_rejected() {
    let first = PreparedCandidate::new(
        release("foo", "1.0.0"),
        NonRepositoryExposure::None,
        vec![occurrence("one", 0)],
    )
    .unwrap();
    let conflicting = PreparedCandidate::new(
        release("foo", "1.0.0"),
        NonRepositoryExposure::None,
        vec![
            RepositoryOccurrence::new(
                RepositoryId::new("one").unwrap(),
                RegistryId::new("registry").unwrap(),
                CandidateAvailability::MetadataOnly,
                CandidateCurrentness::Current,
                RepositoryRank::new(0),
                Vec::new(),
            )
            .unwrap(),
        ],
    )
    .unwrap();
    assert!(matches!(
        first.merge(conflicting),
        Err(PreparedCandidateError::ConflictingOccurrence { .. })
    ));
}

#[test]
fn occurrence_conflicts_are_detected_when_repository_entries_interleave_by_rank() {
    let candidate = PreparedCandidate::new(
        release("foo", "1.0.0"),
        NonRepositoryExposure::None,
        vec![occurrence("a", 0), occurrence("b", 1), occurrence("a", 2)],
    );
    assert!(matches!(
        candidate,
        Err(PreparedCandidateError::ConflictingOccurrence { repository })
            if repository.as_str() == "a"
    ));
}

#[test]
fn source_views_filter_by_provenance_and_exact_identity() {
    let candidate = PreparedCandidate::new(
        bioconductor_release("foo", "1.0.0"),
        NonRepositoryExposure::None,
        vec![occurrence("bioc", 0)],
    )
    .unwrap();
    let name = PackageName::new("foo").unwrap();
    assert!(candidate.is_eligible_for(&SolverKey::Bioconductor {
        namespace: PackageNamespace::new("bioc").unwrap(),
        release: BioconductorRelease::new("3.20").unwrap(),
        name: name.clone(),
    }));
    assert!(!candidate.is_eligible_for(&SolverKey::Registry {
        namespace: PackageNamespace::new("cran").unwrap(),
        name: name.clone(),
    }));
    assert!(!candidate.is_eligible_for(&SolverKey::Bioconductor {
        namespace: PackageNamespace::new("bioc").unwrap(),
        release: BioconductorRelease::new("3.21").unwrap(),
        name,
    }));
}

#[test]
fn candidate_set_preserves_distinct_identities_and_merges_equal_ones() {
    let first = PreparedCandidate::new(
        release("foo", "1.0.0"),
        NonRepositoryExposure::None,
        vec![occurrence("one", 0)],
    )
    .unwrap();
    let second_identity = PreparedCandidate::new(
        release("foo", "2.0.0"),
        NonRepositoryExposure::None,
        vec![occurrence("two", 1)],
    )
    .unwrap();
    let same_identity = PreparedCandidate::new(
        release("foo", "1.0.0"),
        NonRepositoryExposure::None,
        vec![occurrence("two", 1)],
    )
    .unwrap();
    let set =
        PreparedCandidateSet::from_candidates([first, second_identity, same_identity]).unwrap();
    assert_eq!(set.candidates().len(), 2);
    assert_eq!(
        set.applicable(&SolverKey::Repository {
            repository: RepositoryId::new("two").unwrap(),
            name: PackageName::new("foo").unwrap(),
        })
        .len(),
        2
    );
}

#[test]
fn candidate_set_reports_same_identity_metadata_conflicts() {
    let first = PreparedCandidate::new(
        git_release("foo", "1.0.0"),
        NonRepositoryExposure::ExactOnly,
        Vec::new(),
    )
    .unwrap();
    let second = PreparedCandidate::new(
        git_release("foo", "2.0.0"),
        NonRepositoryExposure::ExactOnly,
        Vec::new(),
    )
    .unwrap();
    assert!(matches!(
        PreparedCandidateSet::from_candidates([first, second]),
        Err(PreparedCandidateSetError::Candidate(
            PreparedCandidateError::ConflictingReleaseMetadata { field: "version" }
        ))
    ));
}

#[test]
fn candidate_set_keeps_existing_candidate_when_merge_fails() {
    let first = PreparedCandidate::new(
        git_release("foo", "1.0.0"),
        NonRepositoryExposure::ExactOnly,
        Vec::new(),
    )
    .unwrap();
    let conflicting = PreparedCandidate::new(
        git_release("foo", "2.0.0"),
        NonRepositoryExposure::ExactOnly,
        Vec::new(),
    )
    .unwrap();
    let mut set = PreparedCandidateSet::from_candidates([first.clone()]).unwrap();

    assert!(set.insert(conflicting).is_err());
    assert_eq!(set.candidates().len(), 1);
    assert_eq!(set.candidates()[0].identity(), first.identity());
}

#[test]
fn same_repository_disjoint_distributions_are_merged_canonically() {
    let source = distribution("source.tar.gz");
    let binary = distribution("binary.zip");
    let first = PreparedCandidate::new(
        release_with_distributions("foo", "1.0.0", vec![source.clone()]),
        NonRepositoryExposure::None,
        vec![occurrence_with_distributions(
            "one",
            0,
            vec![source.clone()],
        )],
    )
    .unwrap();
    let second = PreparedCandidate::new(
        release_with_distributions("foo", "1.0.0", vec![binary.clone()]),
        NonRepositoryExposure::None,
        vec![occurrence_with_distributions(
            "one",
            0,
            vec![binary.clone()],
        )],
    )
    .unwrap();

    let merged = first.merge(second).unwrap();
    assert_eq!(merged.release().distributions().len(), 2);
    assert_eq!(merged.occurrences().len(), 1);
    assert_eq!(merged.occurrences()[0].distributions().len(), 2);
    assert!(merged.occurrences()[0].distributions().contains(&source));
    assert!(merged.occurrences()[0].distributions().contains(&binary));
}

#[test]
fn distribution_union_is_independent_of_input_order_and_repository_local() {
    let source = distribution("source.tar.gz");
    let binary = distribution("binary.zip");
    let left = PreparedCandidate::new(
        release_with_distributions("foo", "1.0.0", vec![source.clone(), binary.clone()]),
        NonRepositoryExposure::None,
        vec![
            occurrence_with_distributions("one", 0, vec![source.clone()]),
            occurrence_with_distributions("two", 1, vec![binary.clone()]),
        ],
    )
    .unwrap();
    let right = PreparedCandidate::new(
        release_with_distributions("foo", "1.0.0", vec![binary.clone(), source.clone()]),
        NonRepositoryExposure::None,
        vec![
            occurrence_with_distributions("two", 1, vec![binary]),
            occurrence_with_distributions("one", 0, vec![source]),
        ],
    )
    .unwrap();

    assert_eq!(
        left.release().distributions(),
        right.release().distributions()
    );
    assert_eq!(left.occurrences(), right.occurrences());
    assert_eq!(left.occurrences()[0].distributions().len(), 1);
    assert_eq!(left.occurrences()[1].distributions().len(), 1);
    assert_ne!(
        left.occurrences()[0].distributions(),
        left.occurrences()[1].distributions()
    );
}

#[test]
fn occurrence_rejects_distribution_from_another_registry() {
    let distribution = Distribution {
        registry: RegistryId::new("other-registry").unwrap(),
        channel: DistributionChannel::new("source").unwrap(),
        snapshot: None,
        artifacts: Vec::new(),
        observed_metadata: Default::default(),
    };
    assert!(matches!(
        RepositoryOccurrence::new(
            RepositoryId::new("one").unwrap(),
            RegistryId::new("registry").unwrap(),
            CandidateAvailability::Available,
            CandidateCurrentness::Current,
            RepositoryRank::new(0),
            vec![distribution],
        ),
        Err(RepositoryOccurrenceError::DistributionRegistryMismatch { .. })
    ));
}
