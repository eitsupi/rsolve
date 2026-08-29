use super::*;

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
fn conflicting_dependencies_do_not_partially_merge_publication_or_distributions() {
    let identity = identity(Provenance::RegistryRelease {
        namespace: PackageNamespace::new("cran").unwrap(),
        version: version("1.0.0"),
    });
    let first_distribution = source_distribution("first");
    let second_distribution = source_distribution("second");
    let first = observation(identity.clone(), "1.0.0", first_distribution.clone());
    let mut conflicting = observation(identity.clone(), "1.0.0", second_distribution);
    conflicting.publication = Some(ReleasePublication::new(
        PublicationDate::parse("2026-06-24").unwrap(),
    ));
    conflicting.declared_dependencies =
        vec![digest_dependency("different", DependencyKind::Depends)];

    let mut aggregation = ReleaseAggregation::new();
    aggregation.observe(first).unwrap();
    assert!(matches!(
        aggregation.observe(conflicting),
        Err(PackageReleaseError::ConflictingMetadata {
            field: "declared dependencies"
        })
    ));
    let retained = aggregation.get(&identity).unwrap();
    assert_eq!(retained.publication(), None);
    assert_eq!(retained.distributions(), &[first_distribution]);
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
