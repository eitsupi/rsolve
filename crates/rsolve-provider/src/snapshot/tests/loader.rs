use super::*;

#[test]
fn read_only_loader_maps_present_and_missing_states_without_io() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("present.redb");
    SnapshotGenerationBuilder::new(present_input(), &path)
        .build()
        .unwrap();
    let loader =
        ReadOnlySnapshotCandidateLoader::open(&path, RegistryId::new("cran").unwrap()).unwrap();
    let releases = loader
        .releases(&SolverKey::InstalledName(PackageName::new("foo").unwrap()))
        .unwrap();
    assert_eq!(releases.len(), 1);
    assert_eq!(releases[0].version().to_string(), "1.0");
    let missing = loader
        .releases(&SolverKey::InstalledName(PackageName::new("bar").unwrap()))
        .unwrap_err();
    assert_eq!(missing.category(), CandidateLoadErrorCategory::NotFound);
    let unsupported = loader.releases(&SolverKey::R).unwrap_err();
    assert_eq!(unsupported.category(), CandidateLoadErrorCategory::NotFound);
}

#[test]
fn read_only_loader_maps_partial_and_incomplete_missing_states() {
    let dir = tempdir().unwrap();
    let mut partial = input();
    partial.coverage.state = "partial".into();
    let partial_path = dir.path().join("partial.redb");
    SnapshotGenerationBuilder::new(partial, &partial_path)
        .build()
        .unwrap();
    let partial_loader =
        ReadOnlySnapshotCandidateLoader::open(&partial_path, RegistryId::new("cran").unwrap())
            .unwrap();
    let partial_error = partial_loader
        .releases(&SolverKey::InstalledName(PackageName::new("bar").unwrap()))
        .unwrap_err();
    assert_eq!(
        partial_error.category(),
        CandidateLoadErrorCategory::MetadataInvalid
    );

    let incomplete_path = dir.path().join("incomplete.redb");
    SnapshotGenerationBuilder::new(input(), &incomplete_path)
        .build()
        .unwrap();
    let incomplete_loader =
        ReadOnlySnapshotCandidateLoader::open(&incomplete_path, RegistryId::new("cran").unwrap())
            .unwrap();
    let incomplete_error = incomplete_loader
        .releases(&SolverKey::InstalledName(PackageName::new("foo").unwrap()))
        .unwrap_err();
    assert_eq!(
        incomplete_error.category(),
        CandidateLoadErrorCategory::MetadataInvalid
    );
}

#[test]
fn read_only_loader_reports_all_quarantined_history_as_metadata_invalid() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("quarantined.redb");
    let mut quarantined = input();
    quarantined.histories[0].observations[0].axes.semantics = SemanticsStateV1::Invalid;
    quarantined.histories[0].decisions = vec![DecisionV1 {
        code: DecisionCodeV1::QuarantinedRelease,
        observation_ids: vec![0],
        detail: "release was quarantined after semantic validation".into(),
    }];
    SnapshotGenerationBuilder::new(quarantined, &path)
        .build()
        .unwrap();
    let loader =
        ReadOnlySnapshotCandidateLoader::open(&path, RegistryId::new("cran").unwrap()).unwrap();
    let error = loader
        .releases(&SolverKey::InstalledName(PackageName::new("foo").unwrap()))
        .unwrap_err();
    assert_eq!(
        error.category(),
        CandidateLoadErrorCategory::MetadataInvalid
    );
    assert!(error.diagnostic().contains("incomplete"));
}

#[test]
fn read_only_loader_rejects_registry_and_wire_revision_mismatch() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("snapshot.redb");
    SnapshotGenerationBuilder::new(input(), &path)
        .build()
        .unwrap();
    let wrong_registry =
        ReadOnlySnapshotCandidateLoader::open(&path, RegistryId::new("private").unwrap())
            .err()
            .unwrap();
    assert_eq!(
        wrong_registry.category(),
        CandidateLoadErrorCategory::SnapshotInvalid
    );

    let revision_path = dir.path().join("revision.redb");
    SnapshotGenerationBuilder::new(input(), &revision_path)
        .build()
        .unwrap();
    rewrite_stored_header(&revision_path, |header| {
        header.compatibility_profile = 2;
    });
    let revision_error =
        ReadOnlySnapshotCandidateLoader::open(&revision_path, RegistryId::new("cran").unwrap())
            .err()
            .unwrap();
    assert_eq!(
        revision_error.category(),
        CandidateLoadErrorCategory::SnapshotInvalid
    );

    let encoding_path = dir.path().join("encoding.redb");
    let encoding_generation = SnapshotGenerationBuilder::new(input(), &encoding_path)
        .build()
        .unwrap();
    let mut old_encoding = encoding_generation.header().clone();
    old_encoding.history_encoding = 1;
    old_encoding.generation = generation_id_from_header(&old_encoding);
    rewrite_stored_header(&encoding_path, |header| *header = old_encoding);
    let encoding_error =
        ReadOnlySnapshotCandidateLoader::open(&encoding_path, RegistryId::new("cran").unwrap())
            .err()
            .unwrap();
    assert_eq!(
        encoding_error.category(),
        CandidateLoadErrorCategory::SnapshotInvalid
    );

    let count_path = dir.path().join("count.redb");
    SnapshotGenerationBuilder::new(input(), &count_path)
        .build()
        .unwrap();
    delete_stored_history(&count_path, "foo");
    let count_error =
        ReadOnlySnapshotCandidateLoader::open(&count_path, RegistryId::new("cran").unwrap())
            .err()
            .unwrap();
    assert_eq!(
        count_error.category(),
        CandidateLoadErrorCategory::SnapshotInvalid
    );
}

#[test]
fn read_only_loader_rejects_corrupt_or_inconsistent_history() {
    fn bad_digest(history: &mut PackageHistoryV1) {
        history.eligible_releases[0].metadata_sha256 = [0; 32];
    }
    fn bad_key(history: &mut PackageHistoryV1) {
        history.package = "foo".into();
    }
    fn bad_source(history: &mut PackageHistoryV1) {
        history.observations[0].source_index = 1;
    }
    fn bad_namespace(history: &mut PackageHistoryV1) {
        history.eligible_releases[0].namespace = "bioc".into();
    }
    let cases = [
        ("digest", bad_digest as fn(&mut PackageHistoryV1)),
        ("key", bad_key),
        ("source", bad_source),
        ("namespace", bad_namespace),
    ];
    for (label, mutate) in cases {
        let dir = tempdir().unwrap();
        let path = dir.path().join(format!("{label}.redb"));
        SnapshotGenerationBuilder::new(two_present_input(), &path)
            .build()
            .unwrap();
        rewrite_stored_history(&path, "bar", mutate);
        let loader =
            ReadOnlySnapshotCandidateLoader::open(&path, RegistryId::new("cran").unwrap()).unwrap();
        assert_eq!(
            loader
                .releases(&SolverKey::InstalledName(PackageName::new("foo").unwrap()))
                .unwrap()
                .len(),
            1
        );
        let error = loader
            .releases(&SolverKey::InstalledName(PackageName::new("bar").unwrap()))
            .err()
            .unwrap();
        assert_eq!(
            error.category(),
            CandidateLoadErrorCategory::MetadataInvalid
        );
    }
}
