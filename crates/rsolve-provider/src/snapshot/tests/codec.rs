use super::*;

#[test]
fn envelope_rejects_trailing_and_corruption() {
    let history = input().histories.remove(0);
    let bytes = encode_history(&history).unwrap();
    assert!(decode_history(&[bytes.as_slice(), &[0]].concat()).is_err());
    let mut corrupt = bytes;
    *corrupt.last_mut().unwrap() ^= 1;
    assert!(decode_history(&corrupt).is_err());
}

#[test]
fn header_decoder_rejects_unknown_fields_versions_and_noncanonical_bytes() {
    let dir = tempdir().unwrap();
    let generation = SnapshotGenerationBuilder::new(input(), dir.path().join("a.redb"))
        .build()
        .unwrap();
    let header = generation.header_bytes();
    assert!(decode_header(&[header, b"\n"].concat()).is_err());
    let mut unknown: serde_json::Value = serde_json::from_slice(header).unwrap();
    unknown["unknown"] = serde_json::Value::Bool(true);
    assert!(decode_header(&serde_json::to_vec(&unknown).unwrap()).is_err());
    let mut version: SnapshotHeaderV1 = serde_json::from_slice(header).unwrap();
    version.version = 2;
    assert!(decode_header(&encode_header(&version).unwrap()).is_err());
}

#[test]
fn release_wire_requires_git_provenance_key() {
    let release = present_input().histories[0].eligible_releases[0].clone();
    let mut value = serde_json::to_value(release).unwrap();
    value
        .as_object_mut()
        .expect("release wire value is an object")
        .remove("git_provenance");
    assert!(serde_json::from_value::<EligibleReleaseV1>(value).is_err());
}

#[test]
fn builder_rejects_bad_source_reference_and_state() {
    let dir = tempdir().unwrap();
    let mut bad_source = input();
    bad_source.histories[0].observations[0].source_index = 1;
    assert!(
        SnapshotGenerationBuilder::new(bad_source, dir.path().join("source.redb"))
            .build()
            .is_err()
    );

    let mut bad_state = input();
    bad_state.histories[0].state = LookupStateV1::Present;
    assert!(
        SnapshotGenerationBuilder::new(bad_state, dir.path().join("state.redb"))
            .build()
            .is_err()
    );
}

#[test]
fn readback_validation_rejects_manifest_mismatch() {
    let dir = tempdir().unwrap();
    let generation = SnapshotGenerationBuilder::new(input(), dir.path().join("a.redb"))
        .build()
        .unwrap();
    let mut header = generation.header().clone();
    header.history_manifest_sha256 = "0".repeat(64);
    let bytes = encode_header(&header).unwrap();
    let histories = BTreeMap::new();
    assert!(write_generation(&dir.path().join("bad.redb"), &bytes, &histories).is_err());
}

#[test]
fn destination_is_never_clobbered_and_failed_temp_is_cleaned() {
    let dir = tempdir().unwrap();
    let orphan = dir.path().join(".rsolve-generation-other.tmp");
    std::fs::write(&orphan, b"invalid temporary generation").unwrap();
    let destination = dir.path().join("existing.redb");
    std::fs::write(&destination, b"sentinel").unwrap();
    let result = SnapshotGenerationBuilder::new(input(), &destination).build();
    assert!(result.is_err());
    assert_eq!(std::fs::read(&destination).unwrap(), b"sentinel");
    assert_eq!(
        std::fs::read(&orphan).unwrap(),
        b"invalid temporary generation"
    );
    SnapshotGenerationBuilder::new(input(), dir.path().join("new.redb"))
        .build()
        .unwrap();
    assert_eq!(
        std::fs::read(&orphan).unwrap(),
        b"invalid temporary generation"
    );
    let temporary_files = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with(".rsolve-generation-")
        })
        .count();
    assert_eq!(temporary_files, 1);
}

#[test]
fn nested_collections_and_limits_must_be_canonical() {
    let dir = tempdir().unwrap();
    let mut unsorted = input();
    unsorted.histories[0].decisions = vec![DecisionV1 {
        code: DecisionCodeV1::CurrentOnly,
        observation_ids: vec![0, 0],
        detail: String::new(),
    }];
    assert!(
        SnapshotGenerationBuilder::new(unsorted, dir.path().join("unsorted.redb"))
            .build()
            .is_err()
    );

    let mut oversized = input();
    oversized.histories[0].observations[0].fields = (0..=MEMBER_LIMIT)
        .map(|index| FieldV1 {
            name: format!("f{index:05}"),
            value: "v".into(),
        })
        .collect();
    assert!(
        SnapshotGenerationBuilder::new(oversized, dir.path().join("oversized.redb"))
            .build()
            .is_err()
    );

    let mut oversized_subdirectory = input();
    oversized_subdirectory.histories[0].eligible_releases = vec![EligibleReleaseV1 {
        package: "foo".into(),
        version: "1.0.0".into(),
        namespace: "r-universe".into(),
        git_provenance: Some(GitProvenanceV1 {
            repository: "https://github.com/example/foo.git".into(),
            commit: "0123456789abcdef0123456789abcdef01234567".into(),
            subdirectory: Some("x".repeat(STRING_LIMIT + 1)),
        }),
        currentness: CandidateCurrentnessV1::Current,
        metadata: vec![],
        publication: None,
        dependencies: vec![],
        distributions: vec![],
        metadata_sha256: [1; 32],
        evidence: vec![],
    }];
    oversized_subdirectory.histories[0].state = LookupStateV1::Present;
    assert!(
        SnapshotGenerationBuilder::new(
            oversized_subdirectory,
            dir.path().join("oversized-subdirectory.redb")
        )
        .build()
        .is_err()
    );
}

#[test]
fn versions_use_numeric_components_and_reject_logical_duplicates() {
    let one_nine = RPackageVersion::parse("1.9").unwrap();
    let one_ten = RPackageVersion::parse("1.10").unwrap();
    assert!(canonical_version_components(&one_nine) < canonical_version_components(&one_ten));
    let clause_nine = ClauseV1 {
        op: RelationOpV1::Ge,
        version: "1.9".into(),
    };
    let clause_ten = ClauseV1 {
        op: RelationOpV1::Ge,
        version: "1.10".into(),
    };
    assert!(clause_order_key(&clause_nine).unwrap() < clause_order_key(&clause_ten).unwrap());
    let releases = vec![
        EligibleReleaseV1 {
            package: "foo".into(),
            version: "1.0".into(),
            namespace: "cran".into(),
            git_provenance: None,
            currentness: CandidateCurrentnessV1::Current,
            metadata: vec![],
            publication: None,
            dependencies: vec![],
            distributions: vec![],
            metadata_sha256: [1; 32],
            evidence: vec![],
        },
        EligibleReleaseV1 {
            package: "foo".into(),
            version: "1.0.0".into(),
            namespace: "cran".into(),
            git_provenance: None,
            currentness: CandidateCurrentnessV1::Historical,
            metadata: vec![],
            publication: None,
            dependencies: vec![],
            distributions: vec![],
            metadata_sha256: [2; 32],
            evidence: vec![],
        },
    ];
    assert!(validate_release_order(&releases).is_err());
}

#[test]
fn git_provenance_is_part_of_release_identity_ordering() {
    let release = |commit: &str, version: &str| EligibleReleaseV1 {
        package: "foo".into(),
        version: version.into(),
        namespace: "r-universe".into(),
        git_provenance: Some(GitProvenanceV1 {
            repository: "https://github.com/example/foo.git".into(),
            commit: commit.into(),
            subdirectory: None,
        }),
        currentness: CandidateCurrentnessV1::Current,
        metadata: vec![],
        publication: None,
        dependencies: vec![],
        distributions: vec![],
        metadata_sha256: [1; 32],
        evidence: vec![],
    };
    let first = release("0123456789abcdef0123456789abcdef01234567", "1.0.0");
    let second = release("fedcba9876543210fedcba9876543210fedcba98", "1.0.0");
    assert!(validate_release_order(&[first.clone(), second]).is_ok());
    assert!(validate_release_order(&[first.clone(), first.clone()]).is_err());
    assert!(
        validate_release_order(&[
            first,
            release("0123456789abcdef0123456789abcdef01234567", "2.0.0"),
        ])
        .is_err()
    );
}

#[test]
fn git_commit_order_uses_hash_algorithm_before_hex_value() {
    let release = |commit: String| EligibleReleaseV1 {
        package: "foo".into(),
        version: "1.0.0".into(),
        namespace: "r-universe".into(),
        git_provenance: Some(GitProvenanceV1 {
            repository: "https://github.com/example/foo.git".into(),
            commit,
            subdirectory: None,
        }),
        currentness: CandidateCurrentnessV1::Current,
        metadata: vec![],
        publication: None,
        dependencies: vec![],
        distributions: vec![],
        metadata_sha256: [1; 32],
        evidence: vec![],
    };
    let sha1 = release("f".repeat(40));
    let sha256 = release("1".repeat(64));
    assert!(validate_release_order(&[sha1.clone(), sha256.clone()]).is_ok());
    assert!(validate_release_order(&[sha256, sha1]).is_err());
}

#[test]
fn git_provenance_fields_are_bounded_before_snapshot_publication() {
    let dir = tempdir().unwrap();
    let mut oversized = input();
    oversized.histories[0].eligible_releases = vec![EligibleReleaseV1 {
        package: "foo".into(),
        version: "1.0.0".into(),
        namespace: "r-universe".into(),
        git_provenance: Some(GitProvenanceV1 {
            repository: "x".repeat(STRING_LIMIT + 1),
            commit: "0123456789abcdef0123456789abcdef01234567".into(),
            subdirectory: Some("src/foo".into()),
        }),
        currentness: CandidateCurrentnessV1::Current,
        metadata: vec![],
        publication: None,
        dependencies: vec![],
        distributions: vec![],
        metadata_sha256: [1; 32],
        evidence: vec![],
    }];
    oversized.histories[0].state = LookupStateV1::Present;
    assert!(
        SnapshotGenerationBuilder::new(oversized, dir.path().join("oversized.redb"))
            .build()
            .is_err()
    );
}

#[test]
fn header_rejects_observation_timestamp_generation_and_revision_mismatch() {
    let dir = tempdir().unwrap();
    let mut bad_timestamp = input();
    bad_timestamp.sources[0].observed_at = "not-a-timestamp".into();
    assert!(
        SnapshotGenerationBuilder::new(bad_timestamp, dir.path().join("timestamp.redb"))
            .build()
            .is_err()
    );

    let generation = SnapshotGenerationBuilder::new(input(), dir.path().join("valid.redb"))
        .build()
        .unwrap();
    let mut bad_generation = generation.header().clone();
    bad_generation.generation = "0".repeat(64);
    assert!(decode_header(&encode_header(&bad_generation).unwrap()).is_err());

    let mut bad_revision = input();
    bad_revision.compatibility_profile = 2;
    assert!(
        SnapshotGenerationBuilder::new(bad_revision, dir.path().join("revision.redb"))
            .build()
            .is_err()
    );

    let generation = SnapshotGenerationBuilder::new(input(), dir.path().join("encoding.redb"))
        .build()
        .unwrap();
    let mut old_encoding = generation.header().clone();
    old_encoding.history_encoding = 3;
    old_encoding.generation = generation_id_from_header(&old_encoding);
    assert!(decode_header(&encode_header(&old_encoding).unwrap()).is_err());
}

#[test]
fn header_accepts_parser_schema_three_but_rejects_unknown_schema_four() {
    let dir = tempdir().unwrap();
    let generation = SnapshotGenerationBuilder::new(input(), dir.path().join("valid.redb"))
        .build()
        .unwrap();

    let mut schema_three = generation.header().clone();
    schema_three.parser_schema = 3;
    schema_three.generation = generation_id_from_header(&schema_three);
    assert!(decode_header(&encode_header(&schema_three).unwrap()).is_ok());

    let mut schema_four = schema_three;
    schema_four.parser_schema = 4;
    schema_four.generation = generation_id_from_header(&schema_four);
    assert!(decode_header(&encode_header(&schema_four).unwrap()).is_err());
}
