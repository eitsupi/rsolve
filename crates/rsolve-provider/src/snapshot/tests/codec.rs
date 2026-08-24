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
    old_encoding.history_encoding = 1;
    old_encoding.generation = generation_id_from_header(&old_encoding);
    assert!(decode_header(&encode_header(&old_encoding).unwrap()).is_err());
}
