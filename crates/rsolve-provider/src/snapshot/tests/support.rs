use super::*;

pub(crate) fn input() -> SnapshotBuildInput {
    let source = SourceInput {
        kind: "current-packages".into(),
        representation: "gzip-dcf".into(),
        content_sha256: [7; 32],
        etag: None,
        last_modified: None,
        observed_at: "2026-08-23T00:00:00Z".into(),
        endpoint: "https://example.test/PACKAGES.gz".into(),
    };
    let source_id = source_observation(&source).unwrap().id;
    SnapshotBuildInput {
        registry_id: RegistryId::new("cran").unwrap(),
        compatibility_profile: 1,
        parser_schema: 1,
        normalization_policy: 2,
        created_at: "2026-08-23T00:00:00Z".into(),
        producer: "test".into(),
        coverage: CoverageV1 {
            state: "complete".into(),
            scope: "test".into(),
            freshness: "current".into(),
            source_ids: vec![source_id],
            missing_evidence: vec![],
        },
        sources: vec![source],
        histories: vec![PackageHistoryV1 {
            package: "foo".into(),
            state: LookupStateV1::Incomplete,
            observations: vec![RawObservationV1 {
                id: 0,
                source_index: 0,
                record_index: 0,
                fields: vec![FieldV1 {
                    name: "Package".into(),
                    value: "foo".into(),
                }],
                artifact: None,
                axes: EvidenceAxesV1 {
                    parse: ParseStateV1::Valid,
                    namespace: NamespaceStateV1::Established,
                    occurrence: OccurrenceStateV1::ObservationOnly,
                    semantics: SemanticsStateV1::Incomplete,
                    publication: PublicationStateV1::Unknown,
                    freshness: FreshnessStateV1::CurrentGeneration,
                },
            }],
            decisions: vec![],
            eligible_releases: vec![],
        }],
    }
}

pub(crate) fn two_source_input() -> (SnapshotBuildInput, [String; 2]) {
    let mut input = input();
    input.sources.push(SourceInput {
        kind: "archive-packages".into(),
        representation: "gzip-dcf".into(),
        content_sha256: [8; 32],
        etag: None,
        last_modified: None,
        observed_at: "2026-08-23T00:00:00Z".into(),
        endpoint: "https://example.test/Archive/PACKAGES.gz".into(),
    });
    let source_ids = input
        .sources
        .iter()
        .map(|source| source_observation(source).unwrap().id)
        .collect::<Vec<_>>();
    input.coverage.source_ids = source_ids.clone();
    let mut second_observation = input.histories[0].observations[0].clone();
    second_observation.id = 1;
    second_observation.source_index = 1;
    second_observation.record_index = 1;
    input.histories[0].observations.push(second_observation);
    (input, [source_ids[0].clone(), source_ids[1].clone()])
}

pub(crate) fn present_input() -> SnapshotBuildInput {
    let mut input = input();
    let package = PackageName::new("foo").unwrap();
    let version = RPackageVersion::parse("1.0").unwrap();
    let release = PackageRelease::try_from(ReleaseObservation {
        identity: ReleaseIdentity::new(
            package.clone(),
            Provenance::RegistryRelease {
                namespace: PackageNamespace::new("cran").unwrap(),
                version: version.clone(),
            },
        ),
        observed_package: package,
        observed_version: version,
        metadata: ReleaseMetadata::default(),
        publication: None,
        declared_dependencies: vec![],
        distributions: vec![],
    })
    .unwrap();
    input.histories[0].state = LookupStateV1::Present;
    input.histories[0].eligible_releases = vec![EligibleReleaseV1 {
        package: "foo".into(),
        version: "1.0".into(),
        namespace: "cran".into(),
        git_provenance: None,
        currentness: CandidateCurrentnessV1::Current,
        metadata: vec![],
        publication: None,
        dependencies: vec![],
        distributions: vec![],
        metadata_sha256: parse_hex_32(release.metadata_digest().as_str()).unwrap(),
        evidence: vec![],
    }];
    input
}

pub(crate) fn two_present_input() -> SnapshotBuildInput {
    let mut input = present_input();
    let mut second = input.histories[0].clone();
    second.package = "bar".into();
    second.eligible_releases[0].package = "bar".into();
    let package = PackageName::new("bar").unwrap();
    let version = RPackageVersion::parse("1.0").unwrap();
    let release = PackageRelease::try_from(ReleaseObservation {
        identity: ReleaseIdentity::new(
            package.clone(),
            Provenance::RegistryRelease {
                namespace: PackageNamespace::new("cran").unwrap(),
                version: version.clone(),
            },
        ),
        observed_package: package,
        observed_version: version,
        metadata: ReleaseMetadata::default(),
        publication: None,
        declared_dependencies: vec![],
        distributions: vec![],
    })
    .unwrap();
    second.eligible_releases[0].metadata_sha256 =
        parse_hex_32(release.metadata_digest().as_str()).unwrap();
    input.histories.push(second);
    input
}

pub(crate) fn stored_history(path: &Path) -> PackageHistoryV1 {
    let database = ReadOnlyDatabase::open(path).unwrap();
    let read = database.begin_read().unwrap();
    let table = read.open_table(PACKAGE_HISTORIES).unwrap();
    let bytes = table.get("foo").unwrap().unwrap();
    decode_history(bytes.value()).unwrap()
}

pub(crate) fn stored_header(path: &Path) -> Vec<u8> {
    let database = ReadOnlyDatabase::open(path).unwrap();
    let read = database.begin_read().unwrap();
    let table = read.open_table(SNAPSHOT_HEADER).unwrap();
    table.get(HEADER_KEY).unwrap().unwrap().value().to_vec()
}

pub(crate) fn rewrite_stored_history(
    path: &Path,
    package: &str,
    mutate: impl FnOnce(&mut PackageHistoryV1),
) {
    let database = Database::create(path).unwrap();
    let write = database.begin_write().unwrap();
    {
        let mut table = write.open_table(PACKAGE_HISTORIES).unwrap();
        let current = table.get(package).unwrap().unwrap().value().to_vec();
        let mut history = decode_history(&current).unwrap();
        mutate(&mut history);
        let encoded = encode_history(&history).unwrap();
        table.insert(package, encoded.as_slice()).unwrap();
    }
    write.commit().unwrap();
}

pub(crate) fn corrupt_stored_history(path: &Path, package: &str) {
    let database = Database::create(path).unwrap();
    let write = database.begin_write().unwrap();
    {
        let mut table = write.open_table(PACKAGE_HISTORIES).unwrap();
        table
            .insert(package, b"corrupt history".as_slice())
            .unwrap();
    }
    write.commit().unwrap();
}

pub(crate) fn rewrite_stored_header(path: &Path, mutate: impl FnOnce(&mut SnapshotHeaderV1)) {
    let database = Database::create(path).unwrap();
    let write = database.begin_write().unwrap();
    {
        let mut table = write.open_table(SNAPSHOT_HEADER).unwrap();
        let current = table.get(HEADER_KEY).unwrap().unwrap().value().to_vec();
        let mut header: SnapshotHeaderV1 = serde_json::from_slice(&current).unwrap();
        mutate(&mut header);
        let encoded = encode_header(&header).unwrap();
        table.insert(HEADER_KEY, encoded.as_slice()).unwrap();
    }
    write.commit().unwrap();
}

pub(crate) fn delete_stored_history(path: &Path, package: &str) {
    let database = Database::create(path).unwrap();
    let write = database.begin_write().unwrap();
    {
        let mut table = write.open_table(PACKAGE_HISTORIES).unwrap();
        table.remove(package).unwrap();
    }
    write.commit().unwrap();
}
