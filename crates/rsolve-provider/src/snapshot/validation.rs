use super::*;

pub(super) fn validate_registry_id(value: &RegistryId) -> Result<(), SnapshotError> {
    if value.as_str().is_empty() {
        Err(SnapshotError::Invalid("registry id is empty".into()))
    } else {
        Ok(())
    }
}
pub(super) fn validate_history(
    history: &PackageHistoryV1,
    sources: &BTreeMap<String, u32>,
    source_count: usize,
) -> Result<(), SnapshotError> {
    let package =
        PackageName::new(&history.package).map_err(|e| SnapshotError::Invalid(e.to_string()))?;
    if history.observations.len() > OBSERVATION_LIMIT
        || history.decisions.len() > DECISION_LIMIT
        || history.eligible_releases.len() > ELIGIBLE_RELEASE_LIMIT
    {
        return Err(SnapshotError::Invalid(format!(
            "history {package} exceeds count limit"
        )));
    }
    if matches!(history.state, LookupStateV1::Present) && history.eligible_releases.is_empty() {
        return Err(SnapshotError::Invalid(
            "present history has no eligible release".into(),
        ));
    }
    if matches!(history.state, LookupStateV1::Incomplete) && !history.eligible_releases.is_empty() {
        return Err(SnapshotError::Invalid(
            "incomplete history has eligible releases".into(),
        ));
    }
    let mut ids = BTreeSet::new();
    for (index, observation) in history.observations.iter().enumerate() {
        if observation.id != index as u32 {
            return Err(SnapshotError::Invalid(
                "observation ids are not contiguous".into(),
            ));
        }
        if observation.source_index as usize >= source_count {
            return Err(SnapshotError::Invalid(
                "observation source index is out of range".into(),
            ));
        }
        if !ids.insert(observation.id) {
            return Err(SnapshotError::Invalid("duplicate observation id".into()));
        }
    }
    for decision in &history.decisions {
        for id in &decision.observation_ids {
            if !ids.contains(id) {
                return Err(SnapshotError::Invalid(
                    "decision references unknown observation".into(),
                ));
            }
        }
    }
    for release in &history.eligible_releases {
        if release.package != history.package {
            return Err(SnapshotError::Invalid(
                "release package does not match history key".into(),
            ));
        }
        for evidence in &release.evidence {
            if !ids.contains(&evidence.observation_id) {
                return Err(SnapshotError::Invalid(
                    "release references unknown observation".into(),
                ));
            }
        }
        let _ = release_to_domain(release)?;
    }
    validate_canonical_history(history)?;
    let _ = sources;
    Ok(())
}

pub(super) fn validate_header(header: &SnapshotHeaderV1) -> Result<(), SnapshotError> {
    if header.format != "rsolve-metadata-snapshot"
        || header.version != 1
        || header.history_encoding != HISTORY_ENCODING
        // Policy 2 is the only active normalization generation. Older
        // generations are intentionally rejected at the wire boundary so
        // they cannot re-enter the cache through another load path.
        || header.normalization_policy != 2
        || header.compatibility_profile != 1
        || header.parser_schema != 1
    {
        return Err(SnapshotError::Invalid(
            "unknown snapshot header format or version".into(),
        ));
    }
    if !matches!(header.coverage.state.as_str(), "complete" | "partial") {
        return Err(SnapshotError::Invalid("invalid coverage state".into()));
    }
    for value in [
        &header.registry_id,
        &header.generation,
        &header.created_at,
        &header.producer,
        &header.coverage.scope,
        &header.coverage.freshness,
    ] {
        validate_string(value, true, "required header string")?;
    }
    RegistryId::new(&header.registry_id)
        .map_err(|error| SnapshotError::Invalid(error.to_string()))?;
    parse_hex_32(&header.generation)?;
    if header.generation != generation_id_from_header(header) {
        return Err(SnapshotError::Invalid(
            "snapshot generation does not match header fields".into(),
        ));
    }
    if !is_rfc3339_seconds(&header.created_at) {
        return Err(SnapshotError::Invalid(
            "header created_at is not UTC RFC 3339 seconds".into(),
        ));
    }
    if header.sources.len() > HEADER_SOURCE_LIMIT {
        return Err(SnapshotError::Invalid("too many snapshot sources".into()));
    }
    let mut source_ids = Vec::with_capacity(header.sources.len());
    for source in &header.sources {
        for value in [
            &source.id,
            &source.kind,
            &source.representation,
            &source.content_sha256,
            &source.observed_at,
            &source.endpoint,
        ] {
            validate_string(value, true, "source string")?;
        }
        if source
            .etag
            .as_ref()
            .is_some_and(|value| value.len() > STRING_LIMIT)
            || source
                .last_modified
                .as_ref()
                .is_some_and(|value| value.len() > STRING_LIMIT)
        {
            return Err(SnapshotError::Invalid(
                "source validator exceeds string limit".into(),
            ));
        }
        if !is_rfc3339_seconds(&source.observed_at) {
            return Err(SnapshotError::Invalid(
                "source observed_at is not UTC RFC 3339 seconds".into(),
            ));
        }
        let content = parse_hex_32(&source.content_sha256)?;
        let expected = hex(&hash_parts(
            b"rsolve.metadata-source-id\0v1",
            [&source.kind, &source.representation, &hex(&content)],
        ));
        if expected != source.id {
            return Err(SnapshotError::Invalid(
                "source id does not match source content".into(),
            ));
        }
        source_ids.push(source.id.clone());
    }
    if source_ids.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(SnapshotError::Invalid(
            "snapshot sources are not sorted and unique".into(),
        ));
    }
    if header
        .coverage
        .source_ids
        .windows(2)
        .any(|pair| pair[0] >= pair[1])
        || header
            .coverage
            .missing_evidence
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
    {
        return Err(SnapshotError::Invalid(
            "coverage arrays are not sorted and unique".into(),
        ));
    }
    if header.coverage.source_ids != source_ids {
        return Err(SnapshotError::Invalid(
            "coverage source_ids must enumerate all header sources".into(),
        ));
    }
    for id in &header.coverage.source_ids {
        validate_string(id, true, "coverage source id")?;
    }
    for evidence in &header.coverage.missing_evidence {
        validate_string(evidence, true, "coverage missing evidence")?;
    }
    if header
        .coverage
        .source_ids
        .iter()
        .any(|id| !source_ids.contains(id))
    {
        return Err(SnapshotError::Invalid(
            "coverage references unknown source".into(),
        ));
    }
    let _ = parse_hex_32(&header.history_manifest_sha256)?;
    Ok(())
}

pub(super) fn is_rfc3339_seconds(value: &str) -> bool {
    value.len() == 20
        && value.ends_with('Z')
        && value.as_bytes()[10] == b'T'
        && value.as_bytes()[19] == b'Z'
        && value.parse::<jiff::Timestamp>().is_ok()
}

pub(super) fn validate_string(
    value: &str,
    required: bool,
    label: &str,
) -> Result<(), SnapshotError> {
    if (required && value.is_empty()) || value.len() > STRING_LIMIT {
        return Err(SnapshotError::Invalid(format!(
            "{label} is empty or too long"
        )));
    }
    Ok(())
}

pub(super) fn validate_history_limits(history: &PackageHistoryV1) -> Result<(), SnapshotError> {
    if history.package.len() > STRING_LIMIT
        || history.observations.len() > OBSERVATION_LIMIT
        || history.decisions.len() > DECISION_LIMIT
        || history.eligible_releases.len() > ELIGIBLE_RELEASE_LIMIT
    {
        return Err(SnapshotError::Invalid(
            "history exceeds its count or string limit".into(),
        ));
    }
    for observation in &history.observations {
        if observation.fields.len() > MEMBER_LIMIT {
            return Err(SnapshotError::Invalid(
                "observation has too many fields".into(),
            ));
        }
        for field in &observation.fields {
            validate_string(&field.name, false, "observation field name")?;
            validate_string(&field.value, false, "observation field value")?;
        }
        if let Some(artifact) = &observation.artifact
            && (artifact.locator.len() > STRING_LIMIT || artifact.checksums.len() > MEMBER_LIMIT)
        {
            return Err(SnapshotError::Invalid(
                "observation artifact exceeds limits".into(),
            ));
        }
        if let Some(artifact) = &observation.artifact {
            validate_string(&artifact.locator, true, "observation artifact locator")?;
            for checksum in &artifact.checksums {
                validate_string(&checksum.algorithm, true, "observation checksum algorithm")?;
                validate_string(&checksum.value, true, "observation checksum value")?;
            }
        }
    }
    for decision in &history.decisions {
        if decision.observation_ids.len() > MEMBER_LIMIT || decision.detail.len() > STRING_LIMIT {
            return Err(SnapshotError::Invalid("decision exceeds its limits".into()));
        }
    }
    for release in &history.eligible_releases {
        if release.package.len() > STRING_LIMIT
            || release.version.len() > STRING_LIMIT
            || release.namespace.len() > STRING_LIMIT
            || release.metadata.len() > MEMBER_LIMIT
            || release.dependencies.len() > MEMBER_LIMIT
            || release.distributions.len() > MEMBER_LIMIT
            || release.evidence.len() > MEMBER_LIMIT
        {
            return Err(SnapshotError::Invalid(
                "eligible release exceeds its limits".into(),
            ));
        }
        validate_string(&release.package, true, "release package")?;
        validate_string(&release.version, true, "release version")?;
        validate_string(&release.namespace, true, "release namespace")?;
        for field in &release.metadata {
            validate_string(&field.name, false, "release metadata name")?;
            validate_string(&field.value, false, "release metadata value")?;
        }
        for dependency in &release.dependencies {
            if dependency.package.len() > STRING_LIMIT || dependency.clauses.len() > MEMBER_LIMIT {
                return Err(SnapshotError::Invalid(
                    "dependency exceeds its limits".into(),
                ));
            }
            validate_string(&dependency.package, true, "dependency package")?;
            for clause in &dependency.clauses {
                if clause.version.len() > STRING_LIMIT {
                    return Err(SnapshotError::Invalid(
                        "dependency clause exceeds its limits".into(),
                    ));
                }
                validate_string(&clause.version, true, "dependency clause version")?;
            }
        }
        for distribution in &release.distributions {
            if distribution.registry.len() > STRING_LIMIT
                || distribution.channel.len() > STRING_LIMIT
                || distribution
                    .snapshot
                    .as_ref()
                    .is_some_and(|s| s.len() > STRING_LIMIT)
                || distribution.artifacts.len() > MEMBER_LIMIT
                || distribution.metadata.len() > MEMBER_LIMIT
            {
                return Err(SnapshotError::Invalid(
                    "distribution exceeds its limits".into(),
                ));
            }
            validate_string(&distribution.registry, true, "distribution registry")?;
            validate_string(&distribution.channel, true, "distribution channel")?;
            if let Some(snapshot) = &distribution.snapshot {
                validate_string(snapshot, true, "distribution snapshot")?;
            }
            for field in &distribution.metadata {
                validate_string(&field.name, false, "distribution metadata name")?;
                validate_string(&field.value, false, "distribution metadata value")?;
            }
            for artifact in &distribution.artifacts {
                if artifact.locator.len() > STRING_LIMIT
                    || artifact.upstream_checksums.len() > MEMBER_LIMIT
                {
                    return Err(SnapshotError::Invalid(
                        "distribution artifact exceeds its limits".into(),
                    ));
                }
                validate_string(&artifact.locator, true, "distribution artifact locator")?;
                for checksum in &artifact.upstream_checksums {
                    validate_string(&checksum.algorithm, true, "distribution checksum algorithm")?;
                    validate_string(&checksum.value, true, "distribution checksum value")?;
                }
            }
        }
        for evidence in &release.evidence {
            if evidence.roles.len() > MEMBER_LIMIT {
                return Err(SnapshotError::Invalid(
                    "release evidence exceeds its limits".into(),
                ));
            }
        }
    }
    Ok(())
}

pub(super) fn validate_canonical_history(history: &PackageHistoryV1) -> Result<(), SnapshotError> {
    validate_history_limits(history)?;

    let observation_keys = history
        .observations
        .iter()
        .map(observation_order_key)
        .collect::<Result<Vec<_>, _>>()?;
    if observation_keys.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(SnapshotError::Invalid(
            "observations are not canonically ordered".into(),
        ));
    }
    let decision_keys = history
        .decisions
        .iter()
        .map(decision_order_key)
        .collect::<Vec<_>>();
    if decision_keys.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(SnapshotError::Invalid(
            "decisions are not canonically ordered".into(),
        ));
    }
    for decision in &history.decisions {
        if decision
            .observation_ids
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        {
            return Err(SnapshotError::Invalid(
                "decision observation IDs are not sorted and unique".into(),
            ));
        }
    }
    validate_release_order(&history.eligible_releases)?;
    for observation in &history.observations {
        if let Some(artifact) = &observation.artifact {
            validate_checksums(&artifact.checksums)?;
        }
    }
    for release in &history.eligible_releases {
        validate_fields(&release.metadata, "release metadata")?;
        let dependency_keys = release
            .dependencies
            .iter()
            .map(dependency_order_key)
            .collect::<Result<Vec<_>, _>>()?;
        if dependency_keys.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(SnapshotError::Invalid(
                "dependencies are not canonically ordered".into(),
            ));
        }
        for dependency in &release.dependencies {
            let clause_keys = dependency
                .clauses
                .iter()
                .map(clause_order_key)
                .collect::<Result<Vec<_>, _>>()?;
            if clause_keys.windows(2).any(|pair| pair[0] >= pair[1]) {
                return Err(SnapshotError::Invalid(
                    "dependency clauses are not sorted and unique".into(),
                ));
            }
        }
        let distribution_keys = release
            .distributions
            .iter()
            .map(distribution_order_key)
            .collect::<Vec<_>>();
        if distribution_keys.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(SnapshotError::Invalid(
                "distributions are not canonically ordered".into(),
            ));
        }
        for distribution in &release.distributions {
            validate_fields(&distribution.metadata, "distribution metadata")?;
            let artifact_keys = distribution
                .artifacts
                .iter()
                .map(artifact_order_key)
                .collect::<Result<Vec<_>, _>>()?;
            if artifact_keys.windows(2).any(|pair| pair[0] >= pair[1]) {
                return Err(SnapshotError::Invalid(
                    "artifacts are not canonically ordered".into(),
                ));
            }
            for artifact in &distribution.artifacts {
                validate_checksums(&artifact.upstream_checksums)?;
            }
        }
        let evidence_keys = release
            .evidence
            .iter()
            .map(|e| {
                (
                    e.observation_id,
                    e.roles
                        .iter()
                        .map(|role| role_rank(*role))
                        .collect::<Vec<_>>(),
                )
            })
            .collect::<Vec<_>>();
        if evidence_keys.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(SnapshotError::Invalid(
                "evidence is not canonically ordered".into(),
            ));
        }
        for evidence in &release.evidence {
            let roles = evidence
                .roles
                .iter()
                .map(|role| role_rank(*role))
                .collect::<Vec<_>>();
            if roles.windows(2).any(|pair| pair[0] >= pair[1]) {
                return Err(SnapshotError::Invalid(
                    "evidence roles are not sorted and unique".into(),
                ));
            }
        }
    }
    Ok(())
}

pub(super) type VersionOrderKey = (Vec<u32>, String);
pub(super) type DependencyOrderKey<'a> = (u8, &'a str, Vec<(u8, VersionOrderKey)>);
pub(super) type ArtifactOrderKey = (String, Vec<(String, String)>, Option<u64>);

pub(super) fn observation_order_key(
    observation: &RawObservationV1,
) -> Result<(u32, u64, Vec<u8>), SnapshotError> {
    Ok((
        observation.source_index,
        observation.record_index,
        serde_json::to_vec(&(&observation.fields, &observation.artifact))?,
    ))
}
pub(super) fn decision_order_key(decision: &DecisionV1) -> (u8, Vec<u32>, &str) {
    (
        decision_rank(decision.code),
        decision.observation_ids.clone(),
        decision.detail.as_str(),
    )
}
pub(super) fn dependency_order_key(
    dependency: &DependencyV1,
) -> Result<DependencyOrderKey<'_>, SnapshotError> {
    Ok((
        dependency_rank(dependency.kind),
        dependency.package.as_str(),
        dependency
            .clauses
            .iter()
            .map(clause_order_key)
            .collect::<Result<Vec<_>, _>>()?,
    ))
}
pub(super) fn clause_order_key(clause: &ClauseV1) -> Result<(u8, VersionOrderKey), SnapshotError> {
    let version = RPackageVersion::parse(&clause.version)
        .map_err(|e| SnapshotError::Invalid(e.to_string()))?;
    Ok((
        relation_rank(clause.op),
        (
            canonical_version_components(&version),
            clause.version.clone(),
        ),
    ))
}

pub(super) fn canonical_version_components(version: &RPackageVersion) -> Vec<u32> {
    version
        .components()
        .take(version.canonical_component_count())
        .collect()
}

pub(super) fn validate_release_order(releases: &[EligibleReleaseV1]) -> Result<(), SnapshotError> {
    let keys = releases
        .iter()
        .map(|release| {
            let version = RPackageVersion::parse(&release.version)
                .map_err(|error| SnapshotError::Invalid(error.to_string()))?;
            Ok((
                canonical_version_components(&version),
                release.version.clone(),
                release.metadata_sha256,
            ))
        })
        .collect::<Result<Vec<_>, SnapshotError>>()?;
    if keys.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(SnapshotError::Invalid(
            "eligible releases are not canonically ordered".into(),
        ));
    }
    if keys.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(SnapshotError::Invalid(
            "duplicate eligible release version".into(),
        ));
    }
    Ok(())
}
pub(super) fn distribution_order_key(distribution: &DistributionV1) -> (&str, &str, Option<&str>) {
    (
        distribution.registry.as_str(),
        distribution.channel.as_str(),
        distribution.snapshot.as_deref(),
    )
}
pub(super) fn artifact_order_key(artifact: &ArtifactV1) -> Result<ArtifactOrderKey, SnapshotError> {
    validate_checksums(&artifact.upstream_checksums)?;
    Ok((
        artifact.locator.clone(),
        artifact
            .upstream_checksums
            .iter()
            .map(|c| (c.algorithm.clone(), c.value.clone()))
            .collect(),
        artifact.size,
    ))
}
pub(super) fn validate_fields(fields: &[FieldV1], label: &str) -> Result<(), SnapshotError> {
    let keys = fields.iter().map(|f| f.name.as_str()).collect::<Vec<_>>();
    if keys.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(SnapshotError::Invalid(format!(
            "{label} is not sorted and unique"
        )));
    }
    Ok(())
}
pub(super) fn validate_checksums(checksums: &[ChecksumV1]) -> Result<(), SnapshotError> {
    let keys = checksums
        .iter()
        .map(|c| (c.algorithm.as_str(), c.value.as_str()))
        .collect::<Vec<_>>();
    if keys.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(SnapshotError::Invalid(
            "checksums are not sorted and unique".into(),
        ));
    }
    for checksum in checksums {
        if checksum.algorithm != checksum.algorithm.to_ascii_lowercase() {
            return Err(SnapshotError::Invalid(
                "checksum algorithm is not lowercase".into(),
            ));
        }
        if checksum.algorithm == "sha256" {
            parse_hex_32(&checksum.value)?;
        }
    }
    Ok(())
}
pub(super) fn decision_rank(code: DecisionCodeV1) -> u8 {
    code as u8
}
pub(super) fn dependency_rank(kind: DependencyKindV1) -> u8 {
    kind as u8
}
pub(super) fn relation_rank(op: RelationOpV1) -> u8 {
    op as u8
}
pub(super) fn role_rank(role: EvidenceRoleV1) -> u8 {
    role as u8
}

pub(super) fn parse_hex_32(value: &str) -> Result<[u8; 32], SnapshotError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(SnapshotError::Invalid(
            "expected lowercase SHA-256 digest".into(),
        ));
    }
    let mut result = [0_u8; 32];
    for (index, byte) in result.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| SnapshotError::Invalid("invalid SHA-256 digest".into()))?;
    }
    if value != value.to_ascii_lowercase() {
        return Err(SnapshotError::Invalid(
            "digest must use lowercase hexadecimal".into(),
        ));
    }
    Ok(result)
}

pub(super) fn generation_id(input: &SnapshotBuildInput, header: &SnapshotHeaderV1) -> String {
    let mut bytes = Vec::new();
    append_part(&mut bytes, b"rsolve.metadata-generation\0v1");
    for value in [
        input.registry_id.as_str(),
        &header.version.to_string(),
        &header.history_encoding.to_string(),
        &header.normalization_policy.to_string(),
        &header.compatibility_profile.to_string(),
        &header.parser_schema.to_string(),
        &header.coverage.state,
        &header.coverage.scope,
        &header.coverage.freshness,
    ] {
        append_part(&mut bytes, value.as_bytes());
    }
    for value in &header.coverage.missing_evidence {
        append_part(&mut bytes, value.as_bytes());
    }
    for source in &header.sources {
        append_part(&mut bytes, source.id.as_bytes());
    }
    append_part(&mut bytes, header.history_manifest_sha256.as_bytes());
    hex(&Sha256::digest(bytes))
}

pub(super) fn generation_id_from_header(header: &SnapshotHeaderV1) -> String {
    let mut bytes = Vec::new();
    append_part(&mut bytes, b"rsolve.metadata-generation\0v1");
    for value in [
        header.registry_id.as_str(),
        &header.version.to_string(),
        &header.history_encoding.to_string(),
        &header.normalization_policy.to_string(),
        &header.compatibility_profile.to_string(),
        &header.parser_schema.to_string(),
        &header.coverage.state,
        &header.coverage.scope,
        &header.coverage.freshness,
    ] {
        append_part(&mut bytes, value.as_bytes());
    }
    for value in &header.coverage.missing_evidence {
        append_part(&mut bytes, value.as_bytes());
    }
    for source in &header.sources {
        append_part(&mut bytes, source.id.as_bytes());
    }
    append_part(&mut bytes, header.history_manifest_sha256.as_bytes());
    hex(&Sha256::digest(bytes))
}

pub(super) fn append_part(output: &mut Vec<u8>, bytes: &[u8]) {
    output.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    output.extend_from_slice(bytes);
}
pub(super) fn hash_parts(domain: &[u8], parts: [&String; 3]) -> [u8; 32] {
    let mut bytes = Vec::new();
    append_part(&mut bytes, domain);
    for part in parts {
        append_part(&mut bytes, part.as_bytes());
    }
    Sha256::digest(bytes).into()
}
pub(super) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub(super) fn release_to_domain(wire: &EligibleReleaseV1) -> Result<PackageRelease, SnapshotError> {
    if wire.namespace != "cran" {
        return Err(SnapshotError::Invalid(
            "history v1 only supports the cran namespace".into(),
        ));
    }
    let package =
        PackageName::new(&wire.package).map_err(|e| SnapshotError::Invalid(e.to_string()))?;
    let version =
        RPackageVersion::parse(&wire.version).map_err(|e| SnapshotError::Invalid(e.to_string()))?;
    let identity = ReleaseIdentity::new(
        package.clone(),
        Provenance::RegistryRelease {
            namespace: PackageNamespace::new("cran")
                .map_err(|e| SnapshotError::Invalid(e.to_string()))?,
            version: version.clone(),
        },
    );
    let metadata = ReleaseMetadata::from_pairs(
        wire.metadata
            .iter()
            .map(|x| (x.name.clone(), x.value.clone())),
    )
    .map_err(|e| SnapshotError::Invalid(e.to_string()))?;
    let publication = wire
        .publication
        .as_ref()
        .map(PublicationDate::parse)
        .transpose()
        .map_err(|e| SnapshotError::Invalid(e.to_string()))?
        .map(ReleasePublication::new);
    let dependencies = wire
        .dependencies
        .iter()
        .map(|dependency| {
            let kind = match dependency.kind {
                DependencyKindV1::Depends => DependencyKind::Depends,
                DependencyKindV1::Imports => DependencyKind::Imports,
                DependencyKindV1::LinkingTo => DependencyKind::LinkingTo,
                DependencyKindV1::Suggests => DependencyKind::Suggests,
                DependencyKindV1::Enhances => DependencyKind::Enhances,
            };
            let clauses = dependency
                .clauses
                .iter()
                .map(|clause| {
                    let op = match clause.op {
                        RelationOpV1::Lt => RelationOp::Lt,
                        RelationOpV1::Le => RelationOp::Le,
                        RelationOpV1::Eq => RelationOp::Eq,
                        RelationOpV1::Ne => RelationOp::Ne,
                        RelationOpV1::Ge => RelationOp::Ge,
                        RelationOpV1::Gt => RelationOp::Gt,
                    };
                    Ok(VersionClause::new(
                        op,
                        RPackageVersion::parse(&clause.version)
                            .map_err(|e| SnapshotError::Invalid(e.to_string()))?,
                    ))
                })
                .collect::<Result<Vec<_>, SnapshotError>>()?;
            Ok(DependencyRequirement::new(
                kind,
                PackageName::new(&dependency.package)
                    .map_err(|e| SnapshotError::Invalid(e.to_string()))?,
                DependencySourceConstraint::Any,
                VersionConstraint::new(clauses),
            ))
        })
        .collect::<Result<Vec<_>, SnapshotError>>()?;
    let distributions = wire
        .distributions
        .iter()
        .map(|distribution| {
            let artifacts = distribution
                .artifacts
                .iter()
                .map(|artifact| {
                    let checksums = artifact
                        .upstream_checksums
                        .iter()
                        .map(|checksum| match checksum.algorithm.as_str() {
                            "sha256" => Ok(UpstreamChecksum::Sha256(
                                Sha256Digest::new(&checksum.value)
                                    .map_err(|e| SnapshotError::Invalid(e.to_string()))?,
                            )),
                            "md5" => Ok(UpstreamChecksum::Md5(checksum.value.clone().into())),
                            _ => Ok(UpstreamChecksum::Other {
                                algorithm: checksum.algorithm.clone().into(),
                                value: checksum.value.clone().into(),
                            }),
                        })
                        .collect::<Result<Vec<_>, SnapshotError>>()?;
                    Ok(Artifact::Source(SourceArtifact {
                        locator: ArtifactLocator::new(&artifact.locator)
                            .map_err(|e| SnapshotError::Invalid(e.to_string()))?,
                        upstream_checksums: checksums,
                        size: artifact.size,
                    }))
                })
                .collect::<Result<Vec<_>, SnapshotError>>()?;
            Ok(Distribution {
                registry: RegistryId::new(&distribution.registry)
                    .map_err(|e| SnapshotError::Invalid(e.to_string()))?,
                channel: DistributionChannel::new(&distribution.channel)
                    .map_err(|e| SnapshotError::Invalid(e.to_string()))?,
                snapshot: distribution
                    .snapshot
                    .as_ref()
                    .map(SnapshotId::new)
                    .transpose()
                    .map_err(|e| SnapshotError::Invalid(e.to_string()))?,
                artifacts,
                observed_metadata: DistributionMetadata {
                    fields: distribution
                        .metadata
                        .iter()
                        .map(|x| (x.name.clone(), x.value.clone()))
                        .collect(),
                },
            })
        })
        .collect::<Result<Vec<_>, SnapshotError>>()?;
    let release = PackageRelease::try_from(ReleaseObservation {
        identity,
        observed_package: package,
        observed_version: version,
        metadata,
        publication,
        dependencies,
        distributions,
    })
    .map_err(|e| SnapshotError::Invalid(e.to_string()))?;
    if hex_digest(release.metadata_digest().as_str()) != hex(&wire.metadata_sha256) {
        return Err(SnapshotError::Invalid(
            "eligible release metadata digest mismatch".into(),
        ));
    }
    Ok(release)
}

pub(super) fn hex_digest(value: &str) -> String {
    value.to_ascii_lowercase()
}
