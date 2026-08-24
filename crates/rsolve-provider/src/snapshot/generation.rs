use super::*;

pub struct ValidatedGeneration {
    path: PathBuf,
    generation: String,
    header: SnapshotHeaderV1,
    header_bytes: Vec<u8>,
}

/// A transport-free candidate loader backed by one immutable redb generation.
///
/// The database is opened read-only and remains pinned for the lifetime of the
/// loader.  No refresh, pointer publication, repair, or endpoint state is
/// reachable through this resolver-facing capability.
pub struct ReadOnlySnapshotCandidateLoader {
    database: ReadOnlyDatabase,
    header: SnapshotHeaderV1,
    source_indexes: BTreeMap<String, u32>,
}

impl ReadOnlySnapshotCandidateLoader {
    /// Opens and validates the generation-global coordinates for a configured
    /// registry.  Package histories remain lazy and are validated when looked
    /// up.  The configured registry identity is checked against the immutable
    /// header before the loader is returned.
    pub fn open(
        path: impl AsRef<Path>,
        configured_registry_id: RegistryId,
    ) -> Result<Self, CandidateLoadError> {
        let database = ReadOnlyDatabase::open(path.as_ref()).map_err(snapshot_invalid)?;
        let read = database.begin_read().map_err(snapshot_invalid)?;
        let header_table = read.open_table(SNAPSHOT_HEADER).map_err(snapshot_invalid)?;
        let stored_header = header_table
            .get(HEADER_KEY)
            .map_err(snapshot_invalid)?
            .ok_or_else(|| snapshot_invalid("snapshot header is missing"))?;
        let header_bytes = stored_header.value();
        let header = decode_header(header_bytes).map_err(snapshot_invalid)?;
        if header.registry_id != configured_registry_id.as_str() {
            return Err(snapshot_invalid(format!(
                "snapshot registry {:?} does not match configured registry {:?}",
                header.registry_id,
                configured_registry_id.as_str()
            )));
        }
        let source_indexes = header
            .sources
            .iter()
            .enumerate()
            .map(|(index, source)| (source.id.clone(), index as u32))
            .collect::<BTreeMap<_, _>>();
        let history_table = read
            .open_table(PACKAGE_HISTORIES)
            .map_err(snapshot_invalid)?;
        if history_table.len().map_err(snapshot_invalid)? != header.package_count {
            return Err(snapshot_invalid("snapshot package count mismatch"));
        }
        drop(history_table);
        drop(header_table);
        drop(read);
        Ok(Self {
            database,
            header,
            source_indexes,
        })
    }

    pub(crate) fn header(&self) -> &SnapshotHeaderV1 {
        &self.header
    }

    fn releases_for_name(
        &self,
        name: &PackageName,
    ) -> Result<Vec<PackageRelease>, CandidateLoadError> {
        let read = self.database.begin_read().map_err(snapshot_invalid)?;
        let table = read
            .open_table(PACKAGE_HISTORIES)
            .map_err(snapshot_invalid)?;
        let Some(value) = table.get(name.as_str()).map_err(snapshot_invalid)? else {
            return if self.header.coverage.state == "complete" {
                Err(CandidateLoadError::new(
                    CandidateLoadErrorCategory::NotFound,
                    format!("CRAN snapshot has no candidates for {name}"),
                ))
            } else {
                Err(CandidateLoadError::new(
                    CandidateLoadErrorCategory::MetadataInvalid,
                    format!("CRAN snapshot is partial for missing package {name}"),
                ))
            };
        };
        let history = decode_history(value.value()).map_err(package_metadata_invalid)?;
        if history.package != name.as_str() {
            return Err(package_metadata_invalid("history key/package mismatch"));
        }
        validate_history(&history, &self.source_indexes, self.header.sources.len())
            .map_err(package_metadata_invalid)?;
        if !matches!(history.state, LookupStateV1::Present) {
            return Err(package_metadata_invalid(
                "package history is incomplete and cannot provide candidates",
            ));
        }
        history
            .eligible_releases
            .iter()
            .map(release_to_domain)
            .collect::<Result<Vec<_>, _>>()
            .map_err(package_metadata_invalid)
    }
}

impl CandidateLoader for ReadOnlySnapshotCandidateLoader {
    fn releases(&self, package: &SolverKey) -> Result<Vec<PackageRelease>, CandidateLoadError> {
        let SolverKey::InstalledName(name) = package else {
            return Err(CandidateLoadError::new(
                CandidateLoadErrorCategory::NotFound,
                format!("CRAN snapshot does not support solver key {package:?}"),
            ));
        };
        self.releases_for_name(name)
    }
}

fn snapshot_invalid(error: impl fmt::Display) -> CandidateLoadError {
    CandidateLoadError::new(
        CandidateLoadErrorCategory::SnapshotInvalid,
        error.to_string(),
    )
}

fn package_metadata_invalid(error: impl fmt::Display) -> CandidateLoadError {
    CandidateLoadError::new(
        CandidateLoadErrorCategory::MetadataInvalid,
        error.to_string(),
    )
}
impl ValidatedGeneration {
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn generation(&self) -> &str {
        &self.generation
    }
    pub fn header(&self) -> &SnapshotHeaderV1 {
        &self.header
    }
    pub fn header_bytes(&self) -> &[u8] {
        &self.header_bytes
    }
}

pub struct SnapshotGenerationBuilder {
    input: SnapshotBuildInput,
    destination: PathBuf,
}

struct TemporaryGeneration {
    path: PathBuf,
}

impl Drop for TemporaryGeneration {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn create_temporary_generation(parent: &Path) -> Result<TemporaryGeneration, SnapshotError> {
    let pid = std::process::id();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| SnapshotError::Invalid("system clock is before UNIX epoch".into()))?
        .as_nanos();
    for _ in 0..128 {
        let sequence = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = parent.join(format!(
            ".rsolve-generation-{pid}-{timestamp}-{sequence}.tmp"
        ));
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(_) => return Ok(TemporaryGeneration { path }),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Err(SnapshotError::Invalid(
        "unable to allocate a unique temporary generation".into(),
    ))
}

impl SnapshotGenerationBuilder {
    pub fn new(input: SnapshotBuildInput, destination: impl Into<PathBuf>) -> Self {
        Self {
            input,
            destination: destination.into(),
        }
    }
    pub fn build(self) -> Result<ValidatedGeneration, SnapshotError> {
        let (mut header, histories) = prepare(&self.input)?;
        let generation = generation_id(&self.input, &header);
        header.generation = generation.clone();
        let header_bytes = encode_header(&header)?;
        let parent = destination_parent(&self.destination);
        fs::create_dir_all(parent)?;
        let temp = create_temporary_generation(parent)?;
        write_generation(&temp.path, &header_bytes, &histories)?;
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&self.destination)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    SnapshotError::Invalid("generation destination already exists".into())
                } else {
                    error.into()
                }
            })?;
        if let Err(error) = replace_file(&temp.path, &self.destination) {
            let _ = fs::remove_file(&self.destination);
            return Err(error.into());
        }
        sync_file(&self.destination)?;
        sync_directory(parent)?;
        Ok(ValidatedGeneration {
            path: self.destination,
            generation,
            header,
            header_bytes,
        })
    }
}

pub(super) fn destination_parent(destination: &Path) -> &Path {
    destination
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn prepare(
    input: &SnapshotBuildInput,
) -> Result<(SnapshotHeaderV1, BTreeMap<String, Vec<u8>>), SnapshotError> {
    validate_registry_id(&input.registry_id)?;
    if input.sources.len() > HEADER_SOURCE_LIMIT {
        return Err(SnapshotError::Invalid("too many snapshot sources".into()));
    }
    let mut sources = input
        .sources
        .iter()
        .enumerate()
        .map(|(input_index, source)| -> Result<_, SnapshotError> {
            Ok((input_index, source_observation(source)?))
        })
        .collect::<Result<Vec<_>, _>>()?;
    sources.sort_by(|a, b| a.1.id.cmp(&b.1.id));
    if sources.windows(2).any(|w| w[0].1.id == w[1].1.id) {
        return Err(SnapshotError::Invalid("duplicate source id".into()));
    }
    let mut source_index_remap = vec![0_u32; sources.len()];
    for (sorted_index, (input_index, _)) in sources.iter().enumerate() {
        source_index_remap[*input_index] = sorted_index as u32;
    }
    let sources = sources
        .into_iter()
        .map(|(_, source)| source)
        .collect::<Vec<_>>();
    let source_indexes = sources
        .iter()
        .enumerate()
        .map(|(i, s)| (s.id.clone(), i as u32))
        .collect::<BTreeMap<_, _>>();
    let mut histories = BTreeMap::new();
    for history in &input.histories {
        let mut canonical_history = history.clone();
        for observation in &mut canonical_history.observations {
            let input_index = usize::try_from(observation.source_index).map_err(|_| {
                SnapshotError::Invalid("observation source index is out of range".into())
            })?;
            observation.source_index = *source_index_remap.get(input_index).ok_or_else(|| {
                SnapshotError::Invalid("observation source index is out of range".into())
            })?;
        }
        validate_history(&canonical_history, &source_indexes, sources.len())?;
        let encoded = encode_history(&canonical_history)?;
        if histories
            .insert(canonical_history.package.clone(), encoded)
            .is_some()
        {
            return Err(SnapshotError::Invalid("duplicate package history".into()));
        }
    }
    let manifest = history_manifest(&histories);
    let observation_count = input
        .histories
        .iter()
        .map(|h| h.observations.len() as u64)
        .sum();
    let eligible_count = input
        .histories
        .iter()
        .map(|h| h.eligible_releases.len() as u64)
        .sum();
    let incomplete_count = input
        .histories
        .iter()
        .filter(|h| matches!(h.state, LookupStateV1::Incomplete))
        .count() as u64;
    let mut coverage = input.coverage.clone();
    coverage.source_ids.sort();
    coverage.source_ids.dedup();
    coverage.missing_evidence.sort();
    coverage.missing_evidence.dedup();
    let expected_source_ids = sources
        .iter()
        .map(|source| source.id.clone())
        .collect::<Vec<_>>();
    if coverage.source_ids != expected_source_ids {
        return Err(SnapshotError::Invalid(
            "coverage source_ids must match the configured source observations".into(),
        ));
    }
    let header = SnapshotHeaderV1 {
        format: "rsolve-metadata-snapshot".into(),
        version: 1,
        history_encoding: HISTORY_ENCODING,
        normalization_policy: input.normalization_policy,
        compatibility_profile: input.compatibility_profile,
        parser_schema: input.parser_schema,
        registry_id: input.registry_id.to_string(),
        generation: String::new(),
        created_at: input.created_at.clone(),
        producer: input.producer.clone(),
        coverage,
        sources,
        package_count: histories.len() as u64,
        observation_count,
        eligible_release_count: eligible_count,
        incomplete_package_count: incomplete_count,
        history_manifest_sha256: hex(&manifest),
    };
    Ok((header, histories))
}

pub(crate) fn source_observation(
    input: &SourceInput,
) -> Result<SourceObservationV1, SnapshotError> {
    let content = hex(&input.content_sha256);
    let id = hex(&hash_parts(
        b"rsolve.metadata-source-id\0v1",
        [&input.kind, &input.representation, &content],
    ));
    Ok(SourceObservationV1 {
        id,
        kind: input.kind.clone(),
        representation: input.representation.clone(),
        content_sha256: content,
        etag: input.etag.clone(),
        last_modified: input.last_modified.clone(),
        observed_at: input.observed_at.clone(),
        endpoint: input.endpoint.clone(),
    })
}
