use super::*;

#[cfg(test)]
use std::cell::Cell;

pub(crate) fn encode_history(history: &PackageHistoryV1) -> Result<Vec<u8>, SnapshotError> {
    let payload = postcard::to_stdvec(&PostcardHistoryV1(history.clone()))?;
    if payload.len() > HISTORY_LIMIT - HISTORY_PREFIX_LEN {
        return Err(SnapshotError::Invalid(
            "history payload exceeds its byte limit".into(),
        ));
    }
    let mut output = Vec::with_capacity(HISTORY_PREFIX_LEN + payload.len());
    output.extend_from_slice(HISTORY_MAGIC);
    output.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    output.extend_from_slice(&Sha256::digest(&payload));
    output.extend_from_slice(&payload);
    Ok(output)
}

pub fn decode_history(bytes: &[u8]) -> Result<PackageHistoryV1, SnapshotError> {
    if bytes.len() < HISTORY_PREFIX_LEN
        || bytes.len() > HISTORY_LIMIT
        || &bytes[..8] != HISTORY_MAGIC
    {
        return Err(SnapshotError::Invalid("invalid history envelope".into()));
    }
    let length = usize::try_from(u64::from_le_bytes(
        bytes[8..16]
            .try_into()
            .map_err(|_| SnapshotError::Invalid("invalid history length".into()))?,
    ))
    .map_err(|_| SnapshotError::Invalid("history length does not fit usize".into()))?;
    if length != bytes.len() - HISTORY_PREFIX_LEN {
        return Err(SnapshotError::Invalid(
            "history payload length mismatch".into(),
        ));
    }
    let digest: [u8; 32] = bytes[16..48]
        .try_into()
        .map_err(|_| SnapshotError::Invalid("invalid history digest".into()))?;
    let payload = &bytes[48..];
    if Sha256::digest(payload).as_slice() != digest {
        return Err(SnapshotError::Invalid(
            "history payload digest mismatch".into(),
        ));
    }
    let (decoded, remainder): (PostcardHistoryV1, &[u8]) = postcard::take_from_bytes(payload)?;
    if !remainder.is_empty() || postcard::to_stdvec(&decoded)? != payload {
        return Err(SnapshotError::Invalid(
            "non-canonical history payload".into(),
        ));
    }
    validate_history_limits(&decoded.0)?;
    Ok(decoded.0)
}

/// Encode a snapshot header using the strict canonical JSON representation.
pub fn encode_header(header: &SnapshotHeaderV1) -> Result<Vec<u8>, SnapshotError> {
    let bytes = canonical_json(header)?;
    if bytes.len() > HEADER_LIMIT {
        return Err(SnapshotError::Invalid(
            "snapshot header exceeds its byte limit".into(),
        ));
    }
    Ok(bytes)
}

/// Decode and canonicality-check a snapshot header without consulting redb.
pub fn decode_header(bytes: &[u8]) -> Result<SnapshotHeaderV1, SnapshotError> {
    if bytes.len() > HEADER_LIMIT {
        return Err(SnapshotError::Invalid(
            "snapshot header exceeds its byte limit".into(),
        ));
    }
    let header: SnapshotHeaderV1 = serde_json::from_slice(bytes)?;
    if canonical_json(&header)? != bytes {
        return Err(SnapshotError::Invalid(
            "snapshot header is not canonical JSON".into(),
        ));
    }
    validate_header(&header)?;
    Ok(header)
}

pub(super) fn read_generation_header(path: impl AsRef<Path>) -> Result<Vec<u8>, SnapshotError> {
    let database = ReadOnlyDatabase::open(path.as_ref())?;
    let read = database.begin_read()?;
    let table = read.open_table(SNAPSHOT_HEADER)?;
    let value = table
        .get(HEADER_KEY)?
        .ok_or_else(|| SnapshotError::Invalid("snapshot header is missing".into()))?;
    if value.value().len() > HEADER_LIMIT {
        return Err(SnapshotError::Invalid(
            "snapshot header exceeds its byte limit".into(),
        ));
    }
    Ok(value.value().to_vec())
}

/// Fully validate a read-only generation, including every package history and
/// the header's aggregate counts and history manifest.
pub(super) fn validate_generation(
    path: impl AsRef<Path>,
    configured_registry_id: &RegistryId,
) -> Result<SnapshotHeaderV1, SnapshotError> {
    #[cfg(test)]
    VALIDATION_COUNT.with(|count| count.set(count.get() + 1));
    let database = ReadOnlyDatabase::open(path.as_ref())?;
    let read = database.begin_read()?;
    let header_table = read.open_table(SNAPSHOT_HEADER)?;
    let stored_header = header_table
        .get(HEADER_KEY)?
        .ok_or_else(|| SnapshotError::Invalid("snapshot header is missing".into()))?;
    let header_bytes = stored_header.value();
    let header = decode_header(header_bytes)?;
    if header.registry_id != configured_registry_id.as_str() {
        return Err(SnapshotError::Invalid(
            "snapshot registry does not match configured registry".into(),
        ));
    }
    let source_indexes = header
        .sources
        .iter()
        .enumerate()
        .map(|(index, source)| (source.id.clone(), index as u32))
        .collect::<BTreeMap<_, _>>();
    let history_table = read.open_table(PACKAGE_HISTORIES)?;
    let mut count = 0_u64;
    let mut observation_count = 0_u64;
    let mut eligible_count = 0_u64;
    let mut incomplete_count = 0_u64;
    let mut manifest_entries = BTreeMap::new();
    for row in history_table.iter()? {
        let (key, value) = row?;
        let key = key.value();
        let history = decode_history(value.value())?;
        if history.package != key {
            return Err(SnapshotError::Invalid(
                "history key/package mismatch".into(),
            ));
        }
        validate_history(&history, &source_indexes, header.sources.len())?;
        observation_count += history.observations.len() as u64;
        eligible_count += history.eligible_releases.len() as u64;
        incomplete_count += u64::from(matches!(history.state, LookupStateV1::Incomplete));
        manifest_entries.insert(key.to_owned(), value.value().to_vec());
        count += 1;
    }
    if header.package_count != count
        || header.observation_count != observation_count
        || header.eligible_release_count != eligible_count
        || header.incomplete_package_count != incomplete_count
        || header.history_manifest_sha256 != hex(&history_manifest(&manifest_entries))
        || header.generation != generation_id_from_header(&header)
    {
        return Err(SnapshotError::Invalid(
            "history count or manifest mismatch".into(),
        ));
    }
    Ok(header)
}

pub(super) fn write_generation(
    path: &Path,
    header: &[u8],
    histories: &BTreeMap<String, Vec<u8>>,
) -> Result<(), SnapshotError> {
    write_generation_unvalidated(path, header, histories)?;
    let parsed_header = decode_header(header)?;
    let registry_id = RegistryId::new(&parsed_header.registry_id)
        .map_err(|error| SnapshotError::Invalid(error.to_string()))?;
    let validated_header = validate_generation(path, &registry_id)?;
    if encode_header(&validated_header)? != header
        || validated_header.package_count != histories.len() as u64
    {
        return Err(SnapshotError::Invalid(
            "snapshot validation does not match staged input".into(),
        ));
    }
    Ok(())
}

/// Writes and durably compacts a generation without reading it back.  The
/// caller must validate the resulting file before publication.
pub(super) fn write_generation_unvalidated(
    path: &Path,
    header: &[u8],
    histories: &BTreeMap<String, Vec<u8>>,
) -> Result<(), SnapshotError> {
    let mut database = Database::create(path)?;
    {
        let tx = database.begin_write()?;
        {
            let mut table = tx.open_table(SNAPSHOT_HEADER)?;
            table.insert(HEADER_KEY, header)?;
        }
        {
            let mut table = tx.open_table(PACKAGE_HISTORIES)?;
            for (package, value) in histories {
                table.insert(package.as_str(), value.as_slice())?;
            }
        }
        tx.commit()?;
    }
    database.compact()?;
    drop(database);
    sync_file(path)?;
    Ok(())
}

#[cfg(test)]
thread_local! {
    static VALIDATION_COUNT: Cell<u64> = const { Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn reset_validation_count() {
    VALIDATION_COUNT.with(|count| count.set(0));
}

#[cfg(test)]
pub(crate) fn validation_count() -> u64 {
    VALIDATION_COUNT.with(Cell::get)
}

pub(super) fn sync_file(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(unix)]
pub(super) fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(windows)]
pub(super) fn sync_directory(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
pub(crate) fn replace_file(from: &Path, to: &Path) -> io::Result<()> {
    fs::rename(from, to)
}

#[cfg(windows)]
pub(crate) fn replace_file(from: &Path, to: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };
    let from = from
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let to = to
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    if unsafe {
        MoveFileExW(
            from.as_ptr(),
            to.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(super) fn history_manifest(histories: &BTreeMap<String, Vec<u8>>) -> [u8; 32] {
    let mut input = Vec::new();
    append_part(&mut input, b"rsolve.metadata-history-manifest\0v1");
    append_part(&mut input, histories.len().to_string().as_bytes());
    for (package, bytes) in histories {
        append_part(&mut input, package.as_bytes());
        append_part(&mut input, &Sha256::digest(bytes));
    }
    Sha256::digest(input).into()
}
fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, SnapshotError> {
    Ok(serde_json::to_vec(value)?)
}
