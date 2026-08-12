//! Durable repository publication and crash recovery.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::filesystem::{
    directory_names, hash_file, io_error, is_directory, is_regular_file, transaction_conflict,
};
use crate::packages::write_packages;
use crate::state::{read_state, write_transaction_temp};
use crate::util::{sync_directory, unique_nonce};
use crate::{MaterializationArtifact, MaterializationError, MaterializationRecord};
use sha2::{Digest, Sha256};

use crate::materialization::{
    MaterializationState, MaterializationTransaction, canonical_artifacts, identity_key,
};

const STATE_NAME: &str = "materialization.toml";
const TRANSACTION_NAME: &str = ".materialization.transaction.toml";
const STAGING_PREFIX: &str = ".repository.partial.";

pub(super) fn recover(
    nrr: &Path,
    state_path: &Path,
    transaction_path: &Path,
    repository: &Path,
    requested: &[MaterializationArtifact],
) -> Result<(), MaterializationError> {
    let states = partial_paths(nrr, &format!(".{STATE_NAME}.partial."))?;
    let markers = partial_paths(nrr, &format!("{TRANSACTION_NAME}.partial."))?;
    let stagings = partial_paths(nrr, STAGING_PREFIX)?;
    if !fs::symlink_metadata(transaction_path).is_ok() {
        if reconstruct(nrr, &states, &markers, &stagings, requested)? {
            return recover(nrr, state_path, transaction_path, repository, requested);
        }
        return Ok(());
    }
    if !is_regular_file(transaction_path) {
        return Err(transaction_conflict(
            transaction_path,
            "transaction marker is not a regular file",
        ));
    }
    if !markers.is_empty() {
        return Err(transaction_conflict(
            transaction_path,
            "transaction marker has an ambiguous temporary sibling",
        ));
    }
    let tx = read_transaction(transaction_path)?;
    if tx.schema_version != 2 || !records_match_requested(&tx.records, requested) {
        return Err(transaction_conflict(
            transaction_path,
            "transaction records or schema do not match the request",
        ));
    }
    validate_index_digest(&tx, requested)?;
    let state_temp = transaction_temp_path(nrr, &tx.state_temp)
        .ok_or_else(|| transaction_conflict(transaction_path, "invalid state temporary path"))?;
    let staging = staging_path(nrr, &tx.staging_dir)
        .ok_or_else(|| transaction_conflict(transaction_path, "invalid staging directory path"))?;
    if stagings.len() > 1 || (!stagings.is_empty() && stagings[0] != staging) {
        return Err(transaction_conflict(
            transaction_path,
            "staging does not match transaction marker",
        ));
    }
    let repo_exists = fs::symlink_metadata(repository).is_ok();
    let staging_exists = fs::symlink_metadata(&staging).is_ok();
    if repo_exists == staging_exists {
        return Err(transaction_conflict(
            &staging,
            "repository and staging must have exactly one existing path",
        ));
    }
    if state_path.exists() && !is_regular_file(state_path) {
        return Err(transaction_conflict(
            state_path,
            "committed state is not a regular file",
        ));
    }

    // Validate all transaction inputs before changing either publication name.
    let temporary_state = if state_path.exists() && states.is_empty() {
        let state = read_state(state_path)?;
        if !state_matches(&state, &tx, requested) {
            return Err(transaction_conflict(
                state_path,
                "committed state differs from transaction",
            ));
        }
        None
    } else {
        if states.len() != 1 || states[0] != state_temp || !is_regular_file(&state_temp) {
            return Err(transaction_conflict(
                transaction_path,
                "state temporary does not match marker",
            ));
        }
        let state = read_state(&state_temp).map_err(|error| {
            transaction_conflict(&state_temp, format!("invalid state temporary: {error}"))
        })?;
        if !state_matches(&state, &tx, requested) {
            return Err(transaction_conflict(
                &state_temp,
                "state temporary does not match transaction",
            ));
        }
        if state_path.exists() && read_state(state_path)? != state {
            return Err(transaction_conflict(
                state_path,
                "committed state differs from temporary state",
            ));
        }
        Some(state)
    };
    if repo_exists {
        if !is_directory(repository) {
            return Err(transaction_conflict(
                repository,
                "published repository is not a directory",
            ));
        }
        validate_repository_contents(repository, &tx.records, &tx.index_sha256)?;
    } else {
        if !is_directory(&staging) {
            return Err(transaction_conflict(
                &staging,
                "staging path is not a directory",
            ));
        }
        validate_repository_contents(&staging, &tx.records, &tx.index_sha256)?;
        fs::rename(&staging, repository)
            .map_err(|source| io_error("recover repository publication", repository, source))?;
        sync_directory(nrr).map_err(|source| MaterializationError::Cache {
            path: nrr.to_path_buf(),
            source,
        })?;
    }
    if temporary_state.is_some() {
        if state_path.exists() {
            fs::remove_file(&state_temp).map_err(|source| {
                io_error("remove recovered state temporary", &state_temp, source)
            })?;
        } else {
            fs::rename(&state_temp, state_path)
                .map_err(|source| io_error("recover materialization state", state_path, source))?;
            sync_directory(nrr).map_err(|source| MaterializationError::Cache {
                path: nrr.to_path_buf(),
                source,
            })?;
        }
    }
    fs::remove_file(transaction_path)
        .map_err(|source| io_error("remove recovered transaction", transaction_path, source))?;
    sync_directory(nrr).map_err(|source| MaterializationError::Cache {
        path: nrr.to_path_buf(),
        source,
    })
}

fn state_matches(
    state: &MaterializationState,
    tx: &MaterializationTransaction,
    requested: &[MaterializationArtifact],
) -> bool {
    state.schema_version == 2
        && state.index_sha256 == tx.index_sha256
        && state.records == tx.records
        && records_match_requested(&state.records, requested)
}

fn reconstruct(
    nrr: &Path,
    states: &[PathBuf],
    markers: &[PathBuf],
    stagings: &[PathBuf],
    requested: &[MaterializationArtifact],
) -> Result<bool, MaterializationError> {
    if states.is_empty() && markers.is_empty() && stagings.is_empty() {
        return Ok(false);
    }
    if states.len() != 1 || stagings.len() != 1 || markers.len() > 1 {
        return Err(transaction_conflict(
            nrr,
            "orphaned transaction temporaries are ambiguous",
        ));
    }
    let state_path = &states[0];
    let staging = &stagings[0];
    if !is_regular_file(state_path) || !is_directory(staging) {
        return Err(transaction_conflict(
            nrr,
            "orphaned transaction has an unsafe filesystem type",
        ));
    }
    let state_name = basename(state_path)
        .ok_or_else(|| transaction_conflict(state_path, "invalid state temporary name"))?;
    let staging_name =
        basename(staging).ok_or_else(|| transaction_conflict(staging, "invalid staging name"))?;
    let state = read_state(state_path).map_err(|error| {
        transaction_conflict(state_path, format!("invalid orphan state: {error}"))
    })?;
    if state.schema_version != 2 || !records_match_requested(&state.records, requested) {
        return Err(transaction_conflict(
            state_path,
            "orphan state does not match request",
        ));
    }
    let tx = if let Some(path) = markers.first() {
        if !is_regular_file(path) {
            return Err(transaction_conflict(path, "orphan marker is not regular"));
        }
        let tx = read_transaction(path)?;
        if tx.schema_version != 2
            || tx.state_temp != state_name
            || tx.staging_dir != staging_name
            || tx.index_sha256 != state.index_sha256
            || tx.records != state.records
        {
            return Err(transaction_conflict(
                path,
                "orphan marker does not bind state and staging",
            ));
        }
        tx
    } else {
        MaterializationTransaction {
            schema_version: 2,
            index_sha256: state.index_sha256.clone(),
            state_temp: state_name,
            staging_dir: staging_name,
            records: state.records.clone(),
        }
    };
    validate_index_digest(&tx, requested)?;
    validate_repository_contents(staging, &tx.records, &tx.index_sha256)?;
    let marker = nrr.join(TRANSACTION_NAME);
    if let Some(path) = markers.first() {
        fs::rename(path, &marker)
            .map_err(|source| io_error("publish reconstructed transaction", &marker, source))?;
    } else {
        let temp = nrr.join(format!("{TRANSACTION_NAME}.partial.{}", unique_nonce()));
        write_transaction_temp(&temp, &tx)?;
        fs::rename(&temp, &marker)
            .map_err(|source| io_error("publish reconstructed transaction", &marker, source))?;
    }
    sync_directory(nrr).map_err(|source| MaterializationError::Cache {
        path: nrr.to_path_buf(),
        source,
    })?;
    Ok(true)
}

fn validate_index_digest(
    tx: &MaterializationTransaction,
    requested: &[MaterializationArtifact],
) -> Result<(), MaterializationError> {
    let packages =
        write_packages(requested).map_err(|source| MaterializationError::Packages { source })?;
    let digest = crate::util::hex_lower(&Sha256::digest(&packages));
    if digest != tx.index_sha256 {
        return Err(transaction_conflict(
            Path::new("materialization transaction"),
            "PACKAGES digest does not match requested metadata and dependencies",
        ));
    }
    Ok(())
}

fn basename(path: &Path) -> Option<String> {
    path.file_name()?.to_str().map(ToOwned::to_owned)
}

fn partial_paths(directory: &Path, prefix: &str) -> Result<Vec<PathBuf>, MaterializationError> {
    let mut paths = Vec::new();
    for entry in fs::read_dir(directory)
        .map_err(|source| io_error("scan transaction directory", directory, source))?
    {
        let entry =
            entry.map_err(|source| io_error("read transaction directory", directory, source))?;
        if entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.starts_with(prefix))
        {
            paths.push(entry.path());
        }
    }
    paths.sort();
    Ok(paths)
}

fn transaction_temp_path(nrr: &Path, name: &str) -> Option<PathBuf> {
    safe_temp_name(name, &format!(".{STATE_NAME}.partial.")).then(|| nrr.join(name))
}

fn staging_path(nrr: &Path, name: &str) -> Option<PathBuf> {
    safe_temp_name(name, STAGING_PREFIX).then(|| nrr.join(name))
}

fn safe_temp_name(name: &str, prefix: &str) -> bool {
    !name.is_empty()
        && !name.contains('/')
        && !name.contains('\\')
        && name.starts_with(prefix)
        && name != "."
        && name != ".."
}

fn read_transaction(path: &Path) -> Result<MaterializationTransaction, MaterializationError> {
    let text = fs::read_to_string(path)
        .map_err(|source| io_error("read materialization transaction", path, source))?;
    toml::from_str(&text).map_err(|source| MaterializationError::InvalidState {
        path: path.to_path_buf(),
        reason: source.to_string(),
    })
}

fn records_match_requested(
    records: &[MaterializationRecord],
    requested: &[MaterializationArtifact],
) -> bool {
    let canonical = canonical_artifacts(requested);
    records.len() == canonical.len()
        && canonical.iter().zip(records).all(|(selected, record)| {
            record.identity == identity_key(&selected.identity)
                && record.package == selected.package().to_string()
                && record.version == selected.version.to_string()
                && record.artifact_sha256 == selected.artifact.sha256.to_string()
                && record.size == selected.artifact.size
                && record.destination
                    == format!(
                        "repository/src/contrib/{}_{}.tar.gz",
                        selected.package(),
                        selected.version
                    )
        })
}

pub(super) fn validate_repository_contents(
    repository: &Path,
    records: &[MaterializationRecord],
    index_sha256: &str,
) -> Result<(), MaterializationError> {
    let src = repository.join("src");
    let contrib = src.join("contrib");
    if !is_directory(&src) || !is_directory(&contrib) {
        return Err(transaction_conflict(
            repository,
            "repository layout is not src/contrib",
        ));
    }
    if directory_names(repository)? != HashSet::from([String::from("src")])
        || directory_names(&src)? != HashSet::from([String::from("contrib")])
    {
        return Err(transaction_conflict(
            repository,
            "repository contains unexpected entries",
        ));
    }
    let mut expected: HashSet<String> = records
        .iter()
        .filter_map(|record| {
            record
                .destination
                .strip_prefix("repository/src/contrib/")
                .map(ToOwned::to_owned)
        })
        .collect();
    expected.insert("PACKAGES".to_owned());
    if directory_names(&contrib)? != expected {
        return Err(transaction_conflict(
            &contrib,
            "repository destinations do not match transaction",
        ));
    }
    for record in records {
        let Some(name) = record.destination.strip_prefix("repository/src/contrib/") else {
            return Err(transaction_conflict(
                &contrib,
                "destination escapes src/contrib",
            ));
        };
        let path = contrib.join(name);
        if !is_regular_file(&path) {
            return Err(transaction_conflict(
                &path,
                "destination is not a regular file",
            ));
        }
        let metadata = fs::metadata(&path)
            .map_err(|source| io_error("inspect recovered artifact", &path, source))?;
        if metadata.len() != record.size || hash_file(&path)? != record.artifact_sha256 {
            return Err(transaction_conflict(
                &path,
                "artifact digest or size differs",
            ));
        }
    }
    let packages = contrib.join("PACKAGES");
    if !is_regular_file(&packages) || hash_file(&packages)? != index_sha256 {
        return Err(transaction_conflict(&packages, "PACKAGES digest differs"));
    }
    Ok(())
}
