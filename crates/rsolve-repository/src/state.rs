use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

use crate::filesystem::io_error;
use crate::materialization::{
    MaterializationError, MaterializationState, MaterializationTransaction,
};

pub(super) fn read_state(path: &Path) -> Result<MaterializationState, MaterializationError> {
    let text = fs::read_to_string(path)
        .map_err(|source| io_error("read materialization state", path, source))?;
    toml::from_str(&text).map_err(|source| MaterializationError::InvalidState {
        path: path.to_path_buf(),
        reason: source.to_string(),
    })
}

pub(super) fn write_state_temp(
    path: &Path,
    state: &MaterializationState,
) -> Result<(), MaterializationError> {
    let encoded =
        toml::to_string_pretty(state).map_err(|source| MaterializationError::InvalidState {
            path: path.to_path_buf(),
            reason: source.to_string(),
        })?;
    write_temp(path, encoded.as_bytes(), "materialization state temporary")
}

pub(super) fn write_transaction_temp(
    path: &Path,
    transaction: &MaterializationTransaction,
) -> Result<(), MaterializationError> {
    let encoded = toml::to_string_pretty(transaction).map_err(|source| {
        MaterializationError::InvalidState {
            path: path.to_path_buf(),
            reason: source.to_string(),
        }
    })?;
    write_temp(path, encoded.as_bytes(), "transaction temporary")
}

fn write_temp(path: &Path, bytes: &[u8], label: &'static str) -> Result<(), MaterializationError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|source| io_error("create materialization temporary", path, source))?;
    if let Err(error) = (|| -> io::Result<()> {
        file.write_all(bytes)?;
        file.sync_all()
    })() {
        let _ = fs::remove_file(path);
        return Err(io_error(label, path, error));
    }
    Ok(())
}
