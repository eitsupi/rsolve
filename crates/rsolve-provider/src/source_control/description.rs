//! Projection of a source-tree DESCRIPTION into resolver metadata.
//!
//! This module is deliberately independent of the source-control backend. It
//! consumes an already validated immutable source view and a caller-owned
//! release identity; Git URLs, revisions, and object storage remain outside
//! this boundary.

use std::path::{Path, PathBuf};

use rsolve_core::{
    PackageName, PackageRelease, PackageReleaseError, PackageRequirement, RPackageVersion,
    ReleaseIdentity, ReleaseObservation,
};
use thiserror::Error;

use super::ImmutableSourceView;
use super::tree::ValidatedFileError;
use crate::package_description::{
    DcfDocument, DcfError, DescriptionError, parse_description_fields,
};

/// Maximum DESCRIPTION size accepted by the source-tree projector.
///
/// DESCRIPTION is small package metadata. Keeping this bound separate from
/// the source-tree blob limit ensures malformed metadata cannot consume the
/// larger source-view budget.
pub const MAX_DESCRIPTION_BYTES: u64 = 1 << 20;

/// Inputs required to project one source-tree DESCRIPTION.
#[derive(Clone, Debug)]
pub struct DescriptionProjectionRequest<'a> {
    /// The canonical identity selected by the caller. Its provenance is not
    /// inferred from DESCRIPTION fields.
    pub identity: &'a ReleaseIdentity,
    /// Package and version constraint expected by the selected graph edge.
    pub expected: &'a PackageRequirement,
}

impl<'a> DescriptionProjectionRequest<'a> {
    pub fn new(identity: &'a ReleaseIdentity, expected: &'a PackageRequirement) -> Self {
        Self { identity, expected }
    }
}

/// A failure while reading or validating a source-tree DESCRIPTION.
#[derive(Debug, Error)]
pub enum DescriptionProjectionError {
    #[error("source-tree DESCRIPTION is missing")]
    Missing { path: PathBuf },
    #[error("source-tree DESCRIPTION is a symlink")]
    Symlink { path: PathBuf },
    #[error("source-tree DESCRIPTION is not a regular file")]
    NotRegular { path: PathBuf },
    #[error("source-tree DESCRIPTION exceeds the {limit}-byte limit")]
    TooLarge { path: PathBuf, limit: u64 },
    #[error("source-tree DESCRIPTION changed after validation")]
    Changed { path: PathBuf },
    #[error("source-tree DESCRIPTION I/O failed at {path}: {reason}")]
    Io { path: PathBuf, reason: String },
    #[error("source-tree DESCRIPTION DCF is invalid: {0}")]
    Dcf(#[from] DcfError),
    #[error("source-tree DESCRIPTION must contain exactly one record, found {count}")]
    MultipleRecords { count: usize },
    #[error("source-tree DESCRIPTION is missing required field {field}")]
    MissingField { field: &'static str },
    #[error("source-tree DESCRIPTION contains duplicate field {field}")]
    DuplicateField { field: String },
    #[error("source-tree DESCRIPTION record is invalid: {reason}")]
    InvalidRecord { reason: String },
    #[error("DESCRIPTION package {actual} does not match expected package {expected}")]
    PackageMismatch {
        expected: PackageName,
        actual: PackageName,
    },
    #[error("DESCRIPTION package {description} does not match release identity {identity}")]
    IdentityPackageMismatch {
        identity: PackageName,
        description: PackageName,
    },
    #[error("DESCRIPTION version {version} does not satisfy the expected constraint")]
    VersionConstraintMismatch { version: RPackageVersion },
    #[error("projected DESCRIPTION release is invalid: {0}")]
    Domain(#[from] PackageReleaseError),
}

/// Reads and projects the root `DESCRIPTION` in an immutable source view.
///
/// Only `<view>/DESCRIPTION` is considered. The file is bounded before being
/// handed to the backend-neutral DCF and DESCRIPTION parser, and a DCF
/// document containing anything other than one record is rejected. Dependency
/// parsing and metadata filtering are delegated to the shared
/// `package_description` layer so all providers retain one canonical
/// DESCRIPTION semantics.
pub fn project_description(
    view: &ImmutableSourceView,
    request: DescriptionProjectionRequest<'_>,
) -> Result<PackageRelease, DescriptionProjectionError> {
    if request.expected.name() != request.identity.name() {
        return Err(DescriptionProjectionError::PackageMismatch {
            expected: request.expected.name().clone(),
            actual: request.identity.name().clone(),
        });
    }

    let path = view.path().join("DESCRIPTION");
    let bytes = read_description(view, &path)?;
    let document = DcfDocument::parse(&bytes)?;
    let record = match document.records() {
        [record] => record,
        records => {
            return Err(DescriptionProjectionError::MultipleRecords {
                count: records.len(),
            });
        }
    };
    let fields = record
        .fields()
        .iter()
        .map(|field| (field.name(), field.value()))
        .collect::<Vec<_>>();
    let parsed = parse_description_fields(&fields).map_err(map_record_error)?;

    let description_package = parsed.package.clone();
    if description_package != *request.expected.name() {
        return Err(DescriptionProjectionError::PackageMismatch {
            expected: request.expected.name().clone(),
            actual: description_package,
        });
    }
    if parsed.package != *request.identity.name() {
        return Err(DescriptionProjectionError::IdentityPackageMismatch {
            identity: request.identity.name().clone(),
            description: parsed.package,
        });
    }
    if !request.expected.constraint().satisfies(&parsed.version) {
        return Err(DescriptionProjectionError::VersionConstraintMismatch {
            version: parsed.version,
        });
    }

    let observation = ReleaseObservation {
        identity: request.identity.clone(),
        observed_package: parsed.package,
        observed_version: parsed.version,
        metadata: parsed.metadata,
        publication: parsed.publication,
        declared_dependencies: parsed.dependencies,
        distributions: Vec::new(),
    };
    Ok(PackageRelease::try_from(observation)?)
}

fn map_record_error(error: DescriptionError) -> DescriptionProjectionError {
    match error {
        DescriptionError::MissingField(field) => DescriptionProjectionError::MissingField { field },
        DescriptionError::DuplicateField(field) => {
            DescriptionProjectionError::DuplicateField { field }
        }
        error => DescriptionProjectionError::InvalidRecord {
            reason: error.to_string(),
        },
    }
}

fn read_description(
    view: &ImmutableSourceView,
    display_path: &Path,
) -> Result<Vec<u8>, DescriptionProjectionError> {
    view.read_validated_file("DESCRIPTION", MAX_DESCRIPTION_BYTES)
        .map_err(|error| match error {
            ValidatedFileError::Missing => DescriptionProjectionError::Missing {
                path: display_path.to_owned(),
            },
            ValidatedFileError::Symlink => DescriptionProjectionError::Symlink {
                path: display_path.to_owned(),
            },
            ValidatedFileError::NotRegular => DescriptionProjectionError::NotRegular {
                path: display_path.to_owned(),
            },
            ValidatedFileError::TooLarge { limit } => DescriptionProjectionError::TooLarge {
                path: display_path.to_owned(),
                limit,
            },
            ValidatedFileError::Changed => DescriptionProjectionError::Changed {
                path: display_path.to_owned(),
            },
            ValidatedFileError::Io { reason } => DescriptionProjectionError::Io {
                path: display_path.to_owned(),
                reason,
            },
            ValidatedFileError::NotValidated => DescriptionProjectionError::Io {
                path: display_path.to_owned(),
                reason: error.to_string(),
            },
        })
}

#[cfg(test)]
mod tests;
