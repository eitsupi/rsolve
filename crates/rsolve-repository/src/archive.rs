use std::fs::File;
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};

use flate2::read::GzDecoder;
use rsolve_core::{GitCommitId, NormalizedGitUrl, RepositorySubdir};
use tar::Archive;

use super::{ArtifactValidationExpectation, CacheError};

pub(super) fn validate_source_archive(
    path: &Path,
    expectation: Option<&ArtifactValidationExpectation>,
) -> Result<(), CacheError> {
    const MAX_UNCOMPRESSED_BYTES: u64 = 256 * 1024 * 1024;
    const MAX_ENTRIES: usize = 100_000;
    let input = File::open(path).map_err(|source| CacheError::Io {
        operation: "open source archive for sanity check",
        path: path.to_path_buf(),
        source,
    })?;
    let decoder = GzDecoder::new(input);
    let mut archive = Archive::new(decoder);
    let mut total = 0_u64;
    let mut entries = 0_usize;
    let mut description = None;
    let mut description_bytes = 0_u64;
    let mut description_count = 0_usize;
    for (index, entry) in archive
        .entries()
        .map_err(|source| CacheError::InvalidArchive {
            reason: source.to_string(),
        })?
        .enumerate()
    {
        if index >= MAX_ENTRIES {
            return Err(CacheError::InvalidArchive {
                reason: "archive contains too many entries".to_owned(),
            });
        }
        let mut entry = entry.map_err(|source| CacheError::InvalidArchive {
            reason: source.to_string(),
        })?;
        let entry_path = entry.path().map_err(|source| CacheError::InvalidArchive {
            reason: source.to_string(),
        })?;
        if entry_path.is_absolute()
            || entry_path
                .components()
                .any(|component| matches!(component, Component::ParentDir | Component::RootDir))
        {
            return Err(CacheError::InvalidArchive {
                reason: "archive entry path escapes its root".to_owned(),
            });
        }
        let is_description = expectation.is_some_and(|expected| {
            entry_path == PathBuf::from(expected.package().as_str()).join("DESCRIPTION")
        });
        if is_description {
            description_count += 1;
            if description_count > 1 {
                return Err(CacheError::DuplicateDescription);
            }
            if !entry.header().entry_type().is_file() {
                return Err(CacheError::MalformedDescription {
                    reason: "DESCRIPTION entry is not a regular file".to_owned(),
                });
            }
            const MAX_DESCRIPTION_BYTES: u64 = 1 << 20;
            let mut bytes = Vec::new();
            entry
                .by_ref()
                .take(MAX_DESCRIPTION_BYTES + 1)
                .read_to_end(&mut bytes)
                .map_err(|source| CacheError::InvalidArchive {
                    reason: source.to_string(),
                })?;
            if bytes.len() as u64 > MAX_DESCRIPTION_BYTES {
                return Err(CacheError::DescriptionTooLarge {
                    limit: MAX_DESCRIPTION_BYTES,
                });
            }
            description_bytes = bytes.len() as u64;
            description = Some(parse_description(&bytes)?);
        }
        let remaining = MAX_UNCOMPRESSED_BYTES.saturating_sub(total);
        let copied = if is_description {
            description_bytes
        } else {
            io::copy(
                &mut entry.by_ref().take(remaining.saturating_add(1)),
                &mut io::sink(),
            )
            .map_err(|source| CacheError::InvalidArchive {
                reason: source.to_string(),
            })?
        };
        total = total.saturating_add(copied);
        entries += 1;
        if copied > remaining || total > MAX_UNCOMPRESSED_BYTES {
            return Err(CacheError::InvalidArchive {
                reason: "archive exceeds sanity-check size limit".to_owned(),
            });
        }
    }
    if entries == 0 {
        return Err(CacheError::InvalidArchive {
            reason: "archive contains no entries".to_owned(),
        });
    }
    if let Some(expected) = expectation {
        let fields = description.ok_or(CacheError::MissingDescription)?;
        validate_description(fields, expected)?;
    }
    Ok(())
}

#[derive(Debug)]
struct DescriptionFields {
    package: String,
    version: String,
    remote_url: Option<String>,
    remote_sha: Option<String>,
    remote_subdir: Option<String>,
}

fn parse_description(bytes: &[u8]) -> Result<DescriptionFields, CacheError> {
    let text = std::str::from_utf8(bytes).map_err(|error| CacheError::MalformedDescription {
        reason: format!("DESCRIPTION is not valid UTF-8: {error}"),
    })?;
    let mut values = std::collections::BTreeMap::<String, String>::new();
    let mut current = None::<String>;
    let mut have_field = false;
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if line.starts_with(char::is_whitespace) {
            if !have_field {
                return Err(CacheError::MalformedDescription {
                    reason: "continuation has no preceding field".to_owned(),
                });
            }
            if let Some(field) = current.as_ref() {
                let value = values.get_mut(field).expect("current field was inserted");
                value.push(' ');
                value.push_str(line.trim());
            }
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(CacheError::MalformedDescription {
                reason: "field is missing a colon".to_owned(),
            });
        };
        let key = name.trim().to_ascii_lowercase();
        if key.is_empty() || name.chars().any(char::is_whitespace) {
            return Err(CacheError::MalformedDescription {
                reason: "field name is malformed".to_owned(),
            });
        }
        if !matches!(
            key.as_str(),
            "package" | "version" | "remoteurl" | "remotesha" | "remotesubdir"
        ) {
            current = None;
            have_field = true;
            continue;
        }
        if values.contains_key(&key) {
            return Err(CacheError::DuplicateDescriptionField { field: key });
        }
        values.insert(key.clone(), value.trim().to_owned());
        current = Some(key);
        have_field = true;
    }
    let required = |field: &str| {
        values
            .get(field)
            .filter(|value| !value.is_empty())
            .cloned()
            .ok_or_else(|| CacheError::MalformedDescription {
                reason: format!("required field {field} is missing or empty"),
            })
    };
    Ok(DescriptionFields {
        package: required("package")?,
        version: required("version")?,
        remote_url: values.get("remoteurl").cloned(),
        remote_sha: values.get("remotesha").cloned(),
        remote_subdir: values.get("remotesubdir").cloned(),
    })
}

fn validate_description(
    fields: DescriptionFields,
    expected: &ArtifactValidationExpectation,
) -> Result<(), CacheError> {
    if fields.package != expected.package().as_str() {
        return Err(CacheError::DescriptionFieldMismatch {
            field: "Package",
            expected: expected.package().to_string(),
            actual: fields.package,
        });
    }
    if fields.version != expected.version().as_str() {
        return Err(CacheError::DescriptionFieldMismatch {
            field: "Version",
            expected: expected.version().to_string(),
            actual: fields.version,
        });
    }
    match expected.git_provenance() {
        Some(git) => {
            let actual_url =
                fields
                    .remote_url
                    .ok_or_else(|| CacheError::DescriptionFieldMismatch {
                        field: "RemoteUrl",
                        expected: git.repository().to_string(),
                        actual: "<missing>".to_owned(),
                    })?;
            let normalized_url = NormalizedGitUrl::new(&actual_url).map_err(|error| {
                CacheError::DescriptionFieldMismatch {
                    field: "RemoteUrl",
                    expected: git.repository().to_string(),
                    actual: format!("{actual_url} ({error})"),
                }
            })?;
            if normalized_url != *git.repository() {
                return Err(CacheError::DescriptionFieldMismatch {
                    field: "RemoteUrl",
                    expected: git.repository().to_string(),
                    actual: normalized_url.to_string(),
                });
            }
            let actual_sha =
                fields
                    .remote_sha
                    .ok_or_else(|| CacheError::DescriptionFieldMismatch {
                        field: "RemoteSha",
                        expected: git.commit().to_string(),
                        actual: "<missing>".to_owned(),
                    })?;
            let parsed_sha = GitCommitId::new(&actual_sha).map_err(|error| {
                CacheError::DescriptionFieldMismatch {
                    field: "RemoteSha",
                    expected: git.commit().to_string(),
                    actual: format!("{actual_sha} ({error})"),
                }
            })?;
            if parsed_sha != *git.commit() {
                return Err(CacheError::DescriptionFieldMismatch {
                    field: "RemoteSha",
                    expected: git.commit().to_string(),
                    actual: parsed_sha.to_string(),
                });
            }
            match (git.subdirectory(), fields.remote_subdir) {
                (Some(expected_subdir), Some(actual_subdir)) => {
                    let parsed_subdir = RepositorySubdir::new(&actual_subdir).map_err(|error| {
                        CacheError::DescriptionFieldMismatch {
                            field: "RemoteSubdir",
                            expected: expected_subdir.to_string(),
                            actual: format!("{actual_subdir} ({error})"),
                        }
                    })?;
                    if expected_subdir != &parsed_subdir {
                        return Err(CacheError::DescriptionFieldMismatch {
                            field: "RemoteSubdir",
                            expected: expected_subdir.to_string(),
                            actual: parsed_subdir.to_string(),
                        });
                    }
                }
                (Some(expected_subdir), None) => {
                    return Err(CacheError::DescriptionFieldMismatch {
                        field: "RemoteSubdir",
                        expected: expected_subdir.to_string(),
                        actual: "<missing>".to_owned(),
                    });
                }
                (None, Some(actual_subdir)) => {
                    return Err(CacheError::DescriptionFieldMismatch {
                        field: "RemoteSubdir",
                        expected: "<absent>".to_owned(),
                        actual: actual_subdir,
                    });
                }
                (None, None) => {}
            }
        }
        None => {
            for (field, value) in [
                ("RemoteUrl", fields.remote_url),
                ("RemoteSha", fields.remote_sha),
                ("RemoteSubdir", fields.remote_subdir),
            ] {
                if let Some(value) = value {
                    return Err(CacheError::DescriptionFieldMismatch {
                        field,
                        expected: "<absent>".to_owned(),
                        actual: value,
                    });
                }
            }
        }
    }
    Ok(())
}
