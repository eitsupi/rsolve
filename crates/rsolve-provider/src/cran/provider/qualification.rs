use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::DEFAULT_COMPATIBLE_GENERATION_TTL;
use super::{CRAN_COMPATIBILITY_PROFILE, CRAN_NORMALIZATION_POLICY, CRAN_PARSER_SCHEMA};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Status {
    Positive,
    Negative,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[allow(clippy::enum_variant_names)]
pub(super) enum CoverageStatus {
    CurrentComplete,
    CurrentGapped,
    CurrentConflicting,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct Record {
    pub(super) format: String,
    pub(super) version: u32,
    pub(super) repository_endpoint: String,
    pub(super) feed_endpoint: String,
    pub(super) current_digest: String,
    pub(super) archive_digest: String,
    pub(super) feed_digest: String,
    pub(super) feed_etag: Option<String>,
    pub(super) feed_last_modified: Option<String>,
    pub(super) canonical_current_digest: String,
    pub(super) canonical_archive_digest: String,
    pub(super) coverage_status: CoverageStatus,
    pub(super) covered_count: usize,
    pub(super) gapped_count: usize,
    pub(super) conflicting_count: usize,
    pub(super) coverage_digest: String,
    pub(super) compatibility_profile: u32,
    pub(super) parser_schema: u32,
    pub(super) normalization_policy: u32,
    pub(super) status: Status,
    pub(super) diagnostic: String,
    pub(super) failure_count: u32,
    pub(super) next_probe_at: Option<String>,
    pub(super) validated_at: String,
}

impl Default for Record {
    fn default() -> Self {
        Self {
            format: "rsolve-cran-allpackages-qualification".into(),
            version: 1,
            repository_endpoint: String::new(),
            feed_endpoint: String::new(),
            current_digest: String::new(),
            archive_digest: String::new(),
            feed_digest: String::new(),
            feed_etag: None,
            feed_last_modified: None,
            canonical_current_digest: String::new(),
            canonical_archive_digest: String::new(),
            coverage_status: CoverageStatus::CurrentGapped,
            covered_count: 0,
            gapped_count: 0,
            conflicting_count: 0,
            coverage_digest: String::new(),
            compatibility_profile: CRAN_COMPATIBILITY_PROFILE,
            parser_schema: CRAN_PARSER_SCHEMA,
            normalization_policy: CRAN_NORMALIZATION_POLICY,
            status: Status::Unknown,
            diagnostic: String::new(),
            failure_count: 0,
            next_probe_at: None,
            validated_at: String::new(),
        }
    }
}

/// The registry identity is intentionally not duplicated in this record: the
/// path is allocated below the registry-specific `SnapshotStore` root, so a
/// record can never be opened by another registry namespace.
pub(super) fn load(path: &Path) -> Option<Record> {
    let bytes = fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

pub(super) fn load_result(path: &Path) -> Result<Option<Record>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(path).map_err(|error| error.to_string())?;
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|error| format!("invalid ALLPACKAGES qualification record: {error}"))
}

pub(super) fn matches(
    record: &Record,
    repository_endpoint: &str,
    feed_endpoint: &str,
    current_digest: &str,
    archive_digest: &str,
    feed_digest: Option<&str>,
) -> bool {
    record.format == "rsolve-cran-allpackages-qualification"
        && record.version == 1
        && record.repository_endpoint == repository_endpoint
        && record.feed_endpoint == feed_endpoint
        && record.current_digest == current_digest
        && record.archive_digest == archive_digest
        && feed_digest.is_none_or(|digest| record.feed_digest == digest)
        && record.compatibility_profile == CRAN_COMPATIBILITY_PROFILE
        && record.parser_schema == CRAN_PARSER_SCHEMA
        && record.normalization_policy == CRAN_NORMALIZATION_POLICY
}

pub(super) fn positive_reusable(record: &Record, now: jiff::Timestamp) -> bool {
    if record.canonical_current_digest.is_empty() || record.canonical_archive_digest.is_empty() {
        return false;
    }
    let Ok(validated_at) = record.validated_at.parse::<jiff::Timestamp>() else {
        return false;
    };
    if validated_at > now {
        return false;
    }
    now.duration_since(validated_at)
        .try_into()
        .is_ok_and(|age: Duration| age <= DEFAULT_COMPATIBLE_GENERATION_TTL)
}

pub(super) fn publish(path: &Path, record: &Record) -> Result<(), String> {
    let bytes = serde_json::to_vec(record).map_err(|error| error.to_string())?;
    let temporary = path.with_extension("json.tmp");
    let mut file = File::create(&temporary).map_err(|error| error.to_string())?;
    file.write_all(&bytes).map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())?;
    drop(file);
    crate::snapshot::replace_file(&temporary, path).map_err(|error| error.to_string())?;
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|error| error.to_string())?;
    sync_parent(path.parent().unwrap_or_else(|| Path::new(".")))
}

#[cfg(unix)]
fn sync_parent(path: &Path) -> Result<(), String> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|error| error.to_string())
}

#[cfg(not(unix))]
fn sync_parent(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_record_is_reported_for_revalidation() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("qualification.json");
        fs::write(&path, b"not-json").unwrap();
        let error = load_result(&path).unwrap_err();
        assert!(error.contains("invalid ALLPACKAGES qualification record"));
    }

    #[test]
    fn publish_replaces_record_atomically_and_preserves_feed_binding() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("qualification.json");
        let record = Record {
            repository_endpoint: "repo".into(),
            feed_endpoint: "feed".into(),
            current_digest: "current".into(),
            archive_digest: "archive".into(),
            feed_digest: "feed-digest".into(),
            ..Record::default()
        };
        publish(&path, &record).unwrap();
        let loaded = load_result(&path).unwrap().unwrap();
        assert!(matches(
            &loaded,
            "repo",
            "feed",
            "current",
            "archive",
            Some("feed-digest")
        ));
        assert_eq!(loaded.feed_digest, "feed-digest");
    }

    #[test]
    fn positive_reuse_has_a_fail_closed_24_hour_boundary() {
        let now = "2026-08-25T00:00:00Z".parse().unwrap();
        let mut record = Record {
            validated_at: "2026-08-24T00:00:00Z".into(),
            canonical_current_digest: "current".into(),
            canonical_archive_digest: "archive".into(),
            ..Record::default()
        };
        assert!(positive_reusable(&record, now));
        record.validated_at = "2026-08-23T23:59:59Z".into();
        assert!(!positive_reusable(&record, now));
        record.validated_at = "2026-08-25T00:00:01Z".into();
        assert!(!positive_reusable(&record, now));
        record.validated_at = "not-a-timestamp".into();
        assert!(!positive_reusable(&record, now));
    }
}
