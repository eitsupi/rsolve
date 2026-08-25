//! Provider-private ALLPACKAGES bulk observation helpers.

#[cfg(test)]
use std::cell::Cell;
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Cursor, Read};
use std::path::Path;

use super::super::catalog::{CranCatalog, CranCatalogObservation};
use crate::cran::history::ArchiveEntry;
use redb::{Database, ReadOnlyDatabase, ReadableDatabase, TableDefinition};
use rsolve_core::PackageRelease;
use serde::{Deserialize, Serialize};
use sha2::Digest;

use super::super::catalog::{
    CranProviderObservationProjection, allpackages_observations_from_fields,
};
use super::super::dcf::DcfDocument;
use super::qualification::CoverageStatus;

const PROJECTION_FORMAT: &str = "rsolve-cran-allpackages-projection";
// Bump when the derived semantic projection changes.  Existing redb files
// must be rebuilt rather than interpreted with a different field policy.
const PROJECTION_VERSION: u32 = 2;
// The current CRAN feed is roughly 100 MiB decompressed. Keep substantial
// headroom while retaining a hard limit against compressed zip-bomb input.
const MAX_ALLPACKAGES_DECOMPRESSED_BYTES: usize = 512 * 1024 * 1024;
const HEADER: TableDefinition<&str, &[u8]> = TableDefinition::new("header");
const PACKAGE_OBSERVATIONS: TableDefinition<&str, &[u8]> =
    TableDefinition::new("package_observations");

#[cfg(test)]
thread_local! {
    static PROJECTION_BUILD_COUNT: Cell<usize> = const { Cell::new(0) };
    static PROJECTION_DECODE_COUNT: Cell<usize> = const { Cell::new(0) };
}

#[cfg(test)]
pub(super) fn reset_test_counters() {
    PROJECTION_BUILD_COUNT.with(|counter| counter.set(0));
    PROJECTION_DECODE_COUNT.with(|counter| counter.set(0));
}

#[cfg(test)]
pub(super) fn test_counters() -> (usize, usize) {
    (
        PROJECTION_BUILD_COUNT.with(Cell::get),
        PROJECTION_DECODE_COUNT.with(Cell::get),
    )
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct IndexedRecord {
    package: Option<String>,
    fields: Vec<(String, String)>,
}

pub(super) struct IndexedProjection {
    database: ReadOnlyDatabase,
}

pub(super) struct CoverageSummary {
    pub(super) status: CoverageStatus,
    pub(super) covered_count: usize,
    pub(super) gapped_count: usize,
    pub(super) conflicting_count: usize,
    pub(super) digest: String,
}

impl IndexedProjection {
    pub(super) fn observations(
        &self,
        package: &str,
    ) -> Result<CranProviderObservationProjection, String> {
        let read = self
            .database
            .begin_read()
            .map_err(|error| error.to_string())?;
        let table = read
            .open_table(PACKAGE_OBSERVATIONS)
            .map_err(|error| error.to_string())?;
        let records = table
            .get(package)
            .map_err(|error| error.to_string())?
            .map(|value| postcard::from_bytes::<Vec<IndexedRecord>>(value.value()))
            .transpose()
            .map_err(|error| error.to_string())?
            .unwrap_or_default();
        Ok(allpackages_observations_from_fields(
            records
                .into_iter()
                .enumerate()
                .map(|(index, record)| (index, record.package, record.fields))
                .collect(),
        ))
    }

    /// Classifies the complete current catalog in one read transaction. The
    /// transaction is deliberately separate from package lookup so coverage
    /// qualification never performs one redb transaction per package.
    pub(super) fn classify_current(
        &self,
        current: &CranCatalog,
    ) -> Result<CoverageSummary, String> {
        let read = self
            .database
            .begin_read()
            .map_err(|error| error.to_string())?;
        let table = read
            .open_table(PACKAGE_OBSERVATIONS)
            .map_err(|error| error.to_string())?;
        let mut covered_count = 0;
        let mut gapped_count = 0;
        let mut conflicting_count = 0;
        let mut digest = sha2::Sha256::new();
        for (package, releases) in current.packages() {
            let records = table
                .get(package.as_str())
                .map_err(|error| error.to_string())?
                .map(|value| postcard::from_bytes::<Vec<IndexedRecord>>(value.value()))
                .transpose()
                .map_err(|error| error.to_string())?
                .unwrap_or_default();
            let projection = allpackages_observations_from_fields(
                records
                    .into_iter()
                    .enumerate()
                    .map(|(index, record)| (index, record.package, record.fields))
                    .collect(),
            );
            for release in releases {
                let matching = projection
                    .observations
                    .iter()
                    .filter(|row| row.release().version() == release.version())
                    .collect::<Vec<_>>();
                let rejected = projection.rejections.iter().any(|row| {
                    row.version() == Some(release.version())
                        && row.package().is_some_and(|name| name == package)
                });
                let classification = if rejected || matching.len() > 1 {
                    conflicting_count += 1;
                    "conflicting"
                } else if let Some(row) = matching.first() {
                    if current_semantics_match(row.release(), release) {
                        covered_count += 1;
                        "covered"
                    } else {
                        // A same-identity row with different dependency
                        // semantics conflicts with the current surface.
                        conflicting_count += 1;
                        "conflicting"
                    }
                } else {
                    gapped_count += 1;
                    "gapped"
                };
                digest.update(package.as_str().as_bytes());
                digest.update([0]);
                digest.update(release.version().to_string().as_bytes());
                digest.update([0]);
                digest.update(classification.as_bytes());
                digest.update([0]);
            }
        }
        let status = if conflicting_count > 0 {
            CoverageStatus::CurrentConflicting
        } else if gapped_count > 0 {
            CoverageStatus::CurrentGapped
        } else {
            CoverageStatus::CurrentComplete
        };
        Ok(CoverageSummary {
            status,
            covered_count,
            gapped_count,
            conflicting_count,
            digest: sha256_hex(&digest.finalize()),
        })
    }
}

pub(super) fn load_or_build_projection(
    body: &[u8],
    path: &Path,
) -> Result<IndexedProjection, String> {
    let body_sha256 = sha256_hex(body);
    if path.exists() {
        let database = ReadOnlyDatabase::open(path)
            .map_err(|error| format!("invalid ALLPACKAGES projection database: {error}"))?;
        let read = database
            .begin_read()
            .map_err(|error| format!("invalid ALLPACKAGES projection transaction: {error}"))?;
        let table = read
            .open_table(HEADER)
            .map_err(|error| format!("invalid ALLPACKAGES projection header: {error}"))?;
        let value = table
            .get("header")
            .map_err(|error| format!("invalid ALLPACKAGES projection header: {error}"))?
            .ok_or_else(|| "ALLPACKAGES projection header is missing".to_owned())?;
        let header = postcard::from_bytes::<ProjectionHeader>(value.value())
            .map_err(|error| format!("invalid ALLPACKAGES projection header: {error}"))?;
        if header.format != PROJECTION_FORMAT
            || header.version != PROJECTION_VERSION
            || header.body_sha256 != body_sha256
        {
            return Err("ALLPACKAGES projection header does not match feed digest".into());
        }
        drop(table);
        drop(read);
        return Ok(IndexedProjection { database });
    }
    #[cfg(test)]
    PROJECTION_BUILD_COUNT.with(|counter| counter.set(counter.get() + 1));
    #[cfg(test)]
    PROJECTION_DECODE_COUNT.with(|counter| counter.set(counter.get() + 1));
    let decoded = decode_zstd(body)?;
    let document = DcfDocument::parse(&decoded).map_err(|error| error.to_string())?;
    let mut records = BTreeMap::<String, Vec<IndexedRecord>>::new();
    for record in document.records() {
        let package = record
            .field("Package")
            .map(|field| field.value().to_owned());
        let key = package.clone().unwrap_or_default();
        let fields = record
            .fields()
            .iter()
            .map(|field| (field.name().to_owned(), field.value().to_owned()))
            .collect();
        records
            .entry(key)
            .or_default()
            .push(IndexedRecord { package, fields });
    }
    let header = ProjectionHeader {
        format: PROJECTION_FORMAT.into(),
        version: PROJECTION_VERSION,
        body_sha256,
        record_count: document.records().len(),
    };
    let parent = path
        .parent()
        .ok_or_else(|| "projection path has no parent".to_owned())?;
    fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    let temporary = path.with_extension("redb.tmp");
    let _ = fs::remove_file(&temporary);
    let mut database = Database::create(&temporary).map_err(|error| error.to_string())?;
    {
        let tx = database.begin_write().map_err(|error| error.to_string())?;
        {
            let mut table = tx.open_table(HEADER).map_err(|error| error.to_string())?;
            let encoded = postcard::to_stdvec(&header).map_err(|error| error.to_string())?;
            table
                .insert("header", encoded.as_slice())
                .map_err(|error| error.to_string())?;
        }
        {
            let mut table = tx
                .open_table(PACKAGE_OBSERVATIONS)
                .map_err(|error| error.to_string())?;
            for (package, package_records) in records {
                let encoded =
                    postcard::to_stdvec(&package_records).map_err(|error| error.to_string())?;
                table
                    .insert(package.as_str(), encoded.as_slice())
                    .map_err(|error| error.to_string())?;
            }
        }
        tx.commit().map_err(|error| error.to_string())?;
    }
    database.compact().map_err(|error| error.to_string())?;
    drop(database);
    File::open(&temporary)
        .and_then(|file| file.sync_all())
        .map_err(|error| error.to_string())?;
    fs::rename(&temporary, path).map_err(|error| error.to_string())?;
    sync_parent(parent)?;
    let database = ReadOnlyDatabase::open(path).map_err(|error| error.to_string())?;
    Ok(IndexedProjection { database })
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

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ProjectionHeader {
    format: String,
    version: u32,
    body_sha256: String,
    record_count: usize,
}

fn sha256_hex(input: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(input)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn is_snapshot_date(value: &str) -> bool {
    value.len() == 10
        && value.as_bytes()[4] == b'-'
        && value.as_bytes()[7] == b'-'
        && value
            .bytes()
            .enumerate()
            .all(|(index, byte)| matches!(index, 4 | 7) || byte.is_ascii_digit())
}

pub(super) fn decode_zstd(input: &[u8]) -> Result<Vec<u8>, String> {
    decode_zstd_with_limit(input, MAX_ALLPACKAGES_DECOMPRESSED_BYTES)
}

fn decode_zstd_with_limit(input: &[u8], limit: usize) -> Result<Vec<u8>, String> {
    let decoder = ruzstd::decoding::StreamingDecoder::new(Cursor::new(input))
        .map_err(|error| error.to_string())?;
    let mut output = Vec::new();
    decoder
        .take((limit as u64).saturating_add(1))
        .read_to_end(&mut output)
        .map_err(|error| error.to_string())?;
    if output.len() > limit {
        return Err(format!(
            "ALLPACKAGES decompressed payload exceeds {limit} bytes"
        ));
    }
    if output.is_empty() {
        return Err("ALLPACKAGES zstd stream is empty".to_owned());
    }
    Ok(output)
}

/// Compare only fields needed to qualify an ALLPACKAGES row against the
/// target repository current catalog. Feed transport and presentation fields
/// are deliberately excluded from coverage.
pub(super) fn current_semantics_match(left: &PackageRelease, right: &PackageRelease) -> bool {
    left.identity() == right.identity()
        && left.version() == right.version()
        && left.dependencies() == right.dependencies()
        // ALLPACKAGES has no Published column. An absent publication axis is
        // therefore compatible with a dated canonical current row; compare
        // dates strictly only when both observations provide them.
        && (left.publication().is_none()
            || right.publication().is_none()
            || left.publication() == right.publication())
}

/// Binds one ALLPACKAGES observation to an archive occurrence without using
/// repository-specific filesize fields. Snapshot must agree with the date
/// embedded in DownloadURL and the basename must agree with archive.rds. A
/// duplicate Package/Version is rejected by the caller. archive.rds mtime is
/// intentionally not compared: it is tarball metadata, not a publication or
/// P3M snapshot timestamp (the fixture data demonstrates that those dates do
/// not coincide).
pub(super) fn binds_archive_occurrence(row: &CranCatalogObservation, entry: &ArchiveEntry) -> bool {
    let field = |name: &str| {
        row.fields()
            .iter()
            .find(|(field, _)| field.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    };
    let Some(package) = field("Package") else {
        return false;
    };
    let Some(version) = field("Version") else {
        return false;
    };
    let Some(download_url) = field("DownloadURL") else {
        return false;
    };
    let Some(snapshot) = field("Snapshot") else {
        return false;
    };
    let expected_filename = entry
        .source_archive_relative_path()
        .rsplit('/')
        .next()
        .unwrap_or_default();
    package == entry.package().as_str()
        && version == entry.version().to_string()
        && download_url.split('/').any(|segment| segment == snapshot)
        && is_snapshot_date(snapshot)
        && download_url
            .split('?')
            .next()
            .and_then(|url| url.rsplit('/').next())
            .is_some_and(|filename| filename == expected_filename)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cran::catalog::CranCatalog;
    use crate::cran::catalog::allpackages_observations_from_fields;
    use crate::cran::history::ArchiveEntry;

    fn row(url: &str) -> CranCatalogObservation {
        allpackages_observations_from_fields(vec![(
            0,
            Some("sample".into()),
            vec![
                ("Package".into(), "sample".into()),
                ("Version".into(), "1.0.0".into()),
                ("License".into(), "BSD-3-Clause".into()),
                ("Snapshot".into(), "2026-08-01".into()),
                ("DownloadURL".into(), url.into()),
            ],
        )])
        .observations
        .pop()
        .unwrap()
    }

    #[test]
    fn occurrence_binding_requires_download_url_filename() {
        let entry = ArchiveEntry::for_test("sample", "1.0.0", "sample/sample_1.0.0.tar.gz", 123);
        assert!(binds_archive_occurrence(
            &row("https://packagemanager.posit.co/cran/2026-08-01/src/contrib/sample_1.0.0.tar.gz"),
            &entry
        ));
        assert!(binds_archive_occurrence(
            &row("https://p3m.dev/cran/2026-08-01/src/contrib/sample_1.0.0.tar.gz"),
            &entry
        ));
        assert!(!binds_archive_occurrence(
            &row("https://packagemanager.posit.co/cran/2026-08-01/src/contrib/sample_1.0.1.tar.gz"),
            &entry
        ));
        assert!(!binds_archive_occurrence(
            &row("https://packagemanager.posit.co/cran/2026-08-02/src/contrib/sample_1.0.0.tar.gz"),
            &entry
        ));
    }

    #[test]
    fn feed_transport_fields_do_not_change_release_semantics() {
        let canonical = allpackages_observations_from_fields(vec![(
            0,
            Some("sample".into()),
            vec![
                ("Package".into(), "sample".into()),
                ("Version".into(), "1.0.0".into()),
                ("License".into(), "BSD-3-Clause".into()),
            ],
        )]);
        let with_evidence = allpackages_observations_from_fields(vec![(
            0,
            Some("sample".into()),
            vec![
                ("Package".into(), "sample".into()),
                ("Version".into(), "1.0.0".into()),
                ("License".into(), "BSD-3-Clause".into()),
                (
                    "DownloadURL".into(),
                    "https://p3m.dev/cran/2026-08-01/src/contrib/sample_1.0.0.tar.gz".into(),
                ),
                ("SHA256".into(), "deadbeef".into()),
                ("SHA256Original".into(), "cafebabe".into()),
                ("Repository".into(), "CRAN".into()),
                ("Snapshot".into(), "2026-08-01".into()),
            ],
        )]);
        assert_eq!(
            canonical.observations[0].release().metadata_digest(),
            with_evidence.observations[0].release().metadata_digest()
        );
        assert_eq!(
            canonical.observations[0].release().dependencies(),
            with_evidence.observations[0].release().dependencies()
        );
    }

    fn projection_with_rows(rows: Vec<IndexedRecord>) -> (tempfile::TempDir, IndexedProjection) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("projection.redb");
        let database = Database::create(&path).unwrap();
        let transaction = database.begin_write().unwrap();
        {
            let mut table = transaction.open_table(PACKAGE_OBSERVATIONS).unwrap();
            let encoded = postcard::to_stdvec(&rows).unwrap();
            table.insert("Matrix", encoded.as_slice()).unwrap();
        }
        transaction.commit().unwrap();
        drop(database);
        let database = ReadOnlyDatabase::open(path).unwrap();
        (directory, IndexedProjection { database })
    }

    fn current_catalog() -> CranCatalog {
        CranCatalog::from_packages(b"Package: Matrix\nVersion: 1.0.0\nLicense: BSD-3-Clause\n")
            .unwrap()
    }

    fn current_row(license: &str) -> IndexedRecord {
        IndexedRecord {
            package: Some("Matrix".into()),
            fields: vec![
                ("Package".into(), "Matrix".into()),
                ("Version".into(), "1.0.0".into()),
                ("License".into(), license.into()),
            ],
        }
    }

    #[test]
    fn current_coverage_distinguishes_complete_gapped_and_conflicting() {
        let current = current_catalog();
        // A transport/presentation-only metadata difference is still covered.
        let (_complete_dir, complete) = projection_with_rows(vec![current_row("GPL-3")]);
        let complete_summary = complete.classify_current(&current).unwrap();
        assert_eq!(complete_summary.status, CoverageStatus::CurrentComplete);
        assert_eq!(complete_summary.covered_count, 1);

        let dependency_current = CranCatalog::from_packages(
            b"Package: Matrix\nVersion: 1.0.0\nDepends: R (>= 4.0.0)\nLicense: BSD-3-Clause\n",
        )
        .unwrap();
        let (_dependency_dir, dependency_conflict) = projection_with_rows(vec![IndexedRecord {
            package: Some("Matrix".into()),
            fields: vec![
                ("Package".into(), "Matrix".into()),
                ("Version".into(), "1.0.0".into()),
                ("Depends".into(), "R (>= 3.0.0)".into()),
                ("License".into(), "GPL-3".into()),
            ],
        }]);
        let dependency_summary = dependency_conflict
            .classify_current(&dependency_current)
            .unwrap();
        assert_eq!(
            dependency_summary.status,
            CoverageStatus::CurrentConflicting
        );
        assert_eq!(dependency_summary.conflicting_count, 1);

        let (_gapped_dir, gapped) = projection_with_rows(vec![IndexedRecord {
            package: Some("Matrix".into()),
            fields: vec![
                ("Package".into(), "Matrix".into()),
                ("Version".into(), "0.9.0".into()),
                ("License".into(), "BSD-3-Clause".into()),
            ],
        }]);
        let gapped_summary = gapped.classify_current(&current).unwrap();
        assert_eq!(gapped_summary.status, CoverageStatus::CurrentGapped);
        assert_eq!(gapped_summary.gapped_count, 1);

        let (_conflicting_dir, conflicting) =
            projection_with_rows(vec![current_row("BSD-3-Clause"), current_row("GPL-3")]);
        let conflicting_summary = conflicting.classify_current(&current).unwrap();
        assert_eq!(
            conflicting_summary.status,
            CoverageStatus::CurrentConflicting
        );
        assert_eq!(conflicting_summary.conflicting_count, 1);
    }

    #[test]
    fn zstd_decoder_rejects_payload_at_limit_plus_one() {
        // A one-byte raw zstd frame, used to exercise the bounded reader
        // without allocating anything near the production limit.
        let frame = [0x28, 0xb5, 0x2f, 0xfd, 0x20, 0x01, 0x09, 0x00, 0x00, b'x'];
        assert_eq!(decode_zstd_with_limit(&frame, 1).unwrap(), b"x");
        let error = decode_zstd_with_limit(&frame, 0).unwrap_err();
        assert!(error.contains("exceeds 0 bytes"));
    }
}
