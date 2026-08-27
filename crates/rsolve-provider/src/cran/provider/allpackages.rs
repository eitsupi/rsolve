//! Provider-private ALLPACKAGES bulk observation helpers.

#[cfg(test)]
use std::cell::Cell;
use std::collections::BTreeMap;
use std::io::{Cursor, Read};
use std::path::Path;

use super::super::catalog::{CranCatalog, CranCatalogObservation};
use crate::cran::history::ArchiveEntry;
use rsolve_core::PackageRelease;
use serde::Deserialize;
use sha2::Digest;

use super::super::catalog::{
    CranProviderObservationProjection, allpackages_observations_from_fields,
};
use super::super::dcf::DcfDocument;
use super::model::{CRAN_COMPATIBILITY_PROFILE, CRAN_NORMALIZATION_POLICY, CRAN_PARSER_SCHEMA};
use super::qualification::CoverageStatus;
use super::raw_cache::projection::ProjectionSourceKind;
use super::raw_cache::projection::{
    PackageProjection, ProjectionBuild, ProjectionContract, ProjectionError, ProjectionLookupError,
    ProjectionPackage, ProjectionPayload, ProjectionVisitError,
};

// The current CRAN feed is roughly 100 MiB decompressed. Keep substantial
// headroom while retaining a hard limit against compressed zip-bomb input.
const MAX_ALLPACKAGES_DECOMPRESSED_BYTES: usize = 512 * 1024 * 1024;
#[cfg(test)]
thread_local! {
    static PROJECTION_BUILD_COUNT: Cell<usize> = const { Cell::new(0) };
    static PROJECTION_DECODE_COUNT: Cell<usize> = const { Cell::new(0) };
    static CLASSIFY_CURRENT_COUNT: Cell<usize> = const { Cell::new(0) };
}

#[cfg(test)]
pub(super) fn reset_test_counters() {
    PROJECTION_BUILD_COUNT.with(|counter| counter.set(0));
    PROJECTION_DECODE_COUNT.with(|counter| counter.set(0));
    CLASSIFY_CURRENT_COUNT.with(|counter| counter.set(0));
}

#[cfg(test)]
pub(super) fn test_counters() -> (usize, usize) {
    (
        PROJECTION_BUILD_COUNT.with(Cell::get),
        PROJECTION_DECODE_COUNT.with(Cell::get),
    )
}

#[cfg(test)]
pub(super) fn classify_current_count() -> usize {
    CLASSIFY_CURRENT_COUNT.with(Cell::get)
}

#[derive(Clone, Debug, Deserialize, serde::Serialize)]
struct IndexedRecord {
    package: Option<String>,
    fields: Vec<(String, String)>,
}

pub(super) struct CoverageSummary {
    pub(super) status: CoverageStatus,
    pub(super) covered_count: usize,
    pub(super) gapped_count: usize,
    pub(super) conflicting_count: usize,
    pub(super) digest: String,
}

#[derive(Debug)]
pub(super) enum AllPackagesProjectionError {
    Storage(String),
    Semantic(String),
}

impl std::fmt::Display for AllPackagesProjectionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Storage(error) | Self::Semantic(error) => formatter.write_str(error),
        }
    }
}

pub(super) fn observations(
    projection: &PackageProjection,
    package: &str,
) -> Result<CranProviderObservationProjection, AllPackagesProjectionError> {
    let records = decode_records(
        projection
            .lookup_package(package)
            .map_err(|error| match error {
                ProjectionLookupError::Storage(error) => AllPackagesProjectionError::Storage(error),
                ProjectionLookupError::Invalid(error) => {
                    AllPackagesProjectionError::Semantic(error)
                }
            })?,
        package,
    )
    .map_err(AllPackagesProjectionError::Semantic)?;
    Ok(allpackages_observations_from_fields(
        records
            .into_iter()
            .enumerate()
            .map(|(index, record)| (index, record.package, record.fields))
            .collect(),
    ))
}

pub(super) fn classify_current(
    projection: &PackageProjection,
    current: &CranCatalog,
) -> Result<CoverageSummary, AllPackagesProjectionError> {
    #[cfg(test)]
    CLASSIFY_CURRENT_COUNT.with(|counter| counter.set(counter.get() + 1));
    let package_index = current
        .packages()
        .map(|(package, releases)| (package.as_str(), releases))
        .collect::<BTreeMap<_, _>>();
    let packages = package_index.keys().copied().collect::<Vec<_>>();
    let mut covered_count = 0;
    let mut gapped_count = 0;
    let mut conflicting_count = 0;
    let mut digest = sha2::Sha256::new();
    projection
        .visit_selected_packages(&packages, |package, payload| {
            let records = decode_records(payload, package)?;
            let observation_projection = allpackages_observations_from_fields(
                records
                    .into_iter()
                    .enumerate()
                    .map(|(index, record)| (index, record.package, record.fields))
                    .collect(),
            );
            let releases = package_index.get(package).copied().unwrap_or(&[]);
            for release in releases {
                let matching = observation_projection
                    .observations
                    .iter()
                    .filter(|row| row.release().version() == release.version())
                    .collect::<Vec<_>>();
                let rejected = observation_projection.rejections.iter().any(|row| {
                    row.version() == Some(release.version())
                        && row.package().is_some_and(|name| name.as_str() == package)
                });
                let classification = if rejected || matching.len() > 1 {
                    conflicting_count += 1;
                    "conflicting"
                } else if let Some(row) = matching.first() {
                    if current_semantics_match(row.release(), release) {
                        covered_count += 1;
                        "covered"
                    } else {
                        conflicting_count += 1;
                        "conflicting"
                    }
                } else {
                    gapped_count += 1;
                    "gapped"
                };
                digest.update(package.as_bytes());
                digest.update([0]);
                digest.update(release.version().to_string().as_bytes());
                digest.update([0]);
                digest.update(classification.as_bytes());
                digest.update([0]);
            }
            Ok(())
        })
        .map_err(|error| match error {
            ProjectionVisitError::Storage(error) => AllPackagesProjectionError::Storage(error),
            ProjectionVisitError::Invalid(error) => AllPackagesProjectionError::Semantic(error),
            ProjectionVisitError::Visitor(error) => AllPackagesProjectionError::Semantic(error),
        })?;
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

fn decode_records(
    payload: Option<ProjectionPayload>,
    expected_package: &str,
) -> Result<Vec<IndexedRecord>, String> {
    let Some(payload) = payload else {
        return Ok(Vec::new());
    };
    let records = postcard::from_bytes::<Vec<IndexedRecord>>(&payload.bytes)
        .map_err(|error| error.to_string())?;
    if records.len() != payload.record_count {
        return Err(format!(
            "ALLPACKAGES package projection record count mismatch: expected {}, stored {}",
            payload.record_count,
            records.len()
        ));
    }
    if records
        .iter()
        .any(|record| record.package.as_deref() != Some(expected_package))
    {
        return Err(format!(
            "ALLPACKAGES package projection record is not bound to package {expected_package}"
        ));
    }
    Ok(records)
}

pub(super) fn load_or_build_projection(
    body: &[u8],
    path: &Path,
) -> Result<PackageProjection, String> {
    PackageProjection::open_or_build(
        path,
        body,
        ProjectionSourceKind::Auxiliary,
        ProjectionContract {
            parser_schema: CRAN_PARSER_SCHEMA,
            compatibility_profile: CRAN_COMPATIBILITY_PROFILE,
            normalization_policy: CRAN_NORMALIZATION_POLICY,
        },
        || build_projection(body),
    )
    .map_err(|error| match error {
        ProjectionError::Build(error) | ProjectionError::Storage(error) => error,
    })
}

pub(super) fn rebuild_projection(body: &[u8], path: &Path) -> Result<PackageProjection, String> {
    PackageProjection::rebuild_validated(
        path,
        body,
        ProjectionSourceKind::Auxiliary,
        ProjectionContract {
            parser_schema: CRAN_PARSER_SCHEMA,
            compatibility_profile: CRAN_COMPATIBILITY_PROFILE,
            normalization_policy: CRAN_NORMALIZATION_POLICY,
        },
        || build_projection(body),
        |_| Ok(()),
    )
    .map_err(|error| match error {
        ProjectionError::Build(error) | ProjectionError::Storage(error) => error,
    })
}

fn build_projection(body: &[u8]) -> Result<ProjectionBuild, String> {
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
    let packages = records
        .into_iter()
        .map(|(package, records)| {
            let record_count = records.len();
            Ok(ProjectionPackage {
                package,
                record_count,
                payload: postcard::to_stdvec(&records).map_err(|error| error.to_string())?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(ProjectionBuild {
        packages,
        summary: Vec::new(),
        surface_digest: String::new(),
    })
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

    fn projection_with_rows(rows: Vec<IndexedRecord>) -> (tempfile::TempDir, PackageProjection) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("projection.redb");
        let record_count = rows.len();
        let projection = PackageProjection::open_or_build(
            &path,
            b"raw",
            ProjectionSourceKind::Auxiliary,
            ProjectionContract {
                parser_schema: CRAN_PARSER_SCHEMA,
                compatibility_profile: CRAN_COMPATIBILITY_PROFILE,
                normalization_policy: CRAN_NORMALIZATION_POLICY,
            },
            || {
                Ok(ProjectionBuild {
                    packages: vec![ProjectionPackage {
                        package: "Matrix".into(),
                        record_count,
                        payload: postcard::to_stdvec(&rows).unwrap(),
                    }],
                    summary: Vec::new(),
                    surface_digest: String::new(),
                })
            },
        )
        .unwrap();
        (directory, projection)
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
    fn projection_records_must_match_the_lookup_package() {
        let payload = ProjectionPayload {
            bytes: postcard::to_stdvec(&vec![IndexedRecord {
                package: Some("other".into()),
                fields: Vec::new(),
            }])
            .unwrap(),
            record_count: 1,
        };
        let error = decode_records(Some(payload), "Matrix").unwrap_err();
        assert!(error.contains("not bound to package Matrix"));
    }

    #[test]
    fn current_coverage_distinguishes_complete_gapped_and_conflicting() {
        let current = current_catalog();
        // A transport/presentation-only metadata difference is still covered.
        let (_complete_dir, complete) = projection_with_rows(vec![current_row("GPL-3")]);
        let complete_summary = classify_current(&complete, &current).unwrap();
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
        let dependency_summary =
            classify_current(&dependency_conflict, &dependency_current).unwrap();
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
        let gapped_summary = classify_current(&gapped, &current).unwrap();
        assert_eq!(gapped_summary.status, CoverageStatus::CurrentGapped);
        assert_eq!(gapped_summary.gapped_count, 1);

        let (_conflicting_dir, conflicting) =
            projection_with_rows(vec![current_row("BSD-3-Clause"), current_row("GPL-3")]);
        let conflicting_summary = classify_current(&conflicting, &current).unwrap();
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
