use rsolve_provider::cran::{CranArchiveIndexError, CranCatalog, CranRecordError};

const ARCHIVE: &[u8] = include_bytes!("fixtures/cran-2026-08-08/synthetic-archive-PACKAGES.rds");
const VALID_ARCHIVE: &[u8] =
    include_bytes!("fixtures/cran-2026-08-08/synthetic-valid-archive-PACKAGES.rds");

// R 4.6.1, format 3, uncompressed RDS containing a character vector rather
// than a matrix. It is deliberately small so this structural test has no
// generated upstream data dependency.
const NON_MATRIX_RDS: &[u8] = &[
    88, 10, 0, 0, 0, 3, 0, 4, 6, 1, 0, 3, 5, 0, 0, 0, 0, 5, 85, 84, 70, 45, 56, 0, 0, 0, 16, 0, 0,
    0, 1, 0, 4, 0, 9, 0, 0, 0, 9, 102, 105, 99, 116, 105, 111, 110, 97, 108,
];

#[test]
fn archive_rows_are_not_assumed_to_be_version_ordered() {
    let object = rd_rds::file::from_bytes(VALID_ARCHIVE).expect("archive RDS");
    let matrix = rd_rds::package::PackagesMatrix::from_object(&object).expect("archive matrix");
    assert_eq!(matrix.row(0).unwrap().get("Version"), Some(Some("1.10.0")));
    assert_eq!(matrix.row(1).unwrap().get("Version"), Some(Some("0.3.0")));

    let catalog = CranCatalog::from_archive_index_rds(VALID_ARCHIVE).expect("archive fixture");

    assert_eq!(catalog.package_count(), 2);
    assert_eq!(catalog.candidate_count(), 3);

    let history = catalog.candidates_named("rsolvefixture.history").unwrap();
    assert_eq!(
        history
            .iter()
            .map(|release| release.version().as_str())
            .collect::<Vec<_>>(),
        vec!["0.3.0", "1.10.0"]
    );
    assert_eq!(
        history[0].metadata().fields().get("License"),
        Some(&"RSOLVE Fictional Terms Older".to_owned())
    );
    assert_eq!(
        history[1].metadata().fields().get("License"),
        Some(&"RSOLVE Fictional Terms – Archive".to_owned())
    );
}

#[test]
fn archive_reader_looks_up_columns_and_preserves_dependencies_and_utf8() {
    let object = rd_rds::file::from_bytes(VALID_ARCHIVE).expect("archive RDS");
    let matrix = rd_rds::package::PackagesMatrix::from_object(&object).expect("archive matrix");
    assert_eq!(matrix.row(1).unwrap().get("Depends"), Some(None));
    assert_eq!(
        matrix.row(0).unwrap().get("Package"),
        Some(Some("rsolvefixture.history"))
    );

    let catalog = CranCatalog::from_archive_index_rds(VALID_ARCHIVE).expect("archive fixture");
    let release = &catalog.candidates_named("rsolvefixture.history").unwrap()[1];
    for (kind, name) in [
        (rsolve_core::DependencyKind::Depends, "R"),
        (
            rsolve_core::DependencyKind::Imports,
            "rsolvefixture.import.extra",
        ),
        (rsolve_core::DependencyKind::LinkingTo, "rsolvefixture.link"),
        (
            rsolve_core::DependencyKind::Suggests,
            "rsolvefixture.suggest",
        ),
        (
            rsolve_core::DependencyKind::Enhances,
            "rsolvefixture.enhance",
        ),
    ] {
        assert!(
            release
                .dependencies()
                .iter()
                .any(|dependency| dependency.kind == kind && dependency.name.as_str() == name),
            "missing {kind:?} dependency {name}"
        );
    }
    assert!(
        release
            .dependencies()
            .iter()
            .any(|dependency| dependency.name.as_str() == "rsolvefixture.import.helper")
    );
    assert_eq!(
        catalog.candidates_named("rsolvefixture.utf8").unwrap()[0]
            .metadata()
            .fields()
            .get("License"),
        Some(&"RSOLVE Fictional Terms 日本語".to_owned())
    );
}

#[test]
fn archive_semantic_invalid_rows_fail_without_partial_catalog() {
    let error = CranCatalog::from_archive_index_rds(ARCHIVE).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("record 3 (rsolvefixture.broken)")
    );
    assert!(
        error
            .to_string()
            .contains("1 semantic archive index record(s)")
    );
    assert_eq!(error.diagnostics().len(), 1);
    let diagnostic = &error.diagnostics()[0];

    assert_eq!(diagnostic.record_index(), 3);
    assert_eq!(diagnostic.package(), Some("rsolvefixture.broken"));
    assert!(matches!(
        diagnostic.error(),
        CranRecordError::InvalidVersion(_)
    ));
}

#[test]
fn structural_archive_failures_fail_the_whole_operation() {
    assert!(matches!(
        CranCatalog::from_archive_index_rds(b"not an RDS"),
        Err(CranArchiveIndexError::Decode(_))
    ));
    assert!(matches!(
        CranCatalog::from_archive_index_rds(NON_MATRIX_RDS),
        Err(CranArchiveIndexError::Matrix(_))
    ));
}

/// An envelope this build cannot decompress must stay distinguishable from a
/// corrupt or unrecognised stream, because the two demand different responses:
/// an unsupported envelope is a capability limit of this build that a caller
/// can answer by falling back to another index representation, while an
/// unknown envelope means the bytes are not an RDS file at all.
///
/// The envelope is chosen by whoever writes the file, not by the directory it
/// sits in.  CRAN's current `src/contrib` index is xz today while the
/// per-package archive index is gzip, and R itself already accepts
/// `saveRDS(compress = "zstd")` when built with libzstd.  This build enables
/// gzip and zstd only, so xz and bzip2 must report a capability limit rather
/// than masquerading as corruption.
#[test]
fn an_envelope_this_build_cannot_decompress_is_reported_as_a_capability_limit() {
    // Envelope detection is by magic bytes and happens before decompression,
    // so these need no valid compressed payload.
    const XZ_MAGIC: &[u8] = &[0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 0x00, 0x00];
    const BZIP2_MAGIC: &[u8] = b"BZh9padding";

    for (bytes, expected) in [
        (XZ_MAGIC, rd_rds::file::Compression::Xz),
        (BZIP2_MAGIC, rd_rds::file::Compression::Bzip2),
    ] {
        match CranCatalog::from_archive_index_rds(bytes) {
            Err(CranArchiveIndexError::Decode(rd_rds::file::ReadError::CompressionDisabled {
                format,
            })) => assert_eq!(format, expected),
            other => panic!("expected a disabled-compression report for {expected}, got {other:?}"),
        }
    }

    // The enabled envelopes must not report a capability limit.  Truncated
    // payloads fail later, in decompression or decoding.
    for bytes in [
        &[0x1fu8, 0x8b, 0x08, 0x00][..],
        &[0x28, 0xb5, 0x2f, 0xfd][..],
    ] {
        assert!(
            !matches!(
                CranCatalog::from_archive_index_rds(bytes),
                Err(CranArchiveIndexError::Decode(
                    rd_rds::file::ReadError::CompressionDisabled { .. }
                ))
            ),
            "gzip and zstd must be enabled in this build"
        );
    }

    // Bytes that are neither an XDR stream nor a recognised envelope are a
    // different failure again.
    assert!(matches!(
        CranCatalog::from_archive_index_rds(b"not an RDS"),
        Err(CranArchiveIndexError::Decode(
            rd_rds::file::ReadError::UnknownEnvelope { .. }
        ))
    ));
}
