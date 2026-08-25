//! Snapshot evidence projection for the CRAN acquisition session.

use sha2::{Digest, Sha256};

use super::super::catalog::{
    CranArchiveReleaseRejection, CranCatalog, CranCatalogObservation, CranCatalogRecordScope,
};
use super::super::evidence::{CranEvidenceObservation, DistributionRegistryBinding};
#[cfg(test)]
use super::CranMetadataConfig;
use super::refresher::decode_gzip;
use super::{CranCurrentIndexRepresentation, CranRefreshSession, Transport};
use crate::snapshot::{
    ChecksumV1, EvidenceAxesV1, FieldV1, FreshnessStateV1, NamespaceStateV1, OccurrenceArtifactV1,
    OccurrenceStateV1, ParseStateV1, PublicationStateV1, SemanticsStateV1, SourceInput,
};
use rsolve_core::{CandidateLoadError, CandidateLoadErrorCategory, PackageName};

pub(super) fn source_input(
    kind: &str,
    representation: &str,
    endpoint: &str,
    body: &[u8],
) -> SourceInput {
    source_input_with_metadata(
        kind,
        representation,
        endpoint,
        body,
        jiff::Timestamp::now()
            .strftime("%Y-%m-%dT%H:%M:%SZ")
            .to_string(),
        None,
        None,
    )
}

pub(super) fn source_input_with_metadata(
    kind: &str,
    representation: &str,
    endpoint: &str,
    body: &[u8],
    observed_at: String,
    etag: Option<Box<str>>,
    last_modified: Option<Box<str>>,
) -> SourceInput {
    SourceInput {
        kind: kind.into(),
        representation: representation.into(),
        content_sha256: Sha256::digest(body).into(),
        etag: etag.map(|value| value.into_string()),
        last_modified: last_modified.map(|value| value.into_string()),
        observed_at,
        endpoint: endpoint.into(),
    }
}

pub(super) fn import_current_index(
    representation: CranCurrentIndexRepresentation,
    body: &[u8],
) -> Result<(CranCatalog, Vec<CranCatalogObservation>), String> {
    match representation {
        CranCurrentIndexRepresentation::Rds => {
            CranCatalog::from_archive_index_rds_with_observations(
                body,
                &super::super::archive_index::provider_rds_read_options(),
            )
            .map_err(|error| error.to_string())
        }
        CranCurrentIndexRepresentation::Gzip => decode_gzip(body)
            .map_err(|error| error.to_string())
            .and_then(|decoded| {
                CranCatalog::from_packages_with_observations(&decoded)
                    .map_err(|error| error.to_string())
            }),
        CranCurrentIndexRepresentation::PlainDcf => {
            CranCatalog::from_packages_with_observations(body).map_err(|error| error.to_string())
        }
    }
}

pub(super) fn index_record_to_evidence(
    record: &CranCatalogObservation,
    source: SourceInput,
    base_url: &str,
    current: bool,
    freshness: FreshnessStateV1,
) -> CranEvidenceObservation {
    let package = record.package().as_str();
    let version = record.release().version();
    let locator = match record.scope() {
        CranCatalogRecordScope::Root if current => {
            format!("{base_url}/src/contrib/{package}_{version}.tar.gz")
        }
        CranCatalogRecordScope::Root => {
            format!("{base_url}/src/contrib/Archive/{package}/{package}_{version}.tar.gz")
        }
        CranCatalogRecordScope::RecommendedOverlay { .. } => {
            let path = record
                .fields()
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("Path"))
                .map(|(_, value)| value.as_str())
                .expect("validated Recommended overlay must retain Path");
            format!("{base_url}/src/contrib/{path}/{package}_{version}.tar.gz")
        }
    };
    record_to_evidence(
        record,
        source,
        OccurrenceStateV1::ArtifactBound,
        freshness,
        Some(OccurrenceArtifactV1 {
            locator,
            checksums: checksums_from_index_fields(record),
            size: None,
        }),
    )
}

pub(super) fn tarball_record_to_evidence(
    record: &CranCatalogObservation,
    source: SourceInput,
    locator: String,
    size: u64,
) -> CranEvidenceObservation {
    record_to_evidence(
        record,
        source,
        OccurrenceStateV1::ArtifactBound,
        FreshnessStateV1::BulkGeneration,
        Some(OccurrenceArtifactV1 {
            locator,
            // DESCRIPTION is self-reported by the artifact and does not
            // authenticate the tarball bytes at this evidence boundary.
            checksums: Vec::new(),
            size: Some(size),
        }),
    )
}

/// Projects an ALLPACKAGES observation onto a canonical CRAN archive
/// locator. The feed's SHA256 is for the mirror artifact and MD5sum has no
/// provenance here; only a valid upstream SHA256Original may cross this
/// binding boundary.
pub(super) fn allpackages_record_to_evidence(
    record: &CranCatalogObservation,
    source: SourceInput,
    locator: String,
    size: u64,
) -> CranEvidenceObservation {
    record_to_evidence(
        record,
        source,
        OccurrenceStateV1::ArtifactBound,
        FreshnessStateV1::BulkGeneration,
        Some(OccurrenceArtifactV1 {
            locator,
            checksums: checksums_from_allpackages_fields(record),
            size: Some(size),
        }),
    )
}

/// Retains a release-local archive rejection as raw evidence. Rows with an
/// attributable version retain an archive locator; rows whose raw Version
/// field is malformed remain observation-only so no coordinate is fabricated.
pub(super) fn archive_rejection_to_evidence(
    rejection: &CranArchiveReleaseRejection,
    source: SourceInput,
    base_url: &str,
    freshness: FreshnessStateV1,
) -> CranEvidenceObservation {
    let package = rejection
        .package()
        .expect("release-local archive rejection must identify a package");
    let scope = rejection
        .scope()
        .expect("release-local archive rejection must identify a scope");
    let locator = rejection.version().map(|version| match scope {
        CranCatalogRecordScope::Root => {
            format!("{base_url}/src/contrib/Archive/{package}/{package}_{version}.tar.gz")
        }
        CranCatalogRecordScope::RecommendedOverlay { .. } => {
            let path = rejection
                .fields()
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("Path"))
                .map(|(_, value)| value.as_str())
                .expect("validated Recommended overlay must retain Path");
            format!("{base_url}/src/contrib/{path}/{package}_{version}.tar.gz")
        }
    });
    let occurrence = if locator.is_some() {
        OccurrenceStateV1::ArtifactBound
    } else {
        OccurrenceStateV1::ObservationOnly
    };
    CranEvidenceObservation {
        source,
        package: package.clone(),
        record_index: rejection.record_index() as u64,
        fields: rejection
            .fields()
            .iter()
            .map(|(name, value)| FieldV1 {
                name: name.clone(),
                value: value.clone(),
            })
            .collect(),
        artifact: locator.map(|locator| OccurrenceArtifactV1 {
            locator,
            // Archive rejections are retained even when an index field is
            // malformed. Keep those fields lossless above, but only promote
            // values that satisfy the snapshot checksum contract into the
            // typed artifact projection. Valid observations continue to use
            // the fail-closed path in `checksums_from_index_fields`.
            checksums: checksums_from_rejection_fields(rejection.fields()),
            size: None,
        }),
        axes: EvidenceAxesV1 {
            parse: ParseStateV1::Valid,
            namespace: NamespaceStateV1::Established,
            occurrence,
            semantics: SemanticsStateV1::Invalid,
            publication: PublicationStateV1::Unknown,
            freshness,
        },
        release: None,
        distribution_registry: DistributionRegistryBinding::ConfiguredContext,
        scope: scope.clone(),
    }
}

fn record_to_evidence(
    record: &CranCatalogObservation,
    source: SourceInput,
    occurrence: OccurrenceStateV1,
    freshness: FreshnessStateV1,
    artifact: Option<OccurrenceArtifactV1>,
) -> CranEvidenceObservation {
    CranEvidenceObservation {
        source,
        package: record.package().clone(),
        record_index: record.record_index() as u64,
        fields: record
            .fields()
            .iter()
            .map(|(name, value)| FieldV1 {
                name: name.clone(),
                value: value.clone(),
            })
            .collect(),
        artifact,
        axes: evidence_axes(record.release(), occurrence, freshness),
        release: Some(record.release().clone()),
        distribution_registry: DistributionRegistryBinding::ConfiguredContext,
        scope: record.scope().clone(),
    }
}

fn evidence_axes(
    release: &rsolve_core::PackageRelease,
    occurrence: OccurrenceStateV1,
    freshness: FreshnessStateV1,
) -> EvidenceAxesV1 {
    EvidenceAxesV1 {
        parse: ParseStateV1::Valid,
        namespace: NamespaceStateV1::Established,
        occurrence,
        semantics: SemanticsStateV1::Complete,
        publication: if release.publication().is_some() {
            PublicationStateV1::Dated
        } else {
            PublicationStateV1::Unknown
        },
        freshness,
    }
}

fn checksums_from_index_fields(record: &CranCatalogObservation) -> Vec<ChecksumV1> {
    checksums_from_fields(record.fields())
}

fn checksums_from_allpackages_fields(record: &CranCatalogObservation) -> Vec<ChecksumV1> {
    checksums_from_fields(record.fields())
        .into_iter()
        .filter(|checksum| {
            checksum.algorithm == "sha256-original"
                && checksum.value.len() == 64
                && checksum.value.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
        .collect()
}

fn checksums_from_rejection_fields(fields: &[(String, String)]) -> Vec<ChecksumV1> {
    checksums_from_fields(fields)
        .into_iter()
        .filter(|checksum| match checksum.algorithm.as_str() {
            // The wire validator treats MD5 as an opaque non-empty value,
            // while the original upstream SHA-256 must be exactly 32 bytes
            // of hex. P3M's SHA256 is for its rewritten tarball and is not
            // attached to the canonical CRAN archive locator.
            "md5" => true,
            "sha256-original" => {
                checksum.value.len() == 64
                    && checksum.value.bytes().all(|byte| byte.is_ascii_hexdigit())
            }
            _ => false,
        })
        .collect()
}

fn checksums_from_fields(fields: &[(String, String)]) -> Vec<ChecksumV1> {
    fields
        .iter()
        .filter_map(|(name, value)| {
            let algorithm = if name.eq_ignore_ascii_case("MD5sum") {
                "md5"
            } else if name.eq_ignore_ascii_case("SHA256Original") {
                "sha256-original"
            } else {
                return None;
            };
            let value = value.trim();
            (!value.is_empty()).then(|| ChecksumV1 {
                algorithm: algorithm.into(),
                value: value.into(),
            })
        })
        .collect()
}

#[cfg(test)]
pub(crate) fn refresh_and_publish_with_transport<T: Transport>(
    store: &crate::snapshot::SnapshotStore,
    transport: T,
    base_url: impl AsRef<str>,
    roots: &[PackageName],
) -> Result<
    crate::snapshot::ReadOnlySnapshotCandidateLoader,
    super::super::publish::CranSnapshotPublishError,
> {
    let effective_endpoint = base_url.as_ref().to_owned();
    let raw_cache = super::raw_cache::RawCache::open(store).map_err(|error| {
        super::super::publish::CranSnapshotPublishError::Acquisition(CandidateLoadError::new(
            CandidateLoadErrorCategory::SnapshotInvalid,
            format!("unable to open CRAN current raw cache: {error}"),
        ))
    })?;
    let mut session = CranRefreshSession::new_with_clock(
        std::rc::Rc::new(transport),
        CranMetadataConfig::new(effective_endpoint.as_str(), ""),
        None,
        Some(raw_cache),
    );
    let observations = session
        .refresh_snapshot_observations(roots)
        .map_err(super::super::publish::CranSnapshotPublishError::Acquisition)?;
    super::super::publish::publish_snapshot_with_endpoint(
        store,
        super::super::publish::default_context(store.registry_id().clone()),
        observations,
        effective_endpoint,
    )
}

impl<T: Transport> CranRefreshSession<T> {
    pub(super) fn refresh_snapshot_observations(
        &mut self,
        roots: &[PackageName],
    ) -> Result<Vec<CranEvidenceObservation>, CandidateLoadError> {
        self.refresh_packages(roots)?;
        let observations = self
            .evidence
            .borrow()
            .iter()
            .filter(|observation| roots.iter().any(|root| root == &observation.package))
            .cloned()
            .collect::<Vec<_>>();
        if observations.is_empty() {
            return Err(CandidateLoadError::new(
                CandidateLoadErrorCategory::MetadataInvalid,
                "CRAN refresh produced no validated snapshot observations",
            ));
        }
        Ok(observations)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cran::catalog::{CranCatalogRecordContext, provider_observations_from_fields};
    use crate::cran::evidence::compose_snapshot;
    use crate::cran::publish::default_context;
    use crate::snapshot::SnapshotGenerationBuilder;
    use rsolve_core::RegistryId;

    #[test]
    fn quarantined_checksum_fields_stay_raw_without_blocking_snapshot_publish() {
        let package = PackageName::new("Matrix").unwrap();
        let projection = provider_observations_from_fields(
            vec![(
                0,
                Some(package.to_string()),
                vec![
                    ("Package".into(), "Matrix".into()),
                    ("Version".into(), "1.7-0".into()),
                    ("License".into(), "RSOLVE Fictional Terms Matrix".into()),
                    ("Depends".into(), "libxml (>= )".into()),
                    ("MD5sum".into(), "00000000000000000000000000000021".into()),
                    ("SHA256".into(), "not-a-digest".into()),
                ],
            )],
            CranCatalogRecordContext::PackagesIndex,
            Some(&package),
        );
        let rejection = projection.rejections.first().expect("semantic rejection");
        let evidence = archive_rejection_to_evidence(
            rejection,
            source_input(
                "cran-archive-index",
                "rds",
                "https://cran.invalid/src/contrib/Archive/Matrix/PACKAGES.rds",
                b"archive",
            ),
            "https://cran.invalid",
            FreshnessStateV1::BulkGeneration,
        );

        assert!(
            evidence
                .fields
                .iter()
                .any(|field| { field.name == "SHA256" && field.value == "not-a-digest" })
        );
        assert_eq!(
            evidence.artifact.as_ref().unwrap().checksums,
            vec![ChecksumV1 {
                algorithm: "md5".into(),
                value: "00000000000000000000000000000021".into(),
            }]
        );

        let input = compose_snapshot(
            default_context(RegistryId::new("cran").unwrap()),
            vec![evidence],
        )
        .expect("quarantined invalid checksum must not block composition");
        let directory = tempfile::tempdir().unwrap();
        SnapshotGenerationBuilder::new(input, directory.path().join("generation.redb"))
            .build()
            .expect("quarantined invalid checksum must not block snapshot publish");
    }

    #[test]
    fn allpackages_binding_keeps_only_valid_upstream_sha256_original() {
        let package = PackageName::new("Matrix").unwrap();
        let projection = provider_observations_from_fields(
            vec![(
                0,
                Some(package.to_string()),
                vec![
                    ("Package".into(), "Matrix".into()),
                    ("Version".into(), "1.7-0".into()),
                    ("License".into(), "BSD-3-Clause".into()),
                    ("MD5sum".into(), "0123456789abcdef0123456789abcdef".into()),
                    ("SHA256".into(), "a".repeat(64)),
                    ("SHA256Original".into(), "b".repeat(64)),
                ],
            )],
            CranCatalogRecordContext::PackagesIndex,
            Some(&package),
        );
        let record = projection.observations.first().expect("valid observation");
        let evidence = allpackages_record_to_evidence(
            record,
            source_input(
                "cran-allpackages",
                "zstd",
                "https://ppm.r-pkg.org/ALLPACKAGES.zst",
                b"feed",
            ),
            "https://cran.invalid/src/contrib/Archive/Matrix/Matrix_1.7-0.tar.gz".into(),
            123,
        );

        assert_eq!(
            evidence.artifact.unwrap().checksums,
            vec![ChecksumV1 {
                algorithm: "sha256-original".into(),
                value: "b".repeat(64),
            }]
        );
    }

    #[test]
    fn tarball_description_checksums_are_not_artifact_evidence() {
        let package = PackageName::new("Matrix").unwrap();
        let projection = provider_observations_from_fields(
            vec![(
                0,
                Some(package.to_string()),
                vec![
                    ("Package".into(), "Matrix".into()),
                    ("Version".into(), "1.7-0".into()),
                    ("License".into(), "BSD-3-Clause".into()),
                    ("MD5sum".into(), "0123456789abcdef0123456789abcdef".into()),
                    ("SHA256Original".into(), "b".repeat(64)),
                ],
            )],
            CranCatalogRecordContext::PackagesIndex,
            Some(&package),
        );
        let evidence = tarball_record_to_evidence(
            projection.observations.first().expect("valid observation"),
            source_input(
                "cran-archive-tarball",
                "tar.gz",
                "https://cran.invalid/src/contrib/Archive/Matrix/Matrix_1.7-0.tar.gz",
                b"tarball",
            ),
            "https://cran.invalid/src/contrib/Archive/Matrix/Matrix_1.7-0.tar.gz".into(),
            7,
        );
        assert!(evidence.artifact.unwrap().checksums.is_empty());
    }

    #[test]
    fn invalid_archive_version_is_observation_only_without_fabricated_locator() {
        let package = PackageName::new("nlme").unwrap();
        let projection = provider_observations_from_fields(
            vec![(
                0,
                Some(package.to_string()),
                vec![
                    ("Package".into(), "nlme".into()),
                    ("Version".into(), "3.1-2 (1999/12/23)".into()),
                    ("License".into(), "GPL-2".into()),
                ],
            )],
            CranCatalogRecordContext::PackagesIndex,
            Some(&package),
        );
        let rejection = projection.rejections.first().expect("invalid Version");
        assert!(rejection.version().is_none());
        let evidence = archive_rejection_to_evidence(
            rejection,
            source_input(
                "cran-archive-index",
                "rds",
                "https://cran.invalid/src/contrib/Archive/nlme/PACKAGES.rds",
                b"archive",
            ),
            "https://cran.invalid",
            FreshnessStateV1::BulkGeneration,
        );
        assert!(evidence.artifact.is_none());
        assert_eq!(evidence.axes.occurrence, OccurrenceStateV1::ObservationOnly);
        assert_eq!(evidence.axes.semantics, SemanticsStateV1::Invalid);
        assert!(evidence.release.is_none());
        assert!(
            evidence
                .fields
                .iter()
                .any(|field| field.name == "Version" && field.value == "3.1-2 (1999/12/23)")
        );

        let input = compose_snapshot(
            default_context(RegistryId::new("cran").unwrap()),
            vec![evidence],
        )
        .expect("observation-only invalid Version must compose");
        let directory = tempfile::tempdir().unwrap();
        SnapshotGenerationBuilder::new(input, directory.path().join("generation.redb"))
            .build()
            .expect("observation-only invalid Version must publish");
    }
}
