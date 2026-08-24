//! Snapshot evidence projection for the CRAN acquisition session.

use sha2::{Digest, Sha256};

use super::super::catalog::{
    CranArchiveReleaseRejection, CranCatalog, CranCatalogObservation, CranCatalogRecordScope,
};
use super::super::evidence::{CranEvidenceObservation, DistributionRegistryBinding};
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

pub(super) fn current_records(
    representation: CranCurrentIndexRepresentation,
    body: &[u8],
) -> Result<Vec<CranCatalogObservation>, String> {
    match representation {
        CranCurrentIndexRepresentation::Rds => {
            CranCatalog::observations_from_archive_index_rds(body)
                .map_err(|error| error.to_string())
        }
        CranCurrentIndexRepresentation::Gzip => decode_gzip(body)
            .map_err(|error| error.to_string())
            .and_then(|decoded| {
                CranCatalog::observations_from_packages(&decoded).map_err(|error| error.to_string())
            }),
        CranCurrentIndexRepresentation::PlainDcf => {
            CranCatalog::observations_from_packages(body).map_err(|error| error.to_string())
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
            checksums: Vec::new(),
            size: Some(size),
        }),
    )
}

/// Retains a release-local archive rejection as raw evidence. The provider
/// projection rejects rows without an attributable package/version/scope as
/// package-global failures before this bridge is reached.
pub(super) fn archive_rejection_to_evidence(
    rejection: &CranArchiveReleaseRejection,
    source: SourceInput,
    base_url: &str,
    freshness: FreshnessStateV1,
) -> CranEvidenceObservation {
    let package = rejection
        .package()
        .expect("release-local archive rejection must identify a package");
    let version = rejection
        .version()
        .expect("release-local archive rejection must identify a version");
    let scope = rejection
        .scope()
        .expect("release-local archive rejection must identify a scope");
    let locator = match scope {
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
        artifact: Some(OccurrenceArtifactV1 {
            locator,
            checksums: checksums_from_fields(rejection.fields()),
            size: None,
        }),
        axes: EvidenceAxesV1 {
            parse: ParseStateV1::Valid,
            namespace: NamespaceStateV1::Established,
            occurrence: OccurrenceStateV1::ArtifactBound,
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

fn checksums_from_fields(fields: &[(String, String)]) -> Vec<ChecksumV1> {
    fields
        .iter()
        .filter_map(|(name, value)| {
            let algorithm = if name.eq_ignore_ascii_case("MD5sum") {
                "md5"
            } else if name.eq_ignore_ascii_case("SHA256") {
                "sha256"
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
        &effective_endpoint,
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
