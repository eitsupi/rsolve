//! Snapshot evidence projection for the CRAN acquisition session.

use sha2::{Digest, Sha256};

use super::super::catalog::{CranCatalog, CranCatalogObservation};
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
    SourceInput {
        kind: kind.into(),
        representation: representation.into(),
        content_sha256: Sha256::digest(body).into(),
        etag: None,
        last_modified: None,
        observed_at: jiff::Timestamp::now()
            .strftime("%Y-%m-%dT%H:%M:%SZ")
            .to_string(),
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
    let locator = if current {
        format!("{base_url}/src/contrib/{package}_{version}.tar.gz")
    } else {
        format!("{base_url}/src/contrib/Archive/{package}/{package}_{version}.tar.gz")
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
    record
        .fields()
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
    let mut session = CranRefreshSession::new(std::rc::Rc::new(transport), base_url);
    let observations = session
        .refresh_snapshot_observations(roots)
        .map_err(super::super::publish::CranSnapshotPublishError::Acquisition)?;
    super::super::publish::publish_snapshot(
        store,
        super::super::publish::default_context(store.registry_id().clone()),
        observations,
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
