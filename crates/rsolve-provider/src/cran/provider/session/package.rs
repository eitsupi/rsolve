use std::rc::Rc;

use super::super::super::archive_index::{
    CranArchiveIndexProviderError, provider_archive_index_rds,
};
use super::super::model::{
    CranFastPathStatus, CranRefreshDiagnostic, CranRefreshMetricsSource, CranRefreshSource,
};
use super::super::negative::FastPathFailure;
use super::super::raw_cache::RawCacheRepresentation;
use super::super::runtime::CandidateSource;
use super::super::runtime::CranCandidateSnapshot;
use super::super::runtime::CranProvider;
use super::super::transport::Transport;
use super::{
    AllPackagesSource, BulkCandidateResult, CranRefreshSession, HistorySource,
    MetadataAcquisitionOutcome, MetadataParseFailure, allpackages_record_to_evidence,
    archive_rejection_to_evidence, index_record_to_evidence,
};
use crate::snapshot::FreshnessStateV1;
use crate::{RawCandidateLoadResult, RawCandidateObservation, currentness_for_release};
use rsolve_core::{
    CandidateCurrentness, CandidateLoadError, CandidateLoadErrorCategory, PackageName,
    PackageRelease, ReleaseAggregation, SolverKey,
};

impl<T: Transport + 'static> CranRefreshSession<T> {
    pub(in crate::cran::provider) fn refresh_package(
        &mut self,
        package: &PackageName,
    ) -> Result<RawCandidateLoadResult, CandidateLoadError> {
        if let Some(result) = self.packages.get(package) {
            return result.clone();
        }
        let result = self.refresh_package_uncached(package);
        self.packages.insert(package.clone(), result.clone());
        result
    }

    /// Projects the complete ALLPACKAGES history for one package.
    ///
    /// The result is deliberately package-granular: a single rejected or
    /// unbound archive identity makes the whole historical source fall back to
    /// the package-local archive. This prevents two presentations of one
    /// release from entering the same aggregation while retaining the current
    /// catalog as the sole authority for current identities.
    pub(super) fn bulk_candidates_for_package(
        &mut self,
        package: &PackageName,
        current: &[PackageRelease],
        bulk: &AllPackagesSource,
    ) -> Result<Option<BulkCandidateResult>, CandidateLoadError> {
        let history = match self.ensure_history()? {
            HistorySource::Available { source } => {
                let payload = source.package(package)?;
                if !payload.rejections.is_empty() {
                    return Ok(None);
                }
                payload.entries
            }
            HistorySource::Absent => return Ok(None),
        };
        let package_projection = bulk.observations(package.as_str())?;
        let package_rows = package_projection
            .observations
            .iter()
            .filter(|row| row.package() == package)
            .collect::<Vec<_>>();
        let package_rejections = package_projection
            .rejections
            .iter()
            .filter(|rejection| rejection.package() == Some(package))
            .collect::<Vec<_>>();
        let package_entries = history
            .iter()
            .filter(|entry| entry.package() == package)
            .collect::<Vec<_>>();
        let current_versions = current
            .iter()
            .map(|release| release.version())
            .collect::<std::collections::BTreeSet<_>>();

        // A rejection belongs to the package even when its version could not
        // be recovered. Treating it as a version-local hole would mix source
        // presentations and make the resulting history non-deterministic.
        if !package_rejections.is_empty() {
            self.metrics.borrow_mut().quarantined_releases += package_rejections.len() as u64;
            return Ok(None);
        }

        let historical_entries = package_entries
            .iter()
            .copied()
            .filter(|entry| !current_versions.contains(entry.version()))
            .collect::<Vec<_>>();
        let historical_versions = historical_entries
            .iter()
            .map(|entry| entry.version())
            .collect::<std::collections::BTreeSet<_>>();

        // Rows for current identities are observations only; current metadata
        // always comes from the target current index. Any other feed identity
        // must have a corresponding archive occurrence, otherwise the feed is
        // incomplete for this package and the local history is authoritative.
        let historical_rows = package_rows
            .iter()
            .copied()
            .filter(|row| !current_versions.contains(row.release().version()))
            .collect::<Vec<_>>();
        let feed_versions = historical_rows
            .iter()
            .map(|row| row.release().version())
            .collect::<std::collections::BTreeSet<_>>();
        if feed_versions != historical_versions {
            return Ok(None);
        }

        let mut staged_releases = current.to_vec();
        let mut staged_evidence = Vec::new();
        for entry in &historical_entries {
            let rows = historical_rows
                .iter()
                .filter(|row| row.release().version() == entry.version())
                .copied()
                .collect::<Vec<_>>();
            let entry_count = historical_entries
                .iter()
                .filter(|other| other.version() == entry.version())
                .count();
            if entry_count != 1
                || rows.len() != 1
                || !super::super::allpackages::binds_archive_occurrence(rows[0], entry)
            {
                return Ok(None);
            }
            let row = rows[0];
            staged_releases.push(row.release().clone());
            let locator = super::super::join_endpoint_path(
                &self.base_url,
                &format!(
                    "src/contrib/Archive/{}",
                    entry.source_archive_relative_path()
                ),
            );
            staged_evidence.push(allpackages_record_to_evidence(
                row,
                bulk.source.clone(),
                locator,
                entry.size(),
            ));
        }

        let mut aggregation = ReleaseAggregation::new();
        for release in staged_releases {
            if aggregation.observe_release(release).is_err() {
                return Ok(None);
            }
        }
        let mut candidates = aggregation.releases().cloned().collect::<Vec<_>>();
        candidates.sort_by(|left, right| left.version().cmp(right.version()));
        Ok(Some(BulkCandidateResult {
            candidates: RawCandidateLoadResult::new(
                candidates
                    .into_iter()
                    .map(|release| RawCandidateObservation {
                        currentness: if current_versions.contains(release.version()) {
                            CandidateCurrentness::Current
                        } else {
                            CandidateCurrentness::Historical
                        },
                        release,
                    })
                    .collect(),
                Vec::new(),
            ),
            evidence: staged_evidence,
        }))
    }

    fn refresh_package_uncached(
        &mut self,
        package: &PackageName,
    ) -> Result<RawCandidateLoadResult, CandidateLoadError> {
        self.metrics.borrow_mut().package_history_lookups += 1;
        let current_projection = self.ensure_current()?;
        let current = current_projection.candidates(package)?;
        if let Some(source) = self.current_source.clone() {
            let observations = current_projection.observations(package)?;
            self.evidence
                .borrow_mut()
                .extend(observations.observations.iter().map(|record| {
                    index_record_to_evidence(
                        record,
                        source.clone(),
                        &self.base_url,
                        true,
                        FreshnessStateV1::CurrentGeneration,
                    )
                }));
        }
        let bulk_candidates = if self.allow_allpackages_history {
            match self.ensure_allpackages() {
                Ok(bulk) => self.bulk_candidates_for_package(package, &current, &bulk)?,
                Err(_) => None,
            }
        } else {
            None
        };
        if let Some(result) = bulk_candidates {
            self.metrics.borrow_mut().allpackages_adoptions += 1;
            self.evidence.borrow_mut().extend(result.evidence);
            return Ok(result.candidates);
        }
        self.emit_package_local_fallback();
        let endpoint = super::super::join_endpoint_path(
            &self.base_url,
            &format!("src/contrib/Archive/{}/PACKAGES.rds", package.as_str()),
        );
        let mut package_diagnostics = Vec::new();
        let fast_result = match self.acquire_metadata(
            &endpoint,
            RawCacheRepresentation::PackageArchiveIndexRds,
            "cran-archive-index",
            "rds",
            CranRefreshMetricsSource::PackageLocalIndex,
            |body| {
                let projection = provider_archive_index_rds(body, package).map_err(|error| {
                    let diagnostic = error.to_string().into_boxed_str();
                    match error {
                        CranArchiveIndexProviderError::AllSemantic(_)
                        | CranArchiveIndexProviderError::Identity(_) => {
                            MetadataParseFailure::NoFallback(diagnostic)
                        }
                        _ => MetadataParseFailure::Invalid(diagnostic),
                    }
                })?;
                Ok((
                    projection.catalog,
                    projection.observations,
                    projection.rejections,
                ))
            },
        ) {
            Ok(((catalog, records, rejections), source, outcome)) => {
                self.evidence
                    .borrow_mut()
                    .extend(records.iter().map(|record| {
                        index_record_to_evidence(
                            record,
                            source.clone(),
                            &self.base_url,
                            false,
                            FreshnessStateV1::BulkGeneration,
                        )
                    }));
                self.evidence
                    .borrow_mut()
                    .extend(rejections.iter().map(|rejection| {
                        archive_rejection_to_evidence(
                            rejection,
                            source.clone(),
                            &self.base_url,
                            FreshnessStateV1::BulkGeneration,
                        )
                    }));
                self.metrics.borrow_mut().quarantined_releases += rejections.len() as u64;
                package_diagnostics.push(CranRefreshDiagnostic {
                    endpoint: endpoint.clone().into_boxed_str(),
                    status: Some(match outcome {
                        MetadataAcquisitionOutcome::Revalidated304 => 304,
                        MetadataAcquisitionOutcome::Cached
                        | MetadataAcquisitionOutcome::Network200 => 200,
                    }),
                    status_detail: if rejections.is_empty() {
                        CranFastPathStatus::Available
                    } else {
                        CranFastPathStatus::AvailableWithRejections {
                            count: rejections.len(),
                            diagnostic: {
                                let first = rejections
                                    .first()
                                    .map(|rejection| rejection.diagnostic().to_string())
                                    .unwrap_or_else(|| "no rejection detail".to_owned());
                                let additional = rejections.len().saturating_sub(1);
                                format!(
                                    "{} archive release(s) quarantined after semantic validation; first: {first}; {additional} additional rejection(s)",
                                    rejections.len()
                                )
                                .into()
                            },
                        }
                    },
                    source: CranRefreshSource::ArchiveFastPath,
                });
                Ok(CandidateSource::Fast {
                    catalog,
                    rejections: Rc::from(rejections.into_boxed_slice()),
                })
            }
            Err(error) if matches!(error.status, Some(404 | 410)) => {
                let status = error.status.expect("matched status");
                package_diagnostics.push(CranRefreshDiagnostic {
                    endpoint: endpoint.clone().into_boxed_str(),
                    status: Some(status),
                    status_detail: CranFastPathStatus::Unsupported { status },
                    source: CranRefreshSource::ArchiveFastPath,
                });
                Err(FastPathFailure::Unsupported)
            }
            Err(error) => {
                let diagnostic = match (error.category, error.status) {
                    (CandidateLoadErrorCategory::MetadataInvalid, _) => format!(
                        "archive fast path for {package} has invalid metadata: {}",
                        error.diagnostic
                    ),
                    (CandidateLoadErrorCategory::TransportFailure, Some(status)) => {
                        format!("archive fast path for {package} returned unexpected HTTP {status}")
                    }
                    _ => format!(
                        "archive fast path for {package} failed: {}",
                        error.diagnostic
                    ),
                };
                package_diagnostics.push(CranRefreshDiagnostic {
                    endpoint: endpoint.clone().into_boxed_str(),
                    status: error.status,
                    status_detail: CranFastPathStatus::Invalid {
                        status: error.status.unwrap_or_default(),
                        diagnostic: diagnostic.clone().into_boxed_str(),
                    },
                    source: CranRefreshSource::ArchiveFastPath,
                });
                if !error.fallback_allowed
                    || error.category == CandidateLoadErrorCategory::SnapshotInvalid
                {
                    self.diagnostics.extend(package_diagnostics);
                    return Err(error.into_candidate());
                }
                Err(FastPathFailure::Invalid {
                    category: error.category,
                    diagnostic: diagnostic.into_boxed_str(),
                })
            }
        };
        let mut provider_diagnostics = Vec::new();
        let source = match fast_result {
            Ok(source) => {
                provider_diagnostics = package_diagnostics;
                source
            }
            Err(failure) => {
                match self.resolve_fast_path_failure(package, package_diagnostics, failure)? {
                    Some(source) => source,
                    None => {
                        return Ok(RawCandidateLoadResult::new(
                            current
                                .into_iter()
                                .map(|release| RawCandidateObservation {
                                    currentness: currentness_for_release(&release),
                                    release,
                                })
                                .collect(),
                            Vec::new(),
                        ));
                    }
                }
            }
        };
        let provider = CranProvider::from_source(
            Rc::clone(&self.transport),
            &self.base_url,
            package.clone(),
            source,
            provider_diagnostics,
            Some(Rc::clone(&self.evidence)),
            Some(Rc::new({
                let transport = Rc::clone(&self.transport);
                move |url| {
                    transport.get_with_source(url, CranRefreshMetricsSource::TarballDescription)
                }
            })),
        );
        self.diagnostics
            .extend(provider.diagnostics().iter().cloned());
        let archived = provider.load(&SolverKey::InstalledName(package.clone()))?;
        let current_versions = current
            .iter()
            .map(|release| release.version())
            .collect::<std::collections::BTreeSet<_>>();
        let mut aggregation = ReleaseAggregation::new();
        for release in &current {
            aggregation
                .observe_release(release.clone())
                .map_err(|error| {
                    CandidateLoadError::new(
                        CandidateLoadErrorCategory::MetadataInvalid,
                        format!("conflicting CRAN release metadata for {package}: {error}"),
                    )
                })?;
        }
        for release in archived
            .observations()
            .iter()
            .map(RawCandidateObservation::release)
            .filter(|release| !current_versions.contains(release.version()))
        {
            aggregation
                .observe_release(release.clone())
                .map_err(|error| {
                    CandidateLoadError::new(
                        CandidateLoadErrorCategory::MetadataInvalid,
                        format!("conflicting CRAN release metadata for {package}: {error}"),
                    )
                })?;
        }
        let mut candidates = aggregation.releases().cloned().collect::<Vec<_>>();
        candidates.sort_by(|left, right| left.version().cmp(right.version()));
        Ok(RawCandidateLoadResult::new(
            candidates
                .into_iter()
                .map(|release| RawCandidateObservation {
                    currentness: if current_versions.contains(release.version()) {
                        CandidateCurrentness::Current
                    } else {
                        CandidateCurrentness::Historical
                    },
                    release,
                })
                .collect(),
            archived.quarantined().to_vec(),
        ))
    }

    pub(in crate::cran::provider) fn refresh_packages(
        &mut self,
        roots: &[PackageName],
    ) -> Result<CranCandidateSnapshot, CandidateLoadError> {
        for package in roots {
            self.refresh_package(package)?;
        }
        Ok(CranCandidateSnapshot {
            candidates: self
                .packages
                .iter()
                .filter_map(|(package, result)| {
                    result
                        .as_ref()
                        .ok()
                        .map(|result| (package.clone(), result.observations().to_vec()))
                })
                .collect(),
            quarantined: self
                .packages
                .iter()
                .filter_map(|(package, result)| {
                    result
                        .as_ref()
                        .ok()
                        .map(|result| (package.clone(), result.quarantined().to_vec()))
                })
                .collect(),
        })
    }
}
