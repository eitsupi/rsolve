use std::collections::BTreeMap;
use std::rc::Rc;

use super::super::super::history::{
    ArchiveHistoryRejection, ArchivePackagePayload, enumerate_archive_rds_for_provider,
};
use super::super::model::CranRefreshProgress;
use super::super::model::{
    CranFastPathStatus, CranRefreshDiagnostic, CranRefreshMetricsSource, CranRefreshSource,
};
use super::super::raw_cache::ProjectionNamespace;
use super::super::raw_cache::RawCacheRepresentation;
use super::super::raw_cache::projection::{
    PackageProjection, ProjectionBuild, ProjectionContract, ProjectionError, ProjectionOpenOutcome,
    ProjectionPackage, ProjectionSourceKind,
};
use super::super::transport::Transport;
use super::{
    ArchiveHistorySource, CranRefreshSession, HistorySource, MetadataParseFailure,
    history_surface_digest,
};
use rsolve_core::{CandidateLoadError, CandidateLoadErrorCategory};
use sha2::{Digest, Sha256};

impl<T: Transport + 'static> CranRefreshSession<T> {
    pub(in crate::cran::provider) fn ensure_history(
        &mut self,
    ) -> Result<HistorySource, CandidateLoadError> {
        if let Some(result) = &self.history {
            return result.clone();
        }
        self.emit_progress(CranRefreshProgress::ArchiveHistoryStarted);
        let endpoint = format!("{}/src/contrib/Meta/archive.rds", self.base_url);
        let result = match self.acquire_metadata(
            &endpoint,
            RawCacheRepresentation::ArchiveHistoryRds,
            "cran-archive-history",
            "rds",
            CranRefreshMetricsSource::ArchiveHistory,
            |body| self.parse_archive_history_projection(&endpoint, body),
        ) {
            Ok((source, _source_input, _outcome)) => {
                self.metrics.borrow_mut().quarantined_releases += source.rejections() as u64;
                if source.rejections() != 0 {
                    let first = source.first_rejection().unwrap_or("no rejection detail");
                    let additional = source.rejections().saturating_sub(1);
                    self.push_history_diagnostic(
                        endpoint.clone(),
                        Some(200),
                        format!(
                            "archive history quarantined {} package-local release(s); first: {first}; {additional} additional rejection(s)",
                            source.rejections()
                        ),
                    );
                }
                self.emit_progress(CranRefreshProgress::ArchiveHistoryCompleted {
                    entries: source.entry_count(),
                });
                self.history_surface_digest = Some(source.surface_digest().into());
                Ok(HistorySource::Available { source })
            }
            Err(error) if matches!(error.status, Some(404 | 410)) => {
                let status = error.status.expect("matched status");
                self.diagnostics.push(CranRefreshDiagnostic {
                    endpoint: endpoint.clone().into_boxed_str(),
                    status: Some(status),
                    status_detail: CranFastPathStatus::Absent { status },
                    source: CranRefreshSource::ArchiveHistory,
                });
                self.emit_progress(CranRefreshProgress::ArchiveHistoryCompleted { entries: 0 });
                Ok(HistorySource::Absent)
            }
            Err(error) => {
                let diagnostic = if error.category == CandidateLoadErrorCategory::MetadataInvalid {
                    format!("invalid CRAN archive history: {}", error.diagnostic)
                } else {
                    error.diagnostic.into_string()
                };
                self.push_history_diagnostic(endpoint.clone(), error.status, diagnostic.clone());
                let message = match error.category {
                    CandidateLoadErrorCategory::MetadataInvalid
                    | CandidateLoadErrorCategory::SnapshotInvalid => {
                        format!("failed to refresh {endpoint}: {diagnostic}")
                    }
                    _ => match error.status {
                        Some(status) => format!("failed to refresh {endpoint}: HTTP {status}"),
                        None => format!("failed to refresh {endpoint}: {diagnostic}"),
                    },
                };
                Err(CandidateLoadError::new(error.category, message))
            }
        };
        self.history = Some(result.clone());
        result
    }

    fn parse_archive_history_projection(
        &self,
        endpoint: &str,
        body: &[u8],
    ) -> Result<Rc<ArchiveHistorySource>, MetadataParseFailure> {
        let Some(cache) = &self.raw_cache else {
            let projection = enumerate_archive_rds_for_provider(body)
                .map_err(|error| MetadataParseFailure::Invalid(error.to_string().into()))?;
            return Ok(Rc::new(eager_archive_source(projection)));
        };
        let key = cache
            .key(endpoint, RawCacheRepresentation::ArchiveHistoryRds)
            .map_err(|error| MetadataParseFailure::SnapshotInvalid(error.to_string().into()))?;
        cache
            .prepare_projection_path(ProjectionNamespace::ArchiveHistory, &key)
            .map_err(|error| MetadataParseFailure::SnapshotInvalid(error.to_string().into()))?;
        let path = cache.projection_path_in_namespace(
            ProjectionNamespace::ArchiveHistory,
            &key,
            &hex_digest(Sha256::digest(body)),
        );
        let (projection, projection_outcome) =
            PackageProjection::open_or_build_validated_with_outcome(
                &path,
                body,
                ProjectionSourceKind::ArchiveHistory,
                ProjectionContract {
                    parser_schema: super::CRAN_PARSER_SCHEMA,
                    compatibility_profile: super::CRAN_COMPATIBILITY_PROFILE,
                    normalization_policy: super::CRAN_NORMALIZATION_POLICY,
                },
                || build_archive_projection(body),
                ArchiveHistorySource::validate_projection,
            )
            .map_err(|error| match error {
                ProjectionError::Build(error) => MetadataParseFailure::Invalid(error.into()),
                ProjectionError::Storage(error) => {
                    MetadataParseFailure::SnapshotInvalid(error.into())
                }
            })?;
        match projection_outcome {
            ProjectionOpenOutcome::Reused => self.metrics.borrow_mut().projection_reuses += 1,
            ProjectionOpenOutcome::Built => self.metrics.borrow_mut().projection_builds += 1,
            ProjectionOpenOutcome::Rebuilt => self.metrics.borrow_mut().projection_rebuilds += 1,
        }
        // Derived projection cleanup is bounded but non-essential to metadata
        // correctness; retry a failed cleanup on a later refresh.
        let _ = cache.retain_projection_namespace(ProjectionNamespace::ArchiveHistory, &path, None);
        let rebuild_path = path.clone();
        let rebuild_body = body.to_vec();
        let rebuild: Rc<dyn Fn() -> Result<PackageProjection, String>> = Rc::new(move || {
            PackageProjection::rebuild_validated(
                &rebuild_path,
                &rebuild_body,
                ProjectionSourceKind::ArchiveHistory,
                ProjectionContract {
                    parser_schema: super::CRAN_PARSER_SCHEMA,
                    compatibility_profile: super::CRAN_COMPATIBILITY_PROFILE,
                    normalization_policy: super::CRAN_NORMALIZATION_POLICY,
                },
                || build_archive_projection(&rebuild_body),
                ArchiveHistorySource::validate_projection,
            )
            .map_err(|error| match error {
                ProjectionError::Build(error) | ProjectionError::Storage(error) => error,
            })
        });
        ArchiveHistorySource::from_projection(projection, Some(rebuild), self.metrics.clone())
            .map(Rc::new)
            .map_err(|error| MetadataParseFailure::SnapshotInvalid(error.into()))
    }

    fn push_history_diagnostic(
        &mut self,
        endpoint: String,
        status: Option<u16>,
        diagnostic: String,
    ) {
        self.diagnostics.push(CranRefreshDiagnostic {
            endpoint: endpoint.into_boxed_str(),
            status,
            status_detail: CranFastPathStatus::Invalid {
                status: status.unwrap_or_default(),
                diagnostic: diagnostic.into_boxed_str(),
            },
            source: CranRefreshSource::ArchiveHistory,
        });
    }
}

fn build_archive_projection(body: &[u8]) -> Result<ProjectionBuild, String> {
    #[cfg(test)]
    super::note_archive_projection_build();
    let projection = enumerate_archive_rds_for_provider(body).map_err(|error| error.to_string())?;
    let entry_count = projection.entries.len();
    let rejection_count = projection.rejections.len();
    let first_rejection = projection
        .rejections
        .first()
        .map(ArchiveHistoryRejection::diagnostic);
    let surface_digest = history_surface_digest(&projection.entries);
    let mut grouped = BTreeMap::<String, ArchivePackagePayload>::new();
    for entry in projection.entries {
        grouped
            .entry(entry.package().to_string())
            .or_default()
            .entries
            .push(entry);
    }
    for rejection in projection.rejections {
        grouped
            .entry(rejection.package_hint().to_string())
            .or_default()
            .rejections
            .push(rejection);
    }
    let packages = grouped
        .into_iter()
        .map(|(package, payload)| {
            let record_count = payload.entries.len() + payload.rejections.len();
            Ok(ProjectionPackage {
                package,
                record_count,
                payload: postcard::to_stdvec(&payload).map_err(|error| error.to_string())?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let summary = super::ArchiveHistorySummary {
        entry_count,
        rejection_count,
        first_rejection,
    };
    Ok(ProjectionBuild {
        packages,
        summary: postcard::to_stdvec(&summary).map_err(|error| error.to_string())?,
        surface_digest: surface_digest.to_string(),
    })
}

fn eager_archive_source(
    projection: super::super::super::history::ArchiveHistoryProjection,
) -> ArchiveHistorySource {
    let entry_count = projection.entries.len();
    let rejection_count = projection.rejections.len();
    let first_rejection = projection
        .rejections
        .first()
        .map(ArchiveHistoryRejection::diagnostic)
        .map(Into::into);
    let mut packages = BTreeMap::<String, ArchivePackagePayload>::new();
    for entry in projection.entries {
        packages
            .entry(entry.package().to_string())
            .or_default()
            .entries
            .push(entry);
    }
    for rejection in projection.rejections {
        packages
            .entry(rejection.package_hint().to_string())
            .or_default()
            .rejections
            .push(rejection);
    }
    let surface_entries = packages
        .values()
        .flat_map(|p| p.entries.iter().cloned())
        .collect::<Vec<_>>();
    ArchiveHistorySource {
        projection: super::PackageProjectionRecovery::eager(),
        eager: Some(Rc::new(packages)),
        entry_count,
        rejection_count,
        first_rejection,
        surface_digest: super::history_surface_digest(&surface_entries),
    }
}

fn hex_digest(digest: impl AsRef<[u8]>) -> Box<str> {
    digest
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
        .into_boxed_str()
}
