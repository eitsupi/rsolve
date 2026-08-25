use std::rc::Rc;

use super::super::super::history::{
    ArchiveEntry, ArchiveHistoryRejection, enumerate_archive_rds_for_provider,
};
use super::super::model::{CranFastPathStatus, CranRefreshDiagnostic, CranRefreshSource};
use super::super::raw_cache::RawCacheRepresentation;
use super::super::transport::Transport;
use super::{CranRefreshSession, HistorySource, MetadataParseFailure, history_surface_digest};
use rsolve_core::{CandidateLoadError, CandidateLoadErrorCategory};

impl<T: Transport> CranRefreshSession<T> {
    pub(in crate::cran::provider) fn ensure_history(
        &mut self,
    ) -> Result<HistorySource, CandidateLoadError> {
        if let Some(result) = &self.history {
            return result.clone();
        }
        let endpoint = format!("{}/src/contrib/Meta/archive.rds", self.base_url);
        let result = match self.acquire_metadata(
            &endpoint,
            RawCacheRepresentation::ArchiveHistoryRds,
            "cran-archive-history",
            "rds",
            |body| {
                enumerate_archive_rds_for_provider(body)
                    .map_err(|error| MetadataParseFailure::Invalid(error.to_string().into()))
            },
        ) {
            Ok((projection, _source, _outcome)) => {
                if !projection.rejections.is_empty() {
                    let first = projection
                        .rejections
                        .first()
                        .map(ArchiveHistoryRejection::diagnostic)
                        .unwrap_or_else(|| "no rejection detail".to_owned());
                    let additional = projection.rejections.len().saturating_sub(1);
                    self.push_history_diagnostic(
                        endpoint.clone(),
                        Some(200),
                        format!(
                            "archive history quarantined {} package-local release(s); first: {first}; {additional} additional rejection(s)",
                            projection.rejections.len()
                        ),
                    );
                }
                let entries: Rc<[ArchiveEntry]> = Rc::from(projection.entries.into_boxed_slice());
                self.history_surface_digest = Some(history_surface_digest(&entries));
                Ok(HistorySource::Available {
                    entries,
                    rejections: Rc::from(projection.rejections.into_boxed_slice()),
                })
            }
            Err(error) if matches!(error.status, Some(404 | 410)) => {
                let status = error.status.expect("matched status");
                self.diagnostics.push(CranRefreshDiagnostic {
                    endpoint: endpoint.clone().into_boxed_str(),
                    status: Some(status),
                    status_detail: CranFastPathStatus::Absent { status },
                    source: CranRefreshSource::ArchiveHistory,
                });
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
