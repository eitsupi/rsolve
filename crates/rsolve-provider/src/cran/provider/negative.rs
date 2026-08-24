//! Session-local negative-cache fallback decisions.

use super::CranRefreshDiagnostic;
use super::{CandidateSource, CranRefreshSession, HistorySource, Transport};
use rsolve_core::{CandidateLoadError, CandidateLoadErrorCategory};

pub(super) enum FastPathFailure {
    Unsupported,
    Invalid {
        category: CandidateLoadErrorCategory,
        diagnostic: Box<str>,
    },
}

impl<T: Transport> CranRefreshSession<T> {
    pub(super) fn resolve_fast_path_failure(
        &mut self,
        mut package_diagnostics: Vec<CranRefreshDiagnostic>,
        failure: FastPathFailure,
    ) -> Result<Option<CandidateSource>, CandidateLoadError> {
        // Record the fast-path attempt before probing history so diagnostics
        // follow the actual endpoint order. History itself is cached by the
        // session and contributes at most one diagnostic.
        self.diagnostics.append(&mut package_diagnostics);
        match self.ensure_history()? {
            HistorySource::Available {
                entries,
                rejections,
            } => Ok(Some(CandidateSource::Fallback {
                entries,
                rejections,
            })),
            HistorySource::Absent => match failure {
                FastPathFailure::Unsupported => Ok(None),
                FastPathFailure::Invalid {
                    category,
                    diagnostic,
                } => Err(CandidateLoadError::new(
                    category,
                    format!("{diagnostic}; archive history is absent"),
                )),
            },
        }
    }
}
