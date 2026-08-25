use std::rc::Rc;

use super::super::super::history::enumerate_archive_rds_for_provider;
use super::super::model::{CranFastPathStatus, CranRefreshDiagnostic, CranRefreshSource};
use super::super::qualification;
use super::super::raw_cache::{RawCache, RawCacheRepresentation};
use super::super::transport::Transport;
use super::{
    AllPackagesSource, CRAN_COMPATIBILITY_PROFILE, CRAN_NORMALIZATION_POLICY, CRAN_PARSER_SCHEMA,
    CranCurrentIndexRepresentation, CranRefreshSession, MetadataAcquisitionFailure,
    MetadataAcquisitionOutcome, MetadataParseFailure, catalog_surface_digest, hex_digest,
    history_surface_digest,
};
use rsolve_core::{CandidateLoadError, CandidateLoadErrorCategory};

impl<T: Transport> CranRefreshSession<T> {
    fn push_allpackages_diagnostic(&mut self, status: Option<u16>, diagnostic: String) {
        self.diagnostics.push(CranRefreshDiagnostic {
            endpoint: self.allpackages_feed_endpoint.clone(),
            status,
            status_detail: CranFastPathStatus::Invalid {
                status: status.unwrap_or_default(),
                diagnostic: diagnostic.into_boxed_str(),
            },
            source: CranRefreshSource::AllPackages,
        });
    }

    /// Acquire the independently configured bulk observation feed. Its rows
    /// remain observations until they are bound to the target repository's
    /// current/archive surface.
    pub(super) fn ensure_allpackages(
        &mut self,
    ) -> Result<Rc<AllPackagesSource>, CandidateLoadError> {
        if let Some(result) = &self.allpackages {
            return result.clone();
        }
        if self.raw_cache.is_none() {
            let error = CandidateLoadError::new(
                CandidateLoadErrorCategory::TransportFailure,
                "ALLPACKAGES projection cache is not prepared",
            );
            self.push_allpackages_diagnostic(None, error.diagnostic().to_string());
            self.allpackages = Some(Err(error.clone()));
            return Err(error);
        }
        if self.allpackages_feed_endpoint.is_empty() {
            let error = CandidateLoadError::new(
                CandidateLoadErrorCategory::TransportFailure,
                "ALLPACKAGES feed endpoint is not configured",
            );
            self.push_allpackages_diagnostic(None, error.diagnostic().to_string());
            self.allpackages = Some(Err(error.clone()));
            return Err(error);
        }
        let current_catalog = self.ensure_current()?;
        self.ensure_history()?;
        let endpoint = self.allpackages_feed_endpoint.to_string();
        let qualification_path = self.raw_cache.as_ref().map(RawCache::qualification_path);
        let current_digest = self.current_surface_digest.clone().ok_or_else(|| {
            CandidateLoadError::new(
                CandidateLoadErrorCategory::SnapshotInvalid,
                "current surface digest is unavailable for ALLPACKAGES qualification",
            )
        })?;
        let archive_digest = self.history_surface_digest.clone().ok_or_else(|| {
            CandidateLoadError::new(
                CandidateLoadErrorCategory::SnapshotInvalid,
                "archive surface digest is unavailable for ALLPACKAGES qualification",
            )
        })?;
        let persisted_qualification = match qualification_path.as_deref() {
            Some(path) => match qualification::load_result(path) {
                Ok(record) => record,
                Err(error) => {
                    let diagnostic = format!("invalid ALLPACKAGES qualification: {error}");
                    self.push_allpackages_diagnostic(None, diagnostic.clone());
                    if let Err(remove_error) = std::fs::remove_file(path) {
                        let error = CandidateLoadError::new(
                            CandidateLoadErrorCategory::SnapshotInvalid,
                            format!(
                                "{diagnostic}; unable to remove invalid qualification: {remove_error}"
                            ),
                        );
                        self.push_allpackages_diagnostic(None, error.diagnostic().to_string());
                        self.allpackages = Some(Err(error.clone()));
                        return Err(error);
                    }
                    None
                }
            },
            None => None,
        };
        if let Some(record) = persisted_qualification.as_ref()
            && qualification::matches(
                record,
                &self.base_url,
                &endpoint,
                &current_digest,
                &archive_digest,
                None,
            )
            && !self.refresh_metadata
            && record.status != qualification::Status::Positive
            && record
                .next_probe_at
                .as_deref()
                .and_then(|value| value.parse::<jiff::Timestamp>().ok())
                .is_some_and(|next| self.now() < next)
        {
            let error = CandidateLoadError::new(
                CandidateLoadErrorCategory::TransportFailure,
                format!(
                    "ALLPACKAGES qualification is {:?} until {}",
                    record.status,
                    record.next_probe_at.as_deref().unwrap_or("unknown")
                ),
            );
            self.push_allpackages_diagnostic(None, error.diagnostic().to_string());
            self.allpackages = Some(Err(error.clone()));
            return Err(error);
        }
        let result = match self.acquire_metadata(
            &endpoint,
            RawCacheRepresentation::AllPackagesZstd,
            "cran-allpackages",
            "zstd",
            |body| {
                let projection_path = self.raw_cache.as_ref().and_then(|cache| {
                    cache
                        .key(&endpoint, RawCacheRepresentation::AllPackagesZstd)
                        .ok()
                        .map(|key| cache.projection_path(&key, body))
                });
                let Some(path) = projection_path.as_deref() else {
                    return Err(MetadataParseFailure::Invalid(
                        "ALLPACKAGES projection cache is unavailable".into(),
                    ));
                };
                match super::super::allpackages::load_or_build_projection(body, path) {
                    Ok(projection) => Ok(projection),
                    Err(error) => {
                        // Keep this refresh fail-closed, but remove only the
                        // content-addressed derived file so the next refresh
                        // can safely rebuild it from the validated raw body.
                        let _ = std::fs::remove_file(path);
                        Err(MetadataParseFailure::NoFallback(error.into()))
                    }
                }
            },
        ) {
            Ok((projection, source, outcome)) => {
                let feed_digest = hex_digest(source.content_sha256).to_string();
                let projection_path = self.raw_cache.as_ref().and_then(|cache| {
                    cache
                        .key(&endpoint, RawCacheRepresentation::AllPackagesZstd)
                        .ok()
                        .map(|key| cache.projection_path_for_digest(&key, &source.content_sha256))
                });
                let Some(projection_path) = projection_path else {
                    return Err(CandidateLoadError::new(
                        CandidateLoadErrorCategory::SnapshotInvalid,
                        "ALLPACKAGES projection cache path is unavailable",
                    ));
                };

                // A positive qualification is the durable result of the
                // complete mirror decision. Once the feed bytes have been
                // acquired and all binding inputs still match, reuse that
                // decision directly instead of rescanning the projection or
                // fetching canonical evidence again. Forced refreshes and
                // stale or mismatched records deliberately fall through to
                // the full validation path below.
                let reusable_positive = persisted_qualification.as_ref().filter(|record| {
                    !self.refresh_metadata
                        && record.status == qualification::Status::Positive
                        && qualification::matches(
                            record,
                            &self.base_url,
                            &endpoint,
                            &current_digest,
                            &archive_digest,
                            Some(&feed_digest),
                        )
                        && qualification::positive_reusable(record, self.now())
                });
                if reusable_positive.is_some() {
                    let status = match outcome {
                        MetadataAcquisitionOutcome::Revalidated304 => 304,
                        MetadataAcquisitionOutcome::Cached
                        | MetadataAcquisitionOutcome::Network200 => 200,
                    };
                    self.diagnostics.push(CranRefreshDiagnostic {
                        endpoint: endpoint.clone().into_boxed_str(),
                        status: Some(status),
                        status_detail: CranFastPathStatus::Available,
                        source: CranRefreshSource::AllPackages,
                    });
                    let result = Rc::new(AllPackagesSource {
                        projection: Rc::new(projection),
                        source,
                        projection_path,
                    });
                    let result = Ok(result);
                    self.allpackages = Some(result.clone());
                    return result;
                }

                let coverage = projection
                    .classify_current(&current_catalog)
                    .map_err(|error| {
                        CandidateLoadError::new(
                            CandidateLoadErrorCategory::SnapshotInvalid,
                            format!("invalid ALLPACKAGES coverage projection: {error}"),
                        )
                    })?;
                let (mirror_positive, canonical_current_digest, canonical_archive_digest) =
                    if self.base_url.as_ref() == "https://cloud.r-project.org" {
                        // The built-in anchor is immutable by construction;
                        // avoid re-fetching it solely to qualify itself.
                        (true, current_digest.clone(), archive_digest.clone())
                    } else if let Some(record) = qualification_path
                        .as_deref()
                        .and_then(qualification::load)
                        .filter(|record| {
                            !self.refresh_metadata
                                && qualification::matches(
                                    record,
                                    &self.base_url,
                                    &endpoint,
                                    &current_digest,
                                    &archive_digest,
                                    Some(&feed_digest),
                                )
                                && record.status == qualification::Status::Positive
                                && qualification::positive_reusable(record, self.now())
                        })
                    {
                        (
                            true,
                            record.canonical_current_digest.into(),
                            record.canonical_archive_digest.into(),
                        )
                    } else {
                        self.custom_surface_matches_canonical()?
                    };
                if !mirror_positive {
                    if let Some(path) = qualification_path.as_deref() {
                        let previous = qualification::load(path);
                        let failure_count =
                            previous.map_or(1, |record| record.failure_count.saturating_add(1));
                        qualification::publish(
                            path,
                            &qualification::Record {
                                version: 1,
                                repository_endpoint: self.base_url.to_string(),
                                feed_endpoint: endpoint.clone(),
                                current_digest: current_digest.to_string(),
                                archive_digest: archive_digest.to_string(),
                                feed_digest: feed_digest.clone(),
                                feed_etag: source.etag.clone(),
                                feed_last_modified: source.last_modified.clone(),
                                canonical_current_digest: canonical_current_digest.to_string(),
                                canonical_archive_digest: canonical_archive_digest.to_string(),
                                coverage_status: coverage.status,
                                covered_count: coverage.covered_count,
                                gapped_count: coverage.gapped_count,
                                conflicting_count: coverage.conflicting_count,
                                coverage_digest: coverage.digest.clone(),
                                compatibility_profile: CRAN_COMPATIBILITY_PROFILE,
                                parser_schema: CRAN_PARSER_SCHEMA,
                                normalization_policy: CRAN_NORMALIZATION_POLICY,
                                status: qualification::Status::Negative,
                                diagnostic:
                                    "configured repository does not match canonical CRAN surface"
                                        .into(),
                                failure_count,
                                next_probe_at: Some(qualification::failure_probe_at(
                                    self.now(),
                                    failure_count,
                                    None,
                                    fastrand::u64(..),
                                )),
                                validated_at: self.now().strftime("%Y-%m-%dT%H:%M:%SZ").to_string(),
                                ..qualification::Record::default()
                            },
                        )
                        .map_err(|error| {
                            CandidateLoadError::new(
                                CandidateLoadErrorCategory::SnapshotInvalid,
                                format!("unable to persist ALLPACKAGES qualification: {error}"),
                            )
                        })?;
                    }
                    let error = CandidateLoadError::new(
                        CandidateLoadErrorCategory::MetadataInvalid,
                        "configured CRAN endpoint does not match canonical CRAN surface",
                    );
                    self.push_allpackages_diagnostic(None, error.diagnostic().to_string());
                    return Err(error);
                }
                let validated_at = qualification_path
                    .as_deref()
                    .and_then(qualification::load)
                    .filter(|record| {
                        !self.refresh_metadata
                            && record.status == qualification::Status::Positive
                            && qualification::matches(
                                record,
                                &self.base_url,
                                &endpoint,
                                &current_digest,
                                &archive_digest,
                                Some(&feed_digest),
                            )
                            && qualification::positive_reusable(record, self.now())
                    })
                    .map(|record| record.validated_at)
                    .unwrap_or_else(|| self.now().strftime("%Y-%m-%dT%H:%M:%SZ").to_string());
                if let Some(path) = qualification_path.as_deref() {
                    qualification::publish(
                        path,
                        &qualification::Record {
                            version: 1,
                            repository_endpoint: self.base_url.to_string(),
                            feed_endpoint: endpoint.clone(),
                            current_digest: current_digest.to_string(),
                            archive_digest: archive_digest.to_string(),
                            feed_digest: feed_digest.clone(),
                            feed_etag: source.etag.clone(),
                            feed_last_modified: source.last_modified.clone(),
                            canonical_current_digest: canonical_current_digest.to_string(),
                            canonical_archive_digest: canonical_archive_digest.to_string(),
                            coverage_status: coverage.status,
                            covered_count: coverage.covered_count,
                            gapped_count: coverage.gapped_count,
                            conflicting_count: coverage.conflicting_count,
                            coverage_digest: coverage.digest.clone(),
                            compatibility_profile: CRAN_COMPATIBILITY_PROFILE,
                            parser_schema: CRAN_PARSER_SCHEMA,
                            normalization_policy: CRAN_NORMALIZATION_POLICY,
                            status: qualification::Status::Positive,
                            diagnostic: "repository surface qualified as CRAN mirror".into(),
                            failure_count: 0,
                            next_probe_at: None,
                            validated_at,
                            ..qualification::Record::default()
                        },
                    )
                    .map_err(|error| {
                        CandidateLoadError::new(
                            CandidateLoadErrorCategory::SnapshotInvalid,
                            format!("unable to persist ALLPACKAGES qualification: {error}"),
                        )
                    })?;
                }
                let status = match outcome {
                    MetadataAcquisitionOutcome::Revalidated304 => 304,
                    MetadataAcquisitionOutcome::Cached | MetadataAcquisitionOutcome::Network200 => {
                        200
                    }
                };
                let detail = CranFastPathStatus::Available;
                self.diagnostics.push(CranRefreshDiagnostic {
                    endpoint: endpoint.clone().into_boxed_str(),
                    status: Some(status),
                    status_detail: detail,
                    source: CranRefreshSource::AllPackages,
                });
                Ok(Rc::new(AllPackagesSource {
                    projection: Rc::new(projection),
                    source,
                    projection_path,
                }))
            }
            Err(error) if matches!(error.status, Some(404 | 410)) => {
                let status = error.status.expect("matched status");
                if let Some(path) = qualification_path.as_deref() {
                    let failure_count = qualification::load(path)
                        .map_or(1, |record| record.failure_count.saturating_add(1));
                    qualification::publish(
                        path,
                        &qualification::Record {
                            version: 1,
                            repository_endpoint: self.base_url.to_string(),
                            feed_endpoint: endpoint.clone(),
                            current_digest: current_digest.to_string(),
                            archive_digest: archive_digest.to_string(),
                            feed_digest: String::new(),
                            compatibility_profile: CRAN_COMPATIBILITY_PROFILE,
                            parser_schema: CRAN_PARSER_SCHEMA,
                            normalization_policy: CRAN_NORMALIZATION_POLICY,
                            status: qualification::Status::Negative,
                            diagnostic: error.diagnostic.to_string(),
                            failure_count,
                            next_probe_at: Some(qualification::failure_probe_at(
                                self.now(),
                                failure_count,
                                error.retry_after.as_deref(),
                                fastrand::u64(..),
                            )),
                            validated_at: self.now().strftime("%Y-%m-%dT%H:%M:%SZ").to_string(),
                            ..qualification::Record::default()
                        },
                    )
                    .map_err(|error| {
                        CandidateLoadError::new(
                            CandidateLoadErrorCategory::SnapshotInvalid,
                            format!("unable to persist ALLPACKAGES qualification: {error}"),
                        )
                    })?;
                }
                self.diagnostics.push(CranRefreshDiagnostic {
                    endpoint: endpoint.clone().into_boxed_str(),
                    status: Some(status),
                    status_detail: CranFastPathStatus::Unsupported { status },
                    source: CranRefreshSource::AllPackages,
                });
                Err(error.into_candidate())
            }
            Err(error) => {
                if let Some(path) = qualification_path.as_deref() {
                    let previous = qualification::load(path);
                    let failure_count =
                        previous.map_or(1, |record| record.failure_count.saturating_add(1));
                    let status = if matches!(error.status, Some(404 | 410)) {
                        qualification::Status::Negative
                    } else {
                        qualification::Status::Unknown
                    };
                    qualification::publish(
                        path,
                        &qualification::Record {
                            version: 1,
                            repository_endpoint: self.base_url.to_string(),
                            feed_endpoint: endpoint.clone(),
                            current_digest: current_digest.to_string(),
                            archive_digest: archive_digest.to_string(),
                            feed_digest: String::new(),
                            compatibility_profile: CRAN_COMPATIBILITY_PROFILE,
                            parser_schema: CRAN_PARSER_SCHEMA,
                            normalization_policy: CRAN_NORMALIZATION_POLICY,
                            status,
                            diagnostic: error.diagnostic.to_string(),
                            failure_count,
                            next_probe_at: Some(qualification::failure_probe_at(
                                self.now(),
                                failure_count,
                                error.retry_after.as_deref(),
                                fastrand::u64(..),
                            )),
                            validated_at: self.now().strftime("%Y-%m-%dT%H:%M:%SZ").to_string(),
                            ..qualification::Record::default()
                        },
                    )
                    .map_err(|persist_error| {
                        CandidateLoadError::new(
                            CandidateLoadErrorCategory::SnapshotInvalid,
                            format!("unable to persist ALLPACKAGES qualification: {persist_error}"),
                        )
                    })?;
                }
                self.diagnostics.push(CranRefreshDiagnostic {
                    endpoint: endpoint.clone().into_boxed_str(),
                    status: error.status,
                    status_detail: CranFastPathStatus::Invalid {
                        status: error.status.unwrap_or_default(),
                        diagnostic: error.diagnostic.clone(),
                    },
                    source: CranRefreshSource::AllPackages,
                });
                Err(error.into_candidate())
            }
        };
        self.allpackages = Some(result.clone());
        result
    }

    fn custom_surface_matches_canonical(
        &mut self,
    ) -> Result<(bool, Box<str>, Box<str>), CandidateLoadError> {
        let current_endpoint = "https://cloud.r-project.org/src/contrib/PACKAGES.rds";
        let (canonical_current, _, _) = self
            .acquire_metadata(
                current_endpoint,
                RawCacheRepresentation::CurrentRds,
                "cran-canonical-current",
                "rds",
                |body| {
                    Self::parse_current_body(CranCurrentIndexRepresentation::Rds, body)
                        .map(|(catalog, _)| catalog)
                        .map_err(|error| MetadataParseFailure::Invalid(error.into()))
                },
            )
            .map_err(MetadataAcquisitionFailure::into_candidate)?;
        let history_endpoint = "https://cloud.r-project.org/src/contrib/Meta/archive.rds";
        let (canonical_history, _, _) = self
            .acquire_metadata(
                history_endpoint,
                RawCacheRepresentation::ArchiveHistoryRds,
                "cran-canonical-history",
                "rds",
                |body| {
                    enumerate_archive_rds_for_provider(body)
                        .map_err(|error| MetadataParseFailure::Invalid(error.to_string().into()))
                },
            )
            .map_err(MetadataAcquisitionFailure::into_candidate)?;
        let target_current = self.current_surface_digest.as_deref().ok_or_else(|| {
            CandidateLoadError::new(
                CandidateLoadErrorCategory::SnapshotInvalid,
                "target current surface digest is unavailable",
            )
        })?;
        let target_history = self.history_surface_digest.as_deref().ok_or_else(|| {
            CandidateLoadError::new(
                CandidateLoadErrorCategory::SnapshotInvalid,
                "target archive surface digest is unavailable",
            )
        })?;
        let canonical_current_digest = catalog_surface_digest(&canonical_current);
        let canonical_history_digest = history_surface_digest(&canonical_history.entries);
        Ok((
            target_current == canonical_current_digest.as_ref()
                && target_history == canonical_history_digest.as_ref(),
            canonical_current_digest,
            canonical_history_digest,
        ))
    }
}
