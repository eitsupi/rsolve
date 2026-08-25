use std::rc::Rc;

use super::super::super::catalog::CranCatalog;
use super::super::cache_policy::CacheControlHeader;
use super::super::model::CranRefreshProgress;
use super::super::model::{
    CranCurrentIndexRepresentation, CranFastPathStatus, CranRefreshDiagnostic, CranRefreshSource,
};
use super::super::raw_cache::RawCacheRepresentation;
use super::super::raw_cache::{RawCacheLookup, RawCacheWrite};
use super::super::transport::{Transport, TransportResponseHeaders, TransportValidators};
use super::index_record_to_evidence;
use super::{
    CranRefreshSession, CurrentBody, CurrentBodyOrigin, DEFAULT_COMPATIBLE_GENERATION_TTL,
    cache_control_policy, catalog_surface_digest, permits_reuse,
};
use crate::snapshot::FreshnessStateV1;
use rsolve_core::{CandidateLoadError, CandidateLoadErrorCategory};

impl<T: Transport> CranRefreshSession<T> {
    fn cache_error(error: impl std::fmt::Display) -> CandidateLoadError {
        CandidateLoadError::new(
            CandidateLoadErrorCategory::SnapshotInvalid,
            format!("CRAN current raw cache is invalid: {error}"),
        )
    }

    pub(in crate::cran::provider) fn ensure_current(
        &mut self,
    ) -> Result<Rc<CranCatalog>, CandidateLoadError> {
        if let Some(result) = &self.current {
            return result.clone();
        }
        self.emit_progress(CranRefreshProgress::CurrentIndexStarted);
        let representations = [
            (CranCurrentIndexRepresentation::Gzip, "PACKAGES.gz"),
            (CranCurrentIndexRepresentation::Rds, "PACKAGES.rds"),
            (CranCurrentIndexRepresentation::PlainDcf, "PACKAGES"),
        ];
        let mut failures = Vec::new();
        let mut saw_metadata_invalid = false;
        for (representation, filename) in representations {
            let endpoint = format!("{}/src/contrib/{filename}", self.base_url);
            let cache_key = self
                .raw_cache
                .as_ref()
                .map(|cache| {
                    cache
                        .key(
                            &endpoint,
                            match representation {
                                CranCurrentIndexRepresentation::Rds => {
                                    RawCacheRepresentation::CurrentRds
                                }
                                CranCurrentIndexRepresentation::Gzip => {
                                    RawCacheRepresentation::CurrentGzip
                                }
                                CranCurrentIndexRepresentation::PlainDcf => {
                                    RawCacheRepresentation::CurrentDcf
                                }
                            },
                        )
                        .map_err(Self::cache_error)
                })
                .transpose()?;
            let mut candidate = None;
            let mut origin = None;
            let mut network_attempted = false;
            if let (Some(cache), Some(key)) = (&self.raw_cache, &cache_key) {
                match cache.lookup(key) {
                    RawCacheLookup::Hit(entry) => {
                        let policy = cache_control_policy(
                            &entry.cache_control,
                            DEFAULT_COMPATIBLE_GENERATION_TTL,
                        );
                        if !self.refresh_metadata
                            && permits_reuse(self.now(), entry.validated_at, policy)
                        {
                            candidate = Some(CurrentBody::from_cache(entry));
                            origin = Some(CurrentBodyOrigin::Cached);
                        } else {
                            network_attempted = true;
                            let validators = TransportValidators::from_values(
                                entry.etag.as_deref(),
                                entry.last_modified.as_deref(),
                            );
                            let response = if validators.if_none_match.is_some()
                                || validators.if_modified_since.is_some()
                            {
                                self.transport.get_with_validators(&endpoint, &validators)
                            } else {
                                self.transport.get(&endpoint)
                            };
                            match response {
                                Ok(response)
                                    if response.status == 304 && response.body.is_empty() =>
                                {
                                    let mut body = CurrentBody::from_cache(entry);
                                    if !matches!(
                                        response.headers.cache_control,
                                        CacheControlHeader::Absent
                                    ) {
                                        body.cache_control = response.headers.cache_control.clone();
                                    }
                                    if response.headers.etag.is_some() {
                                        body.etag = response.headers.etag.clone();
                                    }
                                    if response.headers.last_modified.is_some() {
                                        body.last_modified = response.headers.last_modified.clone();
                                    }
                                    candidate = Some(body);
                                    origin = Some(CurrentBodyOrigin::Revalidated304);
                                }
                                Ok(response) if response.status == 200 => {
                                    candidate =
                                        Some(CurrentBody::from_response(response, self.now()));
                                    origin = Some(CurrentBodyOrigin::Network200);
                                }
                                Ok(response) => {
                                    let diagnostic = format!(
                                        "unexpected current index status {}",
                                        response.status
                                    );
                                    self.push_current_diagnostic(
                                        endpoint.clone(),
                                        representation,
                                        Some(response.status),
                                        diagnostic.clone(),
                                    );
                                    failures.push(diagnostic);
                                }
                                Err(error) => {
                                    let diagnostic = format!("transport failure: {error}");
                                    self.push_current_diagnostic(
                                        endpoint.clone(),
                                        representation,
                                        None,
                                        diagnostic.clone(),
                                    );
                                    failures.push(diagnostic);
                                }
                            }
                        }
                    }
                    RawCacheLookup::Missing | RawCacheLookup::Corrupt(_) => {}
                }
            }
            if candidate.is_none() && !network_attempted {
                match self.transport.get(&endpoint) {
                    Ok(response) if response.status == 200 => {
                        candidate = Some(CurrentBody::from_response(response, self.now()));
                        origin = Some(CurrentBodyOrigin::Network200);
                    }
                    Ok(response) => {
                        let diagnostic =
                            format!("unexpected current index status {}", response.status);
                        self.push_current_diagnostic(
                            endpoint.clone(),
                            representation,
                            Some(response.status),
                            diagnostic.clone(),
                        );
                        failures.push(diagnostic);
                    }
                    Err(error) => {
                        let diagnostic = format!("transport failure: {error}");
                        self.push_current_diagnostic(
                            endpoint.clone(),
                            representation,
                            None,
                            diagnostic.clone(),
                        );
                        failures.push(diagnostic);
                    }
                }
            }
            let mut retried_unconditionally = false;
            while let Some(body) = candidate.take() {
                let parsed = Self::parse_current_body(representation, &body.body);
                let (catalog, records) = match parsed {
                    Ok(parsed) => parsed,
                    Err(error)
                        if matches!(
                            origin,
                            Some(CurrentBodyOrigin::Cached | CurrentBodyOrigin::Revalidated304)
                        ) && !retried_unconditionally =>
                    {
                        retried_unconditionally = true;
                        let cached_error = error;
                        match self.transport.get(&endpoint) {
                            Ok(response) if response.status == 200 => {
                                candidate = Some(CurrentBody::from_response(response, self.now()));
                                origin = Some(CurrentBodyOrigin::Network200);
                                continue;
                            }
                            Ok(response) => {
                                let diagnostic = format!(
                                    "cached current index was invalid ({cached_error}) and unconditional recovery returned HTTP {}",
                                    response.status,
                                );
                                self.push_current_diagnostic(
                                    endpoint.clone(),
                                    representation,
                                    Some(response.status),
                                    diagnostic.clone(),
                                );
                                failures.push(diagnostic);
                            }
                            Err(fetch_error) => {
                                let diagnostic = format!(
                                    "cached current index was invalid ({cached_error}) and unconditional recovery failed: {fetch_error}"
                                );
                                self.push_current_diagnostic(
                                    endpoint.clone(),
                                    representation,
                                    None,
                                    diagnostic.clone(),
                                );
                                failures.push(diagnostic);
                            }
                        }
                        break;
                    }
                    Err(error) => {
                        self.push_current_diagnostic(
                            endpoint.clone(),
                            representation,
                            Some(200),
                            error.clone(),
                        );
                        failures.push(error);
                        saw_metadata_invalid = true;
                        break;
                    }
                };
                let mut body = Some(body);
                let source = body
                    .as_ref()
                    .expect("validated current body")
                    .source(representation, &endpoint);
                if let (Some(cache), Some(key), Some(CurrentBodyOrigin::Network200)) =
                    (&self.raw_cache, &cache_key, origin)
                {
                    let body = body.take().expect("validated current body");
                    cache
                        .publish(
                            key,
                            RawCacheWrite {
                                status: 200,
                                body: body.body,
                                observed_at: body.observed_at_timestamp,
                                validated_at: body.observed_at_timestamp,
                                etag: body.etag,
                                last_modified: body.last_modified,
                                cache_control: body.cache_control,
                            },
                        )
                        .map_err(Self::cache_error)?;
                } else if let (Some(cache), Some(key), Some(CurrentBodyOrigin::Revalidated304)) =
                    (&self.raw_cache, &cache_key, origin)
                {
                    let body = body.as_ref().expect("validated current body");
                    let headers = TransportResponseHeaders {
                        etag: body.etag.clone(),
                        last_modified: body.last_modified.clone(),
                        retry_after: None,
                        cache_control: body.cache_control.clone(),
                    };
                    let validated_at = self.now();
                    cache
                        .update_validated_at_with_headers(key, validated_at, &headers)
                        .map_err(Self::cache_error)?;
                }
                self.evidence
                    .borrow_mut()
                    .extend(records.iter().map(|record| {
                        index_record_to_evidence(
                            record,
                            source.clone(),
                            &self.base_url,
                            true,
                            FreshnessStateV1::CurrentGeneration,
                        )
                    }));
                self.diagnostics.push(CranRefreshDiagnostic {
                    endpoint: endpoint.clone().into(),
                    status: Some(
                        if matches!(origin, Some(CurrentBodyOrigin::Revalidated304)) {
                            304
                        } else {
                            200
                        },
                    ),
                    status_detail: CranFastPathStatus::Available,
                    source: CranRefreshSource::CurrentIndex(representation),
                });
                self.current_surface_digest = Some(catalog_surface_digest(&catalog));
                self.emit_progress(CranRefreshProgress::CurrentIndexCompleted {
                    packages: catalog.packages().count(),
                });
                let catalog = Rc::new(catalog);
                self.current = Some(Ok(Rc::clone(&catalog)));
                return Ok(catalog);
            }
        }
        let error = CandidateLoadError::new(
            if saw_metadata_invalid {
                CandidateLoadErrorCategory::MetadataInvalid
            } else {
                CandidateLoadErrorCategory::TransportFailure
            },
            format!(
                "all CRAN current index representations failed: {}",
                failures.join("; ")
            ),
        );
        self.current = Some(Err(error.clone()));
        Err(error)
    }

    fn push_current_diagnostic(
        &mut self,
        endpoint: String,
        representation: CranCurrentIndexRepresentation,
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
            source: CranRefreshSource::CurrentIndex(representation),
        });
    }
}
