use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use sha2::{Digest, Sha256};

use super::super::super::catalog::CranCatalog;
use super::super::cache_policy::CacheControlHeader;
use super::super::model::CranRefreshProgress;
use super::super::model::{
    CranCurrentIndexRepresentation, CranFastPathStatus, CranRefreshDiagnostic,
    CranRefreshMetricsSource, CranRefreshSource,
};
use super::super::raw_cache::RawCacheRepresentation;
use super::super::raw_cache::projection::{
    PackageProjection, ProjectionBuild, ProjectionContract, ProjectionError, ProjectionOpenOutcome,
    ProjectionPackage, ProjectionSourceKind,
};
use super::super::raw_cache::{ProjectionNamespace, RawCacheLookup, RawCacheWrite};
use super::super::transport::{Transport, TransportResponseHeaders, TransportValidators};
use super::{
    CranRefreshSession, CurrentBody, CurrentBodyOrigin, CurrentProjection,
    DEFAULT_COMPATIBLE_GENERATION_TTL, cache_control_policy, permits_reuse,
};
use rsolve_core::{CandidateLoadError, CandidateLoadErrorCategory, PackageName};

fn current_projection_contract() -> ProjectionContract {
    ProjectionContract {
        parser_schema: super::CRAN_PARSER_SCHEMA,
        compatibility_profile: super::CRAN_COMPATIBILITY_PROFILE,
        normalization_policy: super::CRAN_NORMALIZATION_POLICY,
    }
}

#[derive(serde::Deserialize, serde::Serialize)]
pub(super) struct CurrentProjectionRecord {
    pub(super) record_index: usize,
    pub(super) package: String,
    pub(super) fields: Vec<(String, String)>,
}

pub(super) fn decode_current_records(
    payload: &[u8],
    package: &PackageName,
) -> Result<Vec<CurrentProjectionRecord>, String> {
    let records: Vec<CurrentProjectionRecord> =
        postcard::from_bytes(payload).map_err(|error| error.to_string())?;
    if records
        .iter()
        .any(|record| record.package != package.as_str())
    {
        return Err(format!(
            "current package projection payload is not bound to {package}"
        ));
    }
    Ok(records)
}

fn build_current_projection(
    representation: CranCurrentIndexRepresentation,
    body: &[u8],
) -> Result<
    (
        ProjectionBuild,
        CranCatalog,
        Vec<super::super::super::catalog::CranCatalogObservation>,
    ),
    String,
> {
    #[cfg(test)]
    super::note_current_projection_build();
    let (catalog, observations) =
        super::super::snapshot::import_current_index(representation, body)
            .map_err(|error| error.to_string())?;
    let mut grouped = BTreeMap::<String, Vec<CurrentProjectionRecord>>::new();
    for observation in &observations {
        grouped
            .entry(observation.package().to_string())
            .or_default()
            .push(CurrentProjectionRecord {
                record_index: observation.record_index(),
                package: observation.package().to_string(),
                fields: observation.fields().to_vec(),
            });
    }
    let packages = grouped
        .into_iter()
        .map(|(package, records)| {
            let record_count = records.len();
            Ok(ProjectionPackage {
                package,
                record_count,
                payload: postcard::to_stdvec(&records).map_err(|error| error.to_string())?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let surface_digest = super::catalog_surface_digest(&catalog);
    let build = ProjectionBuild {
        packages,
        summary: Vec::new(),
        surface_digest: surface_digest.into(),
    };
    Ok((build, catalog, observations))
}

impl<T: Transport + 'static> CranRefreshSession<T> {
    fn cache_error(error: impl std::fmt::Display) -> CandidateLoadError {
        CandidateLoadError::new(
            CandidateLoadErrorCategory::SnapshotInvalid,
            format!("CRAN current raw cache is invalid: {error}"),
        )
    }

    pub(in crate::cran::provider) fn ensure_current(
        &mut self,
    ) -> Result<Rc<CurrentProjection>, CandidateLoadError> {
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
            let endpoint = super::super::join_endpoint_path(
                &self.base_url,
                &format!("src/contrib/{filename}"),
            );
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
                        self.metrics.borrow_mut().raw_cache_hits += 1;
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
                                self.transport.get_with_validators_with_source(
                                    &endpoint,
                                    &validators,
                                    CranRefreshMetricsSource::CurrentIndex,
                                )
                            } else {
                                self.transport.get_with_source(
                                    &endpoint,
                                    CranRefreshMetricsSource::CurrentIndex,
                                )
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
                    RawCacheLookup::Missing => {
                        self.metrics.borrow_mut().raw_cache_misses += 1;
                    }
                    RawCacheLookup::Corrupt(_) => {
                        self.metrics.borrow_mut().raw_cache_corrupt += 1;
                    }
                }
            }
            if candidate.is_none() && !network_attempted {
                match self
                    .transport
                    .get_with_source(&endpoint, CranRefreshMetricsSource::CurrentIndex)
                {
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
                let projection_path = match (&self.raw_cache, &cache_key) {
                    (Some(cache), Some(key)) => {
                        cache
                            .prepare_projection_path(ProjectionNamespace::Current, key)
                            .map_err(Self::cache_error)?;
                        Some(cache.projection_path_in_namespace(
                            ProjectionNamespace::Current,
                            key,
                            &super::hex_digest(Sha256::digest(&body.body)),
                        ))
                    }
                    _ => None,
                };
                let parsed = match projection_path.as_ref() {
                    Some(path) => {
                        let rebuild_path = path.clone();
                        let rebuild_body = body.body.clone();
                        // Keep the catalog produced by a projection build as
                        // a build artifact. Reopening an existing projection
                        // leaves this empty and therefore retains lazy
                        // materialization.
                        let built_catalog = Rc::new(RefCell::new(None));
                        let build_catalog = Rc::clone(&built_catalog);
                        let rebuild: Rc<dyn Fn() -> Result<PackageProjection, String>> =
                            Rc::new(move || {
                                PackageProjection::rebuild_validated(
                                    &rebuild_path,
                                    &rebuild_body,
                                    ProjectionSourceKind::Current,
                                    current_projection_contract(),
                                    || {
                                        build_current_projection(representation, &rebuild_body)
                                            .map(|(build, _, _)| build)
                                    },
                                    |_| Ok(()),
                                )
                                .map_err(|error| match error {
                                    ProjectionError::Build(error)
                                    | ProjectionError::Storage(error) => error,
                                })
                            });
                        PackageProjection::open_or_build_with_outcome(
                            path,
                            &body.body,
                            ProjectionSourceKind::Current,
                            current_projection_contract(),
                            || {
                                build_current_projection(representation, &body.body).map(
                                    |(build, catalog, _)| {
                                        *build_catalog.borrow_mut() = Some(catalog);
                                        build
                                    },
                                )
                            },
                        )
                        .map(|(projection, outcome)| {
                            match outcome {
                                ProjectionOpenOutcome::Reused => {
                                    self.metrics.borrow_mut().projection_reuses += 1
                                }
                                ProjectionOpenOutcome::Built => {
                                    self.metrics.borrow_mut().projection_builds += 1
                                }
                                ProjectionOpenOutcome::Rebuilt => {
                                    self.metrics.borrow_mut().projection_rebuilds += 1
                                }
                            }
                            CurrentProjection::new(
                                projection,
                                Some(rebuild),
                                built_catalog.borrow_mut().take().map(Rc::new),
                                self.metrics.clone(),
                            )
                        })
                    }
                    None => build_current_projection(representation, &body.body)
                        .map(|(build, catalog, observations)| {
                            debug_assert_eq!(
                                build
                                    .packages
                                    .iter()
                                    .map(|package| package.record_count)
                                    .sum::<usize>(),
                                observations.len()
                            );
                            CurrentProjection::eager(catalog, observations)
                        })
                        .map_err(ProjectionError::Build),
                };
                let current_projection = match parsed {
                    Ok(projection) => projection,
                    Err(ProjectionError::Build(error))
                        if matches!(
                            origin,
                            Some(CurrentBodyOrigin::Cached | CurrentBodyOrigin::Revalidated304)
                        ) && !retried_unconditionally =>
                    {
                        retried_unconditionally = true;
                        let cached_error = error;
                        match self
                            .transport
                            .get_with_source(&endpoint, CranRefreshMetricsSource::CurrentIndex)
                        {
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
                    Err(ProjectionError::Storage(error)) => {
                        let diagnostic =
                            format!("current index projection storage failed: {error}");
                        self.push_current_diagnostic(
                            endpoint.clone(),
                            representation,
                            Some(200),
                            diagnostic.clone(),
                        );
                        failures.push(diagnostic);
                        let error = CandidateLoadError::new(
                            CandidateLoadErrorCategory::SnapshotInvalid,
                            failures
                                .last()
                                .cloned()
                                .unwrap_or_else(|| "current projection storage failed".into()),
                        );
                        self.current = Some(Err(error.clone()));
                        return Err(error);
                    }
                    Err(ProjectionError::Build(error)) => {
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
                if let (Some(cache), Some(path)) = (&self.raw_cache, projection_path.as_deref()) {
                    // Projection cleanup is deliberately best-effort. A
                    // failed attempt is retried on a later refresh and must
                    // not turn valid metadata into a refresh failure.
                    let _ =
                        cache.retain_projection_namespace(ProjectionNamespace::Current, path, None);
                }
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
                self.current_surface_digest = Some(current_projection.surface_digest().into());
                self.current_source = Some(source);
                self.emit_progress(CranRefreshProgress::CurrentIndexCompleted {
                    packages: current_projection.package_count(),
                });
                let current_projection = Rc::new(current_projection);
                self.current = Some(Ok(Rc::clone(&current_projection)));
                return Ok(current_projection);
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
