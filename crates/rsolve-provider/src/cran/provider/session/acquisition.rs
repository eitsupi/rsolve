use super::super::model::CranRefreshMetricsSource;
use super::super::raw_cache::{RawCacheLookup, RawCacheRepresentation, RawCacheWrite};
use super::super::transport::{Transport, TransportResponseHeaders, TransportValidators};
use super::{
    CranRefreshSession, CurrentBody, CurrentBodyOrigin, DEFAULT_COMPATIBLE_GENERATION_TTL,
    MetadataAcquisitionFailure, MetadataAcquisitionOutcome, MetadataParseFailure,
    cache_control_policy, permits_reuse,
};

impl<T: Transport + 'static> CranRefreshSession<T> {
    pub(super) fn acquire_metadata<V, P>(
        &self,
        endpoint: &str,
        representation: RawCacheRepresentation,
        source_kind: &str,
        source_representation: &str,
        metrics_source: CranRefreshMetricsSource,
        mut parse: P,
    ) -> Result<
        (V, crate::snapshot::SourceInput, MetadataAcquisitionOutcome),
        MetadataAcquisitionFailure,
    >
    where
        P: FnMut(&[u8]) -> Result<V, MetadataParseFailure>,
    {
        let cache_key = self
            .raw_cache
            .as_ref()
            .map(|cache| {
                cache
                    .key(endpoint, representation)
                    .map_err(MetadataAcquisitionFailure::cache)
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
                                endpoint,
                                &validators,
                                metrics_source,
                            )
                        } else {
                            self.transport.get_with_source(endpoint, metrics_source)
                        };
                        match response {
                            Ok(response) if response.status == 304 && response.body.is_empty() => {
                                let mut body = CurrentBody::from_cache(entry);
                                if !matches!(
                                    response.headers.cache_control,
                                    super::CacheControlHeader::Absent
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
                                candidate = Some(CurrentBody::from_response(response, self.now()));
                                origin = Some(CurrentBodyOrigin::Network200);
                            }
                            Ok(response) => {
                                return Err(MetadataAcquisitionFailure::response(
                                    response.status,
                                    format!("unexpected metadata status {}", response.status),
                                    response.headers.retry_after.as_deref(),
                                ));
                            }
                            Err(error) => {
                                return Err(MetadataAcquisitionFailure::transport(error));
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
            match self.transport.get_with_source(endpoint, metrics_source) {
                Ok(response) if response.status == 200 => {
                    candidate = Some(CurrentBody::from_response(response, self.now()));
                    origin = Some(CurrentBodyOrigin::Network200);
                }
                Ok(response) => {
                    return Err(MetadataAcquisitionFailure::response(
                        response.status,
                        format!("unexpected metadata status {}", response.status),
                        response.headers.retry_after.as_deref(),
                    ));
                }
                Err(error) => return Err(MetadataAcquisitionFailure::transport(error)),
            }
        }
        let mut retried_unconditionally = false;
        while let Some(body) = candidate.take() {
            match parse(&body.body) {
                Ok(value) => {
                    let source = body.source_as(source_kind, source_representation, endpoint);
                    let mut body = Some(body);
                    if let (Some(cache), Some(key), Some(CurrentBodyOrigin::Network200)) =
                        (&self.raw_cache, &cache_key, origin)
                    {
                        let body = body.take().expect("validated metadata body");
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
                            .map_err(MetadataAcquisitionFailure::cache)?;
                    } else if let (
                        Some(cache),
                        Some(key),
                        Some(CurrentBodyOrigin::Revalidated304),
                    ) = (&self.raw_cache, &cache_key, origin)
                    {
                        let body = body.as_ref().expect("validated metadata body");
                        let headers = TransportResponseHeaders {
                            etag: body.etag.clone(),
                            last_modified: body.last_modified.clone(),
                            retry_after: None,
                            cache_control: body.cache_control.clone(),
                        };
                        cache
                            .update_validated_at_with_headers(key, self.now(), &headers)
                            .map_err(MetadataAcquisitionFailure::cache)?;
                    }
                    let outcome = match origin {
                        Some(CurrentBodyOrigin::Cached) => MetadataAcquisitionOutcome::Cached,
                        Some(CurrentBodyOrigin::Network200) => {
                            MetadataAcquisitionOutcome::Network200
                        }
                        Some(CurrentBodyOrigin::Revalidated304) => {
                            MetadataAcquisitionOutcome::Revalidated304
                        }
                        None => {
                            return Err(MetadataAcquisitionFailure::invalid(
                                None,
                                "metadata acquisition has no response outcome",
                            ));
                        }
                    };
                    return Ok((value, source, outcome));
                }
                Err(error)
                    if matches!(
                        origin,
                        Some(CurrentBodyOrigin::Cached | CurrentBodyOrigin::Revalidated304)
                    ) && error.allows_cached_retry()
                        && !retried_unconditionally =>
                {
                    retried_unconditionally = true;
                    let allows_fallback = error.allows_fallback();
                    match self.transport.get_with_source(endpoint, metrics_source) {
                        Ok(response) if response.status == 200 => {
                            candidate = Some(CurrentBody::from_response(response, self.now()));
                            origin = Some(CurrentBodyOrigin::Network200);
                        }
                        Ok(response) => {
                            return Err(MetadataAcquisitionFailure::parse(
                                Some(response.status),
                                format!(
                                    "cached metadata was invalid ({error}) and unconditional recovery returned HTTP {}",
                                    response.status
                                ),
                                allows_fallback,
                            ));
                        }
                        Err(fetch_error) => {
                            return Err(MetadataAcquisitionFailure::parse(
                                None,
                                format!(
                                    "cached metadata was invalid ({error}) and unconditional recovery failed: {fetch_error}"
                                ),
                                allows_fallback,
                            ));
                        }
                    }
                }
                Err(error) => {
                    let allows_fallback = error.allows_fallback();
                    return Err(MetadataAcquisitionFailure {
                        status: Some(200),
                        retry_after: None,
                        category: error.category(),
                        diagnostic: error.to_string().into(),
                        fallback_allowed: allows_fallback,
                    });
                }
            }
        }
        Err(MetadataAcquisitionFailure::invalid(
            None,
            "metadata acquisition produced no body",
        ))
    }
}
