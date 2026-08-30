use super::{
    CRAN_COMPATIBILITY_PROFILE, CRAN_NORMALIZATION_POLICY, CRAN_PARSER_SCHEMA,
    DEFAULT_COMPATIBLE_GENERATION_TTL,
};
use crate::SnapshotStore;
use crate::snapshot::ReadOnlySnapshotCandidateLoader;
use rsolve_core::CandidateLoadError;

/// Clock and compatibility policy used by the CRAN snapshot reuse boundary.
/// Supplying an explicit timestamp keeps this decision deterministic in tests
/// and leaves room for HTTP cache policy to take precedence later.
#[derive(Clone, Debug)]
pub struct CranSnapshotCachePolicy {
    pub now: jiff::Timestamp,
    pub compatibility_profile: u32,
    pub parser_schema: u32,
    pub normalization_policy: u32,
    pub expected_endpoint: Option<Box<str>>,
    /// The exact provider-private auxiliary feed permitted alongside the
    /// configured repository endpoint. This is deliberately opt-in rather
    /// than a generic second provenance root.
    pub allowed_auxiliary_endpoint: Option<Box<str>>,
    pub refresh_metadata: bool,
}

impl CranSnapshotCachePolicy {
    pub fn at(now: jiff::Timestamp) -> Self {
        Self {
            now,
            compatibility_profile: CRAN_COMPATIBILITY_PROFILE,
            parser_schema: CRAN_PARSER_SCHEMA,
            normalization_policy: CRAN_NORMALIZATION_POLICY,
            expected_endpoint: None,
            allowed_auxiliary_endpoint: None,
            refresh_metadata: false,
        }
    }

    pub fn with_expected_endpoint(mut self, endpoint: impl AsRef<str>) -> Self {
        self.expected_endpoint = Some(endpoint.as_ref().to_owned().into());
        self
    }

    pub fn with_allowed_auxiliary_endpoint(mut self, endpoint: impl AsRef<str>) -> Self {
        let endpoint = endpoint.as_ref().to_owned().into_boxed_str();
        self.allowed_auxiliary_endpoint = Some(endpoint);
        self
    }

    pub fn with_refresh_metadata(mut self) -> Self {
        self.refresh_metadata = true;
        self
    }
}

impl Default for CranSnapshotCachePolicy {
    fn default() -> Self {
        Self::at(jiff::Timestamp::now())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CranSnapshotCacheStatus {
    Fresh,
    Stale,
    Missing,
    RevisionIncompatible,
    Corrupt,
    Incomplete,
}

/// A typed explanation for reusing or rejecting the provider-owned current
/// view generation. Local generation names and paths are intentionally omitted.
#[derive(Clone, Debug)]
pub struct CranSnapshotCacheDiagnostic {
    status: CranSnapshotCacheStatus,
    age_seconds: Option<u64>,
    endpoints: Vec<Box<str>>,
    diagnostic: Box<str>,
    revision_token: Option<Box<str>>,
}

impl std::fmt::Display for CranSnapshotCacheDiagnostic {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{:?}: {}", self.status, self.diagnostic)
    }
}

impl std::error::Error for CranSnapshotCacheDiagnostic {}

impl CranSnapshotCacheDiagnostic {
    pub fn new(
        status: CranSnapshotCacheStatus,
        age_seconds: Option<u64>,
        endpoints: impl IntoIterator<Item = impl Into<Box<str>>>,
        diagnostic: impl Into<Box<str>>,
    ) -> Self {
        let mut endpoints = endpoints.into_iter().map(Into::into).collect::<Vec<_>>();
        endpoints.sort();
        endpoints.dedup();
        Self {
            status,
            age_seconds,
            endpoints,
            diagnostic: diagnostic.into(),
            revision_token: None,
        }
    }
    pub fn status(&self) -> CranSnapshotCacheStatus {
        self.status
    }
    pub fn age_seconds(&self) -> Option<u64> {
        self.age_seconds
    }
    pub fn endpoints(&self) -> impl Iterator<Item = &str> {
        self.endpoints.iter().map(Box::as_ref)
    }
    pub fn diagnostic(&self) -> &str {
        &self.diagnostic
    }

    pub fn revision_token(&self) -> Option<&str> {
        self.revision_token.as_deref()
    }

    pub fn is_routine_online_fallback(&self) -> bool {
        matches!(self.status, CranSnapshotCacheStatus::Missing)
    }

    pub fn closure_incomplete(error: &rsolve_core::CandidateLoadError) -> Self {
        let status = match error.category() {
            rsolve_core::CandidateLoadErrorCategory::SnapshotInvalid => {
                CranSnapshotCacheStatus::Corrupt
            }
            _ => CranSnapshotCacheStatus::Incomplete,
        };
        Self {
            status,
            age_seconds: None,
            endpoints: Vec::new(),
            diagnostic: format!(
                "cached CRAN generation cannot be used for the requested dependency closure: {error}"
            )
            .into(),
            revision_token: None,
        }
    }
}

pub enum CranSnapshotCacheResult {
    Compatible {
        loader: Box<ReadOnlySnapshotCandidateLoader>,
        diagnostic: CranSnapshotCacheDiagnostic,
    },
    Rejected(CranSnapshotCacheDiagnostic),
}

fn cache_revision_token(
    validation: Option<&crate::snapshot::ViewValidationV1>,
) -> Option<Box<str>> {
    validation.map(crate::snapshot::view_validation_revision_token)
}

/// Inspect the selected immutable view without transport. This is the
/// sole CRAN freshness boundary; resolver traversal remains loader-only.
pub fn inspect_cran_snapshot_cache(
    store: &SnapshotStore,
    policy: &CranSnapshotCachePolicy,
) -> CranSnapshotCacheResult {
    let guard = match store.begin_refresh() {
        Ok(guard) => guard,
        Err(error) => {
            return CranSnapshotCacheResult::Rejected(CranSnapshotCacheDiagnostic {
                status: CranSnapshotCacheStatus::Corrupt,
                age_seconds: None,
                endpoints: Vec::new(),
                diagnostic: format!("unable to acquire snapshot refresh lock: {error}").into(),
                revision_token: None,
            });
        }
    };
    inspect_cran_snapshot_cache_with_refresh_guard(&guard, policy)
}

/// Inspect a snapshot view without waiting for another process's
/// refresh transaction. `None` means the transaction lock was busy; callers
/// must not interpret that as a missing or fresh generation and should
/// re-check after acquiring their own transaction.
pub(crate) fn inspect_cran_snapshot_cache_without_wait(
    store: &SnapshotStore,
    policy: &CranSnapshotCachePolicy,
) -> Option<CranSnapshotCacheResult> {
    let guard = match store.try_begin_refresh() {
        Ok(Some(guard)) => guard,
        Ok(None) => return None,
        Err(error) => {
            return Some(CranSnapshotCacheResult::Rejected(
                CranSnapshotCacheDiagnostic {
                    status: CranSnapshotCacheStatus::Corrupt,
                    age_seconds: None,
                    endpoints: Vec::new(),
                    diagnostic: format!("unable to acquire snapshot refresh lock: {error}").into(),
                    revision_token: None,
                },
            ));
        }
    };
    Some(inspect_cran_snapshot_cache_with_refresh_guard(
        &guard, policy,
    ))
}

pub(crate) fn inspect_cran_snapshot_cache_with_refresh_guard(
    guard: &crate::snapshot::SnapshotRefreshGuard<'_>,
    policy: &CranSnapshotCachePolicy,
) -> CranSnapshotCacheResult {
    let (loader, validation) = if let Some(endpoint) = policy.expected_endpoint.as_deref() {
        match guard.read_view_for_endpoint(endpoint) {
            Ok(Some((loader, validation))) => (Ok(Some(loader)), Some(validation)),
            Ok(None) => (Ok(None), None),
            Err(error) => (Err(error), None),
        }
    } else {
        (
            guard.read_latest_view_optional(),
            guard.read_latest_view_validation().ok().flatten(),
        )
    };
    inspect_cran_snapshot_cache_from_reads(policy, loader, validation)
}

fn inspect_cran_snapshot_cache_from_reads(
    policy: &CranSnapshotCachePolicy,
    loader_result: Result<Option<ReadOnlySnapshotCandidateLoader>, CandidateLoadError>,
    validation: Option<crate::snapshot::ViewValidationV1>,
) -> CranSnapshotCacheResult {
    let loader = match loader_result {
        Ok(Some(loader)) => loader,
        Ok(None) => {
            return CranSnapshotCacheResult::Rejected(CranSnapshotCacheDiagnostic {
                status: CranSnapshotCacheStatus::Missing,
                age_seconds: None,
                endpoints: Vec::new(),
                diagnostic: "CRAN snapshot view head is missing".into(),
                revision_token: None,
            });
        }
        Err(error) => {
            return CranSnapshotCacheResult::Rejected(CranSnapshotCacheDiagnostic {
                status: CranSnapshotCacheStatus::Corrupt,
                age_seconds: None,
                endpoints: Vec::new(),
                diagnostic: error.diagnostic().into(),
                revision_token: None,
            });
        }
    };
    let header = loader.header();
    if header.compatibility_profile != policy.compatibility_profile
        || header.parser_schema != policy.parser_schema
        || header.normalization_policy != policy.normalization_policy
    {
        return CranSnapshotCacheResult::Rejected(CranSnapshotCacheDiagnostic {
            status: CranSnapshotCacheStatus::RevisionIncompatible,
            age_seconds: None,
            endpoints: canonical_endpoints(header),
            diagnostic: format!(
                "CRAN snapshot compatibility revisions are incompatible (profile {}, parser {}, normalization {})",
                header.compatibility_profile, header.parser_schema, header.normalization_policy
            ).into(),
            revision_token: None,
        });
    }
    let header_source_identities = header
        .sources
        .iter()
        .map(|source| (source.id.as_str(), source.content_sha256.as_str()))
        .collect::<Vec<_>>();
    let validation_matches = validation.as_ref().is_some_and(|record| {
        record.registry_id == header.registry_id
            && record.generation == header.generation
            && record.compatibility_profile == header.compatibility_profile
            && record.parser_schema == header.parser_schema
            && record.normalization_policy == header.normalization_policy
            && policy
                .expected_endpoint
                .as_deref()
                .is_none_or(|endpoint| record.effective_endpoint == endpoint)
            && record
                .sources
                .iter()
                .map(|source| (source.id.as_str(), source.content_sha256.as_str()))
                .collect::<Vec<_>>()
                == header_source_identities
    });
    let validation_timestamp = validation
        .clone()
        .filter(|_| validation_matches)
        .and_then(|record| record.validated_at.parse::<jiff::Timestamp>().ok());
    let endpoint_provenance_matches = policy.expected_endpoint.as_deref().is_none_or(|expected| {
        let source_allowed = |endpoint: &str| {
            endpoint_belongs_to(endpoint, expected)
                || policy
                    .allowed_auxiliary_endpoint
                    .as_deref()
                    .is_some_and(|allowed| endpoint == allowed)
        };
        if validation_matches {
            validation.as_ref().is_some_and(|record| {
                record.effective_endpoint == expected
                    && record
                        .sources
                        .iter()
                        .all(|source| source_allowed(&source.endpoint))
            })
        } else {
            header
                .sources
                .iter()
                .all(|source| source_allowed(&source.endpoint))
        }
    });
    let diagnostic_endpoints = validation
        .as_ref()
        .filter(|_| validation_matches)
        .map(canonical_validation_endpoints)
        .unwrap_or_else(|| canonical_endpoints(header));
    let mut oldest_source_age = 0_i64;
    let mut future_source = false;
    for source in &header.sources {
        let observed = match source.observed_at.parse::<jiff::Timestamp>() {
            Ok(observed) => observed,
            Err(error) => {
                return CranSnapshotCacheResult::Rejected(CranSnapshotCacheDiagnostic {
                    status: CranSnapshotCacheStatus::Corrupt,
                    age_seconds: None,
                    endpoints: Vec::new(),
                    diagnostic: format!("invalid source observed_at: {error}").into(),
                    revision_token: None,
                });
            }
        };
        let age = policy.now.duration_since(observed).as_secs();
        future_source |= age < 0;
        oldest_source_age = oldest_source_age.max(age.max(0));
    }
    if let Some(validated_at) = validation_timestamp {
        let age = policy.now.duration_since(validated_at).as_secs();
        future_source |= age < 0;
        oldest_source_age = age.max(0);
    }
    if header.sources.is_empty() {
        return CranSnapshotCacheResult::Rejected(CranSnapshotCacheDiagnostic {
            status: CranSnapshotCacheStatus::Corrupt,
            age_seconds: None,
            endpoints: Vec::new(),
            diagnostic: "CRAN snapshot has no source observations".into(),
            revision_token: None,
        });
    }
    let age_seconds = u64::try_from(oldest_source_age).unwrap_or(u64::MAX);
    let fresh = !policy.refresh_metadata
        && endpoint_provenance_matches
        && !future_source
        && oldest_source_age
            <= i64::try_from(DEFAULT_COMPATIBLE_GENERATION_TTL.as_secs()).unwrap_or(i64::MAX);
    let status = if fresh {
        CranSnapshotCacheStatus::Fresh
    } else {
        CranSnapshotCacheStatus::Stale
    };
    let diagnostic = CranSnapshotCacheDiagnostic {
        status,
        age_seconds: Some(age_seconds),
        endpoints: diagnostic_endpoints,
        diagnostic: if fresh {
            "compatible CRAN snapshot generation is within the fallback freshness TTL".into()
        } else if !endpoint_provenance_matches {
            "CRAN snapshot evidence belongs to a different acquisition endpoint; it is not fresh for online reuse".into()
        } else if future_source {
            "CRAN snapshot source timestamp is in the future; generation is not fresh for online reuse".into()
        } else {
            "compatible CRAN snapshot generation is stale but remains usable offline".into()
        },
        revision_token: cache_revision_token(validation.as_ref()),
    };
    CranSnapshotCacheResult::Compatible {
        loader: Box::new(loader),
        diagnostic,
    }
}

fn endpoint_belongs_to(endpoint: &str, base: &str) -> bool {
    if endpoint == base {
        return true;
    }
    if base.ends_with('/') {
        // The configured endpoint already supplies the separator. Preserve
        // every trailing slash in its identity, then accept a non-empty
        // provider-relative suffix without requiring another slash.
        endpoint
            .strip_prefix(base)
            .is_some_and(|suffix| !suffix.is_empty())
    } else {
        endpoint
            .strip_prefix(base)
            .is_some_and(|suffix| suffix.starts_with('/'))
    }
}

fn canonical_endpoints(header: &crate::snapshot::SnapshotHeaderV1) -> Vec<Box<str>> {
    let mut endpoints = header
        .sources
        .iter()
        .map(|source| source.endpoint.clone())
        .collect::<Vec<_>>();
    endpoints.sort();
    endpoints.dedup();
    endpoints.into_iter().map(String::into_boxed_str).collect()
}

fn canonical_validation_endpoints(record: &crate::snapshot::ViewValidationV1) -> Vec<Box<str>> {
    let mut endpoints = record
        .sources
        .iter()
        .flat_map(|source| source.endpoint.split('\n'))
        .chain(record.effective_endpoint.split('\n'))
        .filter(|endpoint| !endpoint.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    endpoints.sort();
    endpoints.dedup();
    endpoints.into_iter().map(String::into_boxed_str).collect()
}

#[cfg(test)]
mod tests {
    use super::CranSnapshotCachePolicy;
    use super::endpoint_belongs_to;

    #[test]
    fn endpoint_provenance_accepts_children_of_slash_terminated_bases() {
        for base in ["https://cran.invalid/cran/", "https://cran.invalid/cran///"] {
            let child = format!("{base}src/contrib/PACKAGES.rds");
            assert!(endpoint_belongs_to(&child, base));
            assert!(!endpoint_belongs_to("https://cran.invalid/cran", base));
        }
        assert!(endpoint_belongs_to(
            "https://cran.invalid/cran/src/contrib/PACKAGES.rds",
            "https://cran.invalid/cran"
        ));
        assert!(!endpoint_belongs_to(
            "https://cran.invalid/crane/src/contrib/PACKAGES.rds",
            "https://cran.invalid/cran"
        ));
    }

    #[test]
    fn cache_policy_keeps_distinct_endpoint_spellings() {
        let timestamp = "2026-08-29T00:00:00Z".parse().unwrap();
        let one = CranSnapshotCachePolicy::at(timestamp)
            .with_expected_endpoint("https://cran.invalid/cran/");
        let many = CranSnapshotCachePolicy::at(timestamp)
            .with_expected_endpoint("https://cran.invalid/cran///");
        assert_ne!(one.expected_endpoint, many.expected_endpoint);
    }
}
