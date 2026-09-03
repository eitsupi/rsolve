use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::io::Read;

use rsolve_core::{
    Artifact, CandidateCurrentness, DependencyKind, Distribution, PackageName, PackageRelease,
    Provenance, RegistryId, Sha256Digest,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use url::Url;

use super::{RUniverseCatalog, RUniverseCatalogError};
use crate::snapshot::{
    ArtifactV1, CandidateCurrentnessV1, ChecksumV1, ClauseV1, CoverageV1, DependencyKindV1,
    DependencyV1, DistributionV1, EligibleReleaseV1, GitProvenanceV1, LookupStateV1,
    PackageHistoryV1, ReadOnlySnapshotCandidateLoader, SnapshotBuildInput, SnapshotStore,
    SourceInput,
};
use crate::{RawCandidateLoadResult, RawCandidateObservation};

/// Local interpretation revision for the R-universe API response profile.
pub const RUNIVERSE_NORMALIZATION_POLICY: u32 = 2;

const MAX_RESPONSE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
enum CoverageScope {
    All,
    Packages(Vec<PackageName>),
}

impl CoverageScope {
    fn from_allowlist(allowlist: Option<&[PackageName]>) -> Result<Self, RUniverseProviderError> {
        Ok(match canonical_allowlist(allowlist)? {
            Some(packages) => Self::Packages(packages),
            None => Self::All,
        })
    }

    fn encode(&self) -> String {
        match self {
            Self::All => "api-catalog".to_owned(),
            Self::Packages(packages) => format!(
                "api-catalog:packages={}",
                packages
                    .iter()
                    .map(PackageName::as_str)
                    .collect::<Vec<_>>()
                    .join(",")
            ),
        }
    }

    fn parse(value: &str) -> Result<Self, String> {
        if value == "api-catalog" {
            return Ok(Self::All);
        }
        let encoded = value
            .strip_prefix("api-catalog:packages=")
            .ok_or_else(|| "unknown coverage scope encoding".to_owned())?;
        if encoded.is_empty() {
            return Err("package coverage scope is empty".to_owned());
        }
        let mut packages = encoded
            .split(',')
            .map(|package| PackageName::new(package).map_err(|error| error.to_string()))
            .collect::<Result<Vec<_>, _>>()?;
        let canonical = {
            packages.sort();
            if packages.windows(2).any(|pair| pair[0] == pair[1]) {
                return Err("package coverage scope contains duplicates".to_owned());
            }
            format!(
                "api-catalog:packages={}",
                packages
                    .iter()
                    .map(PackageName::as_str)
                    .collect::<Vec<_>>()
                    .join(",")
            )
        };
        if canonical != value {
            return Err("package coverage scope is not canonical".to_owned());
        }
        Ok(Self::Packages(packages))
    }

    fn covers(&self, requested: &Self) -> bool {
        match (self, requested) {
            (Self::All, _) => true,
            (Self::Packages(_), Self::All) => false,
            (Self::Packages(available), Self::Packages(requested)) => requested
                .iter()
                .all(|package| available.binary_search(package).is_ok()),
        }
    }

    fn extra_package_count(&self, requested: &Self) -> usize {
        match (self, requested) {
            (Self::All, Self::All) => 0,
            (Self::All, Self::Packages(_)) => usize::MAX,
            (Self::Packages(_), Self::All) => usize::MAX,
            (Self::Packages(available), Self::Packages(requested)) => {
                available.len().saturating_sub(requested.len())
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OpenMode {
    Online,
    Offline,
}

/// A transport-neutral HTTP response used by the R-universe provider.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RUniverseResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

/// Transport errors are kept separate from response/profile failures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RUniverseTransportError(pub String);

impl fmt::Display for RUniverseTransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for RUniverseTransportError {}

/// Minimal HTTP GET port for hermetic provider tests and alternate clients.
pub trait RUniverseTransport {
    fn get(&self, url: &str) -> Result<RUniverseResponse, RUniverseTransportError>;
}

/// The production HTTPS transport for R-universe API requests.
pub struct UreqRUniverseTransport {
    agent: ureq::Agent,
}

impl UreqRUniverseTransport {
    pub fn new() -> Self {
        let tls_config = ureq::tls::TlsConfig::builder()
            .root_certs(ureq::tls::RootCerts::PlatformVerifier)
            .build();
        let agent_config = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .tls_config(tls_config)
            .build();
        Self {
            agent: agent_config.new_agent(),
        }
    }
}

impl Default for UreqRUniverseTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl RUniverseTransport for UreqRUniverseTransport {
    fn get(&self, url: &str) -> Result<RUniverseResponse, RUniverseTransportError> {
        let response = self
            .agent
            .get(url)
            .call()
            .map_err(|error| RUniverseTransportError(format!("request failed: {error}")))?;
        let status = response.status().as_u16();
        let mut body = response.into_body();
        let mut bytes = Vec::new();
        body.as_reader()
            .take((MAX_RESPONSE_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|error| {
                RUniverseTransportError(format!("failed to read response: {error}"))
            })?;
        Ok(RUniverseResponse {
            status,
            body: bytes,
        })
    }
}

/// Typed failures at the R-universe acquisition and snapshot boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RUniverseProviderError {
    InvalidEndpoint(String),
    InvalidAllowlist(String),
    Transport {
        endpoint: String,
        source: RUniverseTransportError,
    },
    HttpStatus {
        endpoint: String,
        status: u16,
    },
    PackageNotFound {
        endpoint: String,
        package: String,
    },
    ResponseTooLarge {
        endpoint: String,
    },
    InvalidResponse {
        endpoint: String,
        source: RUniverseCatalogError,
    },
    InvalidList {
        endpoint: String,
        reason: String,
    },
    PackageMismatch {
        endpoint: String,
        expected: String,
        found: String,
    },
    DuplicatePackage {
        endpoint: String,
        package: String,
    },
    CoverageMismatch {
        endpoint: String,
        expected: Vec<String>,
        found: Vec<String>,
    },
    Snapshot(String),
    OfflineMissing(String),
    OfflineIncompatible(String),
    OfflineCorrupt(String),
}

impl fmt::Display for RUniverseProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEndpoint(reason) => write!(f, "invalid R-universe endpoint: {reason}"),
            Self::InvalidAllowlist(reason) => {
                write!(f, "invalid R-universe package allowlist: {reason}")
            }
            Self::Transport { endpoint, source } => {
                write!(f, "R-universe request failed for {endpoint}: {source}")
            }
            Self::HttpStatus { endpoint, status } => {
                write!(f, "R-universe endpoint {endpoint} returned HTTP {status}")
            }
            Self::PackageNotFound { endpoint, package } => {
                write!(
                    f,
                    "R-universe package {package} was not found at {endpoint}"
                )
            }
            Self::ResponseTooLarge { endpoint } => write!(
                f,
                "R-universe response from {endpoint} exceeds the size limit"
            ),
            Self::InvalidResponse { endpoint, source } => {
                write!(f, "invalid R-universe response from {endpoint}: {source}")
            }
            Self::InvalidList { endpoint, reason } => write!(
                f,
                "invalid R-universe package list from {endpoint}: {reason}"
            ),
            Self::PackageMismatch {
                endpoint,
                expected,
                found,
            } => write!(
                f,
                "R-universe response {endpoint} returned package {found}, expected {expected}"
            ),
            Self::DuplicatePackage { endpoint, package } => write!(
                f,
                "R-universe response {endpoint} contains duplicate package {package}"
            ),
            Self::CoverageMismatch {
                endpoint,
                expected,
                found,
            } => write!(
                f,
                "R-universe response {endpoint} package coverage mismatch (expected {expected:?}, found {found:?})"
            ),
            Self::Snapshot(reason) => write!(f, "R-universe snapshot publication failed: {reason}"),
            Self::OfflineMissing(reason) => {
                write!(f, "R-universe compatible snapshot is unavailable: {reason}")
            }
            Self::OfflineIncompatible(reason) => {
                write!(f, "R-universe snapshot is incompatible: {reason}")
            }
            Self::OfflineCorrupt(reason) => {
                write!(f, "R-universe snapshot candidate is corrupt: {reason}")
            }
        }
    }
}

impl Error for RUniverseProviderError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Transport { source, .. } => Some(source),
            Self::InvalidResponse { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// R-universe API client bound to an explicit effective endpoint and registry.
pub struct RUniverseProvider<T> {
    endpoint: Box<str>,
    registry_id: RegistryId,
    transport: T,
}

impl<T: RUniverseTransport> RUniverseProvider<T> {
    pub fn new(
        endpoint: impl AsRef<str>,
        registry_id: RegistryId,
        transport: T,
    ) -> Result<Self, RUniverseProviderError> {
        let endpoint = validate_endpoint(endpoint.as_ref())?;
        Ok(Self {
            endpoint: endpoint.into_boxed_str(),
            registry_id,
            transport,
        })
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub fn registry_id(&self) -> &RegistryId {
        &self.registry_id
    }

    /// Acquire and validate the current catalog without publishing a snapshot.
    pub fn refresh(
        &self,
        allowlist: Option<&[PackageName]>,
    ) -> Result<RUniverseCatalog, RUniverseProviderError> {
        self.fetch(allowlist).map(|(catalog, _)| catalog)
    }

    /// Acquire current candidate observations with an explicit currentness
    /// fact attached to every release.
    pub fn refresh_observations(
        &self,
        allowlist: Option<&[PackageName]>,
    ) -> Result<RawCandidateLoadResult, RUniverseProviderError> {
        let catalog = self.refresh(allowlist)?;
        Ok(RawCandidateLoadResult::new(
            catalog
                .releases()
                .iter()
                .cloned()
                .map(|release| RawCandidateObservation::new(release, CandidateCurrentness::Current))
                .collect(),
            Vec::new(),
        ))
    }

    /// Acquire a catalog and atomically publish it as an immutable generation.
    pub fn refresh_snapshot(
        &self,
        store: &SnapshotStore,
        allowlist: Option<&[PackageName]>,
    ) -> Result<ReadOnlySnapshotCandidateLoader, RUniverseProviderError> {
        let (catalog, responses) = self.fetch(allowlist)?;
        let scope = coverage_scope(allowlist)?;
        let input = snapshot_input(&self.registry_id, &catalog, &responses, scope)?;
        store
            .build_and_publish_with_endpoint(input, self.endpoint.as_ref())
            .map_err(|error| RUniverseProviderError::Snapshot(error.to_string()))
    }

    /// Open the newest compatible current view for this endpoint, allowing a
    /// complete coverage superset. This method never falls back to network
    /// acquisition.
    pub fn open_compatible(
        &self,
        store: &SnapshotStore,
        allowlist: Option<&[PackageName]>,
    ) -> Result<ReadOnlySnapshotCandidateLoader, RUniverseProviderError> {
        self.open_compatible_with_mode(store, allowlist, OpenMode::Online)
    }

    /// Open a compatible local view for an offline operation. Unlike the
    /// online warm-open path, a view validated for another endpoint may be
    /// reused when its registry and coverage are compatible. The returned
    /// loader retains the candidate's validation endpoint; the requested
    /// endpoint is never reported as validated by this operation.
    pub fn open_compatible_offline(
        &self,
        store: &SnapshotStore,
        allowlist: Option<&[PackageName]>,
    ) -> Result<ReadOnlySnapshotCandidateLoader, RUniverseProviderError> {
        self.open_compatible_with_mode(store, allowlist, OpenMode::Offline)
    }

    fn open_compatible_with_mode(
        &self,
        store: &SnapshotStore,
        allowlist: Option<&[PackageName]>,
        mode: OpenMode,
    ) -> Result<ReadOnlySnapshotCandidateLoader, RUniverseProviderError> {
        let expected_scope = CoverageScope::from_allowlist(allowlist)?;
        let mut candidates = store
            .read_view_candidates()
            .map_err(|error| RUniverseProviderError::OfflineCorrupt(error.to_string()))?;
        let mut corrupt = candidates.invalid_candidates;
        let mut compatible = Vec::new();
        for candidate in candidates.candidates.drain(..) {
            let candidate_scope = match CoverageScope::parse(&candidate.scope) {
                Ok(scope) => scope,
                Err(_) => {
                    corrupt = true;
                    continue;
                }
            };
            let header = candidate.loader.header();
            if header.compatibility_profile != super::RUNIVERSE_COMPATIBILITY_PROFILE
                || header.parser_schema != super::RUNIVERSE_PARSER_SCHEMA
                || header.normalization_policy != RUNIVERSE_NORMALIZATION_POLICY
                || candidate.validation.registry_id != self.registry_id.as_str()
                || candidate.validation.generation != header.generation
                || candidate.validation.compatibility_profile != header.compatibility_profile
                || candidate.validation.parser_schema != header.parser_schema
                || candidate.validation.normalization_policy != header.normalization_policy
                || candidate.state != "complete"
                || candidate.freshness != "current"
                || (mode == OpenMode::Online
                    && candidate.validation.effective_endpoint != self.endpoint.as_ref())
                || !candidate_scope.covers(&expected_scope)
            {
                continue;
            }
            compatible.push((candidate, candidate_scope));
        }
        compatible.sort_by(|left, right| {
            let left_extra = left.1.extra_package_count(&expected_scope);
            let right_extra = right.1.extra_package_count(&expected_scope);
            right
                .0
                .validation
                .refresh_sequence
                .cmp(&left.0.validation.refresh_sequence)
                .then_with(|| left_extra.cmp(&right_extra))
                .then_with(|| {
                    left.0
                        .validation
                        .effective_endpoint
                        .cmp(&right.0.validation.effective_endpoint)
                })
                .then_with(|| {
                    left.0
                        .loader
                        .header()
                        .generation
                        .cmp(&right.0.loader.header().generation)
                })
        });
        if let Some((candidate, _)) = compatible.into_iter().next() {
            return Ok(candidate.loader);
        }
        if corrupt {
            return Err(RUniverseProviderError::OfflineCorrupt(
                "no usable snapshot candidate remains after validation".into(),
            ));
        }
        if !candidates.had_heads {
            return Err(RUniverseProviderError::OfflineMissing(
                "snapshot view head is missing".into(),
            ));
        }
        Err(RUniverseProviderError::OfflineIncompatible(
            "no compatible snapshot view head exists for the provider request".into(),
        ))
    }

    fn fetch(
        &self,
        allowlist: Option<&[PackageName]>,
    ) -> Result<(RUniverseCatalog, Vec<FetchedResponse>), RUniverseProviderError> {
        let packages = canonical_allowlist(allowlist)?;
        if let Some(packages) = packages {
            let mut releases = Vec::new();
            let mut responses = Vec::with_capacity(packages.len());
            for package in packages {
                let endpoint = self.package_endpoint(&package)?;
                let body = match self.get(&endpoint) {
                    Err(RUniverseProviderError::HttpStatus { status: 404, .. }) => {
                        return Err(RUniverseProviderError::PackageNotFound {
                            endpoint,
                            package: package.to_string(),
                        });
                    }
                    result => result,
                }?;
                validate_single_package_response(&endpoint, &body, &package)?;
                let text = std::str::from_utf8(&body).map_err(|error| {
                    RUniverseProviderError::InvalidList {
                        endpoint: endpoint.clone(),
                        reason: error.to_string(),
                    }
                })?;
                let catalog = RUniverseCatalog::from_json(text, self.registry_id.clone()).map_err(
                    |source| RUniverseProviderError::InvalidResponse {
                        endpoint: endpoint.clone(),
                        source,
                    },
                )?;
                releases.extend(catalog.releases().iter().cloned());
                responses.push(FetchedResponse { endpoint, body });
            }
            let mut releases = RUniverseCatalog { releases }.releases;
            releases.sort_by(|left, right| {
                left.identity()
                    .name()
                    .cmp(right.identity().name())
                    .then_with(|| left.version().cmp(right.version()))
            });
            return Ok((RUniverseCatalog { releases }, responses));
        }

        let list_endpoint = self.list_endpoint()?;
        let list_body = self.get(&list_endpoint)?;
        let expected = parse_package_list(&list_endpoint, &list_body)?;
        let bulk_endpoint = self.bulk_endpoint(expected.len())?;
        let bulk_body = self.get(&bulk_endpoint)?;
        validate_bulk_coverage(&bulk_endpoint, &bulk_body, &expected)?;
        let text = std::str::from_utf8(&bulk_body).map_err(|error| {
            RUniverseProviderError::InvalidList {
                endpoint: bulk_endpoint.clone(),
                reason: error.to_string(),
            }
        })?;
        let catalog =
            RUniverseCatalog::from_json(text, self.registry_id.clone()).map_err(|source| {
                RUniverseProviderError::InvalidResponse {
                    endpoint: bulk_endpoint.clone(),
                    source,
                }
            })?;
        let found = catalog
            .releases()
            .iter()
            .map(|release| release.identity().name().to_string())
            .collect::<BTreeSet<_>>();
        let expected_set = expected.iter().cloned().collect::<BTreeSet<_>>();
        if found != expected_set {
            return Err(RUniverseProviderError::CoverageMismatch {
                endpoint: bulk_endpoint.clone(),
                expected,
                found: found.into_iter().collect(),
            });
        }
        Ok((
            catalog,
            vec![
                FetchedResponse {
                    endpoint: list_endpoint,
                    body: list_body,
                },
                FetchedResponse {
                    endpoint: bulk_endpoint,
                    body: bulk_body,
                },
            ],
        ))
    }

    fn get(&self, endpoint: &str) -> Result<Vec<u8>, RUniverseProviderError> {
        let response =
            self.transport
                .get(endpoint)
                .map_err(|source| RUniverseProviderError::Transport {
                    endpoint: endpoint.to_owned(),
                    source,
                })?;
        if response.body.len() > MAX_RESPONSE_BYTES {
            return Err(RUniverseProviderError::ResponseTooLarge {
                endpoint: endpoint.to_owned(),
            });
        }
        if response.status != 200 {
            return Err(RUniverseProviderError::HttpStatus {
                endpoint: endpoint.to_owned(),
                status: response.status,
            });
        }
        Ok(response.body)
    }

    fn list_endpoint(&self) -> Result<String, RUniverseProviderError> {
        self.resource_endpoint("api/ls")
    }

    fn bulk_endpoint(&self, limit: usize) -> Result<String, RUniverseProviderError> {
        self.resource_endpoint(&format!("api/packages?limit={limit}"))
    }

    fn package_endpoint(&self, package: &PackageName) -> Result<String, RUniverseProviderError> {
        self.resource_endpoint(&format!("api/packages/{package}"))
    }

    fn resource_endpoint(&self, relative: &str) -> Result<String, RUniverseProviderError> {
        let mut url = Url::parse(&self.endpoint)
            .map_err(|error| RUniverseProviderError::InvalidEndpoint(error.to_string()))?;
        let (path, query) = relative.split_once('?').unwrap_or((relative, ""));
        {
            let mut segments = url.path_segments_mut().map_err(|_| {
                RUniverseProviderError::InvalidEndpoint(
                    "base endpoint cannot be used for relative resources".into(),
                )
            })?;
            segments.pop_if_empty();
            for segment in path.trim_start_matches('/').split('/') {
                if !segment.is_empty() {
                    segments.push(segment);
                }
            }
        }
        url.set_query((!query.is_empty()).then_some(query));
        Ok(url.to_string())
    }
}

#[derive(Clone)]
struct FetchedResponse {
    endpoint: String,
    body: Vec<u8>,
}

fn validate_endpoint(value: &str) -> Result<String, RUniverseProviderError> {
    let url = Url::parse(value)
        .map_err(|error| RUniverseProviderError::InvalidEndpoint(error.to_string()))?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(RUniverseProviderError::InvalidEndpoint(
            "an absolute HTTP(S) URL with a host is required".into(),
        ));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(RUniverseProviderError::InvalidEndpoint(
            "userinfo credentials are not allowed on the base endpoint".into(),
        ));
    }
    if url.port() == Some(0) {
        return Err(RUniverseProviderError::InvalidEndpoint(
            "port 0 is not a valid base endpoint port".into(),
        ));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(RUniverseProviderError::InvalidEndpoint(
            "query and fragment are not allowed on the base endpoint".into(),
        ));
    }
    Ok(url.to_string().trim_end_matches('/').to_owned())
}

fn canonical_allowlist(
    allowlist: Option<&[PackageName]>,
) -> Result<Option<Vec<PackageName>>, RUniverseProviderError> {
    let Some(allowlist) = allowlist else {
        return Ok(None);
    };
    if allowlist.is_empty() {
        return Err(RUniverseProviderError::InvalidAllowlist(
            "the declared package set must not be empty".into(),
        ));
    }
    let mut packages = allowlist.to_vec();
    packages.sort();
    if packages.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(RUniverseProviderError::InvalidAllowlist(
            "duplicate package names are not allowed".into(),
        ));
    }
    Ok(Some(packages))
}

fn parse_package_list(endpoint: &str, body: &[u8]) -> Result<Vec<String>, RUniverseProviderError> {
    let value: Value =
        serde_json::from_slice(body).map_err(|error| RUniverseProviderError::InvalidList {
            endpoint: endpoint.to_owned(),
            reason: error.to_string(),
        })?;
    let entries = value
        .as_array()
        .ok_or_else(|| RUniverseProviderError::InvalidList {
            endpoint: endpoint.to_owned(),
            reason: "expected an array of package names".into(),
        })?;
    let mut result = Vec::with_capacity(entries.len());
    for entry in entries {
        let value = entry
            .as_str()
            .ok_or_else(|| RUniverseProviderError::InvalidList {
                endpoint: endpoint.to_owned(),
                reason: "package list entries must be strings".into(),
            })?;
        let package =
            PackageName::new(value).map_err(|error| RUniverseProviderError::InvalidList {
                endpoint: endpoint.to_owned(),
                reason: error.to_string(),
            })?;
        result.push(package.to_string());
    }
    result.sort();
    if let Some(pair) = result.windows(2).find(|pair| pair[0] == pair[1]) {
        return Err(RUniverseProviderError::DuplicatePackage {
            endpoint: endpoint.to_owned(),
            package: pair[0].clone(),
        });
    }
    Ok(result)
}

fn validate_single_package_response(
    endpoint: &str,
    body: &[u8],
    expected: &PackageName,
) -> Result<(), RUniverseProviderError> {
    let value: Value =
        serde_json::from_slice(body).map_err(|error| RUniverseProviderError::InvalidList {
            endpoint: endpoint.to_owned(),
            reason: error.to_string(),
        })?;
    let object = value
        .as_object()
        .ok_or_else(|| RUniverseProviderError::InvalidList {
            endpoint: endpoint.to_owned(),
            reason: "individual package response must be an object".into(),
        })?;
    let found = object
        .get("Package")
        .and_then(Value::as_str)
        .ok_or_else(|| RUniverseProviderError::InvalidList {
            endpoint: endpoint.to_owned(),
            reason: "individual package response is missing Package".into(),
        })?;
    if found != expected.as_str() {
        return Err(RUniverseProviderError::PackageMismatch {
            endpoint: endpoint.to_owned(),
            expected: expected.to_string(),
            found: found.to_owned(),
        });
    }
    Ok(())
}

fn validate_bulk_coverage(
    endpoint: &str,
    body: &[u8],
    expected: &[String],
) -> Result<(), RUniverseProviderError> {
    let value: Value =
        serde_json::from_slice(body).map_err(|error| RUniverseProviderError::InvalidList {
            endpoint: endpoint.to_owned(),
            reason: error.to_string(),
        })?;
    let entries = value
        .as_array()
        .ok_or_else(|| RUniverseProviderError::InvalidList {
            endpoint: endpoint.to_owned(),
            reason: "bulk package response must be an array".into(),
        })?;
    let mut found = Vec::with_capacity(entries.len());
    for entry in entries {
        let object = entry
            .as_object()
            .ok_or_else(|| RUniverseProviderError::InvalidList {
                endpoint: endpoint.to_owned(),
                reason: "bulk package entries must be objects".into(),
            })?;
        let package = object
            .get("Package")
            .and_then(Value::as_str)
            .ok_or_else(|| RUniverseProviderError::InvalidList {
                endpoint: endpoint.to_owned(),
                reason: "bulk package entry is missing Package".into(),
            })?;
        found.push(package.to_owned());
    }
    found.sort();
    if let Some(pair) = found.windows(2).find(|pair| pair[0] == pair[1]) {
        return Err(RUniverseProviderError::DuplicatePackage {
            endpoint: endpoint.to_owned(),
            package: pair[0].clone(),
        });
    }
    if found != expected {
        return Err(RUniverseProviderError::CoverageMismatch {
            endpoint: endpoint.to_owned(),
            expected: expected.to_vec(),
            found,
        });
    }
    Ok(())
}

fn snapshot_input(
    registry_id: &RegistryId,
    catalog: &RUniverseCatalog,
    responses: &[FetchedResponse],
    coverage_scope: String,
) -> Result<SnapshotBuildInput, RUniverseProviderError> {
    let mut sources = Vec::with_capacity(responses.len());
    let now = jiff::Timestamp::now()
        .strftime("%Y-%m-%dT%H:%M:%SZ")
        .to_string();
    for response in responses {
        sources.push(SourceInput {
            kind: "r-universe-api".into(),
            representation: response.endpoint.clone(),
            content_sha256: Sha256::digest(&response.body).into(),
            etag: None,
            last_modified: None,
            observed_at: now.clone(),
            endpoint: response.endpoint.clone(),
        });
    }
    let source_ids = sources
        .iter()
        .map(|source| {
            crate::snapshot::source_observation(source)
                .map(|observation| observation.id)
                .map_err(|error| RUniverseProviderError::Snapshot(error.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut grouped = BTreeMap::<PackageName, Vec<&PackageRelease>>::new();
    for release in catalog.releases() {
        grouped
            .entry(release.identity().name().clone())
            .or_default()
            .push(release);
    }
    let histories = grouped
        .into_iter()
        .map(|(package, releases)| {
            let mut eligible_releases = releases
                .into_iter()
                .map(to_wire_release)
                .collect::<Result<Vec<_>, _>>()?;
            eligible_releases.sort_by(|left, right| left.version.cmp(&right.version));
            Ok(PackageHistoryV1 {
                package: package.to_string(),
                state: LookupStateV1::Present,
                observations: Vec::new(),
                decisions: Vec::new(),
                eligible_releases,
            })
        })
        .collect::<Result<Vec<_>, RUniverseProviderError>>()?;
    Ok(SnapshotBuildInput {
        registry_id: registry_id.clone(),
        compatibility_profile: super::RUNIVERSE_COMPATIBILITY_PROFILE,
        parser_schema: super::RUNIVERSE_PARSER_SCHEMA,
        normalization_policy: RUNIVERSE_NORMALIZATION_POLICY,
        created_at: now,
        producer: "rsolve-provider/r-universe".into(),
        coverage: CoverageV1 {
            state: "complete".into(),
            scope: coverage_scope,
            freshness: "current".into(),
            source_ids,
            missing_evidence: Vec::new(),
        },
        sources,
        histories,
    })
}

fn coverage_scope(allowlist: Option<&[PackageName]>) -> Result<String, RUniverseProviderError> {
    Ok(CoverageScope::from_allowlist(allowlist)?.encode())
}

fn to_wire_release(release: &PackageRelease) -> Result<EligibleReleaseV1, RUniverseProviderError> {
    let provenance = match release.identity().provenance() {
        Provenance::GitCommit {
            repository,
            commit,
            subdirectory,
        } => Some(GitProvenanceV1 {
            repository: repository.to_string(),
            commit: commit.to_string(),
            subdirectory: subdirectory.as_ref().map(ToString::to_string),
        }),
        _ => {
            return Err(RUniverseProviderError::Snapshot(
                "R-universe release does not have Git provenance".into(),
            ));
        }
    };
    let dependencies = release
        .declared_dependencies()
        .iter()
        .map(|dependency| DependencyV1 {
            kind: match dependency.kind {
                DependencyKind::Depends => DependencyKindV1::Depends,
                DependencyKind::Imports => DependencyKindV1::Imports,
                DependencyKind::LinkingTo => DependencyKindV1::LinkingTo,
                DependencyKind::Suggests => DependencyKindV1::Suggests,
                DependencyKind::Enhances => DependencyKindV1::Enhances,
            },
            package: dependency.package.name().to_string(),
            clauses: dependency
                .package
                .constraint()
                .clauses
                .iter()
                .map(|clause| ClauseV1 {
                    op: match clause.op {
                        rsolve_core::RelationOp::Lt => crate::snapshot::RelationOpV1::Lt,
                        rsolve_core::RelationOp::Le => crate::snapshot::RelationOpV1::Le,
                        rsolve_core::RelationOp::Eq => crate::snapshot::RelationOpV1::Eq,
                        rsolve_core::RelationOp::Ne => crate::snapshot::RelationOpV1::Ne,
                        rsolve_core::RelationOp::Ge => crate::snapshot::RelationOpV1::Ge,
                        rsolve_core::RelationOp::Gt => crate::snapshot::RelationOpV1::Gt,
                    },
                    version: clause.version.to_string(),
                })
                .collect(),
        })
        .collect();
    let distributions = release
        .distributions()
        .iter()
        .map(to_wire_distribution)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(EligibleReleaseV1 {
        package: release.identity().name().to_string(),
        version: release.version().to_string(),
        namespace: "r-universe".into(),
        git_provenance: provenance,
        currentness: CandidateCurrentnessV1::Current,
        metadata: release
            .metadata()
            .fields()
            .iter()
            .map(|(name, value)| crate::snapshot::FieldV1 {
                name: name.clone(),
                value: value.clone(),
            })
            .collect(),
        publication: release
            .publication()
            .map(|publication| publication.date().to_string()),
        dependencies,
        distributions,
        metadata_sha256: parse_digest(release.metadata_digest())?,
        evidence: Vec::new(),
    })
}

fn to_wire_distribution(
    distribution: &Distribution,
) -> Result<DistributionV1, RUniverseProviderError> {
    let artifacts = distribution
        .artifacts
        .iter()
        .map(|artifact| match artifact {
            Artifact::Source(source) => ArtifactV1 {
                locator: source.locator.to_string(),
                upstream_checksums: source
                    .upstream_checksums
                    .iter()
                    .map(|checksum| match checksum {
                        rsolve_core::UpstreamChecksum::Md5(value) => ChecksumV1 {
                            algorithm: "md5".into(),
                            value: value.to_string(),
                        },
                        rsolve_core::UpstreamChecksum::Sha256(value) => ChecksumV1 {
                            algorithm: "sha256".into(),
                            value: value.to_string(),
                        },
                        rsolve_core::UpstreamChecksum::Other { algorithm, value } => ChecksumV1 {
                            algorithm: algorithm.to_string(),
                            value: value.to_string(),
                        },
                    })
                    .collect(),
                size: source.size,
            },
        })
        .collect();
    Ok(DistributionV1 {
        registry: distribution.registry.to_string(),
        channel: distribution.channel.to_string(),
        snapshot: distribution.snapshot.as_ref().map(ToString::to_string),
        artifacts,
        metadata: distribution
            .observed_metadata
            .fields
            .iter()
            .map(|(name, value)| crate::snapshot::FieldV1 {
                name: name.clone(),
                value: value.clone(),
            })
            .collect(),
    })
}

fn parse_digest(digest: &Sha256Digest) -> Result<[u8; 32], RUniverseProviderError> {
    let value = digest.as_str();
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(RUniverseProviderError::Snapshot(
            "release metadata digest is not a SHA-256 value".into(),
        ));
    }
    let mut output = [0_u8; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).map_err(|_| {
            RUniverseProviderError::Snapshot("release metadata digest is invalid".into())
        })?;
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    #[derive(Clone)]
    struct FixtureTransport {
        responses: Rc<RefCell<BTreeMap<String, RUniverseResponse>>>,
        requests: Rc<RefCell<Vec<String>>>,
    }

    impl RUniverseTransport for FixtureTransport {
        fn get(&self, url: &str) -> Result<RUniverseResponse, RUniverseTransportError> {
            self.requests.borrow_mut().push(url.to_owned());
            self.responses
                .borrow()
                .get(url)
                .cloned()
                .ok_or_else(|| RUniverseTransportError(format!("missing fixture {url}")))
        }
    }

    const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
    const ARTIFACT_SHA256: &str =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn package_entry(package: &str) -> String {
        package_entry_with_commit(package, COMMIT)
    }

    fn package_entry_with_repository(package: &str, repository: &str) -> String {
        package_entry(package).replace(
            "\"_dependencies\":[]}",
            &format!("\"_dependencies\":[],\"Repository\":\"{repository}\"}}"),
        )
    }

    fn package_entry_with_commit(package: &str, commit: &str) -> String {
        format!(
            r#"{{"Package":"{package}","Version":"1.0.0","RemoteUrl":"https://github.com/example/{package}.git","RemoteSha":"{commit}","_type":"src","_status":"success","_file":"{package}_1.0.0.tar.gz","_fileid":"https://downloads.example.test/{package}_1.0.0.tar.gz","_sha256":"{ARTIFACT_SHA256}","_filesize":123,"_dependencies":[]}}"#
        )
    }

    fn fixture_provider(
        base: &str,
        responses: &[(&str, String)],
    ) -> (
        RUniverseProvider<FixtureTransport>,
        Rc<RefCell<Vec<String>>>,
    ) {
        let responses = responses
            .iter()
            .map(|(url, body)| (*url, 200, body.clone()))
            .collect::<Vec<_>>();
        fixture_provider_with_statuses(base, &responses)
    }

    fn fixture_provider_with_statuses(
        base: &str,
        responses: &[(&str, u16, String)],
    ) -> (
        RUniverseProvider<FixtureTransport>,
        Rc<RefCell<Vec<String>>>,
    ) {
        let map = responses
            .iter()
            .map(|(url, status, body)| {
                (
                    (*url).to_owned(),
                    RUniverseResponse {
                        status: *status,
                        body: body.as_bytes().to_vec(),
                    },
                )
            })
            .collect();
        let requests = Rc::new(RefCell::new(Vec::new()));
        let transport = FixtureTransport {
            responses: Rc::new(RefCell::new(map)),
            requests: Rc::clone(&requests),
        };
        let provider =
            RUniverseProvider::new(base, RegistryId::new("universe").unwrap(), transport).unwrap();
        (provider, requests)
    }

    #[test]
    fn coverage_scope_is_strictly_canonical_and_provider_specific() {
        assert_eq!(
            CoverageScope::parse("api-catalog").unwrap(),
            CoverageScope::All
        );
        let packages = CoverageScope::parse("api-catalog:packages=bar,foo").unwrap();
        assert_eq!(
            packages,
            CoverageScope::Packages(vec![
                PackageName::new("bar").unwrap(),
                PackageName::new("foo").unwrap(),
            ])
        );
        for value in [
            "api-catalog:packages=foo,bar",
            "api-catalog:packages=foo,foo",
            "api-catalog:packages=",
            "api-catalog:foo",
        ] {
            assert!(
                CoverageScope::parse(value).is_err(),
                "{value} must be rejected"
            );
        }
        assert!(CoverageScope::All.covers(&packages));
        assert!(!packages.covers(&CoverageScope::All));
        assert!(packages.covers(&CoverageScope::Packages(vec![
            PackageName::new("foo").unwrap()
        ])));
        assert!(!packages.covers(&CoverageScope::Packages(vec![
            PackageName::new("zoo").unwrap()
        ])));
        assert_eq!(
            CoverageScope::All.extra_package_count(&packages),
            usize::MAX
        );
        assert_eq!(
            CoverageScope::All.extra_package_count(&CoverageScope::All),
            0
        );
        assert_eq!(packages.extra_package_count(&packages), 0);
    }

    #[test]
    fn endpoint_paths_are_relative_to_explicit_base() {
        let transport = FixtureTransport {
            responses: Rc::new(RefCell::new(BTreeMap::new())),
            requests: Rc::new(RefCell::new(Vec::new())),
        };
        let provider = RUniverseProvider::new(
            "https://custom.example/universe/",
            RegistryId::new("universe").unwrap(),
            transport,
        )
        .unwrap();
        assert_eq!(
            provider.list_endpoint().unwrap(),
            "https://custom.example/universe/api/ls"
        );
        assert_eq!(
            provider.bulk_endpoint(2).unwrap(),
            "https://custom.example/universe/api/packages?limit=2"
        );
        assert_eq!(
            provider
                .package_endpoint(&PackageName::new("foo").unwrap())
                .unwrap(),
            "https://custom.example/universe/api/packages/foo"
        );
    }

    #[test]
    fn endpoint_validation_rejects_credentials_and_zero_ports() {
        let transport = FixtureTransport {
            responses: Rc::new(RefCell::new(BTreeMap::new())),
            requests: Rc::new(RefCell::new(Vec::new())),
        };
        for endpoint in [
            "https://user:password@example.test/universe",
            "https://example.test:0/universe",
        ] {
            assert!(matches!(
                RUniverseProvider::new(
                    endpoint,
                    RegistryId::new("universe").unwrap(),
                    transport.clone(),
                ),
                Err(RUniverseProviderError::InvalidEndpoint(_))
            ));
        }
    }

    #[test]
    fn endpoint_spellings_are_canonical_and_encoded_paths_are_not_double_encoded() {
        let transport = FixtureTransport {
            responses: Rc::new(RefCell::new(BTreeMap::new())),
            requests: Rc::new(RefCell::new(Vec::new())),
        };
        let first = RUniverseProvider::new(
            "HTTPS://Custom.Example/universe/",
            RegistryId::new("universe").unwrap(),
            transport.clone(),
        )
        .unwrap();
        let second = RUniverseProvider::new(
            "https://custom.example/universe",
            RegistryId::new("universe").unwrap(),
            transport.clone(),
        )
        .unwrap();
        assert_eq!(first.endpoint(), second.endpoint());

        let encoded = RUniverseProvider::new(
            "https://custom.example/a%2Fb/",
            RegistryId::new("universe").unwrap(),
            transport,
        )
        .unwrap();
        assert_eq!(
            encoded.list_endpoint().unwrap(),
            "https://custom.example/a%2Fb/api/ls"
        );
    }

    #[test]
    fn allowlisted_refresh_requests_each_declared_package() {
        let (provider, requests) = fixture_provider(
            "https://custom.example/universe/",
            &[
                (
                    "https://custom.example/universe/api/packages/foo",
                    package_entry("foo"),
                ),
                (
                    "https://custom.example/universe/api/packages/bar",
                    package_entry("bar"),
                ),
            ],
        );
        let packages = [
            PackageName::new("bar").unwrap(),
            PackageName::new("foo").unwrap(),
        ];
        let catalog = provider.refresh(Some(&packages)).unwrap();
        assert_eq!(catalog.releases().len(), 2);
        assert_eq!(
            requests.borrow().as_slice(),
            [
                "https://custom.example/universe/api/packages/bar",
                "https://custom.example/universe/api/packages/foo"
            ]
        );
    }

    #[test]
    fn bulk_refresh_requires_exact_list_coverage_and_explicit_limit() {
        let (provider, requests) = fixture_provider(
            "https://custom.example/universe",
            &[
                (
                    "https://custom.example/universe/api/ls",
                    r#"["foo","bar"]"#.into(),
                ),
                (
                    "https://custom.example/universe/api/packages?limit=2",
                    format!("[{},{}]", package_entry("foo"), package_entry("bar")),
                ),
            ],
        );
        assert_eq!(provider.refresh(None).unwrap().releases().len(), 2);
        assert_eq!(
            requests.borrow().as_slice(),
            [
                "https://custom.example/universe/api/ls",
                "https://custom.example/universe/api/packages?limit=2"
            ]
        );
    }

    #[test]
    fn bulk_refresh_rejects_truncated_or_extra_package_sets() {
        let (provider, _) = fixture_provider(
            "https://custom.example/universe",
            &[
                (
                    "https://custom.example/universe/api/ls",
                    r#"["foo","bar"]"#.into(),
                ),
                (
                    "https://custom.example/universe/api/packages?limit=2",
                    format!("[{}]", package_entry("foo")),
                ),
            ],
        );
        assert!(matches!(
            provider.refresh(None),
            Err(RUniverseProviderError::CoverageMismatch { .. })
        ));
    }

    #[test]
    fn duplicate_package_errors_name_the_actual_duplicate() {
        assert!(matches!(
            parse_package_list(
                "https://custom.example/universe/api/ls",
                br#"["bar","foo","foo"]"#,
            ),
            Err(RUniverseProviderError::DuplicatePackage { package, .. })
                if package == "foo"
        ));
    }

    #[test]
    fn bulk_refresh_rejects_duplicate_release_identity() {
        let (provider, _) = fixture_provider(
            "https://custom.example/universe",
            &[
                (
                    "https://custom.example/universe/api/ls",
                    r#"["foo"]"#.into(),
                ),
                (
                    "https://custom.example/universe/api/packages?limit=1",
                    format!("[{},{}]", package_entry("foo"), package_entry("foo")),
                ),
            ],
        );
        assert!(matches!(
            provider.refresh(None),
            Err(RUniverseProviderError::DuplicatePackage { package, .. })
                if package == "foo"
        ));
    }

    #[test]
    fn allowlisted_missing_package_is_a_typed_boundary_error() {
        let (provider, requests) = fixture_provider_with_statuses(
            "https://custom.example/universe",
            &[(
                "https://custom.example/universe/api/packages/foo",
                404,
                String::new(),
            )],
        );
        let package = PackageName::new("foo").unwrap();
        assert!(matches!(
            provider.refresh(Some(&[package])),
            Err(RUniverseProviderError::PackageNotFound { package, .. }) if package == "foo"
        ));
        assert_eq!(
            requests.borrow().as_slice(),
            ["https://custom.example/universe/api/packages/foo"]
        );
    }

    #[test]
    fn allowlisted_package_mismatch_is_rejected_before_projection() {
        let (provider, _) = fixture_provider(
            "https://custom.example/universe",
            &[(
                "https://custom.example/universe/api/packages/foo",
                package_entry("bar"),
            )],
        );
        let package = PackageName::new("foo").unwrap();
        assert!(matches!(
            provider.refresh(Some(&[package])),
            Err(RUniverseProviderError::PackageMismatch { expected, found, .. })
                if expected == "foo" && found == "bar"
        ));
    }

    #[test]
    fn transport_status_and_response_size_are_contextual_errors() {
        let (provider, _) = fixture_provider_with_statuses(
            "https://custom.example/universe",
            &[(
                "https://custom.example/universe/api/packages/foo",
                503,
                String::new(),
            )],
        );
        let package = PackageName::new("foo").unwrap();
        assert!(matches!(
            provider.refresh(Some(&[package])),
            Err(RUniverseProviderError::HttpStatus { status: 503, .. })
        ));

        let oversized = vec![b'x'; MAX_RESPONSE_BYTES + 1];
        let map = [(
            "https://custom.example/universe/api/packages/foo".to_owned(),
            RUniverseResponse {
                status: 200,
                body: oversized,
            },
        )]
        .into_iter()
        .collect();
        let transport = FixtureTransport {
            responses: Rc::new(RefCell::new(map)),
            requests: Rc::new(RefCell::new(Vec::new())),
        };
        let provider = RUniverseProvider::new(
            "https://custom.example/universe",
            RegistryId::new("universe").unwrap(),
            transport,
        )
        .unwrap();
        assert!(matches!(
            provider.refresh(Some(&[PackageName::new("foo").unwrap()])),
            Err(RUniverseProviderError::ResponseTooLarge { .. })
        ));
    }

    #[test]
    fn refresh_snapshot_round_trips_git_provenance_and_offline_profile() {
        let (provider, _) = fixture_provider(
            "https://custom.example/universe",
            &[
                (
                    "https://custom.example/universe/api/ls",
                    r#"["foo"]"#.into(),
                ),
                (
                    "https://custom.example/universe/api/packages?limit=1",
                    format!(
                        "[{}]",
                        package_entry_with_repository("foo", "https://universe.example")
                    ),
                ),
            ],
        );
        let directory = tempfile::tempdir().unwrap();
        let store =
            SnapshotStore::open(directory.path(), RegistryId::new("universe").unwrap()).unwrap();
        let loader = provider.refresh_snapshot(&store, None).unwrap();
        let releases = loader
            .load(&rsolve_core::SolverKey::InstalledName(
                PackageName::new("foo").unwrap(),
            ))
            .unwrap();
        assert!(matches!(
            releases.observations()[0].release().identity().provenance(),
            Provenance::GitCommit { commit, .. } if commit.as_str() == COMMIT
        ));
        assert!(matches!(
            &releases.observations()[0].release().distributions()[0].artifacts[..],
            [Artifact::Source(source)]
                if source.locator.as_str()
                    == "https://downloads.example.test/foo_1.0.0.tar.gz"
                    && source.size == Some(123)
                    && source.upstream_checksums.len() == 1
        ));
        assert_eq!(
            releases.observations()[0].release().distributions()[0]
                .observed_metadata
                .fields
                .get("Repository"),
            Some(&"https://universe.example".to_owned())
        );
        let offline = provider.open_compatible(&store, None).unwrap();
        assert_eq!(offline.registry_id().as_str(), "universe");
    }

    #[test]
    fn old_parser_schema_is_incompatible_until_a_current_refresh_is_published() {
        let (provider, _) = fixture_provider(
            "https://custom.example/universe",
            &[
                (
                    "https://custom.example/universe/api/ls",
                    r#"["foo"]"#.into(),
                ),
                (
                    "https://custom.example/universe/api/packages?limit=1",
                    format!("[{}]", package_entry("foo")),
                ),
            ],
        );
        let registry = RegistryId::new("universe").unwrap();
        let body = format!("[{}]", package_entry("foo"));
        let catalog = RUniverseCatalog::from_json(&body, registry.clone()).unwrap();
        let response = FetchedResponse {
            endpoint: "https://custom.example/universe/api/packages?limit=1".into(),
            body: body.into_bytes(),
        };
        let mut old_input =
            snapshot_input(&registry, &catalog, &[response], "api-catalog".into()).unwrap();
        old_input.parser_schema = 2;
        let directory = tempfile::tempdir().unwrap();
        let store = SnapshotStore::open(directory.path(), registry).unwrap();
        store
            .build_and_publish_with_endpoint(old_input, "https://custom.example/universe")
            .unwrap();
        assert!(matches!(
            provider.open_compatible_offline(&store, None),
            Err(RUniverseProviderError::OfflineIncompatible(_))
        ));

        provider.refresh_snapshot(&store, None).unwrap();
        let current = provider.open_compatible_offline(&store, None).unwrap();
        assert_eq!(
            current.header().parser_schema,
            crate::r_universe::RUNIVERSE_PARSER_SCHEMA
        );
        assert_eq!(current.header().parser_schema, 3);
    }

    #[test]
    fn compatible_coverage_accepts_supersets_and_rejects_partial_or_disjoint_scopes() {
        let package_foo = PackageName::new("foo").unwrap();
        let package_baz = PackageName::new("baz").unwrap();
        let (provider, _) = fixture_provider(
            "https://custom.example/universe",
            &[
                (
                    "https://custom.example/universe/api/ls",
                    r#"["foo","bar"]"#.into(),
                ),
                (
                    "https://custom.example/universe/api/packages?limit=2",
                    format!("[{},{}]", package_entry("foo"), package_entry("bar")),
                ),
            ],
        );
        let directory = tempfile::tempdir().unwrap();
        let store =
            SnapshotStore::open(directory.path(), RegistryId::new("universe").unwrap()).unwrap();
        provider.refresh_snapshot(&store, None).unwrap();
        assert_eq!(
            provider
                .open_compatible(&store, Some(std::slice::from_ref(&package_foo)))
                .unwrap()
                .header()
                .coverage
                .scope,
            "api-catalog"
        );
        assert_eq!(
            provider
                .open_compatible(&store, Some(&[package_foo.clone(), package_baz.clone()]))
                .unwrap()
                .header()
                .coverage
                .scope,
            "api-catalog"
        );

        let subset_directory = tempfile::tempdir().unwrap();
        let subset_store = SnapshotStore::open(
            subset_directory.path(),
            RegistryId::new("universe").unwrap(),
        )
        .unwrap();
        let (subset_provider, _) = fixture_provider(
            "https://custom.example/subset",
            &[(
                "https://custom.example/subset/api/packages/foo",
                package_entry("foo"),
            )],
        );
        subset_provider
            .refresh_snapshot(&subset_store, Some(std::slice::from_ref(&package_foo)))
            .unwrap();
        assert!(matches!(
            subset_provider
                .open_compatible(&subset_store, Some(std::slice::from_ref(&package_baz))),
            Err(RUniverseProviderError::OfflineIncompatible(_))
        ));
        assert!(matches!(
            subset_provider.open_compatible(&subset_store, Some(&[package_foo, package_baz])),
            Err(RUniverseProviderError::OfflineIncompatible(_))
        ));
        assert!(matches!(
            subset_provider.open_compatible(&subset_store, None),
            Err(RUniverseProviderError::OfflineIncompatible(_))
        ));
    }

    #[test]
    fn newer_complete_superset_is_preferred_over_older_subset() {
        let foo = PackageName::new("foo").unwrap();
        let (provider, _) = fixture_provider(
            "https://custom.example/universe",
            &[
                (
                    "https://custom.example/universe/api/packages/foo",
                    package_entry("foo"),
                ),
                (
                    "https://custom.example/universe/api/ls",
                    r#"["foo","bar"]"#.into(),
                ),
                (
                    "https://custom.example/universe/api/packages?limit=2",
                    format!("[{},{}]", package_entry("foo"), package_entry("bar")),
                ),
            ],
        );
        let directory = tempfile::tempdir().unwrap();
        let store =
            SnapshotStore::open(directory.path(), RegistryId::new("universe").unwrap()).unwrap();
        provider
            .refresh_snapshot(&store, Some(std::slice::from_ref(&foo)))
            .unwrap();
        provider.refresh_snapshot(&store, None).unwrap();
        assert_eq!(
            provider
                .open_compatible(&store, Some(std::slice::from_ref(&foo)))
                .unwrap()
                .header()
                .coverage
                .scope,
            "api-catalog"
        );
    }

    #[test]
    fn exact_package_refreshes_remain_independent_until_an_unrestricted_refresh() {
        let foo = PackageName::new("foo").unwrap();
        let bar = PackageName::new("bar").unwrap();
        let (provider, requests) = fixture_provider(
            "https://custom.example/universe",
            &[
                (
                    "https://custom.example/universe/api/packages/foo",
                    package_entry("foo"),
                ),
                (
                    "https://custom.example/universe/api/packages/bar",
                    package_entry("bar"),
                ),
                (
                    "https://custom.example/universe/api/ls",
                    r#"["bar","foo"]"#.into(),
                ),
                (
                    "https://custom.example/universe/api/packages?limit=2",
                    format!("[{},{}]", package_entry("foo"), package_entry("bar")),
                ),
            ],
        );
        let directory = tempfile::tempdir().unwrap();
        let store =
            SnapshotStore::open(directory.path(), RegistryId::new("universe").unwrap()).unwrap();

        provider
            .refresh_snapshot(&store, Some(std::slice::from_ref(&foo)))
            .unwrap();
        assert_eq!(
            requests.borrow().as_slice(),
            ["https://custom.example/universe/api/packages/foo"]
        );
        requests.borrow_mut().clear();

        provider
            .refresh_snapshot(&store, Some(std::slice::from_ref(&bar)))
            .unwrap();
        assert_eq!(
            requests.borrow().as_slice(),
            ["https://custom.example/universe/api/packages/bar"]
        );
        requests.borrow_mut().clear();

        assert_eq!(
            provider
                .open_compatible_offline(&store, Some(std::slice::from_ref(&foo)))
                .unwrap()
                .header()
                .coverage
                .scope,
            "api-catalog:packages=foo"
        );
        assert_eq!(
            provider
                .open_compatible_offline(&store, Some(std::slice::from_ref(&bar)))
                .unwrap()
                .header()
                .coverage
                .scope,
            "api-catalog:packages=bar"
        );
        assert!(matches!(
            provider.open_compatible_offline(&store, Some(&[foo.clone(), bar.clone()])),
            Err(RUniverseProviderError::OfflineIncompatible(_))
        ));
        assert!(matches!(
            provider.open_compatible_offline(&store, None),
            Err(RUniverseProviderError::OfflineIncompatible(_))
        ));

        provider.refresh_snapshot(&store, None).unwrap();
        assert_eq!(
            requests.borrow().as_slice(),
            [
                "https://custom.example/universe/api/ls",
                "https://custom.example/universe/api/packages?limit=2"
            ]
        );
        assert_eq!(
            provider
                .open_compatible_offline(&store, Some(&[foo.clone(), bar.clone()]))
                .unwrap()
                .header()
                .coverage
                .scope,
            "api-catalog"
        );
        assert_eq!(
            provider
                .open_compatible_offline(&store, Some(std::slice::from_ref(&foo)))
                .unwrap()
                .header()
                .coverage
                .scope,
            "api-catalog"
        );
        assert_eq!(store.read_view_candidates().unwrap().candidates.len(), 3);
    }

    #[test]
    fn snapshot_round_trip_preserves_distinct_git_identities_at_one_version() {
        let registry = RegistryId::new("universe").unwrap();
        let sha256_commit = "1".repeat(64);
        let body = format!(
            "[{},{}]",
            package_entry_with_commit("foo", COMMIT),
            package_entry_with_commit("foo", &sha256_commit)
        );
        let catalog = RUniverseCatalog::from_json(&body, registry.clone()).unwrap();
        let response = FetchedResponse {
            endpoint: "https://custom.example/universe/api/packages".into(),
            body: body.into_bytes(),
        };
        let input = snapshot_input(&registry, &catalog, &[response], "api-catalog".into()).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let store = SnapshotStore::open(directory.path(), registry).unwrap();
        let loader = store
            .build_and_publish_with_endpoint(input, "https://custom.example/universe")
            .unwrap();
        let loaded = loader
            .load(&rsolve_core::SolverKey::InstalledName(
                PackageName::new("foo").unwrap(),
            ))
            .unwrap();
        let commits = loaded
            .observations()
            .iter()
            .filter_map(
                |observation| match observation.release().identity().provenance() {
                    Provenance::GitCommit { commit, .. } => Some(commit.to_string()),
                    _ => None,
                },
            )
            .collect::<BTreeSet<_>>();
        assert_eq!(commits, BTreeSet::from([COMMIT.into(), sha256_commit]));
    }

    #[test]
    fn offline_open_matches_endpoint_and_declared_package_scope() {
        let package = PackageName::new("foo").unwrap();
        let (provider, _) = fixture_provider(
            "https://custom.example/universe",
            &[(
                "https://custom.example/universe/api/packages/foo",
                package_entry("foo"),
            )],
        );
        let directory = tempfile::tempdir().unwrap();
        let store =
            SnapshotStore::open(directory.path(), RegistryId::new("universe").unwrap()).unwrap();
        provider
            .refresh_snapshot(&store, Some(std::slice::from_ref(&package)))
            .unwrap();
        assert!(
            provider
                .open_compatible(&store, Some(std::slice::from_ref(&package)))
                .is_ok()
        );
        assert!(matches!(
            provider.open_compatible(&store, None),
            Err(RUniverseProviderError::OfflineIncompatible(_))
        ));

        let other_transport = FixtureTransport {
            responses: Rc::new(RefCell::new(BTreeMap::new())),
            requests: Rc::new(RefCell::new(Vec::new())),
        };
        let other = RUniverseProvider::new(
            "https://other.example/universe",
            RegistryId::new("universe").unwrap(),
            other_transport,
        )
        .unwrap();
        assert!(matches!(
            other.open_compatible(&store, Some(std::slice::from_ref(&package))),
            Err(RUniverseProviderError::OfflineIncompatible(_))
        ));
        assert!(
            other
                .open_compatible_offline(&store, Some(std::slice::from_ref(&package)))
                .is_ok()
        );
        let candidates = store.read_view_candidates().unwrap();
        assert_eq!(candidates.candidates.len(), 1);
        assert_eq!(
            candidates.candidates[0].validation.effective_endpoint,
            "https://custom.example/universe"
        );
        let offline = other
            .open_compatible_offline(&store, Some(std::slice::from_ref(&package)))
            .unwrap();
        assert_eq!(
            offline.header().sources[0].endpoint,
            "https://custom.example/universe/api/packages/foo"
        );
    }

    #[test]
    fn offline_open_distinguishes_missing_snapshot_from_invalid_validation() {
        let transport = FixtureTransport {
            responses: Rc::new(RefCell::new(BTreeMap::new())),
            requests: Rc::new(RefCell::new(Vec::new())),
        };
        let provider = RUniverseProvider::new(
            "https://custom.example/universe",
            RegistryId::new("universe").unwrap(),
            transport,
        )
        .unwrap();
        let missing_directory = tempfile::tempdir().unwrap();
        let missing_store = SnapshotStore::open(
            missing_directory.path(),
            RegistryId::new("universe").unwrap(),
        )
        .unwrap();
        assert!(matches!(
            provider.open_compatible(&missing_store, None),
            Err(RUniverseProviderError::OfflineMissing(_))
        ));

        let (provider, _) = fixture_provider(
            "https://custom.example/universe",
            &[
                (
                    "https://custom.example/universe/api/ls",
                    r#"["foo"]"#.into(),
                ),
                (
                    "https://custom.example/universe/api/packages?limit=1",
                    format!("[{}]", package_entry("foo")),
                ),
            ],
        );
        let invalid_directory = tempfile::tempdir().unwrap();
        let invalid_store = SnapshotStore::open(
            invalid_directory.path(),
            RegistryId::new("universe").unwrap(),
        )
        .unwrap();
        provider.refresh_snapshot(&invalid_store, None).unwrap();
        let view = std::fs::read_dir(invalid_store.root().join("views"))
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|path| path.extension().and_then(|extension| extension.to_str()) == Some("json"))
            .unwrap();
        std::fs::write(view, b"{}").unwrap();
        assert!(matches!(
            provider.open_compatible(&invalid_store, None),
            Err(RUniverseProviderError::OfflineCorrupt(_))
        ));
    }
}
