//! CRAN archive refresh and lazy DESCRIPTION fallback.

use std::cell::RefCell;
use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::io::Read;
use std::path::Component;
use std::rc::Rc;

use super::catalog::CranCatalog;
#[cfg(test)]
use super::history::CranHistoryError;
use super::history::{ArchiveEntry, enumerate_archive_rds};
use flate2::read::GzDecoder;
use nrr_core::{
    CandidateLoadError, CandidateLoadErrorCategory, CandidateLoader, PackageName, PackageRelease,
    ReleaseAggregation, SolverKey,
};

/// A provider-local response used by both real and fixture transports.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TransportResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

/// A provider-local transport failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TransportError {
    pub diagnostic: Box<str>,
}

impl TransportError {
    fn new(diagnostic: impl Into<Box<str>>) -> Self {
        Self {
            diagnostic: diagnostic.into(),
        }
    }
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.diagnostic)
    }
}

impl Error for TransportError {}

/// The small synchronous seam used by the CRAN provider.
pub(crate) trait Transport {
    fn get(&self, url: &str) -> Result<TransportResponse, TransportError>;
}

impl<T: Transport + ?Sized> Transport for Rc<T> {
    fn get(&self, url: &str) -> Result<TransportResponse, TransportError> {
        self.as_ref().get(url)
    }
}

/// A failure before a provider snapshot can be constructed.
#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CranProviderError {
    Transport {
        endpoint: Box<str>,
        source: TransportError,
    },
    History(CranHistoryError),
}

#[cfg(test)]
impl fmt::Display for CranProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport { endpoint, source } => {
                write!(f, "transport failure for {endpoint}: {source}")
            }
            Self::History(error) => error.fmt(f),
        }
    }
}

#[cfg(test)]
impl Error for CranProviderError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Transport { source, .. } => Some(source),
            Self::History(source) => Some(source),
        }
    }
}

/// The observed result of probing one package's CRAN archive fast path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CranFastPathStatus {
    Available,
    Absent { status: u16 },
    Invalid { status: u16, diagnostic: Box<str> },
}

/// The representation attempted for the shared current CRAN index.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CranCurrentIndexRepresentation {
    Rds,
    Gzip,
    PlainDcf,
}

/// The transport-neutral source of a refresh diagnostic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CranRefreshSource {
    ArchiveFastPath,
    CurrentIndex(CranCurrentIndexRepresentation),
}

/// A transport-neutral diagnostic from refreshing one package's CRAN source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CranRefreshDiagnostic {
    endpoint: Box<str>,
    status: Option<u16>,
    status_detail: CranFastPathStatus,
    source: CranRefreshSource,
}

impl CranRefreshDiagnostic {
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub fn status(&self) -> Option<u16> {
        self.status
    }

    pub fn status_detail(&self) -> &CranFastPathStatus {
        &self.status_detail
    }

    pub fn source(&self) -> CranRefreshSource {
        self.source
    }
}

enum CandidateSource {
    Fast(CranCatalog),
    Fallback(Rc<[ArchiveEntry]>),
}

/// A refreshed CRAN candidate source.
pub(crate) struct CranProvider<T> {
    package: PackageName,
    transport: RefCell<T>,
    base_url: Box<str>,
    source: CandidateSource,
    diagnostics: Vec<CranRefreshDiagnostic>,
    loaded: RefCell<Option<Result<Vec<PackageRelease>, CandidateLoadError>>>,
}

impl<T: Transport> CranProvider<T> {
    /// Refresh one package's archive source.  The fast-path endpoint is
    /// requested exactly once per provider instance.
    #[cfg(test)]
    pub(crate) fn refresh(
        transport: T,
        base_url: impl AsRef<str>,
        package: PackageName,
    ) -> Result<Self, CranProviderError> {
        let base_url = base_url.as_ref().trim_end_matches('/').to_owned();
        let endpoint = format!(
            "{base_url}/src/contrib/Archive/{}/PACKAGES.rds",
            package.as_str()
        );
        let response = transport
            .get(&endpoint)
            .map_err(|source| CranProviderError::Transport {
                endpoint: endpoint.clone().into_boxed_str(),
                source,
            })?;
        let mut diagnostics = Vec::new();
        let source = if response.status == 200 {
            match CranCatalog::from_archive_index_rds(&response.body) {
                Ok(catalog) => {
                    diagnostics.push(CranRefreshDiagnostic {
                        endpoint: endpoint.clone().into_boxed_str(),
                        status: Some(response.status),
                        status_detail: CranFastPathStatus::Available,
                        source: CranRefreshSource::ArchiveFastPath,
                    });
                    CandidateSource::Fast(catalog)
                }
                Err(error) => {
                    diagnostics.push(CranRefreshDiagnostic {
                        endpoint: endpoint.clone().into_boxed_str(),
                        status: Some(response.status),
                        status_detail: CranFastPathStatus::Invalid {
                            status: response.status,
                            diagnostic: error.to_string().into_boxed_str(),
                        },
                        source: CranRefreshSource::ArchiveFastPath,
                    });
                    Self::fallback_source(&transport, &base_url)?
                }
            }
        } else {
            diagnostics.push(CranRefreshDiagnostic {
                endpoint: endpoint.clone().into_boxed_str(),
                status: Some(response.status),
                status_detail: if response.status == 404 {
                    CranFastPathStatus::Absent {
                        status: response.status,
                    }
                } else {
                    CranFastPathStatus::Invalid {
                        status: response.status,
                        diagnostic: "unexpected fast-path status".into(),
                    }
                },
                source: CranRefreshSource::ArchiveFastPath,
            });
            Self::fallback_source(&transport, &base_url)?
        };

        Ok(Self {
            package,
            transport: RefCell::new(transport),
            base_url: base_url.into_boxed_str(),
            source,
            diagnostics,
            loaded: RefCell::new(None),
        })
    }

    pub(crate) fn diagnostics(&self) -> &[CranRefreshDiagnostic] {
        &self.diagnostics
    }

    fn from_source(
        transport: T,
        base_url: impl AsRef<str>,
        package: PackageName,
        source: CandidateSource,
        diagnostics: Vec<CranRefreshDiagnostic>,
    ) -> Self {
        Self {
            package,
            transport: RefCell::new(transport),
            base_url: base_url.as_ref().trim_end_matches('/').into(),
            source,
            diagnostics,
            loaded: RefCell::new(None),
        }
    }

    #[cfg(test)]
    fn fallback_source(
        transport: &T,
        base_url: &str,
    ) -> Result<CandidateSource, CranProviderError> {
        let endpoint = format!("{base_url}/Meta/archive.rds");
        let response = transport
            .get(&endpoint)
            .map_err(|source| CranProviderError::Transport {
                endpoint: endpoint.clone().into_boxed_str(),
                source,
            })?;
        if response.status != 200 {
            return Err(CranProviderError::Transport {
                endpoint: endpoint.into_boxed_str(),
                source: TransportError::new(format!(
                    "history enumeration returned HTTP {}",
                    response.status
                )),
            });
        }
        let entries = enumerate_archive_rds(&response.body).map_err(CranProviderError::History)?;
        Ok(CandidateSource::Fallback(Rc::from(
            entries.into_boxed_slice(),
        )))
    }

    fn load_fallback(
        &self,
        entries: &[ArchiveEntry],
    ) -> Result<Vec<PackageRelease>, CandidateLoadError> {
        let mut releases = Vec::new();
        for entry in entries
            .iter()
            .filter(|entry| entry.package() == &self.package)
        {
            let url = format!(
                "{}/src/contrib/Archive/{}",
                self.base_url,
                entry.source_archive_relative_path()
            );
            let transport = self.transport.borrow();
            let response = transport.get(&url).map_err(|error| {
                CandidateLoadError::new(
                    CandidateLoadErrorCategory::TransportFailure,
                    format!(
                        "failed to fetch {}: {error}",
                        entry.source_archive_relative_path()
                    ),
                )
            })?;
            if response.status != 200 {
                return Err(CandidateLoadError::new(
                    CandidateLoadErrorCategory::TransportFailure,
                    format!(
                        "failed to fetch {}: HTTP {}",
                        entry.source_archive_relative_path(),
                        response.status
                    ),
                ));
            }
            if response.body.len() as u64 != entry.size() {
                return Err(CandidateLoadError::new(
                    CandidateLoadErrorCategory::TransportFailure,
                    format!("size mismatch for {}", entry.source_archive_relative_path()),
                ));
            }
            let description = extract_description(&response.body).map_err(|error| {
                CandidateLoadError::new(
                    CandidateLoadErrorCategory::MetadataInvalid,
                    format!(
                        "invalid DESCRIPTION in {}: {error}",
                        entry.source_archive_relative_path()
                    ),
                )
            })?;
            let catalog = CranCatalog::from_packages(&description).map_err(|error| {
                CandidateLoadError::new(
                    CandidateLoadErrorCategory::MetadataInvalid,
                    format!(
                        "invalid DESCRIPTION in {}: {error}",
                        entry.source_archive_relative_path()
                    ),
                )
            })?;
            releases.extend(catalog.candidates(entry.package()).iter().cloned());
        }
        Ok(releases)
    }
}

impl<T: Transport> CandidateLoader for CranProvider<T> {
    fn releases(&self, package: &SolverKey) -> Result<Vec<PackageRelease>, CandidateLoadError> {
        let SolverKey::InstalledName(name) = package else {
            return Err(CandidateLoadError::new(
                CandidateLoadErrorCategory::NotFound,
                format!("CRAN provider has no candidates for {package:?}"),
            ));
        };
        if name != &self.package {
            return Ok(Vec::new());
        }
        if let Some(result) = self.loaded.borrow().as_ref() {
            return result.clone();
        }
        let result = match &self.source {
            CandidateSource::Fast(catalog) => Ok(catalog.candidates(&self.package).to_vec()),
            CandidateSource::Fallback(entries) => self.load_fallback(entries),
        };
        *self.loaded.borrow_mut() = Some(result.clone());
        result
    }
}

#[cfg(test)]
enum CachedProvider<T> {
    Ready(CranProvider<Rc<T>>),
    Failed(CandidateLoadError),
}

/// The shared lazy runtime path used by fixture and concrete transports.
#[cfg(test)]
pub(crate) struct CranRuntimeLoader<T> {
    base_url: Box<str>,
    transport: Rc<T>,
    providers: RefCell<HashMap<PackageName, CachedProvider<T>>>,
    diagnostics: RefCell<HashMap<PackageName, Vec<CranRefreshDiagnostic>>>,
}

#[cfg(test)]
impl<T: Transport> CranRuntimeLoader<T> {
    pub(crate) fn new(transport: T, base_url: impl AsRef<str>) -> Self {
        Self {
            base_url: base_url.as_ref().trim_end_matches('/').into(),
            transport: Rc::new(transport),
            providers: RefCell::new(HashMap::new()),
            diagnostics: RefCell::new(HashMap::new()),
        }
    }

    fn refresh_provider(&self, package: &PackageName) -> CachedProvider<T> {
        match CranProvider::refresh(Rc::clone(&self.transport), &self.base_url, package.clone()) {
            Ok(provider) => {
                self.diagnostics
                    .borrow_mut()
                    .insert(package.clone(), provider.diagnostics().to_vec());
                CachedProvider::Ready(provider)
            }
            Err(error) => CachedProvider::Failed(provider_error(error)),
        }
    }

    pub(crate) fn diagnostics(&self) -> Vec<CranRefreshDiagnostic> {
        let mut diagnostics = self
            .diagnostics
            .borrow()
            .values()
            .flat_map(|items| items.iter().cloned())
            .collect::<Vec<_>>();
        diagnostics.sort_by(|left, right| left.endpoint.cmp(&right.endpoint));
        diagnostics
    }
}

#[cfg(test)]
impl<T: Transport> CandidateLoader for CranRuntimeLoader<T> {
    fn releases(&self, package: &SolverKey) -> Result<Vec<PackageRelease>, CandidateLoadError> {
        let SolverKey::InstalledName(name) = package else {
            return Err(CandidateLoadError::new(
                CandidateLoadErrorCategory::NotFound,
                format!("CRAN provider has no candidates for {package:?}"),
            ));
        };
        if !self.providers.borrow().contains_key(name) {
            let state = self.refresh_provider(name);
            self.providers
                .borrow_mut()
                .entry(name.clone())
                .or_insert(state);
        }
        let mut providers = self.providers.borrow_mut();
        let Some(provider) = providers.get_mut(name) else {
            return Err(CandidateLoadError::new(
                CandidateLoadErrorCategory::MetadataInvalid,
                "CRAN provider cache insertion failed",
            ));
        };
        match provider {
            CachedProvider::Ready(provider) => provider.releases(package),
            CachedProvider::Failed(error) => Err(error.clone()),
        }
    }
}

/// A transport-free, process-local view handed to the resolver after refresh.
#[derive(Clone, Debug, Default)]
pub struct CranCandidateSnapshot {
    candidates: HashMap<PackageName, Vec<PackageRelease>>,
}

impl CandidateLoader for CranCandidateSnapshot {
    fn releases(&self, package: &SolverKey) -> Result<Vec<PackageRelease>, CandidateLoadError> {
        let SolverKey::InstalledName(name) = package else {
            return Err(CandidateLoadError::new(
                CandidateLoadErrorCategory::NotFound,
                format!("CRAN snapshot has no candidates for {package:?}"),
            ));
        };
        self.candidates.get(name).cloned().ok_or_else(|| {
            CandidateLoadError::new(
                CandidateLoadErrorCategory::NotFound,
                format!("CRAN snapshot has not refreshed package {name}"),
            )
        })
    }
}

impl CranCandidateSnapshot {
    /// Builds a transport-free snapshot from already validated candidates.
    /// This is useful for hermetic orchestration tests and in-memory callers.
    pub fn from_candidates<I>(candidates: I) -> Self
    where
        I: IntoIterator<Item = (PackageName, Vec<PackageRelease>)>,
    {
        Self {
            candidates: candidates.into_iter().collect(),
        }
    }

    /// Returns whether this snapshot contains a refresh result for `package`.
    pub fn contains_package(&self, package: &PackageName) -> bool {
        self.candidates.contains_key(package)
    }

    /// Returns whether an installed-name solver key still needs refreshing.
    pub fn needs_refresh(&self, package: &SolverKey) -> bool {
        matches!(package, SolverKey::InstalledName(name) if !self.contains_package(name))
    }
}

/// A single refresh session. All network and parsing state is discarded from
/// the resolver-facing snapshot once refresh returns it.
struct CranRefreshSession<T> {
    base_url: Box<str>,
    transport: Rc<T>,
    current: Option<Result<Rc<CranCatalog>, CandidateLoadError>>,
    history: Option<Result<Rc<[ArchiveEntry]>, CandidateLoadError>>,
    packages: HashMap<PackageName, Vec<PackageRelease>>,
    diagnostics: Vec<CranRefreshDiagnostic>,
}

impl<T: Transport> CranRefreshSession<T> {
    fn new(transport: Rc<T>, base_url: impl AsRef<str>) -> Self {
        Self {
            base_url: base_url.as_ref().trim_end_matches('/').into(),
            transport,
            current: None,
            history: None,
            packages: HashMap::new(),
            diagnostics: Vec::new(),
        }
    }

    fn ensure_current(&mut self) -> Result<Rc<CranCatalog>, CandidateLoadError> {
        if let Some(result) = &self.current {
            return result.clone();
        }
        let representations = [
            (CranCurrentIndexRepresentation::Rds, "PACKAGES.rds"),
            (CranCurrentIndexRepresentation::Gzip, "PACKAGES.gz"),
            (CranCurrentIndexRepresentation::PlainDcf, "PACKAGES"),
        ];
        let mut failures = Vec::new();
        let mut saw_metadata_invalid = false;
        for (representation, filename) in representations {
            let endpoint = format!("{}/src/contrib/{filename}", self.base_url);
            let response = match self.transport.get(&endpoint) {
                Ok(response) => response,
                Err(error) => {
                    self.push_current_diagnostic(
                        endpoint.clone(),
                        representation,
                        None,
                        format!("transport failure: {error}"),
                    );
                    failures.push(error.to_string());
                    continue;
                }
            };
            if response.status != 200 {
                let diagnostic = format!("unexpected current index status {}", response.status);
                self.push_current_diagnostic(
                    endpoint,
                    representation,
                    Some(response.status),
                    diagnostic.clone(),
                );
                failures.push(diagnostic);
                continue;
            }
            let parsed = match representation {
                CranCurrentIndexRepresentation::Rds => {
                    CranCatalog::from_archive_index_rds(&response.body)
                        .map_err(|error| error.to_string())
                }
                CranCurrentIndexRepresentation::Gzip => {
                    decode_gzip(&response.body).and_then(|body| {
                        CranCatalog::from_packages(&body).map_err(|error| error.to_string())
                    })
                }
                CranCurrentIndexRepresentation::PlainDcf => {
                    CranCatalog::from_packages(&response.body).map_err(|error| error.to_string())
                }
            };
            match parsed {
                Ok(catalog) => {
                    self.diagnostics.push(CranRefreshDiagnostic {
                        endpoint: endpoint.into(),
                        status: Some(response.status),
                        status_detail: CranFastPathStatus::Available,
                        source: CranRefreshSource::CurrentIndex(representation),
                    });
                    let catalog = Rc::new(catalog);
                    self.current = Some(Ok(Rc::clone(&catalog)));
                    return Ok(catalog);
                }
                Err(error) => {
                    self.push_current_diagnostic(
                        endpoint,
                        representation,
                        Some(response.status),
                        error.clone(),
                    );
                    failures.push(error);
                    saw_metadata_invalid = true;
                }
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

    fn ensure_history(&mut self) -> Result<Rc<[ArchiveEntry]>, CandidateLoadError> {
        if let Some(result) = &self.history {
            return result.clone();
        }
        let endpoint = format!("{}/Meta/archive.rds", self.base_url);
        let result = self
            .transport
            .get(&endpoint)
            .map_err(|error| {
                CandidateLoadError::new(
                    CandidateLoadErrorCategory::TransportFailure,
                    format!("failed to refresh {endpoint}: {error}"),
                )
            })
            .and_then(|response| {
                if response.status != 200 {
                    return Err(CandidateLoadError::new(
                        CandidateLoadErrorCategory::TransportFailure,
                        format!("failed to refresh {endpoint}: HTTP {}", response.status),
                    ));
                }
                enumerate_archive_rds(&response.body)
                    .map(|entries| Rc::from(entries.into_boxed_slice()))
                    .map_err(|error| {
                        CandidateLoadError::new(
                            CandidateLoadErrorCategory::MetadataInvalid,
                            format!("invalid CRAN archive history: {error}"),
                        )
                    })
            });
        self.history = Some(result.clone());
        result
    }

    fn refresh_package(
        &mut self,
        package: &PackageName,
    ) -> Result<Vec<PackageRelease>, CandidateLoadError> {
        if let Some(candidates) = self.packages.get(package) {
            return Ok(candidates.clone());
        }
        let current = self.ensure_current()?.candidates(package).to_vec();
        let endpoint = format!(
            "{}/src/contrib/Archive/{}/PACKAGES.rds",
            self.base_url,
            package.as_str()
        );
        let mut package_diagnostics = Vec::new();
        let source = match self.transport.get(&endpoint) {
            Err(error) => {
                package_diagnostics.push(CranRefreshDiagnostic {
                    endpoint: endpoint.clone().into_boxed_str(),
                    status: None,
                    status_detail: CranFastPathStatus::Invalid {
                        status: 0,
                        diagnostic: format!("transport failure: {error}").into_boxed_str(),
                    },
                    source: CranRefreshSource::ArchiveFastPath,
                });
                CandidateSource::Fallback(self.ensure_history()?)
            }
            Ok(response) if response.status == 200 => {
                match CranCatalog::from_archive_index_rds(&response.body) {
                    Ok(catalog) => {
                        package_diagnostics.push(CranRefreshDiagnostic {
                            endpoint: endpoint.clone().into_boxed_str(),
                            status: Some(response.status),
                            status_detail: CranFastPathStatus::Available,
                            source: CranRefreshSource::ArchiveFastPath,
                        });
                        CandidateSource::Fast(catalog)
                    }
                    Err(error) => {
                        package_diagnostics.push(CranRefreshDiagnostic {
                            endpoint: endpoint.clone().into_boxed_str(),
                            status: Some(response.status),
                            status_detail: CranFastPathStatus::Invalid {
                                status: response.status,
                                diagnostic: error.to_string().into_boxed_str(),
                            },
                            source: CranRefreshSource::ArchiveFastPath,
                        });
                        CandidateSource::Fallback(self.ensure_history()?)
                    }
                }
            }
            Ok(response) => {
                let status = response.status;
                let status_detail = if matches!(status, 404 | 410) {
                    CranFastPathStatus::Absent { status }
                } else {
                    CranFastPathStatus::Invalid {
                        status,
                        diagnostic: "unexpected fast-path status".into(),
                    }
                };
                package_diagnostics.push(CranRefreshDiagnostic {
                    endpoint: endpoint.clone().into_boxed_str(),
                    status: Some(status),
                    status_detail,
                    source: CranRefreshSource::ArchiveFastPath,
                });
                CandidateSource::Fallback(self.ensure_history()?)
            }
        };
        let provider = CranProvider::from_source(
            Rc::clone(&self.transport),
            &self.base_url,
            package.clone(),
            source,
            package_diagnostics,
        );
        self.diagnostics
            .extend(provider.diagnostics().iter().cloned());
        let archived = provider.releases(&SolverKey::InstalledName(package.clone()))?;
        let mut aggregation = ReleaseAggregation::new();
        for release in current.into_iter().chain(archived) {
            aggregation.observe_release(release).map_err(|error| {
                CandidateLoadError::new(
                    CandidateLoadErrorCategory::MetadataInvalid,
                    format!("conflicting CRAN release metadata for {package}: {error}"),
                )
            })?;
        }
        let mut candidates = aggregation.releases().cloned().collect::<Vec<_>>();
        candidates.sort_by(|left, right| left.version().cmp(right.version()));
        self.packages.insert(package.clone(), candidates.clone());
        Ok(candidates)
    }

    fn refresh_packages(
        &mut self,
        roots: &[PackageName],
    ) -> Result<CranCandidateSnapshot, CandidateLoadError> {
        for package in roots {
            self.refresh_package(package)?;
        }
        Ok(CranCandidateSnapshot {
            candidates: self.packages.clone(),
        })
    }
}

fn decode_gzip(input: &[u8]) -> Result<Vec<u8>, String> {
    let decoder = GzDecoder::new(input);
    let mut output = Vec::new();
    decoder
        .take(MAX_RESPONSE_BYTES + 1)
        .read_to_end(&mut output)
        .map_err(|error| format!("invalid gzip current index: {error}"))?;
    if output.len() as u64 > MAX_RESPONSE_BYTES {
        return Err(format!(
            "gzip current index exceeds {MAX_RESPONSE_BYTES}-byte limit"
        ));
    }
    Ok(output)
}

// This is a CRAN transport defense limit, not a generic artifact-size contract.
const MAX_RESPONSE_BYTES: u64 = 256 * 1024 * 1024;

#[cfg(test)]
fn provider_error(error: CranProviderError) -> CandidateLoadError {
    match error {
        CranProviderError::Transport { endpoint, source } => CandidateLoadError::new(
            CandidateLoadErrorCategory::TransportFailure,
            format!("failed to refresh {endpoint}: {source}"),
        ),
        CranProviderError::History(error) => CandidateLoadError::new(
            CandidateLoadErrorCategory::MetadataInvalid,
            format!("invalid CRAN archive history: {error}"),
        ),
    }
}

struct UreqTransport {
    agent: ureq::Agent,
}

impl Transport for UreqTransport {
    fn get(&self, url: &str) -> Result<TransportResponse, TransportError> {
        let response = self
            .agent
            .get(url)
            .call()
            .map_err(|error| TransportError::new(format!("request failed: {error}")))?;
        let status = response.status().as_u16();
        let mut body = response.into_body();
        let declared_size = body.content_length();
        if declared_size.is_some_and(|length| length > MAX_RESPONSE_BYTES) {
            return Err(TransportError::new(format!(
                "response exceeds {MAX_RESPONSE_BYTES}-byte limit"
            )));
        }
        let mut bytes = Vec::new();
        body.as_reader()
            .take(MAX_RESPONSE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| TransportError::new(format!("failed to read response: {error}")))?;
        if bytes.len() as u64 > MAX_RESPONSE_BYTES
            || declared_size.is_some_and(|length| length != bytes.len() as u64)
        {
            return Err(TransportError::new(format!(
                "response size exceeds declared or {MAX_RESPONSE_BYTES}-byte limit"
            )));
        }
        Ok(TransportResponse {
            status,
            body: bytes,
        })
    }
}

/// A transport-neutral failure constructing the CRAN snapshot refresher.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CranSnapshotRefresherError {
    InvalidBaseUrl { diagnostic: Box<str> },
}

impl fmt::Display for CranSnapshotRefresherError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBaseUrl { diagnostic } => formatter.write_str(diagnostic),
        }
    }
}

impl Error for CranSnapshotRefresherError {}

/// A synchronous CRAN refresh owner backed by one reusable ureq agent.
///
/// Refreshing this owner blocks while performing network I/O. Async callers
/// should invoke refresh methods through a blocking worker boundary; the
/// returned snapshot itself performs no I/O.
pub struct CranSnapshotRefresher {
    session: RefCell<CranRefreshSession<UreqTransport>>,
}

impl CranSnapshotRefresher {
    pub fn new(base_url: impl AsRef<str>) -> Result<Self, CranSnapshotRefresherError> {
        let base_url = canonical_base_url(base_url.as_ref())?;
        let tls_config = ureq::tls::TlsConfig::builder()
            .root_certs(ureq::tls::RootCerts::PlatformVerifier)
            .build();
        let config = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .tls_config(tls_config)
            .build();
        Ok(Self {
            session: RefCell::new(CranRefreshSession::new(
                Rc::new(UreqTransport {
                    agent: config.new_agent(),
                }),
                base_url,
            )),
        })
    }

    pub fn diagnostics(&self) -> Vec<CranRefreshDiagnostic> {
        let mut diagnostics = self.session.borrow().diagnostics.clone();
        diagnostics.sort_by(|left, right| left.endpoint.cmp(&right.endpoint));
        diagnostics
    }

    /// Refreshes exactly these package names, then returns a transport-free
    /// snapshot containing all package results cached by this refresher.
    pub fn refresh_packages(
        &self,
        roots: &[PackageName],
    ) -> Result<CranCandidateSnapshot, CandidateLoadError> {
        self.session.borrow_mut().refresh_packages(roots)
    }
}

fn canonical_base_url(input: &str) -> Result<Box<str>, CranSnapshotRefresherError> {
    let input = input.trim();
    if input.is_empty() {
        return Err(CranSnapshotRefresherError::InvalidBaseUrl {
            diagnostic: "CRAN base URL must not be empty".into(),
        });
    }
    let mut url =
        url::Url::parse(input).map_err(|error| CranSnapshotRefresherError::InvalidBaseUrl {
            diagnostic: format!("invalid CRAN base URL: {error}").into(),
        })?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(CranSnapshotRefresherError::InvalidBaseUrl {
            diagnostic: "CRAN base URL must use HTTP or HTTPS".into(),
        });
    }
    if url.host_str().is_none() || url.cannot_be_a_base() {
        return Err(CranSnapshotRefresherError::InvalidBaseUrl {
            diagnostic: "CRAN base URL must be hierarchical and include a host".into(),
        });
    }
    if url.query().is_some() {
        return Err(CranSnapshotRefresherError::InvalidBaseUrl {
            diagnostic: "CRAN base URL must not include a query".into(),
        });
    }
    if url.fragment().is_some() {
        return Err(CranSnapshotRefresherError::InvalidBaseUrl {
            diagnostic: "CRAN base URL must not include a fragment".into(),
        });
    }
    let path = url.path().trim_end_matches('/').to_owned();
    url.set_path(if path.is_empty() { "/" } else { &path });
    Ok(url.to_string().trim_end_matches('/').into())
}

fn extract_description(input: &[u8]) -> Result<Vec<u8>, String> {
    let decoder = GzDecoder::new(input);
    let mut archive = tar::Archive::new(decoder);
    let mut description = None;
    for item in archive.entries().map_err(|error| error.to_string())? {
        let entry = item.map_err(|error| error.to_string())?;
        let path = entry
            .path()
            .map_err(|error| error.to_string())?
            .into_owned();
        let components = path.components().collect::<Vec<_>>();
        if components.iter().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        }) {
            return Err("archive contains an unsafe path".to_owned());
        }
        if !entry.header().entry_type().is_file() {
            continue;
        }
        if components.len() == 2
            && components[1].as_os_str() == "DESCRIPTION"
            && matches!(components[0], Component::Normal(_))
        {
            if description.is_some() {
                return Err("archive contains multiple root DESCRIPTION files".to_owned());
            }
            let size = entry.header().size().map_err(|error| error.to_string())?;
            if size > 4 * 1024 * 1024 {
                return Err("DESCRIPTION exceeds size limit".to_owned());
            }
            let mut bytes = Vec::new();
            entry
                .take(4 * 1024 * 1024 + 1)
                .read_to_end(&mut bytes)
                .map_err(|error| error.to_string())?;
            if bytes.len() > 4 * 1024 * 1024 {
                return Err("DESCRIPTION exceeds size limit".to_owned());
            }
            description = Some(bytes);
        }
    }
    description.ok_or_else(|| "archive root has no DESCRIPTION file".to_owned())
}
#[cfg(test)]
mod tests {
    use super::*;
    use nrr_core::{CandidateLoadErrorCategory, PackageName, SolverKey};
    use std::collections::HashMap;
    use std::io::Write;
    use std::rc::Rc;

    const FAST: &[u8] = include_bytes!(
        "../../tests/fixtures/cran-2026-08-08/synthetic-matrix-archive-PACKAGES.rds"
    );
    const WRONG_ROOT: &[u8] = include_bytes!(
        "../../tests/fixtures/cran-2026-08-08/synthetic-matrix-archive-wrong-root.rds"
    );
    const MISSING_VERSION: &[u8] = include_bytes!(
        "../../tests/fixtures/cran-2026-08-08/synthetic-matrix-archive-missing-version.rds"
    );
    const HISTORY: &[u8] =
        include_bytes!("../../tests/fixtures/cran-2026-08-08/synthetic-meta-archive.rds");
    const INVALID_HISTORY_PATHS: &[&[u8]] = &[
        include_bytes!("../../tests/fixtures/cran-2026-08-08/synthetic-meta-invalid-traversal.rds"),
        include_bytes!("../../tests/fixtures/cran-2026-08-08/synthetic-meta-invalid-query.rds"),
        include_bytes!("../../tests/fixtures/cran-2026-08-08/synthetic-meta-invalid-fragment.rds"),
        include_bytes!(
            "../../tests/fixtures/cran-2026-08-08/synthetic-meta-invalid-percent-traversal.rds"
        ),
        include_bytes!("../../tests/fixtures/cran-2026-08-08/synthetic-meta-invalid-backslash.rds"),
        include_bytes!(
            "../../tests/fixtures/cran-2026-08-08/synthetic-meta-invalid-package-mismatch.rds"
        ),
        include_bytes!("../../tests/fixtures/cran-2026-08-08/synthetic-meta-invalid-version.rds"),
    ];
    const OLD_TAR: &[u8] =
        include_bytes!("../../tests/fixtures/cran-2026-08-08/synthetic-Matrix_1.6-5.tar.gz");
    const NEW_TAR: &[u8] =
        include_bytes!("../../tests/fixtures/cran-2026-08-08/synthetic-Matrix_1.7-0.tar.gz");

    #[derive(Clone)]
    struct FixtureTransport {
        responses: HashMap<String, TransportResponse>,
        requests: Rc<RefCell<Vec<String>>>,
    }

    impl FixtureTransport {
        fn fallback(fast: Vec<u8>, status: u16) -> Self {
            let mut responses = HashMap::new();
            responses.insert(fast_url(), TransportResponse { status, body: fast });
            responses.insert(
                history_url(),
                TransportResponse {
                    status: 200,
                    body: HISTORY.to_vec(),
                },
            );
            responses.insert(
                old_url(),
                TransportResponse {
                    status: 200,
                    body: OLD_TAR.to_vec(),
                },
            );
            responses.insert(
                new_url(),
                TransportResponse {
                    status: 200,
                    body: NEW_TAR.to_vec(),
                },
            );
            Self {
                responses,
                requests: Rc::new(RefCell::new(Vec::new())),
            }
        }
    }

    impl Transport for FixtureTransport {
        fn get(&self, url: &str) -> Result<TransportResponse, TransportError> {
            self.requests.borrow_mut().push(url.to_owned());
            self.responses
                .get(url)
                .cloned()
                .ok_or_else(|| TransportError::new(format!("fixture has no response for {url}")))
        }
    }

    fn fast_url() -> String {
        "https://cran.invalid/src/contrib/Archive/Matrix/PACKAGES.rds".to_owned()
    }

    fn history_url() -> String {
        "https://cran.invalid/Meta/archive.rds".to_owned()
    }

    fn old_url() -> String {
        "https://cran.invalid/src/contrib/Archive/Matrix/Matrix_1.6-5.tar.gz".to_owned()
    }

    fn new_url() -> String {
        "https://cran.invalid/src/contrib/Archive/Matrix/Matrix_1.7-0.tar.gz".to_owned()
    }

    fn current_rds_url() -> String {
        "https://cran.invalid/src/contrib/PACKAGES.rds".to_owned()
    }

    fn current_gzip_url() -> String {
        "https://cran.invalid/src/contrib/PACKAGES.gz".to_owned()
    }

    fn current_plain_url() -> String {
        "https://cran.invalid/src/contrib/PACKAGES".to_owned()
    }

    fn fast_url_for(package: &str) -> String {
        format!("https://cran.invalid/src/contrib/Archive/{package}/PACKAGES.rds")
    }

    fn provider(transport: FixtureTransport) -> CranProvider<FixtureTransport> {
        CranProvider::refresh(
            transport,
            "https://cran.invalid",
            PackageName::new("Matrix").unwrap(),
        )
        .unwrap()
    }

    fn runtime_loader(transport: FixtureTransport) -> CranRuntimeLoader<FixtureTransport> {
        CranRuntimeLoader::new(transport, "https://cran.invalid")
    }

    fn session_transport(
        current_rds: TransportResponse,
        current_gzip: TransportResponse,
        current_plain: TransportResponse,
    ) -> FixtureTransport {
        let mut responses = HashMap::new();
        responses.insert(current_rds_url(), current_rds);
        responses.insert(current_gzip_url(), current_gzip);
        responses.insert(current_plain_url(), current_plain);
        responses.insert(
            fast_url(),
            TransportResponse {
                status: 404,
                body: Vec::new(),
            },
        );
        for package in ["methods", "nrrfixture.plain"] {
            responses.insert(
                fast_url_for(package),
                TransportResponse {
                    status: 404,
                    body: Vec::new(),
                },
            );
        }
        responses.insert(
            history_url(),
            TransportResponse {
                status: 200,
                body: HISTORY.to_vec(),
            },
        );
        responses.insert(
            old_url(),
            TransportResponse {
                status: 200,
                body: OLD_TAR.to_vec(),
            },
        );
        responses.insert(
            new_url(),
            TransportResponse {
                status: 200,
                body: NEW_TAR.to_vec(),
            },
        );
        FixtureTransport {
            responses,
            requests: Rc::new(RefCell::new(Vec::new())),
        }
    }

    #[test]
    fn concrete_loader_validates_and_canonicalizes_base_without_requests() {
        assert_eq!(
            canonical_base_url(" https://cran.invalid/mirror/// ").unwrap(),
            "https://cran.invalid/mirror".into()
        );
        assert!(CranSnapshotRefresher::new("https://cran.invalid/mirror///").is_ok());
        for input in [
            "",
            "ftp://cran.invalid",
            "https://",
            "https://cran.invalid?mirror=1",
            "https://cran.invalid/#mirror",
        ] {
            assert!(matches!(
                CranSnapshotRefresher::new(input),
                Err(CranSnapshotRefresherError::InvalidBaseUrl { .. })
            ));
        }
    }

    fn logical_signature(provider: &CranProvider<FixtureTransport>) -> Vec<String> {
        provider
            .releases(&SolverKey::InstalledName(
                PackageName::new("Matrix").unwrap(),
            ))
            .unwrap()
            .into_iter()
            .map(|release| {
                let dependencies = release
                    .dependencies()
                    .iter()
                    .map(|dependency| {
                        (
                            dependency.kind,
                            dependency.name.as_str(),
                            &dependency.source,
                            &dependency.constraint.clauses,
                        )
                    })
                    .collect::<Vec<_>>();
                let common_metadata = ["License", "NeedsCompilation"]
                    .into_iter()
                    .filter_map(|field| {
                        release
                            .metadata()
                            .fields()
                            .get(field)
                            .map(|value| (field, value))
                    })
                    .collect::<Vec<_>>();
                // MD5sum belongs to the index/artifact acquisition layer, not
                // DESCRIPTION or solver-facing release metadata.  It is
                // intentionally excluded so real CRAN fallback remains exact.
                format!(
                    "identity={:?};version={};dependencies={dependencies:?};metadata={common_metadata:?};distributions={:?}",
                    release.identity(),
                    release.version(),
                    release.distributions(),
                )
            })
            .collect()
    }

    #[test]
    fn absent_fast_path_falls_back_lazily_without_reprobe() {
        let transport = FixtureTransport::fallback(Vec::new(), 404);
        let requests = Rc::clone(&transport.requests);
        let provider = provider(transport);
        assert!(matches!(
            provider.diagnostics()[0].status_detail(),
            CranFastPathStatus::Absent { status: 404 }
        ));
        assert_eq!(requests.borrow().len(), 2);
        assert_eq!(requests.borrow()[0], fast_url());
        assert_eq!(requests.borrow()[1], history_url());
        assert_eq!(logical_signature(&provider).len(), 2);
        assert_eq!(
            requests
                .borrow()
                .iter()
                .filter(|url| *url == &fast_url())
                .count(),
            1
        );
        assert_eq!(
            requests
                .borrow()
                .iter()
                .filter(|url| *url == &history_url())
                .count(),
            1
        );
        assert_eq!(
            requests
                .borrow()
                .iter()
                .filter(|url| *url == &old_url())
                .count(),
            1
        );
        assert_eq!(
            requests
                .borrow()
                .iter()
                .filter(|url| *url == &new_url())
                .count(),
            1
        );
        assert_eq!(logical_signature(&provider).len(), 2);
        assert_eq!(
            requests
                .borrow()
                .iter()
                .filter(|url| *url == &old_url())
                .count(),
            1
        );
    }

    #[test]
    fn runtime_loader_caches_each_package_provider_and_its_candidates() {
        let transport = FixtureTransport::fallback(Vec::new(), 404);
        let requests = Rc::clone(&transport.requests);
        let loader = runtime_loader(transport);
        let package = SolverKey::InstalledName(PackageName::new("Matrix").unwrap());

        assert_eq!(loader.releases(&package).unwrap().len(), 2);
        assert!(matches!(
            loader.diagnostics()[0].status_detail(),
            CranFastPathStatus::Absent { status: 404 }
        ));
        assert_eq!(requests.borrow().len(), 4);
        assert_eq!(requests.borrow()[0], fast_url());
        assert_eq!(requests.borrow()[1], history_url());
        assert_eq!(requests.borrow()[2], old_url());
        assert_eq!(requests.borrow()[3], new_url());

        assert_eq!(loader.releases(&package).unwrap().len(), 2);
        assert_eq!(requests.borrow().len(), 4);
    }

    #[test]
    fn runtime_loader_invalid_fast_path_falls_back_to_history() {
        let transport = FixtureTransport::fallback(WRONG_ROOT.to_vec(), 200);
        let requests = Rc::clone(&transport.requests);
        let loader = runtime_loader(transport);
        let package = SolverKey::InstalledName(PackageName::new("Matrix").unwrap());

        assert_eq!(loader.releases(&package).unwrap().len(), 2);
        assert!(matches!(
            loader.diagnostics()[0].status_detail(),
            CranFastPathStatus::Invalid { status: 200, .. }
        ));
        assert_eq!(requests.borrow().len(), 4);
        assert_eq!(requests.borrow()[0], fast_url());
        assert_eq!(requests.borrow()[1], history_url());
    }

    #[test]
    fn invalid_fast_path_shapes_match_fast_catalog() {
        let fast = provider(FixtureTransport::fallback(FAST.to_vec(), 200));
        let expected = logical_signature(&fast);
        for invalid in [b"truncated RDS".as_slice(), WRONG_ROOT, MISSING_VERSION] {
            let fallback = provider(FixtureTransport::fallback(invalid.to_vec(), 200));
            assert_eq!(logical_signature(&fallback), expected);
            assert!(matches!(
                fallback.diagnostics()[0].status_detail(),
                CranFastPathStatus::Invalid { status: 200, .. }
            ));
        }
    }

    #[test]
    fn refresh_session_falls_back_to_plain_current_and_freezes_without_network() {
        let current = b"Package: Matrix\nVersion: 1.8-0\nLicense: NRR Fictional Current\n";
        let transport = session_transport(
            TransportResponse {
                status: 404,
                body: Vec::new(),
            },
            TransportResponse {
                status: 404,
                body: Vec::new(),
            },
            TransportResponse {
                status: 200,
                body: current.to_vec(),
            },
        );
        let requests = Rc::clone(&transport.requests);
        let mut session = CranRefreshSession::new(Rc::new(transport), "https://cran.invalid");
        let snapshot = session
            .refresh_packages(&[PackageName::new("Matrix").unwrap()])
            .unwrap();
        let before = requests.borrow().len();
        let releases = snapshot
            .releases(&SolverKey::InstalledName(
                PackageName::new("Matrix").unwrap(),
            ))
            .unwrap();
        assert_eq!(releases.len(), 3);
        assert_eq!(requests.borrow().len(), before);
        assert_eq!(requests.borrow()[0], current_rds_url());
        assert_eq!(requests.borrow()[1], current_gzip_url());
        assert_eq!(requests.borrow()[2], current_plain_url());
        assert_eq!(
            requests
                .borrow()
                .iter()
                .filter(|url| *url == &history_url())
                .count(),
            1
        );
        assert!(
            !requests
                .borrow()
                .iter()
                .any(|url| url.contains("/Archive/methods/PACKAGES.rds"))
        );
        assert!(session.diagnostics.iter().any(|diagnostic| {
            diagnostic.source()
                == CranRefreshSource::CurrentIndex(CranCurrentIndexRepresentation::PlainDcf)
        }));
    }

    #[test]
    fn snapshot_distinguishes_unrefreshed_from_refreshed_empty_packages() {
        let empty = PackageName::new("nrrfixture.empty").unwrap();
        let unknown = PackageName::new("nrrfixture.unknown").unwrap();
        let snapshot = CranCandidateSnapshot::from_candidates([(empty.clone(), Vec::new())]);
        assert!(snapshot.contains_package(&empty));
        assert!(!snapshot.needs_refresh(&SolverKey::InstalledName(empty.clone())));
        assert!(
            snapshot
                .releases(&SolverKey::InstalledName(empty))
                .unwrap()
                .is_empty()
        );
        assert!(snapshot.needs_refresh(&SolverKey::InstalledName(unknown.clone())));
        assert_eq!(
            snapshot
                .releases(&SolverKey::InstalledName(unknown))
                .unwrap_err()
                .category(),
            CandidateLoadErrorCategory::NotFound
        );
    }

    #[test]
    fn invalid_gzip_current_index_falls_back_to_plain_once() {
        let current = b"Package: nrrfixture.plain\nVersion: 3.0.0\n";
        let transport = session_transport(
            TransportResponse {
                status: 404,
                body: Vec::new(),
            },
            TransportResponse {
                status: 200,
                body: b"not gzip".to_vec(),
            },
            TransportResponse {
                status: 200,
                body: current.to_vec(),
            },
        );
        let requests = Rc::clone(&transport.requests);
        let mut session = CranRefreshSession::new(Rc::new(transport), "https://cran.invalid");
        let snapshot = session
            .refresh_packages(&[PackageName::new("nrrfixture.plain").unwrap()])
            .unwrap();
        assert_eq!(
            snapshot
                .releases(&SolverKey::InstalledName(
                    PackageName::new("nrrfixture.plain").unwrap()
                ))
                .unwrap()
                .len(),
            1
        );
        assert_eq!(requests.borrow()[0], current_rds_url());
        assert_eq!(requests.borrow()[1], current_gzip_url());
        assert_eq!(requests.borrow()[2], current_plain_url());
        assert!(session.diagnostics.iter().any(|diagnostic| {
            diagnostic.source()
                == CranRefreshSource::CurrentIndex(CranCurrentIndexRepresentation::Gzip)
                && matches!(
                    diagnostic.status_detail(),
                    CranFastPathStatus::Invalid { .. }
                )
        }));
    }

    #[test]
    fn current_and_archive_same_identity_merge_or_fail_on_metadata_conflict() {
        let consistent = b"Package: Matrix\nVersion: 1.7-0\nDepends: R (>= 4.4.0)\nImports: methods\nLicense: NRR Fictional Terms Matrix\nNeedsCompilation: yes\n";
        let transport = session_transport(
            TransportResponse {
                status: 404,
                body: Vec::new(),
            },
            TransportResponse {
                status: 404,
                body: Vec::new(),
            },
            TransportResponse {
                status: 200,
                body: consistent.to_vec(),
            },
        );
        let mut session = CranRefreshSession::new(Rc::new(transport), "https://cran.invalid");
        let snapshot = session
            .refresh_packages(&[PackageName::new("Matrix").unwrap()])
            .unwrap();
        assert_eq!(
            snapshot
                .releases(&SolverKey::InstalledName(
                    PackageName::new("Matrix").unwrap()
                ))
                .unwrap()
                .len(),
            2
        );

        let conflicting = b"Package: Matrix\nVersion: 1.7-0\nDepends: R (>= 4.4.0)\nImports: methods\nLicense: conflicting\nNeedsCompilation: yes\n";
        let transport = session_transport(
            TransportResponse {
                status: 404,
                body: Vec::new(),
            },
            TransportResponse {
                status: 404,
                body: Vec::new(),
            },
            TransportResponse {
                status: 200,
                body: conflicting.to_vec(),
            },
        );
        let mut session = CranRefreshSession::new(Rc::new(transport), "https://cran.invalid");
        let error = session
            .refresh_packages(&[PackageName::new("Matrix").unwrap()])
            .unwrap_err();
        assert_eq!(
            error.category(),
            CandidateLoadErrorCategory::MetadataInvalid
        );
        assert!(
            error
                .diagnostic()
                .contains("conflicting CRAN release metadata")
        );
    }

    #[test]
    fn unsupported_rds_current_index_falls_back_to_gzip() {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder
            .write_all(b"Package: nrrfixture.plain\nVersion: 3.0.0\n")
            .unwrap();
        let transport = session_transport(
            TransportResponse {
                status: 200,
                body: vec![0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00],
            },
            TransportResponse {
                status: 200,
                body: encoder.finish().unwrap(),
            },
            TransportResponse {
                status: 500,
                body: Vec::new(),
            },
        );
        let requests = Rc::clone(&transport.requests);
        let mut session = CranRefreshSession::new(Rc::new(transport), "https://cran.invalid");
        session
            .refresh_packages(&[PackageName::new("nrrfixture.plain").unwrap()])
            .unwrap();
        assert_eq!(requests.borrow()[0], current_rds_url());
        assert_eq!(requests.borrow()[1], current_gzip_url());
        assert_eq!(requests.borrow()[2], fast_url_for("nrrfixture.plain"));
        assert!(session.diagnostics.iter().any(|diagnostic| {
            diagnostic.source()
                == CranRefreshSource::CurrentIndex(CranCurrentIndexRepresentation::Gzip)
                && matches!(diagnostic.status_detail(), CranFastPathStatus::Available)
        }));
    }

    #[test]
    fn current_index_transport_or_status_failures_remain_transport_failures() {
        for responses in [
            HashMap::new(),
            HashMap::from([
                (
                    current_rds_url(),
                    TransportResponse {
                        status: 404,
                        body: Vec::new(),
                    },
                ),
                (
                    current_gzip_url(),
                    TransportResponse {
                        status: 410,
                        body: Vec::new(),
                    },
                ),
                (
                    current_plain_url(),
                    TransportResponse {
                        status: 503,
                        body: Vec::new(),
                    },
                ),
            ]),
        ] {
            let transport = FixtureTransport {
                responses,
                requests: Rc::new(RefCell::new(Vec::new())),
            };
            let mut session = CranRefreshSession::new(Rc::new(transport), "https://cran.invalid");
            let error = session.ensure_current().unwrap_err();
            assert_eq!(
                error.category(),
                CandidateLoadErrorCategory::TransportFailure
            );
        }
    }

    #[test]
    fn current_index_http_success_with_invalid_schema_is_metadata_invalid() {
        let mut responses = HashMap::new();
        responses.insert(
            current_rds_url(),
            TransportResponse {
                status: 200,
                body: WRONG_ROOT.to_vec(),
            },
        );
        responses.insert(
            current_gzip_url(),
            TransportResponse {
                status: 404,
                body: Vec::new(),
            },
        );
        responses.insert(
            current_plain_url(),
            TransportResponse {
                status: 503,
                body: Vec::new(),
            },
        );
        let transport = FixtureTransport {
            responses,
            requests: Rc::new(RefCell::new(Vec::new())),
        };
        let mut session = CranRefreshSession::new(Rc::new(transport), "https://cran.invalid");
        let error = session.ensure_current().unwrap_err();
        assert_eq!(
            error.category(),
            CandidateLoadErrorCategory::MetadataInvalid
        );
    }

    #[test]
    fn gone_fast_path_is_absent_and_shared_history_is_fetched_once() {
        let current = b"Package: Matrix\nVersion: 1.8-0\n";
        let mut transport = session_transport(
            TransportResponse {
                status: 404,
                body: Vec::new(),
            },
            TransportResponse {
                status: 404,
                body: Vec::new(),
            },
            TransportResponse {
                status: 200,
                body: current.to_vec(),
            },
        );
        transport.responses.insert(
            fast_url(),
            TransportResponse {
                status: 410,
                body: Vec::new(),
            },
        );
        let requests = Rc::clone(&transport.requests);
        let mut session = CranRefreshSession::new(Rc::new(transport), "https://cran.invalid");
        session
            .refresh_packages(&[PackageName::new("Matrix").unwrap()])
            .unwrap();
        assert_eq!(
            session
                .diagnostics
                .iter()
                .find(|diagnostic| diagnostic.endpoint() == fast_url())
                .unwrap()
                .status_detail(),
            &CranFastPathStatus::Absent { status: 410 }
        );
        assert_eq!(
            requests
                .borrow()
                .iter()
                .filter(|url| *url == &history_url())
                .count(),
            1
        );
    }

    #[test]
    fn fast_path_transport_error_is_diagnostic_and_falls_back() {
        let current = b"Package: Matrix\nVersion: 1.8-0\n";
        let mut transport = session_transport(
            TransportResponse {
                status: 404,
                body: Vec::new(),
            },
            TransportResponse {
                status: 404,
                body: Vec::new(),
            },
            TransportResponse {
                status: 200,
                body: current.to_vec(),
            },
        );
        transport.responses.remove(&fast_url());
        let mut session = CranRefreshSession::new(Rc::new(transport), "https://cran.invalid");
        session
            .refresh_packages(&[PackageName::new("Matrix").unwrap()])
            .unwrap();
        let diagnostic = session
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.endpoint() == fast_url())
            .unwrap();
        assert_eq!(diagnostic.status(), None);
        assert!(matches!(
            diagnostic.status_detail(),
            CranFastPathStatus::Invalid { status: 0, .. }
        ));
    }

    #[test]
    fn history_only_enumerates_file_info_facts() {
        let entries = enumerate_archive_rds(HISTORY).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].package().as_str(), "Matrix");
        assert_eq!(
            entries[0].source_archive_relative_path(),
            "Matrix/Matrix_1.6-5.tar.gz"
        );
        assert_eq!(entries[0].version().as_str(), "1.6-5");
        assert_eq!(entries[0].size(), OLD_TAR.len() as u64);
        assert_eq!(entries[0].mtime(), 1_790_000_000);
    }

    #[test]
    fn history_rejects_non_canonical_archive_paths() {
        for fixture in INVALID_HISTORY_PATHS {
            assert!(matches!(
                enumerate_archive_rds(fixture),
                Err(CranHistoryError::InvalidArchivePath { .. })
            ));
        }
    }

    #[test]
    fn size_mismatch_is_a_hard_acquisition_error() {
        let mut size_transport = FixtureTransport::fallback(Vec::new(), 404);
        size_transport
            .responses
            .get_mut(&old_url())
            .unwrap()
            .body
            .pop();
        let size_provider = provider(size_transport);
        let error = size_provider
            .releases(&SolverKey::InstalledName(
                PackageName::new("Matrix").unwrap(),
            ))
            .unwrap_err();
        assert_eq!(
            error.category(),
            CandidateLoadErrorCategory::TransportFailure
        );
        assert!(error.diagnostic().contains("size mismatch"));
    }

    #[test]
    fn runtime_loader_size_mismatch_is_a_hard_acquisition_error() {
        let mut transport = FixtureTransport::fallback(Vec::new(), 404);
        transport.responses.get_mut(&old_url()).unwrap().body.pop();
        let loader = runtime_loader(transport);
        let error = loader
            .releases(&SolverKey::InstalledName(
                PackageName::new("Matrix").unwrap(),
            ))
            .unwrap_err();
        assert_eq!(
            error.category(),
            CandidateLoadErrorCategory::TransportFailure
        );
        assert!(error.diagnostic().contains("size mismatch"));
    }
}
