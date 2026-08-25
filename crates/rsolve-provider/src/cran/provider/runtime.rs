use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

#[cfg(test)]
use super::super::archive_index::provider_rds_read_options;
use super::super::catalog::{CranArchiveReleaseRejection, CranCatalog};
use super::super::evidence::CranEvidenceObservation;
#[cfg(test)]
use super::super::history::enumerate_archive_rds_for_provider;
use super::super::history::{ArchiveEntry, ArchiveHistoryRejection};
use super::snapshot::source_input;
#[cfg(test)]
use super::{
    CranFastPathStatus, CranProviderError, CranRefreshSource, TransportError, provider_error,
};
use super::{CranRefreshDiagnostic, Transport, extract_description};
use crate::cran::provider::snapshot::tarball_record_to_evidence;
use rsolve_core::{
    CandidateLoadError, CandidateLoadErrorCategory, CandidateLoadResult, CandidateLoader,
    PackageName, PackageRelease, QuarantinedCandidate, SolverKey,
};

pub(super) enum CandidateSource {
    Fast {
        catalog: CranCatalog,
        rejections: Rc<[CranArchiveReleaseRejection]>,
    },
    Fallback {
        entries: Rc<[ArchiveEntry]>,
        rejections: Rc<[ArchiveHistoryRejection]>,
    },
}

/// A refreshed CRAN candidate source.
pub(crate) struct CranProvider<T> {
    package: PackageName,
    transport: RefCell<T>,
    base_url: Box<str>,
    source: CandidateSource,
    diagnostics: Vec<CranRefreshDiagnostic>,
    loaded: RefCell<Option<Result<CandidateLoadResult, CandidateLoadError>>>,
    evidence: Option<Rc<RefCell<Vec<CranEvidenceObservation>>>>,
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
            match CranCatalog::from_archive_index_rds_with_options(
                &response.body,
                &provider_rds_read_options(),
            ) {
                Ok(catalog) => {
                    diagnostics.push(CranRefreshDiagnostic {
                        endpoint: endpoint.clone().into_boxed_str(),
                        status: Some(response.status),
                        status_detail: CranFastPathStatus::Available,
                        source: CranRefreshSource::ArchiveFastPath,
                    });
                    CandidateSource::Fast {
                        catalog,
                        rejections: Rc::from(Vec::new().into_boxed_slice()),
                    }
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
                status_detail: if matches!(response.status, 404 | 410) {
                    CranFastPathStatus::Unsupported {
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
            evidence: None,
        })
    }

    pub(crate) fn diagnostics(&self) -> &[CranRefreshDiagnostic] {
        &self.diagnostics
    }

    pub(super) fn from_source(
        transport: T,
        base_url: impl AsRef<str>,
        package: PackageName,
        source: CandidateSource,
        diagnostics: Vec<CranRefreshDiagnostic>,
        evidence: Option<Rc<RefCell<Vec<CranEvidenceObservation>>>>,
    ) -> Self {
        Self {
            package,
            transport: RefCell::new(transport),
            base_url: base_url.as_ref().trim_end_matches('/').into(),
            source,
            diagnostics,
            loaded: RefCell::new(None),
            evidence,
        }
    }

    #[cfg(test)]
    fn fallback_source(
        transport: &T,
        base_url: &str,
    ) -> Result<CandidateSource, CranProviderError> {
        let endpoint = format!("{base_url}/src/contrib/Meta/archive.rds");
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
        let projection = enumerate_archive_rds_for_provider(&response.body)
            .map_err(CranProviderError::History)?;
        Ok(CandidateSource::Fallback {
            entries: Rc::from(projection.entries.into_boxed_slice()),
            rejections: Rc::from(projection.rejections.into_boxed_slice()),
        })
    }

    fn load_fallback(
        &self,
        entries: &[ArchiveEntry],
        rejections: &[ArchiveHistoryRejection],
    ) -> Result<CandidateLoadResult, CandidateLoadError> {
        let package_rejections = rejections
            .iter()
            .filter(|rejection| rejection.package_hint() == &self.package)
            .collect::<Vec<_>>();
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
            let catalog = CranCatalog::from_description(&description).map_err(|error| {
                CandidateLoadError::new(
                    CandidateLoadErrorCategory::MetadataInvalid,
                    format!(
                        "invalid DESCRIPTION in {}: {error}",
                        entry.source_archive_relative_path()
                    ),
                )
            })?;
            if let Some(evidence) = &self.evidence {
                let source = source_input("cran-archive-tarball", "tar.gz", &url, &response.body);
                let records =
                    CranCatalog::observations_from_description(&description).map_err(|error| {
                        CandidateLoadError::new(
                            CandidateLoadErrorCategory::MetadataInvalid,
                            format!(
                                "invalid DESCRIPTION in {}: {error}",
                                entry.source_archive_relative_path()
                            ),
                        )
                    })?;
                let mut captured = evidence.borrow_mut();
                for record in records
                    .iter()
                    .filter(|record| record.package() == entry.package())
                {
                    captured.push(tarball_record_to_evidence(
                        record,
                        source.clone(),
                        url.clone(),
                        response.body.len() as u64,
                    ));
                }
            }
            releases.extend(catalog.candidates(entry.package()).iter().cloned());
        }
        let quarantined = package_rejections
            .iter()
            .filter_map(|rejection| {
                rejection.version().map(|version| {
                    QuarantinedCandidate::new(version.clone(), rejection.diagnostic())
                })
            })
            .collect::<Vec<_>>();
        if releases.is_empty() && !package_rejections.is_empty() && quarantined.is_empty() {
            return Err(CandidateLoadError::new(
                CandidateLoadErrorCategory::MetadataInvalid,
                format!(
                    "CRAN archive history has no usable releases for {} after quarantining: {}",
                    self.package,
                    package_rejections
                        .iter()
                        .map(|rejection| rejection.diagnostic())
                        .collect::<Vec<_>>()
                        .join("; ")
                ),
            ));
        }
        Ok(CandidateLoadResult::new(releases, quarantined))
    }
}

impl<T: Transport> CandidateLoader for CranProvider<T> {
    fn releases(&self, package: &SolverKey) -> Result<Vec<PackageRelease>, CandidateLoadError> {
        let result = self.load(package)?;
        if result.candidates().is_empty() && !result.quarantined().is_empty() {
            return Err(CandidateLoadError::new(
                CandidateLoadErrorCategory::MetadataInvalid,
                format!("CRAN archive history has no eligible releases for {package:?}"),
            ));
        }
        Ok(result.into_parts().0)
    }

    fn load(&self, package: &SolverKey) -> Result<CandidateLoadResult, CandidateLoadError> {
        let SolverKey::InstalledName(name) = package else {
            return Err(CandidateLoadError::new(
                CandidateLoadErrorCategory::NotFound,
                format!("CRAN provider has no candidates for {package:?}"),
            ));
        };
        if name != &self.package {
            return Ok(CandidateLoadResult::new(Vec::new(), Vec::new()));
        }
        if let Some(result) = self.loaded.borrow().as_ref() {
            return result.clone();
        }
        let result = match &self.source {
            CandidateSource::Fast {
                catalog,
                rejections,
            } => {
                let candidates = catalog.candidates(&self.package).to_vec();
                let quarantined = rejections
                    .iter()
                    .filter_map(|rejection| {
                        rejection.version().map(|version| {
                            QuarantinedCandidate::new(
                                version.clone(),
                                rejection.diagnostic().to_string(),
                            )
                        })
                    })
                    .collect::<Vec<_>>();
                if candidates.is_empty() && !rejections.is_empty() && quarantined.is_empty() {
                    Err(CandidateLoadError::new(
                        CandidateLoadErrorCategory::MetadataInvalid,
                        format!(
                            "CRAN archive index has no usable releases for {} after quarantining: {}",
                            self.package,
                            rejections
                                .iter()
                                .map(|rejection| rejection.diagnostic().to_string())
                                .collect::<Vec<_>>()
                                .join("; ")
                        ),
                    ))
                } else {
                    Ok(CandidateLoadResult::new(candidates, quarantined))
                }
            }
            CandidateSource::Fallback {
                entries,
                rejections,
            } => self.load_fallback(entries, rejections),
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

    fn load(&self, package: &SolverKey) -> Result<CandidateLoadResult, CandidateLoadError> {
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
            CachedProvider::Ready(provider) => provider.load(package),
            CachedProvider::Failed(error) => Err(error.clone()),
        }
    }
}

/// A transport-free, process-local view handed to the resolver after refresh.
#[derive(Clone, Debug, Default)]
pub struct CranCandidateSnapshot {
    pub(super) candidates: HashMap<PackageName, Vec<PackageRelease>>,
    pub(super) quarantined: HashMap<PackageName, Vec<QuarantinedCandidate>>,
}

impl CandidateLoader for CranCandidateSnapshot {
    fn releases(&self, package: &SolverKey) -> Result<Vec<PackageRelease>, CandidateLoadError> {
        let result = self.load(package)?;
        if result.candidates().is_empty() && !result.quarantined().is_empty() {
            return Err(CandidateLoadError::new(
                CandidateLoadErrorCategory::MetadataInvalid,
                format!("CRAN snapshot has no eligible releases for {package:?}"),
            ));
        }
        Ok(result.into_parts().0)
    }

    fn load(&self, package: &SolverKey) -> Result<CandidateLoadResult, CandidateLoadError> {
        let SolverKey::InstalledName(name) = package else {
            return Err(CandidateLoadError::new(
                CandidateLoadErrorCategory::NotFound,
                format!("CRAN snapshot has no candidates for {package:?}"),
            ));
        };
        let candidates = self.candidates.get(name).cloned().ok_or_else(|| {
            CandidateLoadError::new(
                CandidateLoadErrorCategory::NotFound,
                format!("CRAN snapshot has not refreshed package {name}"),
            )
        })?;
        Ok(CandidateLoadResult::new(
            candidates,
            self.quarantined.get(name).cloned().unwrap_or_default(),
        ))
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
            quarantined: HashMap::new(),
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
