//! Coordination of composed registry repositories.
//!
//! This module owns only the orchestration boundary. Registry-specific
//! parsing, transport, and snapshot formats remain in their provider crates.

use std::collections::BTreeSet;

use crate::manifest::{ComposedEnvironment, ManifestError, RegistrySpec, RepositorySpec};
use crate::metrics::ResolutionMetrics;
use crate::orchestration::{
    CompositeCandidateLoader, CranResolutionError, RawCandidateLoader, RepositoryCandidateLoader,
    resolve_prepared_request,
};
use crate::prepared_snapshot::plan_repository_acquisition;
use crate::progress::ProgressCallback;
use rsolve_core::{CandidateLoader, PackageName, RepositoryRank};
use rsolve_provider::r_universe::{
    RUniverseProvider, RUniverseProviderError, UreqRUniverseTransport,
};

mod demand;
use demand::{RepositoryDemandSource, initial_repository_demands, resolve_repository_demands};

/// The transport-free result of resolving a composed repository graph.
pub(crate) struct RepositoryResolutionOutcome {
    pub(crate) resolution: rsolve_core::Resolution,
    pub(crate) metrics: ResolutionMetrics,
    pub(crate) warnings: Vec<String>,
}

trait RUniverseSession {
    fn open_compatible(
        &self,
        store: &rsolve_provider::SnapshotStore,
        allowlist: Option<&[PackageName]>,
    ) -> Result<Box<dyn RawCandidateLoader>, RUniverseProviderError>;

    fn open_compatible_offline(
        &self,
        store: &rsolve_provider::SnapshotStore,
        allowlist: Option<&[PackageName]>,
    ) -> Result<Box<dyn RawCandidateLoader>, RUniverseProviderError>;

    fn refresh_snapshot(
        &self,
        store: &rsolve_provider::SnapshotStore,
        allowlist: Option<&[PackageName]>,
    ) -> Result<Box<dyn RawCandidateLoader>, RUniverseProviderError>;
}

impl<T: rsolve_provider::r_universe::RUniverseTransport> RUniverseSession for RUniverseProvider<T> {
    fn open_compatible(
        &self,
        store: &rsolve_provider::SnapshotStore,
        allowlist: Option<&[PackageName]>,
    ) -> Result<Box<dyn RawCandidateLoader>, RUniverseProviderError> {
        RUniverseProvider::open_compatible(self, store, allowlist)
            .map(|loader| Box::new(loader) as Box<dyn RawCandidateLoader>)
    }

    fn refresh_snapshot(
        &self,
        store: &rsolve_provider::SnapshotStore,
        allowlist: Option<&[PackageName]>,
    ) -> Result<Box<dyn RawCandidateLoader>, RUniverseProviderError> {
        RUniverseProvider::refresh_snapshot(self, store, allowlist)
            .map(|loader| Box::new(loader) as Box<dyn RawCandidateLoader>)
    }

    fn open_compatible_offline(
        &self,
        store: &rsolve_provider::SnapshotStore,
        allowlist: Option<&[PackageName]>,
    ) -> Result<Box<dyn RawCandidateLoader>, RUniverseProviderError> {
        RUniverseProvider::open_compatible_offline(self, store, allowlist)
            .map(|loader| Box::new(loader) as Box<dyn RawCandidateLoader>)
    }
}

trait RUniverseProviderFactory {
    fn create(
        &self,
        endpoint: &str,
        registry: rsolve_core::RegistryId,
    ) -> Result<Box<dyn RUniverseSession>, RUniverseProviderError>;
}

struct DefaultRUniverseProviderFactory;

impl RUniverseProviderFactory for DefaultRUniverseProviderFactory {
    fn create(
        &self,
        endpoint: &str,
        registry: rsolve_core::RegistryId,
    ) -> Result<Box<dyn RUniverseSession>, RUniverseProviderError> {
        Ok(Box::new(RUniverseProvider::new(
            endpoint,
            registry,
            UreqRUniverseTransport::default(),
        )?))
    }
}

trait CranProviderFactory {
    #[allow(clippy::type_complexity)]
    #[allow(clippy::too_many_arguments)]
    fn prepare(
        &self,
        repository: &RepositorySpec,
        roots: &[rsolve_core::RootRequirement],
        optional_demands: &[PackageName],
        metadata_cache: &crate::metadata_cache::MetadataCache,
        offline: bool,
        refresh_metadata: bool,
        publication_cutoff: Option<rsolve_core::PublicationDate>,
        progress: Option<ProgressCallback>,
    ) -> Result<CranPreparationOutcome, RepositoryResolutionError>;
}

struct CranPreparationOutcome {
    loader: Option<Box<dyn RawCandidateLoader>>,
    warnings: Vec<String>,
    metrics: ResolutionMetrics,
}

struct DefaultCranProviderFactory;

impl CranProviderFactory for DefaultCranProviderFactory {
    #[allow(clippy::too_many_arguments)]
    fn prepare(
        &self,
        repository: &RepositorySpec,
        roots: &[rsolve_core::RootRequirement],
        optional_demands: &[PackageName],
        metadata_cache: &crate::metadata_cache::MetadataCache,
        offline: bool,
        refresh_metadata: bool,
        publication_cutoff: Option<rsolve_core::PublicationDate>,
        progress: Option<ProgressCallback>,
    ) -> Result<CranPreparationOutcome, RepositoryResolutionError> {
        let registry = repository
            .configured_registry_id()
            .map_err(RepositoryResolutionError::Composition)?;
        let store = metadata_cache
            .open_store(registry)
            .map_err(RepositoryResolutionError::Cache)?;
        crate::prepared_snapshot::prepare_cran_repository_loader_with_optional_demands(
            repository,
            &store,
            roots,
            optional_demands,
            offline,
            refresh_metadata,
            publication_cutoff,
            progress,
        )
        .map(|(loader, warnings, metrics)| CranPreparationOutcome {
            loader: loader.map(|loader| loader as Box<dyn RawCandidateLoader>),
            warnings,
            metrics,
        })
        .map_err(RepositoryResolutionError::Cran)
    }
}

pub(crate) fn resolve_composed(
    composed: ComposedEnvironment,
    metadata_cache: &crate::metadata_cache::MetadataCache,
    offline: bool,
    refresh_metadata: bool,
    progress: Option<ProgressCallback>,
) -> Result<RepositoryResolutionOutcome, RepositoryResolutionError> {
    let factory = DefaultRUniverseProviderFactory;
    let cran_factory = DefaultCranProviderFactory;
    resolve_composed_with_factory(
        composed,
        metadata_cache,
        offline,
        refresh_metadata,
        progress,
        &factory,
        &cran_factory,
    )
}

fn resolve_composed_with_factory(
    composed: ComposedEnvironment,
    metadata_cache: &crate::metadata_cache::MetadataCache,
    offline: bool,
    refresh_metadata: bool,
    progress: Option<ProgressCallback>,
    provider_factory: &dyn RUniverseProviderFactory,
    cran_factory: &dyn CranProviderFactory,
) -> Result<RepositoryResolutionOutcome, RepositoryResolutionError> {
    composed
        .clone()
        .into_resolution_request()
        .map_err(RepositoryResolutionError::Composition)?;
    validate_repository_set(&composed)?;
    plan_repository_acquisition(&composed.repositories, &composed.roots, &[])
        .map_err(RepositoryResolutionError::Composition)?;
    let request = composed
        .clone()
        .into_resolution_request()
        .map_err(RepositoryResolutionError::Composition)?;

    let needs_provider = composed
        .roots
        .iter()
        .any(crate::manifest::is_remote_cran_root_intent);
    if !needs_provider {
        let empty = EmptyCandidateLoader;
        return finish(request, &empty, progress);
    }

    let mut snapshots: Vec<Box<dyn RawCandidateLoader>> = Vec::new();
    let mut warnings = Vec::new();
    let mut snapshot_indices = vec![None; composed.repositories.len()];
    let mut prepared_groups = BTreeSet::<(String, String)>::new();
    let mut cran_roots = Vec::<rsolve_core::RootRequirement>::new();
    let mut cran_iteration = 0;
    let mut preparation_metrics = ResolutionMetrics::default();

    let cran_index = composed
        .repositories
        .iter()
        .position(|repository| matches!(repository.registry(), RegistrySpec::Cran));
    let initial_demands = initial_repository_demands(&composed.repositories, &composed.roots);

    if let Some(index) = cran_index {
        let initial_optional = initial_demands
            .get(&index)
            .into_iter()
            .flatten()
            .filter(|package| {
                !composed.roots.iter().any(|root| {
                    root.name == **package
                        && matches!(
                            root.source,
                            crate::manifest::ManifestSource::Registry {
                                repository: Some(ref repository)
                            } if repository == composed.repositories[index].id()
                        )
                })
            })
            .cloned()
            .collect::<Vec<_>>();
        for package in initial_demands.get(&index).into_iter().flatten().cloned() {
            cran_roots.push(root_requirement(package)?);
        }
        if !cran_roots.is_empty() {
            let prepared = cran_factory.prepare(
                &composed.repositories[index],
                &cran_roots,
                &initial_optional,
                metadata_cache,
                offline,
                refresh_requested(refresh_metadata, cran_iteration),
                composed.published_before,
                progress.clone(),
            )?;
            warnings.extend(prepared.warnings);
            merge_metrics(&mut preparation_metrics, &prepared.metrics);
            cran_iteration += 1;
            if let Some(loader) = prepared.loader {
                snapshot_indices[index] = Some(snapshots.len());
                snapshots.push(loader);
            }
        }
    }

    loop {
        let mut source = SnapshotDemandSource {
            composed: &composed,
            snapshots: &snapshots,
            snapshot_indices: &snapshot_indices,
        };
        let plan = resolve_repository_demands(&composed.repositories, &composed.roots, &mut source)
            .map_err(|error| {
                RepositoryResolutionError::Cran(CranResolutionError::Refresh(error))
            })?;
        let mut prepared = false;

        if let Some(index) = cran_index {
            let current_cran = snapshot_indices[index].map(|snapshot_index| {
                snapshots[snapshot_index].as_ref() as &dyn RawCandidateLoader
            });
            let mut missing_cran_demand = false;
            for package in plan
                .entry_demands
                .get(&index)
                .into_iter()
                .flatten()
                .cloned()
            {
                let covered = current_cran
                    .map(|loader| raw_package_is_covered(loader, &package))
                    .transpose()
                    .map_err(|error| {
                        RepositoryResolutionError::Cran(CranResolutionError::Refresh(error))
                    })?
                    .unwrap_or(false);
                if !covered
                    && cran_roots
                        .iter()
                        .all(|root| root.package.name() != &package)
                {
                    cran_roots.push(root_requirement(package)?);
                    missing_cran_demand = true;
                }
            }
            if missing_cran_demand {
                // Rebuild the CRAN immutable view when a new cross-provider
                // demand appears. Forced refresh is intentionally limited to
                // the first preparation in this operation.
                let cran_prepared = cran_factory.prepare(
                    &composed.repositories[index],
                    &cran_roots,
                    &cran_optional_demands(&composed, &plan, index),
                    metadata_cache,
                    offline,
                    refresh_requested(refresh_metadata, cran_iteration),
                    composed.published_before,
                    progress.clone(),
                )?;
                warnings.extend(cran_prepared.warnings);
                merge_metrics(&mut preparation_metrics, &cran_prepared.metrics);
                cran_iteration += 1;
                if let Some(loader) = cran_prepared.loader {
                    if let Some(snapshot_index) = snapshot_indices[index] {
                        snapshots[snapshot_index] = loader;
                    } else {
                        snapshot_indices[index] = Some(snapshots.len());
                        snapshots.push(loader);
                    }
                }
                prepared = true;
            }
        }

        for index in 0..composed.repositories.len() {
            let repository = &composed.repositories[index];
            if !matches!(repository.registry(), RegistrySpec::RUniverse)
                || !plan.entry_demands.contains_key(&index)
            {
                continue;
            }
            let registry = repository
                .configured_registry_id()
                .map_err(RepositoryResolutionError::Composition)?;
            let endpoint = repository.manifest_endpoint().as_str().to_owned();
            let group = (registry.to_string(), endpoint.clone());
            if prepared_groups.contains(&group) {
                continue;
            }
            let scope = r_universe_group_scope(&composed.repositories, &registry, &endpoint);
            let store = metadata_cache
                .open_store(registry.clone())
                .map_err(RepositoryResolutionError::Cache)?;
            let provider = provider_factory
                .create(&endpoint, registry.clone())
                .map_err(RepositoryResolutionError::RUniverse)?;
            let loader = if offline {
                provider
                    .open_compatible_offline(&store, scope.as_deref())
                    .map_err(RepositoryResolutionError::RUniverse)?
            } else if refresh_metadata {
                provider
                    .refresh_snapshot(&store, scope.as_deref())
                    .map_err(RepositoryResolutionError::RUniverse)?
            } else {
                match provider.open_compatible(&store, scope.as_deref()) {
                    Ok(loader) => loader,
                    Err(
                        rsolve_provider::r_universe::RUniverseProviderError::OfflineMissing(_)
                        | rsolve_provider::r_universe::RUniverseProviderError::OfflineIncompatible(_)
                        | rsolve_provider::r_universe::RUniverseProviderError::OfflineCorrupt(_),
                    ) => provider
                        .refresh_snapshot(&store, scope.as_deref())
                        .map_err(RepositoryResolutionError::RUniverse)?,
                    Err(error) => return Err(RepositoryResolutionError::RUniverse(error)),
                }
            };
            let snapshot_index = snapshots.len();
            snapshots.push(loader);
            prepared_groups.insert(group);
            for (candidate_index, candidate) in composed.repositories.iter().enumerate() {
                if matches!(candidate.registry(), RegistrySpec::RUniverse)
                    && candidate.configured_registry_id().ok().as_ref() == Some(&registry)
                    && candidate.manifest_endpoint().as_str() == endpoint
                {
                    snapshot_indices[candidate_index] = Some(snapshot_index);
                }
            }
            prepared = true;
        }

        if !prepared {
            break;
        }
    }

    // A repository-qualified R-universe root is an explicit acquisition
    // request. Report its verified absence at the provider boundary instead
    // of allowing it to degrade into a generic solver no-solution result or a
    // CRAN fallback.
    for root in &composed.roots {
        let crate::manifest::ManifestSource::Registry {
            repository: Some(repository_id),
        } = &root.source
        else {
            continue;
        };
        let Some(index) = composed.repositories.iter().position(|repository| {
            repository.id() == repository_id
                && matches!(repository.registry(), RegistrySpec::RUniverse)
        }) else {
            continue;
        };
        let Some(snapshot_index) = snapshot_indices[index] else {
            return Err(RepositoryResolutionError::RUniverse(
                RUniverseProviderError::PackageNotFound {
                    endpoint: composed.repositories[index]
                        .manifest_endpoint()
                        .as_str()
                        .to_owned(),
                    package: root.name.to_string(),
                },
            ));
        };
        match snapshots[snapshot_index]
            .load_raw(&rsolve_core::SolverKey::InstalledName(root.name.clone()))
        {
            Ok(result) if !result.observations().is_empty() => {}
            Ok(_) => {
                return Err(RepositoryResolutionError::RUniverse(
                    RUniverseProviderError::PackageNotFound {
                        endpoint: composed.repositories[index]
                            .manifest_endpoint()
                            .as_str()
                            .to_owned(),
                        package: root.name.to_string(),
                    },
                ));
            }
            Err(error) if error.category() == rsolve_core::CandidateLoadErrorCategory::NotFound => {
                return Err(RepositoryResolutionError::RUniverse(
                    RUniverseProviderError::PackageNotFound {
                        endpoint: composed.repositories[index]
                            .manifest_endpoint()
                            .as_str()
                            .to_owned(),
                        package: root.name.to_string(),
                    },
                ));
            }
            Err(error) => return Err(RepositoryResolutionError::Candidate(error)),
        }
    }

    let mut repository_loaders = Vec::with_capacity(composed.repositories.len());
    for (index, repository) in composed.repositories.iter().enumerate() {
        let Some(snapshot_index) = snapshot_indices[index] else {
            continue;
        };
        let snapshot = snapshots[snapshot_index].as_ref();
        repository_loaders.push(RepositoryCandidateLoader::with_package_allowlist(
            snapshot,
            repository.id().clone(),
            repository
                .configured_registry_id()
                .map_err(RepositoryResolutionError::Composition)?,
            RepositoryRank::new(index as u64),
            repository.packages(),
        ));
    }
    let loader_refs = repository_loaders
        .iter()
        .map(|loader| loader as &dyn CandidateLoader)
        .collect::<Vec<_>>();
    let composite_loader = CompositeCandidateLoader::new(loader_refs);
    if let Some(progress) = &progress {
        progress(crate::progress::ProgressEvent::ResolveStarted);
    }
    let outcome = resolve_prepared_request(request, &composite_loader)
        .map_err(RepositoryResolutionError::Cran)?;
    if let Some(progress) = &progress {
        progress(crate::progress::ProgressEvent::ResolveCompleted {
            packages: outcome.resolution().packages().len(),
        });
    }
    let mut metrics = outcome.metrics().clone();
    merge_metrics(&mut metrics, &preparation_metrics);
    Ok(RepositoryResolutionOutcome {
        resolution: outcome.resolution().clone(),
        metrics,
        warnings,
    })
}

struct SnapshotDemandSource<'a> {
    composed: &'a ComposedEnvironment,
    snapshots: &'a [Box<dyn RawCandidateLoader>],
    snapshot_indices: &'a [Option<usize>],
}

fn raw_package_is_covered(
    loader: &dyn RawCandidateLoader,
    package: &PackageName,
) -> Result<bool, rsolve_core::CandidateLoadError> {
    match loader.load_raw(&rsolve_core::SolverKey::InstalledName(package.clone())) {
        Ok(result) => Ok(!result.observations().is_empty()),
        Err(error) if error.category() == rsolve_core::CandidateLoadErrorCategory::NotFound => {
            Ok(false)
        }
        Err(error) => Err(error),
    }
}

fn root_requirement(
    package: PackageName,
) -> Result<rsolve_core::RootRequirement, RepositoryResolutionError> {
    let requirement = rsolve_core::PackageRequirement::new(
        package,
        rsolve_core::DependencySourceConstraint::Any,
        rsolve_core::VersionConstraint::unconstrained(),
    )
    .map_err(|error| {
        RepositoryResolutionError::Composition(ManifestError::InvalidDependency(error.to_string()))
    })?;
    Ok(rsolve_core::RootRequirement {
        package: requirement,
        expansion: rsolve_core::RootExpansionPolicy::HardOnly,
    })
}

impl RepositoryDemandSource for SnapshotDemandSource<'_> {
    fn load(
        &mut self,
        entry: usize,
        package: &PackageName,
    ) -> Result<Vec<rsolve_core::PackageRelease>, rsolve_core::CandidateLoadError> {
        let repository = &self.composed.repositories[entry];
        if !repository.package_allowed(package) {
            return Ok(Vec::new());
        }
        let Some(snapshot_index) = self.snapshot_indices[entry] else {
            return Ok(Vec::new());
        };
        let result = self.snapshots[snapshot_index]
            .load_raw(&rsolve_core::SolverKey::InstalledName(package.clone()))?;
        Ok(result
            .observations()
            .iter()
            .map(|observation| observation.release().clone())
            .collect())
    }
}

fn refresh_requested(force: bool, iteration: usize) -> bool {
    force && iteration == 0
}

fn merge_metrics(target: &mut ResolutionMetrics, source: &ResolutionMetrics) {
    target.metrics_overflow |= source.metrics_overflow;
    merge_duration(
        &mut target.phases.snapshot_cache_decision_ns,
        source.phases.snapshot_cache_decision_ns,
        &mut target.metrics_overflow,
    );
    merge_duration(
        &mut target.phases.refresh_acquisition_ns,
        source.phases.refresh_acquisition_ns,
        &mut target.metrics_overflow,
    );
    merge_duration(
        &mut target.phases.closure_lookup_ns,
        source.phases.closure_lookup_ns,
        &mut target.metrics_overflow,
    );
    merge_duration(
        &mut target.phases.snapshot_composition_and_publication_ns,
        source.phases.snapshot_composition_and_publication_ns,
        &mut target.metrics_overflow,
    );
    target.loader_lookup_calls = target
        .loader_lookup_calls
        .saturating_add(source.loader_lookup_calls);
    target.loader_unique_package_count = target
        .loader_unique_package_count
        .max(source.loader_unique_package_count);
    if let Some(source_provider) = &source.provider_refresh {
        if let Some(target_provider) = &mut target.provider_refresh {
            merge_refresh_metrics(
                target_provider,
                source_provider,
                &mut target.metrics_overflow,
            );
        } else {
            target.provider_refresh = Some(source_provider.clone());
        }
    }
    target.snapshot_cache_decision = source
        .snapshot_cache_decision
        .or(target.snapshot_cache_decision);
}

fn merge_refresh_metrics(
    target: &mut rsolve_provider::cran::CranRefreshMetrics,
    source: &rsolve_provider::cran::CranRefreshMetrics,
    overflow: &mut bool,
) {
    add_counter(&mut target.http_attempts, source.http_attempts, overflow);
    add_counter(
        &mut target.successful_response_body_bytes,
        source.successful_response_body_bytes,
        overflow,
    );
    add_counter(
        &mut target.statuses.status_200,
        source.statuses.status_200,
        overflow,
    );
    add_counter(
        &mut target.statuses.status_304,
        source.statuses.status_304,
        overflow,
    );
    add_counter(
        &mut target.statuses.status_404,
        source.statuses.status_404,
        overflow,
    );
    add_counter(
        &mut target.statuses.status_410,
        source.statuses.status_410,
        overflow,
    );
    add_counter(&mut target.statuses.other, source.statuses.other, overflow);
    merge_source_metrics(&mut target.current_index, &source.current_index, overflow);
    merge_source_metrics(
        &mut target.archive_history,
        &source.archive_history,
        overflow,
    );
    merge_source_metrics(&mut target.allpackages, &source.allpackages, overflow);
    merge_source_metrics(
        &mut target.package_local_index,
        &source.package_local_index,
        overflow,
    );
    merge_source_metrics(
        &mut target.tarball_description,
        &source.tarball_description,
        overflow,
    );
    add_counter(&mut target.raw_cache_hits, source.raw_cache_hits, overflow);
    add_counter(
        &mut target.raw_cache_misses,
        source.raw_cache_misses,
        overflow,
    );
    add_counter(
        &mut target.raw_cache_corrupt,
        source.raw_cache_corrupt,
        overflow,
    );
    add_counter(
        &mut target.projection_reuses,
        source.projection_reuses,
        overflow,
    );
    add_counter(
        &mut target.projection_builds,
        source.projection_builds,
        overflow,
    );
    add_counter(
        &mut target.projection_rebuilds,
        source.projection_rebuilds,
        overflow,
    );
    add_counter(
        &mut target.package_history_lookups,
        source.package_history_lookups,
        overflow,
    );
    add_counter(
        &mut target.allpackages_adoptions,
        source.allpackages_adoptions,
        overflow,
    );
    add_counter(
        &mut target.package_local_fallbacks,
        source.package_local_fallbacks,
        overflow,
    );
    add_counter(
        &mut target.quarantined_releases,
        source.quarantined_releases,
        overflow,
    );
    add_counter(&mut target.coverage_gaps, source.coverage_gaps, overflow);
    add_counter(
        &mut target.coverage_conflicts,
        source.coverage_conflicts,
        overflow,
    );
}

fn merge_source_metrics(
    target: &mut rsolve_provider::cran::CranRefreshSourceMetrics,
    source: &rsolve_provider::cran::CranRefreshSourceMetrics,
    overflow: &mut bool,
) {
    add_counter(&mut target.requests, source.requests, overflow);
    add_counter(
        &mut target.successful_body_bytes,
        source.successful_body_bytes,
        overflow,
    );
}

fn add_counter(target: &mut u64, source: u64, overflow: &mut bool) {
    match target.checked_add(source) {
        Some(total) => *target = total,
        None => {
            *target = u64::MAX;
            *overflow = true;
        }
    }
}

fn merge_duration(target: &mut Option<u64>, source: Option<u64>, overflow: &mut bool) {
    let Some(source) = source else {
        return;
    };
    let current = target.unwrap_or_default();
    match current.checked_add(source) {
        Some(total) => *target = Some(total),
        None => {
            *target = None;
            *overflow = true;
        }
    }
}

fn cran_optional_demands(
    composed: &ComposedEnvironment,
    plan: &demand::RepositoryDemandPlan,
    cran_index: usize,
) -> Vec<PackageName> {
    plan.entry_demands
        .get(&cran_index)
        .into_iter()
        .flatten()
        .filter(|package| {
            !composed.roots.iter().any(|root| {
                root.name == **package
                    && matches!(
                        root.source,
                        crate::manifest::ManifestSource::Registry {
                            repository: Some(ref repository)
                        } if repository == composed.repositories[cran_index].id()
                    )
            })
        })
        .cloned()
        .collect()
}

fn finish(
    request: rsolve_core::ResolutionRequest,
    loader: &dyn CandidateLoader,
    progress: Option<ProgressCallback>,
) -> Result<RepositoryResolutionOutcome, RepositoryResolutionError> {
    if let Some(progress) = &progress {
        progress(crate::progress::ProgressEvent::ResolveStarted);
    }
    let outcome =
        resolve_prepared_request(request, loader).map_err(RepositoryResolutionError::Cran)?;
    if let Some(progress) = &progress {
        progress(crate::progress::ProgressEvent::ResolveCompleted {
            packages: outcome.resolution().packages().len(),
        });
    }
    Ok(RepositoryResolutionOutcome {
        resolution: outcome.resolution().clone(),
        metrics: outcome.metrics().clone(),
        warnings: Vec::new(),
    })
}

fn r_universe_group_scope(
    repositories: &[RepositorySpec],
    registry: &rsolve_core::RegistryId,
    endpoint: &str,
) -> Option<Vec<PackageName>> {
    let mut packages = BTreeSet::new();
    let mut unrestricted = false;
    for repository in repositories {
        if !matches!(repository.registry(), RegistrySpec::RUniverse)
            || repository.configured_registry_id().ok().as_ref() != Some(registry)
            || repository.manifest_endpoint().as_str() != endpoint
        {
            continue;
        }
        match repository.packages() {
            Some(values) => packages.extend(values.iter().cloned()),
            None => unrestricted = true,
        }
    }
    (!unrestricted).then(|| packages.into_iter().collect())
}

fn validate_repository_set(
    composed: &ComposedEnvironment,
) -> Result<(), RepositoryResolutionError> {
    let cran_count = composed
        .repositories
        .iter()
        .filter(|repository| matches!(repository.registry(), RegistrySpec::Cran))
        .count();
    if composed.repositories.iter().any(|repository| {
        !matches!(
            repository.registry(),
            RegistrySpec::Cran | RegistrySpec::RUniverse
        )
    }) {
        return Err(RepositoryResolutionError::Composition(
            ManifestError::InvalidRegistry {
                reason: "only CRAN and R-universe repositories are supported".into(),
            },
        ));
    }
    if composed
        .roots
        .iter()
        .any(crate::manifest::is_remote_cran_root_intent)
        && cran_count != 1
    {
        return Err(RepositoryResolutionError::Composition(
            ManifestError::InvalidRegistry {
                reason: "remote composed resolutions require one CRAN repository (R-universe repositories are optional and may be repeated)".into(),
            },
        ));
    }
    Ok(())
}

struct EmptyCandidateLoader;

impl CandidateLoader for EmptyCandidateLoader {
    fn releases(
        &self,
        _subject: &rsolve_core::SolverKey,
    ) -> Result<Vec<rsolve_core::PreparedCandidate>, rsolve_core::CandidateLoadError> {
        Ok(Vec::new())
    }
}

#[derive(Debug)]
pub(crate) enum RepositoryResolutionError {
    Composition(ManifestError),
    Cache(crate::metadata_cache::MetadataCacheError),
    Cran(CranResolutionError),
    RUniverse(rsolve_provider::r_universe::RUniverseProviderError),
    Candidate(rsolve_core::CandidateLoadError),
}

impl std::fmt::Display for RepositoryResolutionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Composition(error) => write!(formatter, "manifest composition failed: {error}"),
            Self::Cache(error) => write!(formatter, "metadata cache failed: {error}"),
            Self::Cran(error) => write!(formatter, "CRAN resolution failed: {error}"),
            Self::RUniverse(error) => write!(formatter, "R-universe resolution failed: {error}"),
            Self::Candidate(error) => {
                write!(formatter, "repository candidate loading failed: {error}")
            }
        }
    }
}

impl std::error::Error for RepositoryResolutionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Composition(error) => Some(error),
            Self::Cache(error) => Some(error),
            Self::Cran(error) => Some(error),
            Self::RUniverse(error) => Some(error),
            Self::Candidate(error) => Some(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::rc::Rc;

    use super::*;
    use crate::manifest::{ComposedRootIntent, ManifestSource};
    use rsolve_core::{
        DeclaredDependency, DependencyKind, DependencySourceConstraint, EnvironmentId,
        LockedIdentities, PackageNamespace, PackageRelease, Provenance, RPackageVersion,
        ReleaseIdentity, ReleaseMetadata, ReleaseObservation, ResolutionTarget, VersionConstraint,
    };
    use rsolve_provider::cran::CranCandidateSnapshot;
    use tempfile::tempdir;

    fn package(name: &str) -> PackageName {
        PackageName::new(name).expect("valid test package")
    }

    fn repository(id: &str, registry: RegistrySpec, packages: Option<&[&str]>) -> RepositorySpec {
        RepositorySpec::new_with_packages(
            rsolve_core::RepositoryId::new(id).expect("valid test repository"),
            registry,
            crate::manifest::Endpoint::new("https://example.test/root/").unwrap(),
            packages.map(|names| names.iter().map(|name| package(name)).collect()),
        )
        .unwrap()
    }

    #[derive(Clone, Default)]
    struct FactoryState {
        cran_prepares: usize,
        cran_roots: Vec<Vec<PackageName>>,
        cran_warning: bool,
        ru_creates: usize,
        ru_opens: usize,
        ru_refreshes: usize,
        ru_refresh_scopes: Vec<Option<Vec<PackageName>>>,
        ru_open_corrupt: bool,
    }

    struct FakeCranFactory {
        state: Rc<RefCell<FactoryState>>,
        snapshots: Vec<CranCandidateSnapshot>,
        fail_after: Option<usize>,
        return_none: bool,
    }

    impl CranProviderFactory for FakeCranFactory {
        fn prepare(
            &self,
            _repository: &RepositorySpec,
            roots: &[rsolve_core::RootRequirement],
            _optional_demands: &[PackageName],
            _metadata_cache: &crate::metadata_cache::MetadataCache,
            offline: bool,
            refresh_metadata: bool,
            _publication_cutoff: Option<rsolve_core::PublicationDate>,
            _progress: Option<ProgressCallback>,
        ) -> Result<CranPreparationOutcome, RepositoryResolutionError> {
            let mut state = self.state.borrow_mut();
            let call = state.cran_prepares;
            state.cran_prepares += 1;
            state.cran_roots.push(
                roots
                    .iter()
                    .map(|root| root.package.name().clone())
                    .collect(),
            );
            if self.fail_after == Some(call) {
                return Err(RepositoryResolutionError::Cran(CranResolutionError::Cache(
                    rsolve_provider::cran::CranSnapshotCacheDiagnostic::closure_incomplete(
                        &rsolve_core::CandidateLoadError::new(
                            rsolve_core::CandidateLoadErrorCategory::SnapshotInvalid,
                            "offline coverage is incomplete",
                        ),
                    ),
                )));
            }
            if self.return_none {
                return Ok(CranPreparationOutcome {
                    loader: None,
                    warnings: Vec::new(),
                    metrics: fixture_preparation_metrics(offline, refresh_metadata),
                });
            }
            let snapshot = self
                .snapshots
                .get(call)
                .or_else(|| self.snapshots.last())
                .cloned()
                .unwrap_or_default();
            let warnings = if state.cran_warning {
                vec![
                    "CRAN snapshot cache Stale: age 7200s; sources: https://cran.example.test/: detail"
                        .into(),
                ]
            } else {
                Vec::new()
            };
            Ok(CranPreparationOutcome {
                loader: Some(Box::new(snapshot)),
                warnings,
                metrics: fixture_preparation_metrics(offline, refresh_metadata),
            })
        }
    }

    struct FakeUniverseFactory {
        state: Rc<RefCell<FactoryState>>,
        snapshot: CranCandidateSnapshot,
        compatible: bool,
    }

    struct FakeUniverseSession {
        state: Rc<RefCell<FactoryState>>,
        snapshot: CranCandidateSnapshot,
        compatible: bool,
    }

    impl RUniverseSession for FakeUniverseSession {
        fn open_compatible(
            &self,
            _store: &rsolve_provider::SnapshotStore,
            _allowlist: Option<&[PackageName]>,
        ) -> Result<Box<dyn RawCandidateLoader>, RUniverseProviderError> {
            let mut state = self.state.borrow_mut();
            state.ru_opens += 1;
            if state.ru_open_corrupt {
                return Err(RUniverseProviderError::OfflineCorrupt(
                    "fixture has a corrupt snapshot".into(),
                ));
            }
            if !self.compatible {
                return Err(RUniverseProviderError::OfflineMissing(
                    "fixture has no compatible snapshot".into(),
                ));
            }
            Ok(Box::new(self.snapshot.clone()))
        }

        fn open_compatible_offline(
            &self,
            store: &rsolve_provider::SnapshotStore,
            allowlist: Option<&[PackageName]>,
        ) -> Result<Box<dyn RawCandidateLoader>, RUniverseProviderError> {
            self.open_compatible(store, allowlist)
        }

        fn refresh_snapshot(
            &self,
            _store: &rsolve_provider::SnapshotStore,
            allowlist: Option<&[PackageName]>,
        ) -> Result<Box<dyn RawCandidateLoader>, RUniverseProviderError> {
            let mut state = self.state.borrow_mut();
            state.ru_refreshes += 1;
            state
                .ru_refresh_scopes
                .push(allowlist.map(|packages| packages.to_vec()));
            Ok(Box::new(self.snapshot.clone()))
        }
    }

    impl RUniverseProviderFactory for FakeUniverseFactory {
        fn create(
            &self,
            _endpoint: &str,
            _registry: rsolve_core::RegistryId,
        ) -> Result<Box<dyn RUniverseSession>, RUniverseProviderError> {
            self.state.borrow_mut().ru_creates += 1;
            Ok(Box::new(FakeUniverseSession {
                state: Rc::clone(&self.state),
                snapshot: self.snapshot.clone(),
                compatible: self.compatible,
            }))
        }
    }

    fn release(name: &str, dependencies: &[(&str, DependencyKind)]) -> PackageRelease {
        let package_name = package(name);
        let version = RPackageVersion::parse("1.0.0").unwrap();
        let declared_dependencies = dependencies
            .iter()
            .map(|(dependency, kind)| {
                DeclaredDependency::from_parts(
                    *kind,
                    package(dependency),
                    DependencySourceConstraint::Any,
                    VersionConstraint::unconstrained(),
                )
                .unwrap()
            })
            .collect();
        PackageRelease::try_from(ReleaseObservation {
            identity: ReleaseIdentity::new(
                package_name.clone(),
                Provenance::RegistryRelease {
                    namespace: PackageNamespace::new("cran").unwrap(),
                    version: version.clone(),
                },
            ),
            observed_package: package_name,
            observed_version: version,
            metadata: ReleaseMetadata::new(BTreeMap::new()).unwrap(),
            publication: None,
            declared_dependencies,
            distributions: Vec::new(),
        })
        .unwrap()
    }

    fn snapshot(releases: &[(&str, &[(&str, DependencyKind)])]) -> CranCandidateSnapshot {
        CranCandidateSnapshot::from_candidates(
            releases
                .iter()
                .map(|(name, dependencies)| (package(name), vec![release(name, dependencies)]))
                .collect::<Vec<_>>(),
        )
    }

    fn composed(
        repositories: Vec<RepositorySpec>,
        roots: Vec<ComposedRootIntent>,
    ) -> ComposedEnvironment {
        ComposedEnvironment {
            environment: EnvironmentId::new("default").unwrap(),
            r_requirement: VersionConstraint::unconstrained(),
            published_before: None,
            target: ResolutionTarget::new(RPackageVersion::parse("4.4.0").unwrap()),
            repositories,
            roots,
            locked: LockedIdentities::new(),
        }
    }

    fn run_with_factories(
        environment: ComposedEnvironment,
        state: Rc<RefCell<FactoryState>>,
        cran: FakeCranFactory,
        universe: FakeUniverseFactory,
        offline: bool,
        refresh: bool,
    ) -> Result<RepositoryResolutionOutcome, RepositoryResolutionError> {
        let directory = tempdir().unwrap();
        let cache = crate::metadata_cache::MetadataCache::resolve(Some(directory.path())).unwrap();
        let _ = state;
        resolve_composed_with_factory(
            environment,
            &cache,
            offline,
            refresh,
            None,
            &universe,
            &cran,
        )
    }

    fn manifest_root(
        name: &str,
        repository: Option<&str>,
        expansion: rsolve_core::RootExpansionPolicy,
    ) -> ComposedRootIntent {
        ComposedRootIntent {
            name: package(name),
            constraint: VersionConstraint::unconstrained(),
            source: ManifestSource::Registry {
                repository: repository.map(|id| rsolve_core::RepositoryId::new(id).unwrap()),
            },
            expansion,
        }
    }

    fn fixture_state() -> Rc<RefCell<FactoryState>> {
        Rc::new(RefCell::new(FactoryState::default()))
    }

    fn fixture_preparation_metrics(offline: bool, refresh: bool) -> ResolutionMetrics {
        ResolutionMetrics {
            phases: crate::metrics::ResolutionPhaseMetrics {
                snapshot_cache_decision_ns: Some(1),
                refresh_acquisition_ns: (!offline).then_some(1),
                closure_lookup_ns: (!offline).then_some(1),
                snapshot_composition_and_publication_ns: (!offline).then_some(1),
                ..Default::default()
            },
            snapshot_cache_decision: Some(if offline {
                crate::metrics::SnapshotCacheDecision::OfflineCompatible
            } else if refresh {
                crate::metrics::SnapshotCacheDecision::Refreshed
            } else {
                crate::metrics::SnapshotCacheDecision::FreshHit
            }),
            provider_refresh: (!offline).then(Default::default),
            ..Default::default()
        }
    }

    #[test]
    fn cran_allowlist_excluded_neutral_root_does_not_open_cran_store_or_session() {
        let state = fixture_state();
        let result = run_with_factories(
            composed(
                vec![repository("cran", RegistrySpec::Cran, Some(&["other"]))],
                vec![manifest_root(
                    "widget",
                    None,
                    rsolve_core::RootExpansionPolicy::HardOnly,
                )],
            ),
            Rc::clone(&state),
            FakeCranFactory {
                state: Rc::clone(&state),
                snapshots: vec![snapshot(&[("widget", &[])])],
                fail_after: None,
                return_none: false,
            },
            FakeUniverseFactory {
                state: Rc::clone(&state),
                snapshot: CranCandidateSnapshot::default(),
                compatible: false,
            },
            false,
            false,
        );
        let error = match result {
            Ok(_) => panic!("excluded root unexpectedly resolved"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            RepositoryResolutionError::Composition(ManifestError::NoVisibleRepository { .. })
        ));
        assert_eq!(state.borrow().cran_prepares, 0);
        assert_eq!(state.borrow().ru_creates, 0);
    }

    #[test]
    fn unrelated_r_universe_group_is_not_created_or_opened() {
        let state = fixture_state();
        let cran = repository("cran", RegistrySpec::Cran, None);
        let universe = repository("universe", RegistrySpec::RUniverse, Some(&["unrelated"]));
        let result = run_with_factories(
            composed(
                vec![cran, universe],
                vec![manifest_root(
                    "root",
                    Some("cran"),
                    rsolve_core::RootExpansionPolicy::HardOnly,
                )],
            ),
            Rc::clone(&state),
            FakeCranFactory {
                state: Rc::clone(&state),
                snapshots: vec![snapshot(&[("root", &[])])],
                fail_after: None,
                return_none: false,
            },
            FakeUniverseFactory {
                state: Rc::clone(&state),
                snapshot: CranCandidateSnapshot::default(),
                compatible: false,
            },
            false,
            false,
        )
        .unwrap();
        assert_eq!(result.resolution.packages().len(), 1);
        assert_eq!(state.borrow().ru_creates, 0);
        assert_eq!(state.borrow().ru_opens, 0);
    }

    #[test]
    fn r_universe_group_is_created_once_when_first_neutral_transitive_demand_routes_to_it() {
        let state = fixture_state();
        let cran = repository("cran", RegistrySpec::Cran, None);
        let universe = repository("universe", RegistrySpec::RUniverse, Some(&["dep"]));
        let result = run_with_factories(
            composed(
                vec![cran, universe],
                vec![manifest_root(
                    "root",
                    Some("cran"),
                    rsolve_core::RootExpansionPolicy::HardOnly,
                )],
            ),
            Rc::clone(&state),
            FakeCranFactory {
                state: Rc::clone(&state),
                snapshots: vec![
                    snapshot(&[("root", &[("dep", DependencyKind::Depends)])]),
                    snapshot(&[("root", &[("dep", DependencyKind::Depends)]), ("dep", &[])]),
                ],
                fail_after: None,
                return_none: false,
            },
            FakeUniverseFactory {
                state: Rc::clone(&state),
                snapshot: snapshot(&[("dep", &[])]),
                compatible: false,
            },
            false,
            false,
        )
        .unwrap();
        assert_eq!(result.resolution.packages().len(), 2);
        assert_eq!(state.borrow().ru_creates, 1);
        assert_eq!(state.borrow().ru_refreshes, 1);
    }

    #[test]
    fn qualified_cran_root_transitive_dependency_absent_on_cran_present_on_r_universe() {
        let state = fixture_state();
        let cran = repository("cran", RegistrySpec::Cran, None);
        let universe = repository("universe", RegistrySpec::RUniverse, Some(&["dep"]));
        let _ = run_with_factories(
            composed(
                vec![cran, universe],
                vec![manifest_root(
                    "root",
                    Some("cran"),
                    rsolve_core::RootExpansionPolicy::HardOnly,
                )],
            ),
            Rc::clone(&state),
            FakeCranFactory {
                state: Rc::clone(&state),
                snapshots: vec![
                    snapshot(&[("root", &[("dep", DependencyKind::Depends)])]),
                    snapshot(&[("root", &[("dep", DependencyKind::Depends)])]),
                ],
                fail_after: None,
                return_none: false,
            },
            FakeUniverseFactory {
                state: Rc::clone(&state),
                snapshot: snapshot(&[("dep", &[])]),
                compatible: false,
            },
            false,
            false,
        )
        .unwrap();
        assert_eq!(state.borrow().cran_prepares, 2);
        assert!(state.borrow().cran_roots[1].contains(&package("dep")));
        assert_eq!(state.borrow().ru_creates, 1);
    }

    #[test]
    fn forced_refresh_is_not_repeated_across_fixed_point_iterations() {
        let state = fixture_state();
        let cran = repository("cran", RegistrySpec::Cran, None);
        let universe = repository("universe", RegistrySpec::RUniverse, Some(&["root"]));
        let _ = run_with_factories(
            composed(
                vec![cran, universe],
                vec![manifest_root(
                    "root",
                    Some("universe"),
                    rsolve_core::RootExpansionPolicy::HardOnly,
                )],
            ),
            Rc::clone(&state),
            FakeCranFactory {
                state: Rc::clone(&state),
                snapshots: vec![],
                fail_after: None,
                return_none: false,
            },
            FakeUniverseFactory {
                state: Rc::clone(&state),
                snapshot: snapshot(&[("root", &[])]),
                compatible: true,
            },
            false,
            true,
        )
        .unwrap();
        assert_eq!(state.borrow().ru_refreshes, 1);
        assert_eq!(state.borrow().ru_opens, 0);
    }

    #[test]
    fn neutral_direct_root_with_cran_absence_resolves_from_r_universe() {
        let state = fixture_state();
        let cran = repository("cran", RegistrySpec::Cran, Some(&["root"]));
        let universe = repository("universe", RegistrySpec::RUniverse, Some(&["root"]));
        let result = run_with_factories(
            composed(
                vec![cran, universe],
                vec![manifest_root(
                    "root",
                    None,
                    rsolve_core::RootExpansionPolicy::HardOnly,
                )],
            ),
            Rc::clone(&state),
            FakeCranFactory {
                state: Rc::clone(&state),
                snapshots: Vec::new(),
                fail_after: None,
                return_none: true,
            },
            FakeUniverseFactory {
                state: Rc::clone(&state),
                snapshot: snapshot(&[("root", &[])]),
                compatible: false,
            },
            false,
            false,
        )
        .unwrap();
        assert_eq!(result.resolution.packages().len(), 1);
        assert_eq!(state.borrow().cran_prepares, 1);
        assert_eq!(state.borrow().ru_refreshes, 1);
    }

    #[test]
    fn warm_compatible_r_universe_reuses_snapshot_without_refresh() {
        let state = fixture_state();
        let cran = repository("cran", RegistrySpec::Cran, None);
        let universe = repository("universe", RegistrySpec::RUniverse, Some(&["root"]));
        run_with_factories(
            composed(
                vec![cran, universe],
                vec![manifest_root(
                    "root",
                    Some("universe"),
                    rsolve_core::RootExpansionPolicy::HardOnly,
                )],
            ),
            Rc::clone(&state),
            FakeCranFactory {
                state: Rc::clone(&state),
                snapshots: Vec::new(),
                fail_after: None,
                return_none: false,
            },
            FakeUniverseFactory {
                state: Rc::clone(&state),
                snapshot: snapshot(&[("root", &[])]),
                compatible: true,
            },
            false,
            false,
        )
        .unwrap();
        assert_eq!(state.borrow().ru_creates, 1);
        assert_eq!(state.borrow().ru_opens, 1);
        assert_eq!(state.borrow().ru_refreshes, 0);
    }

    #[test]
    fn online_corrupt_r_universe_warm_open_refreshes_exact_scope() {
        let state = fixture_state();
        state.borrow_mut().ru_open_corrupt = true;
        let result = run_with_factories(
            composed(
                vec![
                    repository("cran", RegistrySpec::Cran, None),
                    repository("universe", RegistrySpec::RUniverse, Some(&["root"])),
                ],
                vec![manifest_root(
                    "root",
                    Some("universe"),
                    rsolve_core::RootExpansionPolicy::HardOnly,
                )],
            ),
            Rc::clone(&state),
            FakeCranFactory {
                state: Rc::clone(&state),
                snapshots: Vec::new(),
                fail_after: None,
                return_none: true,
            },
            FakeUniverseFactory {
                state: Rc::clone(&state),
                snapshot: snapshot(&[("root", &[])]),
                compatible: true,
            },
            false,
            false,
        )
        .unwrap();
        assert_eq!(result.resolution.packages().len(), 1);
        assert_eq!(state.borrow().ru_opens, 1);
        assert_eq!(state.borrow().ru_refreshes, 1);
        assert_eq!(
            state.borrow().ru_refresh_scopes,
            vec![Some(vec![package("root")])]
        );
    }

    #[test]
    fn offline_corrupt_r_universe_warm_open_does_not_refresh() {
        let state = fixture_state();
        state.borrow_mut().ru_open_corrupt = true;
        let result = run_with_factories(
            composed(
                vec![
                    repository("cran", RegistrySpec::Cran, None),
                    repository("universe", RegistrySpec::RUniverse, Some(&["root"])),
                ],
                vec![manifest_root(
                    "root",
                    Some("universe"),
                    rsolve_core::RootExpansionPolicy::HardOnly,
                )],
            ),
            Rc::clone(&state),
            FakeCranFactory {
                state: Rc::clone(&state),
                snapshots: Vec::new(),
                fail_after: None,
                return_none: true,
            },
            FakeUniverseFactory {
                state: Rc::clone(&state),
                snapshot: snapshot(&[("root", &[])]),
                compatible: true,
            },
            true,
            false,
        );
        assert!(matches!(
            result,
            Err(RepositoryResolutionError::RUniverse(
                RUniverseProviderError::OfflineCorrupt(_)
            ))
        ));
        assert_eq!(state.borrow().ru_opens, 1);
        assert_eq!(state.borrow().ru_refreshes, 0);
        assert!(state.borrow().ru_refresh_scopes.is_empty());
    }

    #[test]
    fn cold_cran_preparation_preserves_refresh_phase_metrics() {
        let state = fixture_state();
        let result = run_with_factories(
            composed(
                vec![repository("cran", RegistrySpec::Cran, None)],
                vec![manifest_root(
                    "root",
                    Some("cran"),
                    rsolve_core::RootExpansionPolicy::HardOnly,
                )],
            ),
            Rc::clone(&state),
            FakeCranFactory {
                state,
                snapshots: vec![snapshot(&[("root", &[])])],
                fail_after: None,
                return_none: false,
            },
            FakeUniverseFactory {
                state: fixture_state(),
                snapshot: CranCandidateSnapshot::default(),
                compatible: false,
            },
            false,
            true,
        )
        .unwrap();
        assert_eq!(
            result.metrics.snapshot_cache_decision,
            Some(crate::metrics::SnapshotCacheDecision::Refreshed)
        );
        assert!(result.metrics.phases.snapshot_cache_decision_ns.is_some());
        assert!(result.metrics.phases.refresh_acquisition_ns.is_some());
        assert!(result.metrics.phases.closure_lookup_ns.is_some());
        assert!(
            result
                .metrics
                .phases
                .snapshot_composition_and_publication_ns
                .is_some()
        );
        assert!(result.metrics.phases.solve_ns.is_some());
        assert!(result.metrics.provider_refresh.is_some());
    }

    #[test]
    fn coordinator_preserves_stale_cache_warning_details() {
        let state = fixture_state();
        state.borrow_mut().cran_warning = true;
        let result = run_with_factories(
            composed(
                vec![repository("cran", RegistrySpec::Cran, None)],
                vec![manifest_root(
                    "root",
                    Some("cran"),
                    rsolve_core::RootExpansionPolicy::HardOnly,
                )],
            ),
            Rc::clone(&state),
            FakeCranFactory {
                state,
                snapshots: vec![snapshot(&[("root", &[])])],
                fail_after: None,
                return_none: false,
            },
            FakeUniverseFactory {
                state: fixture_state(),
                snapshot: CranCandidateSnapshot::default(),
                compatible: false,
            },
            false,
            false,
        )
        .unwrap();
        assert_eq!(result.warnings.len(), 1);
        assert!(result.warnings[0].contains("age 7200s"));
        assert!(result.warnings[0].contains("sources: https://cran.example.test/"));
        assert!(result.warnings[0].contains("detail"));
    }

    #[test]
    fn offline_missing_r_universe_snapshot_does_not_refresh() {
        let state = fixture_state();
        let cran = repository("cran", RegistrySpec::Cran, None);
        let universe = repository("universe", RegistrySpec::RUniverse, Some(&["root"]));
        let result = run_with_factories(
            composed(
                vec![cran, universe],
                vec![manifest_root(
                    "root",
                    Some("universe"),
                    rsolve_core::RootExpansionPolicy::HardOnly,
                )],
            ),
            Rc::clone(&state),
            FakeCranFactory {
                state: Rc::clone(&state),
                snapshots: Vec::new(),
                fail_after: None,
                return_none: false,
            },
            FakeUniverseFactory {
                state: Rc::clone(&state),
                snapshot: snapshot(&[("root", &[])]),
                compatible: false,
            },
            true,
            false,
        );
        assert!(matches!(
            result,
            Err(RepositoryResolutionError::RUniverse(
                RUniverseProviderError::OfflineMissing(_)
            ))
        ));
        assert_eq!(state.borrow().ru_opens, 1);
        assert_eq!(state.borrow().ru_refreshes, 0);
    }

    #[test]
    fn offline_compatible_r_universe_opens_without_refresh() {
        let state = fixture_state();
        let result = run_with_factories(
            composed(
                vec![
                    repository("cran", RegistrySpec::Cran, None),
                    repository("universe", RegistrySpec::RUniverse, Some(&["root"])),
                ],
                vec![manifest_root(
                    "root",
                    Some("universe"),
                    rsolve_core::RootExpansionPolicy::HardOnly,
                )],
            ),
            Rc::clone(&state),
            FakeCranFactory {
                state: Rc::clone(&state),
                snapshots: Vec::new(),
                fail_after: None,
                return_none: false,
            },
            FakeUniverseFactory {
                state: Rc::clone(&state),
                snapshot: snapshot(&[("root", &[])]),
                compatible: true,
            },
            true,
            false,
        )
        .unwrap();
        assert_eq!(state.borrow().ru_opens, 1);
        assert_eq!(state.borrow().ru_refreshes, 0);
        assert!(result.metrics.phases.solve_ns.is_some());
    }

    #[test]
    fn shared_r_universe_group_prepares_once_and_keeps_entry_visibility() {
        let state = fixture_state();
        let cran = repository("cran", RegistrySpec::Cran, None);
        let first = repository("first", RegistrySpec::RUniverse, Some(&["root"]));
        let second = repository("second", RegistrySpec::RUniverse, Some(&["root"]));
        let result = run_with_factories(
            composed(
                vec![cran, first, second],
                vec![manifest_root(
                    "root",
                    None,
                    rsolve_core::RootExpansionPolicy::HardOnly,
                )],
            ),
            Rc::clone(&state),
            FakeCranFactory {
                state: Rc::clone(&state),
                snapshots: Vec::new(),
                fail_after: None,
                return_none: true,
            },
            FakeUniverseFactory {
                state: Rc::clone(&state),
                snapshot: snapshot(&[("root", &[])]),
                compatible: false,
            },
            false,
            false,
        )
        .unwrap();
        assert_eq!(state.borrow().ru_creates, 1);
        assert_eq!(state.borrow().ru_refreshes, 1);
        assert_eq!(result.resolution.packages().len(), 1);
        assert_eq!(
            result.resolution.packages()[0].visible_repository_ids(),
            &[
                rsolve_core::RepositoryId::new("first").unwrap(),
                rsolve_core::RepositoryId::new("second").unwrap()
            ]
        );
    }

    #[test]
    fn qualified_r_universe_root_missing_is_reported_at_provider_boundary() {
        let state = fixture_state();
        let cran = repository("cran", RegistrySpec::Cran, None);
        let universe = repository("universe", RegistrySpec::RUniverse, Some(&["root"]));
        let result = run_with_factories(
            composed(
                vec![cran, universe],
                vec![manifest_root(
                    "root",
                    Some("universe"),
                    rsolve_core::RootExpansionPolicy::HardOnly,
                )],
            ),
            Rc::clone(&state),
            FakeCranFactory {
                state: Rc::clone(&state),
                snapshots: Vec::new(),
                fail_after: None,
                return_none: false,
            },
            FakeUniverseFactory {
                state,
                snapshot: CranCandidateSnapshot::default(),
                compatible: false,
            },
            false,
            false,
        );
        assert!(matches!(
            result,
            Err(RepositoryResolutionError::RUniverse(
                RUniverseProviderError::PackageNotFound { .. }
            ))
        ));
    }

    #[test]
    fn three_hop_cross_provider_demands_reach_final_cran_package() {
        let state = fixture_state();
        let cran = repository("cran", RegistrySpec::Cran, None);
        let universe = repository("universe", RegistrySpec::RUniverse, Some(&["a", "b"]));
        let result = run_with_factories(
            composed(
                vec![cran, universe],
                vec![manifest_root(
                    "root",
                    Some("cran"),
                    rsolve_core::RootExpansionPolicy::HardOnly,
                )],
            ),
            Rc::clone(&state),
            FakeCranFactory {
                state: Rc::clone(&state),
                snapshots: vec![
                    snapshot(&[("root", &[("a", DependencyKind::Depends)])]),
                    snapshot(&[("root", &[("a", DependencyKind::Depends)]), ("c", &[])]),
                ],
                fail_after: None,
                return_none: false,
            },
            FakeUniverseFactory {
                state: Rc::clone(&state),
                snapshot: snapshot(&[
                    ("a", &[("b", DependencyKind::Depends)]),
                    ("b", &[("c", DependencyKind::Depends)]),
                ]),
                compatible: false,
            },
            false,
            false,
        )
        .unwrap();
        assert!(
            result
                .resolution
                .packages()
                .iter()
                .any(|resolved| resolved.name() == &package("c"))
        );
        assert_eq!(state.borrow().ru_creates, 1);
    }

    #[test]
    fn offline_additional_cran_coverage_miss_is_typed() {
        let state = fixture_state();
        let cran = repository("cran", RegistrySpec::Cran, None);
        let result = run_with_factories(
            composed(
                vec![cran],
                vec![manifest_root(
                    "root",
                    Some("cran"),
                    rsolve_core::RootExpansionPolicy::HardOnly,
                )],
            ),
            Rc::clone(&state),
            FakeCranFactory {
                state,
                snapshots: vec![snapshot(&[("root", &[])])],
                fail_after: Some(0),
                return_none: false,
            },
            FakeUniverseFactory {
                state: fixture_state(),
                snapshot: CranCandidateSnapshot::default(),
                compatible: false,
            },
            true,
            false,
        );
        assert!(matches!(result, Err(RepositoryResolutionError::Cran(_))));
    }

    #[test]
    fn r_universe_group_scope_unions_allowlists_and_preserves_unrestricted_groups() {
        let first = repository("first", RegistrySpec::RUniverse, Some(&["zeta", "alpha"]));
        let second = repository("second", RegistrySpec::RUniverse, Some(&["beta"]));
        let registry = first.configured_registry_id().unwrap();
        let scope = r_universe_group_scope(
            &[first.clone(), second.clone()],
            &registry,
            first.manifest_endpoint().as_str(),
        );
        assert_eq!(
            scope,
            Some(vec![package("alpha"), package("beta"), package("zeta")]),
            "group scope is canonical across matching repository entries"
        );

        let unrestricted = repository("all", RegistrySpec::RUniverse, None);
        let registry = unrestricted.configured_registry_id().unwrap();
        assert_eq!(
            r_universe_group_scope(
                std::slice::from_ref(&unrestricted),
                &registry,
                unrestricted.manifest_endpoint().as_str(),
            ),
            None
        );
    }

    #[test]
    fn repository_validation_requires_one_cran_for_remote_roots() {
        let root = ComposedRootIntent {
            name: package("widget"),
            constraint: VersionConstraint::unconstrained(),
            source: ManifestSource::Registry { repository: None },
            expansion: rsolve_core::RootExpansionPolicy::HardOnly,
        };
        let composed = ComposedEnvironment {
            environment: EnvironmentId::new("default").unwrap(),
            r_requirement: VersionConstraint::unconstrained(),
            published_before: None,
            target: ResolutionTarget::new(RPackageVersion::parse("4.4.0").unwrap()),
            repositories: vec![repository("universe", RegistrySpec::RUniverse, None)],
            roots: vec![root],
            locked: LockedIdentities::new(),
        };
        assert!(matches!(
            validate_repository_set(&composed),
            Err(RepositoryResolutionError::Composition(
                ManifestError::InvalidRegistry { .. }
            ))
        ));

        let cran_like = repository(
            "other",
            RegistrySpec::cran_like(PackageNamespace::new("other").unwrap()).unwrap(),
            None,
        );
        let invalid = ComposedEnvironment {
            repositories: vec![cran_like],
            ..composed
        };
        assert!(matches!(
            validate_repository_set(&invalid),
            Err(RepositoryResolutionError::Composition(
                ManifestError::InvalidRegistry { .. }
            ))
        ));
    }
}
