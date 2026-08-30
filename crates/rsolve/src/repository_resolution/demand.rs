use std::collections::{BTreeMap, BTreeSet};

use crate::manifest::{ComposedRootIntent, ManifestSource, RepositorySpec};
use rsolve_core::{
    CandidateLoadError, CandidateLoadErrorCategory, DependencyKind, PackageName, PackageRelease,
    RepositoryId,
};

/// The deterministic package demand produced for one composed repository set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RepositoryDemandPlan {
    /// Packages that may be queried from each repository entry, in manifest
    /// order. The entry index is retained because visibility is entry scoped.
    pub(crate) entry_demands: BTreeMap<usize, BTreeSet<PackageName>>,
    /// Packages for which no configured entry can provide a candidate view.
    pub(crate) unrouted: BTreeSet<PackageName>,
    /// Every package reached while inspecting eligible candidate metadata.
    pub(crate) discovered: BTreeSet<PackageName>,
}

/// Candidate acquisition authority used by the pure demand engine.
pub(crate) trait RepositoryDemandSource {
    fn load(
        &mut self,
        entry: usize,
        package: &PackageName,
    ) -> Result<Vec<PackageRelease>, CandidateLoadError>;
}

/// Route only the manifest registry roots without inspecting provider state.
/// This is the coordinator's lazy-preparation seed; dependency expansion is
/// performed by [`resolve_repository_demands`] once a source is available.
pub(crate) fn initial_repository_demands(
    repositories: &[RepositorySpec],
    roots: &[ComposedRootIntent],
) -> BTreeMap<usize, BTreeSet<PackageName>> {
    let mut result = BTreeMap::new();
    for root in roots {
        let ManifestSource::Registry { repository } = &root.source else {
            continue;
        };
        if !is_remote_root(root) {
            continue;
        }
        for entry in eligible_entries(repositories, repository.as_ref(), &root.name) {
            result
                .entry(entry)
                .or_insert_with(BTreeSet::new)
                .insert(root.name.clone());
        }
    }
    result
}

/// Expand source-aware roots and candidate dependency metadata to a stable
/// repository/package demand plan. The source callback is the only operation
/// allowed to inspect provider or snapshot state.
pub(crate) fn resolve_repository_demands<S: RepositoryDemandSource>(
    repositories: &[RepositorySpec],
    roots: &[ComposedRootIntent],
    source: &mut S,
) -> Result<RepositoryDemandPlan, CandidateLoadError> {
    let mut entry_demands = BTreeMap::<usize, BTreeSet<PackageName>>::new();
    let mut pending = Vec::<(PackageName, Option<RepositoryId>, bool)>::new();
    let mut unrouted = BTreeSet::new();
    let mut discovered = BTreeSet::new();

    for root in roots {
        let ManifestSource::Registry { repository } = &root.source else {
            continue;
        };
        if !is_remote_root(root) {
            continue;
        }
        let scope = repository.clone();
        let eligible = eligible_entries(repositories, scope.as_ref(), &root.name);
        if eligible.is_empty() {
            discovered.insert(root.name.clone());
            unrouted.insert(root.name.clone());
            continue;
        }
        for entry in eligible {
            entry_demands
                .entry(entry)
                .or_default()
                .insert(root.name.clone());
        }
        pending.push((
            root.name.clone(),
            scope,
            root.expansion == rsolve_core::RootExpansionPolicy::DirectSuggests,
        ));
    }

    let mut visited = BTreeSet::<(PackageName, Option<RepositoryId>)>::new();
    while let Some((package, scope, promote_suggests)) = pending.pop() {
        if !visited.insert((package.clone(), scope.clone())) {
            continue;
        }
        discovered.insert(package.clone());
        let eligible = eligible_entries(repositories, scope.as_ref(), &package);
        if eligible.is_empty() {
            unrouted.insert(package);
            continue;
        }
        for entry in eligible {
            let candidates = match source.load(entry, &package) {
                Ok(candidates) => candidates,
                Err(error) if error.category() == CandidateLoadErrorCategory::NotFound => {
                    continue;
                }
                Err(error) => return Err(error),
            };
            for candidate in candidates {
                for dependency in candidate.declared_dependencies() {
                    let hard = matches!(
                        dependency.kind,
                        DependencyKind::Depends
                            | DependencyKind::Imports
                            | DependencyKind::LinkingTo
                    );
                    let promoted = promote_suggests && dependency.kind == DependencyKind::Suggests;
                    if !(hard || promoted) || !is_remote_name(dependency.package.name()) {
                        continue;
                    }
                    let dependency_name = dependency.package.name().clone();
                    discovered.insert(dependency_name.clone());
                    let dependency_entries = eligible_entries(repositories, None, &dependency_name);
                    if dependency_entries.is_empty() {
                        unrouted.insert(dependency_name.clone());
                        continue;
                    }
                    for dependency_entry in dependency_entries {
                        entry_demands
                            .entry(dependency_entry)
                            .or_default()
                            .insert(dependency_name.clone());
                    }
                    pending.push((dependency_name, None, false));
                }
            }
        }
    }

    Ok(RepositoryDemandPlan {
        entry_demands,
        unrouted,
        discovered,
    })
}

fn eligible_entries(
    repositories: &[RepositorySpec],
    scope: Option<&RepositoryId>,
    package: &PackageName,
) -> Vec<usize> {
    repositories
        .iter()
        .enumerate()
        .filter(|(_, repository)| {
            scope.is_none_or(|scope| scope == repository.id())
                && repository.package_allowed(package)
        })
        .map(|(index, _)| index)
        .collect()
}

fn is_remote_name(package: &PackageName) -> bool {
    package.as_str() != "R" && !rsolve_resolver::is_r_base_package_name(package)
}

fn is_remote_root(root: &ComposedRootIntent) -> bool {
    if root.name.as_str() == "R" {
        return false;
    }
    match &root.source {
        ManifestSource::Registry {
            repository: Some(_),
        } => true,
        ManifestSource::Registry { repository: None } => is_remote_name(&root.name),
        ManifestSource::Git { .. } | ManifestSource::Url { .. } | ManifestSource::Path { .. } => {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{Endpoint, RegistrySpec};
    use rsolve_core::{
        DeclaredDependency, DependencySourceConstraint, PackageNamespace, Provenance,
        RPackageVersion, ReleaseIdentity, ReleaseMetadata, ReleaseObservation, RepositoryId,
        RootExpansionPolicy, VersionConstraint,
    };

    #[derive(Default)]
    struct ScriptedSource {
        releases: BTreeMap<(usize, PackageName), Vec<PackageRelease>>,
        calls: Vec<(usize, PackageName)>,
        failures: BTreeMap<(usize, PackageName), CandidateLoadError>,
    }

    impl RepositoryDemandSource for ScriptedSource {
        fn load(
            &mut self,
            entry: usize,
            package: &PackageName,
        ) -> Result<Vec<PackageRelease>, CandidateLoadError> {
            self.calls.push((entry, package.clone()));
            if let Some(error) = self.failures.get(&(entry, package.clone())) {
                return Err(error.clone());
            }
            Ok(self
                .releases
                .get(&(entry, package.clone()))
                .cloned()
                .unwrap_or_default())
        }
    }

    fn package(name: &str) -> PackageName {
        PackageName::new(name).expect("valid fixture package")
    }

    fn repository(id: &str, registry: RegistrySpec, packages: Option<&[&str]>) -> RepositorySpec {
        RepositorySpec::new_with_packages(
            RepositoryId::new(id).expect("valid fixture repository"),
            registry,
            Endpoint::new(format!("https://{id}.example.test/")).unwrap(),
            packages.map(|names| names.iter().map(|name| package(name)).collect()),
        )
        .unwrap()
    }

    fn root(
        name: &str,
        repository: Option<&str>,
        expansion: RootExpansionPolicy,
    ) -> ComposedRootIntent {
        ComposedRootIntent {
            name: package(name),
            constraint: VersionConstraint::unconstrained(),
            source: ManifestSource::Registry {
                repository: repository.map(|id| RepositoryId::new(id).unwrap()),
            },
            expansion,
        }
    }

    fn release(name: &str, dependencies: Vec<DeclaredDependency>) -> PackageRelease {
        let name = package(name);
        let version = RPackageVersion::parse("1.0.0").unwrap();
        PackageRelease::try_from(ReleaseObservation {
            identity: ReleaseIdentity::new(
                name.clone(),
                Provenance::RegistryRelease {
                    namespace: PackageNamespace::new("cran").unwrap(),
                    version: version.clone(),
                },
            ),
            observed_package: name,
            observed_version: version,
            metadata: ReleaseMetadata::new(BTreeMap::new()).unwrap(),
            publication: None,
            declared_dependencies: dependencies,
            distributions: Vec::new(),
        })
        .unwrap()
    }

    fn dependency(kind: DependencyKind, name: &str) -> DeclaredDependency {
        DeclaredDependency::from_parts(
            kind,
            package(name),
            DependencySourceConstraint::Any,
            VersionConstraint::unconstrained(),
        )
        .unwrap()
    }

    fn demand(
        source: &mut ScriptedSource,
        repositories: &[RepositorySpec],
        roots: &[ComposedRootIntent],
    ) -> RepositoryDemandPlan {
        resolve_repository_demands(repositories, roots, source).unwrap()
    }

    #[test]
    fn neutral_dependency_routes_to_both_cran_and_r_universe_candidates() {
        let repositories = vec![
            repository("cran", RegistrySpec::Cran, None),
            repository("universe", RegistrySpec::RUniverse, Some(&["root", "dep"])),
        ];
        let root_intent = root("root", Some("universe"), RootExpansionPolicy::HardOnly);
        let mut source = ScriptedSource::default();
        source.releases.insert(
            (1, package("root")),
            vec![release(
                "root",
                vec![dependency(DependencyKind::Depends, "dep")],
            )],
        );
        source
            .releases
            .insert((0, package("dep")), vec![release("dep", Vec::new())]);
        source
            .releases
            .insert((1, package("dep")), vec![release("dep", Vec::new())]);

        let plan = demand(&mut source, &repositories, &[root_intent]);
        assert_eq!(
            source.calls,
            vec![
                (1, package("root")),
                (0, package("dep")),
                (1, package("dep")),
            ]
        );
        assert_eq!(plan.entry_demands[&0], BTreeSet::from([package("dep")]));
        assert_eq!(
            plan.entry_demands[&1],
            BTreeSet::from([package("dep"), package("root")])
        );
    }

    #[test]
    fn repository_qualified_r_base_root_routes_to_its_entry() {
        let repositories = vec![
            repository("cran", RegistrySpec::Cran, None),
            repository("universe", RegistrySpec::RUniverse, Some(&["stats"])),
        ];
        let mut source = ScriptedSource::default();
        source
            .releases
            .insert((1, package("stats")), vec![release("stats", Vec::new())]);
        let plan = demand(
            &mut source,
            &repositories,
            &[root(
                "stats",
                Some("universe"),
                RootExpansionPolicy::HardOnly,
            )],
        );
        assert_eq!(source.calls, vec![(1, package("stats"))]);
        assert_eq!(plan.entry_demands[&1], BTreeSet::from([package("stats")]));
        assert!(!plan.entry_demands.contains_key(&0));
    }

    #[test]
    fn three_hop_cross_provider_demands_reach_final_cran_package() {
        let repositories = vec![
            repository("cran", RegistrySpec::Cran, None),
            repository("universe", RegistrySpec::RUniverse, Some(&["b"])),
        ];
        let mut source = ScriptedSource::default();
        source.releases.insert(
            (0, package("a")),
            vec![release("a", vec![dependency(DependencyKind::Depends, "b")])],
        );
        source.releases.insert(
            (1, package("b")),
            vec![release("b", vec![dependency(DependencyKind::Depends, "c")])],
        );
        source
            .releases
            .insert((0, package("c")), vec![release("c", Vec::new())]);

        let plan = demand(
            &mut source,
            &repositories,
            &[root("a", Some("cran"), RootExpansionPolicy::HardOnly)],
        );
        assert!(source.calls.contains(&(0, package("a"))));
        assert!(source.calls.contains(&(1, package("b"))));
        assert!(source.calls.contains(&(0, package("c"))));
        assert_eq!(
            plan.discovered,
            BTreeSet::from([package("a"), package("b"), package("c")])
        );
    }

    #[test]
    fn unrelated_r_universe_group_is_not_created_or_opened() {
        let repositories = vec![
            repository("cran", RegistrySpec::Cran, None),
            repository("unrelated", RegistrySpec::RUniverse, Some(&["declared"])),
        ];
        let mut source = ScriptedSource::default();
        source
            .releases
            .insert((0, package("root")), vec![release("root", Vec::new())]);
        let plan = demand(
            &mut source,
            &repositories,
            &[root("root", Some("cran"), RootExpansionPolicy::HardOnly)],
        );
        assert_eq!(source.calls, vec![(0, package("root"))]);
        assert!(!plan.entry_demands.contains_key(&1));
    }

    #[test]
    fn r_universe_group_is_created_once_when_first_neutral_transitive_demand_routes_to_it() {
        let repositories = vec![
            repository("cran", RegistrySpec::Cran, None),
            repository("universe", RegistrySpec::RUniverse, Some(&["dep"])),
        ];
        let mut source = ScriptedSource::default();
        source.releases.insert(
            (0, package("root")),
            vec![release(
                "root",
                vec![dependency(DependencyKind::Depends, "dep")],
            )],
        );
        source
            .releases
            .insert((1, package("dep")), vec![release("dep", Vec::new())]);
        let _ = demand(
            &mut source,
            &repositories,
            &[root("root", Some("cran"), RootExpansionPolicy::HardOnly)],
        );
        assert_eq!(
            source.calls,
            vec![
                (0, package("root")),
                (0, package("dep")),
                (1, package("dep"))
            ]
        );
        assert_eq!(
            source.calls.iter().filter(|call| call.0 == 1).count(),
            1,
            "the newly routed entry is queried once for the deduplicated demand"
        );
    }

    #[test]
    fn direct_root_promotes_suggests_but_recursive_suggests_are_not_enqueued() {
        let repositories = vec![repository("cran", RegistrySpec::Cran, None)];
        let mut source = ScriptedSource::default();
        source.releases.insert(
            (0, package("root")),
            vec![release(
                "root",
                vec![
                    dependency(DependencyKind::Suggests, "promoted"),
                    dependency(DependencyKind::Depends, "hard"),
                ],
            )],
        );
        source.releases.insert(
            (0, package("promoted")),
            vec![release(
                "promoted",
                vec![dependency(DependencyKind::Suggests, "recursive")],
            )],
        );
        source
            .releases
            .insert((0, package("hard")), vec![release("hard", Vec::new())]);
        let plan = demand(
            &mut source,
            &repositories,
            &[root("root", None, RootExpansionPolicy::DirectSuggests)],
        );
        assert!(plan.discovered.contains(&package("promoted")));
        assert!(plan.discovered.contains(&package("hard")));
        assert!(!plan.discovered.contains(&package("recursive")));
    }

    #[test]
    fn hard_provider_error_is_not_hidden_by_another_entry_candidate() {
        let repositories = vec![
            repository("first", RegistrySpec::Cran, None),
            repository("second", RegistrySpec::RUniverse, None),
        ];
        let mut source = ScriptedSource::default();
        source.failures.insert(
            (0, package("root")),
            CandidateLoadError::new(
                CandidateLoadErrorCategory::TransportFailure,
                "first provider failed",
            ),
        );
        source
            .releases
            .insert((1, package("root")), vec![release("root", Vec::new())]);
        let error = resolve_repository_demands(
            &repositories,
            &[root("root", None, RootExpansionPolicy::HardOnly)],
            &mut source,
        )
        .unwrap_err();
        assert_eq!(
            error.category(),
            CandidateLoadErrorCategory::TransportFailure
        );
        assert_eq!(source.calls.len(), 1, "a hard error stops the union");
    }

    #[test]
    fn hard_provider_error_after_a_candidate_is_not_hidden() {
        let repositories = vec![
            repository("first", RegistrySpec::Cran, None),
            repository("second", RegistrySpec::RUniverse, None),
        ];
        let mut source = ScriptedSource::default();
        source
            .releases
            .insert((0, package("root")), vec![release("root", Vec::new())]);
        source.failures.insert(
            (1, package("root")),
            CandidateLoadError::new(
                CandidateLoadErrorCategory::MetadataInvalid,
                "second provider returned invalid metadata",
            ),
        );
        let error = resolve_repository_demands(
            &repositories,
            &[root("root", None, RootExpansionPolicy::HardOnly)],
            &mut source,
        )
        .unwrap_err();
        assert_eq!(
            error.category(),
            CandidateLoadErrorCategory::MetadataInvalid
        );
        assert_eq!(source.calls.len(), 2);
    }

    #[test]
    fn not_found_is_skipped_when_another_entry_has_candidates() {
        let repositories = vec![
            repository("first", RegistrySpec::Cran, None),
            repository("second", RegistrySpec::RUniverse, None),
        ];
        let mut source = ScriptedSource::default();
        source.failures.insert(
            (0, package("root")),
            CandidateLoadError::new(CandidateLoadErrorCategory::NotFound, "ordinary absence"),
        );
        source
            .releases
            .insert((1, package("root")), vec![release("root", Vec::new())]);
        let plan = demand(
            &mut source,
            &repositories,
            &[root("root", None, RootExpansionPolicy::HardOnly)],
        );
        assert_eq!(plan.discovered, BTreeSet::from([package("root")]));
        assert_eq!(source.calls.len(), 2);
    }

    #[test]
    fn all_not_found_sources_produce_an_empty_unrouted_surface() {
        let repositories = vec![repository("cran", RegistrySpec::Cran, None)];
        let mut source = ScriptedSource::default();
        source.failures.insert(
            (0, package("missing")),
            CandidateLoadError::new(CandidateLoadErrorCategory::NotFound, "ordinary absence"),
        );
        let plan = demand(
            &mut source,
            &repositories,
            &[root("missing", None, RootExpansionPolicy::HardOnly)],
        );
        assert!(plan.entry_demands.contains_key(&0));
        assert!(plan.discovered.contains(&package("missing")));
        assert!(plan.unrouted.is_empty());
    }

    #[test]
    fn cran_allowlist_excluded_neutral_root_does_not_open_cran_store_or_session() {
        let repositories = vec![repository("cran", RegistrySpec::Cran, Some(&["other"]))];
        let mut source = ScriptedSource::default();
        let plan = demand(
            &mut source,
            &repositories,
            &[root("missing", None, RootExpansionPolicy::HardOnly)],
        );
        assert_eq!(plan.unrouted, BTreeSet::from([package("missing")]));
        assert!(source.calls.is_empty());
    }

    #[test]
    fn zero_repositories_are_an_empty_surface() {
        let mut source = ScriptedSource::default();
        let plan = demand(
            &mut source,
            &[],
            &[root("missing", None, RootExpansionPolicy::HardOnly)],
        );
        assert_eq!(plan.unrouted, BTreeSet::from([package("missing")]));
        assert!(source.calls.is_empty());
    }

    #[test]
    fn shared_session_group_fetches_once_while_entry_visibility_remains_separate() {
        #[derive(Default)]
        struct SharedSource {
            entry_calls: Vec<(usize, PackageName)>,
            group_fetches: BTreeSet<PackageName>,
            fetch_count: usize,
        }

        impl RepositoryDemandSource for SharedSource {
            fn load(
                &mut self,
                entry: usize,
                package: &PackageName,
            ) -> Result<Vec<PackageRelease>, CandidateLoadError> {
                self.entry_calls.push((entry, package.clone()));
                if self.group_fetches.insert(package.clone()) {
                    self.fetch_count += 1;
                }
                Ok(vec![release(package.as_str(), Vec::new())])
            }
        }

        let endpoint = Endpoint::new("https://shared.example.test/").unwrap();
        let repositories = vec![
            RepositorySpec::new(
                RepositoryId::new("first").unwrap(),
                RegistrySpec::RUniverse,
                endpoint.clone(),
            )
            .unwrap(),
            RepositorySpec::new(
                RepositoryId::new("second").unwrap(),
                RegistrySpec::RUniverse,
                endpoint,
            )
            .unwrap(),
        ];
        let mut source = SharedSource::default();
        let plan = resolve_repository_demands(
            &repositories,
            &[root("shared", None, RootExpansionPolicy::HardOnly)],
            &mut source,
        )
        .unwrap();
        assert_eq!(
            source.entry_calls,
            vec![(0, package("shared")), (1, package("shared"))]
        );
        assert_eq!(source.group_fetches, BTreeSet::from([package("shared")]));
        assert_eq!(source.fetch_count, 1);
        assert_eq!(plan.entry_demands[&0], BTreeSet::from([package("shared")]));
        assert_eq!(plan.entry_demands[&1], BTreeSet::from([package("shared")]));
    }

    #[test]
    fn unrouted_transitive_dependency_is_recorded_without_a_provider_call() {
        let repositories = vec![repository("cran", RegistrySpec::Cran, Some(&["root"]))];
        let mut source = ScriptedSource::default();
        source.releases.insert(
            (0, package("root")),
            vec![release(
                "root",
                vec![dependency(DependencyKind::Depends, "hidden")],
            )],
        );
        let plan = demand(
            &mut source,
            &repositories,
            &[root("root", None, RootExpansionPolicy::HardOnly)],
        );
        assert_eq!(plan.unrouted, BTreeSet::from([package("hidden")]));
        assert!(plan.discovered.contains(&package("hidden")));
        assert!(!source.calls.contains(&(0, package("hidden"))));
    }
}
