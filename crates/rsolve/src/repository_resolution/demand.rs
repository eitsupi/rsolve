use std::collections::{BTreeMap, BTreeSet, HashMap};

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

/// Seed repository preparation from registry roots and from the already
/// acquired metadata of direct source roots.  This intentionally does not
/// inspect any repository/provider state: it is safe to use when deciding
/// whether a provider needs to be opened at all.
pub(crate) fn initial_repository_demands_with_direct(
    repositories: &[RepositorySpec],
    roots: &[ComposedRootIntent],
    direct_releases: &BTreeMap<PackageName, PackageRelease>,
) -> BTreeMap<usize, BTreeSet<PackageName>> {
    let mut result = BTreeMap::<usize, BTreeSet<PackageName>>::new();
    for root in roots {
        match &root.source {
            ManifestSource::Registry { repository } => {
                if !is_remote_root(root) {
                    continue;
                }
                for entry in eligible_entries(repositories, repository.as_ref(), &root.name) {
                    result.entry(entry).or_default().insert(root.name.clone());
                }
            }
            ManifestSource::Git { .. } => {
                let Some(release) = direct_releases.get(&root.name) else {
                    continue;
                };
                for dependency in release.declared_dependencies() {
                    let hard = matches!(
                        dependency.kind,
                        DependencyKind::Depends
                            | DependencyKind::Imports
                            | DependencyKind::LinkingTo
                    );
                    let promoted = root.expansion
                        == rsolve_core::RootExpansionPolicy::DirectSuggests
                        && dependency.kind == DependencyKind::Suggests;
                    if !(hard || promoted) || !is_remote_name(dependency.package.name()) {
                        continue;
                    }
                    let name = dependency.package.name();
                    for entry in
                        eligible_dependency_entries(repositories, dependency.package.source(), name)
                    {
                        result.entry(entry).or_default().insert(name.clone());
                    }
                }
            }
            ManifestSource::Url { .. } | ManifestSource::Path { .. } => {}
        }
    }
    result
}

/// Expand source-aware roots and candidate dependency metadata to a stable
/// repository/package demand plan. The source callback is the only operation
/// allowed to inspect provider or snapshot state.
#[allow(dead_code)]
pub(crate) fn resolve_repository_demands<S: RepositoryDemandSource>(
    repositories: &[RepositorySpec],
    roots: &[ComposedRootIntent],
    source: &mut S,
) -> Result<RepositoryDemandPlan, CandidateLoadError> {
    resolve_repository_demands_with_direct(repositories, roots, &BTreeMap::new(), source)
}

/// Expand registry demands while using already-acquired direct-source
/// releases as metadata-only dependency seeds. Direct roots themselves are
/// never routed to repositories; their declared dependencies are.
pub(crate) fn resolve_repository_demands_with_direct<S: RepositoryDemandSource>(
    repositories: &[RepositorySpec],
    roots: &[ComposedRootIntent],
    direct_releases: &BTreeMap<PackageName, PackageRelease>,
    loader: &mut S,
) -> Result<RepositoryDemandPlan, CandidateLoadError> {
    let mut entry_demands = BTreeMap::<usize, BTreeSet<PackageName>>::new();
    let mut pending = Vec::<(PackageName, rsolve_core::DependencySourceConstraint, bool)>::new();
    let mut unrouted = BTreeSet::new();
    let mut discovered = BTreeSet::new();

    for root in roots {
        let repository = match &root.source {
            ManifestSource::Registry { repository } => repository.clone(),
            ManifestSource::Git { .. } => {
                let Some(release) = direct_releases.get(&root.name) else {
                    continue;
                };
                for dependency in release.declared_dependencies() {
                    let hard = matches!(
                        dependency.kind,
                        DependencyKind::Depends
                            | DependencyKind::Imports
                            | DependencyKind::LinkingTo
                    );
                    let promoted = root.expansion
                        == rsolve_core::RootExpansionPolicy::DirectSuggests
                        && dependency.kind == DependencyKind::Suggests;
                    if !(hard || promoted) || !is_remote_name(dependency.package.name()) {
                        continue;
                    }
                    let dependency_name = dependency.package.name().clone();
                    discovered.insert(dependency_name.clone());
                    let dependency_entries = eligible_dependency_entries(
                        repositories,
                        dependency.package.source(),
                        &dependency_name,
                    );
                    if dependency_entries.is_empty() {
                        unrouted.insert(dependency_name.clone());
                    } else {
                        for entry in dependency_entries {
                            entry_demands
                                .entry(entry)
                                .or_default()
                                .insert(dependency_name.clone());
                        }
                        pending.push((dependency_name, dependency.package.source().clone(), false));
                    }
                }
                continue;
            }
            ManifestSource::Url { .. } | ManifestSource::Path { .. } => continue,
        };
        if !is_remote_root(root) {
            continue;
        }
        let source = repository
            .map(|repository| rsolve_core::DependencySourceConstraint::Repository { repository })
            .unwrap_or_default();
        let eligible = eligible_dependency_entries(repositories, &source, &root.name);
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
            source,
            root.expansion == rsolve_core::RootExpansionPolicy::DirectSuggests,
        ));
    }

    // Track the strongest expansion mode already used for each scoped package.
    // A package first reached through a hard-only edge may later be reached as
    // a direct-suggest root; that stronger mode must get one additional walk
    // so its promoted Suggests are not silently lost.
    let mut visited =
        HashMap::<(PackageName, rsolve_core::DependencySourceConstraint), bool>::new();
    while let Some((package, constraint, promote_suggests)) = pending.pop() {
        let key = (package.clone(), constraint.clone());
        match visited.get(&key) {
            Some(strongest) if *strongest || !promote_suggests => continue,
            _ => {
                visited.insert(key, promote_suggests);
            }
        }
        discovered.insert(package.clone());
        let eligible = eligible_dependency_entries(repositories, &constraint, &package);
        if eligible.is_empty() {
            unrouted.insert(package);
            continue;
        }
        for entry in eligible {
            let candidates = match loader.load(entry, &package) {
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
                    let dependency_entries = eligible_dependency_entries(
                        repositories,
                        dependency.package.source(),
                        &dependency_name,
                    );
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
                    pending.push((dependency_name, dependency.package.source().clone(), false));
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

fn eligible_dependency_entries(
    repositories: &[RepositorySpec],
    source: &rsolve_core::DependencySourceConstraint,
    package: &PackageName,
) -> Vec<usize> {
    match source {
        rsolve_core::DependencySourceConstraint::Repository { repository } => {
            eligible_entries(repositories, Some(repository), package)
        }
        rsolve_core::DependencySourceConstraint::Registry { namespace } => repositories
            .iter()
            .enumerate()
            .filter(|(_, repository)| {
                if !repository.package_allowed(package) {
                    return false;
                }
                match repository.registry() {
                    crate::manifest::RegistrySpec::Cran => namespace.as_str() == "cran",
                    crate::manifest::RegistrySpec::CranLike {
                        namespace: candidate,
                    } => candidate == namespace,
                    crate::manifest::RegistrySpec::RUniverse => false,
                }
            })
            .map(|(index, _)| index)
            .collect(),
        rsolve_core::DependencySourceConstraint::Any => {
            eligible_entries(repositories, None, package)
        }
        // A source-qualified dependency cannot be satisfied by an arbitrary
        // registry.  Its dedicated backend/identity resolver owns these
        // constraints; this planner must fail closed rather than silently
        // routing them to CRAN or an R-universe.
        rsolve_core::DependencySourceConstraint::Bioconductor { .. }
        | rsolve_core::DependencySourceConstraint::Git { .. }
        | rsolve_core::DependencySourceConstraint::Exact(_) => Vec::new(),
    }
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
        DeclaredDependency, DependencySourceConstraint, GitCommitId, NormalizedGitUrl,
        PackageNamespace, Provenance, RPackageVersion, ReleaseIdentity, ReleaseMetadata,
        ReleaseObservation, RepositoryId, RootExpansionPolicy, VersionConstraint,
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

    fn direct_git_release(name: &str, dependencies: Vec<DeclaredDependency>) -> PackageRelease {
        let name = package(name);
        let version = RPackageVersion::parse("1.0.0").unwrap();
        PackageRelease::try_from(ReleaseObservation {
            identity: ReleaseIdentity::new(
                name.clone(),
                Provenance::GitCommit {
                    repository: NormalizedGitUrl::new("https://git.example.test/project").unwrap(),
                    commit: GitCommitId::new("0123456789012345678901234567890123456789").unwrap(),
                    subdirectory: None,
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

    fn git_root(name: &str, expansion: RootExpansionPolicy) -> ComposedRootIntent {
        ComposedRootIntent {
            name: package(name),
            constraint: VersionConstraint::unconstrained(),
            source: ManifestSource::Git {
                url: NormalizedGitUrl::new("https://git.example.test/project").unwrap(),
                selector: crate::manifest::GitSelector::DefaultBranch,
                subdirectory: None,
            },
            expansion,
        }
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
    fn direct_git_import_is_seeded_and_routed_to_configured_repository() {
        let repositories = vec![repository("cran", RegistrySpec::Cran, None)];
        let roots = vec![git_root("root", RootExpansionPolicy::HardOnly)];
        let direct = BTreeMap::from([(
            package("root"),
            direct_git_release("root", vec![dependency(DependencyKind::Imports, "dep")]),
        )]);
        let initial = initial_repository_demands_with_direct(&repositories, &roots, &direct);
        assert_eq!(initial[&0], BTreeSet::from([package("dep")]));

        let mut source = ScriptedSource::default();
        source
            .releases
            .insert((0, package("dep")), vec![release("dep", Vec::new())]);
        let plan =
            resolve_repository_demands_with_direct(&repositories, &roots, &direct, &mut source)
                .unwrap();
        assert_eq!(source.calls, vec![(0, package("dep"))]);
        assert_eq!(plan.entry_demands[&0], BTreeSet::from([package("dep")]));
        assert!(plan.discovered.contains(&package("dep")));
    }

    #[test]
    fn source_qualified_direct_dependency_is_not_routed_to_arbitrary_registry() {
        let repositories = vec![repository("cran", RegistrySpec::Cran, None)];
        let roots = vec![git_root("root", RootExpansionPolicy::HardOnly)];
        let dependency = DeclaredDependency::from_parts(
            DependencyKind::Imports,
            package("dep"),
            DependencySourceConstraint::Git {
                repository: NormalizedGitUrl::new("https://other.example.test/project").unwrap(),
            },
            VersionConstraint::unconstrained(),
        )
        .unwrap();
        let direct = BTreeMap::from([(
            package("root"),
            direct_git_release("root", vec![dependency]),
        )]);
        let initial = initial_repository_demands_with_direct(&repositories, &roots, &direct);
        assert!(initial.is_empty());
        let mut source = ScriptedSource::default();
        let plan =
            resolve_repository_demands_with_direct(&repositories, &roots, &direct, &mut source)
                .unwrap();
        assert!(plan.entry_demands.is_empty());
        assert_eq!(plan.unrouted, BTreeSet::from([package("dep")]));
        assert!(plan.discovered.contains(&package("dep")));
        assert!(source.calls.is_empty());
    }

    #[test]
    fn direct_git_suggests_seed_only_under_direct_suggests_expansion() {
        let repositories = vec![repository("cran", RegistrySpec::Cran, None)];
        let optional_dependency = dependency(DependencyKind::Suggests, "optional");
        let hard_only_roots = vec![git_root("root", RootExpansionPolicy::HardOnly)];
        let direct = BTreeMap::from([(
            package("root"),
            direct_git_release("root", vec![optional_dependency]),
        )]);
        assert!(
            initial_repository_demands_with_direct(&repositories, &hard_only_roots, &direct)
                .is_empty()
        );

        let expanded_roots = vec![git_root("root", RootExpansionPolicy::DirectSuggests)];
        let initial =
            initial_repository_demands_with_direct(&repositories, &expanded_roots, &direct);
        assert_eq!(initial[&0], BTreeSet::from([package("optional")]));

        let mut source = ScriptedSource::default();
        let nested = release(
            "optional",
            vec![dependency(DependencyKind::Suggests, "nested")],
        );
        source
            .releases
            .insert((0, package("optional")), vec![nested]);
        let plan = resolve_repository_demands_with_direct(
            &repositories,
            &expanded_roots,
            &direct,
            &mut source,
        )
        .unwrap();
        assert!(plan.discovered.contains(&package("optional")));
        assert!(!plan.discovered.contains(&package("nested")));
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
    fn direct_suggests_revisit_after_weak_traversal_promotes_suggests() {
        let repositories = vec![repository("cran", RegistrySpec::Cran, None)];
        let mut source = ScriptedSource::default();
        source.releases.insert(
            (0, package("direct")),
            vec![release(
                "direct",
                vec![dependency(DependencyKind::Suggests, "promoted")],
            )],
        );
        source.releases.insert(
            (0, package("other")),
            vec![release(
                "other",
                vec![dependency(DependencyKind::Depends, "direct")],
            )],
        );
        source.releases.insert(
            (0, package("promoted")),
            vec![release("promoted", Vec::new())],
        );

        // The direct-suggest root is pushed first. The later ordinary root is
        // popped first and reaches the same package through a weak edge.
        let plan = demand(
            &mut source,
            &repositories,
            &[
                root("direct", None, RootExpansionPolicy::DirectSuggests),
                root("other", None, RootExpansionPolicy::HardOnly),
            ],
        );

        assert_eq!(
            source.calls,
            vec![
                (0, package("other")),
                (0, package("direct")),
                (0, package("direct")),
                (0, package("promoted")),
            ]
        );
        assert!(plan.discovered.contains(&package("promoted")));
    }

    #[test]
    fn strong_first_direct_suggests_root_is_not_revisited_weakly() {
        let repositories = vec![repository("cran", RegistrySpec::Cran, None)];
        let mut source = ScriptedSource::default();
        source.releases.insert(
            (0, package("direct")),
            vec![release(
                "direct",
                vec![dependency(DependencyKind::Suggests, "promoted")],
            )],
        );
        source.releases.insert(
            (0, package("other")),
            vec![release(
                "other",
                vec![dependency(DependencyKind::Depends, "direct")],
            )],
        );
        source.releases.insert(
            (0, package("promoted")),
            vec![release("promoted", Vec::new())],
        );

        let plan = demand(
            &mut source,
            &repositories,
            &[
                root("other", None, RootExpansionPolicy::HardOnly),
                root("direct", None, RootExpansionPolicy::DirectSuggests),
            ],
        );

        assert_eq!(
            source.calls,
            vec![
                (0, package("direct")),
                (0, package("promoted")),
                (0, package("other")),
            ]
        );
        assert!(plan.discovered.contains(&package("promoted")));
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
