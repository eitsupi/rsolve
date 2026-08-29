use std::collections::HashMap;

use rsolve_core::{
    CandidateAvailability, CandidateCurrentness, CandidateLoadError, CandidateLoadErrorCategory,
    CandidateLoader, DependencySourceConstraint, Distribution, DistributionChannel,
    DistributionMetadata, NonRepositoryExposure, PackageName, PackageNamespace, PackageRelease,
    PreparedCandidate, Provenance, RPackageVersion, RegistryId, RelationOp, ReleaseIdentity,
    ReleaseMetadata, ReleaseObservation, RepositoryId, RepositoryOccurrence, RepositoryRank,
    ResolutionRequest, ResolutionTarget, RootExpansionPolicy, RootRequirement, SolverKey,
    VersionConstraint,
};
use rsolve_resolver::{DefaultCandidatePreference, PreferLocked, Resolver};

#[derive(Clone, Copy)]
struct OccurrenceSpec {
    repository: &'static str,
    registry: &'static str,
    availability: CandidateAvailability,
    currentness: CandidateCurrentness,
    rank: u32,
    channel: Option<&'static str>,
}

fn occurrence(
    repository: &'static str,
    registry: &'static str,
    availability: CandidateAvailability,
    currentness: CandidateCurrentness,
    rank: u32,
    channel: Option<&'static str>,
) -> OccurrenceSpec {
    OccurrenceSpec {
        repository,
        registry,
        availability,
        currentness,
        rank,
        channel,
    }
}

fn registry_release(
    namespace: &'static str,
    version: &'static str,
    specs: &[OccurrenceSpec],
) -> PackageRelease {
    let name = PackageName::new("Foo").unwrap();
    let version = RPackageVersion::parse(version).unwrap();
    let identity = ReleaseIdentity::new(
        name.clone(),
        Provenance::RegistryRelease {
            namespace: PackageNamespace::new(namespace).unwrap(),
            version: version.clone(),
        },
    );
    let mut distributions = Vec::new();
    for spec in specs {
        let Some(channel) = spec.channel else {
            continue;
        };
        let distribution = Distribution {
            registry: RegistryId::new(spec.registry).unwrap(),
            channel: DistributionChannel::new(channel).unwrap(),
            snapshot: None,
            artifacts: Vec::new(),
            observed_metadata: DistributionMetadata::default(),
        };
        if !distributions.contains(&distribution) {
            distributions.push(distribution);
        }
    }
    PackageRelease::try_from(ReleaseObservation {
        identity,
        observed_package: name,
        observed_version: version,
        metadata: ReleaseMetadata::default(),
        publication: None,
        declared_dependencies: Vec::new(),
        distributions,
    })
    .unwrap()
}

fn prepared(
    namespace: &'static str,
    version: &'static str,
    specs: &[OccurrenceSpec],
) -> PreparedCandidate {
    let release = registry_release(namespace, version, specs);
    let occurrences = specs
        .iter()
        .map(|spec| {
            let distributions = release
                .distributions()
                .iter()
                .filter(|distribution| {
                    distribution.registry.as_str() == spec.registry
                        && spec
                            .channel
                            .is_some_and(|channel| distribution.channel.as_str() == channel)
                })
                .cloned()
                .collect();
            RepositoryOccurrence::new(
                RepositoryId::new(spec.repository).unwrap(),
                RegistryId::new(spec.registry).unwrap(),
                spec.availability,
                spec.currentness,
                RepositoryRank::new(spec.rank.into()),
                distributions,
            )
            .unwrap()
        })
        .collect();
    PreparedCandidate::new(release, NonRepositoryExposure::None, occurrences).unwrap()
}

fn exact_only(namespace: &'static str) -> PreparedCandidate {
    let release = registry_release(namespace, "1.0.0", &[]);
    PreparedCandidate::new(release, NonRepositoryExposure::ExactOnly, Vec::new()).unwrap()
}

fn request(
    source: DependencySourceConstraint,
    constraint: VersionConstraint,
    locked: Option<ReleaseIdentity>,
) -> ResolutionRequest {
    let package = PackageName::new("Foo").unwrap();
    let mut locked_identities = HashMap::new();
    if let Some(identity) = locked {
        let key = match &source {
            DependencySourceConstraint::Repository { repository } => SolverKey::Repository {
                repository: repository.clone(),
                name: package.clone(),
            },
            _ => SolverKey::InstalledName(package.clone()),
        };
        locked_identities.insert(key, identity);
    }
    ResolutionRequest::new(
        vec![RootRequirement {
            package: rsolve_core::PackageRequirement::new(package, source, constraint).unwrap(),
            expansion: RootExpansionPolicy::HardOnly,
        }],
        ResolutionTarget::new(RPackageVersion::parse("4.4.0").unwrap()),
        VersionConstraint::unconstrained(),
        locked_identities,
    )
}

fn any_request(constraint: VersionConstraint) -> ResolutionRequest {
    request(DependencySourceConstraint::Any, constraint, None)
}

fn repository_request(
    repository: &'static str,
    constraint: VersionConstraint,
) -> ResolutionRequest {
    request(
        DependencySourceConstraint::Repository {
            repository: RepositoryId::new(repository).unwrap(),
        },
        constraint,
        None,
    )
}

fn exact_constraint(version: &'static str) -> VersionConstraint {
    VersionConstraint::from_clause(RelationOp::Eq, RPackageVersion::parse(version).unwrap())
}

struct OccurrenceLoader {
    candidates: Vec<PreparedCandidate>,
    reverse: bool,
}

impl OccurrenceLoader {
    fn new(candidates: Vec<PreparedCandidate>) -> Self {
        Self {
            candidates,
            reverse: false,
        }
    }

    fn reversed(mut self) -> Self {
        self.reverse = true;
        self
    }
}

impl CandidateLoader for OccurrenceLoader {
    fn releases(&self, subject: &SolverKey) -> Result<Vec<PreparedCandidate>, CandidateLoadError> {
        let name = match subject {
            SolverKey::InstalledName(name)
            | SolverKey::Registry { name, .. }
            | SolverKey::Repository { name, .. }
            | SolverKey::Bioconductor { name, .. } => name,
            SolverKey::Exact(identity) => identity.name(),
            SolverKey::R => {
                return Err(CandidateLoadError::new(
                    CandidateLoadErrorCategory::NotFound,
                    "occurrence fixture does not load R",
                ));
            }
        };
        let mut candidates = self
            .candidates
            .iter()
            .filter(|candidate| candidate.identity().name() == name)
            .cloned()
            .collect::<Vec<_>>();
        if self.reverse {
            candidates.reverse();
        }
        Ok(candidates)
    }
}

fn resolver(loader: &OccurrenceLoader) -> Resolver<'_> {
    static PREFERENCE: DefaultCandidatePreference = DefaultCandidatePreference;
    static LOCK_POLICY: PreferLocked = PreferLocked;
    Resolver::new(loader, &PREFERENCE, &LOCK_POLICY)
}

fn selected_namespace(request: ResolutionRequest, loader: &OccurrenceLoader) -> String {
    let resolution = resolver(loader).resolve(request).unwrap();
    let provenance = resolution
        .packages()
        .first()
        .unwrap()
        .identity()
        .provenance();
    match provenance {
        Provenance::RegistryRelease { namespace, .. } => namespace.as_str().to_owned(),
        other => panic!("fixture selected unexpected provenance: {other:?}"),
    }
}

fn selected_version(request: ResolutionRequest, loader: &OccurrenceLoader) -> RPackageVersion {
    resolver(loader)
        .resolve(request)
        .unwrap()
        .packages()
        .first()
        .unwrap()
        .version()
        .clone()
}

#[test]
fn older_current_beats_newer_historical() {
    let loader = OccurrenceLoader::new(vec![
        prepared(
            "cran",
            "1.0.0",
            &[occurrence(
                "main",
                "cran",
                CandidateAvailability::Available,
                CandidateCurrentness::Current,
                0,
                Some("source"),
            )],
        ),
        prepared(
            "cran",
            "2.0.0",
            &[occurrence(
                "main",
                "cran",
                CandidateAvailability::Available,
                CandidateCurrentness::Historical,
                0,
                Some("source"),
            )],
        ),
    ]);
    assert_eq!(
        selected_version(any_request(VersionConstraint::unconstrained()), &loader),
        RPackageVersion::parse("1.0.0").unwrap()
    );
}

#[test]
fn constraint_can_force_historical_fallback() {
    let loader = OccurrenceLoader::new(vec![
        prepared(
            "cran",
            "1.0.0",
            &[occurrence(
                "main",
                "cran",
                CandidateAvailability::Available,
                CandidateCurrentness::Current,
                0,
                Some("source"),
            )],
        ),
        prepared(
            "cran",
            "2.0.0",
            &[occurrence(
                "main",
                "cran",
                CandidateAvailability::Available,
                CandidateCurrentness::Historical,
                0,
                Some("source"),
            )],
        ),
    ]);
    let constraint =
        VersionConstraint::from_clause(RelationOp::Ge, RPackageVersion::parse("2.0.0").unwrap());
    assert_eq!(
        selected_version(any_request(constraint), &loader),
        RPackageVersion::parse("2.0.0").unwrap()
    );
}

#[test]
fn compatible_locked_historical_beats_current() {
    let historical = prepared(
        "cran",
        "2.0.0",
        &[occurrence(
            "main",
            "cran",
            CandidateAvailability::Available,
            CandidateCurrentness::Historical,
            0,
            Some("source"),
        )],
    );
    let locked = historical.identity().clone();
    let loader = OccurrenceLoader::new(vec![
        prepared(
            "cran",
            "1.0.0",
            &[occurrence(
                "main",
                "cran",
                CandidateAvailability::Available,
                CandidateCurrentness::Current,
                0,
                Some("source"),
            )],
        ),
        historical,
    ]);
    let request = request(
        DependencySourceConstraint::Any,
        VersionConstraint::unconstrained(),
        Some(locked),
    );
    assert_eq!(
        selected_version(request, &loader),
        RPackageVersion::parse("2.0.0").unwrap()
    );
}

#[test]
fn lower_applicable_repository_rank_breaks_same_version_tie_and_is_order_independent() {
    let candidates = vec![
        prepared(
            "high",
            "1.0.0",
            &[occurrence(
                "main",
                "cran",
                CandidateAvailability::Available,
                CandidateCurrentness::Current,
                1,
                Some("source"),
            )],
        ),
        prepared(
            "low",
            "1.0.0",
            &[occurrence(
                "main",
                "cran",
                CandidateAvailability::Available,
                CandidateCurrentness::Current,
                0,
                Some("source"),
            )],
        ),
    ];
    let forward = OccurrenceLoader::new(candidates.clone());
    let reverse = OccurrenceLoader::new(candidates).reversed();
    assert!(
        selected_namespace(any_request(VersionConstraint::unconstrained()), &forward)
            .contains("low")
    );
    assert!(
        selected_namespace(any_request(VersionConstraint::unconstrained()), &reverse)
            .contains("low")
    );
}

#[test]
fn explicit_repository_ignores_other_occurrence_facts_and_metadata_only_is_ineligible() {
    let loader = OccurrenceLoader::new(vec![
        prepared(
            "other-current",
            "1.0.0",
            &[
                occurrence(
                    "target",
                    "cran",
                    CandidateAvailability::Available,
                    CandidateCurrentness::Historical,
                    5,
                    Some("source"),
                ),
                occurrence(
                    "other",
                    "cran",
                    CandidateAvailability::Available,
                    CandidateCurrentness::Current,
                    0,
                    Some("binary"),
                ),
            ],
        ),
        prepared(
            "target-current",
            "1.0.0",
            &[occurrence(
                "target",
                "cran",
                CandidateAvailability::Available,
                CandidateCurrentness::Current,
                6,
                Some("source"),
            )],
        ),
    ]);
    let selected = resolver(&loader)
        .resolve(repository_request(
            "target",
            VersionConstraint::unconstrained(),
        ))
        .unwrap();
    assert!(matches!(
        selected.packages().first().unwrap().identity().provenance(),
        Provenance::RegistryRelease { namespace, .. } if namespace.as_str() == "target-current"
    ));

    let metadata_only = OccurrenceLoader::new(vec![prepared(
        "metadata-only",
        "1.0.0",
        &[occurrence(
            "target",
            "cran",
            CandidateAvailability::MetadataOnly,
            CandidateCurrentness::Current,
            0,
            Some("source"),
        )],
    )]);
    assert!(
        resolver(&metadata_only)
            .resolve(repository_request(
                "target",
                VersionConstraint::unconstrained()
            ))
            .is_err()
    );
}

#[test]
fn resolution_keeps_ranked_visible_repositories_and_distribution_union() {
    let candidate = prepared(
        "cran",
        "1.0.0",
        &[
            occurrence(
                "repo-b",
                "cran",
                CandidateAvailability::Available,
                CandidateCurrentness::Current,
                2,
                Some("binary"),
            ),
            occurrence(
                "repo-a",
                "cran",
                CandidateAvailability::Available,
                CandidateCurrentness::Current,
                0,
                Some("source"),
            ),
            occurrence(
                "repo-c",
                "cran",
                CandidateAvailability::Available,
                CandidateCurrentness::Current,
                1,
                Some("mac"),
            ),
            occurrence(
                "repo-a",
                "cran",
                CandidateAvailability::Available,
                CandidateCurrentness::Current,
                0,
                Some("binary"),
            ),
        ],
    );
    let loader = OccurrenceLoader::new(vec![candidate]);
    let package = resolver(&loader)
        .resolve(any_request(VersionConstraint::unconstrained()))
        .unwrap()
        .packages()
        .first()
        .unwrap()
        .clone();
    assert_eq!(
        package.visible_repository_ids(),
        [
            RepositoryId::new("repo-a").unwrap(),
            RepositoryId::new("repo-c").unwrap(),
            RepositoryId::new("repo-b").unwrap(),
        ]
    );
    assert_eq!(package.distributions().len(), 3);

    let explicit = resolver(&loader)
        .resolve(repository_request(
            "repo-c",
            VersionConstraint::unconstrained(),
        ))
        .unwrap();
    let explicit = explicit.packages().first().unwrap();
    assert_eq!(
        explicit.visible_repository_ids(),
        [RepositoryId::new("repo-c").unwrap()]
    );
    assert_eq!(explicit.distributions().len(), 3);
}

#[test]
fn assignment_comparison_uses_applicable_repository_rank_and_is_order_independent() {
    let candidates = vec![
        prepared(
            "high",
            "1.0.0",
            &[occurrence(
                "main",
                "cran",
                CandidateAvailability::Available,
                CandidateCurrentness::Current,
                1,
                Some("source"),
            )],
        ),
        prepared(
            "low",
            "1.0.0",
            &[occurrence(
                "main",
                "cran",
                CandidateAvailability::Available,
                CandidateCurrentness::Current,
                0,
                Some("source"),
            )],
        ),
    ];
    let request = any_request(VersionConstraint::unconstrained());
    let forward = resolver(&OccurrenceLoader::new(candidates.clone()))
        .resolve_with_assignment_comparison(request.clone())
        .unwrap();
    let reverse = resolver(&OccurrenceLoader::new(candidates).reversed())
        .resolve_with_assignment_comparison(request)
        .unwrap();
    assert_eq!(forward.comparison, reverse.comparison);
    let assignment = forward
        .comparison
        .assignments
        .iter()
        .find(|assignment| {
            matches!(
                assignment.subject,
                rsolve_resolver::DecisionSubject::InstalledName(ref name)
                    if name.as_str() == "Foo"
            )
        })
        .unwrap();
    assert!(assignment.alternatives.iter().any(|alternative| matches!(
        alternative.differs_by,
        rsolve_resolver::AssignmentDifference::LowerPreference { .. }
    )));
}

#[test]
fn ineligible_exact_only_and_metadata_only_candidates_do_not_solve_installed_name() {
    let metadata = prepared(
        "metadata",
        "2.0.0",
        &[occurrence(
            "target",
            "cran",
            CandidateAvailability::MetadataOnly,
            CandidateCurrentness::Current,
            0,
            Some("source"),
        )],
    );
    let loader = OccurrenceLoader::new(vec![exact_only("direct"), metadata]);
    assert!(
        resolver(&loader)
            .resolve(any_request(VersionConstraint::unconstrained()))
            .is_err()
    );
}

#[test]
fn exact_only_candidate_remains_eligible_for_exact_scope() {
    let candidate = exact_only("direct");
    let identity = candidate.identity().clone();
    let loader = OccurrenceLoader::new(vec![candidate]);
    let request = request(
        DependencySourceConstraint::Exact(identity.clone()),
        exact_constraint("1.0.0"),
        None,
    );
    let selected = resolver(&loader).resolve(request).unwrap();
    assert_eq!(selected.packages().first().unwrap().identity(), &identity);
}
