use std::cmp::Ordering;

use crate::identity::ReleaseIdentity;
use crate::names::{
    BioconductorRelease, NormalizedGitUrl, PackageName, PackageNamespace, RepositoryId,
};
use crate::r_versions::RPackageVersion;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RelationOp {
    Lt,
    Le,
    Eq,
    Ne,
    Ge,
    Gt,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionClause {
    pub op: RelationOp,
    pub version: RPackageVersion,
}

impl VersionClause {
    pub fn new(op: RelationOp, version: RPackageVersion) -> Self {
        Self { op, version }
    }
}

/// A conjunction of R package-version relation clauses.
///
/// An empty clause list is the explicit unconstrained case.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionConstraint {
    pub clauses: Vec<VersionClause>,
}

impl VersionConstraint {
    pub fn unconstrained() -> Self {
        Self { clauses: vec![] }
    }

    pub fn any() -> Self {
        Self::unconstrained()
    }

    pub fn new(clauses: Vec<VersionClause>) -> Self {
        Self { clauses }
    }

    /// Combines two constraints as a conjunction, preserving every clause.
    pub fn conjunction(&self, other: &Self) -> Self {
        let mut clauses = self.clauses.clone();
        clauses.extend(other.clauses.iter().cloned());
        Self::new(clauses)
    }

    pub fn from_clause(op: RelationOp, version: RPackageVersion) -> Self {
        Self::new(vec![VersionClause::new(op, version)])
    }

    pub fn is_unconstrained(&self) -> bool {
        self.clauses.is_empty()
    }

    pub fn satisfies(&self, candidate: &RPackageVersion) -> bool {
        self.clauses.iter().all(|clause| {
            let ordering = candidate.cmp(&clause.version);
            match clause.op {
                RelationOp::Lt => ordering == Ordering::Less,
                RelationOp::Le => ordering != Ordering::Greater,
                RelationOp::Eq => ordering == Ordering::Equal,
                RelationOp::Ne => ordering != Ordering::Equal,
                RelationOp::Ge => ordering != Ordering::Less,
                RelationOp::Gt => ordering == Ordering::Greater,
            }
        })
    }

    pub fn matches(&self, candidate: &RPackageVersion) -> bool {
        self.satisfies(candidate)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DependencyKind {
    Depends,
    Imports,
    LinkingTo,
    Suggests,
    Enhances,
}

/// An optional source scope for a dependency.  R DESCRIPTION dependencies
/// normally use [`Any`], while providers may preserve a more specific scope.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub enum DependencySourceConstraint {
    #[default]
    Any,
    Registry {
        namespace: PackageNamespace,
    },
    Repository {
        repository: RepositoryId,
    },
    Bioconductor {
        namespace: PackageNamespace,
        release: BioconductorRelease,
    },
    Git {
        repository: NormalizedGitUrl,
    },
    Exact(ReleaseIdentity),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageRequirement {
    name: PackageName,
    source: DependencySourceConstraint,
    constraint: VersionConstraint,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PackageRequirementError {
    ExactIdentityNameMismatch {
        package: PackageName,
        identity: PackageName,
    },
}

impl std::fmt::Display for PackageRequirementError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ExactIdentityNameMismatch { package, identity } => write!(
                f,
                "exact release identity name {identity} does not match package requirement {package}"
            ),
        }
    }
}

impl std::error::Error for PackageRequirementError {}

impl PackageRequirement {
    pub fn new(
        name: PackageName,
        source: DependencySourceConstraint,
        constraint: VersionConstraint,
    ) -> Result<Self, PackageRequirementError> {
        if let DependencySourceConstraint::Exact(identity) = &source
            && identity.name() != &name
        {
            return Err(PackageRequirementError::ExactIdentityNameMismatch {
                package: name,
                identity: identity.name().clone(),
            });
        }
        Ok(Self {
            name,
            source,
            constraint,
        })
    }

    pub fn name(&self) -> &PackageName {
        &self.name
    }

    pub fn source(&self) -> &DependencySourceConstraint {
        &self.source
    }

    pub fn constraint(&self) -> &VersionConstraint {
        &self.constraint
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootRequirement {
    pub package: PackageRequirement,
    pub expansion: RootExpansionPolicy,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RootExpansionPolicy {
    HardOnly,
    DirectSuggests,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RootCompositionError {
    ConflictingSource {
        name: PackageName,
        left: Box<DependencySourceConstraint>,
        right: Box<DependencySourceConstraint>,
    },
    ConflictingExactIdentity {
        name: PackageName,
        left: Box<DependencySourceConstraint>,
        right: Box<DependencySourceConstraint>,
    },
    ConflictingPackageNames {
        left: PackageName,
        right: PackageName,
    },
}

impl std::fmt::Display for RootCompositionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ConflictingSource { name, left, right } => {
                write!(f, "conflicting sources for {name}: {left:?} vs {right:?}")
            }
            Self::ConflictingExactIdentity { name, left, right } => {
                write!(
                    f,
                    "conflicting exact identities for {name}: {left:?} vs {right:?}"
                )
            }
            Self::ConflictingPackageNames { left, right } => {
                write!(f, "cannot combine roots for {left} and {right}")
            }
        }
    }
}

impl std::error::Error for RootCompositionError {}

impl RootRequirement {
    pub fn combine(self, other: Self) -> Result<Self, RootCompositionError> {
        if self.package.name != other.package.name {
            return Err(RootCompositionError::ConflictingPackageNames {
                left: self.package.name,
                right: other.package.name,
            });
        }
        let name = self.package.name.clone();
        let left_source = self.package.source().clone();
        let right_source = other.package.source().clone();
        let source = combine_sources(&left_source, &right_source, name.clone())?;
        Ok(Self {
            package: PackageRequirement::new(
                name,
                source,
                self.package
                    .constraint()
                    .conjunction(other.package.constraint()),
            )
            .map_err(|_| RootCompositionError::ConflictingExactIdentity {
                name: self.package.name,
                left: Box::new(left_source),
                right: Box::new(right_source),
            })?,
            expansion: if self.expansion == RootExpansionPolicy::DirectSuggests
                || other.expansion == RootExpansionPolicy::DirectSuggests
            {
                RootExpansionPolicy::DirectSuggests
            } else {
                RootExpansionPolicy::HardOnly
            },
        })
    }
}

fn combine_sources(
    left: &DependencySourceConstraint,
    right: &DependencySourceConstraint,
    name: PackageName,
) -> Result<DependencySourceConstraint, RootCompositionError> {
    if left == right {
        return Ok(left.clone());
    }
    match (left, right) {
        (DependencySourceConstraint::Any, specific)
        | (specific, DependencySourceConstraint::Any) => Ok(specific.clone()),
        (
            DependencySourceConstraint::Exact(left_identity),
            DependencySourceConstraint::Exact(right_identity),
        ) => {
            if left_identity == right_identity {
                Ok(DependencySourceConstraint::Exact(left_identity.clone()))
            } else {
                Err(RootCompositionError::ConflictingExactIdentity {
                    name,
                    left: Box::new(left.clone()),
                    right: Box::new(right.clone()),
                })
            }
        }
        _ => Err(RootCompositionError::ConflictingSource {
            name,
            left: Box::new(left.clone()),
            right: Box::new(right.clone()),
        }),
    }
}

/// Composes roots by merging entries with the same package name.
pub fn combine_root_requirements(
    roots: impl IntoIterator<Item = RootRequirement>,
) -> Result<Vec<RootRequirement>, RootCompositionError> {
    let mut composed = std::collections::BTreeMap::<PackageName, RootRequirement>::new();
    for root in roots {
        let name = root.package.name.clone();
        if let Some(existing) = composed.remove(&name) {
            composed.insert(name, existing.combine(root)?);
        } else {
            composed.insert(name, root);
        }
    }
    Ok(composed.into_values().collect())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeclaredDependency {
    pub kind: DependencyKind,
    pub package: PackageRequirement,
}

impl DeclaredDependency {
    pub fn new(kind: DependencyKind, package: PackageRequirement) -> Self {
        Self { kind, package }
    }

    pub fn from_parts(
        kind: DependencyKind,
        name: PackageName,
        source: DependencySourceConstraint,
        constraint: VersionConstraint,
    ) -> Result<Self, PackageRequirementError> {
        Ok(Self {
            kind,
            package: PackageRequirement::new(name, source, constraint)?,
        })
    }

    pub fn from_package(kind: DependencyKind, package: PackageRequirement) -> Self {
        Self { kind, package }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum EffectiveDependencyKind {
    Depends,
    Imports,
    LinkingTo,
    PromotedSuggests,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedDependencyEdge {
    pub kind: EffectiveDependencyKind,
    pub package: PackageRequirement,
}

impl DependencyKind {
    pub fn effective(self) -> Option<EffectiveDependencyKind> {
        match self {
            Self::Depends => Some(EffectiveDependencyKind::Depends),
            Self::Imports => Some(EffectiveDependencyKind::Imports),
            Self::LinkingTo => Some(EffectiveDependencyKind::LinkingTo),
            Self::Suggests | Self::Enhances => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn version(value: &str) -> RPackageVersion {
        RPackageVersion::parse(value).unwrap()
    }

    #[test]
    fn constraints_evaluate_all_r_relations_and_unconstrained_case() {
        let candidate = version("4.4.0");
        let cases = [
            (RelationOp::Ge, "4.4", true),
            (RelationOp::Gt, "4.4", false),
            (RelationOp::Le, "4.4.0", true),
            (RelationOp::Lt, "4.4.0", false),
            (RelationOp::Eq, "4.4", true),
            (RelationOp::Ne, "4.4", false),
        ];
        for (op, required, expected) in cases {
            assert_eq!(
                VersionConstraint::from_clause(op, version(required)).satisfies(&candidate),
                expected,
                "{op:?} {required}"
            );
        }
        assert!(VersionConstraint::unconstrained().satisfies(&candidate));
        assert!(
            VersionConstraint::new(vec![
                VersionClause::new(RelationOp::Ge, version("4.0")),
                VersionClause::new(RelationOp::Lt, version("5.0")),
            ])
            .satisfies(&candidate)
        );
    }

    #[test]
    fn declared_and_effective_dependency_models_keep_their_roles_distinct() {
        let package = PackageName::new("child").unwrap();
        let requirement = PackageRequirement::new(
            package.clone(),
            DependencySourceConstraint::Repository {
                repository: RepositoryId::new("primary").unwrap(),
            },
            VersionConstraint::unconstrained(),
        )
        .unwrap();
        let declared =
            DeclaredDependency::from_package(DependencyKind::Imports, requirement.clone());
        assert_eq!(declared.package, requirement);
        assert_eq!(
            DependencyKind::Imports.effective(),
            Some(EffectiveDependencyKind::Imports)
        );
        assert_eq!(DependencyKind::Suggests.effective(), None);
    }

    #[test]
    fn roots_compose_constraints_sources_and_expansion() {
        let name = PackageName::new("pkg").unwrap();
        let repository = RepositoryId::new("main").unwrap();
        let first = RootRequirement {
            package: PackageRequirement::new(
                name.clone(),
                DependencySourceConstraint::Any,
                VersionConstraint::from_clause(RelationOp::Ge, version("1.0")),
            )
            .unwrap(),
            expansion: RootExpansionPolicy::HardOnly,
        };
        let second = RootRequirement {
            package: PackageRequirement::new(
                name.clone(),
                DependencySourceConstraint::Repository { repository },
                VersionConstraint::from_clause(RelationOp::Lt, version("2.0")),
            )
            .unwrap(),
            expansion: RootExpansionPolicy::DirectSuggests,
        };
        let composed = combine_root_requirements([first, second]).unwrap();
        assert_eq!(composed.len(), 1);
        assert_eq!(composed[0].package.constraint().clauses.len(), 2);
        assert_eq!(composed[0].expansion, RootExpansionPolicy::DirectSuggests);
        assert!(matches!(
            composed[0].package.source(),
            DependencySourceConstraint::Repository { .. }
        ));
    }

    #[test]
    fn roots_reject_conflicting_repository_and_exact_sources() {
        let name = PackageName::new("pkg").unwrap();
        let root = |source| RootRequirement {
            package: PackageRequirement::new(
                name.clone(),
                source,
                VersionConstraint::unconstrained(),
            )
            .unwrap(),
            expansion: RootExpansionPolicy::HardOnly,
        };
        let left = root(DependencySourceConstraint::Repository {
            repository: RepositoryId::new("one").unwrap(),
        });
        let right = root(DependencySourceConstraint::Repository {
            repository: RepositoryId::new("two").unwrap(),
        });
        let error = combine_root_requirements([left, right]).unwrap_err();
        let RootCompositionError::ConflictingSource { left, right, .. } = error else {
            panic!("repository source conflict must retain both source intents");
        };
        assert!(matches!(
            (&*left, &*right),
            (
                DependencySourceConstraint::Repository { .. },
                DependencySourceConstraint::Repository { .. }
            )
        ));

        let one = ReleaseIdentity::new(
            name.clone(),
            crate::Provenance::RegistryRelease {
                namespace: PackageNamespace::new("cran").unwrap(),
                version: version("1.0"),
            },
        );
        let two = ReleaseIdentity::new(
            name.clone(),
            crate::Provenance::RegistryRelease {
                namespace: PackageNamespace::new("cran").unwrap(),
                version: version("2.0"),
            },
        );
        let error = combine_root_requirements([
            root(DependencySourceConstraint::Exact(one)),
            root(DependencySourceConstraint::Exact(two)),
        ])
        .unwrap_err();
        let RootCompositionError::ConflictingExactIdentity { left, right, .. } = error else {
            panic!("exact source conflict must retain both source intents");
        };
        assert!(matches!(
            (&*left, &*right),
            (
                DependencySourceConstraint::Exact(_),
                DependencySourceConstraint::Exact(_)
            )
        ));
    }

    #[test]
    fn package_requirement_try_new_rejects_exact_identity_name_mismatch() {
        let identity = ReleaseIdentity::new(
            PackageName::new("other").unwrap(),
            crate::Provenance::RegistryRelease {
                namespace: PackageNamespace::new("cran").unwrap(),
                version: version("1.0"),
            },
        );
        assert!(matches!(
            PackageRequirement::new(
                PackageName::new("pkg").unwrap(),
                DependencySourceConstraint::Exact(identity),
                VersionConstraint::unconstrained(),
            ),
            Err(PackageRequirementError::ExactIdentityNameMismatch { .. })
        ));
    }
}
