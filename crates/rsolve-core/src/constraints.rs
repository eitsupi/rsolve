use std::cmp::Ordering;

use crate::identity::ReleaseIdentity;
use crate::names::{BioconductorRelease, NormalizedGitUrl, PackageName, PackageNamespace};
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
pub struct DependencyRequirement {
    pub kind: DependencyKind,
    pub name: PackageName,
    pub source: DependencySourceConstraint,
    pub constraint: VersionConstraint,
}

impl DependencyRequirement {
    pub fn new(
        kind: DependencyKind,
        name: PackageName,
        source: DependencySourceConstraint,
        constraint: VersionConstraint,
    ) -> Self {
        Self {
            kind,
            name,
            source,
            constraint,
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
}
