use std::collections::HashMap;

use crate::constraints::{DependencySourceConstraint, RootRequirement, VersionConstraint};
use crate::identity::ReleaseIdentity;
use crate::names::{BioconductorRelease, PackageName, PackageNamespace, RepositoryId};
use crate::publication::PublicationCutoff;
use crate::target::ResolutionTarget;

/// The solver-facing key for a logical package subject.
///
/// This is a domain projection, not a manifest or provider type.  In
/// particular, a resolved immutable source is represented by its exact
/// release identity rather than by a mutable selector.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum SolverKey {
    Registry {
        namespace: PackageNamespace,
        name: PackageName,
    },
    Bioconductor {
        namespace: PackageNamespace,
        release: BioconductorRelease,
        name: PackageName,
    },
    Repository {
        repository: RepositoryId,
        name: PackageName,
    },
    Exact(ReleaseIdentity),
    InstalledName(PackageName),
    R,
}

/// Previous lock identities keyed by the logical subject they satisfied.
///
/// The map is intentionally owned so a request can be moved independently of
/// a lock reader, manifest parser, or catalog.
pub type LockedIdentities = HashMap<SolverKey, ReleaseIdentity>;

/// Fully composed, owned input to a resolver.
///
/// Manifest, feature, and environment schemas are deliberately absent here.
/// Composition code supplies the root package requirements, the exact target
/// whose R candidate is fixed, the root R constraint, and any identities from
/// a previous lock.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolutionRequest {
    pub roots: Vec<RootRequirement>,
    pub target: ResolutionTarget,
    pub r_requirement: VersionConstraint,
    pub locked: LockedIdentities,
    pub publication_cutoff: Option<PublicationCutoff>,
}

impl ResolutionRequest {
    pub fn new(
        roots: Vec<RootRequirement>,
        target: ResolutionTarget,
        r_requirement: VersionConstraint,
        locked: LockedIdentities,
    ) -> Self {
        Self {
            roots,
            target,
            r_requirement,
            locked,
            publication_cutoff: None,
        }
    }

    pub fn without_lock(
        roots: Vec<RootRequirement>,
        target: ResolutionTarget,
        r_requirement: VersionConstraint,
    ) -> Self {
        Self::new(roots, target, r_requirement, LockedIdentities::new())
    }

    pub fn with_publication_cutoff(mut self, cutoff: PublicationCutoff) -> Self {
        self.publication_cutoff = Some(cutoff);
        self
    }

    pub fn with_optional_publication_cutoff(mut self, cutoff: Option<PublicationCutoff>) -> Self {
        self.publication_cutoff = cutoff;
        self
    }

    /// Returns the exact identity selected by an exact root for this package,
    /// if any.
    ///
    /// Ordinary dependency declarations use [`DependencySourceConstraint::Any`]
    /// and are normally resolved through the installed-name subject. An exact
    /// root is an explicit exception: its identity is the only
    /// candidate that may satisfy an unqualified dependency on the same
    /// package. Source-qualified dependencies retain their own meaning.
    pub fn exact_root_identity(&self, name: &PackageName) -> Option<&ReleaseIdentity> {
        self.roots.iter().find_map(|root| {
            (root.package.name() == name).then(|| match root.package.source() {
                DependencySourceConstraint::Exact(identity) => Some(identity),
                _ => None,
            })?
        })
    }
}
