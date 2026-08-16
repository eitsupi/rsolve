use std::collections::HashMap;

use crate::constraints::{DependencyRequirement, VersionConstraint};
use crate::identity::ReleaseIdentity;
use crate::names::{BioconductorRelease, PackageName, PackageNamespace};
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
    pub requirements: Vec<DependencyRequirement>,
    pub target: ResolutionTarget,
    pub r_requirement: VersionConstraint,
    pub locked: LockedIdentities,
    pub publication_cutoff: Option<PublicationCutoff>,
}

impl ResolutionRequest {
    pub fn new(
        requirements: Vec<DependencyRequirement>,
        target: ResolutionTarget,
        r_requirement: VersionConstraint,
        locked: LockedIdentities,
    ) -> Self {
        Self {
            requirements,
            target,
            r_requirement,
            locked,
            publication_cutoff: None,
        }
    }

    pub fn without_lock(
        requirements: Vec<DependencyRequirement>,
        target: ResolutionTarget,
        r_requirement: VersionConstraint,
    ) -> Self {
        Self::new(requirements, target, r_requirement, LockedIdentities::new())
    }

    pub fn with_publication_cutoff(mut self, cutoff: PublicationCutoff) -> Self {
        self.publication_cutoff = Some(cutoff);
        self
    }

    pub fn with_optional_publication_cutoff(mut self, cutoff: Option<PublicationCutoff>) -> Self {
        self.publication_cutoff = cutoff;
        self
    }
}
