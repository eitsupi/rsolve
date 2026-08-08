use std::error::Error;
use std::fmt;

use crate::{PackageName, PackageRelease, ResolutionTarget, SolverKey};

/// The stable categories a candidate source may report to the resolver.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CandidateLoadErrorCategory {
    NotFound,
    SnapshotInvalid,
    TransportFailure,
    MetadataInvalid,
    AuthenticationFailed,
    Cancelled,
}

/// A typed, transport-neutral candidate loading failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateLoadError {
    category: CandidateLoadErrorCategory,
    diagnostic: Box<str>,
}

impl CandidateLoadError {
    pub fn new(category: CandidateLoadErrorCategory, diagnostic: impl Into<Box<str>>) -> Self {
        Self {
            category,
            diagnostic: diagnostic.into(),
        }
    }

    pub fn category(&self) -> CandidateLoadErrorCategory {
        self.category
    }

    pub fn diagnostic(&self) -> &str {
        &self.diagnostic
    }
}

impl fmt::Display for CandidateLoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.category, self.diagnostic)
    }
}

impl Error for CandidateLoadError {}

/// The resolver's candidate-loading port.  Implementations own their catalog
/// and any provider-specific conversion; the solver only sees validated
/// domain releases.
pub trait CandidateLoader {
    fn releases(&self, package: &SolverKey) -> Result<Vec<PackageRelease>, CandidateLoadError>;
}

/// One selected installable logical release.
#[derive(Clone, Debug)]
pub struct ResolvedPackage {
    subject: SolverKey,
    release: PackageRelease,
}

impl ResolvedPackage {
    pub fn subject(&self) -> &SolverKey {
        &self.subject
    }

    pub fn release(&self) -> &PackageRelease {
        &self.release
    }

    pub fn name(&self) -> &PackageName {
        self.release.identity().name()
    }

    #[doc(hidden)]
    pub fn new(subject: SolverKey, release: PackageRelease) -> Self {
        Self { subject, release }
    }
}

/// A successful logical solve.  R is represented by `target` and is not an
/// installable package entry.
#[derive(Clone, Debug)]
pub struct Resolution {
    target: ResolutionTarget,
    packages: Vec<ResolvedPackage>,
}

impl Resolution {
    #[doc(hidden)]
    pub fn new(target: ResolutionTarget, packages: Vec<ResolvedPackage>) -> Self {
        Self { target, packages }
    }

    pub fn target(&self) -> &ResolutionTarget {
        &self.target
    }

    pub fn packages(&self) -> &[ResolvedPackage] {
        &self.packages
    }

    pub fn selected(&self, name: &PackageName) -> Option<&PackageRelease> {
        self.packages
            .iter()
            .find(|package| package.name() == name)
            .map(ResolvedPackage::release)
    }
}
