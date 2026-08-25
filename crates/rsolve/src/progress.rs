use std::rc::Rc;

use rsolve_provider::cran::CranRefreshProgress;

/// Orchestration-level progress. Provider events stay scoped to CRAN
/// acquisition; resolver milestones belong to this crate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProgressEvent {
    Cran(CranRefreshProgress),
    ResolveStarted,
    ResolveCompleted { packages: usize },
}

pub type ProgressCallback = Rc<dyn Fn(ProgressEvent)>;
