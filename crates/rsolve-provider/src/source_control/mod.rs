//! Source-control acquisition boundaries used by providers.
//!
//! This module deliberately has no manifest or resolver dependency.  Backend
//! selectors and transport diagnostics stay in [`git`]; downstream callers
//! receive only owned, validated source-control facts.

pub mod description;
pub mod git;
pub(crate) mod tree;

pub use description::{
    DescriptionProjectionError, DescriptionProjectionRequest, project_description,
};
pub use tree::{ImmutableSourceView, TreeError};
