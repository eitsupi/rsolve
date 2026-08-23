mod aggregation;
mod digest;
mod types;

pub use aggregation::ReleaseAggregation;
pub use types::{
    PackageRelease, PackageReleaseError, ReleaseMetadata, ReleaseMetadataError, ReleaseObservation,
};

#[cfg(test)]
mod tests;
