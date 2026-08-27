//! Operation-local resolution telemetry.
//!
//! These types deliberately contain neither provider endpoints nor cache
//! locations. They are snapshots of one resolution invocation and are never
//! written into a metadata snapshot or lockfile.

use std::cell::RefCell;
use std::collections::HashSet;
use std::rc::Rc;
use std::time::Instant;

use rsolve_core::SolverKey;
use rsolve_provider::cran::CranRefreshMetrics;
use serde::Serialize;

/// The cache branch selected by the resolver operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotCacheDecision {
    FreshHit,
    Refreshed,
    OfflineCompatible,
    NotApplicable,
}

/// The independently measured orchestration stages.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct ResolutionPhaseMetrics {
    pub snapshot_cache_decision_ns: Option<u64>,
    pub refresh_acquisition_ns: Option<u64>,
    pub closure_lookup_ns: Option<u64>,
    pub snapshot_composition_and_publication_ns: Option<u64>,
    pub prepared_loader_lookup_ns: Option<u64>,
    pub solve_ns: Option<u64>,
    pub lock_projection_ns: Option<u64>,
    pub lock_serialization_ns: Option<u64>,
    pub lock_round_trip_ns: Option<u64>,
    pub atomic_lock_write_ns: Option<u64>,
}

/// Counts and phases collected for one resolve operation.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct ResolutionMetrics {
    pub phases: ResolutionPhaseMetrics,
    /// Set when any metric could not be represented in the report unit.
    /// Consumers must reject such a report rather than treating it as zero.
    pub metrics_overflow: bool,
    pub snapshot_cache_decision: Option<SnapshotCacheDecision>,
    pub loader_lookup_calls: u64,
    pub loader_unique_package_count: u64,
    pub solve_output_package_count: u64,
    pub provider_refresh: Option<CranRefreshMetrics>,
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
pub(crate) enum Phase {
    SnapshotCacheDecision,
    RefreshAcquisition,
    ClosureLookup,
    SnapshotCompositionAndPublication,
    PreparedLoaderLookup,
    Solve,
    LockProjection,
    LockSerialization,
    LockRoundTrip,
    AtomicLockWrite,
}

#[derive(Debug, Default)]
pub(crate) struct MetricsState {
    pub metrics: ResolutionMetrics,
    packages: HashSet<SolverKey>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct MetricsRecorder {
    state: Rc<RefCell<MetricsState>>,
}

impl MetricsRecorder {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn snapshot(&self) -> ResolutionMetrics {
        self.state.borrow().metrics.clone()
    }

    pub(crate) fn observe_lookup(&self, package: &SolverKey) {
        let mut state = self.state.borrow_mut();
        let Some(calls) = state.metrics.loader_lookup_calls.checked_add(1) else {
            state.metrics.metrics_overflow = true;
            return;
        };
        state.metrics.loader_lookup_calls = calls;
        state.packages.insert(package.clone());
        let Some(unique) = u64::try_from(state.packages.len()).ok() else {
            state.metrics.metrics_overflow = true;
            return;
        };
        state.metrics.loader_unique_package_count = unique;
    }

    pub(crate) fn set_solve_output_count(&self, count: usize) {
        let mut state = self.state.borrow_mut();
        let Some(count) = u64::try_from(count).ok() else {
            state.metrics.metrics_overflow = true;
            return;
        };
        state.metrics.solve_output_package_count = count;
    }

    pub(crate) fn set_provider_refresh(&self, metrics: CranRefreshMetrics) {
        self.state.borrow_mut().metrics.provider_refresh = Some(metrics);
    }

    pub(crate) fn set_cache_decision(&self, decision: SnapshotCacheDecision) {
        self.state.borrow_mut().metrics.snapshot_cache_decision = Some(decision);
    }

    pub(crate) fn measure<T>(&self, phase: Phase, operation: impl FnOnce() -> T) -> T {
        let started = Instant::now();
        let result = operation();
        self.record_duration(phase, started.elapsed());
        result
    }

    pub(crate) fn record_duration(&self, phase: Phase, duration: std::time::Duration) {
        // Duration::as_nanos is bounded by u128. A report cannot represent a
        // value outside u64, so fail closed by leaving the phase absent.
        let Some(nanos) = u64::try_from(duration.as_nanos()).ok() else {
            self.state.borrow_mut().metrics.metrics_overflow = true;
            return;
        };
        let mut state = self.state.borrow_mut();
        let slot = match phase {
            Phase::SnapshotCacheDecision => &mut state.metrics.phases.snapshot_cache_decision_ns,
            Phase::RefreshAcquisition => &mut state.metrics.phases.refresh_acquisition_ns,
            Phase::ClosureLookup => &mut state.metrics.phases.closure_lookup_ns,
            Phase::SnapshotCompositionAndPublication => {
                &mut state.metrics.phases.snapshot_composition_and_publication_ns
            }
            Phase::PreparedLoaderLookup => &mut state.metrics.phases.prepared_loader_lookup_ns,
            Phase::Solve => &mut state.metrics.phases.solve_ns,
            Phase::LockProjection => &mut state.metrics.phases.lock_projection_ns,
            Phase::LockSerialization => &mut state.metrics.phases.lock_serialization_ns,
            Phase::LockRoundTrip => &mut state.metrics.phases.lock_round_trip_ns,
            Phase::AtomicLockWrite => &mut state.metrics.phases.atomic_lock_write_ns,
        };
        let previous = (*slot).unwrap_or_default();
        let overflowed = if let Some(total) = previous.checked_add(nanos) {
            *slot = Some(total);
            false
        } else {
            *slot = None;
            true
        };
        if overflowed {
            state.metrics.metrics_overflow = true;
        }
    }
}

pub(crate) use MetricsRecorder as Recorder;

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn unrepresentable_duration_is_marked_and_not_reported_as_zero() {
        let recorder = Recorder::new();
        recorder.record_duration(Phase::Solve, Duration::new(u64::MAX, 999_999_999));
        let metrics = recorder.snapshot();
        assert!(metrics.metrics_overflow);
        assert_eq!(metrics.phases.solve_ns, None);
    }
}
