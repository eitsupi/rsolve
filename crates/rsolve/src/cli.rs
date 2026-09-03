//! Testable command-line composition for the first lockfile command.

use clap::{Args, Parser, Subcommand};
use serde::Serialize;
use std::cell::RefCell;
use std::error::Error;
use std::fmt;
use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::Instant;
use tempfile::NamedTempFile;

use rsolve_core::{PackageName, PublicationDate, RPackageVersion, VersionConstraint};

use crate::filesystem::ExistingPathIdentity;
use crate::lock::{canonical_lock_basename, legacy_composed_environment};
use crate::manifest::{
    ComposedEnvironment, Endpoint, ManifestError, ManifestSource, RegistrySpec,
    is_remote_cran_root_intent, load_manifest,
};
use crate::metadata_cache::MetadataCache;
use crate::metrics::ResolutionMetrics;
use crate::orchestration::cran_registry_id;
use crate::progress::{ProgressCallback, ProgressEvent};
use crate::{
    EnvironmentId, Lockfile, Manifest, ManifestDependency, ManifestTarget, from_toml, to_toml,
};
use rsolve_provider::cran::{CranRefreshProgress, CranSnapshotCachePolicy};

const DEFAULT_CRAN_MIRROR: &str = "https://cloud.r-project.org";
const DEFAULT_OUTPUT: &str = "rsolve.lock";

/// The top-level command line.
#[derive(Clone, Debug, Parser)]
#[command(name = "rsolve", version, about = "Resolve R packages into a lockfile")]
pub struct CommandLine {
    #[command(subcommand)]
    pub command: Command,
}

/// Supported commands.
#[derive(Clone, Debug, Subcommand)]
pub enum Command {
    /// Resolve explicit packages against CRAN and write a lockfile.
    Lock(LockCommand),
}

/// Arguments for `rsolve lock`.
#[derive(Clone, Debug, Args)]
pub struct LockCommand {
    /// Exact target R version.
    #[arg(long, value_name = "EXACT")]
    pub r_version: String,
    /// Path to a manifest. If omitted, discover the nearest rsolve.toml.
    #[arg(long, conflicts_with = "package")]
    pub manifest: Option<PathBuf>,
    /// Select a named manifest environment.
    #[arg(long, conflicts_with = "package", value_name = "NAME")]
    pub environment: Option<String>,
    /// One direct package name. Repeat this flag for multiple packages.
    #[arg(long, value_name = "NAME", action = clap::ArgAction::Append)]
    pub package: Vec<String>,
    /// CRAN mirror base URL.
    #[arg(long, value_name = "URL")]
    pub cran_mirror: Option<String>,
    /// Fixed publication cutoff in YYYY-MM-DD form.
    #[arg(long)]
    pub publication_cutoff: Option<String>,
    /// Lockfile destination in legacy package mode. Manifest mode derives this
    /// from the manifest project root and rejects explicit output paths.
    #[arg(long, value_name = "PATH")]
    pub output: Option<PathBuf>,
    /// Metadata cache root. Defaults to the platform cache directory.
    #[arg(long, value_name = "ROOT")]
    pub metadata_cache: Option<PathBuf>,
    /// Resolve only from the current metadata snapshot without network access.
    #[arg(long, conflicts_with = "refresh_metadata")]
    pub offline: bool,
    /// Revalidate repository metadata and the bulk history feed immediately.
    #[arg(long, conflicts_with = "offline")]
    pub refresh_metadata: bool,
    /// Optional secondary destination for a versioned JSON success metrics report.
    /// A report publication failure does not roll back the published lockfile.
    #[arg(long, value_name = "PATH")]
    pub metrics_output: Option<PathBuf>,
}

#[derive(Debug, Eq, PartialEq)]
pub enum CliError {
    Value(String),
    Operational(String),
}

impl CliError {
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Value(_) => 2,
            Self::Operational(_) => 1,
        }
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Value(message) | Self::Operational(message) => formatter.write_str(message),
        }
    }
}

impl Error for CliError {}

/// Renderable output from a successful command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandResult {
    pub summary: String,
    pub warnings: Vec<String>,
    /// Operation-local metrics. This is never rendered unless the caller
    /// explicitly requests `--metrics-output`.
    pub metrics: ResolutionMetrics,
}

trait ResolutionBackend {
    fn resolve(
        &self,
        manifest: Manifest,
        mirror: &str,
        cutoff: Option<PublicationDate>,
        metadata_cache: &MetadataCache,
        offline: bool,
        refresh_metadata: bool,
    ) -> Result<ResolvedData, CliError>;

    #[allow(clippy::too_many_arguments)]
    fn resolve_with_progress(
        &self,
        manifest: Manifest,
        mirror: &str,
        cutoff: Option<PublicationDate>,
        metadata_cache: &MetadataCache,
        offline: bool,
        refresh_metadata: bool,
        _progress: Option<ProgressCallback>,
    ) -> Result<ResolvedData, CliError> {
        self.resolve(
            manifest,
            mirror,
            cutoff,
            metadata_cache,
            offline,
            refresh_metadata,
        )
    }

    fn resolve_composed(
        &self,
        _composed: ComposedEnvironment,
        _metadata_cache: &MetadataCache,
        _offline: bool,
        _refresh_metadata: bool,
        _progress: Option<ProgressCallback>,
    ) -> Result<ResolvedData, CliError> {
        Err(CliError::Operational(
            "manifest-backed resolution is unavailable for this backend".into(),
        ))
    }
}

struct CranBackend;

struct ResolvedData {
    resolution: rsolve_core::Resolution,
    warnings: Vec<String>,
    metrics: ResolutionMetrics,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct MetricsSuccessReport {
    pub schema_version: u32,
    pub metrics: ResolutionMetrics,
    pub lock_byte_count: u64,
}

impl ResolutionBackend for CranBackend {
    fn resolve(
        &self,
        manifest: Manifest,
        mirror: &str,
        cutoff: Option<PublicationDate>,
        metadata_cache: &MetadataCache,
        offline: bool,
        refresh_metadata: bool,
    ) -> Result<ResolvedData, CliError> {
        self.resolve_with_progress(
            manifest,
            mirror,
            cutoff,
            metadata_cache,
            offline,
            refresh_metadata,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn resolve_with_progress(
        &self,
        manifest: Manifest,
        mirror: &str,
        cutoff: Option<PublicationDate>,
        metadata_cache: &MetadataCache,
        offline: bool,
        refresh_metadata: bool,
        progress: Option<ProgressCallback>,
    ) -> Result<ResolvedData, CliError> {
        let registry_id = cran_registry_id(mirror)
            .map_err(|error| CliError::Value(format!("invalid --cran-mirror: {error}")))?;
        let store = metadata_cache
            .open_store(registry_id)
            .map_err(|error| CliError::Operational(format!("metadata cache: {error}")))?;
        let outcome = if offline {
            crate::prepared_snapshot::resolve_from_cran_offline_with_store_at_policy_with_progress(
                manifest,
                cutoff,
                &store,
                CranSnapshotCachePolicy::default(),
                progress,
            )
        } else {
            if refresh_metadata {
                crate::prepared_snapshot::resolve_from_cran_with_store_at_policy_with_progress(
                    manifest,
                    mirror,
                    cutoff,
                    &store,
                    CranSnapshotCachePolicy::default().with_refresh_metadata(),
                    progress,
                )
            } else {
                crate::prepared_snapshot::resolve_from_cran_with_store_at_policy_with_progress(
                    manifest,
                    mirror,
                    cutoff,
                    &store,
                    CranSnapshotCachePolicy::default(),
                    progress,
                )
            }
        }
        .map_err(|error| CliError::Operational(format!("resolution failed: {error}")))?;
        let warnings: Vec<String> = outcome
            .diagnostics()
            .iter()
            .filter_map(|diagnostic| match diagnostic.status_detail() {
                rsolve_provider::cran::CranFastPathStatus::Available => None,
                status => Some(format!(
                    "CRAN refresh diagnostic at {}: {status:?}",
                    diagnostic.endpoint()
                )),
            })
            .collect();
        let mut warnings = warnings;
        warnings.extend(render_cache_warnings(outcome.cache_diagnostics()));
        Ok(ResolvedData {
            resolution: outcome.resolution().clone(),
            warnings,
            metrics: outcome.metrics().clone(),
        })
    }

    fn resolve_composed(
        &self,
        composed: ComposedEnvironment,
        metadata_cache: &MetadataCache,
        offline: bool,
        refresh_metadata: bool,
        progress: Option<ProgressCallback>,
    ) -> Result<ResolvedData, CliError> {
        validate_composed_repository_selection(&composed)?;
        let outcome = crate::repository_resolution::resolve_composed(
            composed,
            metadata_cache,
            offline,
            refresh_metadata,
            progress,
        )
        .map_err(|error| CliError::Operational(error.to_string()))?;
        Ok(ResolvedData {
            resolution: outcome.resolution,
            warnings: outcome.warnings,
            metrics: outcome.metrics,
        })
    }
}

fn validate_composed_repository_selection(composed: &ComposedEnvironment) -> Result<(), CliError> {
    if composed.repositories.iter().any(|repository| {
        !matches!(
            repository.registry(),
            RegistrySpec::Cran | RegistrySpec::RUniverse
        )
    }) {
        return Err(value_error(
            "manifest repositories must use registry = \"cran\" or \"r-universe\"".into(),
        ));
    }
    let cran_count = composed
        .repositories
        .iter()
        .filter(|repository| matches!(repository.registry(), RegistrySpec::Cran))
        .count();
    if composed.roots.iter().any(|root| {
        matches!(root.source, ManifestSource::Registry { .. }) && is_remote_cran_root_intent(root)
    }) && cran_count != 1
    {
        return Err(value_error(
            "remote composed resolutions require one repository of kind CRAN; additional R-universe repositories are allowed".into(),
        ));
    }
    Ok(())
}

fn render_cache_warnings(
    diagnostics: &[rsolve_provider::cran::CranSnapshotCacheDiagnostic],
) -> Vec<String> {
    diagnostics
        .iter()
        .filter(|diagnostic| {
            !matches!(
                diagnostic.status(),
                rsolve_provider::cran::CranSnapshotCacheStatus::Fresh
                    | rsolve_provider::cran::CranSnapshotCacheStatus::Missing
            )
        })
        .map(crate::prepared_snapshot::render_cran_cache_warning)
        .collect()
}

/// Execute a parsed command. Successful commands write no stdout.
pub fn run(command_line: CommandLine) -> Result<CommandResult, CliError> {
    run_with_progress(command_line, None)
}

/// Execute a parsed command with an optional semantic progress sink.
pub fn run_with_progress(
    command_line: CommandLine,
    progress: Option<ProgressCallback>,
) -> Result<CommandResult, CliError> {
    match command_line.command {
        Command::Lock(command) => run_lock_with_backend_progress(command, &CranBackend, progress),
    }
}

struct TerminalProgress<W> {
    writer: W,
}

impl<W: Write> TerminalProgress<W> {
    fn render(&mut self, event: ProgressEvent) {
        let message = match event {
            ProgressEvent::Cran(event) => match event {
                CranRefreshProgress::CurrentIndexStarted => {
                    "CRAN: refreshing current index".to_owned()
                }
                CranRefreshProgress::CurrentIndexCompleted { packages } => {
                    format!("CRAN: current index ready ({packages} packages)")
                }
                CranRefreshProgress::ArchiveHistoryStarted => {
                    "CRAN: refreshing archive history".to_owned()
                }
                CranRefreshProgress::ArchiveHistoryCompleted { entries } => {
                    format!("CRAN: archive history ready ({entries} entries)")
                }
                CranRefreshProgress::AllPackagesStarted => {
                    "CRAN: acquiring ALLPACKAGES feed".to_owned()
                }
                CranRefreshProgress::AllPackagesProjected => {
                    "CRAN: ALLPACKAGES projection ready".to_owned()
                }
                CranRefreshProgress::AllPackagesQualified { reused } => {
                    if reused {
                        "CRAN: ALLPACKAGES qualification reused".to_owned()
                    } else {
                        "CRAN: ALLPACKAGES qualification complete".to_owned()
                    }
                }
                CranRefreshProgress::PackageLocalFallbackStarted => {
                    "CRAN: using package-local archive fallback".to_owned()
                }
                CranRefreshProgress::SnapshotPublishStarted { packages } => {
                    format!("CRAN: publishing snapshot ({packages} packages)")
                }
                CranRefreshProgress::SnapshotPublishCompleted => {
                    "CRAN: snapshot published".to_owned()
                }
            },
            ProgressEvent::ResolveStarted => "resolving dependencies".to_owned(),
            ProgressEvent::ResolveCompleted { packages } => {
                format!("resolved ({packages} packages)")
            }
        };
        let _ = writeln!(self.writer, "{message}");
        let _ = self.writer.flush();
    }
}

pub fn terminal_progress() -> Option<ProgressCallback> {
    if !io::stderr().is_terminal() {
        return None;
    }
    let renderer = Rc::new(RefCell::new(TerminalProgress {
        writer: io::stderr(),
    }));
    Some(Rc::new(move |event| renderer.borrow_mut().render(event)))
}

#[cfg(test)]
fn run_lock_with_backend(
    command: LockCommand,
    backend: &dyn ResolutionBackend,
) -> Result<CommandResult, CliError> {
    run_lock_with_backend_progress(command, backend, None)
}

fn run_lock_with_backend_progress(
    command: LockCommand,
    backend: &dyn ResolutionBackend,
    progress: Option<ProgressCallback>,
) -> Result<CommandResult, CliError> {
    let target_r = RPackageVersion::parse(&command.r_version)
        .map_err(|error| value_error(format!("invalid --r-version: {error}")))?;
    if command.manifest.is_some() || command.package.is_empty() {
        return run_manifest_lock_with_backend_progress(command, target_r, backend, progress);
    }
    let package_names = command
        .package
        .iter()
        .map(|value| {
            PackageName::new(value)
                .map_err(|error| value_error(format!("invalid --package {value:?}: {error}")))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let cutoff = command
        .publication_cutoff
        .as_deref()
        .map(PublicationDate::parse)
        .transpose()
        .map_err(|error| value_error(format!("invalid --publication-cutoff: {error}")))?;
    let mirror = canonical_mirror(
        command
            .cran_mirror
            .as_deref()
            .unwrap_or(DEFAULT_CRAN_MIRROR),
    )?;
    let output = command
        .output
        .clone()
        .unwrap_or_else(|| PathBuf::from(DEFAULT_OUTPUT));
    validate_output_path(&output)?;
    if let Some(metrics_output) = &command.metrics_output {
        validate_output_path(metrics_output)?;
        if destination_paths_equal(&output, metrics_output)?
            || existing_destinations_share_identity(&output, metrics_output)?
        {
            return Err(CliError::Value(
                "--metrics-output must differ from --output".into(),
            ));
        }
    }
    let target = ManifestTarget::new(target_r);
    let manifest = Manifest::new(
        VersionConstraint::unconstrained(),
        target,
        package_names
            .into_iter()
            .map(|name| ManifestDependency::new(name, VersionConstraint::unconstrained()))
            .collect(),
    )
    .map_err(|error| value_error(format!("invalid manifest: {error}")))?;
    let legacy_composed = legacy_composed_environment(&manifest, &mirror, cutoff)
        .map_err(|error| CliError::Operational(format!("lock applicability failed: {error}")))?;

    let requested_package_count = command.package.len();
    let metadata_cache = MetadataCache::resolve(command.metadata_cache.as_deref())
        .map_err(|error| CliError::Operational(format!("metadata cache: {error}")))?;
    let resolved = backend.resolve_with_progress(
        manifest,
        &mirror,
        cutoff,
        &metadata_cache,
        command.offline,
        command.refresh_metadata,
        progress,
    )?;
    if command.metrics_output.is_some() && resolved.metrics.metrics_overflow {
        return Err(CliError::Operational(
            "metrics overflow; refusing to write report".into(),
        ));
    }
    let projection_started = Instant::now();
    let lock =
        Lockfile::from_resolution_with_composed_environment(&resolved.resolution, &legacy_composed)
            .map_err(|error| CliError::Operational(format!("lock projection failed: {error}")))?;
    let projection_ns = elapsed_ns(projection_started)?;
    let serialization_started = Instant::now();
    let serialized = to_toml(&lock)
        .map_err(|error| CliError::Operational(format!("lock serialization failed: {error}")))?;
    let serialization_ns = elapsed_ns(serialization_started)?;
    let round_trip_started = Instant::now();
    let reparsed = from_toml(&serialized)
        .map_err(|error| CliError::Operational(format!("lock round-trip failed: {error}")))?;
    if reparsed != lock {
        return Err(CliError::Operational(
            "lock round-trip changed the logical lock domain".into(),
        ));
    }
    let round_trip_ns = elapsed_ns(round_trip_started)?;
    let reserialization_started = Instant::now();
    let bytes = to_toml(&reparsed)
        .map_err(|error| CliError::Operational(format!("lock re-serialization failed: {error}")))?;
    let reserialization_ns = elapsed_ns(reserialization_started)?;

    let write_started = Instant::now();
    let changed = write_lockfile(&output, bytes.as_bytes())?;
    let write_ns = elapsed_ns(write_started)?;
    // Recheck after publishing the primary lock: this catches aliases that
    // were both missing during preflight. A report failure leaves that lock
    // published and valid.
    let lock_identity = if command.metrics_output.is_some() {
        Some(lock_output_identity(&output)?)
    } else {
        None
    };
    let mut metrics = resolved.metrics;
    metrics.phases.lock_projection_ns = Some(projection_ns);
    metrics.phases.lock_serialization_ns = Some(
        serialization_ns
            .checked_add(reserialization_ns)
            .ok_or_else(|| CliError::Operational("metrics overflow".into()))?,
    );
    metrics.phases.lock_round_trip_ns = Some(round_trip_ns);
    metrics.phases.atomic_lock_write_ns = changed.then_some(write_ns);
    if let Some(path) = command.metrics_output {
        let report_identity = path_identity(&path, "metrics output")?;
        if same_existing_identity(lock_identity.as_ref(), report_identity.as_ref()) {
            return Err(CliError::Value(
                "--metrics-output must differ from --output".into(),
            ));
        }
        let report = MetricsSuccessReport {
            schema_version: 1,
            metrics: metrics.clone(),
            lock_byte_count: u64::try_from(bytes.len())
                .map_err(|_| CliError::Operational("lock byte count overflow".into()))?,
        };
        let encoded = serde_json::to_vec_pretty(&report).map_err(|error| {
            CliError::Operational(format!("metrics report serialization failed: {error}"))
        })?;
        write_report(&path, &encoded)?;
    }
    let status = if changed { "updated" } else { "up-to-date" };
    Ok(CommandResult {
        summary: format!(
            "target R {}; {} direct package(s); output {}; {}",
            command.r_version,
            requested_package_count,
            output.display(),
            status
        ),
        warnings: resolved.warnings,
        metrics,
    })
}

fn run_manifest_lock_with_backend_progress(
    command: LockCommand,
    target_r: RPackageVersion,
    backend: &dyn ResolutionBackend,
    progress: Option<ProgressCallback>,
) -> Result<CommandResult, CliError> {
    let cwd = std::env::current_dir().map_err(|error| {
        CliError::Operational(format!("cannot determine current directory: {error}"))
    })?;
    let environment_variable = environment_variable_for(command.environment.as_deref(), || {
        std::env::var("RSOLVE_ENVIRONMENT")
    })?;
    run_manifest_lock_with_backend_progress_at(
        command,
        target_r,
        backend,
        progress,
        &cwd,
        environment_variable.as_deref(),
    )
}

fn run_manifest_lock_with_backend_progress_at(
    command: LockCommand,
    target_r: RPackageVersion,
    backend: &dyn ResolutionBackend,
    progress: Option<ProgressCallback>,
    cwd: &Path,
    environment_variable: Option<&str>,
) -> Result<CommandResult, CliError> {
    if command.cran_mirror.is_some() {
        return Err(value_error(
            "--cran-mirror cannot be combined with manifest-backed resolution".into(),
        ));
    }
    if command.publication_cutoff.is_some() {
        return Err(value_error(
            "--publication-cutoff cannot be combined with --manifest; use resolution.published-before"
                .into(),
        ));
    }
    let (manifest_path, document) =
        load_manifest(command.manifest.as_deref(), cwd).map_err(|error| {
            let source = command
                .manifest
                .as_deref()
                .map(|path| format!("--manifest {}", path.display()))
                .unwrap_or_else(|| format!("cwd {}", cwd.display()));
            value_error(format!("manifest selection ({source}) failed: {error}"))
        })?;
    let (environment_name, environment_source) =
        select_environment(command.environment.as_deref(), environment_variable);
    let composed = document
        .compose_environment(
            environment_name,
            rsolve_core::ResolutionTarget::new(target_r),
        )
        .map_err(|error| {
            value_error(format!(
                "environment selection ({environment_source}={environment_name:?}) failed: {error}"
            ))
        })?;
    if command.output.is_some() {
        return Err(value_error(
            "--output cannot be used with manifest-backed resolution; output is derived from the manifest project root"
                .into(),
        ));
    }
    let output = manifest_output_path(&manifest_path, &composed.environment)?;
    validate_output_path(&output)?;
    let composed = if command.offline && output.is_file() {
        let bytes = fs::read_to_string(&output).map_err(|error| {
            CliError::Operational(format!(
                "cannot read existing lockfile {}: {error}",
                output.display()
            ))
        })?;
        let previous = from_toml(&bytes).map_err(|error| {
            CliError::Operational(format!("existing lockfile is invalid: {error}"))
        })?;
        previous
            .consume_composed_environment(&composed)
            .map_err(|error| {
                CliError::Operational(format!("existing lockfile is incompatible: {error}"))
            })?;
        let locked = previous.locked_identities().map_err(|error| {
            CliError::Operational(format!("existing lockfile is invalid: {error}"))
        })?;
        document
            .compose_environment_with_locked(
                environment_name,
                rsolve_core::ResolutionTarget::new(composed.target.r_version.clone()),
                locked,
            )
            .map_err(|error| {
                CliError::Operational(format!("locked environment composition failed: {error}"))
            })?
    } else {
        composed
    };
    if composed.roots.iter().any(|root| {
        matches!(
            root.source,
            ManifestSource::Url { .. } | ManifestSource::Path { .. }
        )
    }) {
        return Err(value_error(
            "manifest direct URL/path source requires acquisition".into(),
        ));
    }
    if let Some(metrics_output) = &command.metrics_output {
        validate_output_path(metrics_output)?;
        if destination_paths_equal(&output, metrics_output)?
            || existing_destinations_share_identity(&output, metrics_output)?
        {
            return Err(CliError::Value(
                "--metrics-output must differ from --output".into(),
            ));
        }
    }
    validate_composed_repository_selection(&composed)?;
    let metadata_cache = MetadataCache::resolve(command.metadata_cache.as_deref())
        .map_err(|error| CliError::Operational(format!("metadata cache: {error}")))?;
    let resolved = backend.resolve_composed(
        composed.clone(),
        &metadata_cache,
        command.offline,
        command.refresh_metadata,
        progress,
    )?;
    if command.metrics_output.is_some() && resolved.metrics.metrics_overflow {
        return Err(CliError::Operational(
            "metrics overflow; refusing to write report".into(),
        ));
    }
    let projection_started = Instant::now();
    let lock = Lockfile::from_resolution_with_composed_environment(&resolved.resolution, &composed)
        .map_err(|error| CliError::Operational(format!("lock projection failed: {error}")))?;
    let projection_ns = elapsed_ns(projection_started)?;
    let serialization_started = Instant::now();
    let serialized = to_toml(&lock)
        .map_err(|error| CliError::Operational(format!("lock serialization failed: {error}")))?;
    let serialization_ns = elapsed_ns(serialization_started)?;
    let round_trip_started = Instant::now();
    let reparsed = from_toml(&serialized)
        .map_err(|error| CliError::Operational(format!("lock round-trip failed: {error}")))?;
    if reparsed != lock {
        return Err(CliError::Operational(
            "lock round-trip changed the logical lock domain".into(),
        ));
    }
    let round_trip_ns = elapsed_ns(round_trip_started)?;
    let reserialization_started = Instant::now();
    let bytes = to_toml(&reparsed)
        .map_err(|error| CliError::Operational(format!("lock re-serialization failed: {error}")))?;
    let reserialization_ns = elapsed_ns(reserialization_started)?;
    let write_started = Instant::now();
    let changed = write_lockfile(&output, bytes.as_bytes())?;
    let write_ns = elapsed_ns(write_started)?;
    let lock_identity = if command.metrics_output.is_some() {
        Some(lock_output_identity(&output)?)
    } else {
        None
    };
    let mut metrics = resolved.metrics;
    metrics.phases.lock_projection_ns = Some(projection_ns);
    metrics.phases.lock_serialization_ns = Some(
        serialization_ns
            .checked_add(reserialization_ns)
            .ok_or_else(|| CliError::Operational("metrics overflow".into()))?,
    );
    metrics.phases.lock_round_trip_ns = Some(round_trip_ns);
    metrics.phases.atomic_lock_write_ns = changed.then_some(write_ns);
    if let Some(path) = command.metrics_output {
        let report_identity = path_identity(&path, "metrics output")?;
        if same_existing_identity(lock_identity.as_ref(), report_identity.as_ref()) {
            return Err(CliError::Value(
                "--metrics-output must differ from --output".into(),
            ));
        }
        let report = MetricsSuccessReport {
            schema_version: 1,
            metrics: metrics.clone(),
            lock_byte_count: u64::try_from(bytes.len())
                .map_err(|_| CliError::Operational("lock byte count overflow".into()))?,
        };
        let encoded = serde_json::to_vec_pretty(&report).map_err(|error| {
            CliError::Operational(format!("metrics report serialization failed: {error}"))
        })?;
        write_report(&path, &encoded)?;
    }
    let status = if changed { "updated" } else { "up-to-date" };
    Ok(CommandResult {
        summary: format!(
            "target R {}; environment {} ({environment_source}); manifest {}; output {}; {}",
            command.r_version,
            composed.environment,
            manifest_path.display(),
            output.display(),
            status
        ),
        warnings: resolved.warnings,
        metrics,
    })
}

fn select_environment<'a>(
    explicit: Option<&'a str>,
    variable: Option<&'a str>,
) -> (&'a str, &'static str) {
    if let Some(value) = explicit {
        (value, "--environment")
    } else if let Some(value) = variable {
        (value, "RSOLVE_ENVIRONMENT")
    } else {
        ("default", "default")
    }
}

fn manifest_output_path(
    manifest_path: &Path,
    environment: &EnvironmentId,
) -> Result<PathBuf, CliError> {
    let parent = manifest_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let project_root = fs::canonicalize(parent).map_err(|error| {
        CliError::Operational(format!(
            "cannot canonicalize manifest project root {}: {error}",
            parent.display()
        ))
    })?;
    Ok(project_root.join(canonical_lock_basename(environment)))
}

fn environment_variable_for<F>(explicit: Option<&str>, read: F) -> Result<Option<String>, CliError>
where
    F: FnOnce() -> Result<String, std::env::VarError>,
{
    if explicit.is_some() {
        return Ok(None);
    }
    match read() {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(value_error(
            "RSOLVE_ENVIRONMENT is not valid UTF-8; refusing environment fallback".into(),
        )),
    }
}

fn elapsed_ns(started: Instant) -> Result<u64, CliError> {
    u64::try_from(started.elapsed().as_nanos())
        .map_err(|_| CliError::Operational("metrics overflow".into()))
}

fn destination_identity(path: &Path) -> Result<PathBuf, CliError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent = fs::canonicalize(parent).map_err(|error| {
        CliError::Operational(format!(
            "cannot canonicalize output parent {}: {error}",
            parent.display()
        ))
    })?;
    Ok(parent.join(
        path.file_name()
            .ok_or_else(|| CliError::Value("output has no file name".into()))?,
    ))
}

fn destination_paths_equal(left: &Path, right: &Path) -> Result<bool, CliError> {
    let left = destination_identity(left)?;
    let right = destination_identity(right)?;
    Ok(left == right)
}

fn path_identity(path: &Path, label: &str) -> Result<Option<ExistingPathIdentity>, CliError> {
    ExistingPathIdentity::from_path(path).map_err(|error| {
        CliError::Operational(format!(
            "cannot identify {label} {}: {error}",
            path.display()
        ))
    })
}

fn same_existing_identity(
    left: Option<&ExistingPathIdentity>,
    right: Option<&ExistingPathIdentity>,
) -> bool {
    matches!((left, right), (Some(left), Some(right)) if left == right)
}

fn existing_destinations_share_identity(left: &Path, right: &Path) -> Result<bool, CliError> {
    let left_identity = path_identity(left, "lock output")?;
    let right_identity = path_identity(right, "metrics output")?;
    Ok(same_existing_identity(
        left_identity.as_ref(),
        right_identity.as_ref(),
    ))
}

fn lock_output_identity(path: &Path) -> Result<ExistingPathIdentity, CliError> {
    path_identity(path, "lock output")?.ok_or_else(|| {
        CliError::Operational(format!(
            "lock output disappeared after write: {}",
            path.display()
        ))
    })
}

fn canonical_mirror(input: &str) -> Result<Box<str>, CliError> {
    let input = input.trim();
    if input.is_empty() {
        return Err(value_error("--cran-mirror must not be empty".into()));
    }
    Endpoint::parse(input)
        .map(|endpoint| endpoint.as_str().into())
        .map_err(|error| {
            let detail = match &error {
                ManifestError::InvalidEndpoint { reason, .. }
                    if reason == "credentials are forbidden" =>
                {
                    "mirror URL must not include userinfo".to_owned()
                }
                ManifestError::InvalidEndpoint { reason, .. }
                    if reason == "query and fragment are forbidden" =>
                {
                    "mirror must not include a query or fragment".to_owned()
                }
                _ => error.to_string(),
            };
            value_error(format!("invalid --cran-mirror: {detail}"))
        })
}

fn value_error(message: String) -> CliError {
    CliError::Value(message)
}

fn validate_output_path(path: &Path) -> Result<(), CliError> {
    if path.as_os_str().is_empty() {
        return Err(CliError::Value("--output must not be empty".into()));
    }
    if path.as_os_str() == "-" {
        return Err(CliError::Value("--output - is not supported".into()));
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent_metadata = fs::metadata(parent).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            CliError::Value(format!(
                "output parent does not exist: {}",
                parent.display()
            ))
        } else {
            CliError::Operational(format!(
                "cannot inspect output parent {}: {error}",
                parent.display()
            ))
        }
    })?;
    if !parent_metadata.is_dir() {
        return Err(CliError::Value(format!(
            "output parent is not a directory: {}",
            parent.display()
        )));
    }
    let file_name = path
        .file_name()
        .ok_or_else(|| CliError::Value("--output has no file name".into()))?;
    if file_name.is_empty() || file_name == "." || file_name == ".." {
        return Err(CliError::Value("--output has no usable file name".into()));
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(CliError::Value(format!(
            "refusing symlink output {}",
            path.display()
        ))),
        Ok(metadata) if metadata.is_dir() => Err(CliError::Value(format!(
            "output is a directory: {}",
            path.display()
        ))),
        Ok(metadata) if metadata.is_file() => Ok(()),
        Ok(_) => Err(CliError::Value(format!(
            "output is not a regular file: {}",
            path.display()
        ))),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(CliError::Operational(format!(
            "cannot inspect output {}: {error}",
            path.display()
        ))),
    }
}

fn write_lockfile(path: &Path, bytes: &[u8]) -> Result<bool, CliError> {
    validate_output_path(path)?;
    match fs::read(path) {
        Ok(existing) => {
            if existing == bytes {
                return Ok(false);
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(CliError::Operational(format!(
                "cannot read existing output {}: {error}",
                path.display()
            )));
        }
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temp = NamedTempFile::new_in(parent).map_err(|error| {
        CliError::Operational(format!(
            "atomic lockfile write failed: create temp file: {error}"
        ))
    })?;
    temp.write_all(bytes)
        .and_then(|()| temp.flush())
        .and_then(|()| temp.as_file().sync_all())
        .map_err(|error| CliError::Operational(format!("atomic lockfile write failed: {error}")))?;
    // Re-check after the potentially slow write so a destination replaced by
    // a symlink or special file is rejected before the commit attempt.
    validate_output_path(path)?;
    commit_temp(temp, path, persist_temp, "lockfile")?;
    Ok(true)
}

fn write_report(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    validate_output_path(path)?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temp = NamedTempFile::new_in(parent).map_err(|error| {
        CliError::Operational(format!(
            "atomic metrics report write failed: create temp file: {error}"
        ))
    })?;
    temp.write_all(bytes)
        .and_then(|()| temp.flush())
        .and_then(|()| temp.as_file().sync_all())
        .map_err(|error| {
            CliError::Operational(format!("atomic metrics report write failed: {error}"))
        })?;
    validate_output_path(path)?;
    commit_temp(temp, path, persist_temp, "metrics report")
}

fn persist_temp(temp: NamedTempFile, path: &Path) -> Result<(), String> {
    #[cfg(not(windows))]
    {
        temp.persist(path)
            .map(|_| ())
            .map_err(|error| error.error.to_string())
    }

    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::{
            MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
        };

        let (file, temporary_path) = temp.keep().map_err(|error| error.error.to_string())?;
        drop(file);
        let source = temporary_path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let destination = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let result = unsafe {
            MoveFileExW(
                source.as_ptr(),
                destination.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        };
        if result == 0 {
            let error = io::Error::last_os_error();
            let _ = fs::remove_file(&temporary_path);
            return Err(error.to_string());
        }
        Ok(())
    }
}

fn commit_temp<F>(temp: NamedTempFile, path: &Path, commit: F, kind: &str) -> Result<(), CliError>
where
    F: FnOnce(NamedTempFile, &Path) -> Result<(), String>,
{
    commit(temp, path)
        .map_err(|error| CliError::Operational(format!("atomic {kind} write failed: {error}")))
}

#[cfg(test)]
mod tests;
