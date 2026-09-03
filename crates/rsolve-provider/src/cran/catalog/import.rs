use super::*;
use crate::package_description::{DescriptionError, parse_description_fields};
use std::collections::BTreeSet;

type ProviderIdentityKey = (PackageName, RPackageVersion, CranCatalogRecordScope);

fn provider_identity_key(
    package: &PackageName,
    version: &RPackageVersion,
    scope: &CranCatalogRecordScope,
) -> ProviderIdentityKey {
    (package.clone(), version.clone(), scope.clone())
}
pub(crate) fn allpackages_observations_from_fields(
    records: Vec<CatalogRecord>,
) -> CranProviderObservationProjection {
    // ALLPACKAGES carries transport/evidence columns in addition to the
    // canonical CRAN PACKAGES semantics.  Keep those columns in the indexed
    // raw projection for occurrence binding, but never let them affect the
    // PackageRelease semantic digest.
    let raw_fields = records
        .iter()
        .map(|(index, _, fields)| (*index, fields.clone()))
        .collect::<HashMap<_, _>>();
    let records = records
        .into_iter()
        .map(|(index, package, fields)| {
            let fields = fields
                .into_iter()
                .filter(|(name, _)| !is_allpackages_transport_field(name))
                .collect();
            (index, package, fields)
        })
        .collect();
    let mut projection =
        provider_observations_from_fields(records, CranCatalogRecordContext::PackagesIndex, None);
    // Restore raw transport fields after semantic parsing so occurrence
    // binding can use DownloadURL and checksum/snapshot evidence without
    // changing release identity.
    for observation in &mut projection.observations {
        if let Some(fields) = raw_fields.get(&observation.record_index) {
            observation.fields = fields.clone();
        }
    }
    for rejection in &mut projection.rejections {
        if let Some(fields) = raw_fields.get(&rejection.record_index) {
            rejection.fields = fields.clone();
        }
    }
    projection
}

pub(crate) fn validated_observations_from_fields(
    records: Vec<CatalogRecord>,
) -> Result<Vec<CranCatalogObservation>, CranCatalogError> {
    validated_observations_from_fields_with_context(
        records,
        CranCatalogRecordContext::PackagesIndex,
    )
}

pub(crate) fn validated_observations_from_fields_with_context(
    records: Vec<CatalogRecord>,
    context: CranCatalogRecordContext,
) -> Result<Vec<CranCatalogObservation>, CranCatalogError> {
    let fields_by_index = records
        .iter()
        .map(|(record_index, _, fields)| (*record_index, fields.clone()))
        .collect::<HashMap<_, _>>();
    let parsed = records
        .iter()
        .map(|(record_index, package, fields)| {
            let field_refs = fields
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str()))
                .collect::<Vec<_>>();
            (
                *record_index,
                package.clone(),
                observation_from_fields_with_context(&field_refs, context),
            )
        })
        .collect::<Vec<_>>();
    // Validate root records through the ordinary aggregation boundary, while
    // retaining every valid overlay for lossless evidence persistence.  The
    // aggregation function deliberately excludes overlays from candidate
    // selection, so an overlay can never create a metadata conflict with its
    // root release.
    select_and_aggregate(parsed.clone(), context).map_err(CranCatalogError::Semantic)?;

    Ok(parsed
        .into_iter()
        .filter_map(|(record_index, _, observation)| {
            let observation = observation.ok()?;
            let scope = observation_scope(&observation, context);
            let package = observation.identity.name().clone();
            let release = PackageRelease::try_from(observation)
                .expect("catalog validation already accepted the observation");
            Some(CranCatalogObservation {
                record_index,
                package,
                fields: fields_by_index
                    .get(&record_index)
                    .cloned()
                    .expect("selected catalog record must have source fields"),
                release,
                scope,
            })
        })
        .collect::<Vec<_>>())
}

pub(crate) fn provider_observations_from_fields(
    records: Vec<CatalogRecord>,
    context: CranCatalogRecordContext,
    expected_package: Option<&PackageName>,
) -> CranProviderObservationProjection {
    let fields_by_index = records
        .iter()
        .map(|(record_index, _, fields)| (*record_index, fields.clone()))
        .collect::<HashMap<_, _>>();
    let mut observations = Vec::new();
    let mut rejections = Vec::new();
    let mut aggregation = ReleaseAggregation::new();
    let mut seen_identities = HashMap::<ProviderIdentityKey, bool>::new();

    for (record_index, _package, fields) in records {
        let field_refs = fields
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect::<Vec<_>>();
        let package_hint =
            field(&field_refs, "Package").and_then(|value| PackageName::new(value.trim()).ok());
        let version_hint = field(&field_refs, "Version")
            .and_then(|value| RPackageVersion::parse(value.trim()).ok());
        let scope_hint = match context {
            CranCatalogRecordContext::PackagesIndex => match field(&field_refs, "Path") {
                Some(path) => classify_path(path).ok(),
                None => Some(CranCatalogRecordScope::Root),
            },
            CranCatalogRecordContext::Description => Some(CranCatalogRecordScope::Root),
        };
        let identity = match provider_identity_from_fields(&field_refs, context) {
            Ok(identity) => identity,
            Err(error) => {
                rejections.push(CranArchiveReleaseRejection {
                    record_index,
                    package: package_hint.clone(),
                    version: version_hint,
                    scope: scope_hint,
                    fields,
                    error,
                });
                continue;
            }
        };
        if let Some(expected) = expected_package
            && identity.0 != *expected
        {
            rejections.push(CranArchiveReleaseRejection {
                record_index,
                package: Some(identity.0.clone()),
                version: Some(identity.1.clone()),
                scope: Some(identity.2.clone()),
                fields,
                error: CranRecordError::UnexpectedPackage {
                    expected: expected.to_string(),
                    actual: identity.0.to_string(),
                },
            });
            continue;
        }
        let identity_key = provider_identity_key(&identity.0, &identity.1, &identity.2);
        let parsed = observation_from_fields_with_context(&field_refs, context);
        let observation = match parsed {
            Ok(observation) => observation,
            Err(error) => {
                let was_rejected = seen_identities.insert(identity_key, true);
                if was_rejected.is_some() {
                    rejections.push(CranArchiveReleaseRejection {
                        record_index,
                        package: Some(identity.0),
                        version: Some(identity.1),
                        scope: Some(identity.2),
                        fields,
                        error: CranRecordError::Domain(PackageReleaseError::ConflictingMetadata {
                            field: "duplicate identity",
                        }),
                    });
                } else {
                    rejections.push(CranArchiveReleaseRejection {
                        record_index,
                        package: Some(identity.0),
                        version: Some(identity.1),
                        scope: Some(identity.2),
                        fields,
                        error,
                    });
                }
                continue;
            }
        };
        let scope = observation_scope(&observation, context);
        let package_name = observation.identity.name().clone();
        let release = match PackageRelease::try_from(observation.clone()) {
            Ok(release) => release,
            Err(error) => {
                let was_rejected = seen_identities.insert(identity_key, true);
                let rejection_error = if was_rejected.is_some() {
                    CranRecordError::Domain(PackageReleaseError::ConflictingMetadata {
                        field: "duplicate identity",
                    })
                } else {
                    CranRecordError::Domain(error)
                };
                rejections.push(CranArchiveReleaseRejection {
                    record_index,
                    package: Some(package_name),
                    version: Some(identity.1),
                    scope: Some(identity.2),
                    fields,
                    error: rejection_error,
                });
                continue;
            }
        };
        let was_rejected = seen_identities.insert(identity_key, false);
        if was_rejected == Some(true) {
            rejections.push(CranArchiveReleaseRejection {
                record_index,
                package: Some(package_name),
                version: Some(identity.1),
                scope: Some(identity.2),
                fields,
                error: CranRecordError::Domain(PackageReleaseError::ConflictingMetadata {
                    field: "duplicate identity",
                }),
            });
            continue;
        }
        if matches!(scope, CranCatalogRecordScope::Root)
            && let Err(error) = aggregation.observe_release(release.clone())
        {
            rejections.push(CranArchiveReleaseRejection {
                record_index,
                package: Some(package_name),
                version: Some(identity.1),
                scope: Some(identity.2),
                fields,
                error: CranRecordError::Domain(error),
            });
            continue;
        }
        observations.push(CranCatalogObservation {
            record_index,
            package: package_name,
            fields: fields_by_index
                .get(&record_index)
                .cloned()
                .expect("provider record fields must be retained"),
            release,
            scope,
        });
    }

    CranProviderObservationProjection {
        observations,
        rejections,
    }
}

fn provider_identity_from_fields(
    fields: &[(&str, &str)],
    context: CranCatalogRecordContext,
) -> Result<(PackageName, RPackageVersion, CranCatalogRecordScope), CranRecordError> {
    reject_identity_duplicates(fields)?;
    let version = RPackageVersion::parse(required_field(fields, "Version")?.trim())
        .map_err(CranRecordError::InvalidVersion)?;
    let package = PackageName::new(required_field(fields, "Package")?.trim())
        .map_err(CranRecordError::InvalidPackageName)?;
    let scope = match context {
        CranCatalogRecordContext::PackagesIndex => field(fields, "Path")
            .map(classify_path)
            .transpose()?
            .unwrap_or(CranCatalogRecordScope::Root),
        CranCatalogRecordContext::Description => CranCatalogRecordScope::Root,
    };
    Ok((package, version, scope))
}

fn reject_identity_duplicates(fields: &[(&str, &str)]) -> Result<(), CranRecordError> {
    let mut names = BTreeSet::new();
    for (name, _) in fields {
        let normalized = name.to_ascii_lowercase();
        if !matches!(normalized.as_str(), "package" | "version" | "path") {
            continue;
        }
        if !names.insert(normalized) {
            return Err(CranRecordError::DuplicateField((*name).to_owned()));
        }
    }
    Ok(())
}
fn metadata_field<'a>(observation: &'a ReleaseObservation, name: &str) -> Option<&'a str> {
    observation
        .metadata
        .fields()
        .iter()
        .find(|(field, _)| field.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

pub(super) fn observation_scope(
    observation: &ReleaseObservation,
    context: CranCatalogRecordContext,
) -> CranCatalogRecordScope {
    let Some(path) = metadata_field(observation, "Path") else {
        return CranCatalogRecordScope::Root;
    };
    match context {
        CranCatalogRecordContext::PackagesIndex => {
            classify_path(path).expect("validated CRAN observation must have a valid Path")
        }
        CranCatalogRecordContext::Description => CranCatalogRecordScope::Root,
    }
}

#[cfg(test)]
pub(crate) fn observation_from_fields(
    fields: &[(&str, &str)],
) -> Result<ReleaseObservation, CranRecordError> {
    observation_from_fields_with_context(fields, CranCatalogRecordContext::PackagesIndex)
}

pub(super) fn observation_from_fields_with_context(
    fields: &[(&str, &str)],
    context: CranCatalogRecordContext,
) -> Result<ReleaseObservation, CranRecordError> {
    let parsed = parse_description_fields(fields).map_err(map_description_error)?;
    let package = parsed.package;
    let version = parsed.version;
    if matches!(context, CranCatalogRecordContext::PackagesIndex)
        && let Some(path) = field(fields, "Path")
    {
        classify_path(path)?;
    }
    let identity = ReleaseIdentity::new(
        package.clone(),
        Provenance::RegistryRelease {
            namespace: rsolve_core::PackageNamespace::new(CRAN_NAMESPACE)
                .expect("the fixed CRAN namespace is valid"),
            version: version.clone(),
        },
    );

    Ok(ReleaseObservation {
        identity,
        observed_package: package,
        observed_version: version,
        metadata: parsed.metadata,
        publication: parsed.publication,
        declared_dependencies: parsed.dependencies,
        distributions: vec![Distribution {
            registry: RegistryId::new(CRAN_NAMESPACE).expect("the fixed CRAN registry is valid"),
            channel: DistributionChannel::new(SOURCE_CHANNEL)
                .expect("the fixed source channel is valid"),
            snapshot: None,
            artifacts: Vec::new(),
            observed_metadata: DistributionMetadata::default(),
        }],
    })
}

fn map_description_error(error: DescriptionError) -> CranRecordError {
    match error {
        DescriptionError::MissingField(field) => CranRecordError::MissingField(field),
        DescriptionError::DuplicateField(field) => CranRecordError::DuplicateField(field),
        DescriptionError::InvalidPackageName(error) => CranRecordError::InvalidPackageName(error),
        DescriptionError::InvalidVersion(error) => CranRecordError::InvalidVersion(error),
        DescriptionError::InvalidMetadata(error) => CranRecordError::InvalidMetadata(error),
        DescriptionError::InvalidPublicationDate { value, diagnostic } => {
            CranRecordError::InvalidPublicationDate { value, diagnostic }
        }
        DescriptionError::InvalidDependency(error) => CranRecordError::InvalidDependency(error),
        DescriptionError::Dependency {
            field,
            entry,
            source,
        } => CranRecordError::Dependency {
            field,
            entry,
            source,
        },
    }
}

fn classify_path(value: &str) -> Result<CranCatalogRecordScope, CranRecordError> {
    let mut segments = value.split('/');
    let version = segments.next().unwrap_or_default();
    let suffix = segments.next().unwrap_or_default();
    if segments.next().is_some() || suffix != "Recommended" || version.is_empty() {
        return Err(CranRecordError::InvalidPath {
            value: value.to_owned(),
            diagnostic: "expected <R version>/Recommended".into(),
        });
    }
    let runtime =
        RPackageVersion::parse_bare(version).map_err(|error| CranRecordError::InvalidPath {
            value: value.to_owned(),
            diagnostic: format!("invalid Recommended runtime version: {error}"),
        })?;
    Ok(CranCatalogRecordScope::RecommendedOverlay { runtime })
}

fn required_field<'a>(
    fields: &'a [(&str, &str)],
    name: &'static str,
) -> Result<&'a str, CranRecordError> {
    field(fields, name).ok_or(CranRecordError::MissingField(name))
}

fn field<'a>(fields: &'a [(&str, &str)], name: &str) -> Option<&'a str> {
    fields
        .iter()
        .find(|(field_name, _)| field_name.eq_ignore_ascii_case(name))
        .map(|(_, value)| *value)
}

fn is_allpackages_transport_field(name: &str) -> bool {
    let normalized = name.to_ascii_lowercase();
    normalized == "downloadurl"
        || normalized == "filesize"
        || normalized == "repository"
        || normalized == "snapshot"
        || normalized.starts_with("sha256")
}
