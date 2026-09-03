use rsolve_core::{
    CandidateLoadError, CandidateLoadErrorCategory, CandidateLoadResult, CandidateLoader,
    PreparedCandidateSet, QuarantinedCandidate, SolverKey,
};

/// A transport-free union of repository-scoped candidate views.
///
/// Each entry is queried in manifest order. A source may report `NotFound` to
/// indicate an ordinary absence, but all other failures remain observable and
/// stop the union immediately. Equal release identities are merged by the
/// domain candidate set; distinct provenance remains distinct.
#[allow(dead_code)]
pub(crate) struct CompositeCandidateLoader<'a> {
    loaders: Vec<&'a dyn CandidateLoader>,
}

#[allow(dead_code)]
impl<'a> CompositeCandidateLoader<'a> {
    pub(crate) fn new(loaders: Vec<&'a dyn CandidateLoader>) -> Self {
        Self { loaders }
    }

    pub(crate) fn from_iter(loaders: impl IntoIterator<Item = &'a dyn CandidateLoader>) -> Self {
        Self::new(loaders.into_iter().collect())
    }
}

impl CandidateLoader for CompositeCandidateLoader<'_> {
    fn releases(
        &self,
        subject: &SolverKey,
    ) -> Result<Vec<rsolve_core::PreparedCandidate>, CandidateLoadError> {
        self.load(subject).map(|result| result.into_parts().0)
    }

    fn load(&self, subject: &SolverKey) -> Result<CandidateLoadResult, CandidateLoadError> {
        let mut candidates = PreparedCandidateSet::new();
        let mut quarantined = Vec::<QuarantinedCandidate>::new();

        for (index, loader) in self.loaders.iter().enumerate() {
            let result = match loader.load(subject) {
                Ok(result) => result,
                Err(error) if error.category() == CandidateLoadErrorCategory::NotFound => {
                    continue;
                }
                Err(error) => return Err(contextual_error(index, error)),
            };
            for candidate in result.candidates() {
                candidates.insert(candidate.clone()).map_err(|error| {
                    CandidateLoadError::new(
                        CandidateLoadErrorCategory::MetadataInvalid,
                        format!("candidate source {index} produced a merge conflict: {error}"),
                    )
                })?;
            }
            for entry in result.quarantined() {
                if !quarantined.contains(entry) {
                    quarantined.push(entry.clone());
                }
            }
        }

        Ok(CandidateLoadResult::new(
            candidates.candidates().into_iter().cloned().collect(),
            quarantined,
        ))
    }
}

#[allow(dead_code)]
fn contextual_error(index: usize, error: CandidateLoadError) -> CandidateLoadError {
    CandidateLoadError::new(
        error.category(),
        format!("candidate source {index}: {}", error.diagnostic()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsolve_core::{
        Artifact, ArtifactLocator, CandidateAvailability, CandidateCurrentness, Distribution,
        DistributionChannel, DistributionMetadata, GitCommitId, NonRepositoryExposure,
        NormalizedGitUrl, PackageName, PackageRelease, PreparedCandidate, Provenance,
        RPackageVersion, ReleaseIdentity, ReleaseMetadata, ReleaseObservation, RepositoryId,
        RepositoryOccurrence, RepositoryRank, SourceArtifact,
    };
    use std::collections::HashSet;

    fn distribution(channel: &str, locator: &str) -> Distribution {
        distribution_with_metadata(channel, locator, DistributionMetadata::default())
    }

    fn distribution_with_metadata(
        channel: &str,
        locator: &str,
        observed_metadata: DistributionMetadata,
    ) -> Distribution {
        Distribution {
            registry: rsolve_core::RegistryId::new("registry").unwrap(),
            channel: DistributionChannel::new(channel).unwrap(),
            snapshot: None,
            artifacts: vec![Artifact::Source(SourceArtifact {
                locator: ArtifactLocator::new(locator).unwrap(),
                upstream_checksums: Vec::new(),
                size: None,
            })],
            observed_metadata,
        }
    }

    fn release(name: &str, commit: &str, distributions: Vec<Distribution>) -> PackageRelease {
        let name = PackageName::new(name).unwrap();
        let identity = ReleaseIdentity::new(
            name.clone(),
            Provenance::GitCommit {
                repository: NormalizedGitUrl::new("https://example.test/project.git").unwrap(),
                commit: GitCommitId::new(commit).unwrap(),
                subdirectory: None,
            },
        );
        PackageRelease::try_from(ReleaseObservation {
            identity,
            observed_package: name,
            observed_version: RPackageVersion::parse("1.0.0").unwrap(),
            metadata: ReleaseMetadata::new(Default::default()).unwrap(),
            publication: None,
            declared_dependencies: Vec::new(),
            distributions,
        })
        .unwrap()
    }

    fn candidate(
        repository: &str,
        release: PackageRelease,
        distributions: Vec<Distribution>,
    ) -> PreparedCandidate {
        PreparedCandidate::new(
            release,
            NonRepositoryExposure::None,
            vec![
                RepositoryOccurrence::new(
                    RepositoryId::new(repository).unwrap(),
                    rsolve_core::RegistryId::new("registry").unwrap(),
                    CandidateAvailability::Available,
                    CandidateCurrentness::Current,
                    RepositoryRank::new(0),
                    distributions,
                )
                .unwrap(),
            ],
        )
        .unwrap()
    }

    struct FixedLoader {
        result: Result<CandidateLoadResult, CandidateLoadError>,
    }

    impl CandidateLoader for FixedLoader {
        fn releases(
            &self,
            subject: &SolverKey,
        ) -> Result<Vec<PreparedCandidate>, CandidateLoadError> {
            self.load(subject).map(|result| result.into_parts().0)
        }

        fn load(&self, _subject: &SolverKey) -> Result<CandidateLoadResult, CandidateLoadError> {
            self.result.clone()
        }
    }

    fn result(
        candidates: Vec<PreparedCandidate>,
    ) -> Result<CandidateLoadResult, CandidateLoadError> {
        Ok(CandidateLoadResult::new(candidates, Vec::new()))
    }

    #[test]
    fn same_git_identity_merges_occurrences_and_distributions() {
        let first_distribution = distribution("source", "https://example.test/one.tar.gz");
        let second_distribution = distribution("binary", "https://example.test/two.zip");
        let first_release = release(
            "pkg",
            "0123456789012345678901234567890123456789",
            vec![first_distribution.clone()],
        );
        let second_release = release(
            "pkg",
            "0123456789012345678901234567890123456789",
            vec![second_distribution.clone()],
        );
        let first = FixedLoader {
            result: result(vec![candidate(
                "first",
                first_release,
                vec![first_distribution.clone()],
            )]),
        };
        let second = FixedLoader {
            result: result(vec![candidate(
                "second",
                second_release,
                vec![second_distribution.clone()],
            )]),
        };
        let loader = CompositeCandidateLoader::from_iter([
            &first as &dyn CandidateLoader,
            &second as &dyn CandidateLoader,
        ]);
        let loaded = loader
            .load(&SolverKey::InstalledName(PackageName::new("pkg").unwrap()))
            .unwrap();
        assert_eq!(loaded.candidates().len(), 1);
        assert_eq!(loaded.candidates()[0].occurrences().len(), 2);
        assert_eq!(loaded.candidates()[0].release().distributions().len(), 2);
        assert_eq!(
            loaded.candidates()[0]
                .occurrences()
                .iter()
                .map(|occurrence| occurrence.distributions().len())
                .collect::<Vec<_>>(),
            vec![1, 1]
        );
        assert_eq!(
            loaded.candidates()[0]
                .occurrences()
                .iter()
                .map(|occurrence| occurrence.repository().as_str())
                .collect::<Vec<_>>(),
            vec!["first", "second"]
        );
    }

    #[test]
    fn same_git_identity_merges_r_universe_occurrences_with_distinct_repository_evidence() {
        let first_distribution = distribution_with_metadata(
            "source",
            "https://example.test/one.tar.gz",
            DistributionMetadata {
                fields: [("Repository".into(), "first".into())].into(),
            },
        );
        let second_distribution = distribution_with_metadata(
            "source",
            "https://example.test/two.tar.gz",
            DistributionMetadata {
                fields: [("Repository".into(), "second".into())].into(),
            },
        );
        let first_release = release(
            "pkg",
            "0123456789012345678901234567890123456789",
            vec![first_distribution.clone()],
        );
        let second_release = release(
            "pkg",
            "0123456789012345678901234567890123456789",
            vec![second_distribution.clone()],
        );
        let first = FixedLoader {
            result: result(vec![candidate(
                "first",
                first_release,
                vec![first_distribution.clone()],
            )]),
        };
        let second = FixedLoader {
            result: result(vec![candidate(
                "second",
                second_release,
                vec![second_distribution.clone()],
            )]),
        };
        let loaded = CompositeCandidateLoader::from_iter([
            &first as &dyn CandidateLoader,
            &second as &dyn CandidateLoader,
        ])
        .load(&SolverKey::InstalledName(PackageName::new("pkg").unwrap()))
        .unwrap();
        assert_eq!(loaded.candidates().len(), 1);
        assert_eq!(loaded.candidates()[0].release().distributions().len(), 2);
        assert_eq!(
            loaded.candidates()[0]
                .release()
                .distributions()
                .iter()
                .map(|distribution| {
                    distribution
                        .observed_metadata
                        .fields
                        .get("Repository")
                        .unwrap()
                        .as_str()
                })
                .collect::<Vec<_>>(),
            vec!["first", "second"]
        );
    }

    #[test]
    fn same_name_and_version_with_distinct_identities_remains_distinct() {
        let first_release = release(
            "pkg",
            "0123456789012345678901234567890123456789",
            Vec::new(),
        );
        let second_release = release(
            "pkg",
            "fedcba9876543210fedcba9876543210fedcba98",
            Vec::new(),
        );
        let first = FixedLoader {
            result: result(vec![candidate("first", first_release, Vec::new())]),
        };
        let second = FixedLoader {
            result: result(vec![candidate("second", second_release, Vec::new())]),
        };
        let loader = CompositeCandidateLoader::new(vec![&first, &second]);
        let loaded = loader
            .load(&SolverKey::InstalledName(PackageName::new("pkg").unwrap()))
            .unwrap();
        assert_eq!(loaded.candidates().len(), 2);
        assert_eq!(
            loaded
                .candidates()
                .iter()
                .map(|candidate| candidate.identity().clone())
                .collect::<HashSet<_>>()
                .len(),
            2
        );
    }

    #[test]
    fn not_found_is_skipped_when_another_source_has_candidates() {
        let missing = FixedLoader {
            result: Err(CandidateLoadError::new(
                CandidateLoadErrorCategory::NotFound,
                "package is absent",
            )),
        };
        let package = PackageName::new("pkg").unwrap();
        let present = FixedLoader {
            result: result(vec![candidate(
                "present",
                release(
                    "pkg",
                    "0123456789012345678901234567890123456789",
                    Vec::new(),
                ),
                Vec::new(),
            )]),
        };
        let loader = CompositeCandidateLoader::new(vec![&missing, &present]);
        assert_eq!(
            loader
                .load(&SolverKey::InstalledName(package))
                .unwrap()
                .candidates()
                .len(),
            1
        );
    }

    #[test]
    fn hard_source_error_is_not_hidden_by_later_candidates() {
        let failure = FixedLoader {
            result: Err(CandidateLoadError::new(
                CandidateLoadErrorCategory::TransportFailure,
                "provider unavailable",
            )),
        };
        let present = FixedLoader {
            result: result(vec![candidate(
                "present",
                release(
                    "pkg",
                    "0123456789012345678901234567890123456789",
                    Vec::new(),
                ),
                Vec::new(),
            )]),
        };
        let loader = CompositeCandidateLoader::new(vec![&failure, &present]);
        let error = loader
            .load(&SolverKey::InstalledName(PackageName::new("pkg").unwrap()))
            .unwrap_err();
        assert_eq!(
            error.category(),
            CandidateLoadErrorCategory::TransportFailure
        );
        assert!(error.diagnostic().contains("candidate source 0"));
    }

    #[test]
    fn all_sources_not_found_remains_an_empty_ordinary_absence() {
        let first = FixedLoader {
            result: Err(CandidateLoadError::new(
                CandidateLoadErrorCategory::NotFound,
                "first absence",
            )),
        };
        let second = FixedLoader {
            result: Err(CandidateLoadError::new(
                CandidateLoadErrorCategory::NotFound,
                "second absence",
            )),
        };
        let loader = CompositeCandidateLoader::new(vec![&first, &second]);
        let result = loader
            .load(&SolverKey::InstalledName(PackageName::new("pkg").unwrap()))
            .unwrap();
        assert!(result.candidates().is_empty());
        assert!(result.quarantined().is_empty());
    }

    #[test]
    fn zero_sources_remains_an_empty_ordinary_absence() {
        let loader = CompositeCandidateLoader::new(Vec::new());
        let result = loader
            .load(&SolverKey::InstalledName(PackageName::new("pkg").unwrap()))
            .unwrap();
        assert!(result.candidates().is_empty());
        assert!(result.quarantined().is_empty());
    }

    #[test]
    fn hard_source_error_after_candidates_is_not_hidden() {
        let present = FixedLoader {
            result: result(vec![candidate(
                "present",
                release(
                    "pkg",
                    "0123456789012345678901234567890123456789",
                    Vec::new(),
                ),
                Vec::new(),
            )]),
        };
        let failure = FixedLoader {
            result: Err(CandidateLoadError::new(
                CandidateLoadErrorCategory::MetadataInvalid,
                "invalid metadata",
            )),
        };
        let loader = CompositeCandidateLoader::new(vec![&present, &failure]);
        let error = loader
            .load(&SolverKey::InstalledName(PackageName::new("pkg").unwrap()))
            .unwrap_err();
        assert_eq!(
            error.category(),
            CandidateLoadErrorCategory::MetadataInvalid
        );
        assert!(error.diagnostic().contains("candidate source 1"));
    }

    #[test]
    fn quarantine_union_preserves_source_order_and_deduplicates_exact_values() {
        let package = PackageName::new("pkg").unwrap();
        let first = FixedLoader {
            result: Ok(CandidateLoadResult::new(
                Vec::new(),
                vec![
                    QuarantinedCandidate::new(RPackageVersion::parse("1.0.0").unwrap(), "first"),
                    QuarantinedCandidate::new(RPackageVersion::parse("2.0.0").unwrap(), "shared"),
                ],
            )),
        };
        let second = FixedLoader {
            result: Ok(CandidateLoadResult::new(
                Vec::new(),
                vec![
                    QuarantinedCandidate::new(RPackageVersion::parse("2.0.0").unwrap(), "shared"),
                    QuarantinedCandidate::new(RPackageVersion::parse("3.0.0").unwrap(), "second"),
                ],
            )),
        };
        let loader = CompositeCandidateLoader::new(vec![&first, &second]);
        let loaded = loader.load(&SolverKey::InstalledName(package)).unwrap();
        assert_eq!(loaded.quarantined().len(), 3);
        assert_eq!(loaded.quarantined()[0].diagnostic(), "first");
        assert_eq!(loaded.quarantined()[1].diagnostic(), "shared");
        assert_eq!(loaded.quarantined()[2].diagnostic(), "second");
    }

    struct ScopedLoader {
        repository: RepositoryId,
        candidate: PreparedCandidate,
    }

    impl CandidateLoader for ScopedLoader {
        fn releases(
            &self,
            subject: &SolverKey,
        ) -> Result<Vec<PreparedCandidate>, CandidateLoadError> {
            self.load(subject).map(|result| result.into_parts().0)
        }

        fn load(&self, subject: &SolverKey) -> Result<CandidateLoadResult, CandidateLoadError> {
            match subject {
                SolverKey::Repository { repository, .. } if repository == &self.repository => Ok(
                    CandidateLoadResult::new(vec![self.candidate.clone()], Vec::new()),
                ),
                _ => Err(CandidateLoadError::new(
                    CandidateLoadErrorCategory::NotFound,
                    "repository-scoped absence",
                )),
            }
        }
    }

    #[test]
    fn repository_qualified_subject_is_left_to_each_loader_scope() {
        let package = PackageName::new("pkg").unwrap();
        let first_id = RepositoryId::new("first").unwrap();
        let second_id = RepositoryId::new("second").unwrap();
        let first = ScopedLoader {
            repository: first_id.clone(),
            candidate: candidate(
                "first",
                release(
                    "pkg",
                    "0123456789012345678901234567890123456789",
                    Vec::new(),
                ),
                Vec::new(),
            ),
        };
        let second = ScopedLoader {
            repository: second_id.clone(),
            candidate: candidate(
                "second",
                release(
                    "pkg",
                    "fedcba9876543210fedcba9876543210fedcba98",
                    Vec::new(),
                ),
                Vec::new(),
            ),
        };
        let loader = CompositeCandidateLoader::new(vec![&first, &second]);
        let loaded = loader
            .load(&SolverKey::Repository {
                repository: first_id,
                name: package,
            })
            .unwrap();
        assert_eq!(loaded.candidates().len(), 1);
        assert_eq!(
            loaded.candidates()[0].occurrences()[0].repository(),
            &RepositoryId::new("first").unwrap()
        );
    }

    #[test]
    fn reversing_loader_order_keeps_the_same_union() {
        let first = FixedLoader {
            result: result(vec![candidate(
                "first",
                release(
                    "pkg",
                    "0123456789012345678901234567890123456789",
                    Vec::new(),
                ),
                Vec::new(),
            )]),
        };
        let second = FixedLoader {
            result: result(vec![candidate(
                "pkg-source",
                release(
                    "pkg",
                    "fedcba9876543210fedcba9876543210fedcba98",
                    Vec::new(),
                ),
                Vec::new(),
            )]),
        };
        let subject = SolverKey::InstalledName(PackageName::new("pkg").unwrap());
        let forward = CompositeCandidateLoader::new(vec![&first, &second])
            .load(&subject)
            .unwrap();
        let reverse = CompositeCandidateLoader::new(vec![&second, &first])
            .load(&subject)
            .unwrap();
        let forward_ids = forward
            .candidates()
            .iter()
            .map(|candidate| candidate.identity().clone())
            .collect::<HashSet<_>>();
        let reverse_ids = reverse
            .candidates()
            .iter()
            .map(|candidate| candidate.identity().clone())
            .collect::<HashSet<_>>();
        assert_eq!(forward_ids, reverse_ids);
    }
}
