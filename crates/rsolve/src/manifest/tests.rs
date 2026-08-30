use super::*;
use rsolve_core::{
    PackageName, PackageNamespace, Provenance, RelationOp, ReleaseIdentity, RepositoryId,
    ResolutionTarget, SolverKey, VersionClause,
};
use std::path::PathBuf;

fn version(value: &str) -> RPackageVersion {
    RPackageVersion::parse(value).unwrap()
}

fn package(value: &str) -> PackageName {
    PackageName::new(value).unwrap()
}

fn minimal_manifest() -> Manifest {
    Manifest::new(
        VersionConstraint::from_clause(RelationOp::Ge, version("4.3")),
        ManifestTarget::new(version("4.4.0")),
        vec![ManifestDependency::new(
            package("example"),
            VersionConstraint::new(vec![VersionClause::new(RelationOp::Ge, version("1.2.0"))]),
        )],
    )
    .unwrap()
}

#[test]
fn minimal_manifest_composes_to_one_request() {
    let request = compose_resolution_request(minimal_manifest()).unwrap();

    assert_eq!(request.roots.len(), 1);
    assert_eq!(request.roots[0].package.name(), &package("example"));
    assert_eq!(
        request.roots[0].package.constraint(),
        &VersionConstraint::from_clause(RelationOp::Ge, version("1.2.0"))
    );
    assert_eq!(request.target.r_version, version("4.4.0"));
    assert_eq!(
        request.r_requirement,
        VersionConstraint::from_clause(RelationOp::Ge, version("4.3"))
    );
    assert!(request.locked.is_empty());
}

#[test]
fn composition_preserves_owned_lock_identity_mapping() {
    let key = SolverKey::Registry {
        namespace: PackageNamespace::new("cran").unwrap(),
        name: package("example"),
    };
    let identity = ReleaseIdentity::new(
        package("example"),
        Provenance::RegistryRelease {
            namespace: PackageNamespace::new("cran").unwrap(),
            version: version("1.2.3"),
        },
    );
    let mut locked = LockedIdentities::new();
    locked.insert(key.clone(), identity.clone());

    let request =
        compose_resolution_request_with_locked(minimal_manifest(), locked.clone()).unwrap();
    assert_eq!(request.locked, locked);
    assert_eq!(request.locked.get(&key), Some(&identity));
}

#[test]
fn manifest_rejects_r_as_a_regular_requirement() {
    let result = Manifest::new(
        VersionConstraint::unconstrained(),
        ManifestTarget::new(version("4.4.0")),
        vec![ManifestDependency::new(
            package("R"),
            VersionConstraint::unconstrained(),
        )],
    );
    assert_eq!(result, Err(ManifestError::RIsNotAPackageRequirement));
}

#[test]
fn manifest_rejects_duplicate_requirements() {
    let result = Manifest::new(
        VersionConstraint::unconstrained(),
        ManifestTarget::new(version("4.4.0")),
        vec![
            ManifestDependency::new(package("example"), VersionConstraint::unconstrained()),
            ManifestDependency::new(package("example"), VersionConstraint::unconstrained()),
        ],
    );
    assert_eq!(
        result,
        Err(ManifestError::DuplicateRequirement {
            name: package("example")
        })
    );
}

#[test]
fn strict_codec_normalizes_repositories_and_rejects_unknown_fields() {
    let document = parse_manifest(
        r#"
                [rsolve]
                schema = 1
                [r]
                version = "*"
                [[repositories]]
                id = "cran"
                url = "HTTPS://EXAMPLE.ORG:443/a/../cran"
                registry = { kind = "cran" }
                [dependencies]
                "data.table" = "*"
            "#,
    )
    .unwrap();
    assert_eq!(
        document.repositories[0].manifest_endpoint().as_str(),
        "https://example.org/cran"
    );
    assert!(matches!(
        document.repositories[0].registry(),
        RegistrySpec::Cran
    ));

    let error = parse_manifest("[rsolve]\nschema = 1\n[unexpected]\nvalue = true\n").unwrap_err();
    assert!(matches!(error, ManifestError::UnknownField { .. }));
    let error =
        parse_manifest("[rsolve]\nschema = 1\nextra = true\n[r]\nversion='*'\n").unwrap_err();
    assert!(matches!(error, ManifestError::UnknownField { .. }));
}

#[test]
fn repository_package_allowlists_are_canonical_and_part_of_intent() {
    let first = parse_manifest(
        "[rsolve]\nschema=1\n[r]\nversion='*'\n[[repositories]]\nid='cran'\nurl='https://example.org'\nregistry='cran'\npackages=['zeta','alpha']\n",
    )
    .unwrap();
    assert_eq!(
        first.repositories[0]
            .packages()
            .unwrap()
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        vec!["alpha", "zeta"]
    );
    assert_eq!(
        first.repositories[0].configured_registry_id().unwrap(),
        parse_manifest(
            "[rsolve]\nschema=1\n[r]\nversion='*'\n[[repositories]]\nid='other'\nurl='https://example.org'\nregistry='cran'\npackages=['alpha']\n",
        )
        .unwrap()
        .repositories[0]
        .configured_registry_id()
        .unwrap()
    );
    let reordered = parse_manifest(
        "[rsolve]\nschema=1\n[r]\nversion='*'\n[[repositories]]\nid='cran'\nurl='https://example.org'\nregistry='cran'\npackages=['alpha','zeta']\n",
    )
    .unwrap();
    assert_eq!(
        first.repository_intent_digest().unwrap(),
        reordered.repository_intent_digest().unwrap()
    );
    let changed = parse_manifest(
        "[rsolve]\nschema=1\n[r]\nversion='*'\n[[repositories]]\nid='cran'\nurl='https://example.org'\nregistry='cran'\npackages=['alpha']\n",
    )
    .unwrap();
    assert_ne!(
        first.repository_intent_digest().unwrap(),
        changed.repository_intent_digest().unwrap()
    );
    assert!(matches!(
        parse_manifest(
            "[rsolve]\nschema=1\n[r]\nversion='*'\n[[repositories]]\nid='cran'\nurl='https://example.org'\nregistry='cran'\npackages=[]\n",
        ),
        Err(ManifestError::EmptyRepositoryPackageAllowlist { .. })
    ));
    assert!(matches!(
        parse_manifest(
            "[rsolve]\nschema=1\n[r]\nversion='*'\n[[repositories]]\nid='cran'\nurl='https://example.org'\nregistry='cran'\npackages=['alpha','alpha']\n",
        ),
        Err(ManifestError::DuplicateRepositoryPackage { .. })
    ));
    assert!(matches!(
        parse_manifest(
            "[rsolve]\nschema=1\n[r]\nversion='*'\n[[repositories]]\nid='cran'\nurl='https://example.org'\nregistry='cran'\npackages=['not-a-package']\n",
        ),
        Err(ManifestError::InvalidRepositoryPackage { .. })
    ));
    assert!(matches!(
        parse_manifest(
            "[rsolve]\nschema=1\n[r]\nversion='*'\n[[repositories]]\nid='cran'\nurl='https://example.org'\nregistry='cran'\npackages='alpha'\n",
        ),
        Err(ManifestError::WrongType { .. })
    ));
    assert!(matches!(
        parse_manifest(
            "[rsolve]\nschema=1\n[r]\nversion='*'\n[[repositories]]\nid='cran'\nurl='https://example.org'\nregistry='cran'\npackages=['alpha', 1]\n",
        ),
        Err(ManifestError::WrongType { field, .. })
            if field == "repositories[cran].packages[]"
    ));
}

#[test]
fn repository_qualified_root_must_be_in_the_repository_allowlist() {
    let allowed = parse_manifest(
        "[rsolve]\nschema=1\n[r]\nversion='*'\n[[repositories]]\nid='cran'\nurl='https://example.org'\nregistry='cran'\npackages=['foo']\n[dependencies]\nfoo={repository='cran'}\n",
    )
    .unwrap();
    assert!(
        allowed
            .compose_environment("default", ResolutionTarget::new(version("4.4.0")))
            .is_ok()
    );
    let rejected = parse_manifest(
        "[rsolve]\nschema=1\n[r]\nversion='*'\n[[repositories]]\nid='cran'\nurl='https://example.org'\nregistry='cran'\npackages=['foo']\n[dependencies]\nbar={repository='cran'}\n",
    )
    .unwrap();
    assert!(matches!(
        rejected.compose_environment("default", ResolutionTarget::new(version("4.4.0"))),
        Err(ManifestError::RepositoryPackageNotAllowed { .. })
    ));
}

#[test]
fn registry_forms_and_invalid_kinds_are_typed() {
    let cran_like = parse_manifest(
            "[rsolve]\nschema=1\n[r]\nversion='*'\n[[repositories]]\nid='private'\nurl='https://example.org'\nregistry={kind='cran-like',namespace='company'}\n",
        )
        .unwrap();
    assert!(matches!(
        cran_like.repositories[0].registry(),
        RegistrySpec::CranLike { .. }
    ));
    let error = parse_manifest(
            "[rsolve]\nschema=1\n[r]\nversion='*'\n[[repositories]]\nid='p3m'\nurl='https://example.org'\nregistry='posit-package-manager'\n",
        )
        .unwrap_err();
    assert!(matches!(error, ManifestError::UnknownRegistryKind { .. }));

    let shorthand = parse_manifest("[rsolve]\nschema=1\n[r]\nversion='*'\n[[repositories]]\nid='u'\nurl='https://custom.example.org/catalog'\nregistry='r-universe'\n").unwrap();
    let table = parse_manifest("[rsolve]\nschema=1\n[r]\nversion='*'\n[[repositories]]\nid='u'\nurl='https://custom.example.org/catalog'\nregistry={kind='r-universe'}\n").unwrap();
    assert_eq!(
        shorthand.repositories[0].registry(),
        table.repositories[0].registry()
    );
    let error = parse_manifest("[rsolve]\nschema=1\n[r]\nversion='*'\n[[repositories]]\nid='u'\nurl='https://custom.example.org'\nregistry={kind='r-universe',service='catalog'}\n").unwrap_err();
    assert!(matches!(error, ManifestError::UnknownField { .. }));
    let error = parse_manifest("[rsolve]\nschema=1\n[r]\nversion='*'\n[[repositories]]\nid='u'\nurl='https://custom.example.org'\nregistry={kind='cran-like'}\n").unwrap_err();
    assert!(matches!(error, ManifestError::InvalidRegistry { .. }));
    let error = parse_manifest("[rsolve]\nschema=1\n[r]\nversion='*'\n[[repositories]]\nid='u'\nurl='https://custom.example.org'\nregistry={kind='cran-like',namespace='cran'}\n").unwrap_err();
    assert!(matches!(error, ManifestError::InvalidRegistry { .. }));
}

#[test]
fn effective_endpoint_does_not_change_shared_identity_or_digest() {
    let document = parse_manifest("[rsolve]\nschema=1\n[r]\nversion='*'\n[[repositories]]\nid='cran'\nurl='https://example.org'\nregistry='cran'\n[dependencies]\nfoo='*'\n").unwrap();
    let spec = &document.repositories[0];
    let registry_id = spec.configured_registry_id().unwrap();
    let digest = document.repository_intent_digest().unwrap();
    let effective = spec.effective(Endpoint::parse("https://mirror.example.org").unwrap());
    assert_eq!(effective.configured_registry_id().unwrap(), registry_id);
    assert_eq!(
        effective.spec().manifest_endpoint(),
        spec.manifest_endpoint()
    );
    assert_eq!(digest, document.repository_intent_digest().unwrap());

    let renamed = parse_manifest("[rsolve]\nschema=1\n[r]\nversion='*'\n[[repositories]]\nid='mirror'\nurl='https://example.org'\nregistry='cran'\n").unwrap();
    assert_eq!(
        renamed.repositories[0].configured_registry_id().unwrap(),
        registry_id
    );
    assert_ne!(renamed.repository_intent_digest().unwrap(), digest);
    let changed_endpoint = parse_manifest("[rsolve]\nschema=1\n[r]\nversion='*'\n[[repositories]]\nid='cran'\nurl='https://other.example.org'\nregistry='cran'\n").unwrap();
    assert_ne!(
        changed_endpoint.repositories[0]
            .configured_registry_id()
            .unwrap(),
        registry_id
    );
    assert_ne!(changed_endpoint.repository_intent_digest().unwrap(), digest);
    let changed_provider = parse_manifest("[rsolve]\nschema=1\n[r]\nversion='*'\n[[repositories]]\nid='cran'\nurl='https://example.org'\nregistry={kind='cran-like',namespace='private'}\n").unwrap();
    assert_ne!(
        changed_provider.repositories[0]
            .configured_registry_id()
            .unwrap(),
        registry_id
    );
    assert_ne!(changed_provider.repository_intent_digest().unwrap(), digest);
    let ordered = parse_manifest("[rsolve]\nschema=1\n[r]\nversion='*'\n[[repositories]]\nid='one'\nurl='https://one.example.org'\nregistry='cran'\n[[repositories]]\nid='two'\nurl='https://two.example.org'\nregistry='cran'\n").unwrap();
    let swapped = parse_manifest("[rsolve]\nschema=1\n[r]\nversion='*'\n[[repositories]]\nid='two'\nurl='https://two.example.org'\nregistry='cran'\n[[repositories]]\nid='one'\nurl='https://one.example.org'\nregistry='cran'\n").unwrap();
    assert_ne!(
        ordered.repository_intent_digest().unwrap(),
        swapped.repository_intent_digest().unwrap()
    );
}

#[test]
fn duplicate_toml_keys_fail_before_normalization() {
    let error = parse_manifest("[rsolve]\nschema = 1\nschema = 1\n").unwrap_err();
    assert!(matches!(error, ManifestError::Toml(_)));
}

#[test]
fn wire_facts_and_source_union_are_lossless() {
    let document = parse_manifest(
        r#"
        [rsolve]
        schema = 1
        [r]
        version = ">= 4.4"
        [resolution]
        published-before = "2026-08-01"
        [[repositories]]
        id = "default"
        url = "https://example.org"
        registry = "cran"
        [environments]
        test = ["test"]
        [dependencies]
        gitpkg = { git = "https://github.com/example/gitpkg.git", branch = "main", subdirectory = "pkg dir", include-suggests = true }
        urlpkg = { url = "https://example.org/pkg.tar.gz?download=1", sha256 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" }
        localpkg = { path = "../local dir", sha256 = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB" }
        [groups.test.dependencies]
        testthat = "*"
        "#,
    )
    .unwrap();
    assert_eq!(document.r_requirement, ">= 4.4");
    assert_eq!(document.published_before.unwrap().to_string(), "2026-08-01");
    assert_eq!(document.groups["test"].len(), 1);
    assert_eq!(document.environments["test"], vec!["test"]);
    assert!(matches!(document.repositories[0].id().as_str(), "default"));
    assert!(matches!(
        document.dependencies[&package("gitpkg")].source,
        ManifestSource::Git {
            subdirectory: Some(_),
            ..
        }
    ));
    assert!(
        matches!(&document.dependencies[&package("urlpkg")].source, ManifestSource::Url { url, .. } if url.as_str().contains("?download=1"))
    );
    assert!(
        matches!(&document.dependencies[&package("localpkg")].source, ManifestSource::Path { path, sha256: Some(_) } if path == "../local dir")
    );
}

#[test]
fn source_union_rejects_invalid_combinations_and_preserves_query() {
    let base = "[rsolve]\nschema=1\n[r]\nversion='*'\n[dependencies]\nfoo = ";
    for value in [
        "{ git='https://github.com/a/a.git', branch='main', tag='v1' }",
        "{ git='https://github.com/a/a.git', sha256='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' }",
        "{ repository='default', subdirectory='pkg' }",
        "{ path='pkg', subdirectory='pkg' }",
    ] {
        assert!(matches!(
            parse_manifest(&format!("{base}{value}")),
            Err(ManifestError::SourceConflict { .. })
        ));
    }
    assert!(parse_manifest(&format!("{base}{{ url='http://example.org/a.tar.gz' }}")).is_err());
    for url in [
        "https://example.org\\..\\mirror",
        "https://example.org/ordinary\\path/a.tar.gz",
    ] {
        assert!(parse_manifest(&format!("{base}{{ url='{url}' }}")).is_err());
    }
    assert!(
        parse_manifest(&format!(
            "{base}{{ url='https://user@example.org/a.tar.gz' }}"
        ))
        .is_err()
    );
    assert!(
        parse_manifest(&format!(
            "{base}{{ url='https://example.org/a.tar.gz#frag' }}"
        ))
        .is_err()
    );
    let query = parse_manifest(&format!(
        "{base}{{ url='https://example.org/a/../a.tar.gz?x=1' }}"
    ))
    .unwrap();
    assert!(
        matches!(&query.dependencies[&package("foo")].source, ManifestSource::Url { url, .. } if url.as_str() == "https://example.org/a.tar.gz?x=1")
    );
    let query_only = parse_manifest(&format!(
        "{base}{{ url='https://example.org?redirect=/../x' }}"
    ))
    .unwrap();
    assert!(
        matches!(&query_only.dependencies[&package("foo")].source, ManifestSource::Url { url, .. } if url.as_str() == "https://example.org/?redirect=/../x")
    );
    assert!(
        parse_manifest(&format!(
            "{base}{{ url='https://example.org/../x?redirect=/ok' }}"
        ))
        .is_err()
    );
    let encoded_query = parse_manifest(&format!(
        "{base}{{ url='https://example.org?redirect=%2e%2e/x' }}"
    ))
    .unwrap();
    assert!(
        matches!(&encoded_query.dependencies[&package("foo")].source, ManifestSource::Url { url, .. } if url.as_str() == "https://example.org/?redirect=%2e%2e/x")
    );
    let literal_backslash_query = parse_manifest(&format!(
        "{base}{{ url='https://example.org?redirect=\\path' }}"
    ))
    .unwrap();
    assert!(
        matches!(&literal_backslash_query.dependencies[&package("foo")].source, ManifestSource::Url { url, .. } if url.as_str() == "https://example.org/?redirect=\\path")
    );
}

#[test]
fn url_normalization_preserves_repeated_slashes() {
    let repeated = parse_manifest("[rsolve]\nschema=1\n[r]\nversion='*'\n[[repositories]]\nid='main'\nurl='https://example.org/repo//path'\nregistry='cran'\n[dependencies]\nfoo={url='https://example.org/repo//pkg.tar.gz?x=1'}\n").unwrap();
    let single = parse_manifest("[rsolve]\nschema=1\n[r]\nversion='*'\n[[repositories]]\nid='main'\nurl='https://example.org/repo/path'\nregistry='cran'\n").unwrap();
    assert_eq!(
        repeated.repositories[0].manifest_endpoint().as_str(),
        "https://example.org/repo//path"
    );
    assert_ne!(
        repeated.repositories[0].configured_registry_id().unwrap(),
        single.repositories[0].configured_registry_id().unwrap()
    );
    assert!(
        matches!(&repeated.dependencies[&package("foo")].source, ManifestSource::Url { url, .. } if url.as_str() == "https://example.org/repo//pkg.tar.gz?x=1")
    );
    let parent_after_empty = parse_manifest("[rsolve]\nschema=1\n[r]\nversion='*'\n[[repositories]]\nid='main'\nurl='https://example.org/repo//../path'\nregistry='cran'\n").unwrap();
    assert_eq!(
        parent_after_empty.repositories[0]
            .manifest_endpoint()
            .as_str(),
        "https://example.org/repo/path"
    );
    assert!(parse_manifest("[rsolve]\nschema=1\n[r]\nversion='*'\n[[repositories]]\nid='main'\nurl='https://example.org/../path'\nregistry='cran'\n").is_err());
    let encoded_parent = parse_manifest("[rsolve]\nschema=1\n[r]\nversion='*'\n[[repositories]]\nid='main'\nurl='https://example.org/repo/%2e%2e/path'\nregistry='cran'\n").unwrap();
    assert_eq!(
        encoded_parent.repositories[0].manifest_endpoint().as_str(),
        "https://example.org/path"
    );
    let encoded_repeated_parent = parse_manifest("[rsolve]\nschema=1\n[r]\nversion='*'\n[[repositories]]\nid='main'\nurl='https://example.org/repo//%2E%2E/path'\nregistry='cran'\n").unwrap();
    assert_eq!(
        encoded_repeated_parent.repositories[0]
            .manifest_endpoint()
            .as_str(),
        "https://example.org/repo/path"
    );
    assert!(parse_manifest("[rsolve]\nschema=1\n[r]\nversion='*'\n[[repositories]]\nid='main'\nurl='https://example.org/%2e%2e/path'\nregistry='cran'\n").is_err());
    assert!(parse_manifest("[rsolve]\nschema=1\n[r]\nversion='*'\n[[repositories]]\nid='main'\nurl='https://example.org/ordinary\\path'\nregistry='cran'\n").is_err());
    let encoded_direct = parse_manifest("[rsolve]\nschema=1\n[r]\nversion='*'\n[dependencies]\nfoo={url='https://example.org/repo/%2e%2e/pkg.tar.gz?x=1'}\n").unwrap();
    assert!(
        matches!(&encoded_direct.dependencies[&package("foo")].source, ManifestSource::Url { url, .. } if url.as_str() == "https://example.org/pkg.tar.gz?x=1")
    );
}

#[test]
fn runtime_cran_registry_id_uses_manifest_endpoint_normalization() {
    let document = parse_manifest("[rsolve]\nschema=1\n[r]\nversion='*'\n[[repositories]]\nid='cran'\nurl='https://cloud.r-project.org'\nregistry='cran'\n").unwrap();
    let configured = document.repositories[0].configured_registry_id().unwrap();
    let runtime =
        crate::prepared_snapshot::cran_registry_id("https://cloud.r-project.org/").unwrap();
    assert_eq!(configured, runtime);
}

#[test]
fn explicit_read_and_nearest_discovery_are_tool_owned() {
    let root = tempfile::tempdir().unwrap();
    let nested = root.path().join("a/b");
    std::fs::create_dir_all(&nested).unwrap();
    let root_manifest = root.path().join("rsolve.toml");
    std::fs::write(&root_manifest, "[rsolve]\nschema=1\n[r]\nversion='*'\n").unwrap();
    let nested_manifest = nested.join("rsolve.toml");
    std::fs::write(
        &nested_manifest,
        "[rsolve]\nschema=1\n[r]\nversion='>= 4.0'\n",
    )
    .unwrap();
    let (found, document) = discover_manifest(&nested).unwrap();
    assert_eq!(found, nested_manifest);
    assert_eq!(document.r_requirement, ">= 4.0");
    let empty = tempfile::tempdir().unwrap();
    assert!(matches!(
        discover_manifest(empty.path()),
        Err(ManifestError::NotFound { .. })
    ));
    let explicit = nested.join("explicit.toml");
    std::fs::write(&explicit, "[rsolve]\nschema=1\n[r]\nversion='*'\n").unwrap();
    let (read, _) = load_manifest(Some(&explicit), root.path()).unwrap();
    assert_eq!(read, explicit);
    let (discovered, _) = load_manifest(None, &nested).unwrap();
    assert_eq!(discovered, nested_manifest);
}

#[test]
fn r_requirement_and_publication_cutoff_are_required_and_typed() {
    let missing = parse_manifest("[rsolve]\nschema=1\n").unwrap_err();
    assert!(matches!(missing, ManifestError::MissingField { .. }));
    let empty = parse_manifest("[rsolve]\nschema=1\n[r]\nversion=''\n").unwrap_err();
    assert!(matches!(empty, ManifestError::InvalidField { .. }));
    let wrong = parse_manifest("[rsolve]\nschema=1\n[r]\nversion=1\n").unwrap_err();
    assert!(matches!(wrong, ManifestError::WrongType { .. }));
    let invalid_date = parse_manifest(
        "[rsolve]\nschema=1\n[r]\nversion='*'\n[resolution]\npublished-before='2026-2-01'\n",
    )
    .unwrap_err();
    assert!(matches!(invalid_date, ManifestError::InvalidField { .. }));
    let valid = parse_manifest(
        "[rsolve]\nschema=1\n[r]\nversion='*'\n[resolution]\npublished-before='2026-02-01'\n",
    )
    .unwrap();
    assert_eq!(valid.published_before.unwrap().to_string(), "2026-02-01");
}

#[test]
fn r_constraints_allow_one_component_versions_but_package_constraints_do_not() {
    let r = parse_manifest("[rsolve]\nschema=1\n[r]\nversion='>= 4'\n").unwrap();
    assert!(
        r.compose_environment("default", ResolutionTarget::new(version("4.4.0")))
            .is_ok()
    );
    for dependency in ["'1'", "'>= 1'"] {
        let error = parse_manifest(&format!(
            "[rsolve]\nschema=1\n[r]\nversion='*'\n[dependencies]\nfoo={dependency}\n"
        ))
        .unwrap()
        .compose_environment("default", ResolutionTarget::new(version("4.4.0")))
        .unwrap_err();
        assert!(matches!(
            error,
            ManifestError::InvalidVersionConstraint { .. }
        ));
    }
    assert!(
        parse_manifest("[rsolve]\nschema=1\n[r]\nversion='*'\n[dependencies]\nfoo='1.0'\n")
            .unwrap()
            .compose_environment("default", ResolutionTarget::new(version("4.4.0")))
            .is_ok()
    );
    let missing_version =
        parse_manifest("[rsolve]\nschema=1\n[r]\nversion='*'\n[dependencies]\nfoo='>'\n")
            .unwrap()
            .compose_environment("default", ResolutionTarget::new(version("4.4.0")))
            .unwrap_err();
    assert!(matches!(
        missing_version,
        ManifestError::InvalidVersionConstraint { reason, .. }
            if reason == "relation must have a numeric version"
    ));
}

#[test]
fn explicit_repository_references_are_validated_during_parse() {
    let error = parse_manifest(
        "[rsolve]\nschema=1\n[r]\nversion='*'\n[dependencies]\nfoo={repository='missing'}\n",
    )
    .unwrap_err();
    assert!(matches!(
        error,
        ManifestError::UnknownRepositoryReference { .. }
    ));
    let error = parse_manifest("[rsolve]\nschema=1\n[r]\nversion='*'\n[dependencies]\nR='*'\n")
        .unwrap_err();
    assert_eq!(error, ManifestError::RIsNotAPackageRequirement);
}

#[test]
fn dependency_versions_reject_empty_values_in_both_wire_forms() {
    for dependency in ["''", "{version=''}"] {
        let error = parse_manifest(&format!(
            "[rsolve]\nschema=1\n[r]\nversion='*'\n[dependencies]\nfoo={dependency}\n"
        ))
        .unwrap_err();
        assert!(matches!(
            error,
            ManifestError::InvalidDependencyField { .. }
        ));
    }
}

#[test]
fn environment_group_references_are_validated_without_reordering() {
    let unknown =
        parse_manifest("[rsolve]\nschema=1\n[r]\nversion='*'\n[environments]\nci=['missing']\n")
            .unwrap_err();
    assert!(matches!(
        unknown,
        ManifestError::UnknownEnvironmentGroup { environment, group }
            if environment == "ci" && group == "missing"
    ));

    let duplicate = parse_manifest(
        "[rsolve]\nschema=1\n[r]\nversion='*'\n[groups.check]\n[environments]\nci=['check','check']\n",
    )
    .unwrap_err();
    assert!(matches!(
        duplicate,
        ManifestError::DuplicateEnvironmentGroup { environment, group }
            if environment == "ci" && group == "check"
    ));

    let valid = parse_manifest(
        "[rsolve]\nschema=1\n[r]\nversion='*'\n[groups.check]\n[groups.lint]\n[environments]\nci=['lint','check']\n",
    )
    .unwrap();
    assert_eq!(valid.environments["ci"], vec!["lint", "check"]);

    let digit = parse_manifest(
        "[rsolve]\nschema=1\n[r]\nversion='*'\n[groups.check]\n[environments]\n'1ci'=['check']\n",
    )
    .unwrap();
    assert!(digit.environments.contains_key("1ci"));
}

#[test]
fn repository_constructor_enforces_registry_invariants() {
    let namespace = PackageNamespace::new("cran").unwrap();
    let error = RepositorySpec::new(
        RepositoryId::new("main").unwrap(),
        RegistrySpec::CranLike { namespace },
        Endpoint::parse("https://example.org").unwrap(),
    )
    .unwrap_err();
    assert!(matches!(error, ManifestError::InvalidRegistry { .. }));
    let registry = RegistrySpec::cran_like(PackageNamespace::new("private").unwrap()).unwrap();
    let spec = RepositorySpec::new(
        RepositoryId::new("main").unwrap(),
        registry,
        Endpoint::parse("https://example.org").unwrap(),
    )
    .unwrap();
    assert_eq!(spec.id().as_str(), "main");
    assert_eq!(spec.manifest_endpoint().as_str(), "https://example.org/");
}

#[test]
fn document_composition_merges_base_and_selected_groups_deterministically() {
    let document = parse_manifest(
        r#"
        [rsolve]
        schema = 1
        [r]
        version = ">= 4.0, < 5.0"
        [[repositories]]
        id = "main"
        url = "https://example.org"
        registry = "cran"
        [dependencies]
        zzz = ">= 1.0"
        foo = { version = ">= 1.0" }
        [groups.test.dependencies]
        foo = { version = "< 2.0", repository = "main", include-suggests = true }
        aaa = "*"
        [environments]
        test = ["test"]
        "#,
    )
    .unwrap();
    let composed = document
        .compose_environment("test", ResolutionTarget::new(version("4.4.0")))
        .unwrap();
    assert_eq!(
        composed
            .roots
            .iter()
            .map(|root| root.name.as_str())
            .collect::<Vec<_>>(),
        vec!["aaa", "foo", "zzz"]
    );
    let foo = &composed.roots[1];
    assert_eq!(foo.constraint.clauses.len(), 2);
    assert_eq!(foo.expansion, RootExpansionPolicy::DirectSuggests);
    assert!(matches!(
        foo.source,
        ManifestSource::Registry {
            repository: Some(ref id)
        } if id.as_str() == "main"
    ));
    let request = composed.into_resolution_request().unwrap();
    assert_eq!(request.roots.len(), 3);
    assert_eq!(
        request.r_requirement,
        super::compose::parse_r_constraint(">= 4.0, < 5.0", "r").unwrap()
    );
    assert!(request.publication_cutoff.is_none());
}

#[test]
fn direct_sources_remain_pending_until_acquisition() {
    let document = parse_manifest(
        "[rsolve]\nschema=1\n[r]\nversion='*'\n[dependencies]\nfoo={url='https://example.org/foo.tar.gz'}\n",
    )
    .unwrap();
    let composed = document
        .compose_environment("default", ResolutionTarget::new(version("4.4.0")))
        .unwrap();
    assert!(matches!(
        composed.clone().into_resolution_request(),
        Err(ManifestError::DirectSourceRequiresAcquisition { name }) if name.as_str() == "foo"
    ));
    assert!(matches!(
        composed.roots[0].source,
        ManifestSource::Url { .. }
    ));
}

#[test]
fn composition_rejects_unknown_environment_and_incompatible_target() {
    let document = parse_manifest("[rsolve]\nschema=1\n[r]\nversion='>= 5.0'\n").unwrap();
    let unknown = document
        .compose_environment("dev", ResolutionTarget::new(version("5.1.0")))
        .unwrap_err();
    assert!(matches!(unknown, ManifestError::UnknownEnvironment { .. }));
    let incompatible = document
        .compose_environment("default", ResolutionTarget::new(version("4.4.0")))
        .unwrap_err();
    assert!(matches!(
        incompatible,
        ManifestError::TargetOutsideRConstraint { .. }
    ));
}

#[test]
fn composition_revalidates_public_environment_and_repository_references() {
    let mut document = parse_manifest(
        "[rsolve]\nschema=1\n[r]\nversion='*'\n[groups.test.dependencies]\nfoo='*'\n",
    )
    .unwrap();
    document
        .environments
        .insert("dev".into(), vec!["missing".into()]);
    let error = document
        .compose_environment("dev", ResolutionTarget::new(version("4.4.0")))
        .unwrap_err();
    assert!(matches!(
        error,
        ManifestError::UnknownEnvironmentGroup { .. }
    ));
}

#[test]
fn composition_canonicalizes_public_requested_source_paths() {
    let mut document = parse_manifest(
        "[rsolve]\nschema=1\n[r]\nversion='*'\n[dependencies]\ngitpkg={git='https://github.com/example/pkg.git',subdirectory='pkg/./src'}\nlocalpkg={path='local/../tree'}\n",
    )
    .unwrap();
    if let ManifestSource::Git { subdirectory, .. } = &mut document
        .dependencies
        .get_mut(&package("gitpkg"))
        .unwrap()
        .source
    {
        *subdirectory = Some("pkg/./src".into());
    }
    if let ManifestSource::Path { path, .. } = &mut document
        .dependencies
        .get_mut(&package("localpkg"))
        .unwrap()
        .source
    {
        *path = "local/../tree".into();
    }
    let composed = document
        .compose_environment("default", ResolutionTarget::new(version("4.4.0")))
        .unwrap();
    assert!(matches!(
        &composed.roots[0].source,
        ManifestSource::Git { subdirectory: Some(value), .. } if value == "pkg/src"
    ));
    assert!(matches!(
        &composed.roots[1].source,
        ManifestSource::Path { path, .. } if path == "tree"
    ));
}

#[test]
fn equivalent_constraint_spellings_have_the_same_intent_digest() {
    let first = parse_manifest(
        "[rsolve]\nschema=1\n[r]\nversion='>= 4.0, < 5.0'\n[dependencies]\nfoo='>= 1.0, >= 1.0.0, < 2.0'\n",
    )
    .unwrap()
    .compose_environment("default", ResolutionTarget::new(version("4.4.0")))
    .unwrap();
    let second = parse_manifest(
        "[rsolve]\nschema=1\n[r]\nversion='>= 4.0.0, < 5'\n[dependencies]\nfoo='< 2.0, >= 1.0'\n",
    )
    .unwrap()
    .compose_environment("default", ResolutionTarget::new(version("4.4.0")))
    .unwrap();
    assert_eq!(
        first.resolution_intent_digest().unwrap(),
        second.resolution_intent_digest().unwrap()
    );
    let mut zero = first.clone();
    zero.roots[0].constraint =
        VersionConstraint::from_clause(RelationOp::Eq, RPackageVersion::parse("0.0").unwrap());
    assert!(zero.resolution_intent_digest().is_ok());
}

#[test]
fn selected_environment_digest_excludes_unselected_groups_and_project_root() {
    let input = "[rsolve]\nschema=1\n[r]\nversion='*'\n[dependencies]\nfoo='>= 1.0'\n[groups.other.dependencies]\nbar='*'\n";
    let first = parse_manifest(input)
        .unwrap()
        .compose_environment("default", ResolutionTarget::new(version("4.4.0")))
        .unwrap();
    let mut changed = parse_manifest(input).unwrap();
    changed.project_root = Some(PathBuf::from("/machine/local/project"));
    changed
        .groups
        .get_mut("other")
        .unwrap()
        .get_mut(&package("bar"))
        .unwrap()
        .version = "< 9.0".into();
    let second = changed
        .compose_environment("default", ResolutionTarget::new(version("4.4.0")))
        .unwrap();
    assert_eq!(
        first.resolution_intent_digest().unwrap(),
        second.resolution_intent_digest().unwrap()
    );
}

#[test]
fn composition_rejects_conflicting_repository_and_git_intents() {
    let repositories = "[[repositories]]\nid='one'\nurl='https://one.example'\nregistry='cran'\n[[repositories]]\nid='two'\nurl='https://two.example'\nregistry='cran'\n";
    let repository_conflict = parse_manifest(&format!(
        "[rsolve]\nschema=1\n[r]\nversion='*'\n{repositories}[dependencies]\nfoo={{repository='one'}}\n[groups.dev.dependencies]\nfoo={{repository='two'}}\n[environments]\ndev=['dev']\n"
    ))
    .unwrap();
    assert!(matches!(
        repository_conflict.compose_environment("dev", ResolutionTarget::new(version("4.4.0"))),
        Err(ManifestError::SourceConflict { .. })
    ));

    let git_conflict = parse_manifest(
        "[rsolve]\nschema=1\n[r]\nversion='*'\n[dependencies]\nfoo={git='https://github.com/example/foo.git',branch='main'}\n[groups.dev.dependencies]\nfoo={git='https://github.com/example/foo.git',tag='v1'}\n[environments]\ndev=['dev']\n",
    )
    .unwrap();
    assert!(matches!(
        git_conflict.compose_environment("dev", ResolutionTarget::new(version("4.4.0"))),
        Err(ManifestError::SourceConflict { .. })
    ));
}

#[test]
fn composition_revalidates_bypassed_repository_references_and_duplicate_groups() {
    let mut document = parse_manifest(
        "[rsolve]\nschema=1\n[r]\nversion='*'\n[groups.check.dependencies]\nfoo='*'\n[environments]\nci=['check']\n",
    )
    .unwrap();
    document
        .environments
        .insert("ci".into(), vec!["check".into(), "check".into()]);
    let duplicate = document
        .clone()
        .compose_environment("ci", ResolutionTarget::new(version("4.4.0")))
        .unwrap_err();
    assert!(matches!(
        duplicate,
        ManifestError::DuplicateEnvironmentGroup { .. }
    ));

    document
        .environments
        .insert("ci".into(), vec!["check".into()]);
    document.dependencies.insert(
        package("bar"),
        ManifestDependencySpec {
            version: "*".into(),
            source: ManifestSource::Registry {
                repository: Some(RepositoryId::new("missing").unwrap()),
            },
            include_suggests: false,
        },
    );
    let unknown = document
        .compose_environment("ci", ResolutionTarget::new(version("4.4.0")))
        .unwrap_err();
    assert!(matches!(
        unknown,
        ManifestError::UnknownRepositoryReference { .. }
    ));
}

#[test]
fn registry_request_preserves_locked_mapping_and_publication_cutoff() {
    let document = parse_manifest(
        "[rsolve]\nschema=1\n[r]\nversion='*'\n[resolution]\npublished-before='2026-08-01'\n[dependencies]\nfoo='*'\n",
    )
    .unwrap();
    let key = SolverKey::InstalledName(package("foo"));
    let identity = ReleaseIdentity::new(
        package("foo"),
        Provenance::RegistryRelease {
            namespace: PackageNamespace::new("cran").unwrap(),
            version: version("1.0.0"),
        },
    );
    let mut locked = LockedIdentities::new();
    locked.insert(key.clone(), identity.clone());
    let request = document
        .compose_environment_with_locked(
            "default",
            ResolutionTarget::new(version("4.4.0")),
            locked.clone(),
        )
        .unwrap()
        .into_resolution_request()
        .unwrap();
    assert_eq!(request.locked.get(&key), Some(&identity));
    assert_eq!(
        request.publication_cutoff.unwrap().date().to_string(),
        "2026-08-01"
    );
}

#[test]
fn source_path_spellings_canonicalize_to_equal_intents() {
    let first = parse_manifest(
        "[rsolve]\nschema=1\n[r]\nversion='*'\n[dependencies]\ngitpkg={git='https://github.com/example/pkg.git',subdirectory='pkg/src'}\nlocalpkg={path='tree'}\n",
    )
    .unwrap()
    .compose_environment("default", ResolutionTarget::new(version("4.4.0")))
    .unwrap();
    let second = parse_manifest(
        "[rsolve]\nschema=1\n[r]\nversion='*'\n[dependencies]\ngitpkg={git='https://github.com/example/pkg.git',subdirectory='pkg/./src'}\nlocalpkg={path='work/../tree'}\n",
    )
    .unwrap()
    .compose_environment("default", ResolutionTarget::new(version("4.4.0")))
    .unwrap();
    assert_eq!(first.roots, second.roots);
    assert_eq!(
        first.resolution_intent_digest().unwrap(),
        second.resolution_intent_digest().unwrap()
    );
    let leading = parse_manifest(
        "[rsolve]\nschema=1\n[r]\nversion='*'\n[dependencies]\nfoo={path='../foo'}\n",
    )
    .unwrap()
    .compose_environment("default", ResolutionTarget::new(version("4.4.0")))
    .unwrap();
    assert!(
        matches!(&leading.roots[0].source, ManifestSource::Path { path, .. } if path == "../foo")
    );
    assert!(
        parse_manifest(
            "[rsolve]\nschema=1\n[r]\nversion='*'\n[dependencies]\nfoo={path='tree/..'}\n"
        )
        .is_err()
    );
}

#[test]
fn zero_and_equivalent_constraints_have_canonical_digests() {
    let zero = |constraint: &str| {
        parse_manifest(&format!(
            "[rsolve]\nschema=1\n[r]\nversion='*'\n[dependencies]\nfoo='{constraint}'\n"
        ))
        .unwrap()
        .compose_environment("default", ResolutionTarget::new(version("4.4.0")))
        .unwrap()
        .resolution_intent_digest()
        .unwrap()
    };
    assert_eq!(zero("=0.0"), zero("=0.0.0"));
}

#[test]
fn group_reference_order_does_not_affect_canonical_composition() {
    let manifest = |order: &str| {
        parse_manifest(&format!(
            "[rsolve]\nschema=1\n[r]\nversion='*'\n[[repositories]]\nid='main'\nurl='https://example.org'\nregistry='cran'\n[groups.a.dependencies]\nfoo={{version='>= 1.0'}}\n[groups.b.dependencies]\nfoo={{version='< 2.0',repository='main',include-suggests=true}}\n[environments]\ndev=[{order}]\n"
        ))
        .unwrap()
        .compose_environment("dev", ResolutionTarget::new(version("4.4.0")))
        .unwrap()
    };
    let first = manifest("'a','b'");
    let second = manifest("'b','a'");
    assert_eq!(first.roots, second.roots);
    assert_eq!(
        first.clone().into_resolution_request().unwrap().roots,
        second.clone().into_resolution_request().unwrap().roots
    );
    assert_eq!(
        first.resolution_intent_digest().unwrap(),
        second.resolution_intent_digest().unwrap()
    );
}

#[test]
fn resolution_intent_digest_tracks_selected_inputs_only() {
    let baseline = "[rsolve]\nschema=1\n[r]\nversion='>= 4.0, < 5.0'\n[resolution]\npublished-before='2026-08-01'\n[[repositories]]\nid='one'\nurl='https://one.example'\nregistry='cran'\n[[repositories]]\nid='two'\nurl='https://two.example'\nregistry='cran'\n[dependencies]\nfoo={version='>= 1.0',git='https://github.com/example/foo.git',branch='main',include-suggests=true}\n[groups.unselected.dependencies]\nbar='*'\n[environments]\ndev=['unselected']\n";
    let target = ResolutionTarget::new(version("4.4.0"));
    let baseline_document = parse_manifest(baseline).unwrap();
    let baseline_environment = baseline_document
        .compose_environment_with_locked("default", target.clone(), LockedIdentities::new())
        .unwrap();
    let baseline_digest = baseline_environment.resolution_intent_digest().unwrap();

    let changed = [
        baseline.replace(
            "[[repositories]]\nid='one'\nurl='https://one.example'\nregistry='cran'\n[[repositories]]\nid='two'\nurl='https://two.example'\nregistry='cran'",
            "[[repositories]]\nid='two'\nurl='https://two.example'\nregistry='cran'\n[[repositories]]\nid='one'\nurl='https://one.example'\nregistry='cran'",
        ),
        baseline.replace("url='https://one.example'", "url='https://changed.example'"),
        baseline.replace("version='>= 1.0'", "version='>= 2.0'"),
        baseline.replace("branch='main'", "tag='v1'"),
        baseline.replace("include-suggests=true", "include-suggests=false"),
        baseline.replace("published-before='2026-08-01'", "published-before='2026-09-01'"),
        baseline.replace("version='>= 4.0, < 5.0'", "version='>= 4.1, < 5.0'"),
    ];
    for input in changed {
        let digest = parse_manifest(&input)
            .unwrap()
            .compose_environment("default", target.clone())
            .unwrap()
            .resolution_intent_digest()
            .unwrap();
        assert_ne!(baseline_digest, digest);
    }

    let unselected_changed = baseline.replace("dev=['unselected']", "dev=[]");
    let digest = parse_manifest(&unselected_changed)
        .unwrap()
        .compose_environment("default", target.clone())
        .unwrap()
        .resolution_intent_digest()
        .unwrap();
    assert_eq!(baseline_digest, digest);

    let identity = ReleaseIdentity::new(
        package("foo"),
        Provenance::RegistryRelease {
            namespace: PackageNamespace::new("cran").unwrap(),
            version: version("1.0.0"),
        },
    );
    let key = SolverKey::InstalledName(package("foo"));
    let mut locked = LockedIdentities::new();
    locked.insert(key, identity);
    let compatible_target = ResolutionTarget::new(version("4.3.0"));
    let digest = parse_manifest(baseline)
        .unwrap()
        .compose_environment_with_locked("default", compatible_target, locked)
        .unwrap()
        .resolution_intent_digest()
        .unwrap();
    assert_eq!(baseline_digest, digest);
}
