use super::*;
use rsolve_core::{
    PackageName, PackageNamespace, Provenance, RelationOp, ReleaseIdentity, RepositoryId,
    SolverKey, VersionClause,
};

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
