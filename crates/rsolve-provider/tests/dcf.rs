use rsolve_provider::cran::{DcfDocument, DcfError};

const SYNTHETIC_PACKAGES: &[u8] = include_bytes!("fixtures/cran-2026-08-08/synthetic-PACKAGES");
const SYNTHETIC_DESCRIPTION: &[u8] =
    include_bytes!("fixtures/cran-2026-08-08/synthetic-DESCRIPTION");

#[test]
fn reads_synthetic_packages_and_preserves_record_values() {
    let document = DcfDocument::parse(SYNTHETIC_PACKAGES).unwrap();
    assert_eq!(document.len(), 4);

    let expected = [
        ("rsolvefixture.core", "0.1.0", "2026-06-24 19:14:59 UTC"),
        ("rsolvefixture.folded", "0.2.0", "2026-06-25 19:14:59 UTC"),
        ("rsolvefixture.rare", "1.0.0", "2026-06-26 19:14:59 UTC"),
        ("rsolvefixture.plain", "3.0.0", "2026-06-27 19:14:59 UTC"),
    ];
    for (record, (package, version, published)) in document.records().iter().zip(expected) {
        assert_eq!(record.field("package").unwrap().value(), package);
        assert_eq!(record.field("Version").unwrap().value(), version);
        assert_eq!(record.field("Published").unwrap().value(), published);
    }

    let core = &document.records()[0];
    for field in ["Depends", "Imports", "LinkingTo", "Suggests", "Enhances"] {
        assert!(
            core.field(field).is_some(),
            "missing dependency field {field}"
        );
    }
    assert_eq!(core.field("Priority").unwrap().value(), "fixture-primary");
    assert_eq!(core.field("Repository").unwrap().value(), "synthetic/core");
    assert!(
        core.field("License")
            .unwrap()
            .value()
            .starts_with("RSOLVE Fictional")
    );

    let folded = document.records()[1].field("Suggests").unwrap().value();
    assert_eq!(folded.lines().count(), 25);
    assert_eq!(folded.matches('\n').count(), 24);
    assert!(folded.contains("rsolvefixture.suggest.24"));
    assert!(
        document.records()[1]
            .field("Description")
            .unwrap()
            .value()
            .contains("日本語の説明 – café")
    );

    let rare = &document.records()[2];
    assert_eq!(rare.field("OS_type").unwrap().value(), "fixture-windows");
    assert_eq!(
        rare.field("Archs").unwrap().value(),
        "fixture-riscv, fixture-wasm"
    );
    assert_eq!(rare.field("License_restricts_use").unwrap().value(), "yes");
}

#[test]
fn parses_the_generated_single_description_record() {
    let document = DcfDocument::parse(SYNTHETIC_DESCRIPTION).unwrap();
    assert_eq!(document.len(), 1);
    assert_eq!(
        document.records()[0].field("Package").unwrap().value(),
        "rsolvefixture.description"
    );
    assert!(
        document.records()[0]
            .field("Description")
            .unwrap()
            .value()
            .contains("日本語とcafé")
    );
}

#[test]
fn preserves_unknown_fields_order_and_original_spelling() {
    // This fixture exercises unknown provider fields, spelling, order, and lookup.
    let document =
        DcfDocument::parse_str("Package: demo\nSHA256: abc\ncontains: binary\nPublished: \n\n")
            .unwrap();
    let record = &document.records()[0];
    assert_eq!(
        record
            .fields()
            .iter()
            .map(|field| field.name())
            .collect::<Vec<_>>(),
        ["Package", "SHA256", "contains", "Published"]
    );
    assert_eq!(record.field("sha256").unwrap().value(), "abc");
    assert_eq!(record.field("CONTAINS").unwrap().value(), "binary");
}

#[test]
fn distinguishes_absent_and_empty_fields() {
    // This fixture exercises the distinction between a missing field and an empty one.
    let document = DcfDocument::parse_str("Package: demo\nDescription:\n\n").unwrap();
    let record = &document.records()[0];
    assert!(record.field("Imports").is_none());
    assert_eq!(record.field("Description").unwrap().value(), "");
}

#[test]
fn parses_a_single_description_record_and_utf8() {
    let document = DcfDocument::parse(SYNTHETIC_DESCRIPTION).unwrap();
    assert_eq!(document.len(), 1);
    assert_eq!(
        document.records()[0].field("PACKAGE").unwrap().value(),
        "rsolvefixture.description"
    );
    assert!(
        document.records()[0]
            .field("description")
            .unwrap()
            .value()
            .contains("日本語とcafé")
    );
}

#[test]
fn exercises_rare_field_shapes_in_the_generated_fixture() {
    let document = DcfDocument::parse(SYNTHETIC_PACKAGES).unwrap();
    let record = &document.records()[2];
    assert_eq!(
        record.field("repository").unwrap().value(),
        "synthetic/rare"
    );
    assert_eq!(record.field("os_type").unwrap().value(), "fixture-windows");
    assert_eq!(record.field("license_is_foss").unwrap().value(), "no");
}

#[test]
fn accepts_crlf_and_removes_only_line_terminator_cr_bytes() {
    // This fixture pins CRLF support and line-ending-only CR removal.
    let document =
        DcfDocument::parse(b"Package: demo\r\nDescription: first\r\n second\r\n\r\n").unwrap();
    assert_eq!(
        document.records()[0].field("Description").unwrap().value(),
        "first\nsecond"
    );
}

#[test]
fn malformed_inputs_return_typed_errors_without_panicking() {
    // These fixtures exercise every required malformed-input error category.
    enum ExpectedError {
        Continuation,
        MissingColon,
        EmptyFieldName,
    }
    let malformed = [
        (
            b" continuation\n".as_slice(),
            "continuation",
            ExpectedError::Continuation,
        ),
        (
            b"Package demo\n".as_slice(),
            "missing colon",
            ExpectedError::MissingColon,
        ),
        (
            b": value\n".as_slice(),
            "empty field",
            ExpectedError::EmptyFieldName,
        ),
    ];
    for (input, label, expected) in malformed {
        let result = std::panic::catch_unwind(|| DcfDocument::parse(input));
        assert!(result.is_ok(), "{label} input panicked");
        let result = result.unwrap();
        assert!(result.is_err(), "{label} input was accepted");
        let error = result.as_ref().unwrap_err();
        let matches_expected = matches!(
            (expected, error),
            (
                ExpectedError::Continuation,
                DcfError::ContinuationBeforeField { .. }
            ) | (ExpectedError::MissingColon, DcfError::MissingColon { .. })
                | (
                    ExpectedError::EmptyFieldName,
                    DcfError::EmptyFieldName { .. }
                )
        );
        assert!(matches_expected, "{label} got wrong error");
    }

    let invalid_utf8 = std::panic::catch_unwind(|| DcfDocument::parse(b"Package: \xff\n"));
    assert!(invalid_utf8.is_ok());
    assert!(matches!(
        invalid_utf8.unwrap(),
        Err(DcfError::InvalidUtf8 { .. })
    ));
}

#[test]
fn accepts_empty_and_eof_terminated_documents_like_r() {
    assert_eq!(DcfDocument::parse(b"").unwrap().len(), 0);
    assert_eq!(DcfDocument::parse(b"\n").unwrap().len(), 0);
    assert_eq!(DcfDocument::parse(b"Package: one").unwrap().len(), 1);
    assert_eq!(
        DcfDocument::parse(b"Package: one\n\nPackage: two")
            .unwrap()
            .len(),
        2
    );
    assert_eq!(DcfDocument::parse(b"Package: one\n\n\n").unwrap().len(), 1);
}

#[test]
fn rejects_bare_carriage_return_line_endings() {
    // This fixture pins the deliberate rejection of bare carriage returns.
    assert!(matches!(
        DcfDocument::parse(b"Package: demo\r"),
        Err(DcfError::InvalidLineEnding { .. })
    ));
    assert!(DcfDocument::parse(b"Package: demo\r\nVersion: 1\r\n\r\n").is_ok());
}
