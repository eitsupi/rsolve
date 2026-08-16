use std::{collections::BTreeMap, env, fs, path::PathBuf, process::Command, time::SystemTime};

use rsolve_provider::cran::DcfDocument;

fn external_packages_path() -> PathBuf {
    let root = env::var_os("RSOLVE_CRAN_CORPUS")
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| {
            panic!(
                "RSOLVE_CRAN_CORPUS is required; provide a repository root containing src/contrib/PACKAGES"
            )
        });
    let root = PathBuf::from(root);
    assert!(
        root.is_dir(),
        "RSOLVE_CRAN_CORPUS is not a directory: {}",
        root.display()
    );
    let path = root.join("src/contrib/PACKAGES");
    assert!(
        path.is_file(),
        "external corpus is missing {}",
        path.display()
    );
    let size = fs::metadata(&path)
        .unwrap_or_else(|error| panic!("cannot stat {}: {error}", path.display()))
        .len();
    assert!(
        size > 0,
        "external corpus file is empty: {}",
        path.display()
    );
    path
}

fn rust_records(document: &DcfDocument) -> Vec<BTreeMap<String, String>> {
    document
        .records()
        .iter()
        .map(|record| {
            record
                .fields()
                .iter()
                .map(|field| (field.name().to_owned(), field.value().to_owned()))
                .collect()
        })
        .collect()
}

fn decode_hex(value: &str) -> String {
    assert!(
        value.len().is_multiple_of(2),
        "odd-length hex value: {value}"
    );
    let bytes = (0..value.len())
        .step_by(2)
        .map(|offset| {
            u8::from_str_radix(&value[offset..offset + 2], 16)
                .unwrap_or_else(|error| panic!("invalid oracle hex at {offset}: {error}"))
        })
        .collect::<Vec<_>>();
    String::from_utf8(bytes).expect("oracle emitted invalid UTF-8")
}

fn oracle_records(path: &PathBuf) -> Vec<BTreeMap<String, String>> {
    let stamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_nanos();
    let directory = env::temp_dir().join(format!(
        "rsolve-provider-dcf-oracle-{}-{stamp}",
        std::process::id()
    ));
    fs::create_dir_all(&directory).expect("create oracle temporary directory");
    let output = directory.join("oracle.tsv");
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/support/corpus_oracle.R");
    let result = Command::new("Rscript")
        .arg(script)
        .arg(path)
        .arg(&output)
        .output()
        .expect("run R corpus oracle");
    assert!(
        result.status.success(),
        "R corpus oracle failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );

    let mut records = Vec::new();
    for (line_number, line) in fs::read_to_string(&output)
        .expect("read R corpus oracle output")
        .lines()
        .enumerate()
    {
        let columns = line.split('\t').collect::<Vec<_>>();
        match columns.as_slice() {
            ["records", count] => {
                assert!(records.is_empty(), "records header must be first");
                let count = count
                    .parse::<usize>()
                    .unwrap_or_else(|error| panic!("invalid records count: {error}"));
                records.resize_with(count, BTreeMap::new);
            }
            ["field", row, name, value] => {
                let row = row
                    .parse::<usize>()
                    .unwrap_or_else(|error| panic!("invalid row at line {line_number}: {error}"));
                assert!(row > 0 && row <= records.len(), "oracle row out of range");
                let name = decode_hex(name);
                let value = decode_hex(value);
                assert!(
                    records[row - 1].insert(name.clone(), value).is_none(),
                    "oracle emitted duplicate field {name}"
                );
            }
            _ => panic!("malformed oracle output at line {line_number}: {line}"),
        }
    }
    let _ = fs::remove_dir_all(directory);
    records
}

#[test]
#[ignore = "requires an external CRAN-like repository corpus and R 4.6.1"]
fn dcf_matches_r_read_dcf_on_external_corpus() {
    let path = external_packages_path();
    let bytes = fs::read(&path).expect("read external PACKAGES corpus");
    let rust = DcfDocument::parse(&bytes).expect("Rust DCF parser accepts external corpus");
    let oracle = oracle_records(&path);
    assert_eq!(rust_records(&rust), oracle);
}
