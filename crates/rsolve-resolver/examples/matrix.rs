#[path = "../tests/support/matrix_scenario.rs"]
mod matrix_scenario;

use matrix_scenario::MatrixCatalog;
use rsolve_core::PackageName;

fn main() {
    let catalog = MatrixCatalog::new();
    let matrix = PackageName::new("Matrix").unwrap();
    for r_version in std::env::args().nth(1).map_or_else(
        || vec!["4.3.3".to_owned(), "4.4.0".to_owned()],
        |version| vec![version],
    ) {
        let resolution = catalog
            .resolver()
            .resolve(catalog.request(&r_version))
            .expect("matrix example must resolve");
        println!(
            "R {r_version}: Matrix {}",
            resolution.selected(&matrix).unwrap().version()
        );
    }
}
