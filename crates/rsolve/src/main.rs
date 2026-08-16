use clap::Parser;

fn main() {
    let command = rsolve::cli::CommandLine::parse();
    match rsolve::cli::run(command) {
        Ok(result) => {
            for warning in result.warnings {
                eprintln!("warning: {warning}");
            }
            eprintln!("{}", result.summary);
        }
        Err(error) => {
            eprintln!("rsolve: {error}");
            std::process::exit(error.exit_code());
        }
    }
}
