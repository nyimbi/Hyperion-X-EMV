#[cfg(not(coverage))]
fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let mut stdout = std::io::stdout();
    let mut stderr = std::io::stderr();
    std::process::exit(hyperion_emv::cli::run_hyperion_cli(
        &args,
        &mut stdout,
        &mut stderr,
    ));
}

#[cfg(coverage)]
fn main() {}

#[cfg(all(test, coverage))]
mod tests {
    #[test]
    fn coverage_main_is_callable() {
        super::main();
    }
}
