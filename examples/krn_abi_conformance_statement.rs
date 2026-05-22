use hyperion_emv::conformance::baseline_conformance_statement;
use hyperion_emv::ffi::KRN_ABI_VERSION;

fn main() {
    println!(
        "{}",
        baseline_conformance_statement(KRN_ABI_VERSION).canonical_json()
    );
}
