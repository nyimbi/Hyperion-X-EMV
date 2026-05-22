use hyperion_emv::ffi::KRN_ABI_VERSION;
use hyperion_emv::quality::prelab_quality_gates_json;

fn main() {
    print!("{}", prelab_quality_gates_json(KRN_ABI_VERSION));
}
