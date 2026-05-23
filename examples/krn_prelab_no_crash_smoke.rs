use hyperion_emv::quality::prelab_no_crash_smoke_json;

fn main() -> hyperion_emv::KernelResult<()> {
    print!("{}", prelab_no_crash_smoke_json()?);
    Ok(())
}
