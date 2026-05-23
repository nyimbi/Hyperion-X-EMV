use hyperion_emv::quality::prelab_fuzz_seed_corpus_json;

fn main() -> hyperion_emv::KernelResult<()> {
    print!("{}", prelab_fuzz_seed_corpus_json()?);
    Ok(())
}
