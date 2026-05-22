use hyperion_emv::config::decode_hex;
use hyperion_emv::ffi::KRN_ABI_VERSION;
use hyperion_emv::trace::{
    ApduTraceContext, LogPolicy, ReplayExchange, ReplayScript, TraceIdentity,
};
use hyperion_emv::KernelResult;
use std::process;

fn main() {
    match prelab_trace_pack_jsonl() {
        Ok(jsonl) => print!("{jsonl}"),
        Err(err) => {
            eprintln!("failed to generate pre-lab trace pack: {}", err.name());
            process::exit(1);
        }
    }
}

fn prelab_trace_pack_jsonl() -> KernelResult<String> {
    let select = ReplayExchange::new(
        &decode_hex("00A4040007A000000003101000")?,
        &decode_hex("6F098407A0000000031010")?,
        [0x90, 0x00],
        ApduTraceContext::Generic,
    )?;
    let record = ReplayExchange::new(
        &decode_hex("00B2011400")?,
        &decode_hex("700A5A08123456789012345F")?,
        [0x90, 0x00],
        ApduTraceContext::Generic,
    )?;
    let first_gac = ReplayExchange::new(
        &decode_hex("80AE800000")?,
        &decode_hex("800B8000091112131415161718")?,
        [0x90, 0x00],
        ApduTraceContext::GenerateAcResponse,
    )?;
    let script = ReplayScript::new(vec![select, record, first_gac])?;
    let identity = TraceIdentity::current(KRN_ABI_VERSION, 2);
    script.masked_jsonl_with_trace_identity(LogPolicy::production(), &identity)
}
