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
    let mut out = String::new();
    append_case(
        &mut out,
        "prelab.masking.generate-ac",
        generate_ac_masking_script()?,
    )?;
    append_case(
        &mut out,
        "prelab.masking.issuer-auth-script",
        issuer_auth_script_masking_script()?,
    )?;
    append_case(
        &mut out,
        "prelab.masking.follow-up-status",
        followup_status_masking_script()?,
    )?;
    Ok(out)
}

fn append_case(out: &mut String, case_id: &str, script: ReplayScript) -> KernelResult<()> {
    out.push_str(
        "{\"type\":\"trace-pack-metadata\",\
         \"trace_pack_id\":\"PRELAB-MASKED-APDU-001\",\
         \"scope\":\"repository-controlled pre-lab fixture\",\
         \"case_id\":\"",
    );
    out.push_str(case_id);
    out.push_str("\",\"does_not_close\":\"CERT-OPEN-012\"}\n");
    let identity = TraceIdentity::current(KRN_ABI_VERSION, 2);
    out.push_str(&script.masked_jsonl_with_trace_identity(LogPolicy::production(), &identity)?);
    Ok(())
}

fn generate_ac_masking_script() -> KernelResult<ReplayScript> {
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
        &decode_hex("80AE80000301020300")?,
        &decode_hex("800B8000091112131415161718")?,
        [0x90, 0x00],
        ApduTraceContext::GenerateAcResponse,
    )?;
    ReplayScript::new(vec![select, record, first_gac])
}

fn issuer_auth_script_masking_script() -> KernelResult<ReplayScript> {
    let external_authenticate = ReplayExchange::new(
        &decode_hex("00820000081122334455667788")?,
        &[],
        [0x90, 0x00],
        ApduTraceContext::Generic,
    )?;
    let issuer_script_warning = ReplayExchange::new(
        &decode_hex("80DA9F36020009")?,
        &[],
        [0x63, 0x00],
        ApduTraceContext::Generic,
    )?;
    ReplayScript::new(vec![external_authenticate, issuer_script_warning])
}

fn followup_status_masking_script() -> KernelResult<ReplayScript> {
    let gpo_requires_get_response = ReplayExchange::new(
        &decode_hex("80A8000002830000")?,
        &[],
        [0x61, 0x0c],
        ApduTraceContext::Generic,
    )?;
    let get_response = ReplayExchange::new(
        &decode_hex("00C000000C")?,
        &decode_hex("770A82028000940410010100")?,
        [0x90, 0x00],
        ApduTraceContext::Generic,
    )?;
    let generate_ac_retry_required = ReplayExchange::new(
        &decode_hex("80AE80000301020300")?,
        &[],
        [0x6c, 0x1c],
        ApduTraceContext::Generic,
    )?;
    let generate_ac_retry = ReplayExchange::new(
        &decode_hex("80AE8000030102031C")?,
        &decode_hex("800B8000091112131415161718")?,
        [0x90, 0x00],
        ApduTraceContext::GenerateAcResponse,
    )?;
    ReplayScript::new(vec![
        gpo_requires_get_response,
        get_response,
        generate_ac_retry_required,
        generate_ac_retry,
    ])
}
