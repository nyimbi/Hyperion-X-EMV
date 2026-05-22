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
        PrelabTraceCase {
            case_id: "prelab.masking.generate-ac",
            script: generate_ac_masking_script()?,
            expected_step_count: 3,
            expected_fsm_events: &["AidSelected", "RecordRead", "GacArqc"],
            expected_fsm_actions: &[
                "SelectNextAid",
                "ReadRecords",
                "RequestFirstGenerateAc",
                "BuildHostRequest",
            ],
            expected_status_actions: &[],
            expected_terminal_outcome: "online-authorization-request",
            masking_assertions: &[
                "full-apdu-disabled",
                "pan-last-four-only",
                "transaction-cryptogram-suppressed",
            ],
        },
    )?;
    append_case(
        &mut out,
        PrelabTraceCase {
            case_id: "prelab.masking.issuer-auth-script",
            script: issuer_auth_script_masking_script()?,
            expected_step_count: 2,
            expected_fsm_events: &["IssuerAuthenticationSuccess", "ScriptNonCriticalFailure"],
            expected_fsm_actions: &[
                "ProcessArpc",
                "ProcessIssuerScripts",
                "RequestFinalGenerateAc",
            ],
            expected_status_actions: &[],
            expected_terminal_outcome: "continue-to-final-generate-ac",
            masking_assertions: &[
                "full-apdu-disabled",
                "issuer-authentication-data-suppressed",
                "issuer-script-command-data-suppressed",
            ],
        },
    )?;
    append_case(
        &mut out,
        PrelabTraceCase {
            case_id: "prelab.masking.track2-record",
            script: track2_record_masking_script()?,
            expected_step_count: 1,
            expected_fsm_events: &["RecordRead"],
            expected_fsm_actions: &["ReadRecords"],
            expected_status_actions: &[],
            expected_terminal_outcome: "record-data-collected",
            masking_assertions: &["full-apdu-disabled", "track2-suppressed"],
        },
    )?;
    append_case(
        &mut out,
        PrelabTraceCase {
            case_id: "prelab.masking.follow-up-status",
            script: followup_status_masking_script()?,
            expected_step_count: 4,
            expected_fsm_events: &["GpoTemplate77", "GacArqc"],
            expected_fsm_actions: &["BuildGpo", "RequestFirstGenerateAc", "BuildHostRequest"],
            expected_status_actions: &["GetResponse61xx", "RetryWithCorrectLe6cxx"],
            expected_terminal_outcome: "first-generate-ac-complete",
            masking_assertions: &[
                "full-apdu-disabled",
                "follow-up-response-tag-masked",
                "transaction-cryptogram-suppressed",
            ],
        },
    )?;
    Ok(out)
}

struct PrelabTraceCase {
    case_id: &'static str,
    script: ReplayScript,
    expected_step_count: usize,
    expected_fsm_events: &'static [&'static str],
    expected_fsm_actions: &'static [&'static str],
    expected_status_actions: &'static [&'static str],
    expected_terminal_outcome: &'static str,
    masking_assertions: &'static [&'static str],
}

fn append_case(out: &mut String, case: PrelabTraceCase) -> KernelResult<()> {
    out.push_str(
        "{\"type\":\"trace-pack-metadata\",\
         \"trace_pack_id\":\"PRELAB-MASKED-APDU-001\",\
         \"scope\":\"repository-controlled pre-lab fixture\",\
         \"case_id\":\"",
    );
    out.push_str(case.case_id);
    out.push_str("\",\"does_not_close\":\"CERT-OPEN-012\"}\n");
    append_scenario(out, &case);
    let identity = TraceIdentity::current(KRN_ABI_VERSION, 2);
    out.push_str(
        &case
            .script
            .masked_jsonl_with_trace_identity(LogPolicy::production(), &identity)?,
    );
    Ok(())
}

fn append_scenario(out: &mut String, case: &PrelabTraceCase) {
    out.push_str("{\"type\":\"trace-scenario\",\"case_id\":\"");
    out.push_str(case.case_id);
    out.push_str("\",\"expected_step_count\":");
    out.push_str(&case.expected_step_count.to_string());
    out.push_str(",\"expected_fsm_events\":");
    append_string_array(out, case.expected_fsm_events);
    out.push_str(",\"expected_fsm_actions\":");
    append_string_array(out, case.expected_fsm_actions);
    out.push_str(",\"expected_status_actions\":");
    append_string_array(out, case.expected_status_actions);
    out.push_str(",\"expected_terminal_outcome\":\"");
    out.push_str(case.expected_terminal_outcome);
    out.push_str("\",\"masking_assertions\":");
    append_string_array(out, case.masking_assertions);
    out.push_str("}\n");
}

fn append_string_array(out: &mut String, values: &[&str]) {
    out.push('[');
    for (idx, value) in values.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        out.push('"');
        out.push_str(value);
        out.push('"');
    }
    out.push(']');
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

fn track2_record_masking_script() -> KernelResult<ReplayScript> {
    let track2_record = ReplayExchange::new(
        &decode_hex("00B2021400")?,
        &decode_hex("7010570E123456789012D25122012345678F")?,
        [0x90, 0x00],
        ApduTraceContext::Generic,
    )?;
    ReplayScript::new(vec![track2_record])
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
