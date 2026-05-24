use hyperion_emv::ffi::KRN_ABI_VERSION;
use hyperion_emv::trace_audit::{
    audit_trace_pack, trace_pack_audit_json, trace_pack_audit_markdown,
    trace_pack_is_prelab_reviewable, DEFAULT_PRELAB_TRACE_PACK_PATH,
};
use std::env;
use std::io;
use std::path::Path;
use std::process;

fn main() {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let result = match args.as_slice() {
        [] => emit_json(Path::new(DEFAULT_PRELAB_TRACE_PACK_PATH), Requirement::None),
        [flag, path] if flag == "--path" => emit_json(Path::new(path), Requirement::None),
        [flag, path, format] if flag == "--path" && format == "--markdown" => {
            emit_markdown(Path::new(path), Requirement::None)
        }
        [flag, path, requirement]
            if flag == "--path" && requirement == "--require-prelab-fixture" =>
        {
            emit_json(Path::new(path), Requirement::PrelabFixture)
        }
        _ => {
            eprintln!(
                "usage: cargo run --example krn_trace_pack_audit -- [--path <jsonl> [--markdown|--require-prelab-fixture]]"
            );
            process::exit(2);
        }
    };

    if let Err(err) = result {
        eprintln!("failed to audit trace pack: {err}");
        process::exit(1);
    }
}

#[derive(Clone, Copy)]
enum Requirement {
    None,
    PrelabFixture,
}

fn emit_json(path: &Path, requirement: Requirement) -> io::Result<()> {
    let audit = audit_trace_pack(path)?;
    print!("{}", trace_pack_audit_json(KRN_ABI_VERSION, &audit));
    enforce_requirement(&audit, requirement);
    Ok(())
}

fn emit_markdown(path: &Path, requirement: Requirement) -> io::Result<()> {
    let audit = audit_trace_pack(path)?;
    print!("{}", trace_pack_audit_markdown(KRN_ABI_VERSION, &audit));
    enforce_requirement(&audit, requirement);
    Ok(())
}

fn enforce_requirement(
    audit: &hyperion_emv::trace_audit::TracePackAudit,
    requirement: Requirement,
) {
    let accepted = match requirement {
        Requirement::None => true,
        Requirement::PrelabFixture => trace_pack_is_prelab_reviewable(audit),
    };
    if !accepted {
        eprintln!(
            "trace pack status `{}` does not satisfy requested requirement",
            audit.status
        );
        process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn cli_audit_accepts_reviewable_prelab_trace_pack() {
        let path = env::temp_dir().join(format!(
            "hyperion-trace-audit-cli-reviewable-{}",
            process::id()
        ));
        fs::write(&path, valid_trace_pack()).unwrap();

        let audit = audit_trace_pack(&path).unwrap();

        assert!(trace_pack_is_prelab_reviewable(&audit));
        assert!(trace_pack_audit_json(KRN_ABI_VERSION, &audit)
            .contains("\"status\":\"prelab_fixture_reviewable\""));

        fs::remove_file(&path).unwrap();
    }

    fn valid_trace_pack() -> String {
        concat!(
            "{\"type\":\"trace-pack-metadata\",\"trace_pack_id\":\"PRELAB-MASKED-APDU-001\",\"scope\":\"repository-controlled pre-lab fixture\",\"case_id\":\"prelab.cli\",\"does_not_close\":\"CERT-OPEN-012\"}\n",
            "{\"type\":\"trace-scenario\",\"case_id\":\"prelab.cli\",\"expected_step_count\":1,\"expected_fsm_events\":[\"GacArqc\"],\"expected_fsm_actions\":[\"BuildHostRequest\"],\"expected_status_actions\":[],\"expected_command_flow\":[\"generate-ac\"],\"expected_response_shapes\":[\"gac-template-77\"],\"expected_terminal_outcome\":\"online-authorization-request\",\"expected_tlv_stream_count\":0,\"masking_assertions\":[\"full-apdu-disabled\",\"transaction-cryptogram-suppressed\"]}\n",
            "{\"type\":\"trace-identity\",\"kernel_name\":\"hyperion-emv\",\"kernel_version\":\"0.1.0\",\"abi_version\":2,\"profile_version\":2,\"profile_sha256\":\"abcdef\",\"log_build_mode\":\"production\",\"support_authorization_verified\":false}\n",
            "{\"sequence\":0,\"direction\":\"command\",\"context\":\"generic\",\"cla\":\"80\",\"ins\":\"ae\",\"p1\":\"80\",\"p2\":\"00\",\"data\":{\"type\":\"suppressed\",\"reason\":\"full-apdu-disabled\"},\"fields\":[]}\n",
            "{\"sequence\":1,\"direction\":\"response\",\"context\":\"generate-ac-response\",\"sw\":\"9000\",\"data\":{\"type\":\"suppressed\",\"reason\":\"tag-masked\"},\"fields\":[{\"tag\":\"9f26\",\"value\":{\"type\":\"suppressed\",\"reason\":\"transaction-cryptogram\"}}]}\n",
        )
        .to_string()
    }
}
