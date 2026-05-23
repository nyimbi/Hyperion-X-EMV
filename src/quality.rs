use crate::aip::ApplicationInterchangeProfile;
use crate::apdu::{self, CdaRequestControl, CryptogramRequest};
use crate::cvm::CvmResults;
use crate::dol::{self, DataStore, DolEntry};
use crate::error::{KernelError, KernelResult};
use crate::numeric;
use crate::record;
use crate::restrictions::{ApplicationUsageControl, EmvDate};
use crate::terminal::TerminalType;
use crate::transaction::{CurrencyExponent, TransactionType};
use crate::{gac, issuer, tlv, trace};
use core::fmt::Write;

struct QualityGate {
    id: &'static str,
    command: &'static str,
    purpose: &'static str,
}

struct FreezeHashRequirement {
    id: &'static str,
    artifact: &'static str,
    evidence_source: &'static str,
}

const QUALITY_GATES: &[QualityGate] = &[
    QualityGate {
        id: "PRELAB-CONFORMANCE",
        command: "cargo run --quiet --example krn_abi_conformance_statement | diff -u docs/abi_conformance_statement.json -",
        purpose: "regenerate and compare the ABI conformance statement artifact",
    },
    QualityGate {
        id: "PRELAB-TRACEPACK",
        command: "cargo run --quiet --example krn_prelab_trace_pack | diff -u docs/prelab_apdu_trace_pack.jsonl -",
        purpose: "regenerate and compare the masked pre-lab APDU trace fixture",
    },
    QualityGate {
        id: "PRELAB-SCHEME-DICTIONARY",
        command: "cargo run --quiet --example krn_scheme_profile_dictionary | diff -u docs/scheme_profile_dictionary.md -",
        purpose: "regenerate and compare the human-readable scheme profile dictionary",
    },
    QualityGate {
        id: "PRELAB-QUALITY-GATES",
        command: "cargo run --quiet --example krn_prelab_quality_gates | diff -u docs/prelab_quality_gates.json -",
        purpose: "regenerate and compare this pre-lab quality gate manifest",
    },
    QualityGate {
        id: "PRELAB-NO-CRASH-SMOKE",
        command: "cargo run --quiet --example krn_prelab_no_crash_smoke | diff -u docs/prelab_no_crash_smoke.json -",
        purpose: "regenerate and compare the deterministic parser/APDU no-crash smoke artifact",
    },
    QualityGate {
        id: "PRELAB-BUILD-PROVENANCE",
        command: "cargo run --quiet --example krn_build_manifest -- src Cargo.lock Cargo.toml docs/spec.md docs/lab_submission_manifest.md docs/requirements_traceability.csv docs/requirements-traceability-matrix.csv docs/scheme_profiles.cert.json docs/scheme_profile_dictionary.md docs/oda_test_vectors.json docs/tlv_catalogue.csv docs/state_machine.csv docs/bitmap_catalogue.csv docs/performance_profile.csv docs/abi_conformance_statement.json docs/prelab_apdu_trace_pack.jsonl docs/prelab_quality_gates.json docs/prelab_no_crash_smoke.json docs/certification_open_issues.md docs/standards_watch.md docs/open_source.md examples/krn_build_manifest.rs examples/krn_abi_conformance_statement.rs examples/krn_cabi_script_adapter.rs examples/krn_scheme_profile_dictionary.rs examples/krn_prelab_trace_pack.rs examples/krn_prelab_quality_gates.rs examples/krn_prelab_no_crash_smoke.rs examples/krn_emv_decode.rs",
        purpose: "emit canonical build provenance for source, controlled annexes, and evidence generators",
    },
    QualityGate {
        id: "PRELAB-UNIT-INTEGRATION",
        command: "cargo test",
        purpose: "run repository unit and integration tests",
    },
    QualityGate {
        id: "PRELAB-EXAMPLES",
        command: "cargo test --examples",
        purpose: "compile and execute example evidence generators",
    },
    QualityGate {
        id: "PRELAB-FORMAT",
        command: "cargo fmt --check",
        purpose: "verify Rust formatting is stable",
    },
    QualityGate {
        id: "PRELAB-STATIC",
        command: "cargo clippy --all-targets --all-features -- -D warnings",
        purpose: "run the repository static-analysis lint gate with warnings as failures",
    },
    QualityGate {
        id: "PRELAB-DIFF",
        command: "git diff --check",
        purpose: "reject whitespace errors in the working tree diff",
    },
];

const EXTERNAL_REPORTS_PENDING: &[&str] = &[
    "Unit coverage report >=95%",
    "Full EMV test-plan integration report",
    "Static-analysis report accepted for the submission context",
    "Fuzzing/no-crash report with tool versions and corpus",
];

const FREEZE_HASH_REQUIREMENTS: &[FreezeHashRequirement] = &[
    FreezeHashRequirement {
        id: "kernel_binary_hash",
        artifact: "submitted kernel binary",
        evidence_source: "release build pipeline artifact digest accepted for the lab submission",
    },
    FreezeHashRequirement {
        id: "config_bundle_hash",
        artifact: "signed runtime configuration bundle",
        evidence_source: "signed configuration package digest tied to the submitted binary",
    },
    FreezeHashRequirement {
        id: "capk_bundle_hash",
        artifact: "scheme/acquirer-approved CAPK bundle",
        evidence_source: "accepted CAPK package digest with signed provenance",
    },
    FreezeHashRequirement {
        id: "scheme_profile_hash",
        artifact: "scheme/acquirer-approved profile bundle",
        evidence_source: "accepted scheme profile package digest with profile authority evidence",
    },
    FreezeHashRequirement {
        id: "test_vector_hash",
        artifact: "lab-supplied ODA and APDU test-vector bundle",
        evidence_source: "recognized-lab vector and trace-pack digest",
    },
    FreezeHashRequirement {
        id: "traceability_matrix_hash",
        artifact: "final RTM and lab/tool crosswalk",
        evidence_source: "final RTM digest after lab test-case ID reconciliation",
    },
];

pub fn prelab_quality_gates_json(abi_version: u32) -> String {
    let mut out = String::new();
    out.push('{');
    push_json_str(&mut out, "type", "prelab-quality-gates");
    out.push(',');
    push_json_str(&mut out, "kernel_name", env!("CARGO_PKG_NAME"));
    out.push(',');
    push_json_str(&mut out, "kernel_version", env!("CARGO_PKG_VERSION"));
    out.push(',');
    push_json_number(&mut out, "abi_version", abi_version as u64);
    out.push(',');
    push_json_str(
        &mut out,
        "scope",
        "repository-controlled engineering gates only",
    );
    out.push_str(",\"does_not_close\":[");
    push_json_string(&mut out, "CERT-OPEN-009");
    out.push(',');
    push_json_string(&mut out, "CERT-OPEN-010");
    out.push(']');
    out.push_str(",\"commands\":[");
    for (idx, gate) in QUALITY_GATES.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        out.push('{');
        push_json_str(&mut out, "id", gate.id);
        out.push(',');
        push_json_str(&mut out, "command", gate.command);
        out.push(',');
        push_json_str(&mut out, "purpose", gate.purpose);
        out.push('}');
    }
    out.push_str("],\"external_reports_pending\":[");
    for (idx, report) in EXTERNAL_REPORTS_PENDING.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        push_json_string(&mut out, report);
    }
    out.push_str("],\"certification_freeze_hashes_required\":[");
    for (idx, requirement) in FREEZE_HASH_REQUIREMENTS.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        out.push('{');
        push_json_str(&mut out, "id", requirement.id);
        out.push(',');
        push_json_str(&mut out, "artifact", requirement.artifact);
        out.push(',');
        push_json_str(&mut out, "evidence_source", requirement.evidence_source);
        out.push(',');
        push_json_str(&mut out, "status", "pending external certification freeze");
        out.push('}');
    }
    out.push_str("]}\n");
    out
}

struct NoCrashSmokeCase {
    id: &'static str,
    surface: &'static str,
    expected: KernelError,
    run: fn() -> KernelResult<()>,
}

const NO_CRASH_SMOKE_CASES: &[NoCrashSmokeCase] = &[
    NoCrashSmokeCase {
        id: "TLV-VALID-RECORD-TEMPLATE",
        surface: "tlv::parse_many",
        expected: KernelError::Ok,
        run: smoke_valid_tlv_record_template,
    },
    NoCrashSmokeCase {
        id: "TLV-TRUNCATED-HIGH-TAG",
        surface: "tlv::parse_many",
        expected: KernelError::ParseError,
        run: smoke_truncated_tlv_high_tag,
    },
    NoCrashSmokeCase {
        id: "DOL-TRUNCATED-TAG",
        surface: "dol::parse_dol",
        expected: KernelError::ParseError,
        run: smoke_truncated_dol_tag,
    },
    NoCrashSmokeCase {
        id: "NUMERIC-NON-BCD-AMOUNT",
        surface: "numeric::decode_numeric_bcd_fixed",
        expected: KernelError::ParseError,
        run: smoke_non_bcd_numeric_amount,
    },
    NoCrashSmokeCase {
        id: "DATE-NONLEAP-FEBRUARY-29",
        surface: "restrictions::EmvDate::from_bcd",
        expected: KernelError::ParseError,
        run: smoke_nonleap_february_29_date,
    },
    NoCrashSmokeCase {
        id: "CURRENCY-EXPONENT-INVALID",
        surface: "transaction::CurrencyExponent::parse",
        expected: KernelError::InvalidArgument,
        run: smoke_invalid_currency_exponent,
    },
    NoCrashSmokeCase {
        id: "TRANSACTION-TYPE-VALID-CASHBACK",
        surface: "transaction::TransactionType::parse",
        expected: KernelError::Ok,
        run: smoke_valid_transaction_type,
    },
    NoCrashSmokeCase {
        id: "TERMINAL-TYPE-UNKNOWN",
        surface: "terminal::TerminalType::parse",
        expected: KernelError::InvalidArgument,
        run: smoke_unknown_terminal_type,
    },
    NoCrashSmokeCase {
        id: "AIP-SHORT",
        surface: "aip::ApplicationInterchangeProfile::parse",
        expected: KernelError::MissingMandatoryTag,
        run: smoke_short_aip,
    },
    NoCrashSmokeCase {
        id: "AUC-SHORT",
        surface: "restrictions::ApplicationUsageControl::parse",
        expected: KernelError::ParseError,
        run: smoke_short_application_usage_control,
    },
    NoCrashSmokeCase {
        id: "CVM-RESULTS-SHORT",
        surface: "cvm::CvmResults::parse",
        expected: KernelError::ParseError,
        run: smoke_short_cvm_results,
    },
    NoCrashSmokeCase {
        id: "TRACK2-VALID-SHAPE",
        surface: "record::summarize_track2_equivalent_data",
        expected: KernelError::Ok,
        run: smoke_valid_track2_shape,
    },
    NoCrashSmokeCase {
        id: "TRACK2-MISSING-SEPARATOR",
        surface: "record::summarize_track2_equivalent_data",
        expected: KernelError::ParseError,
        run: smoke_track2_missing_separator,
    },
    NoCrashSmokeCase {
        id: "APDU-OVERSIZE-GPO-PDOL",
        surface: "apdu::get_processing_options",
        expected: KernelError::LengthOverflow,
        run: smoke_oversize_gpo_pdol,
    },
    NoCrashSmokeCase {
        id: "APDU-GENERATE-AC-BAD-CDA-BITS",
        surface: "apdu::generate_ac",
        expected: KernelError::InvalidProfile,
        run: smoke_generate_ac_bad_cda_bits,
    },
    NoCrashSmokeCase {
        id: "ISSUER-SCRIPT-MALFORMED-COMMAND",
        surface: "issuer::parse_host_response",
        expected: KernelError::ParseError,
        run: smoke_malformed_issuer_script_command,
    },
    NoCrashSmokeCase {
        id: "GAC-MISSING-MANDATORY-TAGS",
        surface: "gac::parse_generate_ac_response",
        expected: KernelError::MissingMandatoryTag,
        run: smoke_gac_missing_mandatory_tags,
    },
    NoCrashSmokeCase {
        id: "REPLAY-STRUCTURALLY-INVALID-COMMAND",
        surface: "trace::ReplayExchange::new",
        expected: KernelError::ParseError,
        run: smoke_replay_invalid_command,
    },
];

pub fn prelab_no_crash_smoke_json() -> KernelResult<String> {
    let mut out = String::new();
    out.push('{');
    push_json_str(&mut out, "type", "prelab-no-crash-smoke");
    out.push(',');
    push_json_str(
        &mut out,
        "scope",
        "repository-controlled parser and APDU boundary smoke only",
    );
    out.push_str(",\"does_not_close\":[");
    push_json_string(&mut out, "CERT-OPEN-010");
    out.push(']');
    out.push(',');
    push_json_number(&mut out, "case_count", NO_CRASH_SMOKE_CASES.len() as u64);
    out.push_str(",\"cases\":[");
    for (idx, case) in NO_CRASH_SMOKE_CASES.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        let actual = match (case.run)() {
            Ok(()) => KernelError::Ok,
            Err(err) => err,
        };
        if actual != case.expected {
            return Err(KernelError::InternalError);
        }
        out.push('{');
        push_json_str(&mut out, "id", case.id);
        out.push(',');
        push_json_str(&mut out, "surface", case.surface);
        out.push(',');
        push_json_str(&mut out, "expected", case.expected.name());
        out.push(',');
        push_json_str(&mut out, "actual", actual.name());
        out.push('}');
    }
    out.push_str("]}\n");
    Ok(out)
}

fn smoke_valid_tlv_record_template() -> KernelResult<()> {
    tlv::parse_many(&[0x70, 0x03, 0x5a, 0x01, 0x12]).map(|_| ())
}

fn smoke_truncated_tlv_high_tag() -> KernelResult<()> {
    tlv::parse_many(&[0x9f]).map(|_| ())
}

fn smoke_truncated_dol_tag() -> KernelResult<()> {
    dol::parse_dol(&[0x9f]).map(|_| ())
}

fn smoke_non_bcd_numeric_amount() -> KernelResult<()> {
    numeric::decode_numeric_bcd_fixed(&[0x00, 0x00, 0x00, 0x0a, 0x00, 0x00]).map(|_| ())
}

fn smoke_nonleap_february_29_date() -> KernelResult<()> {
    EmvDate::from_bcd([0x25, 0x02, 0x29]).map(|_| ())
}

fn smoke_invalid_currency_exponent() -> KernelResult<()> {
    CurrencyExponent::parse(&[0x0a]).map(|_| ())
}

fn smoke_valid_transaction_type() -> KernelResult<()> {
    TransactionType::parse(&[0x09]).map(|_| ())
}

fn smoke_unknown_terminal_type() -> KernelResult<()> {
    TerminalType::parse(0x00).map(|_| ())
}

fn smoke_short_aip() -> KernelResult<()> {
    ApplicationInterchangeProfile::parse(&[0x80]).map(|_| ())
}

fn smoke_short_application_usage_control() -> KernelResult<()> {
    ApplicationUsageControl::parse(&[0xff]).map(|_| ())
}

fn smoke_short_cvm_results() -> KernelResult<()> {
    CvmResults::parse(&[0x01, 0x00]).map(|_| ())
}

fn smoke_valid_track2_shape() -> KernelResult<()> {
    record::summarize_track2_equivalent_data(&[
        0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0xd2, 0x51, 0x22, 0x01, 0x23, 0x45, 0x67, 0x8f,
    ])
    .map(|_| ())
}

fn smoke_track2_missing_separator() -> KernelResult<()> {
    record::summarize_track2_equivalent_data(&[0x12, 0x34, 0x56, 0x78]).map(|_| ())
}

fn smoke_oversize_gpo_pdol() -> KernelResult<()> {
    apdu::get_processing_options(
        &[DolEntry {
            tag: vec![0x9f, 0x37],
            length: apdu::MAX_GPO_PDOL_VALUE_LEN + 1,
        }],
        &DataStore::new(),
    )
    .map(|_| ())
}

fn smoke_generate_ac_bad_cda_bits() -> KernelResult<()> {
    apdu::generate_ac(
        CryptogramRequest::Arqc,
        &[0x00],
        CdaRequestControl::P1LowBits(0xc0),
    )
    .map(|_| ())
}

fn smoke_malformed_issuer_script_command() -> KernelResult<()> {
    issuer::parse_host_response(&[0x8a, 0x02, b'0', b'0', 0x71, 0x04, 0x86, 0x02, 0x00, 0xda])
        .map(|_| ())
}

fn smoke_gac_missing_mandatory_tags() -> KernelResult<()> {
    gac::parse_generate_ac_response(&[0x77, 0x00]).map(|_| ())
}

fn smoke_replay_invalid_command() -> KernelResult<()> {
    trace::ReplayExchange::new(
        &[0x00, 0xa4],
        &[],
        [0x90, 0x00],
        trace::ApduTraceContext::Generic,
    )
    .map(|_| ())
}

fn push_json_number(out: &mut String, key: &str, value: u64) {
    push_json_key(out, key);
    let _ = write!(out, "{value}");
}

fn push_json_str(out: &mut String, key: &str, value: &str) {
    push_json_key(out, key);
    push_json_string(out, value);
}

fn push_json_key(out: &mut String, key: &str) {
    push_json_string(out, key);
    out.push(':');
}

fn push_json_string(out: &mut String, value: &str) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}
