use core::fmt::Write;

struct QualityGate {
    id: &'static str,
    command: &'static str,
    purpose: &'static str,
}

const QUALITY_GATES: &[QualityGate] = &[
    QualityGate {
        id: "PRELAB-TRACEPACK",
        command: "cargo run --quiet --example krn_prelab_trace_pack | diff -u docs/prelab_apdu_trace_pack.jsonl -",
        purpose: "regenerate and compare the masked pre-lab APDU trace fixture",
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
        command: "cargo clippy --all-targets --all-features",
        purpose: "run the repository static-analysis lint gate",
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
    out.push_str("]}\n");
    out
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
