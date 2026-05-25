//! Static audit for the signed-profile data boundary.
//!
//! Hyperion's production kernel code may know how to parse and evaluate
//! profiles, but scheme-specific AIDs/RIDs, CAPKs, limits, TAC/IAC values, CDA
//! controls, and certification vectors must live in signed profile bundles or
//! test fixtures. This module provides a deterministic pre-lab audit for that
//! boundary over production Rust source files.

use crate::error::{KernelError, KernelResult};
use core::fmt::Write;

pub const MAX_BOUNDARY_AUDIT_FILES: usize = 128;
pub const MAX_BOUNDARY_AUDIT_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_BOUNDARY_FINDINGS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BoundaryAuditInput<'a> {
    pub path: &'a str,
    pub contents: &'a str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForbiddenProductionLiteral {
    pub literal: String,
    pub classification: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundaryFinding {
    pub path: String,
    pub line: usize,
    pub literal: String,
    pub classification: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundaryAudit {
    pub checked_files: usize,
    pub checked_bytes: usize,
    pub findings: Vec<BoundaryFinding>,
}

impl BoundaryAudit {
    pub fn passed(&self) -> bool {
        self.findings.is_empty()
    }

    pub fn canonical_json(&self) -> String {
        let mut out = String::new();
        out.push('{');
        push_json_str(&mut out, "type", "variable-data-boundary-audit");
        out.push(',');
        push_json_str(&mut out, "kernel_name", env!("CARGO_PKG_NAME"));
        out.push(',');
        push_json_str(&mut out, "kernel_version", env!("CARGO_PKG_VERSION"));
        out.push(',');
        push_json_str(
            &mut out,
            "scope",
            "production Rust source only; test fixtures and signed profile bundles remain allowed data locations",
        );
        out.push(',');
        push_json_number(&mut out, "checked_files", self.checked_files as u64);
        out.push(',');
        push_json_number(&mut out, "checked_bytes", self.checked_bytes as u64);
        out.push(',');
        push_json_str(
            &mut out,
            "status",
            if self.passed() { "pass" } else { "fail" },
        );
        out.push_str(",\"forbidden_literals\":[");
        for (idx, literal) in forbidden_production_literals().iter().enumerate() {
            if idx > 0 {
                out.push(',');
            }
            out.push('{');
            push_json_str(&mut out, "literal", &literal.literal);
            out.push(',');
            push_json_str(&mut out, "classification", literal.classification);
            out.push('}');
        }
        out.push_str("],\"findings\":[");
        for (idx, finding) in self.findings.iter().enumerate() {
            if idx > 0 {
                out.push(',');
            }
            out.push('{');
            push_json_str(&mut out, "path", &finding.path);
            out.push(',');
            push_json_number(&mut out, "line", finding.line as u64);
            out.push(',');
            push_json_str(&mut out, "literal", &finding.literal);
            out.push(',');
            push_json_str(&mut out, "classification", finding.classification);
            out.push('}');
        }
        out.push_str("]}");
        out
    }
}

fn forbidden_production_literals() -> Vec<ForbiddenProductionLiteral> {
    vec![
        ForbiddenProductionLiteral {
            literal: join2("A000", "000003"),
            classification: "payment-rid-or-aid",
        },
        ForbiddenProductionLiteral {
            literal: join2("A000", "000004"),
            classification: "payment-rid-or-aid",
        },
        ForbiddenProductionLiteral {
            literal: join2("A000", "000025"),
            classification: "payment-rid-or-aid",
        },
        ForbiddenProductionLiteral {
            literal: join2("A000", "000065"),
            classification: "payment-rid-or-aid",
        },
        ForbiddenProductionLiteral {
            literal: join2("A000", "000152"),
            classification: "payment-rid-or-aid",
        },
        ForbiddenProductionLiteral {
            literal: join2("A000", "000333"),
            classification: "payment-rid-or-aid",
        },
        ForbiddenProductionLiteral {
            literal: join2("A000", "000524"),
            classification: "payment-rid-or-aid",
        },
        ForbiddenProductionLiteral {
            literal: join2("Vi", "sa"),
            classification: "scheme-brand",
        },
        ForbiddenProductionLiteral {
            literal: join2("Master", "card"),
            classification: "scheme-brand",
        },
        ForbiddenProductionLiteral {
            literal: join2("American ", "Express"),
            classification: "scheme-brand",
        },
        ForbiddenProductionLiteral {
            literal: join2("Dis", "cover"),
            classification: "scheme-brand",
        },
        ForbiddenProductionLiteral {
            literal: join2("J", "CB"),
            classification: "scheme-brand",
        },
        ForbiddenProductionLiteral {
            literal: join2("Union", "Pay"),
            classification: "scheme-brand",
        },
        ForbiddenProductionLiteral {
            literal: join2("legacy_", "visa"),
            classification: "scheme-profile-alias",
        },
        ForbiddenProductionLiteral {
            literal: join2("D2E5F5", "B3A1"),
            classification: "synthetic-capk-prefix",
        },
        ForbiddenProductionLiteral {
            literal: join2("E0F8C8", "0000"),
            classification: "tac-or-iac-fixture-value",
        },
    ]
}

pub fn audit_variable_data_boundary(
    inputs: &[BoundaryAuditInput<'_>],
) -> KernelResult<BoundaryAudit> {
    if inputs.is_empty() || inputs.len() > MAX_BOUNDARY_AUDIT_FILES {
        return Err(KernelError::LengthOverflow);
    }

    let mut checked_bytes = 0usize;
    let mut findings = Vec::new();
    for input in inputs {
        validate_input(input)?;
        checked_bytes = checked_bytes
            .checked_add(input.contents.len())
            .ok_or(KernelError::LengthOverflow)?;
        if checked_bytes > MAX_BOUNDARY_AUDIT_BYTES {
            return Err(KernelError::LengthOverflow);
        }

        let forbidden_literals = forbidden_production_literals();
        for (line_idx, line) in production_source(input.contents).lines().enumerate() {
            for literal in &forbidden_literals {
                if line.contains(&literal.literal) {
                    if findings.len() == MAX_BOUNDARY_FINDINGS {
                        return Err(KernelError::LengthOverflow);
                    }
                    findings.push(BoundaryFinding {
                        path: input.path.to_string(),
                        line: line_idx + 1,
                        literal: literal.literal.clone(),
                        classification: literal.classification,
                    });
                }
            }
        }
    }

    Ok(BoundaryAudit {
        checked_files: inputs.len(),
        checked_bytes,
        findings,
    })
}

fn validate_input(input: &BoundaryAuditInput<'_>) -> KernelResult<()> {
    if input.path.is_empty()
        || input.path.len() > 256
        || !input.path.ends_with(".rs")
        || input.contents.is_empty()
        || input.path.bytes().any(|byte| {
            !matches!(byte, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'_' | b'-' | b'/')
        })
    {
        return Err(KernelError::InvalidArgument);
    }
    if input.path.starts_with('/')
        || input
            .path
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return Err(KernelError::InvalidArgument);
    }
    Ok(())
}

fn production_source(contents: &str) -> &str {
    let mut byte_offset = 0usize;
    let mut previous_cfg_test_line_start = None;
    for line in contents.split_inclusive('\n') {
        let trimmed = line.trim();
        if trimmed == "#[cfg(test)]" {
            previous_cfg_test_line_start = Some(byte_offset);
        } else if trimmed.starts_with("mod tests") && previous_cfg_test_line_start.is_some() {
            let test_line_start = previous_cfg_test_line_start.unwrap_or_default();
            return &contents[..test_line_start];
        } else if !trimmed.is_empty() && !trimmed.starts_with("#[") {
            previous_cfg_test_line_start = None;
        }
        byte_offset += line.len();
    }
    contents
}

fn join2(left: &str, right: &str) -> String {
    let mut out = String::with_capacity(left.len() + right.len());
    out.push_str(left);
    out.push_str(right);
    out
}

fn push_json_str(out: &mut String, key: &str, value: &str) {
    out.push('"');
    out.push_str(key);
    out.push_str("\":");
    push_json_string(out, value);
}

fn push_json_number(out: &mut String, key: &str, value: u64) {
    out.push('"');
    out.push_str(key);
    let _ = write!(out, "\":{value}");
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
            ch if ch.is_control() => {
                let _ = write!(out, "\\u{:04x}", ch as u32);
            }
            ch => out.push(ch),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_passes_when_scheme_values_are_only_in_test_modules() {
        let source = r#"
pub fn parse_profile_value(input: &str) -> bool {
    !input.is_empty()
}

#[cfg(test)]
mod tests {
    const PROFILE: &str = "A000000003 Visa D2E5F5B3A1 E0F8C80000";
}
"#;

        let audit = audit_variable_data_boundary(&[BoundaryAuditInput {
            path: "src/example.rs",
            contents: source,
        }])
        .unwrap();
        assert!(audit.passed());
        assert!(audit.canonical_json().contains("\"status\":\"pass\""));
    }

    #[test]
    fn audit_fails_when_production_source_contains_scheme_values() {
        let source = r#"
pub const BAD_AID: &str = "A0000000031010";
pub const BAD_BRAND: &str = "Visa";
"#;

        let audit = audit_variable_data_boundary(&[BoundaryAuditInput {
            path: "src/bad.rs",
            contents: source,
        }])
        .unwrap();
        assert!(!audit.passed());
        assert_eq!(audit.findings.len(), 2);
        assert_eq!(audit.findings[0].literal, "A000000003");
        assert_eq!(audit.findings[1].literal, "Visa");
        assert!(audit.canonical_json().contains("\"status\":\"fail\""));
    }

    #[test]
    fn audit_rejects_ambiguous_paths_and_resource_overflow() {
        assert_eq!(
            audit_variable_data_boundary(&[BoundaryAuditInput {
                path: "../src/bad.rs",
                contents: "pub fn ok() {}",
            }]),
            Err(KernelError::InvalidArgument)
        );
        assert_eq!(
            audit_variable_data_boundary(&[]),
            Err(KernelError::LengthOverflow)
        );
    }

    #[test]
    fn audit_rejects_boundary_size_finding_and_path_limits() {
        let oversized = "x".repeat(MAX_BOUNDARY_AUDIT_BYTES + 1);
        assert_eq!(
            audit_variable_data_boundary(&[BoundaryAuditInput {
                path: "src/oversized.rs",
                contents: &oversized,
            }]),
            Err(KernelError::LengthOverflow)
        );

        let too_many_findings = (0..=MAX_BOUNDARY_FINDINGS)
            .map(|idx| format!("pub const BAD_{idx}: &str = \"Visa\";"))
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(
            audit_variable_data_boundary(&[BoundaryAuditInput {
                path: "src/too_many.rs",
                contents: &too_many_findings,
            }]),
            Err(KernelError::LengthOverflow)
        );

        for path in [
            "src/bad path.rs",
            "/src/bad.rs",
            "src//bad.rs",
            "src/./bad.rs",
        ] {
            assert_eq!(
                audit_variable_data_boundary(&[BoundaryAuditInput {
                    path,
                    contents: "pub fn ok() {}",
                }]),
                Err(KernelError::InvalidArgument),
                "accepted invalid path {path}"
            );
        }

        let split_source =
            "pub fn ok() {}\n#[cfg(test)]\nmod tests { const BAD: &str = \"Visa\"; }\n";
        assert_eq!(production_source(split_source), "pub fn ok() {}\n");
    }

    #[test]
    fn boundary_audit_json_escapes_control_characters() {
        let mut out = String::new();
        push_json_string(&mut out, "quote\" slash\\ line\ncarriage\rtab\t nul\x00");
        assert_eq!(
            out,
            "\"quote\\\" slash\\\\ line\\ncarriage\\rtab\\t nul\\u0000\""
        );
    }
}
