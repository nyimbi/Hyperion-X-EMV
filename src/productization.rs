//! Productization helpers for packaged Hyperion tooling.
//!
//! This module turns the example-oriented repository surfaces into reusable
//! package surfaces: command catalogues, formal schema emission, C ABI header
//! generation, and repeatable submission-pack assembly. The pack assembly is
//! intentionally fail-closed: without all external authority artifacts bound to
//! release-freeze slots it can write a review workspace only when the caller
//! explicitly allows incomplete output.

use core::fmt::Write;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::conformance::baseline_conformance_statement;
use crate::ffi::KRN_ABI_VERSION;
use crate::freeze::{certification_freeze_manifest_json, certification_freeze_manifest_markdown};
use crate::integration_import::{
    certification_integration_import_report_json, certification_integration_import_report_markdown,
    certification_release_freeze_json, certification_release_freeze_markdown,
    compile_certification_integration_artifacts, CertificationIntegrationReport,
};
use crate::provenance::{sha256, to_hex};
use crate::quality::prelab_quality_gates_json;
use crate::reporting::{
    certification_report_markdown, certification_report_pack_json, certification_report_ui_html,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CliCommandSpec {
    pub command: &'static str,
    pub purpose: &'static str,
    pub primary_output: &'static str,
    pub fail_closed_on: &'static str,
}

const INTEGRATION_IMPORT_JSON: &str = "certification_integration_import_report.json";
const INTEGRATION_IMPORT_MD: &str = "certification_integration_import_report.md";
const FREEZE_TEMPLATE_JSON: &str = "certification_freeze_manifest_template.json";
const FREEZE_TEMPLATE_MD: &str = "certification_freeze_manifest_template.md";

pub const HYPERION_CLI_COMMANDS: &[CliCommandSpec] = &[
    CliCommandSpec {
        command: "hyperion bundle init --out <dir>",
        purpose: "create a guided signed certification/testing data-bundle workspace",
        primary_output: "<dir>/bundle/certification_bundle.json",
        fail_closed_on: "invalid bundle fields or unsafe signing/provisioning input",
    },
    CliCommandSpec {
        command: "hyperion bundle lint --bundle <file> --trust-anchors <file>",
        purpose: "compile and lint a signed data bundle before profile loading",
        primary_output: "JSON lint report on stdout",
        fail_closed_on: "signature, rollback, trust-anchor, placeholder, or certification-policy failure",
    },
    CliCommandSpec {
        command: "hyperion bundle sign --out <dir>",
        purpose: "write a local signed bundle scaffold for authority-data replacement",
        primary_output: "<dir>/certification_bundle.json",
        fail_closed_on: "invalid bundle material or unsafe trust configuration",
    },
    CliCommandSpec {
        command: "hyperion artifacts import --root <dir> --out <dir>",
        purpose: "hash, classify, and normalize staged lab/scheme/CAPK/vector/device/report artifacts",
        primary_output: "certification_integration_import_report.json",
        fail_closed_on: "unsafe paths, private key material, bad hashes, unsupported containers, or manifest errors",
    },
    CliCommandSpec {
        command: "hyperion release freeze --artifacts <dir> --out <dir>",
        purpose: "assemble the submission freeze pack and require all freeze slots unless --allow-incomplete is set",
        primary_output: "submission_manifest.json and certification_release_freeze.json",
        fail_closed_on: "pending freeze slots, import findings, missing bundle/profile/report evidence, or hash mismatch",
    },
    CliCommandSpec {
        command: "hyperion report workspace --out <dir>",
        purpose: "write report pack JSON/Markdown/HTML and checklist artifacts for local review",
        primary_output: "<dir>/index.html",
        fail_closed_on: "I/O or deterministic report generation failure",
    },
    CliCommandSpec {
        command: "hyperion certify check",
        purpose: "emit the repository-controlled pre-lab quality gates and external evidence boundaries",
        primary_output: "prelab_quality_gates.json on stdout",
        fail_closed_on: "not a lab approval command; open external gates remain open",
    },
    CliCommandSpec {
        command: "hyperion schemas write --out <dir>",
        purpose: "write JSON Schemas for data bundles, integration manifests, report packs, and freeze manifests",
        primary_output: "<dir>/*.schema.json",
        fail_closed_on: "schema write failure",
    },
    CliCommandSpec {
        command: "hyperion c-header write --out <file>",
        purpose: "write the packaged C ABI header for SDK consumers",
        primary_output: "hyperion_emv.h",
        fail_closed_on: "header write failure",
    },
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SchemaSpec {
    pub id: &'static str,
    pub file_name: &'static str,
    pub title: &'static str,
    pub json: &'static str,
}

pub const SCHEMA_SPECS: &[SchemaSpec] = &[
    SchemaSpec {
        id: "certification-data-bundle",
        file_name: "certification-data-bundle.schema.json",
        title: "Hyperion Certification Data Bundle",
        json: CERTIFICATION_DATA_BUNDLE_SCHEMA,
    },
    SchemaSpec {
        id: "integration-manifest",
        file_name: "integration-manifest.schema.json",
        title: "Hyperion Integration Manifest",
        json: INTEGRATION_MANIFEST_SCHEMA,
    },
    SchemaSpec {
        id: "report-pack",
        file_name: "report-pack.schema.json",
        title: "Hyperion Certification Report Pack",
        json: REPORT_PACK_SCHEMA,
    },
    SchemaSpec {
        id: "freeze-manifest",
        file_name: "freeze-manifest.schema.json",
        title: "Hyperion Certification Freeze Manifest",
        json: FREEZE_MANIFEST_SCHEMA,
    },
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductizationFile {
    pub path: String,
    pub size_bytes: u64,
    pub sha256_hex: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubmissionPackInput {
    pub artifacts_root: PathBuf,
    pub out_dir: PathBuf,
    pub allow_incomplete: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubmissionPackOutput {
    pub out_dir: PathBuf,
    pub status: &'static str,
    pub missing_freeze_slots: Vec<String>,
    pub files: Vec<ProductizationFile>,
}

pub fn hyperion_cli_catalog_markdown() -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# Hyperion CLI Command Surface");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "| Command | Purpose | Primary Output | Fails Closed On |"
    );
    let _ = writeln!(out, "| --- | --- | --- | --- |");
    for command in HYPERION_CLI_COMMANDS {
        let _ = writeln!(
            out,
            "| `{}` | {} | `{}` | {} |",
            command.command, command.purpose, command.primary_output, command.fail_closed_on
        );
    }
    out
}

pub fn hyperion_cli_catalog_json() -> String {
    let mut out = String::new();
    out.push_str("{\"type\":\"hyperion-cli-catalog\",\"commands\":[");
    for (idx, command) in HYPERION_CLI_COMMANDS.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        out.push('{');
        push_json_str(&mut out, "command", command.command);
        out.push(',');
        push_json_str(&mut out, "purpose", command.purpose);
        out.push(',');
        push_json_str(&mut out, "primary_output", command.primary_output);
        out.push(',');
        push_json_str(&mut out, "fail_closed_on", command.fail_closed_on);
        out.push('}');
    }
    out.push_str("]}\n");
    out
}

pub fn write_schema_catalog(dir: &Path) -> io::Result<Vec<ProductizationFile>> {
    fs::create_dir_all(dir)?;
    for schema in SCHEMA_SPECS {
        fs::write(dir.join(schema.file_name), schema.json)?;
    }
    inventory_files(dir, &[])
}

pub fn hyperion_c_header() -> &'static str {
    HYPERION_C_HEADER
}

pub fn write_c_header(path: &Path) -> io::Result<ProductizationFile> {
    ensure_parent_dir(path)?;
    fs::write(path, HYPERION_C_HEADER)?;
    productization_file_absolute(path)
}

pub fn write_report_workspace(dir: &Path) -> io::Result<Vec<ProductizationFile>> {
    fs::create_dir_all(dir)?;
    let report_json = certification_report_pack_json(KRN_ABI_VERSION);
    let report_markdown = certification_report_markdown(KRN_ABI_VERSION);
    let report_html = certification_report_ui_html(KRN_ABI_VERSION);
    let conformance_json = baseline_conformance_statement(KRN_ABI_VERSION).canonical_json();
    let quality_gates_json = prelab_quality_gates_json(KRN_ABI_VERSION);
    write_output_file(dir, "report_pack.json", report_json)?;
    write_output_file(dir, "report_pack.md", report_markdown)?;
    write_output_file(dir, "index.html", report_html)?;
    write_output_file(dir, "abi_conformance_statement.json", conformance_json)?;
    write_output_file(dir, "prelab_quality_gates.json", quality_gates_json)?;
    inventory_files(dir, &[])
}

pub fn write_submission_pack(input: &SubmissionPackInput) -> io::Result<SubmissionPackOutput> {
    fs::create_dir_all(&input.out_dir)?;
    let integration = compile_certification_integration_artifacts(&input.artifacts_root)?;
    let missing = missing_freeze_slots(&integration);
    let has_errors = integration.status == "fail" || integration.status == "missing";
    if !input.allow_incomplete && (has_errors || !missing.is_empty()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "submission freeze is incomplete: status={}, missing_freeze_slots={}",
                integration.status,
                missing.join(",")
            ),
        ));
    }

    let integration_json =
        certification_integration_import_report_json(KRN_ABI_VERSION, &integration);
    let integration_markdown =
        certification_integration_import_report_markdown(KRN_ABI_VERSION, &integration);
    let release_json = certification_release_freeze_json(KRN_ABI_VERSION, &integration);
    let release_markdown = certification_release_freeze_markdown(KRN_ABI_VERSION, &integration);
    let freeze_template_json = certification_freeze_manifest_json(KRN_ABI_VERSION);
    let freeze_template_markdown = certification_freeze_manifest_markdown(KRN_ABI_VERSION);
    let out_dir = &input.out_dir;
    write_output_file(out_dir, INTEGRATION_IMPORT_JSON, integration_json)?;
    write_output_file(out_dir, INTEGRATION_IMPORT_MD, integration_markdown)?;
    write_output_file(out_dir, "certification_release_freeze.json", release_json)?;
    write_output_file(out_dir, "certification_release_freeze.md", release_markdown)?;
    write_output_file(out_dir, FREEZE_TEMPLATE_JSON, freeze_template_json)?;
    write_output_file(out_dir, FREEZE_TEMPLATE_MD, freeze_template_markdown)?;
    write_report_workspace(&out_dir.join("report-workspace"))?;
    write_schema_catalog(&out_dir.join("schemas"))?;
    write_c_header(&out_dir.join("include/hyperion_emv.h"))?;
    let readme = submission_pack_readme(&integration, &missing);
    write_output_file(out_dir, "README.md", readme)?;

    let files = inventory_files(out_dir, &[])?;
    let submission_manifest = submission_manifest_json(&integration, &missing, &files);
    write_output_file(out_dir, "submission_manifest.json", submission_manifest)?;
    let files = inventory_files(out_dir, &[])?;
    Ok(SubmissionPackOutput {
        out_dir: input.out_dir.clone(),
        status: if missing.is_empty() && integration.status == "pass_unreviewed" {
            "complete_unreviewed"
        } else {
            "incomplete_unreviewed"
        },
        missing_freeze_slots: missing,
        files,
    })
}

#[rustfmt::skip]
fn ensure_parent_dir(path: &Path) -> io::Result<()> {
    match path.parent() { Some(parent) => fs::create_dir_all(parent), None => Ok(()) }
}

fn write_output_file(root: &Path, name: &str, contents: String) -> io::Result<()> {
    fs::write(root.join(name), contents)
}

fn productization_file_absolute(path: &Path) -> io::Result<ProductizationFile> {
    let bytes = fs::read(path)?;
    Ok(ProductizationFile {
        path: path.display().to_string(),
        size_bytes: bytes.len() as u64,
        sha256_hex: to_hex(&sha256(&bytes)),
    })
}

fn push_productization_file(
    root: &Path,
    path: &Path,
    out: &mut Vec<ProductizationFile>,
) -> io::Result<()> {
    out.push(productization_file_for_path(root, path)?);
    Ok(())
}

fn missing_freeze_slots(report: &CertificationIntegrationReport) -> Vec<String> {
    report
        .freeze_bindings
        .iter()
        .filter(|binding| binding.status != "bound_unreviewed")
        .map(|binding| binding.freeze_artifact_id.to_string())
        .collect()
}

fn submission_pack_readme(report: &CertificationIntegrationReport, missing: &[String]) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# Hyperion Submission Pack");
    let _ = writeln!(out);
    let _ = writeln!(out, "Status: `{}`", report.status);
    let _ = writeln!(out);
    let _ = writeln!(out, "This directory binds repository-controlled reports, schemas, the C ABI header, and staged external artifact hashes for certification review. It is not an approval artifact by itself.");
    if !missing.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, "Missing freeze slots: `{}`", missing.join("`, `"));
    }
    out
}

fn submission_manifest_json(
    report: &CertificationIntegrationReport,
    missing: &[String],
    files: &[ProductizationFile],
) -> String {
    let mut out = String::new();
    out.push('{');
    push_json_str(&mut out, "type", "hyperion-submission-pack-manifest");
    out.push(',');
    push_json_str(&mut out, "kernel_name", "Hyperion EMV Kernel");
    out.push(',');
    push_json_str(&mut out, "kernel_version", env!("CARGO_PKG_VERSION"));
    out.push(',');
    push_json_number(&mut out, "abi_version", KRN_ABI_VERSION as u64);
    out.push(',');
    push_json_str(&mut out, "integration_status", report.status);
    out.push(',');
    push_json_str(
        &mut out,
        "status",
        if missing.is_empty() && report.status == "pass_unreviewed" {
            "complete_unreviewed"
        } else {
            "incomplete_unreviewed"
        },
    );
    out.push_str(",\"missing_freeze_slots\":[");
    for (idx, slot) in missing.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        push_json_string(&mut out, slot);
    }
    out.push_str("],\"files\":[");
    for (idx, file) in files.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        out.push('{');
        push_json_str(&mut out, "path", &file.path);
        out.push(',');
        push_json_number(&mut out, "size_bytes", file.size_bytes);
        out.push(',');
        push_json_str(&mut out, "sha256", &file.sha256_hex);
        out.push('}');
    }
    out.push_str("],\"boundary\":");
    push_json_string(
        &mut out,
        "repository-controlled submission assembly only; external authorities still decide certification acceptance",
    );
    out.push_str("}\n");
    out
}

fn inventory_files(root: &Path, exclude_names: &[&str]) -> io::Result<Vec<ProductizationFile>> {
    let mut paths = Vec::new();
    collect_files(root, root, exclude_names, &mut paths)?;
    paths.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(paths)
}

#[rustfmt::skip]
fn collect_files(root: &Path, path: &Path, exclude_names: &[&str], out: &mut Vec<ProductizationFile>) -> io::Result<()> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if exclude_names.iter().any(|excluded| *excluded == name) { continue; }
        let metadata = entry.metadata()?;
        if metadata.is_dir() { collect_files(root, &path, exclude_names, out)?; continue; }
        if metadata.is_file() { push_productization_file(root, &path, out)?; }
    }
    Ok(())
}

fn productization_file_for_path(root: &Path, path: &Path) -> io::Result<ProductizationFile> {
    let bytes = fs::read(path)?;
    Ok(ProductizationFile {
        path: path_for_manifest(root, path),
        size_bytes: bytes.len() as u64,
        sha256_hex: to_hex(&sha256(&bytes)),
    })
}

fn path_for_manifest(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

fn push_json_str(out: &mut String, key: &str, value: &str) {
    push_json_key(out, key);
    push_json_string(out, value);
}

fn push_json_number(out: &mut String, key: &str, value: u64) {
    push_json_key(out, key);
    let _ = write!(out, "{value}");
}

fn push_json_key(out: &mut String, key: &str) {
    push_json_string(out, key);
    out.push(':');
}

fn push_json_string(out: &mut String, value: &str) {
    out.push('"');
    for byte in value.bytes() {
        match byte {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            0x20..=0x7e => out.push(byte as char),
            _ => {
                out.push_str("\\u00");
                out.push(hex_nibble(byte >> 4));
                out.push(hex_nibble(byte & 0x0f));
            }
        }
    }
    out.push('"');
}

fn hex_nibble(value: u8) -> char {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    HEX[usize::from(value & 0x0f)] as char
}

const CERTIFICATION_DATA_BUNDLE_SCHEMA: &str = r##"{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://schemas.hyperion-emv.local/certification-data-bundle.schema.json",
  "title": "Hyperion Certification Data Bundle",
  "type": "object",
  "required": ["schema_version", "bundle_id", "bundle_version", "rollback_counter", "payload", "signature"],
  "additionalProperties": true,
  "properties": {
    "schema_version": {"type": "string", "pattern": "^hyperion-certification-bundle-"},
    "bundle_id": {"type": "string", "minLength": 1, "maxLength": 128},
    "bundle_version": {"type": "integer", "minimum": 1},
    "rollback_counter": {"type": "integer", "minimum": 0},
    "payload": {"type": "object"},
    "signature": {"type": "object"}
  }
}
"##;

const INTEGRATION_MANIFEST_SCHEMA: &str = r##"{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://schemas.hyperion-emv.local/integration-manifest.schema.json",
  "title": "Hyperion Integration Manifest",
  "type": "object",
  "required": ["schema_version", "manifest_id", "authority", "artifacts"],
  "additionalProperties": false,
  "properties": {
    "schema_version": {"const": "hyperion-certification-integration-manifest-1.0"},
    "manifest_id": {"type": "string", "minLength": 1, "maxLength": 128},
    "authority": {"type": "string", "minLength": 1, "maxLength": 256},
    "artifacts": {"type": "array", "minItems": 1, "maxItems": 128, "items": {"$ref": "#/$defs/artifact"}}
  },
  "$defs": {
    "artifact": {
      "type": "object",
      "required": ["path", "artifact_id", "artifact_kind", "binds_open_issues"],
      "additionalProperties": false,
      "properties": {
        "path": {"type": "string"},
        "adapter_id": {"type": "string"},
        "artifact_id": {"type": "string"},
        "artifact_kind": {"type": "string"},
        "binds_open_issues": {"type": "array", "items": {"type": "string", "pattern": "^CERT-OPEN-[0-9]{3}$"}},
        "bundle_field": {"type": "string"},
        "freeze_artifact_id": {"type": "string"},
        "expected_sha256_hex": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        "metadata": {"type": "array", "items": {"type": "string"}}
      }
    }
  }
}
"##;

const REPORT_PACK_SCHEMA: &str = r##"{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://schemas.hyperion-emv.local/report-pack.schema.json",
  "title": "Hyperion Certification Report Pack",
  "type": "object",
  "required": ["type", "kernel_name", "kernel_version", "abi_version"],
  "properties": {
    "type": {"const": "certification-report-pack"},
    "kernel_name": {"type": "string"},
    "kernel_version": {"type": "string"},
    "abi_version": {"type": "integer"}
  },
  "additionalProperties": true
}
"##;

const FREEZE_MANIFEST_SCHEMA: &str = r##"{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://schemas.hyperion-emv.local/freeze-manifest.schema.json",
  "title": "Hyperion Certification Freeze Manifest",
  "type": "object",
  "required": ["type", "kernel_name", "kernel_version", "abi_version"],
  "properties": {
    "type": {"enum": ["certification-freeze-manifest-template", "certification-release-freeze", "hyperion-submission-pack-manifest"]},
    "kernel_name": {"type": "string"},
    "kernel_version": {"type": "string"},
    "abi_version": {"type": "integer"},
    "release_freeze_bindings": {"type": "array"},
    "missing_freeze_slots": {"type": "array", "items": {"type": "string"}}
  },
  "additionalProperties": true
}
"##;

const HYPERION_C_HEADER: &str = r#"#ifndef HYPERION_EMV_H
#define HYPERION_EMV_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define KRN_ABI_VERSION 2u
#define KRN_MAX_APDU_RESPONSE_LEN 258u
#define KRN_MAX_ONLINE_AUTH_DATA_LEN 1024u
#define KRN_MAX_HOST_RESPONSE_LEN 1024u
#define KRN_PROFILE_SHA256_LEN 32u
#define KRN_INTERFACE_CONTACT 1u
#define KRN_INTERFACE_CONTACTLESS 2u

typedef struct KrnContext KrnContext;
typedef int32_t (*KrnTransmitApduCallback)(const uint8_t *cmd, size_t cmd_len, uint8_t *resp, size_t *resp_len, int32_t timeout_ms, void *user_data);
typedef int32_t (*KrnGetUnpredictableNumberCallback)(uint8_t *out, size_t out_len, void *user_data);

typedef struct KrnConfigBlob {
    uint32_t abi_version;
    uint32_t struct_size;
    const uint8_t *bytes;
    size_t len;
} KrnConfigBlob;

typedef struct KrnRuntime {
    uint32_t abi_version;
    uint32_t struct_size;
    KrnTransmitApduCallback transmit_apdu;
    KrnGetUnpredictableNumberCallback get_unpredictable_number;
    void *contactless_outcome;
    void *user_data;
} KrnRuntime;

typedef struct KrnTxnParams {
    uint32_t struct_size;
    uint64_t amount_authorised_minor;
    uint64_t amount_other_minor;
    uint16_t currency_code;
    uint8_t currency_exponent;
    uint16_t terminal_country_code;
    uint8_t transaction_type;
    uint8_t terminal_type;
    uint8_t merchant_category_code[2];
    uint8_t interface_preference;
    const uint8_t *merchant_name_location;
    size_t merchant_name_location_len;
} KrnTxnParams;

KrnContext *krn_context_new(void);
int32_t krn_init(KrnContext *ctx, const KrnConfigBlob *config, const KrnRuntime *runtime);
void krn_context_free(KrnContext *ctx);
int32_t krn_reset(KrnContext *ctx);
int32_t krn_get_last_error(const KrnContext *ctx);
uint32_t krn_abi_version(void);
int32_t krn_set_transaction_params(KrnContext *ctx, const KrnTxnParams *params);
int32_t krn_load_profiles_verified(KrnContext *ctx, const uint8_t *profile_json, size_t profile_json_len);
int32_t krn_load_certification_bundle_verified(KrnContext *ctx, const uint8_t *bundle_json, size_t bundle_json_len, const uint8_t *trust_anchor_json, size_t trust_anchor_json_len);
int32_t krn_run_transaction(KrnContext *ctx);
int32_t krn_build_select_environment(KrnContext *ctx, uint8_t *out, size_t *out_len);
int32_t krn_build_generate_ac(KrnContext *ctx, uint8_t cryptogram_type, uint8_t *out, size_t *out_len);
int32_t krn_get_online_authorization_data(KrnContext *ctx, uint8_t *out, size_t *out_len);
int32_t krn_apply_host_response(KrnContext *ctx, const uint8_t *response, size_t response_len);
int32_t krn_process_issuer_authentication(KrnContext *ctx);
int32_t krn_process_issuer_scripts(KrnContext *ctx);
int32_t krn_process_final_generate_ac(KrnContext *ctx);
int32_t krn_get_final_outcome(const KrnContext *ctx);
int32_t krn_get_profile_sha256(const KrnContext *ctx, uint8_t *out, size_t out_len);
int32_t krn_mask_apdu_command_json(const uint8_t *cmd, size_t cmd_len, uint8_t *out, size_t *out_len);
int32_t krn_mask_apdu_response_json(const uint8_t *resp, size_t resp_len, uint8_t *out, size_t *out_len);
int32_t krn_get_conformance_statement_json(uint8_t *out, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::process;

    #[test]
    fn command_catalog_and_schemas_are_reviewable() {
        let markdown = hyperion_cli_catalog_markdown();
        let json = hyperion_cli_catalog_json();
        assert!(markdown.contains("hyperion release freeze"));
        assert!(json.contains("hyperion-cli-catalog"));
        assert!(SCHEMA_SPECS
            .iter()
            .any(|schema| schema.file_name == "integration-manifest.schema.json"));
        assert!(CERTIFICATION_DATA_BUNDLE_SCHEMA.contains("certification-data-bundle"));
        let mut escaped = String::new();
        push_json_string(
            &mut escaped,
            "quote\" slash\\ newline\n carriage\r tab\t high\u{00ff}",
        );
        assert_eq!(
            escaped,
            "\"quote\\\" slash\\\\ newline\\n carriage\\r tab\\t high\\u00c3\\u00bf\""
        );
    }

    #[test]
    fn writes_schemas_header_report_workspace_and_incomplete_submission_pack() {
        let root = env::temp_dir().join(format!("hyperion-productization-{}", process::id()));
        let _ = fs::remove_dir_all(&root);
        let schemas = write_schema_catalog(&root.join("schemas")).unwrap();
        assert_eq!(schemas.len(), SCHEMA_SPECS.len());
        let header = write_c_header(&root.join("include/hyperion_emv.h")).unwrap();
        assert!(header.sha256_hex.len() == 64);
        assert!(hyperion_c_header().contains("krn_context_new"));
        let reports = write_report_workspace(&root.join("reports")).unwrap();
        assert!(reports.iter().any(|file| file.path == "index.html"));

        let artifacts = root.join("artifacts");
        let out = root.join("submission");
        fs::create_dir_all(&artifacts).unwrap();
        let strict_err = write_submission_pack(&SubmissionPackInput {
            artifacts_root: artifacts.clone(),
            out_dir: out.clone(),
            allow_incomplete: false,
        })
        .unwrap_err();
        assert_eq!(strict_err.kind(), io::ErrorKind::InvalidData);
        let output = write_submission_pack(&SubmissionPackInput {
            artifacts_root: artifacts,
            out_dir: out.clone(),
            allow_incomplete: true,
        })
        .unwrap();
        assert_eq!(output.status, "incomplete_unreviewed");
        assert!(output
            .missing_freeze_slots
            .iter()
            .any(|slot| slot == "kernel_binary_hash"));
        let manifest = fs::read_to_string(out.join("submission_manifest.json")).unwrap();
        assert!(manifest.contains("hyperion-submission-pack-manifest"));
        assert!(manifest.contains("include/hyperion_emv.h"));
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn complete_submission_manifest_and_inventory_edges_are_covered() {
        let report = CertificationIntegrationReport {
            root: "/tmp/hyperion".to_string(),
            status: "pass_unreviewed",
            import_report: crate::artifact_import::ArtifactImportReport {
                root: "/tmp/hyperion".to_string(),
                adapters: Vec::new(),
            },
            normalized_artifacts: Vec::new(),
            bundle_bindings: Vec::new(),
            freeze_bindings: Vec::new(),
            findings: Vec::new(),
        };
        let files = [ProductizationFile {
            path: "reports/line\nitem.txt".to_string(),
            size_bytes: 7,
            sha256_hex: "abc\r\t\u{00ff}".to_string(),
        }];
        let manifest = submission_manifest_json(&report, &[], &files);
        assert!(manifest.contains("complete_unreviewed"));
        assert!(manifest.contains("line\\nitem.txt"));
        assert!(manifest.contains("abc\\r\\t\\u00c3\\u00bf"));

        let root = env::temp_dir().join(format!("hyperion-inventory-{}", process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("nested")).unwrap();
        fs::write(root.join("keep.txt"), b"keep").unwrap();
        fs::write(root.join("skip.txt"), b"skip").unwrap();
        fs::write(root.join("nested/child.txt"), b"child").unwrap();
        let inventory = inventory_files(&root, &["skip.txt"]).unwrap();
        assert!(inventory.iter().any(|file| file.path == "keep.txt"));
        assert!(inventory.iter().any(|file| file.path == "nested/child.txt"));
        assert!(!inventory.iter().any(|file| file.path == "skip.txt"));
        assert!(path_for_manifest(&root, Path::new("outside.txt")).contains("outside.txt"));
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn strict_submission_pack_can_complete_when_all_freeze_slots_are_bound() {
        let root = env::temp_dir().join(format!("hyperion-complete-submission-{}", process::id()));
        let artifacts = root.join("artifacts");
        let out = root.join("submission");
        let _ = fs::remove_dir_all(&root);
        write_complete_artifact_root(&artifacts);
        let output = write_submission_pack(&SubmissionPackInput {
            artifacts_root: artifacts,
            out_dir: out,
            allow_incomplete: false,
        })
        .unwrap();
        assert_eq!(output.status, "complete_unreviewed");
        assert!(output.missing_freeze_slots.is_empty());
        ensure_parent_dir(Path::new("/")).unwrap();
        fs::remove_dir_all(&root).unwrap();
    }

    fn write_complete_artifact_root(root: &Path) {
        for dir in ["device", "scheme", "capk", "vectors", "reports", "lab"] {
            fs::create_dir_all(root.join(dir)).unwrap();
        }
        for path in [
            "device/kernel.txt",
            "scheme/config.json",
            "scheme/profile.json",
            "capk/capk.json",
            "vectors/vectors.json",
            "reports/trace.json",
            "reports/coverage.lcov",
            "reports/fuzz.sarif",
            "lab/approval.json",
        ] {
            fs::write(root.join(path), format!("artifact:{path}")).unwrap();
        }
        fs::write(
            root.join("hyperion-integration-manifest.json"),
            r#"{"schema_version":"hyperion-certification-integration-manifest-1.0","manifest_id":"complete","authority":"test-lab","artifacts":[{"path":"device/kernel.txt","adapter_id":"DEVICE","artifact_id":"kernel.binary","artifact_kind":"build artifact","binds_open_issues":["CERT-OPEN-006"],"freeze_artifact_id":"kernel_binary_hash","metadata":["authority"]},{"path":"scheme/config.json","adapter_id":"SCHEME-PROFILE","artifact_id":"config.bundle","artifact_kind":"signed configuration","binds_open_issues":["CERT-OPEN-002"],"freeze_artifact_id":"config_bundle_hash","metadata":["authority"]},{"path":"scheme/profile.json","adapter_id":"SCHEME-PROFILE","artifact_id":"scheme.profile","artifact_kind":"scheme profile","binds_open_issues":["CERT-OPEN-002"],"freeze_artifact_id":"scheme_profile_hash","metadata":["authority"]},{"path":"capk/capk.json","adapter_id":"CAPK","artifact_id":"capk.bundle","artifact_kind":"public key material","binds_open_issues":["CERT-OPEN-003"],"freeze_artifact_id":"capk_bundle_hash","metadata":["authority"]},{"path":"vectors/vectors.json","adapter_id":"VECTOR","artifact_id":"vectors.bundle","artifact_kind":"test vectors","binds_open_issues":["CERT-OPEN-004"],"freeze_artifact_id":"test_vector_hash","metadata":["authority"]},{"path":"reports/trace.json","adapter_id":"REPORT","artifact_id":"trace.pack","artifact_kind":"trace pack","binds_open_issues":["CERT-OPEN-012"],"freeze_artifact_id":"trace_pack_hash","metadata":["authority"]},{"path":"reports/coverage.lcov","adapter_id":"REPORT","artifact_id":"coverage.report","artifact_kind":"quality report","binds_open_issues":["CERT-OPEN-009"],"freeze_artifact_id":"coverage_report_hash","metadata":["authority"]},{"path":"reports/fuzz.sarif","adapter_id":"REPORT","artifact_id":"fuzz.report","artifact_kind":"quality report","binds_open_issues":["CERT-OPEN-010"],"freeze_artifact_id":"static_fuzz_report_hash","metadata":["authority"]},{"path":"lab/approval.json","adapter_id":"LAB-APPROVAL","artifact_id":"approval.package","artifact_kind":"approval artifact","binds_open_issues":["CERT-OPEN-011"],"freeze_artifact_id":"approval_package_hash","metadata":["authority"]}]}"#,
        ).unwrap();
    }
}
