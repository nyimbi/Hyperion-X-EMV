//! Certification report-pack and static workbench generation.
//!
//! The UI generated here is deliberately static and dependency-free. It is an
//! inspection and report-production surface for repository-controlled evidence;
//! it does not close external lab, scheme, device, PCI, or approval gates.

use crate::evidence::{certification_evidence_requirements, EvidenceRequirement};
use core::fmt::Write;

pub struct ReportArtifact {
    pub id: &'static str,
    pub title: &'static str,
    pub path: &'static str,
    pub category: &'static str,
    pub generator: &'static str,
    pub status: &'static str,
    pub boundary: &'static str,
}

pub struct RequiredReport {
    pub id: &'static str,
    pub title: &'static str,
    pub status: &'static str,
    pub required_evidence: &'static str,
    pub closure_gate: &'static str,
}

pub struct ToolCommand {
    pub id: &'static str,
    pub title: &'static str,
    pub command: &'static str,
    pub output: &'static str,
}

const REPORT_ARTIFACTS: &[ReportArtifact] = &[
    ReportArtifact {
        id: "SPEC",
        title: "Kernel specification",
        path: "docs/spec.md",
        category: "requirements",
        generator: "human-controlled annex",
        status: "repository-controlled",
        boundary: "licensed standards prevail on conflict",
    },
    ReportArtifact {
        id: "RTM",
        title: "Requirement traceability matrices",
        path: "docs/requirements_traceability.csv; docs/requirements-traceability-matrix.csv",
        category: "requirements",
        generator: "traceability tests",
        status: "repository-controlled",
        boundary: "lab test-case crosswalk remains external",
    },
    ReportArtifact {
        id: "MANIFEST",
        title: "Lab submission manifest",
        path: "docs/lab_submission_manifest.md",
        category: "submission",
        generator: "human-controlled annex",
        status: "repository-controlled template",
        boundary: "unattached report rows remain open",
    },
    ReportArtifact {
        id: "OPEN-ISSUES",
        title: "Certification open issues",
        path: "docs/certification_open_issues.md",
        category: "submission",
        generator: "human-controlled register",
        status: "repository-controlled",
        boundary: "controls external blockers",
    },
    ReportArtifact {
        id: "ABI",
        title: "ABI conformance statement",
        path: "docs/abi_conformance_statement.json",
        category: "conformance",
        generator: "cargo run --quiet --example krn_abi_conformance_statement",
        status: "generated",
        boundary: "not a signed lab conformance template",
    },
    ReportArtifact {
        id: "PROFILE-DICTIONARY",
        title: "Scheme profile dictionary",
        path: "docs/scheme_profile_dictionary.md",
        category: "configuration",
        generator: "cargo run --quiet --example krn_scheme_profile_dictionary",
        status: "generated",
        boundary: "does not disclose raw CAPK modulus material",
    },
    ReportArtifact {
        id: "TRACE-PACK",
        title: "Masked pre-lab APDU trace fixture",
        path: "docs/prelab_apdu_trace_pack.jsonl",
        category: "trace",
        generator: "cargo run --quiet --example krn_prelab_trace_pack",
        status: "generated",
        boundary: "full lab trace pack remains external",
    },
    ReportArtifact {
        id: "QUALITY-GATES",
        title: "Pre-lab quality gate manifest",
        path: "docs/prelab_quality_gates.json",
        category: "quality",
        generator: "cargo run --quiet --example krn_prelab_quality_gates",
        status: "generated",
        boundary: "coverage and formal reports remain external",
    },
    ReportArtifact {
        id: "NO-CRASH",
        title: "Parser/APDU no-crash smoke artifact",
        path: "docs/prelab_no_crash_smoke.json",
        category: "quality",
        generator: "cargo run --quiet --example krn_prelab_no_crash_smoke",
        status: "generated",
        boundary: "not a fuzzing report",
    },
    ReportArtifact {
        id: "STATIC-FUZZ-PLAN",
        title: "Static and fuzz evidence plan",
        path: "docs/prelab_static_fuzz_plan.json",
        category: "quality",
        generator: "cargo run --quiet --example krn_prelab_static_fuzz_plan",
        status: "generated",
        boundary: "plan only; accepted reports remain external",
    },
    ReportArtifact {
        id: "FUZZ-SEEDS",
        title: "Fuzz seed corpus manifest",
        path: "docs/prelab_fuzz_seed_corpus.json",
        category: "quality",
        generator: "cargo run --quiet --example krn_prelab_fuzz_seed_corpus",
        status: "generated",
        boundary: "hash-only synthetic seed evidence",
    },
    ReportArtifact {
        id: "STANDARDS-WATCH",
        title: "Public standards watch",
        path: "docs/public_standards_watch.json",
        category: "drift",
        generator: "cargo run --quiet --example krn_public_standards_watch",
        status: "generated",
        boundary: "public drift signal only",
    },
    ReportArtifact {
        id: "EVIDENCE-CHECKLIST",
        title: "Certification evidence attachment checklist",
        path:
            "docs/certification_evidence_checklist.json; docs/certification_evidence_checklist.md",
        category: "submission",
        generator: "cargo run --quiet --example krn_certification_evidence_checklist",
        status: "generated",
        boundary: "attachment checklist only; does not close external gates",
    },
    ReportArtifact {
        id: "EVIDENCE-INTAKE",
        title: "Certification evidence intake ledger",
        path: "docs/certification_evidence_intake.json; docs/certification_evidence_intake.md",
        category: "submission",
        generator: "cargo run --quiet --example krn_certification_evidence_intake",
        status: "generated",
        boundary: "attachment slots only; accepted external evidence remains required",
    },
    ReportArtifact {
        id: "REPORT-PACK",
        title: "Certification report pack",
        path: "docs/certification_report_pack.json; docs/certification_report_pack.md",
        category: "reporting",
        generator: "cargo run --quiet --example krn_certification_report_ui",
        status: "generated",
        boundary: "index only; external report attachments remain required",
    },
    ReportArtifact {
        id: "REPORT-UI",
        title: "Certification report workbench",
        path: "docs/certification_report_ui.html",
        category: "reporting",
        generator: "cargo run --quiet --example krn_certification_report_ui -- --html",
        status: "generated",
        boundary: "static local UI; not a lab portal or approval system",
    },
    ReportArtifact {
        id: "COVERAGE-WORKFLOW",
        title: "100% coverage workflow",
        path: "docs/coverage.md; scripts/coverage_100.sh",
        category: "quality",
        generator: "scripts/coverage_100.sh",
        status: "prepared",
        boundary: "accepted submitted-build report remains external",
    },
    ReportArtifact {
        id: "TUTORIALS",
        title: "Tutorial and glossary learning path",
        path: "docs/tutorial/",
        category: "education",
        generator: "human-controlled docs",
        status: "repository-controlled",
        boundary: "education only; not approval evidence",
    },
];

const REQUIRED_REPORTS: &[RequiredReport] = &[
    RequiredReport {
        id: "CERT-REPORT-COVERAGE",
        title: "100% unit coverage report",
        status: "pending external attachment",
        required_evidence: "submitted commit, tool versions, target, feature set, coverage metadata JSON, and HTML/XML or lab-accepted report",
        closure_gate: "CERT-OPEN-009",
    },
    RequiredReport {
        id: "CERT-REPORT-INTEGRATION",
        title: "Full EMV integration report",
        status: "pending external attachment",
        required_evidence: "test-tool version, profile set, device firmware, APDU traces, outcomes, deviations, and disposition",
        closure_gate: "CERT-OPEN-009",
    },
    RequiredReport {
        id: "CERT-REPORT-STATIC",
        title: "Static-analysis report",
        status: "pending external attachment",
        required_evidence: "accepted tool version, command lines, findings, remediations, and residual-risk acceptance",
        closure_gate: "CERT-OPEN-010",
    },
    RequiredReport {
        id: "CERT-REPORT-FUZZ",
        title: "Fuzzing/no-crash report",
        status: "pending external attachment",
        required_evidence: "engine versions, corpus hashes, run budgets, coverage/path metrics, crashes, and dispositions",
        closure_gate: "CERT-OPEN-010",
    },
    RequiredReport {
        id: "CERT-REPORT-CONFORMANCE",
        title: "Signed conformance template and approval artifact",
        status: "pending external attachment",
        required_evidence: "recognized lab or authority-signed template tied to submitted binary, profile, and device scope",
        closure_gate: "CERT-OPEN-011",
    },
    RequiredReport {
        id: "CERT-REPORT-DEVICE",
        title: "Device, L1, and PCI/PED evidence",
        status: "pending external attachment",
        required_evidence: "target device approval, reader/L1 evidence, and PCI PTS/PED integration statement",
        closure_gate: "CERT-OPEN-006; CERT-OPEN-007",
    },
];

const TOOL_COMMANDS: &[ToolCommand] = &[
    ToolCommand {
        id: "UI",
        title: "Generate certification workbench UI",
        command: "cargo run --quiet --example krn_certification_report_ui -- --out target/hyperion-cert-ui",
        output: "target/hyperion-cert-ui/index.html",
    },
    ToolCommand {
        id: "REPORT-JSON",
        title: "Emit report-pack JSON",
        command: "cargo run --quiet --example krn_certification_report_ui -- --json",
        output: "stdout JSON",
    },
    ToolCommand {
        id: "REPORT-MD",
        title: "Emit report-pack Markdown",
        command: "cargo run --quiet --example krn_certification_report_ui -- --markdown",
        output: "stdout Markdown",
    },
    ToolCommand {
        id: "EVIDENCE",
        title: "Emit certification evidence checklist",
        command: "cargo run --quiet --example krn_certification_evidence_checklist -- --out docs",
        output: "docs/certification_evidence_checklist.json and .md",
    },
    ToolCommand {
        id: "INTAKE",
        title: "Emit certification evidence intake ledger",
        command: "cargo run --quiet --example krn_certification_evidence_intake -- --out docs",
        output: "docs/certification_evidence_intake.json and .md",
    },
    ToolCommand {
        id: "POS",
        title: "Run basic scripted PoS integration",
        command: "cargo run --quiet --example krn_basic_pos",
        output: "stdout JSON transaction summary",
    },
];

pub fn certification_report_pack_json(abi_version: u32) -> String {
    let mut out = String::new();
    out.push('{');
    push_json_str(&mut out, "type", "certification-report-pack");
    out.push(',');
    push_json_str(&mut out, "kernel_name", "Hyperion EMV Kernel");
    out.push(',');
    push_json_str(&mut out, "kernel_version", env!("CARGO_PKG_VERSION"));
    out.push(',');
    push_json_number(&mut out, "abi_version", abi_version as u64);
    out.push(',');
    push_json_str(
        &mut out,
        "scope",
        "repository-controlled report production and certification preparation",
    );
    out.push_str(",\"does_not_close\":[");
    for (idx, issue) in [
        "CERT-OPEN-001",
        "CERT-OPEN-005",
        "CERT-OPEN-006",
        "CERT-OPEN-007",
        "CERT-OPEN-009",
        "CERT-OPEN-010",
        "CERT-OPEN-011",
        "CERT-OPEN-012",
    ]
    .iter()
    .enumerate()
    {
        if idx > 0 {
            out.push(',');
        }
        push_json_string(&mut out, issue);
    }
    out.push_str("],\"artifacts\":[");
    for (idx, artifact) in REPORT_ARTIFACTS.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        push_report_artifact_json(&mut out, artifact);
    }
    out.push_str("],\"required_reports\":[");
    for (idx, report) in REQUIRED_REPORTS.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        push_required_report_json(&mut out, report);
    }
    out.push_str("],\"evidence_requirements\":[");
    for (idx, requirement) in certification_evidence_requirements().iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        push_evidence_requirement_json(&mut out, requirement);
    }
    out.push_str("],\"tool_commands\":[");
    for (idx, tool) in TOOL_COMMANDS.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        push_tool_command_json(&mut out, tool);
    }
    out.push_str("]}\n");
    out
}

pub fn certification_report_markdown(abi_version: u32) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# Hyperion Certification Report Pack");
    let _ = writeln!(out);
    let _ = writeln!(out, "- Kernel version: {}", env!("CARGO_PKG_VERSION"));
    let _ = writeln!(out, "- ABI version: {abi_version}");
    let _ = writeln!(
        out,
        "- Scope: repository-controlled report production and certification preparation"
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "## Repository Artifacts");
    let _ = writeln!(
        out,
        "| ID | Title | Category | Path | Status | Generator | Boundary |"
    );
    let _ = writeln!(out, "| --- | --- | --- | --- | --- | --- | --- |");
    for artifact in REPORT_ARTIFACTS {
        let _ = writeln!(
            out,
            "| {} | {} | {} | `{}` | {} | `{}` | {} |",
            artifact.id,
            artifact.title,
            artifact.category,
            artifact.path,
            artifact.status,
            artifact.generator,
            artifact.boundary
        );
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "## Required External Reports");
    let _ = writeln!(
        out,
        "| ID | Title | Status | Required Evidence | Closure Gate |"
    );
    let _ = writeln!(out, "| --- | --- | --- | --- | --- |");
    for report in REQUIRED_REPORTS {
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} | {} |",
            report.id, report.title, report.status, report.required_evidence, report.closure_gate
        );
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "## Evidence Attachment Checklist");
    let _ = writeln!(
        out,
        "| Open Issue | Area | Authority | Required Attachment | Metadata | Acceptance Gate | Repository Support | Status |"
    );
    let _ = writeln!(out, "| --- | --- | --- | --- | --- | --- | --- | --- |");
    for requirement in certification_evidence_requirements() {
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} | {} | {} | `{}` | {} |",
            requirement.open_issue,
            requirement.area,
            requirement.authority,
            requirement.required_attachment,
            requirement.required_metadata,
            requirement.acceptance_gate,
            requirement.repository_support,
            requirement.status
        );
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "## Tool Commands");
    let _ = writeln!(out, "| ID | Title | Command | Output |");
    let _ = writeln!(out, "| --- | --- | --- | --- |");
    for tool in TOOL_COMMANDS {
        let _ = writeln!(
            out,
            "| {} | {} | `{}` | `{}` |",
            tool.id, tool.title, tool.command, tool.output
        );
    }
    out
}

pub fn certification_report_ui_html(abi_version: u32) -> String {
    let data = certification_report_pack_json(abi_version);
    let markdown = certification_report_markdown(abi_version);
    let mut out = String::new();
    out.push_str("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">");
    out.push_str("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
    out.push_str("<title>Hyperion Certification Workbench</title>");
    out.push_str("<style>");
    out.push_str("*,*::before,*::after{box-sizing:border-box}body{margin:0;font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,\"Segoe UI\",sans-serif;color:#1b1f24;background:#f7f8fa;line-height:1.45}header{background:#0f1720;color:#f8fafc;padding:20px 24px;border-bottom:4px solid #1f9d8a}main{padding:18px 24px 28px;max-width:1480px;margin:0 auto}.topbar{display:flex;gap:16px;align-items:flex-end;justify-content:space-between;flex-wrap:wrap}.title{margin:0;font-size:26px;font-weight:720;letter-spacing:0}.meta{display:flex;gap:12px;flex-wrap:wrap;margin-top:8px;color:#cbd5df;font-size:13px}.toolbar{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.toolbar button,.toolbar input{height:36px;border:1px solid #ccd3dc;background:#fff;color:#1b1f24;padding:0 10px;border-radius:6px;font:inherit}.toolbar button{cursor:pointer}.toolbar button[aria-pressed=\"true\"]{background:#1f9d8a;color:#fff;border-color:#1f9d8a}.toolbar input{min-width:260px}.summary{display:grid;grid-template-columns:repeat(5,minmax(140px,1fr));gap:12px;margin:18px 0}.metric{background:#fff;border:1px solid #d9dee6;border-radius:8px;padding:14px}.metric strong{display:block;font-size:24px}.metric span{color:#52606d;font-size:13px}section{margin-top:18px}.section-head{display:flex;align-items:center;justify-content:space-between;gap:12px;border-bottom:1px solid #d9dee6;padding-bottom:8px}h2{font-size:17px;margin:0}.table-wrap{overflow:auto;background:#fff;border:1px solid #d9dee6;border-radius:8px}table{border-collapse:collapse;width:100%;min-width:920px}th,td{text-align:left;vertical-align:top;border-bottom:1px solid #edf0f4;padding:10px 12px;font-size:13px}th{position:sticky;top:0;background:#edf3f7;color:#23313f;font-size:12px;text-transform:uppercase}tr:last-child td{border-bottom:0}.status{font-weight:700;color:#8a4b00}.ok{color:#0b6e4f}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px}.hidden{display:none}@media(max-width:980px){.summary{grid-template-columns:repeat(2,minmax(130px,1fr))}}@media(max-width:780px){header,main{padding-left:14px;padding-right:14px}.title{font-size:22px}.toolbar{width:100%}.toolbar input{min-width:0;width:100%}}");
    out.push_str("</style></head><body><header><div class=\"topbar\"><div><h1 class=\"title\">Hyperion Certification Workbench</h1><div class=\"meta\"><span id=\"kernel\"></span><span id=\"abi\"></span><span id=\"scope\"></span></div></div><div class=\"toolbar\" role=\"toolbar\" aria-label=\"Workbench views\"><button data-view=\"artifacts\" aria-pressed=\"true\">Artifacts</button><button data-view=\"reports\" aria-pressed=\"false\">Reports</button><button data-view=\"evidence\" aria-pressed=\"false\">Evidence</button><button data-view=\"tools\" aria-pressed=\"false\">Tools</button><button id=\"download-json\">JSON</button><button id=\"download-md\">Markdown</button><input id=\"search\" type=\"search\" placeholder=\"Filter\" aria-label=\"Filter rows\"></div></div></header><main><div class=\"summary\"><div class=\"metric\"><strong id=\"artifact-count\">0</strong><span>repository artifacts</span></div><div class=\"metric\"><strong id=\"report-count\">0</strong><span>required reports</span></div><div class=\"metric\"><strong id=\"evidence-count\">0</strong><span>evidence attachments</span></div><div class=\"metric\"><strong id=\"tool-count\">0</strong><span>tool commands</span></div><div class=\"metric\"><strong id=\"open-count\">0</strong><span>open external gates</span></div></div>");
    out.push_str("<section id=\"artifacts\"><div class=\"section-head\"><h2>Repository Artifacts</h2></div><div class=\"table-wrap\"><table><thead><tr><th>ID</th><th>Title</th><th>Category</th><th>Path</th><th>Status</th><th>Generator</th><th>Boundary</th></tr></thead><tbody id=\"artifact-body\"></tbody></table></div></section>");
    out.push_str("<section id=\"reports\" class=\"hidden\"><div class=\"section-head\"><h2>Required External Reports</h2></div><div class=\"table-wrap\"><table><thead><tr><th>ID</th><th>Title</th><th>Status</th><th>Required Evidence</th><th>Closure Gate</th></tr></thead><tbody id=\"report-body\"></tbody></table></div></section>");
    out.push_str("<section id=\"evidence\" class=\"hidden\"><div class=\"section-head\"><h2>Evidence Attachment Checklist</h2></div><div class=\"table-wrap\"><table><thead><tr><th>Open Issue</th><th>Area</th><th>Authority</th><th>Required Attachment</th><th>Metadata</th><th>Acceptance Gate</th><th>Repository Support</th><th>Status</th></tr></thead><tbody id=\"evidence-body\"></tbody></table></div></section>");
    out.push_str("<section id=\"tools\" class=\"hidden\"><div class=\"section-head\"><h2>Tool Commands</h2></div><div class=\"table-wrap\"><table><thead><tr><th>ID</th><th>Title</th><th>Command</th><th>Output</th></tr></thead><tbody id=\"tool-body\"></tbody></table></div></section>");
    out.push_str("</main><script id=\"report-data\" type=\"application/json\">");
    push_html_text(&mut out, &data);
    out.push_str("</script><script id=\"report-markdown\" type=\"text/plain\">");
    push_html_text(&mut out, &markdown);
    out.push_str("</script><script>");
    out.push_str("const data=JSON.parse(document.getElementById('report-data').textContent);const markdown=document.getElementById('report-markdown').textContent;const q=document.getElementById('search');const views=['artifacts','reports','evidence','tools'];function esc(v){return String(v).replace(/[&<>\"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',\"'\":'&#39;'}[c]));}function cell(v,cls=''){return `<td class=\"${cls}\">${esc(v)}</td>`;}function render(){const term=q.value.toLowerCase();document.getElementById('kernel').textContent=`${data.kernel_name} ${data.kernel_version}`;document.getElementById('abi').textContent=`ABI ${data.abi_version}`;document.getElementById('scope').textContent=data.scope;document.getElementById('artifact-count').textContent=data.artifacts.length;document.getElementById('report-count').textContent=data.required_reports.length;document.getElementById('evidence-count').textContent=data.evidence_requirements.length;document.getElementById('tool-count').textContent=data.tool_commands.length;document.getElementById('open-count').textContent=data.does_not_close.length;const match=o=>JSON.stringify(o).toLowerCase().includes(term);document.getElementById('artifact-body').innerHTML=data.artifacts.filter(match).map(a=>`<tr>${cell(a.id,'mono')}${cell(a.title)}${cell(a.category)}${cell(a.path,'mono')}${cell(a.status,a.status==='generated'?'ok':'')}${cell(a.generator,'mono')}${cell(a.boundary)}</tr>`).join('');document.getElementById('report-body').innerHTML=data.required_reports.filter(match).map(r=>`<tr>${cell(r.id,'mono')}${cell(r.title)}${cell(r.status,'status')}${cell(r.required_evidence)}${cell(r.closure_gate,'mono')}</tr>`).join('');document.getElementById('evidence-body').innerHTML=data.evidence_requirements.filter(match).map(e=>`<tr>${cell(e.open_issue,'mono')}${cell(e.area)}${cell(e.authority)}${cell(e.required_attachment)}${cell(e.required_metadata)}${cell(e.acceptance_gate)}${cell(e.repository_support,'mono')}${cell(e.status,'status')}</tr>`).join('');document.getElementById('tool-body').innerHTML=data.tool_commands.filter(match).map(t=>`<tr>${cell(t.id,'mono')}${cell(t.title)}${cell(t.command,'mono')}${cell(t.output,'mono')}</tr>`).join('');}function show(view){views.forEach(v=>document.getElementById(v).classList.toggle('hidden',v!==view));document.querySelectorAll('[data-view]').forEach(b=>b.setAttribute('aria-pressed',String(b.dataset.view===view)));}function download(name,type,text){const blob=new Blob([text],{type});const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=name;a.click();URL.revokeObjectURL(a.href);}document.querySelectorAll('[data-view]').forEach(b=>b.addEventListener('click',()=>show(b.dataset.view)));document.getElementById('download-json').addEventListener('click',()=>download('hyperion-certification-report-pack.json','application/json',JSON.stringify(data,null,2)));document.getElementById('download-md').addEventListener('click',()=>download('hyperion-certification-report-pack.md','text/markdown',markdown));q.addEventListener('input',render);render();");
    out.push_str("</script></body></html>\n");
    out
}

fn push_report_artifact_json(out: &mut String, artifact: &ReportArtifact) {
    out.push('{');
    push_json_str(out, "id", artifact.id);
    out.push(',');
    push_json_str(out, "title", artifact.title);
    out.push(',');
    push_json_str(out, "path", artifact.path);
    out.push(',');
    push_json_str(out, "category", artifact.category);
    out.push(',');
    push_json_str(out, "generator", artifact.generator);
    out.push(',');
    push_json_str(out, "status", artifact.status);
    out.push(',');
    push_json_str(out, "boundary", artifact.boundary);
    out.push('}');
}

fn push_required_report_json(out: &mut String, report: &RequiredReport) {
    out.push('{');
    push_json_str(out, "id", report.id);
    out.push(',');
    push_json_str(out, "title", report.title);
    out.push(',');
    push_json_str(out, "status", report.status);
    out.push(',');
    push_json_str(out, "required_evidence", report.required_evidence);
    out.push(',');
    push_json_str(out, "closure_gate", report.closure_gate);
    out.push('}');
}

fn push_evidence_requirement_json(out: &mut String, requirement: &EvidenceRequirement) {
    out.push('{');
    push_json_str(out, "open_issue", requirement.open_issue);
    out.push(',');
    push_json_str(out, "area", requirement.area);
    out.push(',');
    push_json_str(out, "authority", requirement.authority);
    out.push(',');
    push_json_str(out, "required_attachment", requirement.required_attachment);
    out.push(',');
    push_json_str(out, "required_metadata", requirement.required_metadata);
    out.push(',');
    push_json_str(out, "acceptance_gate", requirement.acceptance_gate);
    out.push(',');
    push_json_str(out, "repository_support", requirement.repository_support);
    out.push(',');
    push_json_str(out, "status", requirement.status);
    out.push('}');
}

fn push_tool_command_json(out: &mut String, tool: &ToolCommand) {
    out.push('{');
    push_json_str(out, "id", tool.id);
    out.push(',');
    push_json_str(out, "title", tool.title);
    out.push(',');
    push_json_str(out, "command", tool.command);
    out.push(',');
    push_json_str(out, "output", tool.output);
    out.push('}');
}

fn push_json_str(out: &mut String, key: &str, value: &str) {
    push_json_key(out, key);
    push_json_string(out, value);
}

fn push_json_number(out: &mut String, key: &str, value: u64) {
    push_json_key(out, key);
    out.push_str(&value.to_string());
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

fn push_html_text(out: &mut String, value: &str) {
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            _ => out.push(ch),
        }
    }
}

fn hex_nibble(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        10..=15 => (b'a' + value - 10) as char,
        _ => '0',
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_pack_json_lists_artifacts_reports_and_tools_without_approval_claims() {
        let json = certification_report_pack_json(2);

        assert!(json.contains("\"type\":\"certification-report-pack\""));
        assert!(json.contains("\"abi_version\":2"));
        assert!(json.contains("docs/prelab_quality_gates.json"));
        assert!(json.contains("CERT-REPORT-COVERAGE"));
        assert!(json.contains("krn_certification_report_ui"));
        assert!(json.contains("krn_basic_pos"));
        assert!(json.contains("CERT-OPEN-011"));
        assert!(!json.contains("certified\":true"));
    }

    #[test]
    fn report_ui_embeds_downloadable_json_and_markdown() {
        let html = certification_report_ui_html(2);

        assert!(html.contains("Hyperion Certification Workbench"));
        assert!(html.contains("download-json"));
        assert!(html.contains("report-data"));
        assert!(html.contains("Repository Artifacts"));
        assert!(html.contains("Required External Reports"));
        assert!(html.contains("Tool Commands"));
        assert!(html.contains("docs/prelab_apdu_trace_pack.jsonl"));
    }

    #[test]
    fn report_markdown_is_table_shaped_and_scoped() {
        let markdown = certification_report_markdown(2);

        assert!(markdown.contains("# Hyperion Certification Report Pack"));
        assert!(
            markdown.contains("| ID | Title | Category | Path | Status | Generator | Boundary |")
        );
        assert!(markdown.contains("pending external attachment"));
        assert!(markdown.contains("cargo run --quiet --example krn_basic_pos"));
    }
}
