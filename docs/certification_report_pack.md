# Hyperion Certification Report Pack

- Kernel version: 0.1.0
- ABI version: 2
- Scope: repository-controlled report production and certification preparation

## Repository Artifacts
| ID | Title | Category | Path | Status | Generator | Boundary |
| --- | --- | --- | --- | --- | --- | --- |
| SPEC | Kernel specification | requirements | `docs/spec.md` | repository-controlled | `human-controlled annex` | licensed standards prevail on conflict |
| RTM | Requirement traceability matrices | requirements | `docs/requirements_traceability.csv; docs/requirements-traceability-matrix.csv` | repository-controlled | `traceability tests` | lab test-case crosswalk remains external |
| MANIFEST | Lab submission manifest | submission | `docs/lab_submission_manifest.md` | repository-controlled template | `human-controlled annex` | unattached report rows remain open |
| OPEN-ISSUES | Certification open issues | submission | `docs/certification_open_issues.md` | repository-controlled | `human-controlled register` | controls external blockers |
| ABI | ABI conformance statement | conformance | `docs/abi_conformance_statement.json` | generated | `cargo run --quiet --example krn_abi_conformance_statement` | not a signed lab conformance template |
| PROFILE-DICTIONARY | Scheme profile dictionary | configuration | `docs/scheme_profile_dictionary.md` | generated | `cargo run --quiet --example krn_scheme_profile_dictionary` | does not disclose raw CAPK modulus material |
| TRACE-PACK | Masked pre-lab APDU trace fixture | trace | `docs/prelab_apdu_trace_pack.jsonl` | generated | `cargo run --quiet --example krn_prelab_trace_pack` | full lab trace pack remains external |
| QUALITY-GATES | Pre-lab quality gate manifest | quality | `docs/prelab_quality_gates.json` | generated | `cargo run --quiet --example krn_prelab_quality_gates` | coverage and formal reports remain external |
| NO-CRASH | Parser/APDU no-crash smoke artifact | quality | `docs/prelab_no_crash_smoke.json` | generated | `cargo run --quiet --example krn_prelab_no_crash_smoke` | not a fuzzing report |
| STATIC-FUZZ-PLAN | Static and fuzz evidence plan | quality | `docs/prelab_static_fuzz_plan.json` | generated | `cargo run --quiet --example krn_prelab_static_fuzz_plan` | plan only; accepted reports remain external |
| FUZZ-SEEDS | Fuzz seed corpus manifest | quality | `docs/prelab_fuzz_seed_corpus.json` | generated | `cargo run --quiet --example krn_prelab_fuzz_seed_corpus` | hash-only synthetic seed evidence |
| STANDARDS-WATCH | Public standards watch | drift | `docs/public_standards_watch.json` | generated | `cargo run --quiet --example krn_public_standards_watch` | public drift signal only |
| REPORT-PACK | Certification report pack | reporting | `docs/certification_report_pack.json; docs/certification_report_pack.md` | generated | `cargo run --quiet --example krn_certification_report_ui` | index only; external report attachments remain required |
| REPORT-UI | Certification report workbench | reporting | `docs/certification_report_ui.html` | generated | `cargo run --quiet --example krn_certification_report_ui -- --html` | static local UI; not a lab portal or approval system |
| COVERAGE-WORKFLOW | 100% coverage workflow | quality | `docs/coverage.md; scripts/coverage_100.sh` | prepared | `scripts/coverage_100.sh` | accepted submitted-build report remains external |
| TUTORIALS | Tutorial and glossary learning path | education | `docs/tutorial/` | repository-controlled | `human-controlled docs` | education only; not approval evidence |

## Required External Reports
| ID | Title | Status | Required Evidence | Closure Gate |
| --- | --- | --- | --- | --- |
| CERT-REPORT-COVERAGE | 100% unit coverage report | pending external attachment | submitted commit, tool versions, target, feature set, and HTML/XML or lab-accepted report | CERT-OPEN-009 |
| CERT-REPORT-INTEGRATION | Full EMV integration report | pending external attachment | test-tool version, profile set, device firmware, APDU traces, outcomes, deviations, and disposition | CERT-OPEN-009 |
| CERT-REPORT-STATIC | Static-analysis report | pending external attachment | accepted tool version, command lines, findings, remediations, and residual-risk acceptance | CERT-OPEN-010 |
| CERT-REPORT-FUZZ | Fuzzing/no-crash report | pending external attachment | engine versions, corpus hashes, run budgets, coverage/path metrics, crashes, and dispositions | CERT-OPEN-010 |
| CERT-REPORT-CONFORMANCE | Signed conformance template and approval artifact | pending external attachment | recognized lab or authority-signed template tied to submitted binary, profile, and device scope | CERT-OPEN-011 |
| CERT-REPORT-DEVICE | Device, L1, and PCI/PED evidence | pending external attachment | target device approval, reader/L1 evidence, and PCI PTS/PED integration statement | CERT-OPEN-006; CERT-OPEN-007 |

## Tool Commands
| ID | Title | Command | Output |
| --- | --- | --- | --- |
| UI | Generate certification workbench UI | `cargo run --quiet --example krn_certification_report_ui -- --out target/hyperion-cert-ui` | `target/hyperion-cert-ui/index.html` |
| REPORT-JSON | Emit report-pack JSON | `cargo run --quiet --example krn_certification_report_ui -- --json` | `stdout JSON` |
| REPORT-MD | Emit report-pack Markdown | `cargo run --quiet --example krn_certification_report_ui -- --markdown` | `stdout Markdown` |
| POS | Run basic scripted PoS integration | `cargo run --quiet --example krn_basic_pos` | `stdout JSON transaction summary` |
