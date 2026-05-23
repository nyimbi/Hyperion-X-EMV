# Hyperion EMV Tutorial Series

This directory is the educational path for engineers, fintech builders,
reviewers, and test contributors who need to understand what an EMV kernel is,
where Hyperion fits, and what remains before certification.

The tutorials are written as implementation-aware guides. They do not replace
licensed EMVCo, scheme, acquirer, PCI PTS, device, or laboratory documents.
When a licensed source, scheme profile, lab result, or approval artifact
conflicts with these tutorials, the external authority prevails.

## Learning Path

Read these in order if you are new to EMV kernels:

1. [What Is An EMV Kernel?](01-what-is-an-emv-kernel.md)
2. [Where The Kernel Fits In The Payment Stack](02-payment-stack.md)
3. [Transaction Flow Tutorial](03-transaction-flow.md)
4. [Hyperion Architecture](04-hyperion-architecture.md)
5. [Using Hyperion-X-EMV](05-using-hyperion.md)
6. [Certification And Evidence](06-certification-and-evidence.md)
7. [Testing And Contribution Playbook](07-testing-and-contribution.md)
8. [Glossary](glossary.md)

## Who This Is For

- Fintech teams evaluating whether to build on a shared EMV foundation.
- Terminal, reader, and POS integrators wiring a kernel into device software.
- Test engineers creating APDU traces, malformed inputs, and regression cases.
- Security reviewers checking trust boundaries and sensitive-data custody.
- Certification coordinators assembling lab submission evidence.
- Contributors who want to improve Hyperion without copying code or importing
  unlicensed certification material.

## What You Should Know First

You do not need to be an EMV expert before reading. The early tutorials define
the basic terms: ICC, APDU, AID, TLV, DOL, CVM, TVR, TSI, ARQC, TC, AAC, CAPK,
and Level 1 / Level 2 / Level 3 boundaries.

You should be comfortable with:

- Reading structured technical documentation.
- Running Cargo commands for Rust projects.
- Understanding that certification is evidence-driven, not claim-driven.
- Keeping licensed standards, scheme materials, CAPKs, lab vectors, and device
  approval artifacts separate from MIT-licensed repository source.

## Current Hyperion Position

Hyperion-X-EMV is an engineering baseline for a Rust EMV Level 2 kernel. It is
not a final certification claim. The repository includes source code, tests,
controlled annexes, evidence generators, masked trace fixtures, and open issue
tracking. Final certification still requires recognized lab execution, signed
profiles, accepted CAPKs, device and L1 evidence, PCI/PED evidence, test-tool
reports, and approval artifacts.

## How To Use This Directory

Use the tutorials for orientation and implementation context. Use the canonical
project documents for controlled requirements and evidence:

- `docs/spec.md`: current kernel specification.
- `docs/eng_notes.md`: engineering notes and certification boundaries.
- `docs/lab_submission_manifest.md`: draft lab submission checklist.
- `docs/certification_open_issues.md`: external blockers.
- `docs/requirements_traceability.csv`: requirement-to-evidence mapping.
- `README.md`: quick project overview and local commands.

