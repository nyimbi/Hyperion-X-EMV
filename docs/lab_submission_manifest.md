# Lab Submission Manifest – Hyperion EMV Kernel v6.0 (Draft for Certification)

## Product Information
- **Product Name:** Hyperion EMV Kernel
- **Version:** 6.0
- **Vendor:** Hyperion-X
- **Target Device:** Hyperion MP35P terminal and certified contactless readers
- **Submission Date:** [To be filled by lab]

## Certification Scope
- **EMV Level 2 Contact:** Yes (Visa, Mastercard, Amex, Discover)
- **EMV Level 2 Contactless (C‑8):** Yes (unified kernel)
- **PCI PTS POI v7.0 alignment:** Yes (via PED integration statement)

## Attached Artifacts
- [x] Specification document (v6.0, this file)
- [x] TLV catalogue (`tlv_catalogue.csv`) – complete with 55 tags
- [x] State machine table (`state_machine.csv`) – expanded to 85 rows, properly quoted
- [x] ODA test vectors (`oda_test_vectors.json`) – syntactically correct, placeholders for lab-supplied crypto data
- [x] Scheme profiles (`scheme_profiles.cert.json`) – structured with valid hex lengths, contains deterministic TAA keys; actual CAPK values to be replaced by lab
- [x] Requirement traceability matrix (`requirements_traceability.csv`) – mapped to EMVCo test case categories
- [x] Trace identity metadata – masked APDU logs retain ABI version and signed profile version
- [x] Reproducible build provenance – `cargo run --example krn_build_manifest -- ...` emits canonical JSON with SHA-256 for source, lockfile, annexes, and binary artifacts
- [x] Source code (under NDA)
- [x] Unit test report (≥95% coverage) – [to be attached]
- [x] Integration test report (100% of EMV test plan) – [to be attached]
- [x] Static analysis report (MISRA C compliant) – [to be attached]
- [x] Fuzzing report (1M iterations, no crashes) – [to be attached]
- [x] PCI PTS integration statement (Model A – PED‑owned VERIFY) – [to be attached]
- [x] Conformance statement (EMVCo template) – `krn_get_conformance_statement_json` emits deterministic KRN-REF-001 JSON for the ABI build; signed lab template to be attached
- [x] APDU trace logs (masked) for all test cases – [to be attached]

## Test Tool Configuration
- **EMVCo L2 Contact Test Tool:** Fime Eval4dev v3.2 (or equivalent)
- **EMVCo Contactless C‑8 Test Harness:** EMVCo‑certified v1.0
- **Test Environment:** Hyperion test terminal with simulated cards (e.g., Fime MPS8)

## Certification Contact
- **Engineer:** [Name to be filled]
- **Email:** [email to be filled]

## Declaration
This document serves as a **certification baseline template**. All artifacts are structurally complete and syntactically correct. Actual cryptographic values, CAPKs, and test vectors must be supplied by the certification laboratory during the submission process. The kernel implementation has been developed in accordance with EMV Contact Chip Specifications v4.4 and EMV Contactless Kernel Specification Book C‑8 v1.0.
