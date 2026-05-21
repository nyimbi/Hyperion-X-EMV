# Lab Submission Manifest – Hyperion EMV Kernel v6.0 (Draft for Certification)

## Product Information
- **Product Name:** Hyperion EMV Kernel
- **Version:** 6.0
- **Vendor:** Hyperion-X
- **Target Device:** Hyperion MP35P terminal and certified contactless readers
- **Submission Date:** [To be filled by lab]

## Certification Scope
- **EMV Level 2 Contact:** Yes (Visa, Mastercard); Amex and Discover require lab-supplied signed profiles before claim
- **EMV Level 2 Contactless (C‑8):** Yes (unified kernel approval package; profile data supplied by lab)
- **PCI PTS POI v7.0 alignment:** Yes (via PED integration statement)

## Attached Artifacts
- [x] Specification document (v6.0, this file)
- [x] Bitmap catalogue (`bitmap_catalogue.csv`) – canonical TVR/TSI symbolic bit mapping with RFU masks
- [x] Performance profile (`performance_profile.csv`) – product-level certification timing buckets and targets
- [x] TLV catalogue (`tlv_catalogue.csv`) – complete with 58 tags and required 10-column schema
- [x] State machine table (`state_machine.csv`) – expanded to 85 rows, properly quoted
- [x] ODA test vectors (`oda_test_vectors.json`) – syntactically validated with deterministic unit fixtures; lab-supplied SDA/DDA/CDA vectors still required for final certification
- [x] Scheme profiles (`scheme_profiles.cert.json`) – structured with valid hex lengths, contains deterministic TAA keys; actual CAPK values to be replaced by lab
- [x] Requirement traceability matrix (`requirements_traceability.csv`) – mapped to EMVCo test case categories
- [x] Trace identity metadata – masked APDU logs retain ABI version and signed profile version
- [x] Reproducible build provenance – `cargo run --example krn_build_manifest -- ...` emits canonical JSON with SHA-256 for source, lockfile, annexes, and binary artifacts
- [x] Source code (under NDA)
- [ ] Unit test report (≥95% coverage) – [to be attached]
- [ ] Integration test report (100% of EMV test plan) – [to be attached]
- [ ] Static analysis report (MISRA C compliant) – [to be attached]
- [ ] Fuzzing report (1M iterations, no crashes) – [to be attached]
- [ ] PCI PTS integration statement (Model A – PED‑owned VERIFY) – [to be attached]
- [x] Conformance statement (ABI JSON) – `krn_get_conformance_statement_json` emits deterministic KRN-REF-001 JSON for the ABI build
- [ ] Conformance statement (signed EMVCo/lab template) – [to be attached]
- [ ] APDU trace logs (masked) for all test cases – [to be attached]

## Test Tool Configuration
- **EMVCo L2 Contact Test Tool:** Fime Eval4dev v3.2 (or equivalent)
- **EMVCo Contactless C‑8 Test Harness:** EMVCo‑certified v1.0
- **Test Environment:** Hyperion test terminal with simulated cards (e.g., Fime MPS8)

## Certification Contact
- **Engineer:** [Name to be filled]
- **Email:** [email to be filled]

## Declaration
This document serves as a **certification baseline template**. All artifacts are structurally complete and syntactically correct, with deterministic executable fixtures where bundled. Lab-supplied cryptographic values, CAPKs, and scheme certification vectors must be supplied during the submission process. The kernel implementation has been developed in accordance with EMV Contact Chip Specifications v4.4 and EMV Contactless Kernel Specification Book C‑8 v1.0.
