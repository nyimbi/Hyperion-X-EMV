# Hyperion Certification Artifact Import Plan

- Kernel version: 0.1.0
- ABI version: 2
- Scope: format-agnostic adapters for real lab, scheme, CAPK, vector, device, and report artifacts
- Boundary: hash inventory and intake normalization only; external authorities still decide acceptance.

## Adapter Lanes
| Adapter | Input Directory | Slot | Open Issues | Accepted Extensions | Required Metadata | Security Policy |
| --- | --- | --- | --- | --- | --- | --- |
| Lab and approval artifacts | `lab` | `CERT-OPEN-001` | CERT-OPEN-001, CERT-OPEN-011 | csv, json, md, pdf, txt, xml | authority, approval_reference, claimed_interface, submitted_binary_hash, profile_hash | accept public approval, report, and conformance records only; private signing material is rejected |
| Scheme and acquirer profile data | `scheme` | `CERT-OPEN-002` | CERT-OPEN-002, CERT-OPEN-005, CERT-OPEN-012 | csv, json, md, txt, xml | scheme, authority, retrieval_date, profile_version, signature_status | accept signed or countersigned public profile material; do not import issuer secrets or private keys |
| CAPK authority data | `capk` | `CERT-OPEN-003` | CERT-OPEN-003, CERT-OPEN-004 | csv, json, md, pem, txt, xml | rid, key_index, source, retrieval_date, expiry_date, checksum | accept public CAPK provenance and checksum material only; private key containers are rejected |
| Lab vector and expected-output data | `vectors` | `CERT-OPEN-004` | CERT-OPEN-004, CERT-OPEN-009, CERT-OPEN-012 | csv, json, md, txt, xml | vector_class, vector_source, tool_version, method_coverage, expected_outputs | accept complete vector data and expected outcomes; scenario summaries remain advisory until vectors validate |
| Device, L1, and PED evidence | `device` | `CERT-OPEN-006` | CERT-OPEN-006, CERT-OPEN-007 | csv, json, md, pdf, txt, xml | device_model, hardware_revision, firmware_version, l1_reference, pci_pts_reference | accept device, reader, L1, and PED evidence; clear PIN data and private material are never accepted |
| Coverage, integration, static, fuzz, trace, and security reports | `reports` | `CERT-OPEN-009` | CERT-OPEN-008, CERT-OPEN-009, CERT-OPEN-010, CERT-OPEN-012 | csv, html, json, lcov, md, pdf, sarif, txt, xml | tool_version, command, submitted_binary_hash, profile_hash, finding_disposition | accept masked reports and trace packs; unmasked PAN, PIN, cryptogram, or issuer-script payload evidence must remain external |
