# Hyperion Certification Bundle Compile Report

- Status: `warn`
- Mode: `certification`
- Bundle SHA-256: `e07e62a9a62e21b34e12df559421f193a5398ffc2af68da9d280ba4278613f9d`
- Payload SHA-256: `5d0e03b2dc65006c22a88bfefa1a1d16d65713650dabc92445d397b4be911ebd`
- Verification status: `trust-anchor-verified`

## Findings

- `warning` `terminal_profile.device_model`: External evidence placeholder remains Suggestion: Attach the lab, scheme, L1, device, PCI/PED, or acquirer evidence and update this field with the accepted reference.
- `warning` `terminal_profile.firmware_version`: External evidence placeholder remains Suggestion: Attach the lab, scheme, L1, device, PCI/PED, or acquirer evidence and update this field with the accepted reference.
- `warning` `terminal_profile.l1_approval_reference`: External evidence placeholder remains Suggestion: Attach the lab, scheme, L1, device, PCI/PED, or acquirer evidence and update this field with the accepted reference.
- `warning` `terminal_profile.pci_pts_reference`: External evidence placeholder remains Suggestion: Attach the lab, scheme, L1, device, PCI/PED, or acquirer evidence and update this field with the accepted reference.
- `warning` `submission_scope.authorities[1]`: External evidence placeholder remains Suggestion: Attach the lab, scheme, L1, device, PCI/PED, or acquirer evidence and update this field with the accepted reference.
- `warning` `submission_scope.authorities[2]`: External evidence placeholder remains Suggestion: Attach the lab, scheme, L1, device, PCI/PED, or acquirer evidence and update this field with the accepted reference.
- `warning` `trust_anchors[0].verification_secret_hex`: Fixture signing secret is still present Suggestion: Generate and custody a submission-specific trust anchor outside the repository fixture.
- `info` `bundle`: Bundle compiled and authenticated Suggestion: Keep the bundle, trust anchors, fingerprints, reports, and submitted binary hash together in the certification pack.

## EMV Capability Coverage

| ID | Area | Status | Bundle Source | Role |
| --- | --- | --- | --- | --- |
| selection | Application selection | covered | `payload.scheme_profile_set_json.schemes[].aids` | Selects PSE/PPSE, matches configured AIDs, and keeps scheme choice data-driven. |
| contact_l2 | Contact EMV L2 | covered | `payload.submission_scope.interfaces + scheme_profile_set_json` | Binds contact interface, contact kernel type, TAC/IAC, DOL, CVM, TRM, and scripts to profile data. |
| contactless_c8 | Contactless Kernel C-8 | covered | `payload.kernel_registry + scheme_profile_set_json` | Binds contactless scope to C-8 package data, TTQ/CVM limits, relay resistance, and masked traces. |
| capk_authority | CAPK authority data | covered | `payload.scheme_profile_set_json.schemes[].capks` | Supplies RID/index public keys, expiry, checksums, and provenance for ODA validation. |
| oda_vectors | SDA/DDA/CDA and ODA vectors | covered | `payload.vector_bundle_json + payload.artifact_hashes` | Binds cryptographic vector evidence and CDA request behavior to bundle hashes. |
| cvm_pin | CVM and PIN integration | covered | `payload.cvm_extensions + scheme_profile_set_json.aids` | Controls CVM limits, CDCVM support, extension codes, and PED-owned offline PIN behavior. |
| trm | Terminal risk management | covered | `payload.scheme_profile_set_json.aids[].trm` | Drives floor limits, random selection, transaction type limits, and offline counters from profile data. |
| taa | Terminal action analysis | covered | `payload.scheme_profile_set_json.schemes[].taa` | Keeps TAC/IAC policy in signed profile data rather than compiled constants. |
| issuer_scripts | Issuer script handling | covered | `payload.scheme_profile_set_json.aids[].critical_issuer_script_ins` | Defines which issuer script INS values are critical for post-authorization handling. |
| relay_resistance | Relay resistance | warning | `payload.scheme_profile_set_json.aids[].relay_resistance` | Controls contactless relay resistance behavior where required by scheme/profile. |
| runtime_abi | Runtime ABI and timeouts | covered | `payload.runtime_policy.callback_timeouts` | Sets APDU, host authorization, PIN entry, and contactless UI callback bounds from bundle data. |
| security_trust | Signature, trust, and anti-rollback | covered | `signature + trust_anchors + rollback_counter` | Authenticates bundle payloads, enforces rollback counters, and records verification status. |
| device_l1 | Device and L1 evidence | external_required | `payload.terminal_profile` | Binds target device, firmware, interface, and L1 approval references to the bundle. |
| pci_ped | PCI/PED evidence | external_required | `payload.terminal_profile.pci_pts_reference` | Records PED/PIN custody evidence for CVM and offline PIN integration. |
| standards_bulletins | Standards and bulletins | covered | `payload.standards_target` | Captures contact/contactless target versions and bulletin inclusions/exclusions as data. |
| evidence_freeze | Evidence freeze and reports | covered | `payload.test_plan + payload.artifact_hashes` | Binds test plan, artifact hashes, fingerprints, and report pack outputs for reproducible submissions. |
| trace_privacy | Trace privacy | covered | `payload.runtime_policy.trace_masking_policy` | Requires masked APDU traces and prevents sensitive data from becoming report content. |

Boundary: this report proves repository loader compatibility and data coverage. It does not replace external EMVCo, scheme, laboratory, device, L1, PCI/PED, or acquirer evidence.
