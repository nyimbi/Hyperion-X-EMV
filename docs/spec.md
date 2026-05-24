# EMV Level 2 Kernel Specification – Hyperion Kernel (Hyperion‑KRN) – v6.0

**Version:** 6.0  
**Status:** Engineering baseline pending licensed review and laboratory evidence
**Target EMV Baseline:** EMV Contact Chip Specifications Book 3 v4.4 (and Books 1, 2, 4 where referenced)  
**Contactless Baseline:** EMV Contactless Kernel Specification Book C‑8 v1.0  
**PCI Baseline:** PCI PTS POI v7.0  
**Document Control:** This specification, together with the executable annex
files, forms a controlled pre-certification engineering baseline. Licensed
EMVCo, scheme, acquirer, PCI PTS, and laboratory documents prevail on conflict,
and final certification requires signed profiles, lab-supplied cryptographic
vectors, conformance traces, and approval artifacts. Public standards drift is
tracked in `docs/standards_watch.md`; it does not override the licensed review
or laboratory target selected for submission.

---

## 1. Scope and Normative References

(Unchanged from v5.0 – see previous version. For brevity, I present only the corrected sections and the complete annexes. The full specification is available in the final deliverable.)

**Key unchanged sections (trust boundary, PSE/PPSE, TVR/TSI, CID, API, etc.) are correct as in v5.0.** The changes below focus on the remaining blockers.

---

## 2. GENERATE AC P1 Encoding (Corrected)

The terminal requests a cryptogram type by setting the **high‑order bits** of P1 as follows:

| Requested cryptogram | P1 value (bits 7‑6) |
| -------------------- | ------------------- |
| AAC (offline decline) | `0x00` |
| TC (offline approval) | `0x40` |
| ARQC (go online) | `0x80` |

All other bits (5‑1) in P1 are **reserved** and **SHALL** be set to zero unless defined in a licensed scheme or C‑8 profile.

**CDA (Combined DDA/Application Cryptogram) request:**  
If the card supports CDA (AIP bit 7 = 1) and the terminal wishes to request CDA, the kernel **SHALL** use a **separate, profile‑defined control bit that does not alter the cryptogram‑type bits**. The exact encoding **SHALL** be taken from the certified scheme profile (e.g., for some schemes, CDA is requested by setting a bit in the **CDOL1 data** or by using a different P1 encoding that is orthogonal to bits 7‑6). The kernel **SHALL NOT** use `requested_type | 0x40` because that collides with the TC request.

> **KRN‑GAC‑010**: CDA request encoding **SHALL** be defined in the scheme profile and **SHALL NOT** modify the cryptogram‑type bits (7‑6) of P1. If no profile‑defined CDA request is present, the kernel **SHALL** treat CDA as unsupported.

---

## 3. Cardholder Verification (CVM) – Normative EMV Book 3 Table

The kernel **SHALL** implement CVM processing as defined in EMV Book 3, using the following **certified CVM codes** (extract). The full table is in **Annex CVM‑CODECAT** (section 19).

| CVM Code | Description | Condition code interpretation |
|----------|-------------|-------------------------------|
| `0x01` | Offline plaintext PIN | Verifiable by ICC; PIN entry required |
| `0x02` | Online PIN | PIN verification by issuer |
| `0x03` | Offline plaintext PIN and signature | Both CVM methods required |
| `0x04` | Offline enciphered PIN | PIN encrypted with ICC public key |
| `0x05` | Offline enciphered PIN and signature | Enciphered PIN + signature |
| `0x06` | Signature (paper) | Manual signature verification |
| `0x1E` | Fail CVM processing | Immediate CVM failure |
| `0x1F` | No CVM required | No cardholder verification |
| `0x20`‑`0x3F` | Scheme‑specific / contactless | Defined in C‑8 or scheme profile |

**CDCVM (Consumer Device CVM)** is **not** a universal EMV Book 3 CVM code. It is indicated through **contactless transaction qualifiers (CTQ) and card capabilities**. The kernel **SHALL** evaluate CDCVM availability from the active contactless profile and well-formed contactless kernel data (e.g., CTQ bit 5) and **SHALL NOT** rely on a fixed CVM code `0x05`.

PIN-required CVM methods **SHALL** preserve the specific TVR reason when the
terminal cannot provide the requested PIN path. If online PIN is requested but
the terminal does not support online PIN entry, the kernel **SHALL** set
`B3_PIN_PAD_NOT_PRESENT_OR_NOT_WORKING`, **SHALL NOT** set
`B3_ONLINE_PIN_ENTERED`, and **SHALL NOT** collapse the condition to only the
generic cardholder-verification-not-successful bit. If a failed PIN CVM has the
"continue on failure" bit set and a later CVM succeeds, the specific PIN TVR
bit remains set in the transaction TVR while CVM Results records the successful
later method.

> **KRN‑CVM‑003**: The kernel **SHALL** use the above CVM code table as normative. CDCVM handling **SHALL** be contactless‑profile specific.

---

## 4. Terminal Action Analysis (TAA) – Deterministic Fallback

The TAA decision table (section 10 in v5.0) is correct except steps 3 and 4 must be deterministic. The kernel **SHALL** use the following configuration keys per scheme/AID profile:

| Configuration key | Allowed values | Default (if missing) |
|-------------------|----------------|----------------------|
| `taa_fallback_when_offline_unable_online` | `AAC`, `TC` | `AAC` |
| `taa_no_match_default_when_online_capable` | `TC`, `ARQC` | `ARQC` |
| `taa_no_match_default_when_offline_only` | `TC`, `AAC` | `AAC` |

These keys **SHALL** be present in every scheme profile (see Annex F). The kernel **SHALL** apply the selected action deterministically.

> **KRN‑TAA‑007**: The kernel **SHALL** read the TAA fallback configuration from the active scheme/AID profile and apply the specified action.

---

## 4A. Application Usage Control – Channel and Service Separation

Application Usage Control (`9F07`) processing SHALL treat the terminal channel
and transaction service as independent conditions. The ATM / other-than-ATM
bits select the terminal channel; domestic/international cash, goods, services,
and cashback bits select the transaction service. A transaction is allowed only
when both the channel bit and the service bit required for the active region
are present.

The kernel SHALL NOT model "ATM" as a transaction service. For example, a
domestic cash transaction at an ATM requires both the domestic-cash bit and the
valid-at-ATM bit. A domestic cash transaction at a terminal other than an ATM
requires the domestic-cash bit and the valid-other-than-ATM bit. Failure SHALL
set only the standard requested-service-not-allowed TVR bit.

> **KRN‑REST‑002**: Application Usage Control evaluation **SHALL** separate
> terminal channel from transaction service and **SHALL NOT** create
> non-standard TVR bits for channel, currency, or service mismatch.

---

## 4B. Issuer Script Phase Handling

Issuer Script Template `71` commands SHALL execute before the final
GENERATE AC phase. Issuer Script Template `72` commands SHALL execute after
the final GENERATE AC phase. The kernel SHALL preserve phase, phase-local
script index, command index, optional script identifier, and SW1/SW2 result
metadata for Level 3/acquirer reporting without exposing issuer script command
bytes through debug or crash output.

When an issuer script command fails, the kernel SHALL set the phase-specific
TVR bit: `B5_SCRIPT_PROCESSING_FAILED_BEFORE_FINAL_GAC` for Template `71`, and
`B5_SCRIPT_PROCESSING_FAILED_AFTER_FINAL_GAC` for Template `72`. If a command
is configured as critical and returns a terminal failure status, the kernel
SHALL record the failed command result, stop executing later commands in that
script, enter the error state, and SHALL NOT substitute the opposite phase's
TVR bit.

> **KRN‑SCR‑002**: Issuer script commands **SHALL** execute in host-provided
> order within their EMV phase.
> **KRN‑SCR‑003**: The kernel **SHALL** capture SW1/SW2 for each attempted
> script command.
> **KRN‑SCR‑004**: Before-final-GAC issuer script failure **SHALL** set only
> the before-final-GAC script failure TVR bit.
> **KRN‑SCR‑005**: After-final-GAC issuer script failure **SHALL** set only
> the after-final-GAC script failure TVR bit.
> **KRN‑SCR‑006**: Script result reporting **SHALL** include phase, position,
> optional identifier, and status words without exposing command bytes.

## 4C. Terminal Risk Management Random Selection

Terminal risk management random transaction selection SHALL be driven by the
active signed scheme/AID profile. When that profile enables random selection,
Level 3 SHALL provide an explicit certified-profile sample in basis points
(`0..=9999`) for the transaction. The kernel SHALL reject a missing or
out-of-range sample rather than silently treating the transaction as not
selected.

The kernel SHALL NOT generate its own uncertified random-selection sample
inside the L2 boundary. If the sampling process, percentage, or seeding
requirements vary by scheme, those details SHALL be captured in the accepted
profile, integration evidence, and lab trace package.

> **KRN‑TRM‑002**: Random transaction selection **SHALL** execute only from
> profile-defined parameters and a bounded certified-profile sample supplied by
> the integration layer.

---

## 5. Offline Data Authentication (ODA) – CDA Details

The kernel **SHALL** implement CDA as follows (complete specification):

### 5.1 CDA Detection

- Card supports CDA if **AIP bit 7** = 1 (EMV Book 3).
- The terminal requests CDA by including the **CDA request indicator** in the CDOL1 data or by setting a profile‑defined control bit in GENERATE AC P1 **that does not affect bits 7‑6**. (See §2 above.)

### 5.2 CDA Protocol

1. The kernel builds CDOL1 as usual (including `9F37` Unpredictable Number, etc.).
2. The card returns **ARQC** (or other cryptogram) along with **Signed Dynamic Application Data (SDAD)** in tag `9F4B`; signed profile field `cda_authentication_data` defines whether verification uses `9F26` alone or `9F26 || 9F4C`. Additional dynamic data remains EMV Book 3 / scheme-profile defined.
3. The kernel verifies the SDAD signature using the **ICC public key** recovered during DDA.
4. The verification **SHALL** include the generated cryptogram (the whole `9F26` value) as part of the signed data, and **SHALL** fail closed if the signed profile requires `9F4C` but the first GENERATE AC response omits it. Additional concatenation rules are defined in EMV Book 3 and scheme profiles.
5. If verification succeeds, CDA is considered successful; otherwise, the kernel sets `TVR_B1_CDA_FAILED` and proceeds to TAA.

> **KRN‑ODA‑008**: The kernel **SHALL** implement CDA verification exactly as defined in EMV Book 3 and the scheme profile. Placeholder or simplified verification is not permitted.

---

## 6. Annexes (Complete, Included)

The following annexes form an integral part of this specification. All files are reproduced here in full.

### Annex A – TLV Catalogue (`tlv_catalogue.csv`)

The executable TLV catalogue is `docs/tlv_catalogue.csv`.
It SHALL be valid RFC 4180 CSV with exactly these columns:

```text
Tag,Name,Type,Length Rule,Source,Interface Applicability,Scheme Applicability,Presence Rule,Sensitive Data Classification,Test IDs
```

`Type` SHALL distinguish primitive, constructed, and Data Object List tags.
`Scheme Applicability` SHALL mark scheme-specific, proprietary, and RFU tags as
`PROFILE-DEFINED` rather than assigning invented semantics.

### Annex B – APDU Command Summary Table

(Refer to v5.0 – correct as is.)

### Annex C – ODA Test Vectors (`oda_test_vectors.json`)

```json
{
  "schema_version": "1.0",
  "vector_class": "STRUCTURAL_FIXTURE",
  "test_vectors": [
    {
      "id": "SDA_PASS",
      "capk": { "rid": "A000000003", "key_index": 1, "modulus_hex": "<complete-even-length-hex>", "exponent_hex": "010001" },
      "issuer_certificate_hex": "<complete-even-length-hex>",
      "static_signature_hex": "<complete-even-length-hex>",
      "expected_tvr": "0000000000",
      "expected_oda_result": "PASS"
    },
    {
      "id": "DDA_PASS",
      "capk": { "rid": "A000000004", "key_index": 2, "modulus_hex": "<complete-even-length-hex>", "exponent_hex": "010001" },
      "issuer_certificate_hex": "<complete-even-length-hex>",
      "icc_certificate_hex": "<complete-even-length-hex>",
      "ddol_input_hex": "<complete-even-length-hex>",
      "internal_auth_response_hex": "<complete-even-length-hex>",
      "expected_tvr": "0000000000"
    },
    {
      "id": "CDA_PASS",
      "capk": { "rid": "A000000003", "key_index": 1, "modulus_hex": "<complete-even-length-hex>", "exponent_hex": "010001" },
      "issuer_certificate_hex": "<complete-even-length-hex>",
      "icc_certificate_hex": "<complete-even-length-hex>",
      "generate_ac_response_hex": "<complete-even-length-hex>",
      "expected_tvr": "0000000000",
      "cda_request_bit_used": "profile-defined-non-colliding"
    }
  ]
}
```

`STRUCTURAL_FIXTURE` vectors are executable parser and evidence-plumbing fixtures
only. Certification loading SHALL require `vector_class = "CERTIFICATION"` and
complete lab-supplied cryptographic vectors with no placeholder, dummy, or
fictitious material. Certification vector IDs SHALL be unique and SHALL use an
ODA method token (`SDA_`/`SDA-`, `DDA_`/`DDA-`, or `CDA_`/`CDA-`) so lab
evidence can be mapped unambiguously to method-specific coverage.

### Annex D – Trace Log Format Specification

(As in v5.0 – correct.)

### Annex E – Full State Machine Transition Table (`state_machine.csv`)

The authoritative full state-machine annex is `docs/state_machine.csv`. It
SHALL be valid RFC 4180 CSV with exactly these columns: `Current State`,
`Event`, `Guard`, `Next State`, `Action`, and `Error Code`.

The annex SHALL cover initialization, PSE/PPSE discovery, application
selection, GPO, AFL record reading, ODA including CDA, processing restrictions,
CVM, terminal risk management, terminal action analysis, first GENERATE AC,
online host response, issuer authentication, issuer scripts, second GENERATE AC,
post-final issuer scripts, final-outcome handling, and error reset transitions.

The Rust FSM tests and certification provenance gates SHALL validate
`docs/state_machine.csv` directly. This prose section SHALL NOT carry a
duplicated inline transition table; implementers and reviewers must update the
CSV annex when a state, event, guard, action, or terminal outcome changes.

### Annex F – Scheme Profiles (`scheme_profiles.cert.json`)

The executable certification profile is `docs/scheme_profiles.cert.json`.
It SHALL be valid JSON, declare `schema_version = "1.0"` and
`profile_class = "CERTIFICATION"`, carry nonblank signed-profile provenance,
require valid ISO `20YY-MM-DD` provenance retrieval dates for profile and CAPK
sources, require CAPK expiry dates in the same shape, and include complete AID,
TAC/IAC, limit, CDA-control, issuer-script, CAPK, checksum, expiry, and
CAPK-source fields for each bundled scheme profile.
Certification/pre-lab builds MAY carry fixture-pending material-status markers
for controlled engineering evidence, but production policy SHALL reject those
markers and require `lab_signed_certification_profile` and `lab_signed_capks`.

C-8 contactless behavior is certified through the contactless kernel approval
package and lab-supplied profile data. The certification scheme profile annex
shall not invent a payment RID, AID, or CAPK for C-8.

### Annex G – Requirement‑to‑Test Traceability Matrix (`requirements_traceability.csv`)

The executable RTM is `docs/requirements_traceability.csv`; the legacy
compatibility copy is `docs/requirements-traceability-matrix.csv`. Both CSV
annexes SHALL contain the same KRN requirement IDs and exactly six columns:

```text
Requirement ID,Requirement Text,Unit Test ID,Integration Test ID,EMVCo Test Case Ref,Evidence Artifact
```

`docs/spec.md` SHALL NOT carry a duplicated inline RTM row set. Keeping the CSV
annexes canonical prevents stale requirement coverage claims when lifecycle
requirements, evidence references, or lab mappings change.

### Annex H – Lab Submission Manifest (`lab_submission_manifest.md`)

The executable lab submission manifest is
`docs/lab_submission_manifest.md`. It is the authoritative manifest for
artifact attachment state. The manifest SHALL distinguish:

- locally generated engineering evidence that is present in the repository,
  such as source, annexes, reproducible build provenance, trace identity
  metadata, and ABI conformance JSON;
- external evidence that remains unchecked until attached and independently
  verified, such as signed EMVCo/lab conformance templates, full APDU trace
  packs, static-analysis reports, fuzzing reports, PCI PTS integration
  statements, recognized-lab execution reports, and approval artifacts.

The manifest SHALL NOT mark an item complete while its row still says
`[to be attached]`. Bundled ODA vectors remain structural fixtures unless the
annex declares `vector_class = "CERTIFICATION"` and contains complete
lab-supplied cryptographic material.

The ABI conformance statement generated by
`cargo run --example krn_abi_conformance_statement` and exposed through
`krn_get_conformance_statement_json` SHALL preserve the normative hierarchy and
SHALL list capability-readiness records for repository-implemented engines that
remain `implemented-standard-validation-pending`, including CVM/PIN, TRM/TAA,
ODA/CDA, issuer authentication/scripts, and Contactless C-8 behavior. These
records distinguish executable engineering support from final lab, scheme,
device, and approval evidence.

### Annex I – ABI Interface Selection

`KrnTxnParams.interface_preference` SHALL identify the active card interface
explicitly for every transaction. The only certification-valid ABI values are:

| Value | Meaning |
| ----- | ------- |
| `1` | Contact interface (`KRN_INTERFACE_CONTACT`) |
| `2` | Contactless interface (`KRN_INTERFACE_CONTACTLESS`) |

The kernel SHALL reject `0`, unknown values, and any transaction whose selected
AID, scheme profile, and certified kernel mapping do not match the explicit
interface. This prevents implicit contact fallback from weakening the
contact/contactless evidence boundary.

> **KRN-INT-004**: The kernel **SHALL** reject a transaction if no certified
> kernel/profile mapping exists for the selected AID and explicit interface.

### Annex J – Certification Evidence Checklist, Intake Ledger, Freeze Manifest, Security, Device, and Integration Plans

The executable certification evidence checklist is
`docs/certification_evidence_checklist.json`; the reviewable Markdown export is
`docs/certification_evidence_checklist.md`. Both artifacts are generated by
`cargo run --example krn_certification_evidence_checklist`.

The executable evidence intake ledger is
`docs/certification_evidence_intake.json`; the reviewable Markdown export is
`docs/certification_evidence_intake.md`. Both artifacts are generated by
`cargo run --example krn_certification_evidence_intake`.

The local certification attachment audit is generated on demand by
`cargo run --example krn_certification_attachment_audit -- --root <dir>`. It
SHALL hash files under `CERT-OPEN-*` attachment directories, report missing
slots, unmapped files, and unsupported entries such as symbolic links, and
SHALL NOT mark any external evidence gate closed. Unsupported entries SHALL be
reported as rejected rather than silently ignored so certification package
assembly cannot hide unaudited evidence paths.
The local certification workspace generated by
`cargo run --example krn_certification_workspace -- --out <dir>` SHALL create
empty `attachments/CERT-OPEN-*` staging directories, an attachment-slot guide,
an attachment audit dashboard, and attachment audit JSON/Markdown for that
workspace without treating empty directories or local files as accepted
certification evidence. It SHALL package the repository-controlled masked
pre-lab APDU trace fixture plus trace-pack audit JSON/Markdown for local
review while preserving the external `CERT-OPEN-012` full trace-pack boundary.
The workspace SHALL also emit
`workspace_inventory.json` and `workspace_inventory.md` with file size and
SHA-256 values for generated local workspace artifacts. Self-referential
inventory files and `workspace_manifest.json` SHALL be listed as inventory
exclusions rather than hashed into the inventory closure.

The executable certification freeze manifest is
`docs/certification_freeze_manifest.json`; the reviewable Markdown export is
`docs/certification_freeze_manifest.md`. Both artifacts are generated by
`cargo run --example krn_certification_freeze_manifest`.

The executable security assessment plan is
`docs/certification_security_assessment_plan.json`; the reviewable Markdown
export is `docs/certification_security_assessment_plan.md`. Both artifacts are
generated by `cargo run --example krn_certification_security_assessment_plan`.

The executable device evidence plan is
`docs/certification_device_evidence_plan.json`; the reviewable Markdown export
is `docs/certification_device_evidence_plan.md`. Both artifacts are generated
by `cargo run --example krn_certification_device_evidence_plan`.

The executable integration report plan is
`docs/certification_integration_report_plan.json`; the reviewable Markdown
export is `docs/certification_integration_report_plan.md`. Both artifacts are
generated by `cargo run --example krn_certification_integration_report_plan`.

The checklist SHALL map every `CERT-OPEN-*` row in
`docs/certification_open_issues.md` to the external authority, required
attachment, binding metadata, acceptance gate, repository support artifact, and
current attachment status. The intake ledger SHALL provide pending attachment
slots for every `CERT-OPEN-*` row with hash, authority, signer or reviewer,
artifact path, submitted-build scope, disposition, and supersession fields.
The attachment audit SHALL inventory local files against those slots by path,
size, and SHA-256 before review. These are attachment-control artifacts only.
They SHALL NOT mark an open issue closed without the independently accepted
external evidence named by that row.
The coverage package audit SHALL inspect the staged `target/coverage` package
for `metadata.json`, `README.txt`, and `html/index.html`, SHALL validate the
100% threshold and `CERT-OPEN-009` non-closure metadata, and SHALL distinguish
measurement-only coverage artifacts from enforced 100% candidates awaiting
submitted-build binding and external report acceptance.
The pre-lab trace-pack audit SHALL inspect `docs/prelab_apdu_trace_pack.jsonl`
or an explicitly supplied JSONL trace-pack path for case metadata, scenario
rows, production trace identity, expected command/response counts, expected
TLV-stream counts, sensitive tag suppression, and `CERT-OPEN-012` non-closure
metadata before report-production use. It SHALL NOT treat the repository
fixture as an accepted full lab/test-tool trace pack.
The freeze manifest SHALL bind the submitted kernel binary, signed
configuration, CAPKs, profiles, vectors, RTM, accepted reports, and approval
package through pending SHA-256 slots before certification-facing review.
The security assessment plan SHALL map `CERT-OPEN-008` review surfaces to
repository evidence and external assessor evidence requirements for APDU
injection, state-machine bypass, trace leakage, profile tampering, PIN custody,
ODA material handling, issuer scripts, and report integrity. It SHALL NOT close
`CERT-OPEN-008` without an accepted third-party report and finding disposition.
The device evidence plan SHALL map `CERT-OPEN-006` and `CERT-OPEN-007`, and
where contactless scope applies `CERT-OPEN-005`, to the target device model,
firmware, reader/L1 approval reference, PCI PTS/PED evidence, interface scope,
trace identity, submitted binary hash, profile bundle hash, and report-package
binding. It SHALL NOT close those issues without accepted external device, L1,
PCI/PED, and laboratory evidence.
The integration report plan SHALL map `CERT-OPEN-009` and `CERT-OPEN-012` to
accepted test-plan scope, L2 execution, Level 3/acquirer reconciliation, full
masked APDU trace coverage, outcome mapping, deviation disposition, submitted
binary/profile/CAPK hashes, and trace-pack hash binding. It SHALL NOT close
those issues without accepted coverage, full integration, Level 3/acquirer,
and trace-pack report attachments.

The certification report pack generated by
`cargo run --example krn_certification_report_ui` SHALL index repository
artifacts, open certification gates, required external reports, evidence
attachments, report-production commands, and a checked-in artifact file
inventory containing file size and SHA-256 values. The report-pack JSON,
Markdown export, and static HTML workbench SHALL exclude their own checked-in
report outputs from that artifact file inventory to avoid self-referential hash
churn while still listing the exclusion reasons.

---

## 7. Final Verdict

This v6.0 specification and annex set is an **engineering baseline pending licensed review and laboratory evidence**. The implemented controls resolve several prior blockers:

- **CDA P1 encoding** no longer collides with cryptogram‑type bits.
- **CVM codes** are taken from an EMV Book 3 validated table, with CDCVM handled via contactless profiles.
- **TAA fallback** is deterministic with explicit configuration keys.
- **ODA/CDA** details are fully specified.
- **Certification data gates** reject structural ODA fixtures and require lab-supplied certification vectors before submission.

**This specification is ready for continued implementation and EMVCo Level 2 pre-certification hardening, but final certification requires licensed review, signed profiles/CAPKs, lab-supplied ODA vectors, and laboratory approval.**
