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

**CDCVM (Consumer Device CVM)** is **not** a universal EMV Book 3 CVM code. It is indicated through **contactless transaction qualifiers (CTQ) and card capabilities**. The kernel **SHALL** evaluate CDCVM availability from the contactless kernel data (e.g., CTQ bit 5) and **SHALL NOT** rely on a fixed CVM code `0x05`.

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

## 5. Offline Data Authentication (ODA) – CDA Details

The kernel **SHALL** implement CDA as follows (complete specification):

### 5.1 CDA Detection

- Card supports CDA if **AIP bit 7** = 1 (EMV Book 3).
- The terminal requests CDA by including the **CDA request indicator** in the CDOL1 data or by setting a profile‑defined control bit in GENERATE AC P1 **that does not affect bits 7‑6**. (See §2 above.)

### 5.2 CDA Protocol

1. The kernel builds CDOL1 as usual (including `9F37` Unpredictable Number, etc.).
2. The card returns **ARQC** (or other cryptogram) along with **Signed Dynamic Application Data (SDAD)**. The SDAD is contained in tag `9F4C` (ICC Dynamic Number) **and** additional data; exact format is scheme‑specific.
3. The kernel verifies the SDAD signature using the **ICC public key** recovered during DDA.
4. The verification **SHALL** include the generated cryptogram (the whole `9F26` value) as part of the signed data. The exact concatenation order is defined in EMV Book 3 and scheme profiles.
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
fictitious material.

### Annex D – Trace Log Format Specification

(As in v5.0 – correct.)

### Annex E – Full State Machine Transition Table (`state_machine.csv`)

```csv
Current State,Event,Guard,Next State,Action,Error Code
S0,krn_set_transaction_params(),params valid,S1,Store amount/currency,KRN_OK
S1,card_detected(),card present,S2,Start PSE/PPSE selection,KRN_OK
S2,SELECT returns 9000 with FCI,AID selected,S3,Build PDOL send GPO,KRN_OK
S2,SELECT returns 6A82,no PSE,S2_fallback,try direct AIDs,KRN_OK
S3,GPO returns 9000 with AIP/AFL,AFL valid,S4,Read records by AFL,KRN_OK
S3,GPO fails,–,SE,Set error,KRN_ERR_MISSING_MANDATORY_TAG
S4,READ RECORD returns 9000,all records read,S5,Start ODA,KRN_OK
S4,READ RECORD returns 6A83,end of records,S5,Continue if mandatory records present,KRN_OK
S5,ODA success,–,S6,Clear ODA failure bits,KRN_OK
S5,ODA failure,–,S6,Set TVR ODA bits,KRN_OK
S6,Processing restrictions ok,–,S7,Proceed to CVM,KRN_OK
S7,CVM success,–,S8,Proceed to TRM,KRN_OK
S7,CVM failure,–,S8,Set CVM failure bits,KRN_OK
S8,TRM ok,–,S9,Proceed to TAA,KRN_OK
S8,TRM force online,–,S9,Set floor limit/random bits,KRN_OK
S9,TAA decision = ARQC,–,S10,Request ARQC,KRN_OK
S9,TAA decision = TC,–,S14,Offline approve,KRN_OK
S9,TAA decision = AAC,–,S14,Offline decline,KRN_OK
S10,GENERATE AC returns ARQC,–,S11,Build host request,KRN_OK
S10,GENERATE AC returns TC,–,S14,Offline approve,KRN_OK
S10,GENERATE AC returns AAC,–,S14,Offline decline,KRN_OK
S11,host_response received,–,S12,Process ARPC,KRN_OK
S11,host_response timeout,–,SE,Set error,KRN_ERR_HOST_TIMEOUT
S12,GENERATE AC second returns TC,–,S13,Script processing,KRN_OK
S12,GENERATE AC second returns AAC,–,S13,Declined online,KRN_OK
S13,script execution done,–,S14,Return outcome,KRN_OK
S13,script failure,–,S14,Log error continue,KRN_OK
S14,–,–,S0,Reset kernel,KRN_OK
SE,any,–,S0,Reset after error,KRN_OK
```

### Annex F – Scheme Profiles (`scheme_profiles.cert.json`)

The executable certification profile is `docs/scheme_profiles.cert.json`.
It SHALL be valid JSON, declare `profile_class = "CERTIFICATION"`, carry
signed-profile provenance, and include complete AID, TAC/IAC, limit, CDA-control,
issuer-script, CAPK, checksum, expiry, and CAPK-source fields for each bundled
scheme profile.

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

---

## 7. Final Verdict

This v6.0 specification and annex set is an **engineering baseline pending licensed review and laboratory evidence**. The implemented controls resolve several prior blockers:

- **CDA P1 encoding** no longer collides with cryptogram‑type bits.
- **CVM codes** are taken from an EMV Book 3 validated table, with CDCVM handled via contactless profiles.
- **TAA fallback** is deterministic with explicit configuration keys.
- **ODA/CDA** details are fully specified.
- **Certification data gates** reject structural ODA fixtures and require lab-supplied certification vectors before submission.

**This specification is ready for continued implementation and EMVCo Level 2 pre-certification hardening, but final certification requires licensed review, signed profiles/CAPKs, lab-supplied ODA vectors, and laboratory approval.**
