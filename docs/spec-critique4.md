## Executive verdict

**The specification is not yet fully correct, complete, or certifiable.** It is substantially better than earlier versions, but v4.0 still contains **hard technical defects** that would block certification or mislead implementers if treated as normative. The biggest issue is that it still presents itself as a **“normative implementation and certification baseline”**, while several sections contain internal uncertainty, incorrect APDU encodings, incomplete EMV state logic, and unresolved dependencies on external annex files. 

The current public baseline assumptions are broadly reasonable: EMVCo confirms that the **Book C-8 Kernel 8 testing process** became available on **16 October 2024**, and PCI SSC confirms publication of **PCI PTS POI v7.0** as a major revision of PIN Transaction Security POI requirements. ([EMVCo][1]) The problem is not the chosen standards baseline. The problem is that the specification does not yet express those standards with sufficient precision.

## Scorecard

| Dimension                    |        Score | Assessment                                                                                                                                                                  |
| ---------------------------- | -----------: | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Correctness**              | **6.5 / 10** | Improved, but still has certification-critical errors in selection APDUs, PIN handling, APDU tables, and EMV processing semantics.                                          |
| **Completeness**             | **5.5 / 10** | Good topical coverage, but missing full state machine, real annexes, test traceability, full SW1/SW2 handling, full TLV profile, scheme rules, and lab submission controls. |
| **Certifiability**           | **4.5 / 10** | Not certifiable as written. It lacks real scheme configuration, executable ODA vectors, lab conformance mapping, complete Book C-8 behavior, and exact test-tool alignment. |
| **Architecture quality**     |   **7 / 10** | Trust-boundary model and separation of kernel, PED, L3, acquirer, and issuer are broadly sound.                                                                             |
| **Specification discipline** |   **6 / 10** | Requirement IDs are useful, but several requirements contain uncertainty, optionality, or invalid normative wording.                                                        |

---

# 1. Correctness review

## 1.1 The contact PSE command is internally contradictory and technically wrong

The specification correctly states that **contact PSE** should use `1PAY.SYS.DDF01` and **contactless PPSE** should use `2PAY.SYS.DDF01`. That correction is conceptually right. 

However, the actual command shown for contact PSE is defective:

```text
00 A4 04 00 0E 31 50 41 59 2E 53 59 53 2E 44 44 46 30 31 00
```

The string `1PAY.SYS.DDF01` is **14 bytes**, not 15 bytes. The command uses `Lc = 0E`, which means 14 bytes. That part is consistent. But the prose says **“15 bytes, right-padded with 0F”** and then adds uncertainty: **“Spec may expect 14-byte 2PAY... or 15-byte padded 1PAY...”** 

That uncertainty cannot exist in a normative certification baseline.

**Correct statement:**

```text
Contact PSE name:  1PAY.SYS.DDF01
Hex data:          31 50 41 59 2E 53 59 53 2E 44 44 46 30 31
Lc:                0E
APDU:              00 A4 04 00 0E 31 50 41 59 2E 53 59 53 2E 44 44 46 30 31 00
```

```text
Contactless PPSE name: 2PAY.SYS.DDF01
Hex data:              32 50 41 59 2E 53 59 53 2E 44 44 46 30 31
Lc:                    0E
APDU:                  00 A4 04 00 0E 32 50 41 59 2E 53 59 53 2E 44 44 46 30 31 00
```

**Finding:** The **concept** is correct, but the **normative row is not certifiable** because it contains unresolved ambiguity.

---

## 1.2 The trust boundary is mostly correct, but the PED responsibility statement is too broad

The document properly states that the kernel must not store issuer master keys, must not generate ARQC/TC/AAC, and should treat CAPKs as public keys requiring authenticity and integrity, not confidentiality. 

This is a strong correction.

However, the responsibility table says the **PED** owns **“offline plaintext PIN VERIFY APDU handling.”**  That is not a safe general statement. In many architectures, the kernel orchestrates the VERIFY APDU, while the PED securely captures the PIN and returns the PIN data or a secure PIN service result according to the certified POI architecture. The exact split depends on whether plaintext offline PIN or enciphered offline PIN is used, and how the PED API is certified.

A better division is:

| Function                                  | Owner                                                                             |
| ----------------------------------------- | --------------------------------------------------------------------------------- |
| Secure PIN entry                          | PED                                                                               |
| PIN try counter display policy            | Kernel plus UI callback                                                           |
| VERIFY APDU construction                  | Kernel or PED service, depending certified integration architecture               |
| Plaintext PIN data handling               | PED or secure PIN service only                                                    |
| Enciphered offline PIN block construction | Secure PIN service using ICC public key material                                  |
| Online encrypted PIN block                | PED or certified secure PIN module, passed to L3 or host path by secure reference |

**Finding:** The trust boundary is mostly right, but PIN control must be specified as a certified integration profile, not assumed.

---

## 1.3 The TVR table is still not reliable enough

The specification now includes a TVR table, which is necessary, but it is not complete enough to be used as a normative implementation source. 

There are several problems.

First, byte 5 is not specified. It is reduced to **“Merchant / scheme specific.”**  That is insufficient for certification. TVR byte 5 includes important issuer authentication and script processing conditions in the standard EMV contact flow. A kernel cannot omit these bits from a normative table and still claim complete Book 3 coverage.

Second, the table appears to include a standard-like but incomplete mapping. If the document intends to be normative, each TVR bit must be exact, including RFU bits, byte numbering, bit numbering, mask value, semantic condition, setting phase, and clearing behavior.

A certifiable table should include at least:

| Field          | Required                                                    |
| -------------- | ----------------------------------------------------------- |
| Byte index     | 1 to 5                                                      |
| Bit index      | b8 to b1                                                    |
| Hex mask       | `0x80`, `0x40`, etc.                                        |
| EMV condition  | Exact standard wording or controlled paraphrase             |
| Setting module | ODA, restrictions, CVM, TRM, issuer authentication, scripts |
| Reset rule     | Cleared at transaction start                                |
| Test IDs       | Positive and negative tests                                 |

**Finding:** The TVR table is **directionally useful** but not yet a certification-safe source of truth.

---

## 1.4 TSI is incomplete

The TSI table covers byte 1 but leaves byte 2 as reserved.  That is acceptable only if verified against the selected EMV baseline and contactless profile. But the specification does not provide the exact bit masks or test assertions.

The table should include:

```c
#define TSI_B1_ODA_PERFORMED              0x80
#define TSI_B1_CVM_PERFORMED              0x40
#define TSI_B1_CARD_RISK_MGMT_PERFORMED   0x20
#define TSI_B1_ISSUER_AUTH_PERFORMED      0x10
#define TSI_B1_TRM_PERFORMED              0x08
#define TSI_B1_SCRIPT_PROCESSING_PERFORMED 0x04
```

**Finding:** TSI is usable as a conceptual table, but not complete as code-level normative material.

---

## 1.5 CID decoding is largely correct but bit numbering should be clarified

The CID table maps:

| Bits | Meaning                  |
| ---- | ------------------------ |
| `00` | AAC                      |
| `01` | TC                       |
| `10` | ARQC                     |
| `11` | AAR/referral or reserved |

and the code shifts `cid >> 6`. 

This is mostly correct, but the text says **“bits 7-6”**, while EMV documents usually use **b8-b1** terminology. To remove ambiguity, the normative rule should be expressed as:

```c
uint8_t type = cid & 0xC0;
```

with:

```c
0x00 = AAC
0x40 = TC
0x80 = ARQC
0xC0 = AAR or scheme-specific/referral/reserved
```

**Finding:** This section is close, but should use mask-level notation for implementation safety.

---

## 1.6 Offline PIN handling remains logically inconsistent

The specification says for **plaintext offline PIN**:

> “PED captures PIN securely; kernel constructs VERIFY APDU without encryption; sends to card.” 

Then the requirement says:

> “The kernel SHALL NOT construct, modify, or access any PIN block in clear text.” 

These two statements conflict unless there is a secure handoff model where the PED constructs the VERIFY data field and the kernel merely transmits it without visibility, or the APDU is sent by the PED/security module. A plaintext offline PIN VERIFY APDU necessarily contains PIN-related data in the APDU data field. If the kernel constructs that APDU in normal memory, it is handling clear PIN-derived data.

The specification must choose one certified integration model:

**Model A, PED-owned VERIFY**

The PED captures the PIN, constructs the VERIFY APDU or protected command payload, sends it to the ICC through a secure path, and returns only status to the kernel.

**Model B, kernel-orchestrated secure buffer**

The PED returns an opaque secure buffer handle for the VERIFY APDU data field. The kernel passes the handle to a transport layer that can transmit without exposing the clear data to kernel memory.

**Model C, kernel handles plaintext PIN data**

This would contradict the current security requirements and may not be acceptable for the intended PCI PTS boundary.

**Finding:** The PIN section is **not internally consistent** and is not certifiable until the certified PIN data path is specified.

---

## 1.7 APDU status-word handling is improved but still too generic

The APDU status word table now includes `9000`, `61xx`, `6Cxx`, `6985`, `6A82`, `6A83`, `6283`, and `63Cx`. 

This is a useful improvement, but still incomplete for a certification-grade kernel. EMV handling must be state-specific. For example, `6A82` during PSE selection may mean fallback to direct AID selection. `6A83` during READ RECORD may mean no such record, but whether it is fatal depends on AFL processing and whether the record was mandatory. `6985` may have different consequences depending on command and state.

The specification should have an APDU-by-APDU SW table:

| Command     | SW          | Meaning                    | Next state                     | TVR/TSI mutation       | Error code                       |
| ----------- | ----------- | -------------------------- | ------------------------------ | ---------------------- | -------------------------------- |
| SELECT PSE  | `6A82`      | PSE not found              | Direct AID selection           | none                   | none                             |
| SELECT AID  | `6A82`      | AID not found              | Try next candidate             | none                   | maybe no-common-AID if exhausted |
| READ RECORD | `6A83`      | Record not found           | Continue or error based on AFL | maybe ICC data missing | conditional                      |
| VERIFY      | `63Cx`      | PIN failed, x tries remain | CVM next rule or fail          | CVM bits               | conditional                      |
| GPO         | non-success | Application cannot proceed | Error or next candidate        | depends                | conditional                      |

**Finding:** The general SW table is insufficient for certifiability.

---

## 1.8 GENERATE AC P1 encoding is corrected in principle but incomplete for CDA

The table now states:

| Requested cryptogram | P1     |
| -------------------- | ------ |
| AAC                  | `0x00` |
| TC                   | `0x40` |
| ARQC                 | `0x80` |

This corrects the previous major error. 

However, the CDA instruction says:

> “CDA request: Bit-mask as per EMV Book 3” and “set additional P1 bits according to EMV Book 3.” 

This is acceptable as a placeholder, but not as a normative implementation baseline. If CDA is in scope, the spec must explicitly define:

| CDA item                 | Required                                    |
| ------------------------ | ------------------------------------------- |
| AIP capability detection | Which AIP bit indicates CDA support         |
| CDA request bit          | Exact P1 bit/mask                           |
| CDOL1 data requirements  | Data needed for signed dynamic data         |
| Response parsing         | Signed dynamic application data location    |
| AC binding verification  | How the cryptogram is included and verified |
| Failure handling         | TVR bit, TAA path, fallback prohibition     |

**Finding:** Non-CDA GENERATE AC is now close. CDA remains under-specified.

---

## 1.9 CVM method codes are oversimplified and likely wrong as a normative table

The CVM section lists method codes:

| Code | Method                |
| ---- | --------------------- |
| `01` | Offline plaintext PIN |
| `02` | Online PIN            |
| `03` | Signature             |
| `04` | No CVM                |
| `05` | CDCVM                 |



This is not sufficiently accurate for EMV CVM list processing. EMV CVM codes include method and condition information, plus “fail CVM processing,” plaintext offline PIN, enciphered offline PIN, plaintext offline PIN plus signature, enciphered offline PIN plus signature, signature, no CVM, and scheme/contactless-specific interpretations. **CDCVM is not simply a universal EMV Book 3 method code `05`** in the way the table implies.

The specification must implement the CVM List as a sequence of:

[
(\text{CVM Code}, \text{CVM Condition Code})
]

with amount X/Y handling, terminal capability checks, unsupported method handling, fallback behavior, and CVM Results `9F34`.

**Finding:** This is a certification-critical incompleteness. The CVM table is too simplified to be normative.

---

## 1.10 TAA is improved but still not complete

The TAA table now uses both **TAC** and **IAC**, which is correct directionally. 

However, it still has unresolved ambiguity:

> “request AAC (decline) or TC per scheme fallback policy”
> “request TC or ARQC according to scheme/application profile” 

That is not wrong, but it is not complete. Certifiability requires the fallback policy to be **explicitly configured and tested per scheme/AID**, not described generically.

The spec also says IACs are read from the card’s records.  That is broadly right, but it must specify behavior when IAC tags are absent, malformed, or partially absent. EMV has defaults and terminal behavior for missing issuer action codes depending on profile. This cannot be left implicit.

**Finding:** TAA is now structurally correct but not certification-complete.

---

## 1.11 C-8 section is still too thin

The C-8 annex says the kernel shall implement Book C-8 for contactless transactions and return outcome parameters.  EMVCo confirms C-8 is a contactless kernel specification and that its testing process evaluates whether products perform in accordance with that specification. ([EMVCo][1])

However, the section is still far too thin for a Book C-8 implementation baseline. It lacks:

| Missing C-8 element                | Why it matters                                                              |
| ---------------------------------- | --------------------------------------------------------------------------- |
| Book A / Entry Point dependencies  | Contactless selection behavior is not just PPSE plus highest priority AID.  |
| Complete Outcome Parameter Set     | The listed fields are not enough to implement exact C-8 outcomes.           |
| UI Request Data model              | Need exact message IDs, status, hold time, language/preferred display data. |
| Data Record and Discretionary Data | Needed for L3 handoff.                                                      |
| Restart / Try Again semantics      | Critical for RF field behavior.                                             |
| Relay resistance details           | The text says support APDUs and timing constraints but gives no protocol.   |
| C-8 data object set                | TTQ/CTQ-like concepts are not enough for C-8.                               |
| Approval testing profile           | Need test-tool and EMVCo C-8 approval package mapping.                      |

**Finding:** The section correctly states C-8 is contactless-only, but it is **not a C-8 kernel specification**.

---

## 1.12 CDOL example is malformed

The CDOL section states:

> “Example CDOL1 encoding (4 bytes of tag-length data)” and then lists four tag-length pairs. 

That is wrong. The listed DOL elements are not 4 bytes total. For example:

```text
9F02 06 = 3 bytes
9A 03   = 2 bytes
5F2A 02 = 3 bytes
9F37 04 = 3 bytes
```

Total = **11 bytes**, not 4.

**Finding:** This is a simple but important precision error.

---

## 1.13 API remains skeletal

The API defines initialization and callbacks, but it is not complete enough for implementation. 

Missing items include:

| Missing API item                    | Why it matters                                                   |
| ----------------------------------- | ---------------------------------------------------------------- |
| `krn_run_transaction()` signature   | Outcome enum is defined, but function itself is missing in v4.0. |
| `krn_reset()`                       | Required for abnormal termination and transaction cleanup.       |
| `krn_get_last_error()`              | Required for diagnostics.                                        |
| `krn_get_trace()` or trace callback | Required for lab reproducibility.                                |
| `krn_set_transaction_params()`      | Required to load amount/currency/type before run.                |
| Buffer maximums                     | Prevents overflow and ABI instability.                           |
| Struct versioning for callbacks     | `struct_size` exists for runtime but not for all passed structs. |
| Secure handle lifecycle             | Who creates, owns, expires, and destroys `krn_secure_handle_t`.  |

**Finding:** API/ABI section is useful but incomplete.

---

## 1.14 Security logging has an unsafe debug-mode formulation

The spec says ARQC/ARPC may be logged in debug mode only with `#ifdef DEBUG` not in production. 

This is not a sufficient security control. Payment kernels need a formal **log policy**, not a compile-time macro convention. Debug logging of sensitive authorization data should require:

| Control                 | Requirement                                                 |
| ----------------------- | ----------------------------------------------------------- |
| Build-time gating       | Production build cannot include debug logging code path.    |
| Runtime authorization   | Support mode must be signed and time-bound if enabled.      |
| Data minimization       | Hash or truncate where possible.                            |
| Secure export           | Logs encrypted and access controlled.                       |
| Certification alignment | Lab traces and production logs must use different policies. |

**Finding:** Logging policy is directionally good but not production-grade.

---

# 2. Completeness review

## 2.1 Missing formal state machine

The document says the full state machine exists in `state_machine.csv`, but the uploaded v4.0 specification does not include the state table itself. It only references an external file. 

For a certifiable specification, the state machine cannot be optional or loosely external. It must include:

| Required state machine content                        | Status                 |
| ----------------------------------------------------- | ---------------------- |
| Full state list                                       | Missing from v4.0 body |
| Events                                                | Missing                |
| Guards                                                | Missing                |
| Actions                                               | Missing                |
| TVR/TSI mutations                                     | Missing                |
| Error transitions                                     | Missing                |
| Contact vs contactless branch points                  | Missing                |
| Online/unable-online behavior                         | Missing                |
| Script-before-final and script-after-final sequencing | Missing                |
| Card removal and timeout handling                     | Missing                |

**Completeness finding:** Major gap.

---

## 2.2 Missing full APDU command specification

Appendix B gives a summary table, but a certifiable APDU spec needs APDU-by-APDU exact definitions. 

At minimum:

| APDU                  | Missing                                                                          |
| --------------------- | -------------------------------------------------------------------------------- |
| SELECT                | PSE absent fallback, FCI parsing, application priority, partial selection rules  |
| GPO                   | PDOL absent handling, `83` template construction, `80` vs `77` response handling |
| READ RECORD           | AFL loop, SFI validation, record range handling, offline auth data participation |
| GET DATA              | ATC, PIN try counter, log entries where applicable                               |
| INTERNAL AUTHENTICATE | DDOL construction and signed dynamic data parsing                                |
| VERIFY                | Plaintext vs enciphered offline PIN distinction                                  |
| GENERATE AC           | CDOL1/CDOL2, CDA, response template variants                                     |
| EXTERNAL AUTHENTICATE | When needed vs when ARPC is embedded in second GENERATE AC                       |
| Issuer scripts        | Tags `71` and `72`, pre/post second GENERATE AC handling                         |

**Completeness finding:** The APDU section is not yet implementation-complete.

---

## 2.3 Missing ODA details

Appendix C claims that ODA vectors contain complete CAPK modulus/exponent, certificates, signatures, DDOL, INTERNAL AUTHENTICATE response, GENERATE AC CDA signature, recovered data, and expected TVR/TSI. 

However, the current uploaded context from previous files showed ODA vectors that were placeholders, not complete executable vectors. Unless a new complete `oda_test_vectors.json` exists and is real, this claim is unsupported.

The ODA section also lacks full details for:

| ODA component       | Missing                                                                |
| ------------------- | ---------------------------------------------------------------------- |
| CAPK selection      | RID, index, hash algorithm, expiry, revocation                         |
| Issuer key recovery | Certificate format, hash input, remainder handling                     |
| ICC key recovery    | Certificate format, remainder handling                                 |
| SDA                 | Static Data Authentication Tag List and Signed Static Application Data |
| DDA                 | DDOL defaulting, INTERNAL AUTHENTICATE response parsing                |
| CDA                 | Signed dynamic application data and AC binding                         |
| Failure handling    | Exact TVR bit and TAA path                                             |

**Completeness finding:** ODA is not sufficiently specified for development or certification.

---

## 2.4 Missing configuration schema

The v4.0 specification references a `scheme_profiles.cert.json` containing real non-placeholder values.  It does not include the JSON schema or validation rules in the document body.

A certifiable configuration model needs:

| Required configuration control | Status              |
| ------------------------------ | ------------------- |
| JSON schema                    | Missing             |
| Signature envelope             | Missing             |
| Root of trust                  | Missing             |
| Key rotation                   | Missing             |
| Anti-rollback                  | Missing             |
| CAPK expiry handling           | Missing             |
| RID/AID validation             | Missing             |
| TAC/IAC source validation      | Partially described |
| Per-scheme lab profile         | Missing             |
| Environment separation         | Missing             |
| Version pinning                | Missing             |

**Completeness finding:** Not enough for certifiable configuration management.

---

## 2.5 Missing requirement-to-test traceability

The certification section says there must be a conformance statement and test plan coverage.  But the specification itself does not map requirements to tests.

A certifiable artifact needs:

| Requirement   | Unit test    | Integration test | EMVCo test case | Evidence          |
| ------------- | ------------ | ---------------- | --------------- | ----------------- |
| `KRN-SEL-001` | `UT-SEL-001` | `IT-SEL-001`     | Lab case ID     | Trace             |
| `KRN-GAC-008` | `UT-GAC-001` | `IT-GAC-003`     | Lab case ID     | APDU log          |
| `KRN-TAA-006` | `UT-TAA-001` | `IT-TAA-010`     | Lab case ID     | TVR/TAC/IAC trace |

**Completeness finding:** Certification evidence exists as a category, not as an executable traceability matrix.

---

# 3. Certifiability review

## 3.1 It cannot be certified “as a specification” in the current form

EMVCo approval testing evaluates products, kernels, and acceptance devices against the relevant specifications and approval process. EMVCo’s C-8 testing announcement states that approval testing evaluates whether products perform in accordance with the C-8 specification when deployed, and supports both full contactless device testing and standalone kernel testing. ([EMVCo][1])

This document can support a certification program, but it is not itself enough for certification because it lacks:

| Certifiability requirement                | Current status          |
| ----------------------------------------- | ----------------------- |
| Complete lab conformance statement        | Not present             |
| Final target product definition           | Not present             |
| Approved L1 dependency definition         | Not present             |
| Full L2 test tool mapping                 | Not present             |
| Scheme-specific profiles                  | Referenced, not present |
| Real CAPKs and AIDs                       | Referenced, not present |
| Real ODA vectors                          | Claimed, not shown      |
| Full APDU traces                          | Not present             |
| Version-controlled binary/config manifest | Not present             |
| Test harness                              | Not present             |
| Failure evidence                          | Not present             |

**Certifiability finding:** This is not a certification package. It is a specification draft for a future certification package.

---

## 3.2 The phrase “normative implementation and certification baseline” is unsafe

The document title block says:

> “Status: Normative implementation and certification baseline.” 

Given the uncertainty in the PSE row, incomplete TVR byte 5, incomplete C-8 behavior, incomplete CVM processing, and absent annexes, this status is not justified.

Recommended status:

> **Status:** Engineering draft for EMV L2 kernel implementation. Not yet a certification baseline. Certification baseline status requires completion of controlled annexes, licensed-standard reconciliation, lab conformance mapping, and scheme/acquirer validation.

---

## 3.3 External files are asserted but not available in the evaluated upload

The spec repeatedly references separate files:

| Referenced file             | Purpose                     |
| --------------------------- | --------------------------- |
| `tlv_catalogue.csv`         | Full TLV catalogue          |
| `oda_test_vectors.json`     | ODA test vectors            |
| `state_machine.csv`         | Full transition table       |
| `scheme_profiles.cert.json` | Real certification profiles |



The uploaded file is only `spec4.md`. Unless those annexes are supplied as controlled, validated artifacts, the specification cannot be evaluated as complete or certifiable.

**Certifiability finding:** A certification baseline must be a controlled artifact set, not a markdown file that refers to missing annexes.

---

# 4. Highest-priority corrections

## Priority 0 corrections

These must be fixed before engineering freeze.

| Issue                                                               | Required correction                                                                                                        |
| ------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| PSE row contains uncertainty and wrong padding comment              | Remove uncertainty. Use exact 14-byte `1PAY.SYS.DDF01` and `Lc=0E`.                                                        |
| Plaintext offline PIN model conflicts with no-clear-PIN requirement | Choose a certified PIN integration model and make APDU/data handling consistent.                                           |
| CVM method table oversimplified                                     | Replace with full CVM code and condition-code processing model.                                                            |
| TVR byte 5 incomplete                                               | Add complete TVR byte 5 mapping and exact masks for all bytes.                                                             |
| CDA under-specified                                                 | Define CDA request bit, response parsing, signature verification, and failure path.                                        |
| External annexes missing                                            | Attach real `tlv_catalogue.csv`, `state_machine.csv`, `scheme_profiles.cert.json`, and executable `oda_test_vectors.json`. |

## Priority 1 corrections

| Issue                          | Required correction                                                                                                |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------ |
| TAA fallback ambiguity         | Create per-scheme deterministic decision table.                                                                    |
| APDU SW handling generic       | Add state-specific SW handling tables.                                                                             |
| API incomplete                 | Add `krn_run_transaction`, `krn_reset`, `krn_get_last_error`, trace access, secure handle lifecycle.               |
| C-8 thin                       | Add C-8 outcome, UI request, data record, discretionary data, restart, relay-resistance, and Entry Point behavior. |
| ODA incomplete                 | Add certificate recovery structure, remainders, hash inputs, SDA/DDA/CDA test vectors.                             |
| Certification evidence generic | Add requirement-test-evidence matrix.                                                                              |

---

# 5. Recommended revised status

| Question                                    | Answer                                                                                                                                                                                                                                               |
| ------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Is it correct?**                          | **Partially.** Trust boundary, CAPK treatment, ARQC non-generation, PSE/PPSE concept, and GAC request constants are improved. But PSE command prose, PIN handling, CVM method codes, TVR completeness, CDA, and APDU behavior still need correction. |
| **Is it complete?**                         | **No.** It lacks full state machine, full APDU/SW behavior, real configuration schema, real ODA vectors, complete C-8 behavior, and full traceability.                                                                                               |
| **Is it certifiable?**                      | **No.** It is not yet a controlled lab submission package or final certification baseline.                                                                                                                                                           |
| **Can it guide implementation?**            | **Yes, with caution.** It is useful as an architectural draft, but not as a final normative standard.                                                                                                                                                |
| **Can it be given to developers?**          | **Yes, but only with a defect register and instruction not to treat ambiguous sections as final.**                                                                                                                                                   |
| **Can it be given to a certification lab?** | **Not yet.** It would invite immediate clarification requests and likely rejection as incomplete.                                                                                                                                                    |

---

## Final judgment

The v4.0 specification is **a strong architectural draft, not a certifiable EMV L2 kernel specification**.

It has corrected several major previous flaws, especially around the **issuer key boundary**, **CAPK confidentiality**, **ARQC generation**, **C-8 contactless-only positioning**, and **GENERATE AC request constants**. But it still contains enough unresolved ambiguity and incomplete normative machinery that it cannot honestly be called **fully correct**, **complete**, or **certification-ready**.

The single most important next step is not more prose. It is to produce a **controlled certification artifact pack**:

1. `spec.md`, corrected and de-ambiguous.
2. `state_machine.csv`, complete and machine-validated.
3. `tlv_catalogue.csv`, exact and scheme-profiled.
4. `apdu_sw_matrix.csv`, command/state/SW behavior.
5. `scheme_profiles.cert.json`, real certification configuration.
6. `oda_test_vectors.json`, executable cryptographic vectors.
7. `requirements_traceability.xlsx`, mapping every `KRN-*` requirement to tests and evidence.
8. `lab_submission_manifest.md`, defining the product, version, test tool, configuration, and target approval scope.

[1]: https://www.emvco.com/news/emvco-launches-the-emv-contactless-kernel-testing-process/?utm_source=chatgpt.com "EMVCo Launches the EMV® Contactless Kernel Testing ..."
