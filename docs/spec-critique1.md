## Executive assessment

The second version is a **material improvement** over the first. It corrects the most serious conceptual errors, especially the incorrect claim that the kernel generates ARQC, the improper placement of issuer master keys inside the kernel, and the absence of a formal state machine, API surface, TLV table, APDU table, and certification evidence model. The specification now reads like a **serious engineering scaffold** rather than a general explanatory memo. 

However, it still **overclaims certification readiness**. It is now **implementation-oriented**, but not yet truly **certification-ready** or directly handoff-ready to an EMVCo lab. The document contains several remaining technical errors, some invented or non-normative TVR bit references, an oversimplified TAA formula, insufficient contactless/C-8 treatment, and a still-incomplete API/security boundary.

My revised rating:

| Dimension                |   Rating | Assessment                                                                               |
| ------------------------ | -------: | ---------------------------------------------------------------------------------------- |
| Conceptual correctness   |   8 / 10 | Major first-draft errors corrected.                                                      |
| EMV technical precision  | 6.5 / 10 | Much better, but still has incorrect APDU/CID/TVR details.                               |
| Implementation readiness |   7 / 10 | Good scaffold, but incomplete data structures, state table, and edge cases.              |
| Certification readiness  |   6 / 10 | Evidence matrix added, but no true conformance mapping to EMVCo/spec tests.              |
| Security architecture    |   7 / 10 | Trust boundaries improved, but CAPK/SE and PIN-block handling need correction.           |
| Specification discipline | 7.5 / 10 | Requirement IDs and normative language added, but many requirements are still too broad. |

---

## What improved substantially

The strongest improvement is the **trust-boundary correction**. The document now states that issuer master keys must not be stored in the kernel and that the kernel does not generate ARQC, TC, or AAC.  That is a crucial correction. In EMV, the card generates the application cryptogram in response to **GENERATE AC**; the kernel constructs CDOL input, requests a cryptogram type, parses the result, and exposes the result to the terminal application.

The document also correctly reframes the kernel as one component inside a broader payment acceptance system. It distinguishes the **EMV L2 kernel**, **secure PIN subsystem**, **Level 3 terminal application**, **acquirer/switch**, and **issuer/issuer processor**.  This is much closer to how a real POI architecture must be decomposed.

The version baseline is also directionally current. The specification uses EMV Contact Chip v4.4 as target baseline and Book C-8 for contactless.  EMVCo confirmed that Book C-8 Kernel 8 testing became available on 16 October 2024, and describes the testing process as intended to evaluate whether products perform in accordance with the C-8 specification. ([EMVCo][1]) PCI SSC also published PCI PTS POI v7.0 in May 2025, so referencing PCI PTS POI v7.0 is current. ([PCI Perspectives][2])

The inclusion of **requirement identifiers**, **state machine**, **APDU table**, **TLV dictionary**, **configuration schema**, **API callbacks**, **error taxonomy**, **testing matrix**, and **deployment/update controls** substantially improves the document’s engineering utility. 

---

## Remaining critical defects

### 1. The document still overstates certification readiness

The document ends by claiming it is “normative, complete, and certification-ready” and can be “handed directly to a kernel development team and a certification laboratory.”  That is still too strong.

A certification laboratory will require a precise **implementation conformance statement**, target scheme declarations, kernel family/version, test-tool compatibility, configuration manifest, supported interfaces, exception behavior, and test traces. The current document has an evidence matrix, but not a true **EMVCo conformance mapping**.

A better claim would be:

> This specification is an implementation-oriented engineering baseline. It is not, by itself, a lab submission package. Certification readiness requires completion of the scheme-specific conformance matrix, full APDU/SW1/SW2 handling tables, complete TLV catalogue, certified configuration profile, test traces, and laboratory pre-validation.

---

### 2. The TAA algorithm is materially oversimplified

The current formula is:

```text
decision = (TVR & TAC_Online) != 0 ? ONLINE :
           (TVR & TAC_Denial) != 0 ? DECLINE_OFFLINE :
           DEFAULT_ACTION
```

This is not robust enough. In EMV terminal action analysis, the decision process involves **Terminal Action Codes** and **Issuer Action Codes**, commonly **IAC-Denial**, **IAC-Online**, and **IAC-Default**, not just TACs. Denial conditions are normally checked before online conditions, and the logic depends on whether the terminal is online-capable and on the requested cryptogram path.

The document should not encode a simplified ternary as normative EMV logic. At minimum, it should define evaluation against:

[
\text{TVR} \land (\text{TAC-Denial} \lor \text{IAC-Denial})
]

then:

[
\text{TVR} \land (\text{TAC-Online} \lor \text{IAC-Online})
]

then default behavior:

[
\text{TVR} \land (\text{TAC-Default} \lor \text{IAC-Default})
]

The current version omits **Issuer Action Codes** entirely from the TAA section.  That is a serious completeness gap.

---

### 3. CID values are incorrect or at least dangerously underspecified

The document says:

| CID value | Cryptogram type |
| --------- | --------------- |
| `00`      | TC              |
| `10`      | AAC             |
| `40`      | ARQC            |



This is likely incorrect as stated. The **Cryptogram Information Data** encodes the cryptogram type in specific high-order bits, but the values are not safely represented by this table without a bit-mask explanation. In many EMV references, the cryptogram type coding is commonly treated as:

| Cryptogram type | Common coding interpretation |
| --------------- | ---------------------------- |
| AAC             | `00` in cryptogram type bits |
| TC              | `40` in cryptogram type bits |
| ARQC            | `80` in cryptogram type bits |

The specification should avoid hardcoding a possibly wrong table unless it quotes the exact EMV Book 3 bit semantics. It should instead specify:

```c
cryptogram_type = cid & 0xC0;
```

and map the masked value according to the applicable EMV baseline and scheme profile.

This is a **Priority 0 correction** because wrong CID interpretation can invert approve/decline/online behavior.

---

### 4. Several TVR bit references are not precise enough and may be wrong

The document repeatedly cites TVR bits using values such as `60`, `62`, `40`, `10`, `08`, `04`, and `20` for conditions like certificate expiry, validation failure, SDA/DDA failed, version mismatch, date failure, currency mismatch, and AUC failure. 

This is not acceptable as a normative specification. TVR is a **5-byte bit field**, and each condition must be specified by **byte number and bit number**, not by ambiguous hex-like shorthand. For example:

```text
TVR[byte_index].bit_name = 1
```

or:

```c
tvr[0] |= TVR_B1_OFFLINE_DATA_AUTHENTICATION_NOT_PERFORMED;
```

The current notation risks implementers setting the wrong byte or wrong bit. A certification-grade version must include a canonical TVR table:

| Byte | Bit | EMV condition                                 | Set by        |
| ---: | --: | --------------------------------------------- | ------------- |
|    1 |   8 | Offline data authentication was not performed | ODA engine    |
|    1 |   7 | SDA failed                                    | ODA engine    |
|    1 |   6 | ICC data missing                              | TLV validator |
|  ... | ... | ...                                           | ...           |

The same applies to **TSI**, **CVM Results**, **AIP**, and **CID**.

---

### 5. The contactless/C-8 section is too thin

The document now states that C-8 should be used for contactless transactions to reduce certification maintenance.  That is directionally reasonable, and EMVCo’s C-8 testing process confirms that C-8 is a contactless kernel specification intended to support contactless/mobile payment acceptance. ([EMVCo][1]) Ingenico also announced EMVCo approval for a Book C-8 kernel on AXIUM DX8000 in late 2024, showing the certification path is real, not theoretical. ([ingenico.com][3])

But the specification does not properly model contactless behavior. It lacks:

| Missing C-8/contactless element | Why it matters                                                                                  |
| ------------------------------- | ----------------------------------------------------------------------------------------------- |
| **Entry Point processing**      | Contactless application/kernel selection is not equivalent to contact application selection.    |
| **Outcome parameter set**       | Contactless kernels return structured outcome/UI/restart data, not just approve/decline.        |
| **UI request data**             | “Present card”, “Remove card”, “Try another interface”, “See phone” are operationally material. |
| **Card removal behavior**       | Contactless state transitions depend on timing and field loss.                                  |
| **Relay/resistance handling**   | Mentioned in first draft but not formalized in this version.                                    |
| **CVM/contactless limits**      | CVM limit, transaction limit, floor limit, and no-CVM behavior vary by scheme and region.       |
| **CDCVM verification path**     | Current CDCVM handling is too generic.                                                          |
| **Mobile wallet specifics**     | Tokenized PAN, device CVM, and form-factor indicators need treatment.                           |

As written, the contactless portion is more of a policy statement than a specification.

---

### 6. The APDU table contains errors and imprecision

The **READ RECORD** table appears malformed:

```text
P2 = SFI (0x1C | 00)
```



P2 for READ RECORD should be constructed from the **short file identifier** shifted into the correct bit positions, with the record mode bits set. It should not be expressed as `SFI (0x1C | 00)`, which is syntactically and semantically unclear.

The **GENERATE AC** table also says:

```text
P1 = 80 (first) / 00-FF (second)
```



That is not a safe formulation. P1 encodes the requested cryptogram type and related flags. “First” vs “second” is not itself the P1 value. The requested cryptogram type must be specified using the exact EMV bit encoding, not “80 first.”

The **INTERNAL AUTHENTICATE** section says “Response: signed dynamic data (SDA or DDA signature).”  INTERNAL AUTHENTICATE is relevant to DDA, not SDA. SDA uses signed static application data recovered during offline data authentication, not an INTERNAL AUTHENTICATE round trip.

---

### 7. The TLV dictionary has suspicious and incomplete entries

The document says `8C` and `8D` are “Constructed.”  CDOL1 and CDOL2 are **data object lists**, but describing them as “constructed” is likely misleading. DOLs are sequences of tag-length pairs, not BER-TLV constructed templates.

The table lists `9F5F` as “AIP (for C-8)” with “special handling.”  This needs verification against the actual C-8 specification. If the spec does not have access to the proprietary or EMVCo-controlled C-8 text, it should not assert tag semantics loosely.

It also omits or under-specifies critical tags such as:

| Tag                                     | Why it matters                                                            |
| --------------------------------------- | ------------------------------------------------------------------------- |
| `94` AFL                                | Required after GPO to read records.                                       |
| `9F33` Terminal Capabilities            | Core terminal capability object.                                          |
| `9F35` Terminal Type                    | Processing context.                                                       |
| `9F40` Additional Terminal Capabilities | CVM/interface/cashback capability expression.                             |
| `9F66` TTQ                              | Critical for contactless qVSDC-style flows and many contactless profiles. |
| `9F6C` CTQ                              | Contactless/mobile CVM behavior.                                          |
| `9F7C` Customer Exclusive Data          | Used in some profiles.                                                    |
| `9F6E` Form Factor Indicator            | Mobile/contactless device behavior.                                       |
| `9F4C` ICC Dynamic Number               | CDA/DDA relevance.                                                        |

A v2.1 should define a **minimum common EMV tag set** plus **scheme/contactless extensions**.

---

### 8. The API contract still exposes unsafe or ambiguous PIN behavior

The callback is:

```c
int (*request_pin)(int online, int max_len, int *try_remain);
```



This is insufficient. For offline PIN, the kernel may need to drive the VERIFY APDU path, but it must not receive the clear PIN. For online PIN, the encrypted PIN block and key serial number, if DUKPT is used, are usually consumed by the Level 3 host-message layer, not the EMV kernel core.

The callback should return a typed object:

```c
typedef struct {
    krn_pin_status_t status;
    uint8_t pin_try_counter;
    krn_secure_blob_ref_t encrypted_pin_block_ref;
    size_t encrypted_pin_block_len;
    krn_pin_method_t method;
} krn_pin_result_t;
```

Even better, the kernel should not dereference PIN block memory at all. It should receive only **PIN result status** for offline PIN and a **secure reference/handle** for online PIN to be passed to L3.

The current text says the PIN block should not pass through kernel memory, but then the API does not enforce that. 

---

### 9. CAPK storage requirement is too strong and perhaps wrong

The document says CAPKs must be stored in a **secure element or TEE** and that the kernel accesses CAPKs through a secure API, “never in main memory.” 

That is security-positive, but may be operationally unrealistic and not strictly required in many EMV kernel implementations because CAPKs are **public keys**, not secret keys. They must be authentic, versioned, checked, and protected against unauthorized modification, but they are not confidential. Treating them like secret keys can unnecessarily complicate implementation.

A better requirement:

> CAPKs shall be integrity-protected, versioned, authenticated before use, and protected against unauthorized modification. Confidentiality protection is not required for CAPKs because they are public keys, but implementations may store them in a TEE or secure element where platform architecture requires it.

This distinction matters because the document currently conflates **integrity-critical public trust anchors** with **confidential symmetric or private key material**.

---

### 10. The performance and memory constraints are arbitrary

The document requires:

| Constraint                                       | Requirement |
| ------------------------------------------------ | ----------- |
| Contact execution excluding APDU and host        | ≤ 80 ms     |
| Contactless execution excluding RF/card response | ≤ 40 ms     |
| Code + static data                               | ≤ 256 KB    |
| Transaction context                              | ≤ 4 KB      |



These may be reasonable targets for a constrained embedded implementation, but they should not be normative unless tied to actual Hyperion device hardware and compiler/toolchain constraints. RSA verification, CDA, TLV parsing, logging, and scheme variability may exceed these budgets depending on platform. If the product target includes Android POS devices, 256 KB may be unnecessarily restrictive. If it includes Cortex-M devices, it may be appropriate but must be justified.

Rewrite as:

| Tier   | Target class    | Constraints                                      |
| ------ | --------------- | ------------------------------------------------ |
| Tier A | Cortex-M / RTOS | ≤ 256 KB code/static, ≤ 4 KB transaction context |
| Tier B | Linux embedded  | ≤ 1 MB code/static, ≤ 32 KB context              |
| Tier C | Android POS     | performance-bound, not memory-bound              |

---

## Quality issues by section

| Section           | Current quality | Key remaining issue                                                         | Action                                                        |
| ----------------- | --------------: | --------------------------------------------------------------------------- | ------------------------------------------------------------- |
| 1. Scope          |            Good | Normative references lack URLs, document IDs, and retrieval/version policy. | Add reference control table.                                  |
| 2. Trust Boundary |            Good | CAPKs treated as secret material; PIN boundary API mismatch.                | Clarify public vs secret key material and use secure handles. |
| 3. Interfaces     |          Medium | Contactless/C-8 not modeled.                                                | Add Entry Point, outcomes, UI requests, limits.               |
| 4. State Machine  |     Medium-good | Excerpt only; hidden complexity remains.                                    | Add complete transition table and error transitions.          |
| 5. TLV Dictionary |          Medium | Missing critical tags; ambiguous tag types; possible wrong C-8 tag.         | Split common/contact/contactless/scheme tags.                 |
| 6. APDU           |      Medium-low | READ RECORD, GENERATE AC, CID, INTERNAL AUTHENTICATE issues.                | Rewrite with exact APDU semantics and SW tables.              |
| 7. ODA            |          Medium | TVR bits wrong/ambiguous; CDA too thin.                                     | Add certificate structures, recovered data rules, CDA path.   |
| 8. Restrictions   |          Medium | TVR bit shorthand unsafe.                                                   | Use byte/bit symbolic constants.                              |
| 9. CVM            |          Medium | CVM codes oversimplified; CDCVM generic.                                    | Add CVM condition-code evaluation and contactless limits.     |
| 10. TRM           |          Medium | No exception file, random selection algorithm, lower/upper limits.          | Add EMV risk algorithm details.                               |
| 11. TAA           |            Weak | Missing IAC and wrong evaluation ordering.                                  | Rewrite completely.                                           |
| 12. Generate AC   |          Medium | P1/CID semantics unsafe.                                                    | Use exact bit masks and CDOL data model.                      |
| 13. Scripts       |          Medium | Script timing and 71/72 handling missing.                                   | Add script templates and result reporting.                    |
| 14. Config        |            Good | YAML useful but not enough for binary/kernel deployment.                    | Add JSON schema, signature envelope, version policy.          |
| 15. Security      |            Good | Good direction, but needs PCI/SRED/logging specificity.                     | Add secrets inventory and data classification.                |
| 16. API           |          Medium | Not type-safe enough; PIN callback weak.                                    | Add full structs, ownership, lifetimes, buffer rules.         |
| 17. Performance   |          Medium | Arbitrary constraints.                                                      | Tie to hardware tiers.                                        |
| 18. Testing       |            Good | Coverage claims not mapped to EMVCo tests.                                  | Add test IDs and requirement traceability.                    |
| 19. Deployment    |            Good | Rollback protection good; needs key/signature model.                        | Add signing root, rotation, anti-bricking process.            |

---

## Priority corrections for v2.1

### Priority 0: Correct approval/decline/online semantics

Replace the CID table and all cryptogram decoding with a masked-bit implementation:

```c
typedef enum {
    KRN_CRYPTOGRAM_AAC,
    KRN_CRYPTOGRAM_TC,
    KRN_CRYPTOGRAM_ARQC,
    KRN_CRYPTOGRAM_AAR,
    KRN_CRYPTOGRAM_RESERVED
} krn_cryptogram_type_t;

krn_cryptogram_type_t krn_decode_cid(uint8_t cid) {
    switch (cid & 0xC0) {
        case 0x00: return KRN_CRYPTOGRAM_AAC;
        case 0x40: return KRN_CRYPTOGRAM_TC;
        case 0x80: return KRN_CRYPTOGRAM_ARQC;
        default:   return KRN_CRYPTOGRAM_RESERVED;
    }
}
```

This exact mapping should still be verified against the chosen EMV baseline before being made normative.

---

### Priority 1: Rewrite Terminal Action Analysis

The TAA section should be replaced with a version that uses **TAC + IAC**:

```text
if (TVR & (TAC_Denial | IAC_Denial)) != 0:
    request AAC

else if terminal_is_online_capable and
        (TVR & (TAC_Online | IAC_Online)) != 0:
    request ARQC

else if terminal_is_online_capable == false and
        (TVR & (TAC_Default | IAC_Default)) != 0:
    request AAC or TC according to default-denial policy

else:
    request TC or ARQC according to scheme/application profile
```

This should be expressed as a table, not just pseudocode, because offline-only, online-capable, and unable-to-go-online cases differ.

---

### Priority 2: Replace all TVR shorthand with symbolic constants

Use:

```c
typedef enum {
    TVR_B1_OFFLINE_DATA_AUTH_NOT_PERFORMED = 0x80,
    TVR_B1_SDA_FAILED                      = 0x40,
    TVR_B1_ICC_DATA_MISSING                = 0x20,
    TVR_B1_CARD_ON_EXCEPTION_FILE          = 0x10,
    TVR_B1_DDA_FAILED                      = 0x08,
    TVR_B1_CDA_FAILED                      = 0x04
} krn_tvr_byte1_bits_t;
```

Then require all sections to say:

```text
Set TVR.byte1.SDA_FAILED
```

not:

```text
Set TVR bit 40
```

---

### Priority 3: Add a true Contactless/C-8 annex

The annex should include:

| C-8 artifact       | Required content                                                        |
| ------------------ | ----------------------------------------------------------------------- |
| Entry Point        | PPSE processing, candidate list, kernel activation.                     |
| Outcome            | Approval, decline, online, try-again, select-next, alternate interface. |
| UI requests        | Message identifier, status, hold time, language preference.             |
| Limits             | Contactless transaction limit, CVM limit, floor limit.                  |
| CDCVM              | How wallet-reported CVM is recognized and verified.                     |
| Relay/resistance   | If supported, where it sits in state machine.                           |
| Scheme coexistence | C-8 vs legacy kernels on same terminal.                                 |

---

### Priority 4: Strengthen API and ABI

The API must define:

| Concern              | Missing detail                                          |
| -------------------- | ------------------------------------------------------- |
| Buffer ownership     | Who allocates, who frees, maximum lengths.              |
| Reentrancy           | Single-thread stated, but no locking/error behavior.    |
| Callback timeouts    | APDU, host, PIN, UI timeout behavior.                   |
| Secure memory        | How secure handles are passed.                          |
| Versioning           | ABI version, struct size fields, forward compatibility. |
| Deterministic replay | Ability to replay a trace for certification debugging.  |

A better initialization pattern:

```c
typedef struct {
    uint32_t abi_version;
    uint32_t struct_size;
    krn_callbacks_t callbacks;
    krn_allocator_t allocator;
    krn_timeouts_t timeouts;
    krn_log_policy_t log_policy;
} krn_runtime_t;

emv_status_t krn_init(const krn_config_t *cfg,
                      const krn_runtime_t *runtime,
                      krn_handle_t *out_kernel);
```

---

## Revised verdict

The second specification is **approximately 60 to 70 percent of the way toward a real engineering specification**. It is now structurally credible. It would be useful for aligning architects, kernel developers, terminal application developers, security engineers, and QA teams.

It is **not yet certification-ready** because certification readiness requires exactness at the bit, APDU, TLV, SW1/SW2, state-transition, and scheme-profile level. The remaining defects are not cosmetic. The most serious are:

1. **CID decoding is likely wrong.**
2. **TAA omits Issuer Action Codes and oversimplifies decision ordering.**
3. **TVR bit references are ambiguous and possibly incorrect.**
4. **Contactless/C-8 behavior is too thin for an implementation claiming C-8 support.**
5. **APDU definitions are incomplete or imprecise.**
6. **The PIN API does not fully enforce the security boundary it describes.**
7. **CAPKs are incorrectly treated as confidential secrets rather than integrity-critical public trust anchors.**
8. **The document still overclaims completion and certification readiness.**

The right next step is a **v2.1 precision pass**, not a prose expansion. Focus on bit-level correctness, scheme profile separation, exact APDU/SW1/SW2 handling, and a complete requirement-to-test-to-evidence traceability matrix.

[1]: https://www.emvco.com/news/emvco-launches-the-emv-contactless-kernel-testing-process/?utm_source=chatgpt.com "EMVCo Launches the EMV® Contactless Kernel Testing ..."
[2]: https://blog.pcisecuritystandards.org/just-published-pts-poi-v7-0?utm_source=chatgpt.com "Just Published: PTS POI v7.0"
[3]: https://ingenico.com/en/newsroom/press-releases/ingenico-obtains-first-emvco-approval-c8-book-kernel?utm_source=chatgpt.com "Ingenico obtains the first EMVCo approval for the C8 Book ..."
