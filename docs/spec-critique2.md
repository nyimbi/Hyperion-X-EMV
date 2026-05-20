## Verdict

**No. The v3.0 specification is better, but it is not fully correct.** It is now structurally close to an implementation baseline, but it still contains **several material EMV errors** that would cause implementation defects or certification failure if treated as normative. The most serious remaining issues are in **PSE/PPSE selection**, **GENERATE AC P1 encoding**, **contact/contactless kernel positioning**, **TVR bit definitions**, **offline PIN semantics**, **TAA/default behavior**, and the machine-readable annexes.

The document should be treated as a **strong draft**, not as a fully correct certification baseline. The claim that it is “normative for all engineering, testing, and certification activities” is premature. 

---

## Critical defects that must be fixed

### 1. Contact PSE is wrong

The spec states that both contact PSE and contactless PPSE use:

```text
2PAY.SYS.DDF01
```

For **contactless PPSE**, `2PAY.SYS.DDF01` is correct. For **contact PSE**, the conventional EMV payment system environment name is:

```text
1PAY.SYS.DDF01
```

This is a Priority 0 correction. The current table would make a contact implementation attempt PPSE-style selection where PSE selection is intended. The table appears in the APDU command section of the uploaded v3.0 specification. 

**Correction:**

| Environment      | DF name          |
| ---------------- | ---------------- |
| Contact PSE      | `1PAY.SYS.DDF01` |
| Contactless PPSE | `2PAY.SYS.DDF01` |

---

### 2. GENERATE AC P1 encoding is wrong

The spec says:

```c
uint8_t p1 = 0x80; // first GENERATE AC flag
if (request == ARQC) p1 |= 0x02;
else if (request == TC) p1 |= 0x01;
else if (request == AAC) p1 |= 0x00;
```

This is not correct EMV GENERATE AC encoding. The high-order bits of P1 encode the requested cryptogram type. It is not “bit 8 always 1 for first GENERATE AC.” That construction would generate nonsensical request values such as `0x82` for ARQC and `0x81` for TC. 

The request type should be defined using masked cryptogram request constants, for example:

```c
typedef enum {
    KRN_REQ_AAC  = 0x00,
    KRN_REQ_TC   = 0x40,
    KRN_REQ_ARQC = 0x80
} krn_ac_request_t;
```

Then:

```c
uint8_t p1 = requested_cryptogram;
```

Any CDA-related or scheme-specific bits must be handled explicitly against the licensed EMV Book 3 and scheme kernel specifications. This is a certification-critical defect.

---

### 3. CID decoding is improved, but must be tied to exact bit numbering

The CID decoding function uses:

```c
uint8_t type_bits = (cid >> 6) & 0x03;
```

and maps:

```text
0 = AAC
1 = TC
2 = ARQC
3 = AAR
```

This is broadly the right shape, but the document says “bits 7 and 6,” while many EMV bit tables number bits from **b8 to b1**, not 7 to 0. That is not merely stylistic. Bit-numbering ambiguity causes implementation errors.

**Fix:** express both representations:

```text
CID cryptogram type = (CID & 0xC0)

0x00 = AAC
0x40 = TC
0x80 = ARQC
0xC0 = AAR / referral or reserved according to profile
```

Then the code becomes:

```c
switch (cid & 0xC0) {
    case 0x00: return KRN_CRYPTOGRAM_AAC;
    case 0x40: return KRN_CRYPTOGRAM_TC;
    case 0x80: return KRN_CRYPTOGRAM_ARQC;
    case 0xC0: return KRN_CRYPTOGRAM_AAR;
}
```

The current function is not necessarily wrong, but the normative expression is still too easy to misread. 

---

### 4. TVR table still appears materially wrong

The v3.0 spec introduces a TVR bit table, which is a good improvement, but several entries are likely incorrect or non-standard.

Examples:

| Spec entry                                          | Problem                                                                                                                     |
| --------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| `TVR_B3_APP_VERSION_MISMATCH`                       | EMV processing-restriction conditions are not represented this way in the shown TVR table.                                  |
| `TVR_B4_CURRENCY_MISMATCH`                          | Currency mismatch is not normally represented as a generic TVR byte 4 bit 7 in the way described.                           |
| `TVR_B4_NEW_CARD` and `TVR_B4_CARDHOLDER_ACTIVATED` | These do not look like standard EMV TVR conditions.                                                                         |
| Duplicated random-selection concepts                | The table has both “Random selection triggered” and “Transaction selected for random force online,” which appear redundant. |

The spec should not invent symbolic constants unless each maps exactly to EMV Book 3 TVR byte and bit definitions. The current table risks creating a kernel that sets non-existent or wrong TVR flags. 

**Required fix:** replace Section 5.3 with a strict EMV Book 3 TVR table, using byte and bit labels such as:

```text
TVR byte 1, bit 8
TVR byte 1, bit 7
...
TVR byte 5, bit 1
```

and map each condition exactly to the licensed specification.

---

### 5. Offline PIN handling is still wrong or at least unsafe

The spec says offline VERIFY sends a “PIN block encrypted by PED.”  That is too imprecise and likely wrong.

EMV offline PIN has distinct modes, including **plaintext offline PIN** and **enciphered offline PIN**. For plaintext offline PIN, the PIN is not “encrypted by PED” before VERIFY in the same sense as online PIN. For enciphered offline PIN, the PIN block is enciphered using the ICC public key mechanism. Online PIN is different again: it is formatted and encrypted for host/acquirer processing.

The current wording collapses three different things:

| PIN mode               | Correct handling boundary                                                                                         |
| ---------------------- | ----------------------------------------------------------------------------------------------------------------- |
| Plaintext offline PIN  | PED captures PIN securely; VERIFY APDU carries the appropriate EMV PIN block to card.                             |
| Enciphered offline PIN | PED/secure module constructs enciphered PIN block using ICC public key data.                                      |
| Online PIN             | PED creates encrypted PIN block for host authorization path, often under DUKPT or other acquirer-approved scheme. |

**Required fix:** split CVM handling into separate requirements for plaintext offline PIN, enciphered offline PIN, and online PIN. The API should return method-specific secure handles, not one generic `encrypted_pin_handle`.

---

### 6. TAA is better but still incomplete

The v3.0 spec now includes **TAC + IAC**, which is a major improvement.  But it still simplifies the decision process too aggressively.

The default branch says:

```c
request_cryptogram = default_cryptogram; // from configuration
```

This is not sufficient. EMV terminal action analysis depends on whether the terminal can go online, whether denial/online/default action codes match TVR, issuer action codes, terminal action codes, and scheme/application profile rules. The “default cryptogram” should not be a free configuration value without constraints, because it could allow unsafe offline approval in conditions where the scheme would require ARQC or AAC.

**Required fix:** define a TAA decision table covering:

| Case                                             | Required decision                                 |
| ------------------------------------------------ | ------------------------------------------------- |
| Denial mask matches                              | Request AAC                                       |
| Online mask matches and terminal online capable  | Request ARQC                                      |
| Online required but terminal unable to go online | Evaluate default masks and scheme fallback policy |
| No mask matches and offline approval allowed     | Request TC                                        |
| No mask matches and offline approval not allowed | Request ARQC or AAC depending profile             |

---

### 7. Contact and contactless are still conflated

The spec says the **contact** preferred kernel may be “scheme-specific or C-8 if certified.”  This is suspect. **Book C-8 is an EMV Contactless Kernel Specification**, and EMVCo describes C-8 testing as testing for the EMV Contactless Kernel Specification, not as a contact kernel replacement. ([EMVCo][1])

The specification should not present C-8 as a contact kernel option unless there is a specific certified contact kernel variant and documentary basis for that claim.

**Correction:**

| Interface   | Kernel strategy                                                                                   |
| ----------- | ------------------------------------------------------------------------------------------------- |
| Contact     | EMV contact L2 kernel, typically scheme/application-profile driven.                               |
| Contactless | C-8 unified kernel where certified, or legacy scheme-specific contactless kernels where required. |

---

### 8. The scheme profiles contain placeholder and invalid data

The uploaded `scheme_profiles.json` is not usable as a real certification or implementation profile. It contains placeholder modulus values such as:

```json
"D2E5F5B3A1..."
```

and an invalid checksum-like value:

```json
"E5F6G7H8"
```

`G` and `H` are not valid hexadecimal characters. 

It also contains a fictitious-looking C-8 RID and AID:

```json
"rid": "A000000999"
"aid": "A000000999C8"
```

This should not be presented as a scheme profile unless explicitly marked as a **non-normative illustrative placeholder**. 

**Required fix:** split profiles into:

| File                           | Purpose                                                                             |
| ------------------------------ | ----------------------------------------------------------------------------------- |
| `scheme_profiles.example.json` | Dummy examples, clearly non-certification.                                          |
| `scheme_profiles.cert.json`    | Real scheme, AID, CAPK, TAC/IAC, limit, and kernel parameters used for lab testing. |

---

### 9. ODA test vectors are not real test vectors

The uploaded `oda_test_vectors.json` contains placeholder values such as:

```json
"modulus_hex": "D2E5F5B3A1..."
"data_hex": "6F2A..."
"signature_hex": "3A4F..."
```

These cannot be used to verify RSA recovery, certificate parsing, static signature validation, DDA, or CDA. They are scenario descriptions, not executable cryptographic test vectors. 

This matters because the main spec says Appendix C provides ODA test vectors. The provided file does not yet satisfy that claim.

**Required fix:** each ODA vector must include complete hexadecimal inputs and expected outputs:

| Required field                             | Needed for                  |
| ------------------------------------------ | --------------------------- |
| CAPK modulus and exponent                  | RSA public recovery         |
| CAPK hash/checksum                         | CAPK integrity check        |
| Issuer public key certificate              | Issuer key recovery         |
| Issuer public key remainder, if applicable | Full modulus reconstruction |
| ICC public key certificate                 | DDA/CDA                     |
| ICC public key remainder, if applicable    | Full modulus reconstruction |
| Signed static application data             | SDA                         |
| DDOL input                                 | DDA                         |
| INTERNAL AUTHENTICATE response             | DDA                         |
| GENERATE AC response with CDA signature    | CDA                         |
| Expected recovered data                    | Verification                |
| Expected TVR/TSI                           | Behavioral assertion        |

---

### 10. The state machine CSV is malformed and semantically inconsistent

I inspected the uploaded `state_machine.csv` directly. It is not valid clean CSV: five rows contain unescaped commas, causing field-count mismatches. Examples include rows whose action field contains text like “Set TVR, jump to TAA,” which creates extra CSV columns.

There is also a semantic inconsistency: one row sends a missing-tag READ RECORD failure to `SE`, but the action says “Set TVR, jump to TAA.” Those are different behaviors. A recoverable EMV risk/TVR condition should not be represented as an unrecoverable state-machine error unless the specification explicitly defines it as fatal.

**Required fix:** quote all CSV fields that contain commas and separate fatal protocol errors from TVR-mediated risk outcomes.

---

### 11. TLV catalogue still has typing problems

The TLV catalogue still labels `8C` and `8D` as:

```text
Constructed (DOL)
```

That is not a good type description. CDOL1 and CDOL2 are **Data Object Lists**, encoded as tag-length pairs. They are not constructed BER-TLV templates in the ordinary TLV sense.

The spec itself also repeats this ambiguity:

```text
8C CDOL1 Constructed? If present
8D CDOL2 Constructed? If present
```



**Fix:** change the format to:

```text
DOL, primitive value containing concatenated tag-length references
```

or simply:

```text
Data Object List, tag-length sequence
```

---

### 12. APDU response handling is too narrow

The spec says unexpected APDU responses are those where SW1/SW2 is not `90 00` or `63 CX`.  That is too narrow.

EMV kernels must handle a broader class of APDU status words, including at least:

| SW     | Meaning category                             |
| ------ | -------------------------------------------- |
| `61xx` | More data available                          |
| `6Cxx` | Correct expected length indicated            |
| `6985` | Conditions of use not satisfied              |
| `6A82` | File/application not found                   |
| `6A83` | Record not found                             |
| `6283` | Selected file invalidated, context-dependent |
| `9000` | Success                                      |
| `63Cx` | VERIFY warning with tries remaining          |

Some may be fatal in specific states, but they should not all be collapsed into a generic unexpected APDU response rule.

---

## Current standard-reference position

The version baseline is broadly current. EMVCo confirms that the **Book C-8 Kernel 8 testing process** became available on **16 October 2024**, and that the process evaluates whether products perform in accordance with the C-8 specification when deployed. ([EMVCo][1]) PCI SSC also published **PCI PTS POI v7.0**, moving from v6.2 to v7.0, which supports the spec’s use of PCI PTS POI v7.0 as a current PIN-device security baseline. ([PCI Perspectives][2]) EMVCo states that it maintains the EMV Chip Specifications and supporting approval/evaluation processes, so the document is right to treat EMVCo approval requirements as central rather than optional. ([EMVCo][3])

The problem is not the selected baseline. The problem is the **technical expression of that baseline**.

---

## Correctness scorecard

| Area                     | Status                   | Comment                                                              |
| ------------------------ | ------------------------ | -------------------------------------------------------------------- |
| Scope and trust boundary | Mostly correct           | Good correction on issuer keys and CAPKs.                            |
| EMV references           | Mostly correct           | Needs exact document IDs and licensed baseline control.              |
| Contact PSE / PPSE       | Incorrect                | Contact PSE must be `1PAY.SYS.DDF01`, not `2PAY.SYS.DDF01`.          |
| CID decoding             | Mostly correct           | Use `CID & 0xC0` notation to avoid bit-numbering ambiguity.          |
| GENERATE AC P1           | Incorrect                | Current P1 encoding is certification-critical wrong.                 |
| TVR bits                 | Not reliable             | Several entries appear invented or misplaced.                        |
| TSI bits                 | Partially correct        | Needs exact EMV table and reserved-bit handling.                     |
| Offline PIN              | Not correct enough       | Must split plaintext offline, enciphered offline, and online PIN.    |
| TAA                      | Improved but incomplete  | TAC/IAC included, but default path too loose.                        |
| Contactless / C-8        | Incomplete               | C-8 positioning improved, but still thin and partly overgeneralized. |
| Scheme profiles          | Not implementation-ready | Placeholder/invalid hex and fictitious profile data.                 |
| ODA vectors              | Not executable           | Scenario stubs, not cryptographic test vectors.                      |
| State machine CSV        | Not clean                | CSV malformed and semantically inconsistent.                         |
| TLV catalogue            | Useful but imperfect     | CDOL typing and scheme-specific tags need cleanup.                   |
| Certification readiness  | Not yet                  | Needs real conformance mapping and executable annexes.               |

---

## Required v3.1 correction list

The next revision should be a **precision correction**, not a prose expansion.

1. **Fix PSE/PPSE names**: contact PSE `1PAY.SYS.DDF01`, contactless PPSE `2PAY.SYS.DDF01`.

2. **Rewrite GENERATE AC P1 encoding** using `0x00`, `0x40`, `0x80` request constants and exact CDA/scheme handling.

3. **Replace the TVR table** with a verbatim-equivalent, byte/bit-accurate symbolic mapping from EMV Book 3.

4. **Replace offline PIN text** with separate flows for plaintext offline PIN, enciphered offline PIN, and online PIN.

5. **Make C-8 contactless-only** unless a referenced certification basis says otherwise.

6. **Rewrite TAA as a constrained decision table**, not an open-ended `default_cryptogram`.

7. **Fix malformed CSV rows** in `state_machine.csv` and ensure every transition has a single unambiguous next state.

8. **Demote placeholder JSON files** to examples or replace them with real lab-profile values.

9. **Replace ODA test-vector stubs** with complete cryptographic vectors.

10. **Expand SW1/SW2 handling** by APDU and state.

11. **Clean TLV catalogue typing**, especially CDOL/DDOL/PDOL/TDOL.

12. **Add requirement-to-test traceability**, linking each `KRN-*` requirement to test IDs and evidence artifacts.

---

## Final judgment

The new specification is **not fully correct**.

It is now a credible **architecture and implementation scaffold**, but it still contains enough bit-level and protocol-level errors that an implementation built directly from it could fail EMV L2 testing. The two most urgent corrections are **GENERATE AC P1 encoding** and **contact PSE selection**. The next most serious are the **TVR table**, **offline PIN semantics**, and the fact that the JSON/CSV annexes are not yet executable certification artifacts.

Treat v3.0 as a strong draft. Do not freeze it as a certification baseline until v3.1 corrects the issues above.

[1]: https://www.emvco.com/news/emvco-launches-the-emv-contactless-kernel-testing-process/?utm_source=chatgpt.com "EMVCo Launches the EMV® Contactless Kernel Testing ..."
[2]: https://blog.pcisecuritystandards.org/just-published-pts-poi-v7-0?utm_source=chatgpt.com "Just Published: PTS POI v7.0"
[3]: https://www.emvco.com/emv-technologies/emv-contact-chip/?utm_source=chatgpt.com "EMV® Contact Chip"
