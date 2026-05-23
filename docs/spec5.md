# EMV Level 2 Kernel Specification – Hyperion Kernel (Hyperion‑KRN) – v5.0

**Version:** 5.0  
**Status:** Normative implementation and certification baseline (controlled artifact set)  
**Target EMV Baseline:** EMV Contact Chip Specifications Book 3 v4.4 (and Books 1, 2, 4 where referenced)  
**Contactless Baseline:** EMV Contactless Kernel Specification Book C‑8 v1.0  
**PCI Baseline:** PCI PTS POI v7.0  
**Document Control:** This specification, together with the attached controlled annex files, is normative for all engineering, testing, and certification activities related to the Hyperion EMV kernel.

---

## 1. Scope and Normative References

### 1.1 Scope

This document defines the **behaviour, interfaces, configuration, testing, and certification requirements** of the Hyperion EMV Level 2 kernel (hereinafter “the kernel”). The kernel executes EMV transaction logic for contact (ISO7816) and contactless (ISO14443) payment cards, but **does not** implement:

- Physical or electrical card interface (Level 1)
- PIN capture or secure PIN entry device (PED) logic
- Host (acquirer, issuer) authorisation messaging
- Issuer master key custody or cryptogram validation (except CAPKs for offline data authentication)

### 1.2 Normative References

| ID | Reference | Version | Applicability |
|---|---|---|---|
| **[EMV4.4]** | EMV Contact Chip Specifications – Books 1‑4 | v4.4 | Core contact logic |
| **[EMV4.3]** | EMV Contact Chip Specifications – Books 1‑4 | v4.3 | Legacy compatibility floor |
| **[C8]** | EMV Contactless Specifications for Payment Systems – Book C‑8 (Kernel 8) | v1.0 | Contactless unified kernel |
| **[EMVCo L2]** | EMV Level 2 Approval Process | current | Certification process |
| **[PCI PTS]** | PCI PIN Transaction Security POI Modular Requirements | v7.0 | PIN handling alignment |
| **[ISO7816‑3]** | Identification cards – Integrated circuit cards – Part 3 | latest | T=0/T=1 protocol |
| **[ISO7816‑4]** | Interindustry commands for interchange | latest | APDU structure |
| **[ISO14443‑4]** | Contactless – Part 4: Transmission protocol | latest | Contactless APDU |
| **[ISO9564‑1]** | PIN block formats | latest | Online PIN encryption |

> **KRN‑REF‑001**: The implementation **SHALL** comply with all normative references. In case of conflict between references and this specification, the referenced standards prevail.

---

## 2. Trust Boundary and Responsibility Model

The kernel is one component inside a payment acceptance system. The following table defines ownership boundaries.

| Component | Responsibilities | Owned by | Security classification |
|---|---|---|---|
| **EMV L2 kernel** | CAPK integrity checks; ODA (SDA, DDA, CDA); APDU orchestration; TVR/TSI setting; CDOL/DDOL construction; cryptogram response parsing; final decision (offline approve/decline/go online) | Hyperion kernel | Integrity‑critical, no confidentiality for CAPKs |
| **Secure PIN subsystem (PED)** | PIN capture; PIN block formatting (ISO9564‑1); online PIN encryption (DUKPT); offline plaintext PIN VERIFY APDU data field construction (opaque secure buffer); enciphered offline PIN block construction using ICC public key | Terminal manufacturer / kernel integrator | Confidentiality‑critical |
| **Level 3 application** | UI, host communication, scripting environment, receipt printing | Terminal application developer | Functional |
| **Acquirer / switch** | ISO 8583/ISO 20022 routing, authorisation request forwarding | Acquirer | Functional |
| **Issuer / issuer processor** | Issuer master keys, ARQC validation, ARPC generation, issuer scripts | Issuer | Confidentiality‑critical |

**Certified PIN integration model (mandatory):**  
The kernel **SHALL** use **Model A – PED‑owned VERIFY** for offline plaintext PIN:
- The PED captures the PIN, constructs the VERIFY APDU data field **inside a secure environment**, and returns an **opaque secure handle** to the kernel.
- The kernel calls a certified transport function that transmits the secure buffer to the ICC without exposing the plaintext PIN data to kernel memory.
- The kernel receives only the APDU response status (SW1/SW2) and the try counter.

For enciphered offline PIN and online PIN, the kernel receives a secure handle to the encrypted PIN block, passes it to the host interface, and never dereferences it.

> **KRN‑SEC‑001**: No issuer master key **SHALL** be stored or accessible inside the kernel.  
> **KRN‑SEC‑002**: The kernel **SHALL NOT** generate ARQC, TC, or AAC; these cryptograms are returned by the card in response to GENERATE AC.  
> **KRN‑SEC‑003**: CAPKs are **public keys**; they require integrity protection and authenticity but **not confidentiality**. They may be stored in plaintext with a digital signature covering the configuration blob.  
> **KRN‑SEC‑004**: PIN processing **SHALL** follow the certified integration model (Model A) above; the kernel **SHALL NOT** construct, modify, or access any PIN‑related data in clear text.

---

## 3. Application Selection – Contact PSE and Contactless PPSE

The kernel **MUST** correctly differentiate between contact and contactless environments using the following exact APDUs:

| Environment | DF name | Hex data | Lc | Full APDU |
|---|---|---|---|---|
| **Contact PSE** | `1PAY.SYS.DDF01` | `31 50 41 59 2E 53 59 53 2E 44 44 46 30 31` | `0E` | `00 A4 04 00 0E 31 50 41 59 2E 53 59 53 2E 44 44 46 30 31 00` |
| **Contactless PPSE** | `2PAY.SYS.DDF01` | `32 50 41 59 2E 53 59 53 2E 44 44 46 30 31` | `0E` | `00 A4 04 00 0E 32 50 41 59 2E 53 59 53 2E 44 44 46 30 31 00` |

> **KRN‑SEL‑001**: The kernel **SHALL** select the PSE using the exact contact APDU above for contact cards, and the PPSE using the exact contactless APDU above for contactless cards. No padding or modification is allowed.

---

## 4. Data Objects Dictionary

The following table lists mandatory EMV tags. For the complete TLV catalogue, see **Annex A** (attached CSV file).

| Tag | Name | Format | Presence | Source |
|---|---|---|---|---|
| `4F` | AID | Primitive, variable | Mandatory | EMV Book 3 |
| `50` | Application Label | Primitive, variable | Recommended | EMV Book 3 |
| `57` | Track 2 Equivalent Data | Primitive, variable | Mandatory | EMV Book 3 |
| `5A` | PAN | Primitive, variable | Mandatory | EMV Book 3 |
| `5F24` | Application Expiration Date | Primitive, 3 bytes | Mandatory | EMV Book 3 |
| `5F2A` | Transaction Currency Code | Primitive, 2 bytes | Mandatory (terminal) | EMV Book 3 |
| `82` | AIP | Primitive, 2 bytes | Mandatory after GPO | EMV Book 3 |
| `84` | DF Name (PPSE) | Primitive, variable | Contactless | EMV Contactless |
| `8C` | CDOL1 | Data Object List (tag‑length pairs) | If present | EMV Book 3 |
| `8D` | CDOL2 | Data Object List (tag‑length pairs) | If present | EMV Book 3 |
| `8E` | CVM List | Constructed | Mandatory | EMV Book 3 |
| `91` | Issuer Authentication Data | Primitive, variable | For ARPC | EMV Book 3 |
| `94` | AFL | Primitive, variable | Mandatory after GPO | EMV Book 3 |
| `95` | TVR | Primitive, 5 bytes | Kernel sets | EMV Book 3 |
| `9A` | Transaction Date | Primitive, 3 bytes | Terminal sets | EMV Book 3 |
| `9B` | TSI | Primitive, 2 bytes | Kernel sets | EMV Book 3 |
| `9C` | Transaction Type | Primitive, 1 byte | Terminal sets | EMV Book 3 |
| `9F02` | Amount Authorised | Primitive, 6 bytes | Terminal sets | EMV Book 3 |
| `9F07` | Application Usage Control | Primitive, 2 bytes | Mandatory | EMV Book 3 |
| `9F09` | Application Version Number | Primitive, 2 bytes | Mandatory | EMV Book 3 |
| `9F10` | Issuer Application Data | Primitive, variable | Mandatory for host | EMV Book 3 |
| `9F1A` | Terminal Country Code | Primitive, 2 bytes | Terminal sets | EMV Book 3 |
| `9F26` | Application Cryptogram | Primitive, 8 bytes | From card | EMV Book 3 |
| `9F27` | CID | Primitive, 1 byte | From card | EMV Book 3 |
| `9F33` | Terminal Capabilities | Primitive, 3 bytes | Terminal sets | EMV Book 3 |
| `9F34` | CVM Results | Primitive, 3 bytes | Kernel sets | EMV Book 3 |
| `9F35` | Terminal Type | Primitive, 1 byte | Terminal sets | EMV Book 3 |
| `9F36` | ATC | Primitive, 2 bytes | From card | EMV Book 3 |
| `9F37` | Unpredictable Number | Primitive, 4 bytes | Terminal generates | EMV Book 3 |
| `9F4C` | ICC Dynamic Number | Primitive, variable | For CDA | EMV Book 3 |
| `9F4E` | Merchant Category Code | Primitive, 2 bytes | Terminal sets | EMV Book 3 |
| `9F6C` | CTQ | Primitive, 1 byte | For contactless | EMV Contactless |
| `9F66` | TTQ | Primitive, 4 bytes | For contactless | EMV Contactless |

---

## 5. Terminal Verification Results (TVR) – 5‑byte exact definition

The TVR records the results of risk and compliance checks performed by the terminal. The following table defines **all 5 bytes**, including RFU bits. Bit numbering is b8 (most significant) to b1 (least significant) within each byte.

| Byte | Bit | Mask | EMV Condition | Set by | Symbolic constant |
|---|---|---|---|---|---|
| 1 | b8 | `0x80` | Offline data authentication was not performed | ODA engine | `TVR_B1_OFFLINE_DATA_AUTH_NOT_PERFORMED` |
| 1 | b7 | `0x40` | SDA failed | ODA engine | `TVR_B1_SDA_FAILED` |
| 1 | b6 | `0x20` | ICC data missing | TLV validator | `TVR_B1_ICC_DATA_MISSING` |
| 1 | b5 | `0x10` | Card appears on terminal exception file | TRM | `TVR_B1_CARD_ON_EXCEPTION_FILE` |
| 1 | b4 | `0x08` | DDA failed | ODA engine | `TVR_B1_DDA_FAILED` |
| 1 | b3 | `0x04` | CDA failed | ODA engine | `TVR_B1_CDA_FAILED` |
| 1 | b2‑b1 | `0x03` | RFU | – | – |
| 2 | b8 | `0x80` | ICC and terminal have different application versions | Processing restrictions | `TVR_B2_APP_VERSION_MISMATCH` |
| 2 | b7 | `0x40` | Expired application | Processing restrictions | `TVR_B2_APP_EXPIRED` |
| 2 | b6 | `0x20` | Application not yet effective | Processing restrictions | `TVR_B2_APP_NOT_EFFECTIVE` |
| 2 | b5 | `0x10` | Requested service not allowed for card product | Processing restrictions | `TVR_B2_SERVICE_NOT_ALLOWED` |
| 2 | b4 | `0x08` | New card | Processing restrictions | `TVR_B2_NEW_CARD` |
| 2 | b3‑b1 | `0x07` | RFU | – | – |
| 3 | b8 | `0x80` | Cardholder verification was not successful | CVM module | `TVR_B3_CVM_FAILED` |
| 3 | b7 | `0x40` | Unrecognised CVM | CVM module | `TVR_B3_UNRECOGNISED_CVM` |
| 3 | b6 | `0x20` | PIN try limit exceeded | CVM module (from VERIFY response) | `TVR_B3_PIN_TRY_LIMIT_EXCEEDED` |
| 3 | b5 | `0x10` | PIN entry required and PIN pad not present or not working | CVM module | `TVR_B3_PIN_PAD_NOT_PRESENT` |
| 3 | b4 | `0x08` | PIN entry required, PIN pad present, but PIN not entered | CVM module | `TVR_B3_PIN_NOT_ENTERED` |
| 3 | b3 | `0x04` | Online PIN entered | CVM module | `TVR_B3_ONLINE_PIN_ENTERED` |
| 3 | b2‑b1 | `0x03` | RFU | – | – |
| 4 | b8 | `0x80` | Transaction exceeds floor limit | TRM | `TVR_B4_EXCEEDS_FLOOR_LIMIT` |
| 4 | b7 | `0x40` | Lower consecutive offline limit exceeded | TRM | `TVR_B4_LOWER_CONSECUTIVE_OFFLINE_LIMIT` |
| 4 | b6 | `0x20` | Upper consecutive offline limit exceeded | TRM | `TVR_B4_UPPER_CONSECUTIVE_OFFLINE_LIMIT` |
| 4 | b5 | `0x10` | Transaction selected for random force online | TRM | `TVR_B4_RANDOM_SELECTION` |
| 4 | b4‑b1 | `0x0F` | RFU | – | – |
| 5 | b8 | `0x80` | Issuer authentication failed | Kernel (online response) | `TVR_B5_ISSUER_AUTH_FAILED` |
| 5 | b7 | `0x40` | Script processing failed after final GENERATE AC | Script processor | `TVR_B5_SCRIPT_FAILED` |
| 5 | b6 | `0x20` | Script processing failed before final GENERATE AC (if script phase) | Script processor | `TVR_B5_SCRIPT_FAILED_EARLY` |
| 5 | b5‑b1 | `0x1F` | RFU / scheme‑specific | – | – |

> **KRN‑TVR‑001**: The kernel **SHALL** use the symbolic constants above when setting TVR bits; raw hex constants **SHALL NOT** be used directly in code without a mapping layer.  
> **KRN‑TVR‑002**: The kernel **SHALL** clear TVR before each transaction.  
> **KRN‑TVR‑003**: The kernel **SHALL** implement all bits marked RFU as reserved; they **SHALL NOT** be set.

---

## 6. Transaction Status Information (TSI) – 2‑byte exact definition

| Byte | Bit | Mask | Condition | Set by | Symbolic constant |
|---|---|---|---|---|---|
| 1 | b8 | `0x80` | Offline data authentication performed | ODA engine | `TSI_B1_ODA_PERFORMED` |
| 1 | b7 | `0x40` | Cardholder verification performed | CVM module | `TSI_B1_CVM_PERFORMED` |
| 1 | b6 | `0x20` | Card risk management performed | Card (from AIP) | – |
| 1 | b5 | `0x10` | Issuer authentication performed | Kernel after online response | `TSI_B1_ISSUER_AUTH_PERFORMED` |
| 1 | b4 | `0x08` | Terminal risk management performed | TRM engine | `TSI_B1_TRM_PERFORMED` |
| 1 | b3 | `0x04` | Script processing performed | Script processor | `TSI_B1_SCRIPT_PROCESSING_PERFORMED` |
| 1 | b2‑b1 | `0x03` | RFU | – | – |
| 2 | b8‑b1 | all | RFU | – | – |

> **KRN‑TSI‑001**: The kernel **SHALL** set TSI bits as above.

---

## 7. Cryptogram Information Data (CID) – Tag `9F27`, 1 byte

The CID cryptogram type is determined by the two most significant bits (b8 and b7). Using mask `0xC0`:

| Mask (`CID & 0xC0`) | Meaning | Action |
|---|---|---|
| `0x00` | AAC (Application Authentication Cryptogram) | Offline decline |
| `0x40` | TC (Transaction Certificate) | Offline approval |
| `0x80` | ARQC (Authorization Request Cryptogram) | Go online |
| `0xC0` | AAR / referral or reserved (scheme‑specific) | Follow scheme profile |

**Implementation code:**
```c
typedef enum {
    KRN_CRYPTOGRAM_AAC = 0,
    KRN_CRYPTOGRAM_TC  = 1,
    KRN_CRYPTOGRAM_ARQC = 2,
    KRN_CRYPTOGRAM_AAR = 3,
    KRN_CRYPTOGRAM_RESERVED = 4
} krn_cryptogram_type_t;

krn_cryptogram_type_t krn_decode_cid(uint8_t cid) {
    switch (cid & 0xC0) {
        case 0x00: return KRN_CRYPTOGRAM_AAC;
        case 0x40: return KRN_CRYPTOGRAM_TC;
        case 0x80: return KRN_CRYPTOGRAM_ARQC;
        case 0xC0: return KRN_CRYPTOGRAM_AAR;
        default:   return KRN_CRYPTOGRAM_RESERVED;
    }
}
```

> **KRN‑CID‑001**: The kernel **SHALL** decode CID using the above mask and mapping.

---

## 8. Cardholder Verification (CVM) Processing

The kernel implements the CVM List as a sequence of `(CVM Code, CVM Condition Code)` pairs. The following CVM codes are supported:

| CVM Code | Method | Condition code handling |
|---|---|---|
| `0x01` | Offline plaintext PIN | Verify using VERIFY APDU; PED constructs secure buffer (see §2) |
| `0x02` | Online PIN | Pass secure handle to host; kernel does not touch PIN data |
| `0x03` | Signature | (where permitted) call `notify_signature_required()` |
| `0x04` | No CVM | Accept if amount ≤ CVM limit |
| `0x05` | Consumer Device CVM (CDCVM) | Accept if card indicates CDCVM performed |
| `0x06` | Offline enciphered PIN | Use ICC public key; PED constructs secure buffer |
| `0x1E` | Fail CVM processing | Force CVM failure |

Condition codes (`0x00` to `0x0F`) encode amount thresholds (X, Y) and terminal capability requirements. The kernel evaluates each pair in priority order.

> **KRN‑CVM‑001**: The kernel **SHALL** parse the CVM List according to EMV Book 3, evaluate condition codes, and enforce amount limits.  
> **KRN‑CVM‑002**: The kernel **SHALL** set TVR byte 3 bits based on CVM outcome.

---

## 9. GENERATE AC P1 Encoding

The terminal requests a cryptogram type by setting P1 as follows:

| Requested cryptogram | P1 value |
|---|---|
| AAC (offline decline) | `0x00` |
| TC (offline approval) | `0x40` |
| ARQC (go online) | `0x80` |
| CDA request (if supported) | `P1 = (requested_type) | 0x40` (see scheme profile) |

> **KRN‑GAC‑008**: The kernel **SHALL** encode P1 using the above constants.  
> **KRN‑GAC‑009**: If CDA is supported and enabled, the kernel **SHALL** set the CDA request bit as defined in the scheme profile (typically `0x40` combined with the base type).

---

## 10. Terminal Action Analysis (TAA) – Deterministic Decision Table

The kernel uses Terminal Action Codes (TAC) and Issuer Action Codes (IAC) (each 5‑byte masks) to determine the next action. The decision order is:

| Step | Condition | Action |
|---|---|---|
| 1 | `(TVR & (IAC_Denial | TAC_Denial)) != 0` | Request AAC (offline decline) |
| 2 | Else if terminal is online capable and `(TVR & (IAC_Online | TAC_Online)) != 0` | Request ARQC (go online) |
| 3 | Else if terminal is NOT online capable and `(TVR & (IAC_Default | TAC_Default)) != 0` | Request AAC (decline) **or** TC per scheme fallback policy (explicitly configured) |
| 4 | Else | Request TC (offline approve) **or** ARQC per scheme/application profile (explicitly configured) |

**IAC retrieval:**  
- IAC_Denial, IAC_Online, IAC_Default are read from card’s application records (tags `9F0D`, `9F0E`, `9F0F` respectively).  
- If a tag is missing, the corresponding IAC value **SHALL** be treated as all zeros.

**TAC retrieval:**  
- TAC_Denial, TAC_Online, TAC_Default are loaded from signed configuration per AID.

> **KRN‑TAA‑004**: The kernel **SHALL** fetch IACs from the card; missing tags default to zero.  
> **KRN‑TAA‑005**: The kernel **SHALL** fetch TACs from configuration.  
> **KRN‑TAA‑006**: The kernel **SHALL** evaluate the decision steps in the exact order. The fallback policy **SHALL** be explicitly configured per scheme/AID (no “free” default).

---

## 11. APDU Command Handling and State‑Specific SW Tables

The kernel must handle APDU status words in a state‑dependent manner. The following table provides a baseline; full state‑by‑state handling is defined in **Annex E** (state machine CSV).

| Command | SW | Meaning | Next state | TVR/TSI action |
|---|---|---|---|---|
| SELECT (PSE/PPSE) | `90 00` | Success, FCI returned | S2 → S3 (if AID matched) | – |
| SELECT (PSE/PPSE) | `6A82` | PSE/PPSE not found | Fall back to direct AID selection | – |
| SELECT (AID) | `6A82` | AID not found | Try next candidate; if none, error `KRN_ERR_NO_COMMON_AID` | – |
| GPO | `90 00` | Success with `77` or `80` template | S3 → S4 | – |
| GPO | `6A81` | Function not supported | S3 → SE (error) | – |
| READ RECORD | `90 00` | Record read | Continue AFL loop | – |
| READ RECORD | `6A83` | Record not found | End of records; if mandatory record missing, set `TVR_B1_ICC_DATA_MISSING` | Set TVR |
| VERIFY (offline) | `90 00` | PIN success | CVM success | Clear CVM failure bits |
| VERIFY (offline) | `63Cx` | PIN failed, x tries remain | CVM retry or next method | Set `TVR_B3_PIN_TRY_LIMIT_EXCEEDED` if x==0 |
| GENERATE AC (first) | `90 00` | Cryptogram returned | S10 → S11 if ARQC, else S14 | – |
| GENERATE AC (first) | `6985` | Conditions of use not satisfied | S10 → SE | – |

> **KRN‑APDU‑009**: The kernel **SHALL** implement state‑specific handling for all SW codes listed in the full state machine (Annex E).  
> **KRN‑APDU‑010**: The kernel **SHALL NOT** treat all non‑`9000` responses as generic errors.

---

## 12. Offline Data Authentication (ODA) – Certificate Recovery and Verification

The kernel implements SDA, DDA, and CDA as per EMV Book 3. The following steps are mandatory:

### 12.1 CAPK Management

- CAPKs are stored per (RID, key index) in the signed configuration.  
- Each CAPK record includes: modulus, exponent, expiry, and a hash (SHA‑256) for integrity.  
- **KRN‑ODA‑001**: The kernel **SHALL** verify the CAPK hash before use; if invalid, treat as missing.  
- **KRN‑ODA‑002**: CAPKs are public keys; confidentiality not required, but integrity and authenticity are mandatory.

### 12.2 Issuer Public Key Certificate Recovery

- Use CAPK to verify the digital signature of the issuer public key certificate.  
- Extract issuer public key (modulus, exponent).  
- **KRN‑ODA‑003**: If recovery fails, set `TVR_B1_SDA_FAILED` (for SDA) or `TVR_B1_DDA_FAILED` (for DDA) and proceed to TAA.

### 12.3 ICC Public Key Certificate Recovery (DDA/CDA)

- Use recovered issuer public key to verify the ICC public key certificate.  
- Extract ICC public key.  
- **KRN‑ODA‑004**: If recovery fails, set `TVR_B1_DDA_FAILED` or `TVR_B1_CDA_FAILED` accordingly.

### 12.4 SDA

- Verify the Signed Static Application Data (tag `90` or `93`) using the recovered issuer public key.  
- **KRN‑ODA‑005**: Failure sets `TVR_B1_SDA_FAILED`.

### 12.5 DDA

- Build DDOL data (or default if DDOL absent).  
- Send INTERNAL AUTHENTICATE; verify dynamic signature using ICC public key.  
- **KRN‑ODA‑006**: Failure sets `TVR_B1_DDA_FAILED`.

### 12.6 CDA

- The card supports CDA if AIP bit 7 is set.  
- The kernel requests a CDA by setting the CDA request bit in GENERATE AC P1 (see scheme profile).  
- The response includes Signed Dynamic Application Data (tag `9F4C`).  
- Verify the signature includes the generated cryptogram (TC/ARQC/AAC).  
- **KRN‑ODA‑007**: Failure sets `TVR_B1_CDA_FAILED`. If CDA is supported and fails, the kernel **SHALL NOT** fall back to DDA; the transaction must proceed according to TAA.

---

## 13. Contactless / C‑8 Kernel Specification

The kernel **SHALL** implement EMV Contactless Kernel Specification Book C‑8 (Kernel 8) for all contactless transactions where supported. The following mandatory elements are required:

- **Entry Point**: Use `2PAY.SYS.DDF01` (PPSE) as defined in §3.  
- **Candidate List Selection**: Parse PPSE FCI and select the highest priority AID that matches terminal configuration.  
- **Outcome Parameter Set**: After transaction completion, the kernel returns:

  - `outcome_code`: `APPROVED`, `DECLINED`, `ONLINE_REQUIRED`, `TRY_AGAIN`, `SELECT_NEXT`, `ALTERNATE_INTERFACE`  
  - `ui_message_id`: `PRESENT_CARD`, `REMOVE_CARD`, `SEE_PHONE` (plus optional scheme‑specific)  
  - `hold_time` (milliseconds)  
  - `restart` (boolean)

- **Limits**: Support CTL (contactless transaction limit) and CCL (contactless CVM limit) from configuration.  
- **Relay Resistance**: If the card supports relay resistance, the kernel **SHALL** implement the required APDUs and timing constraints as defined in Book C‑8.  
- **Data Objects**: Full support for TTQ (`9F66`), CTQ (`9F6C`), Form Factor Indicator (`9F6E`), and Discretionary Data.

> **KRN‑C8‑001**: The kernel **SHALL** implement C‑8 unified kernel for contactless transactions.  
> **KRN‑C8‑002**: The kernel **SHALL** return outcome parameters via the `contactless_outcome()` callback.  
> **KRN‑C8‑003**: The kernel **SHALL NOT** treat C‑8 as a contact kernel replacement; contact transactions **SHALL** use contact EMV L2 kernels.

---

## 14. API / ABI Specification

The kernel exposes a C API (ABI stable). All functions return `emv_status_t`.

```c
typedef enum {
    KRN_OK = 0,
    KRN_ERR_INVALID_STATE,
    KRN_ERR_CARD_REMOVED,
    KRN_ERR_MISSING_MANDATORY_TAG,
    KRN_ERR_ODA_FAILED,
    KRN_ERR_CVM_FAILED,
    KRN_ERR_HOST_TIMEOUT,
    KRN_ERR_SCRIPT_FAILED,
    KRN_ERR_CONFIG_INVALID,
    KRN_ERR_NO_COMMON_AID
} emv_status_t;

typedef enum {
    KRN_OUTCOME_APPROVED_OFFLINE,
    KRN_OUTCOME_DECLINED_OFFLINE,
    KRN_OUTCOME_GO_ONLINE,
    KRN_OUTCOME_APPROVED_ONLINE,
    KRN_OUTCOME_DECLINED_ONLINE,
    KRN_OUTCOME_TRY_AGAIN,
    KRN_OUTCOME_TERMINATED
} krn_outcome_t;

typedef struct {
    uint32_t abi_version;          // must be KRN_ABI_VERSION
    uint32_t struct_size;          // sizeof(krn_runtime_t)
    krn_callbacks_t callbacks;
    krn_allocator_t allocator;     // optional, use malloc/free if NULL
    krn_timeouts_t timeouts;       // in milliseconds
    krn_log_policy_t log_policy;
} krn_runtime_t;

typedef struct {
    uint64_t amount_authorised;    // in minor units
    uint64_t amount_other;         // cashback, etc.
    uint16_t currency_code;        // ISO numeric
    uint8_t transaction_type;
    uint8_t terminal_type;
    uint8_t merchant_category_code[2];
} krn_txn_params_t;

// Callbacks (implemented by Level 3)
typedef struct {
    int (*transmit_apdu)(const uint8_t *cmd, size_t cmd_len,
                         uint8_t *resp, size_t *resp_len, int timeout_ms);
    krn_pin_result_t (*request_pin)(int online, int max_len, int *try_remain);
    void (*display_message)(const char *msg, int error, int duration_ms);
    int (*send_online_request)(const uint8_t *data, size_t len,
                               uint8_t *response, size_t *resp_len, int timeout_ms);
    int (*get_unpredictable_number)(uint8_t *un, size_t len);
    void (*log_event)(int level, const char *fmt, ...);
    void (*contactless_outcome)(uint8_t outcome_code, const char *ui_message);
} krn_callbacks_t;

// Core functions
emv_status_t krn_init(const krn_config_blob_t *cfg,
                      const krn_runtime_t *runtime,
                      krn_handle_t *out_kernel);
emv_status_t krn_set_transaction_params(krn_handle_t kernel, const krn_txn_params_t *params);
krn_outcome_t krn_run_transaction(krn_handle_t kernel);
emv_status_t krn_reset(krn_handle_t kernel);
emv_status_t krn_get_last_error(krn_handle_t kernel, char *buf, size_t buf_len);
void krn_destroy(krn_handle_t kernel);
```

> **KRN‑API‑004**: The kernel **SHALL NOT** be re‑entrant; the caller **SHALL** serialise calls to a single kernel instance.  
> **KRN‑API‑005**: All buffers passed to callbacks are owned by the caller; the kernel **SHALL NOT** free them.  
> **KRN‑API‑006**: The kernel **SHALL** provide `krn_run_transaction`, `krn_reset`, and `krn_get_last_error`.

---

## 15. Security Architecture – Logging and Data Masking

| Data type | Masking rule |
|---|---|
| PAN | Keep only last 4 digits; replace all others with `*` |
| Track 2 equivalent data | Never log; only hash for debugging (opt‑in) |
| PIN block | Never log, never accessible |
| ARQC/ARPC | May be logged only in **signed, time‑limited support mode** (not compile‑time `#ifdef`). Production builds **MUST NOT** log these. |
| Full APDU logs | Configurable; disabled in production unless certified support mode enabled. |
| Crash dumps | Must exclude all cardholder data and keys. |

> **KRN‑LOG‑001**: The kernel **SHALL** enforce a formal log policy meeting the above requirements. Production builds **SHALL NOT** include debug logging paths that can be enabled at runtime without cryptographic authorisation.

---

## 16. Performance and Resource Model

The kernel **SHALL** meet the following constraints (target tier dependent):

| Tier | Target class | Code+Static | Transaction context | Contact execution (kernel only) | Contactless execution (kernel only) |
|---|---|---|---|---|---|
| A | Cortex‑M / RTOS | ≤ 256 KB | ≤ 4 KB | ≤ 80 ms | ≤ 40 ms |
| B | Linux embedded | ≤ 1 MB | ≤ 32 KB | ≤ 60 ms | ≤ 30 ms |
| C | Android POS | not limited | not limited | performance‑bound (aim ≤ 50 ms) | performance‑bound (aim ≤ 25 ms) |

---

## 17. Testing and Certification Evidence

### 17.1 Testing Requirements

| Test level | Scope | Coverage target |
|---|---|---|
| Unit | Each function (TLV, APDU builder, TVR/TSI, state machine) | 100% branch coverage |
| Integration | Full transaction with simulated card (APDU script replay) | 100 % of EMV test plan for each scheme |
| Fuzz | APDU parser, TLV parser, configuration parser | 1 million iterations, no crash/memory leak |
| Simulator | Run EMVCo test tool (e.g., Fime Eval4dev) | Pass all relevant test cases for target schemes |

### 17.2 Certification Evidence Artifacts

The following **controlled artifacts** accompany this specification and are part of the certification baseline:

| Artifact | File name | Format |
|---|---|---|
| Complete TLV catalogue | `tlv_catalogue.csv` | CSV |
| Full state machine transition table | `state_machine.csv` | CSV (quoted fields) |
| ODA test vectors (executable) | `oda_test_vectors.json` | JSON |
| Scheme profiles (real certification values) | `scheme_profiles.cert.json` | JSON |
| Requirement‑to‑test traceability matrix | `requirements_traceability.xlsx` | Excel/CSV |
| Lab submission manifest | `lab_submission_manifest.md` | Markdown |

> **KRN‑CERT‑003**: The kernel **SHALL** achieve EMVCo Level 2 certification for each claimed scheme and interface (contact, contactless, C‑8).  
> **KRN‑CERT‑004**: The kernel **SHOULD** pass a third‑party penetration test focused on APDU injection and state machine bypass.

---

## Annexes (Controlled Artifacts)

The following files are attached separately and form part of this specification.

### Annex A – TLV Catalogue (`tlv_catalogue.csv`)

(Provides complete tag list with byte‑level formats, presence rules, and scheme notes.)

### Annex B – APDU Command Summary Table

(Provided as a table in the specification – see §11 and Annex E for state‑specific behaviour.)

### Annex C – ODA Test Vectors (`oda_test_vectors.json`)

(Contains CAPK modulus/exponent, issuer certificate, ICC certificate, static signature, DDOL input, INTERNAL AUTHENTICATE response, GENERATE AC response with CDA signature, expected recovered data, and expected TVR/TSI for each test case.)

### Annex D – Trace Log Format Specification

(JSON schema as defined in §15.)

### Annex E – Full State Machine Transition Table (`state_machine.csv`)

(CSV with columns: CurrentState, Event, Guard, NextState, Action, ErrorCode. All fields containing commas are double‑quoted.)

### Annex F – Scheme Profiles (`scheme_profiles.cert.json`)

(Real, non‑placeholder configuration for Visa, Mastercard, and C‑8, including AIDs, CAPKs, TACs, IACs, limits, and kernel parameters used for lab testing.)

### Annex G – Requirement‑to‑Test Traceability Matrix (`requirements_traceability.xlsx`)

(Maps every `KRN-*` requirement to unit test IDs, integration test IDs, EMVCo test case references, and evidence artifacts.)

---

**End of Specification v5.0**
